#!/usr/bin/env python3
"""Offline record-output comparison. Python 3.11+, standard library only."""
from __future__ import annotations
import argparse
import csv
import hashlib
import html
import json
import math
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

VERSION = "0.1.0"


def reject_constant(value):
    raise ValueError("Non-finite JSON numbers are not supported")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON object key")
        result[key] = value
    return result


def read_records(path):
    path = Path(path)
    raw = path.read_bytes()
    text = raw.decode("utf-8-sig")
    suffix = path.suffix.lower()
    if suffix == ".csv":
        reader = csv.DictReader(text.splitlines(keepends=True), strict=True)
        headers = reader.fieldnames or []
        if not headers or any(not h for h in headers) or len(headers) != len(set(headers)):
            raise ValueError("CSV needs unique, non-empty column headers")
        rows = list(reader)
        if any(None in r or any(v is None for v in r.values()) for r in rows):
            raise ValueError("CSV row width differs from the header")
    elif suffix in (".jsonl", ".ndjson"):
        rows = [json.loads(line, parse_constant=reject_constant, object_pairs_hook=unique_object)
                for line in text.splitlines() if line.strip()]
    elif suffix == ".json":
        rows = json.loads(text, parse_constant=reject_constant, object_pairs_hook=unique_object)
        if not isinstance(rows, list):
            raise ValueError("JSON input must be an array of objects")
    else:
        raise ValueError("Supported inputs: .csv, .json, .jsonl, .ndjson")
    if any(not isinstance(r, dict) for r in rows):
        raise ValueError("Every record must be an object")
    return rows, hashlib.sha256(raw).hexdigest()


def timestamp(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Timestamp must be a non-empty ISO 8601 string")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("Timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def value_type(value):
    if value is None:
        return "null"
    return {str: "string", bool: "boolean", int: "integer", float: "number",
            list: "array", dict: "object"}[type(value)]


def schema(rows, ignore):
    fields = defaultdict(set)
    for row in rows:
        for key, value in row.items():
            if key not in ignore:
                fields[key].add(value_type(value))
    all_keys = set(fields)
    for row in rows:
        for key in all_keys - set(row):
            fields[key].add("missing")
    return {k: sorted(v) for k, v in sorted(fields.items())}


def record_key(row, key):
    value = row.get(key)
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    if isinstance(value, (dict, list, bool)):
        return None
    return json.dumps(value, sort_keys=True, allow_nan=False)


def canonical(row, ignore, time_fields):
    result = {k: v for k, v in row.items() if k not in ignore}
    for field in time_fields:
        if field in result:
            try:
                result[field] = timestamp(result[field]).isoformat()
            except (ValueError, TypeError):
                pass
    return json.dumps(result, sort_keys=True, separators=(",", ":"), allow_nan=False)


def p95(values):
    return sorted(values)[max(0, math.ceil(len(values) * .95) - 1)] if values else None


def profile(rows, key, event_field=None, ingest_field=None, ignore=()):
    ids = [record_key(r, key) for r in rows]
    counts = Counter(i for i in ids if i is not None)
    times, latencies = [], []
    invalid_times = negative_latency = 0
    if event_field:
        for row in rows:
            try:
                event = timestamp(row.get(event_field))
                times.append(event)
                if ingest_field:
                    latency = (timestamp(row.get(ingest_field)) - event).total_seconds()
                    if latency < 0:
                        negative_latency += 1
                    latencies.append(latency)
            except (ValueError, TypeError):
                invalid_times += 1
    return {
        "records": len(rows), "missing_or_invalid_ids": ids.count(None),
        "duplicate_id_rows": sum(c - 1 for c in counts.values()),
        "schema": schema(rows, set(ignore)),
        "invalid_timestamps": invalid_times, "negative_latency_rows": negative_latency,
        "event_min_utc": min(times).isoformat() if times else None,
        "event_max_utc": max(times).isoformat() if times else None,
        "latency_p95_seconds": p95(latencies),
        "latency_max_seconds": max(latencies) if latencies else None,
    }


def compare(baseline, candidate, *, key, event_field=None, ingest_field=None,
            ignore=(), max_count_drift_pct=0.0, max_p95_latency=None):
    if not math.isfinite(max_count_drift_pct) or max_count_drift_pct < 0:
        raise ValueError("Count tolerance must be finite and non-negative")
    if max_p95_latency is not None and (not math.isfinite(max_p95_latency) or max_p95_latency < 0):
        raise ValueError("Latency threshold must be finite and non-negative")
    if ingest_field and not event_field:
        raise ValueError("An ingest field requires an event timestamp field")
    if max_p95_latency is not None and not ingest_field:
        raise ValueError("Latency threshold requires event and ingest timestamp fields")
    if key in ignore:
        raise ValueError("The record key cannot be ignored")
    if event_field and event_field == ingest_field:
        raise ValueError("Event and ingest timestamp fields must differ")
    ignored = set(ignore)
    profiles = [profile(r, key, event_field, ingest_field, ignored) for r in [baseline, candidate]]
    checks = []
    def check(name, ok, detail):
        checks.append({"check": name, "status": "PASS" if ok else "FAIL", "detail": detail})
    check("Non-empty inputs", bool(baseline) and bool(candidate), "Both exports must contain records.")
    drift = abs(len(candidate) - len(baseline)) / len(baseline) * 100 if baseline else None
    check("Record count", drift is not None and drift <= max_count_drift_pct,
          f"baseline={len(baseline)}, candidate={len(candidate)}, drift_pct={drift}, limit={max_count_drift_pct}")
    check("Required record IDs", all(p["missing_or_invalid_ids"] == 0 for p in profiles),
          "Missing/invalid IDs: " + ", ".join(str(p["missing_or_invalid_ids"]) for p in profiles))
    check("Unique record IDs", all(p["duplicate_id_rows"] == 0 for p in profiles),
          "Duplicate rows: " + ", ".join(str(p["duplicate_id_rows"]) for p in profiles))
    check("Observed top-level schema", profiles[0]["schema"] == profiles[1]["schema"],
          "Compare field names, observed JSON types, and missing-field patterns; CSV values remain strings.")
    maps = [{record_key(r, key): r for r in rows if record_key(r, key) is not None} for rows in [baseline, candidate]]
    a, b = set(maps[0]), set(maps[1])
    check("Record ID coverage", a == b, f"missing={len(a-b)}, unexpected={len(b-a)}")
    compare_ignore = ignored | ({ingest_field} if ingest_field else set())
    times = [f for f in [event_field] if f]
    changed = sum(canonical(maps[0][i], compare_ignore, times) != canonical(maps[1][i], compare_ignore, times) for i in a & b)
    check("Matched record content", changed == 0, f"changed_records={changed}; arrival timestamp excluded from value comparison")
    if event_field:
        check("Valid timestamps", all(p["invalid_timestamps"] == 0 for p in profiles),
              "Invalid timestamps: " + ", ".join(str(p["invalid_timestamps"]) for p in profiles))
    if ingest_field:
        check("Non-negative arrival delay", all(p["negative_latency_rows"] == 0 for p in profiles),
              "Negative delays indicate clock or timestamp problems.")
    if max_p95_latency is not None:
        value = profiles[1]["latency_p95_seconds"]
        check("Candidate p95 arrival delay", value is not None and value <= max_p95_latency,
              f"p95_seconds={value}, limit_seconds={max_p95_latency}")
    return {"tool": "NiFi.ai Flow Validation", "version": VERSION,
            "status": "PASS" if all(c["status"] == "PASS" for c in checks) else "FAIL",
            "scope": "Exported record comparison; not a NiFi flow certification or production approval.",
            "policy": {"key": key, "event_field": event_field, "ingest_field": ingest_field,
                       "ignored_fields": sorted(ignored), "max_count_drift_pct": max_count_drift_pct,
                       "max_p95_latency_seconds": max_p95_latency},
            "baseline": profiles[0], "candidate": profiles[1], "checks": checks}


def report_html(report):
    rows = "".join("<tr><td>" + html.escape(c["check"]) + "</td><td class='" + c["status"].lower()
                   + "'>" + c["status"] + "</td><td>" + html.escape(c["detail"]) + "</td></tr>" for c in report["checks"])
    payload = html.escape(json.dumps(report, indent=2, allow_nan=False))
    return """<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NiFi.ai | Flow Validation</title><style>body{margin:0;background:#090f12;color:#eaf4f1;font:16px/1.6 system-ui}main{max-width:1100px;margin:auto;padding:40px 24px}small{color:#8fa5a0;letter-spacing:.16em}h1{font-size:44px;margin:14px 0}b{color:#65efc1}.pass{color:#65efc1}.fail{color:#ffbe70}table{width:100%;border-collapse:collapse;margin:24px 0}td,th{text-align:left;padding:14px;border-bottom:1px solid #263836}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#101c1c;padding:20px}p{max-width:800px;color:#acc0b9}section{overflow-x:auto}</style><main>
<small>NIFI.AI / OFFLINE ENGINEERING TOOL / v0.1.0</small><h1>Same records. Same outcome?</h1>
<p>Compare exported records before promoting a pipeline change. This report is generated locally with no network calls.</p>
<h2>Result: <b class='""" + report["status"].lower() + "'>" + report["status"] + "</b></h2><section><table><tr><th>Check</th><th>Result</th><th>Evidence</th></tr>" + rows + "</table></section><p>" + html.escape(report["scope"]) + "</p><details><summary>Full evidence report</summary><pre>" + payload + "</pre></details><p>Independent tooling by Lloyd Clark / Federal.AI. Not affiliated with or endorsed by the Apache Software Foundation.</p></main></html>"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--key", required=True)
    parser.add_argument("--event-field")
    parser.add_argument("--ingest-field")
    parser.add_argument("--ignore-field", action="append", default=[])
    parser.add_argument("--max-count-drift-pct", type=float, default=0)
    parser.add_argument("--max-p95-latency", type=float)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--html-out", type=Path)
    args = parser.parse_args(argv)
    try:
        outputs = [p.resolve() for p in [args.json_out, args.html_out] if p]
        inputs = [args.baseline.resolve(), args.candidate.resolve()]
        if len(outputs) != len(set(outputs)) or any(p in inputs for p in outputs):
            raise ValueError("Output paths must be distinct from each other and the input files")
        a, ahash = read_records(args.baseline)
        b, bhash = read_records(args.candidate)
        result = compare(a, b, key=args.key, event_field=args.event_field,
                         ingest_field=args.ingest_field, ignore=args.ignore_field,
                         max_count_drift_pct=args.max_count_drift_pct,
                         max_p95_latency=args.max_p95_latency)
        result["source_sha256"] = {"baseline": ahash, "candidate": bhash}
        result["generated_at_utc"] = datetime.now(timezone.utc).isoformat()
        if args.json_out:
            args.json_out.write_text(json.dumps(result, indent=2, allow_nan=False) + "\n", encoding="utf-8")
        if args.html_out:
            args.html_out.write_text(report_html(result), encoding="utf-8")
        print(result["status"] + " | " + "; ".join(c["check"] for c in result["checks"] if c["status"] == "FAIL"))
        return 0 if result["status"] == "PASS" else 1
    except (OSError, UnicodeError, ValueError, csv.Error) as error:
        print("ERROR | " + str(error))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

