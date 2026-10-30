"""Bounded record-outcome comparison for lab verification.

Adapted from the FlightDeckAI "flowcheck" comparator (MIT, see ATTRIBUTION.md and
third_party/flowcheck/LICENSE). Changes: bounded input (bytes, records, depth),
route-membership comparison per record key, and no file writes.

Invariant kept from the original: equal record counts never prove equivalence.
Missing, duplicated, misrouted or altered records fail even when totals match.
"""
from __future__ import annotations

import json
from collections import Counter
from typing import Any, Iterable

from ..core.jsonsafe import loads_bounded

MAX_RECORDS = 10_000
MAX_BYTES = 10 * 1024 * 1024


class ComparisonInputError(ValueError):
    pass


def read_records(data: bytes, *, max_records: int = MAX_RECORDS) -> list[dict]:
    """Parse a JSON array or JSON Lines document of objects with strict bounds."""
    if len(data) > MAX_BYTES:
        raise ComparisonInputError("record input exceeds the size limit")
    text = data.decode("utf-8")
    stripped = text.lstrip()
    if stripped.startswith("["):
        rows = loads_bounded(data, max_bytes=MAX_BYTES, max_depth=32)
    else:
        rows = [loads_bounded(line.encode(), max_bytes=MAX_BYTES, max_depth=32) for line in text.splitlines() if line.strip()]
    if not isinstance(rows, list) or any(not isinstance(r, dict) for r in rows):
        raise ComparisonInputError("records must be JSON objects")
    if len(rows) > max_records:
        raise ComparisonInputError("too many records")
    return rows


def _key(row: dict, key: str) -> str | None:
    value = row.get(key)
    if value is None or isinstance(value, (dict, list, bool)) or (isinstance(value, str) and not value.strip()):
        return None
    return json.dumps(value, sort_keys=True)


def _canon(row: dict, ignore: set[str]) -> str:
    return json.dumps({k: v for k, v in row.items() if k not in ignore}, sort_keys=True, separators=(",", ":"))


def compare_records(expected: list[dict], observed: list[dict], *, key: str, ignore: Iterable[str] = ()) -> dict:
    """Compare two record sets by identity, values and schema. Returns PASS/FAIL with per-check detail."""
    ignore = set(ignore)
    if key in ignore:
        raise ComparisonInputError("the record key cannot be ignored")
    checks = []

    def check(name: str, ok: bool, detail: str) -> None:
        checks.append({"check": name, "status": "PASS" if ok else "FAIL", "detail": detail})

    check("Non-empty inputs", bool(expected) and bool(observed), "both sides must contain records")
    exp_keys = [_key(r, key) for r in expected]
    obs_keys = [_key(r, key) for r in observed]
    check("Record keys present", None not in exp_keys and None not in obs_keys,
          f"missing keys: expected={exp_keys.count(None)}, observed={obs_keys.count(None)}")
    exp_counts, obs_counts = Counter(k for k in exp_keys if k), Counter(k for k in obs_keys if k)
    dup_obs = {k: c for k, c in obs_counts.items() if c > exp_counts.get(k, 0)}
    check("No unexpected duplicates", not dup_obs, f"{len(dup_obs)} key(s) observed more often than expected")
    missing = sorted(set(exp_counts) - set(obs_counts))
    extra = sorted(set(obs_counts) - set(exp_counts))
    check("Key coverage", not missing and not extra, f"missing={len(missing)}, unexpected={len(extra)}")
    exp_rows = Counter(_canon(r, ignore) for r in expected)
    obs_rows = Counter(_canon(r, ignore) for r in observed)
    changed = sum((exp_rows - obs_rows).values())
    check("Record values", exp_rows == obs_rows, f"{changed} expected record(s) not observed exactly")
    exp_schema = sorted({k for r in expected for k in r} - ignore)
    obs_schema = sorted({k for r in observed for k in r} - ignore)
    check("Field schema", exp_schema == obs_schema, f"expected fields {exp_schema}, observed {obs_schema}")
    check("Record count (informational, never sufficient alone)", len(expected) == len(observed),
          f"expected={len(expected)}, observed={len(observed)}")
    status = "PASS" if all(c["status"] == "PASS" for c in checks) else "FAIL"
    return {"status": status, "checks": checks, "key": key, "ignored_fields": sorted(ignore),
            "note": "Equal counts alone never establish equivalence."}


def compare_membership(cases: list[dict], observed: list[dict], *, key: str = "case_id",
                       extra_attributes: bool = True) -> dict:
    """Route membership per labeled case.

    cases: [{"id", "expected": [port, ...], "expected_attributes": {...}?}]
    observed: [{"case_id", "port", "attributes": {...}}] one row per FlowFile observed at an output.
    """
    expected_rows = []
    for case in cases:
        for port in case["expected"]:
            row = {key: case["id"], "port": port}
            if extra_attributes and case.get("expected_attributes"):
                row["attributes"] = case["expected_attributes"]
            expected_rows.append(row)
    observed_rows = []
    for row in observed:
        item = {key: row.get(key), "port": row.get("port")}
        if extra_attributes and any(c.get("expected_attributes") for c in cases):
            wanted = next((c.get("expected_attributes") for c in cases if c["id"] == row.get(key)), None)
            if wanted:
                item["attributes"] = {k: (row.get("attributes") or {}).get(k) for k in wanted}
        observed_rows.append(item)
    records = compare_records(expected_rows, observed_rows, key=key)
    per_case = []
    by_case_obs: dict[str, Counter] = {}
    for row in observed_rows:
        by_case_obs.setdefault(row[key], Counter())[row["port"]] += 1
    for case in cases:
        want = Counter(case["expected"])
        got = by_case_obs.get(case["id"], Counter())
        per_case.append({"case_id": case["id"], "expected": sorted(want.elements()), "observed": sorted(got.elements()),
                         "status": "PASS" if want == got else "FAIL"})
    unknown = sorted(set(by_case_obs) - {c["id"] for c in cases}, key=str)
    status = "PASS" if records["status"] == "PASS" and all(c["status"] == "PASS" for c in per_case) and not unknown else "FAIL"
    return {"status": status, "cases": per_case, "unlabeled_observations": unknown, "record_checks": records}
