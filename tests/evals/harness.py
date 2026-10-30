"""Materializes corpus cases as offline bundles, runs the deterministic tools and checks labels.

This evaluates the deterministic rules and envelope contracts only. It is not a model evaluation.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import anyio

from nifimcp.artifacts import ArtifactStore
from nifimcp.config import OperatorConfig
from nifimcp.core.evidence import verify_citation
from nifimcp.service import Service, Session, call_tool, register_input

SCOPE = "eval-scope"
COLLECTED_AT = "2026-10-29T02:00:00.000Z"
SEVERITY_ORDER = {"info": 0, "review": 1, "warning": 2, "error": 3}


def _raw(doc) -> bytes:
    return (json.dumps(doc, indent=1, sort_keys=True) + "\n").encode()


def _group_id(doc: dict) -> str:
    if "flowContents" in doc:
        return doc["flowContents"]["instanceIdentifier"]
    return doc["processGroupFlow"]["id"]


def materialize(case: dict, folder: Path) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    files = []

    def add(name, kind, doc, interval=None):
        data = _raw(doc)
        (folder / name).write_bytes(data)
        entry = {"path": name, "kind": kind, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data),
                 "collected_at": COLLECTED_AT, "node_id": "standalone"}
        if interval:
            entry["interval"] = interval
        files.append(entry)

    add("flow-definition.json", "flow_definition", case["flow"])
    for name, (kind, doc, interval) in case["extra_files"].items():
        if kind == "operator_notes":
            doc = json.loads(json.dumps(doc))
            for note in doc["notes"]:
                if note["source_sha256"] == "bind":
                    note["source_sha256"] = files[0]["sha256"]
        add(name, kind, doc, interval)
    manifest = {
        "bundle_schema": "nifimcp-bundle/1", "bundle_id": "eval-" + case["id"].lower(), "created_at": COLLECTED_AT,
        "collector": {"name": "nifimcp-eval-corpus", "version": "1"},
        "nifi": {"version": "2.12.0", "profile": "synthetic evaluation case"},
        "declared_scope": {"scope_id": SCOPE, "process_group_id": _group_id(case["flow"])},
        "nodes": [{"node_id": "standalone", "included": True}],
        "source_kinds": sorted({f["kind"] for f in files}), "files": files,
        "redaction": {"policy": "synthetic", "sensitive_values_present": False},
        "completeness": {"status": "complete", "missing": []},
    }
    manifest.update(case["manifest_overrides"])
    (folder / "manifest.json").write_bytes(_raw(manifest))
    return folder


def run_case(case: dict, workdir: Path) -> list[dict]:
    bundle = materialize(case, workdir / "bundle")
    cfg = OperatorConfig.model_validate({"schema_version": "1", "mode": "bundle",
                                         "artifact_dir": str(workdir / "art"), "base_dir": str(workdir)})
    store = ArtifactStore(cfg.artifact_path, cfg.retention_days)
    register_input(cfg, store, bundle, "bundle", "eval")
    service = Service(Session(cfg))
    outputs = []
    for tool, args in case["calls"]:
        args = dict(args)
        if tool in ("describe_flow", "get_flow_health", "trace_feed") and "scope_id" not in args:
            args["scope_id"] = SCOPE
        outputs.append(anyio.run(call_tool, service, tool, args))
    return outputs


# A forbidden pattern counts only when asserted. A sentence that negates it before the match
# ("does not prove the data never existed") is the qualified form the contract requires.
NEGATION = re.compile(r"\b(not|cannot|can't|doesn't|does not|is not|without|no evidence)\b", re.IGNORECASE)


def sentences(texts: list[str]) -> list[str]:
    out = []
    for t in texts:
        out.extend(x for x in re.split(r"(?<=[.!?])\s+", t) if x)
    return out


def statements(env: dict) -> list[str]:
    out = []
    for f in env.get("findings") or []:
        out.append(f.get("statement") or "")
        out.extend(f.get("limitations") or [])
    for g in env.get("gaps") or []:
        out.append(g.get("detail") or "")
    if env.get("error"):
        out.append(env["error"].get("message") or "")
        out.append(env["error"].get("next_step") or "")
    return out


def _finding_ids(envs):
    return [f["finding_id"] for e in envs for f in e.get("findings") or []]


def _matching(envs, prefix):
    return [f for e in envs for f in e.get("findings") or []
            if f["finding_id"] == prefix or f["finding_id"].startswith(prefix + ":") or f["finding_id"].startswith(prefix)]


def citations_valid(env: dict, bundle_dir: Path) -> tuple[int, int]:
    """Exact-reference check: each cited evidence record must exist in the envelope, its source hash must equal
    the bundle file's bytes and its JSON pointer must resolve in that file."""
    by_id = {e["evidence_id"]: e for e in env.get("evidence") or []}
    total = ok = 0
    for f in env.get("findings") or []:
        for eid in f.get("evidence_ids") or []:
            total += 1
            rec = by_id.get(eid)
            if rec is None or not str(rec.get("source_id", "")).startswith("bundle:"):
                continue
            path = bundle_dir / rec["source_id"].split(":", 1)[1]
            if path.parent != bundle_dir or not path.is_file():
                continue
            try:
                verify_citation(rec, path.read_bytes())
                ok += 1
            except Exception:  # noqa: BLE001 - an invalid citation counts as a failure
                pass
    return ok, total


def check(case: dict, envs: list[dict], global_forbidden: list[str]) -> list[str]:
    """Return a list of label violations (empty when the case passes)."""
    problems = []
    text = [s for e in envs for s in statements(e)]
    for req in case["required"]:
        if "finding" in req:
            hits = _matching(envs, req["finding"])
            if not hits:
                problems.append(f"missing finding {req['finding']} (have {_finding_ids(envs)})")
                continue
            if "kind" in req and not any(h["kind"] == req["kind"] for h in hits):
                problems.append(f"finding {req['finding']} kind != {req['kind']}")
            if "severity" in req and not any(h["severity"] == req["severity"] for h in hits):
                problems.append(f"finding {req['finding']} severity != {req['severity']} "
                                f"({[h['severity'] for h in hits]})")
        elif "no_finding" in req:
            if _matching(envs, req["no_finding"]):
                problems.append(f"unexpected finding {req['no_finding']}")
        elif "gap" in req:
            if not any(g["code"] == req["gap"] for e in envs for g in e.get("gaps") or []):
                problems.append(f"missing gap {req['gap']} (have {[g['code'] for e in envs for g in e.get('gaps') or []]})")
        elif "no_gap" in req:
            if any(g["code"] == req["no_gap"] for e in envs for g in e.get("gaps") or []):
                problems.append(f"unexpected gap {req['no_gap']}")
        elif "error" in req:
            if not any((e.get("error") or {}).get("code") == req["error"] for e in envs):
                problems.append(f"missing error {req['error']} (have {[(e.get('error') or {}).get('code') for e in envs]})")
        elif "status" in req:
            if not any(e.get("status") == req["status"] for e in envs):
                problems.append(f"no envelope with status {req['status']} ({[e.get('status') for e in envs]})")
        elif "envelope_scope" in req:
            if not all(e.get("scope") == req["envelope_scope"] for e in envs):
                problems.append(f"envelope scope is not {req['envelope_scope']}: {[e.get('scope') for e in envs]}")
        elif "text" in req:
            if not any(req["text"].lower() in s.lower() for s in text):
                problems.append(f"no statement mentions {req['text']!r}")
        elif "limitation" in req:
            lims = [x for e in envs for f in e.get("findings") or [] for x in f.get("limitations") or []]
            lims += [g.get("detail") or "" for e in envs for g in e.get("gaps") or []]
            if not any(req["limitation"].lower() in s.lower() for s in lims):
                problems.append(f"no limitation mentions {req['limitation']!r}")
        elif "events" in req:
            counts = [(e.get("data") or {}).get("events") for e in envs
                      if isinstance((e.get("data") or {}).get("events"), int)]
            if req["events"] not in counts:
                problems.append(f"event count {counts} != {req['events']}")
        elif "max_severity" in req:
            limit = SEVERITY_ORDER[req["max_severity"]]
            worst = [(f["finding_id"], f["severity"]) for e in envs for f in e.get("findings") or []
                     if SEVERITY_ORDER.get(f["severity"], 9) > limit]
            if worst:
                problems.append(f"findings above {req['max_severity']}: {worst}")
        else:
            problems.append(f"unknown label {req}")
    for pattern in list(case["forbidden"]) + list(global_forbidden):
        rx = re.compile(pattern, re.IGNORECASE)
        for sentence in sentences(text):
            m = rx.search(sentence)
            if m and not NEGATION.search(sentence[:m.start()]):
                problems.append(f"forbidden claim /{pattern}/ in: {sentence[:160]}")
    return problems
