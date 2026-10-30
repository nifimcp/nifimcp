"""Native lab verification of one exact Flow Draft Preview artifact.

Steps (lab only, through the boundary-checked lab client):
 1. Locate the draft's native definition, plan and static receipt in the operator's
    artifact directory and check the receipt still binds them (and the pinned catalog).
 2. Import the exact bytes into a newly created, owned harness group in the lab.
 3. Record native validation of every imported component.
 4. Run labeled positive and negative cases one at a time and capture which output
    port each record reaches (case.id attribute), then compare membership exactly.
 5. Stop, export the imported native definition, clean up, and write a lab receipt
    and report that separate static checks, observed NiFi behavior and untested claims.

A valid native import with incorrect record outcomes is reported as FAIL.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import html
import json
import os
import time
from pathlib import Path

from nifimcp.catalog import load_catalog
from nifimcp.comparator.records import compare_membership
from nifimcp.draft.examples import example_cases, example_plans
from nifimcp.draft.receipts import make_lab_receipt, verify_receipt

from .client import CLIENT_ID, LabClient

GEN = "org.apache.nifi.processors.standard.GenerateFlowFile"
SINK = "org.apache.nifi.processors.attributes.UpdateAttribute"
KEY_ATTR = "case.id"


class VerificationError(RuntimeError):
    pass


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def log(msg: str) -> None:
    import sys
    print(f"[lab-verify] {msg}", file=sys.stderr, flush=True)


def find_draft(artifact_dir: Path, artifact_id: str) -> dict:
    if not artifact_id.startswith("art_") or "/" in artifact_id or ".." in artifact_id:
        raise VerificationError("invalid artifact id")
    matches = list((artifact_dir / "sessions").glob(f"*/{artifact_id}/flow-definition.json"))
    if len(matches) != 1:
        raise VerificationError("draft artifact not found in the artifact directory")
    native_path = matches[0]
    native = native_path.read_bytes()
    native_sha = hashlib.sha256(native).hexdigest()
    session_dir = native_path.parent.parent
    receipt = plan = None
    for candidate in session_dir.glob("*/receipt.json"):
        data = json.loads(candidate.read_text())
        if data.get("native_artifact_sha256") == native_sha and data.get("kind") == "static_validation":
            receipt = data
    if receipt is None:
        raise VerificationError("no static validation receipt binds this artifact")
    for candidate in session_dir.glob("*/plan.json"):
        raw = json.loads(candidate.read_text())
        digest = hashlib.sha256(json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
        if digest == receipt["plan_sha256"]:
            plan = raw
    if plan is None:
        raise VerificationError("the plan bound by the receipt was not found or was changed")
    return {"native": native, "native_sha": native_sha, "receipt": receipt, "plan": plan, "path": native_path}


def _escape_el(value: str) -> str:
    return value.replace("$", "$$")


def _flow(c: LabClient, group: str) -> dict:
    return c.get(f"/flow/process-groups/{group}")["processGroupFlow"]["flow"]


def _native_validation(c: LabClient, child: str, plan: dict) -> dict:
    flow = _flow(c, child)
    procs = flow.get("processors", [])
    comps = []
    for p in procs:
        comp = p["component"]
        comps.append({"name": comp["name"], "type": comp["type"], "state": comp.get("state"),
                      "validation_status": comp.get("validationStatus"),
                      "validation_errors": len(comp.get("validationErrors") or [])})
    expected_procs = sorted(c_["id"] for c_ in plan["components"] if c_["kind"] == "processor")
    expected_in = sorted(c_["id"] for c_ in plan["components"] if c_["kind"] == "input_port")
    expected_out = sorted(c_["id"] for c_ in plan["components"] if c_["kind"] == "output_port")
    fidelity = {
        "processors": sorted(c_["name"] for c_ in comps) == expected_procs,
        "input_ports": sorted(p["component"]["name"] for p in flow.get("inputPorts", [])) == expected_in,
        "output_ports": sorted(p["component"]["name"] for p in flow.get("outputPorts", [])) == expected_out,
        "connections": len(flow.get("connections", [])) == len(plan["connections"]),
        "all_stopped": all(c_["state"] in ("STOPPED", "DISABLED") for c_ in comps),
    }
    props_ok = True
    for p in procs:
        comp = p["component"]
        planned = next(x for x in plan["components"] if x["id"] == comp["name"])
        actual = comp["config"]["properties"]
        for k, v in planned["properties"].items():
            if actual.get(k) != v:
                props_ok = False
    fidelity["properties_preserved"] = props_ok
    valid = all(c_["validation_status"] == "VALID" for c_ in comps)
    return {"imported": True, "components": comps, "all_valid": valid, "fidelity": fidelity,
            "status": "PASS" if valid and all(fidelity.values()) else "FAIL"}


def run_verification(lab_dir: Path, artifact_dir: Path, artifact_id: str, *, cases: dict | None,
                     keep: bool = False, out_dir: Path | None = None) -> dict:
    draft = find_draft(artifact_dir, artifact_id)
    catalog = load_catalog()
    problems = verify_receipt(draft["receipt"], plan_sha=draft["receipt"]["plan_sha256"], native_bytes=draft["native"],
                              catalog_hash=catalog["catalog_hash"], target_version="2.12.0")
    if problems:
        raise VerificationError("static receipt no longer binds the artifact: " + "; ".join(problems))
    plan = draft["plan"]
    if cases is None:
        reference = example_plans(catalog["catalog_hash"]).get(plan["blueprint"])
        if reference is None or json.dumps(reference, sort_keys=True) != json.dumps(plan, sort_keys=True):
            raise VerificationError("this plan is not a reference plan; supply --cases with labeled cases")
        cases = example_cases()[plan["blueprint"]]
    if cases.get("blueprint") != plan["blueprint"]:
        raise VerificationError("cases were written for a different blueprint")
    out_ports = sorted(c_["id"] for c_ in plan["components"] if c_["kind"] == "output_port")
    for case in cases["cases"]:
        if not set(case["expected"]) <= set(out_ports):
            raise VerificationError(f"case {case['id']} names an output port the plan does not have")
    started = _now()
    with LabClient(lab_dir) as c:
        runtime = {"nifi_version": c.get("/flow/about")["about"]["version"], "image_digest": c.manifest["image"]["digest"],
                   "lab_id": c.manifest["lab_id"], "java_version": c.manifest["runtime"]["java_version"].splitlines()[0],
                   "container_id": c.boundary_facts["container_id"]}
        drafts_group = c.manifest["fixtures"]["drafts_group_id"]
        harness = c.create_group(drafts_group, f"verify {plan['blueprint']} {draft['native_sha'][:8]} {started}", 0, 0)["id"]
        log(f"importing exact draft bytes ({draft['native_sha'][:12]}) into owned group {harness}")
        imported = c.upload_definition(harness, f"draft {draft['native_sha'][:8]}", draft["native"], x=0, y=0)
        child = imported["id"]
        native_validation = _native_validation(c, child, plan)
        cflow = _flow(c, child)
        in_port = cflow["inputPorts"][0]["id"]
        out_by_name = {p["component"]["name"]: p["id"] for p in cflow["outputPorts"]}
        gen = c.create_processor(harness, GEN, "case source", x=-500, y=0, scheduling_period="1 sec",
                                 properties={"Data Format": "Text", "Batch Size": "1", "Unique FlowFiles": "false"})
        c.connect(harness, {"id": gen["id"], "groupId": harness, "type": "PROCESSOR"},
                  {"id": in_port, "groupId": child, "type": "INPUT_PORT"}, ["success"], name="cases in")
        sink_conns = {}
        for i, name in enumerate(sorted(out_by_name)):
            sink = c.create_processor(harness, SINK, f"sink {name}", x=400 * i, y=600, auto_terminate=["success"])
            conn = c.connect(harness, {"id": out_by_name[name], "groupId": child, "type": "OUTPUT_PORT"},
                             {"id": sink["id"], "groupId": harness, "type": "PROCESSOR"}, [], name=name)
            sink_conns[name] = conn["id"]
        observations: list[dict] = []
        case_results = None
        exported_sha = None
        try:
            if native_validation["status"] == "PASS":
                c.schedule_group(child, "RUNNING")
                time.sleep(1.5)
                previous_keys: set[str] = set()
                expected_total = 0
                for case in cases["cases"]:
                    # GenerateFlowFile rejects empty Custom Text; attribute-only cases use a fixed placeholder body.
                    props = {"Custom Text": _escape_el(case.get("content") or "nifimcp-lab-case"), KEY_ATTR: case["id"]}
                    for key in previous_keys - set(case.get("attributes", {})):
                        props[key] = None
                    for key, value in case.get("attributes", {}).items():
                        props[key] = _escape_el(value)
                    previous_keys = set(case.get("attributes", {}))
                    c.update_processor(gen["id"], properties=props)
                    c.set_run_state("processor", gen["id"], "RUN_ONCE")
                    expected_total += len(case["expected"])
                    deadline = time.monotonic() + 15
                    while time.monotonic() < deadline:
                        total = sum(c.connection_queue_count(cid) for cid in sink_conns.values())
                        if total >= expected_total:
                            break
                        time.sleep(0.3)
                    time.sleep(0.4)
                time.sleep(2.0)
                c.schedule_group(child, "STOPPED")
                for port, conn_id in sink_conns.items():
                    for summary in c.list_queue(conn_id):
                        attrs = c.flowfile_attributes(conn_id, summary["uuid"])
                        observations.append({"case_id": attrs.get(KEY_ATTR), "port": port,
                                             "attributes": {k: v for k, v in attrs.items()
                                                            if k not in ("uuid", "path", "filename")}})
                case_results = compare_membership(cases["cases"], observations)
            else:
                case_results = {"status": "NOT_RUN", "reason": "native validation failed; outcomes not tested"}
            exported = c.download_definition(child)
            exported_sha = hashlib.sha256(exported).hexdigest()
        finally:
            try:
                c.schedule_group(child, "STOPPED")
            except Exception:  # noqa: BLE001
                pass
            if not keep:
                remove_harness(c, harness)
                log("harness group removed")
    overall = "PASS" if native_validation["status"] == "PASS" and case_results and case_results.get("status") == "PASS" else "FAIL"
    receipt = make_lab_receipt(static_receipt=draft["receipt"], native_bytes=draft["native"], runtime=runtime,
                               native_validation={k: native_validation[k] for k in ("status", "all_valid", "fidelity")},
                               cases={"status": case_results.get("status") if case_results else "NOT_RUN",
                                      "count": len(cases["cases"]),
                                      "failed": [x["case_id"] for x in (case_results or {}).get("cases", []) if x["status"] != "PASS"]},
                               exported_definition_sha256=exported_sha)
    result = {"verification_schema": "nifimcp-lab-verification/1", "overall": overall, "blueprint": plan["blueprint"],
              "artifact_id": artifact_id, "native_artifact_sha256": draft["native_sha"],
              "plan_sha256": draft["receipt"]["plan_sha256"], "catalog_hash": draft["receipt"]["catalog_hash"],
              "runtime": runtime, "started_at": started, "finished_at": _now(),
              "performed_by": {"tool": "nifimcp lab CLI (scripts/lab_verify_draft.py), not the MCP server",
                               "identity": c.manifest["pki"]["identities"]["admin"]["dn"],
                               "write_route": "POST /process-groups/{id}/process-groups/upload into the lab's drafts group",
                               "target": "disposable lab container verified by ID, label, image digest and TLS pin"},
              "static_checks": {"stage": draft["receipt"]["validation_stage"], "receipt_sha256": draft["receipt"]["receipt_sha256"]},
              "native_validation": native_validation, "cases": case_results, "observations": observations,
              "exported_definition_sha256": exported_sha, "lab_receipt": receipt,
              "untested": ["Behavior on any NiFi other than stock 2.12.0 in this lab",
                           "Records, attribute values or content shapes not covered by the labeled cases",
                           "Throughput, latency and back-pressure behavior", "Clustered or load-balanced operation",
                           "Downstream systems connected to the output ports"],
              "statement": "Evidence about this exact artifact in a disposable lab. Not permission to deploy it."}
    out_dir = out_dir or (artifact_dir / "lab-results" / draft["native_sha"][:16])
    out_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(out_dir, 0o700)
    for name, data in (("lab-verification.json", json.dumps(result, indent=1, sort_keys=True) + "\n"),
                       ("lab-receipt.json", json.dumps(receipt, indent=1, sort_keys=True) + "\n"),
                       ("lab-report.html", render_report(result))):
        path = out_dir / name
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(data)
    result["outputs"] = str(out_dir)
    return result


def remove_harness(c: LabClient, harness: str) -> None:
    """Stop, drain and delete an owned harness group (lab only)."""
    c.schedule_group(harness, "STOPPED")
    time.sleep(0.5)
    status = c.get(f"/flow/process-groups/{harness}/status", params={"recursive": "true"})
    stack = [status["processGroupStatus"]["aggregateSnapshot"]]
    while stack:
        snap = stack.pop()
        for cs in snap.get("connectionStatusSnapshots", []):
            if cs["connectionStatusSnapshot"].get("flowFilesQueued"):
                c.empty_queue(cs["connectionStatusSnapshot"]["id"])
        stack.extend(g["processGroupStatusSnapshot"] for g in snap.get("processGroupStatusSnapshots", []))
    c.delete_group(harness)


def remove_all_harnesses(c: LabClient) -> int:
    drafts = c.manifest["fixtures"]["drafts_group_id"]
    groups = c.get(f"/flow/process-groups/{drafts}")["processGroupFlow"]["flow"]["processGroups"]
    for g in groups:
        remove_harness(c, g["id"])
    return len(groups)


def render_report(result: dict) -> str:
    e = lambda v: html.escape("" if v is None else str(v), quote=True)  # noqa: E731
    nv = result["native_validation"]
    comp_rows = "".join(f"<tr><td>{e(c['name'])}</td><td>{e(c['type'].rsplit('.', 1)[-1])}</td><td>{e(c['state'])}</td>"
                        f"<td>{e(c['validation_status'])}</td><td>{e(c['validation_errors'])}</td></tr>" for c in nv["components"])
    case_rows = "".join(f"<tr class={'ok' if x['status'] == 'PASS' else 'bad'}><td>{e(x['case_id'])}</td>"
                        f"<td>{e(', '.join(x['expected']))}</td><td>{e(', '.join(x['observed']) or '(none)')}</td>"
                        f"<td>{e(x['status'])}</td></tr>" for x in (result["cases"] or {}).get("cases", []))
    fidelity = "".join(f"<li>{e(k)}: {'yes' if v else 'NO'}</li>" for k, v in nv["fidelity"].items())
    untested = "".join(f"<li>{e(u)}</li>" for u in result["untested"])
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>NiFiMCP lab verification</title>
<style>body{{font:15px/1.5 system-ui,sans-serif;max-width:1000px;margin:auto;padding:24px 16px;color:#16232a;background:#fff}}
table{{border-collapse:collapse;width:100%}}td,th{{border-bottom:1px solid #d5dde1;padding:6px;text-align:left}}
.ok td:last-child{{color:#0b6e69;font-weight:600}}.bad td:last-child{{color:#a1262b;font-weight:600}}
.verdict{{font-size:22px;font-weight:700}}code{{font:12.5px ui-monospace,monospace;overflow-wrap:anywhere}}</style></head><body>
<h1>Flow Draft Preview: native lab verification</h1>
<p class=verdict>Overall: {e(result['overall'])}</p>
<p>Blueprint {e(result['blueprint'])} · artifact <code>{e(result['artifact_id'])}</code> · native sha256
<code>{e(result['native_artifact_sha256'])}</code> · NiFi {e(result['runtime']['nifi_version'])} image
<code>{e(result['runtime']['image_digest'])}</code> · lab {e(result['runtime']['lab_id'])} · {e(result['finished_at'])}</p>
<h2>1. Static checks (before the lab)</h2><p>Validation stage {e(result['static_checks']['stage'])}; static receipt
<code>{e(result['static_checks']['receipt_sha256'])}</code>.</p>
<h2>2. Observed NiFi behavior</h2><h3>Native import and validation: {e(nv['status'])}</h3>
<table><tr><th>Component</th><th>Type</th><th>State</th><th>NiFi validation</th><th>Errors</th></tr>{comp_rows}</table>
<ul>{fidelity}</ul>
<h3>Labeled cases: {e((result['cases'] or {}).get('status'))}</h3>
<table><tr><th>Case</th><th>Expected outputs</th><th>Observed outputs</th><th>Result</th></tr>{case_rows}</table>
<p>Exported definition after the run: <code>{e(result['exported_definition_sha256'])}</code></p>
<h2>3. Model-generated interpretation</h2><p>None. This report contains no model output.</p>
<h2>4. Untested claims</h2><ul>{untested}</ul>
<p><strong>{e(result['statement'])}</strong></p></body></html>
"""
