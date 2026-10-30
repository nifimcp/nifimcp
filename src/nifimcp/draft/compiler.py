"""Compile a validated FlowPlan into a stopped native NiFi 2.12.0 flow definition.

The compiler works only from the submitted plan: different plans yield different
graphs, and the same plan always yields byte-identical output. Component
identifiers are UUIDv5 values derived from the canonical plan hash and a fixed
draft namespace. Nothing is deployed; artifacts are written to the private
workspace only.
"""
from __future__ import annotations

import html
import json
import uuid
from collections import defaultdict, deque

from .. import __version__
from ..errors import ErrorCode, NiFiMCPError
from ..models import FlowPlan
from ..util import iso, sha256_hex, utc_now
from .receipts import make_static_receipt
from .validate import PORT_REL, plan_hash, validate_plan

DRAFT_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/FlightDeckAI/nifimcp/flow-draft-preview/v1")


class DraftValidationError(NiFiMCPError):
    def __init__(self, report: dict):
        super().__init__(ErrorCode.VALIDATION_FAILED,
                         f"plan failed static validation at stage '{report['stage_reached']}' "
                         f"with {len(report['errors'])} error(s)",
                         "Fix the errors listed in data.validation and call validate_flow_plan again.")
        self.report = report


def _layout(plan: FlowPlan) -> dict[str, tuple[float, float]]:
    outgoing = defaultdict(list)
    for c in sorted(plan.connections, key=lambda c: c.id):
        outgoing[c.source].append(c.destination)
    rank: dict[str, int] = {}
    starts = sorted(c.id for c in plan.components if c.kind == "input_port")
    queue = deque((s, 0) for s in starts)
    while queue:
        node, r = queue.popleft()
        if rank.get(node, -1) >= r:
            continue
        rank[node] = r
        for nxt in outgoing[node]:
            queue.append((nxt, r + 1))
    rows: dict[int, int] = defaultdict(int)
    pos = {}
    for comp in sorted(plan.components, key=lambda c: (rank.get(c.id, 0), c.id)):
        r = rank.get(comp.id, 0)
        pos[comp.id] = (float(rows[r] * 420), float(r * 220))
        rows[r] += 1
    return pos


def build_native(plan: FlowPlan, catalog: dict) -> tuple[dict, dict[str, str]]:
    digest = plan_hash(plan)
    ns = uuid.uuid5(DRAFT_NAMESPACE, digest)
    ids = {c.id: str(uuid.uuid5(ns, "component:" + c.id)) for c in plan.components}
    group_id = str(uuid.uuid5(ns, "group"))
    entries = {e["type_id"]: e for e in catalog["entries"]}
    pos = _layout(plan)
    processors, inputs, outputs = [], [], []
    for comp in sorted(plan.components, key=lambda c: c.id):
        x, y = pos[comp.id]
        if comp.kind == "processor":
            entry = entries[comp.type_id]
            props = {k: v["default"] for k, v in entry["properties"].items() if v.get("default") is not None}
            props.update(comp.properties)
            descriptors = {k: {"name": k, "displayName": entry["properties"].get(k, {}).get("display_name") or k,
                               "identifiesControllerService": False, "sensitive": False,
                               "dynamic": k not in entry["properties"]} for k in sorted(props)}
            processors.append({
                "identifier": ids[comp.id], "name": comp.id, "comments": "", "position": {"x": x, "y": y},
                "type": comp.type_id, "bundle": dict(entry["bundle"]),
                "properties": dict(sorted(props.items())), "propertyDescriptors": descriptors, "style": {},
                "schedulingPeriod": entry.get("default_scheduling_period") or "0 sec",
                "schedulingStrategy": "TIMER_DRIVEN", "executionNode": "ALL",
                "penaltyDuration": entry.get("default_penalty_duration") or "30 sec",
                "yieldDuration": entry.get("default_yield_duration") or "1 sec",
                "bulletinLevel": entry.get("default_bulletin_level") or "WARN", "runDurationMillis": 0,
                "concurrentlySchedulableTaskCount": 1,
                "autoTerminatedRelationships": sorted(comp.auto_terminated_relationships),
                "scheduledState": "ENABLED", "retryCount": 10, "retriedRelationships": [],
                "backoffMechanism": "PENALIZE_FLOWFILE", "maxBackoffPeriod": "10 mins",
                "componentType": "PROCESSOR", "groupIdentifier": group_id,
            })
        else:
            port_type = "INPUT_PORT" if comp.kind == "input_port" else "OUTPUT_PORT"
            (inputs if comp.kind == "input_port" else outputs).append({
                "identifier": ids[comp.id], "name": comp.id, "position": {"x": x, "y": y}, "type": port_type,
                "concurrentlySchedulableTaskCount": 1, "scheduledState": "ENABLED", "allowRemoteAccess": False,
                "portFunction": "STANDARD", "componentType": port_type, "groupIdentifier": group_id,
            })
    kinds = {c.id: c.kind for c in plan.components}
    ctype = {"processor": "PROCESSOR", "input_port": "INPUT_PORT", "output_port": "OUTPUT_PORT"}
    connections = []
    for conn in sorted(plan.connections, key=lambda c: c.id):
        def end(cid: str) -> dict:
            return {"id": ids[cid], "type": ctype[kinds[cid]], "groupId": group_id, "name": cid, "comments": ""}
        connections.append({
            "identifier": str(uuid.uuid5(ns, "connection:" + conn.id)), "name": conn.id,
            "source": end(conn.source), "destination": end(conn.destination), "labelIndex": 1, "zIndex": 0,
            "selectedRelationships": [] if conn.relationship == PORT_REL else [conn.relationship],
            "backPressureObjectThreshold": 10000, "backPressureDataSizeThreshold": "1 GB",
            "flowFileExpiration": "0 sec", "prioritizers": [], "bends": [],
            "loadBalanceStrategy": "DO_NOT_LOAD_BALANCE", "partitioningAttribute": "",
            "loadBalanceCompression": "DO_NOT_COMPRESS", "componentType": "CONNECTION",
            "groupIdentifier": group_id,
        })
    flow_contents = {
        "identifier": group_id, "name": f"NiFiMCP draft {plan.blueprint} {digest[:8]}",
        "comments": ("Flow Draft Preview (experimental). Compiled by NiFiMCP from plan sha256 " + digest
                     + ". Not deployed. All components are stopped. Review and test in a lab before any use."),
        "position": {"x": 0.0, "y": 0.0}, "processGroups": [], "remoteProcessGroups": [],
        "processors": processors, "inputPorts": inputs, "outputPorts": outputs, "connections": connections,
        "labels": [], "funnels": [], "controllerServices": [],
        "defaultFlowFileExpiration": "0 sec", "defaultBackPressureObjectThreshold": 10000,
        "defaultBackPressureDataSizeThreshold": "1 GB", "scheduledState": "ENABLED", "executionEngine": "INHERITED",
        "maxConcurrentTasks": 1, "statelessFlowTimeout": "1 min", "flowFileConcurrency": "UNBOUNDED",
        "flowFileOutboundPolicy": "STREAM_WHEN_AVAILABLE", "componentType": "PROCESS_GROUP",
    }
    contexts = {}
    if plan.parameter_references:
        ctx_name = f"nifimcp-draft-{digest[:12]}"
        flow_contents["parameterContextName"] = ctx_name
        contexts[ctx_name] = {
            "name": ctx_name, "description": "Unresolved parameters declared by a NiFiMCP draft; set values in NiFi.",
            "parameters": [{"name": p.name, "description": "", "sensitive": p.sensitive, "provided": False}
                           for p in sorted(plan.parameter_references, key=lambda p: p.name)],
            "inheritedParameterContexts": [], "componentType": "PARAMETER_CONTEXT",
        }
    native = {"flowContents": flow_contents, "externalControllerServices": {}, "parameterContexts": contexts,
              "flowEncodingVersion": "1.0", "parameterProviders": {}, "latest": False}
    return native, ids


def native_bytes(native: dict) -> bytes:
    return (json.dumps(native, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def review_html(plan: FlowPlan, report: dict, native_sha: str, ids: dict[str, str]) -> str:
    e = lambda v: html.escape("" if v is None else str(v), quote=True)  # noqa: E731
    rows = "".join(
        f"<tr><td>{e(c.id)}</td><td>{e(c.kind)}</td><td>{e(c.type_id.rsplit('.', 1)[-1])}</td>"
        f"<td><code>{e(ids[c.id])}</code></td><td><ul>"
        + "".join(f"<li><strong>{e(k)}</strong>: <code>{e(v)}</code></li>" for k, v in sorted(c.properties.items()))
        + f"</ul></td><td>{e(', '.join(c.auto_terminated_relationships) or '-')}</td></tr>"
        for c in sorted(plan.components, key=lambda c: c.id))
    conns = "".join(f"<tr><td>{e(c.id)}</td><td>{e(c.source)}</td><td>{e(c.relationship)}</td><td>{e(c.destination)}</td></tr>"
                    for c in sorted(plan.connections, key=lambda c: c.id))
    exps = "".join(f"<li><strong>{e(x.port_id)}</strong>: {e(x.condition)}</li>" for x in plan.output_expectations)
    warns = "".join(f"<li>{e(w['code'])} at {e(w['path'])}: {e(w['message'])}</li>" for w in report["warnings"]) or "<li>None</li>"
    unknowns = "".join(f"<li>{e(u['code'])}: {e(u['detail'])}</li>" for u in report["unknowns"])
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>NiFiMCP draft review</title>
<style>body{{font:15px/1.5 system-ui,sans-serif;max-width:1100px;margin:auto;padding:24px 16px;color:#16232a;background:#fff}}
table{{border-collapse:collapse;width:100%}}td,th{{border-bottom:1px solid #d5dde1;padding:6px;text-align:left;vertical-align:top}}
.banner{{background:#fff1dd;border:1px solid #e0b46a;padding:10px 14px;border-radius:6px}}code{{font:12.5px ui-monospace,monospace;overflow-wrap:anywhere}}</style>
</head><body><h1>Flow Draft Preview: review report</h1>
<p class=banner><strong>EXPERIMENTAL. NOT DEPLOYED.</strong> Static checks passed at stage {e(report['stage_reached'])}.
Native importability and record outcomes are unknown until the separate lab verification runs on this exact artifact.
A receipt is evidence about this artifact, not permission to deploy it.</p>
<p>Blueprint <strong>{e(plan.blueprint)}</strong> · target NiFi {e(plan.target_version)} · plan sha256 <code>{e(report['plan_sha256'])}</code>
· native artifact sha256 <code>{e(native_sha)}</code> · catalog <code>{e(plan.catalog_hash)}</code></p>
<h2>Intent (host-supplied text)</h2><p>{e(plan.intent)}</p>
<h2>Components</h2><table><tr><th>Logical id</th><th>Kind</th><th>Type</th><th>Draft UUID</th><th>Properties (preserved, not evaluated)</th><th>Auto-terminated</th></tr>{rows}</table>
<h2>Connections</h2><table><tr><th>Id</th><th>Source</th><th>Relationship</th><th>Destination</th></tr>{conns}</table>
<h2>Declared output expectations</h2><ul>{exps or '<li>None declared</li>'}</ul>
<h2>Warnings</h2><ul>{warns}</ul><h2>Unknown until lab verification</h2><ul>{unknowns}</ul>
</body></html>
"""


def graph_of(plan: FlowPlan, ids: dict[str, str]) -> dict:
    return {"nodes": [{"id": c.id, "uuid": ids[c.id], "kind": c.kind, "type": c.type_id.rsplit(".", 1)[-1]}
                      for c in sorted(plan.components, key=lambda c: c.id)],
            "edges": [{"id": c.id, "source": c.source, "relationship": c.relationship, "destination": c.destination}
                      for c in sorted(plan.connections, key=lambda c: c.id)]}


def compile_draft(plan: FlowPlan, catalog: dict, store, session_id: str) -> dict:
    report = validate_plan(plan, catalog)
    if not report["valid"]:
        raise DraftValidationError(report)
    native, ids = build_native(plan, catalog)
    data = native_bytes(native)
    native_sha = sha256_hex(data)
    plan_doc = (json.dumps(plan.model_dump(mode="json"), indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()
    receipt = make_static_receipt(plan_sha=report["plan_sha256"], native_sha=native_sha,
                                  catalog_hash=catalog["catalog_hash"], target_version=plan.target_version,
                                  report=report, server_version=__version__)
    label = f"{plan.blueprint} {report['plan_sha256'][:8]}"
    recs = {
        "native_flow_definition": store.put(session_id, "draft", data, filename="flow-definition.json",
                                            media_type="application/json", label=f"Native draft {label}", scope="draft"),
        "plan": store.put(session_id, "draft", plan_doc, filename="plan.json", media_type="application/json",
                          label=f"Plan {label}", scope="draft"),
        "review_report": store.put(session_id, "draft", review_html(plan, report, native_sha, ids).encode(),
                                   filename="review.html", media_type="text/html", label=f"Review {label}", scope="draft"),
        "validation_receipt": store.put(session_id, "draft_receipt",
                                        (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode(),
                                        filename="receipt.json", media_type="application/json",
                                        label=f"Static receipt {label}", scope="draft"),
    }
    return {
        "experimental": True,
        "deployed": False,
        "all_components_stopped": True,
        "plan_sha256": report["plan_sha256"],
        "native_artifact_sha256": native_sha,
        "catalog_hash": catalog["catalog_hash"],
        "target_version": plan.target_version,
        "draft_uuids": ids,
        "graph": graph_of(plan, ids),
        "validation": report,
        "receipt": receipt,
        "artifacts": {k: v.public() for k, v in recs.items()},
        "next_step": ("Operator, lab only: uv run python scripts/lab_verify_draft.py --artifact-dir <artifact_dir> "
                      f"--artifact-id {recs['native_flow_definition'].artifact_id} --cases <cases.json>. "
                      "NiFiMCP never imports drafts into a live target."),
        "created_at": iso(utc_now()),
    }
