#!/usr/bin/env python3
"""Build the packaged synthetic demo bundle from a real, owned NiFi 2.12.0 lab.

The flow, its status, bulletins, provenance and queue metadata are produced by
stock NiFi 2.12.0 running synthetic data. Planted canary strings (prefix
``DEMO-CANARY-``) let tests prove that secrets never reach outputs.

    uv run python scripts/lab_bootstrap.py --create-owned-lab
    uv run python scripts/build_demo_bundle.py

Writes src/nifimcp/demo_data/telemetry-intake/ (directory bundle) and
src/nifimcp/demo_data/telemetry-intake-candidate.json (changed snapshot for diff).
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import shutil
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lab"))

from nifimcp_lab.bootstrap import current_lab_dir  # noqa: E402
from nifimcp_lab.client import CLIENT_ID, LabClient  # noqa: E402

GEN = "org.apache.nifi.processors.standard.GenerateFlowFile"
UPDATE = "org.apache.nifi.processors.attributes.UpdateAttribute"
ROUTE = "org.apache.nifi.processors.standard.RouteOnAttribute"
EJP = "org.apache.nifi.processors.standard.EvaluateJsonPath"
LOGATTR = "org.apache.nifi.processors.standard.LogAttribute"
INVOKE = "org.apache.nifi.processors.standard.InvokeHTTP"
PUTFILE = "org.apache.nifi.processors.standard.PutFile"
OUT = ROOT / "src/nifimcp/demo_data"
BUNDLE_DIR = OUT / "telemetry-intake"


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def ref(entity, group, kind):
    return {"id": entity["id"], "groupId": group, "type": kind}


DEMO_NAME = "Telemetry Intake (synthetic demo)"


def cleanup(c: LabClient) -> None:
    """Remove a previous demo group and parameter context from this owned lab."""
    root = c.root_id()
    flow = c.get(f"/flow/process-groups/{root}")["processGroupFlow"]["flow"]
    for group in flow.get("processGroups", []):
        if group["component"]["name"] != DEMO_NAME:
            continue
        gid = group["id"]
        c.schedule_group(gid, "STOPPED")
        time.sleep(2)
        status = c.get(f"/flow/process-groups/{gid}/status", params={"recursive": "true"})

        def conns(snap):
            for cs in snap.get("connectionStatusSnapshots", []):
                yield cs["connectionStatusSnapshot"]["id"]
            for sg in snap.get("processGroupStatusSnapshots", []):
                yield from conns(sg["processGroupStatusSnapshot"])
        for cid in conns(status["processGroupStatus"]["aggregateSnapshot"]):
            c.empty_queue(cid)
        c.delete_group(gid)
    for ctx in c.get("/flow/parameter-contexts").get("parameterContexts", []):
        if ctx.get("component", {}).get("name") == "telemetry-intake":
            c.request("DELETE", f"/parameter-contexts/{ctx['id']}",
                      params={"version": ctx["revision"]["version"], "clientId": CLIENT_ID})


def build(c: LabClient) -> dict:
    cleanup(c)
    root = c.root_id()
    ctx = c.request("POST", "/parameter-contexts", json_body={
        "revision": {"version": 0, "clientId": CLIENT_ID},
        "component": {"name": "telemetry-intake", "description": "Synthetic demo parameters",
                      "parameters": [
                          {"parameter": {"name": "routing.critical.level", "sensitive": False, "value": "critical"}},
                          {"parameter": {"name": "archive.directory", "sensitive": False, "value": "/tmp/nifimcp-demo-archive"}},
                          {"parameter": {"name": "splunk.hec.token", "sensitive": True, "value": "DEMO-CANARY-HEC-TOKEN-0001"}},
                      ]},
    })
    top = c.create_group(root, DEMO_NAME, 1800, 0)["id"]
    entity = c.get(f"/process-groups/{top}")
    c.request("PUT", f"/process-groups/{top}", json_body={
        "revision": c.revision(entity),
        "component": {"id": top, "parameterContext": {"id": ctx["id"]}},
    })
    intake = c.create_group(top, "Intake", 0, 0)["id"]
    normalize = c.create_group(top, "Normalize", 0, 350)["id"]
    route = c.create_group(top, "Route and deliver", 0, 700)["id"]
    for gid in (intake, normalize, route):
        ent = c.get(f"/process-groups/{gid}")
        c.request("PUT", f"/process-groups/{gid}", json_body={
            "revision": c.revision(ent), "component": {"id": gid, "parameterContext": {"id": ctx["id"]}}})

    gen = c.create_processor(intake, GEN, "Synthetic sensor feed", x=0, y=0, scheduling_period="400 ms", properties={
        "Custom Text": '{"level":"${random():mod(4):equals(0):ifElse(\'critical\', ${random():mod(3):equals(0):ifElse(\'warning\', ${random():mod(2):equals(0):ifElse(\'info\',\'diagnostic\')})})}","sensor":"sensor-${random():mod(5)}","synthetic":true}',
        "filename": "telemetry-${nextInt()}.json",
        "mime.type": "application/json",
    })
    tag = c.create_processor(intake, UPDATE, "Tag source", x=0, y=250, properties={
        "source.system": "lab-sensors",
        "feed.owner": "telemetry-team",
        "api.key": "DEMO-CANARY-LITERAL-KEY-0002",
        "upstream.url": "https://ingest-user:DEMO-CANARY-USERINFO-0004@collector.example.invalid/feed",
    })
    out_i = c.create_port(intake, "output", "to-normalize", x=0, y=500)
    c.connect(intake, ref(gen, intake, "PROCESSOR"), ref(tag, intake, "PROCESSOR"), ["success"], name="generated")
    c.connect(intake, ref(tag, intake, "PROCESSOR"), ref(out_i, intake, "OUTPUT_PORT"), ["success"], name="tagged")

    in_n = c.create_port(normalize, "input", "from-intake", x=0, y=0)
    ejp = c.create_processor(normalize, EJP, "Extract level and sensor", x=0, y=250, auto_terminate=["unmatched"],
                             properties={"Destination": "flowfile-attribute", "event.level": "$.level",
                                         "sensor.id": "$.sensor"})
    fail_log = c.create_processor(normalize, LOGATTR, "Log parse failures", x=400, y=250, auto_terminate=["success"])
    out_n = c.create_port(normalize, "output", "to-route", x=0, y=500)
    c.connect(normalize, ref(in_n, normalize, "INPUT_PORT"), ref(ejp, normalize, "PROCESSOR"), [], name="raw events")
    c.connect(normalize, ref(ejp, normalize, "PROCESSOR"), ref(fail_log, normalize, "PROCESSOR"), ["failure"],
              name="parse failures")
    c.connect(normalize, ref(ejp, normalize, "PROCESSOR"), ref(out_n, normalize, "OUTPUT_PORT"), ["matched"],
              name="normalized")

    in_r = c.create_port(route, "input", "from-normalize", x=0, y=0)
    router = c.create_processor(route, ROUTE, "Route by level", x=0, y=250, properties={
        "critical": "${event.level:equals('critical')}",
        "warning": "${event.level:equals('warning')}",
    })
    hec = c.create_processor(route, INVOKE, "Deliver to Splunk HEC", x=-450, y=550,
                             auto_terminate=["Original", "Response", "Retry", "No Retry", "Failure"], properties={
                                 "HTTP Method": "POST",
                                 "HTTP URL": "http://splunk.example.invalid:8088/services/collector",
                                 "Request Username": "demo-hec",
                                 "Request Password": "#{splunk.hec.token}",
                                 "X-Debug-Token": "Bearer DEMO-CANARY-BEARER-TOKEN-00000003",
                             })
    archive = c.create_processor(route, PUTFILE, "Archive critical copy", x=-450, y=850,
                                 auto_terminate=["success", "failure"],
                                 properties={"Directory": "#{archive.directory}", "Conflict Resolution Strategy": "replace"})
    warn_log = c.create_processor(route, LOGATTR, "Deliver warnings", x=0, y=550, auto_terminate=["success"],
                                  scheduling_period="0 sec",
                                  properties={"Log Level": "debug", "Log prefix": "#{warning.log.prefix}"})
    review = c.create_processor(route, UPDATE, "Unmatched review", x=450, y=550, auto_terminate=["success"])
    c.connect(route, ref(in_r, route, "INPUT_PORT"), ref(router, route, "PROCESSOR"), [], name="routable events")
    c.connect(route, ref(router, route, "PROCESSOR"), ref(hec, route, "PROCESSOR"), ["critical"],
              name="critical to HEC", expiration="5 min")
    c.connect(route, ref(router, route, "PROCESSOR"), ref(archive, route, "PROCESSOR"), ["critical"],
              name="critical to archive")
    c.connect(route, ref(router, route, "PROCESSOR"), ref(warn_log, route, "PROCESSOR"), ["warning"], name="warnings")
    unmatched = c.connect(route, ref(router, route, "PROCESSOR"), ref(review, route, "PROCESSOR"), ["unmatched"],
                          name="Unmatched hold", object_threshold=0, size_threshold="0 B")
    c.connect(top, {"id": out_i["id"], "groupId": intake, "type": "OUTPUT_PORT"},
              {"id": in_n["id"], "groupId": normalize, "type": "INPUT_PORT"}, [], name="intake to normalize")
    c.connect(top, {"id": out_n["id"], "groupId": normalize, "type": "OUTPUT_PORT"},
              {"id": in_r["id"], "groupId": route, "type": "INPUT_PORT"}, [], name="normalize to route")
    return {"top": top, "intake": intake, "normalize": normalize, "route": route, "router": router["id"],
            "unmatched": unmatched["id"], "review": review["id"], "gen": gen["id"], "tag": tag["id"],
            "ports": [("output", out_i["id"]), ("input", in_n["id"]), ("output", out_n["id"]), ("input", in_r["id"])],
            "procs": [tag["id"], ejp["id"], fail_log["id"], router["id"], hec["id"], archive["id"], warn_log["id"]]}


def wrap(endpoint: str, response, collected_at: str, query: dict | None = None) -> dict:
    return {"collection": {"endpoint": endpoint, "collected_at": collected_at, "node_id": None,
                           "query": query or {}, "collector": "nifimcp-lab-demo-builder"},
            "response": response}


def provenance(c: LabClient, terms: dict, start: dt.datetime, end: dt.datetime, max_results: int = 200) -> dict:
    body = {"provenance": {"request": {
        "maxResults": max_results, "summarize": False, "incrementalResults": False,
        "startDate": start.strftime("%m/%d/%Y %H:%M:%S UTC"), "endDate": end.strftime("%m/%d/%Y %H:%M:%S UTC"),
        "searchTerms": {k: {"value": v, "inverse": False} for k, v in terms.items()}}}}
    created = c.request("POST", "/provenance", json_body=body)
    pid = created["provenance"]["id"]
    try:
        cur = c.wait(lambda: (lambda r: r if r["provenance"]["finished"] else None)(
            c.get(f"/provenance/{pid}", params={"summarize": "false", "incrementalResults": "false"})),
            timeout=30, what="provenance")
        return cur
    finally:
        c.request("DELETE", f"/provenance/{pid}")


def write_file(name: str, value, *, raw: bytes | None = None) -> bytes:
    data = raw if raw is not None else (json.dumps(value, indent=1, sort_keys=True) + "\n").encode()
    (BUNDLE_DIR / name).write_bytes(data)
    return data


def main() -> int:
    lab_dir = current_lab_dir(ROOT / ".lab")
    with LabClient(lab_dir) as c:
        ids = build(c)
        start = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1)
        for kind, pid in ids["ports"]:
            c.set_run_state(kind, pid, "RUNNING")
        for pid in ids["procs"]:
            try:
                c.set_run_state("processor", pid, "RUNNING")
            except Exception as exc:  # invalid components stay stopped; that is part of the demo
                print(f"[demo] could not start {pid}: {type(exc).__name__}", file=sys.stderr)
        c.set_run_state("processor", ids["gen"], "RUNNING")
        time.sleep(30)
        c.set_run_state("processor", ids["gen"], "STOPPED")
        time.sleep(8)
        end = dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=1)

        if BUNDLE_DIR.exists():
            shutil.rmtree(BUNDLE_DIR)
        BUNDLE_DIR.mkdir(parents=True)
        files = []

        def add(name, kind, data, collected_at, interval=None, description=""):
            entry = {"path": name, "kind": kind, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data),
                     "collected_at": collected_at, "node_id": "standalone", "origin": "machine_collected",
                     "description": description}
            if interval:
                entry["interval"] = interval
            files.append(entry)

        t = now()
        definition = c.download_definition(ids["top"])
        add("flow-definition.json", "flow_definition", write_file("flow-definition.json", None, raw=definition), t,
            description="Native NiFi 2.12.0 flow definition download of the demo process group")
        t = now()
        status = c.get(f"/flow/process-groups/{ids['top']}/status", params={"recursive": "true"})
        add("status.json", "status", write_file("status.json", wrap(f"GET /flow/process-groups/{ids['top']}/status?recursive=true", status, t)), t,
            description="Recursive status snapshot")
        t = now()
        board = c.get("/flow/bulletin-board", params={"limit": "200"})
        add("bulletins.json", "bulletins", write_file("bulletins.json", wrap("GET /flow/bulletin-board?limit=200", board, t)), t,
            description="Bulletin board snapshot")
        interval = {"start": start.isoformat(timespec="seconds").replace("+00:00", "Z"),
                    "end": end.isoformat(timespec="seconds").replace("+00:00", "Z")}
        t = now()
        unmatched_prov = provenance(c, {"Relationship": "unmatched", "ProcessorID": ids["router"]}, start, end)
        add("provenance-unmatched.json", "provenance",
            write_file("provenance-unmatched.json", wrap("POST /provenance", unmatched_prov, t,
                                                         {"Relationship": "unmatched", "ProcessorID": ids["router"]})),
            t, interval, "Provenance events routed to unmatched by the router")
        events = unmatched_prov["provenance"]["results"]["provenanceEvents"]
        crit = provenance(c, {"Relationship": "critical", "ProcessorID": ids["router"]}, start, end, 5)
        crit_events = crit["provenance"]["results"]["provenanceEvents"]
        trace_uuid = crit_events[0]["flowFileUuid"] if crit_events else events[0]["flowFileUuid"]
        t = now()
        trace = provenance(c, {"FlowFileUUID": trace_uuid}, start, end)
        add("provenance-trace.json", "provenance",
            write_file("provenance-trace.json", wrap("POST /provenance", trace, t, {"FlowFileUUID": trace_uuid})),
            t, interval, "Lineage events for one critical FlowFile")
        t = now()
        listing = c.list_queue(ids["unmatched"])
        add("queue-sample-unmatched.json", "queue_sample",
            write_file("queue-sample-unmatched.json", wrap(f"POST /flowfile-queues/{ids['unmatched']}/listing-requests",
                                                           {"connection_id": ids["unmatched"], "flowFileSummaries": listing[:10],
                                                            "sampled": min(10, len(listing))}, t)),
            t, None, "Metadata sample (first 10 entries) of the Unmatched hold queue")

        # Operator notes bound to the exact definition bytes (one current, one stale).
        defn = json.loads(definition)
        def_hash = hashlib.sha256(definition).hexdigest()
        route_group = next(i for i, g in enumerate(defn["flowContents"]["processGroups"]) if g["name"] == "Route and deliver")
        conns = defn["flowContents"]["processGroups"][route_group]["connections"]
        hold = next(i for i, cn in enumerate(conns) if cn["name"] == "Unmatched hold")
        pointer = f"/flowContents/processGroups/{route_group}/connections/{hold}"
        notes = {"notes_schema": "nifimcp-notes/1", "notes": [
            {"note_id": "note-unmatched-purpose", "author": "telemetry-team (synthetic)", "created_at": now(),
             "source_file": "flow-definition.json", "source_sha256": def_hash, "pointer": pointer,
             "component_id": conns[hold]["instanceIdentifier"],
             "text": "Unmatched holds diagnostic and info events that are not onboarded yet. Reviewed weekly.",
             "origin": "operator_note"},
            {"note_id": "note-old-threshold", "author": "telemetry-team (synthetic)", "created_at": "2026-09-01T12:00:00.000Z",
             "source_file": "flow-definition.json", "source_sha256": "0" * 64, "pointer": pointer,
             "component_id": conns[hold]["instanceIdentifier"],
             "text": "Back pressure on Unmatched hold is set to 10,000 objects.",
             "origin": "operator_note"},
        ]}
        t = now()
        add("operator-notes.json", "operator_notes", write_file("operator-notes.json", notes), t,
            description="Operator notes (one current, one written against an older source)")

        manifest = {
            "bundle_schema": "nifimcp-bundle/1", "bundle_id": "demo-telemetry-intake", "created_at": now(),
            "collector": {"name": "nifimcp-lab-demo-builder", "version": "0.1.0"},
            "nifi": {"version": "2.12.0", "profile": "stock apache/nifi 2.12.0 docker image, standalone, secure"},
            "declared_scope": {"scope_id": "demo-telemetry-intake", "process_group_id": ids["top"],
                               "label": "Telemetry Intake (synthetic demo)"},
            "nodes": [{"node_id": "standalone", "included": True, "note": "single-node lab"}],
            "source_kinds": sorted({f["kind"] for f in files}),
            "files": files,
            "redaction": {"policy": "none at collection; NiFiMCP redacts on read", "sensitive_values_present": False,
                          "notes": "Synthetic canary strings are planted in non-sensitive properties for leak tests."},
            "completeness": {"status": "complete", "missing": []},
        }
        (BUNDLE_DIR / "manifest.json").write_text(json.dumps(manifest, indent=1, sort_keys=True) + "\n")

        # Candidate snapshot: move a processor (layout), change a route rule, add a processor.
        c.set_run_state("processor", ids["router"], "STOPPED")
        router_entity = c.get(f"/processors/{ids['router']}")
        c.request("PUT", f"/processors/{ids['router']}", json_body={
            "revision": c.revision(router_entity),
            "component": {"id": ids["router"], "position": {"x": 120.0, "y": 300.0},
                          "config": {"properties": {"warning": "${event.level:equalsIgnoreCase('warning')}"}}}})
        c.create_processor(ids["route"], LOGATTR, "Audit unmatched sample", x=450, y=850, auto_terminate=["success"])
        candidate = c.download_definition(ids["top"])
        (OUT / "telemetry-intake-candidate.json").write_bytes(candidate)
        meta = {"demo_group_id": ids["top"], "built_at": now(), "lab_id": c.manifest["lab_id"],
                "image_digest": c.manifest["image"]["digest"], "trace_flowfile_uuid": trace_uuid,
                "unmatched_connection_id": ids["unmatched"], "unmatched_events": len(events)}
        (OUT / "build-info.json").write_text(json.dumps(meta, indent=1, sort_keys=True) + "\n")
        print(json.dumps(meta, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
