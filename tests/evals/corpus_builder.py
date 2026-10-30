"""Builds the labeled incident corpus (development and frozen holdout splits).

Each case is a self-contained synthetic bundle plus tool calls and labels:
  required  - facts the deterministic system MUST produce (finding prefixes, gap codes, statuses, errors)
  forbidden - conclusions it must NOT claim (regexes over every statement, limitation and gap detail)
Label provenance: authored by the implementing engineer (Claude) from the build specification's
mandatory distinctions. Not expert-reviewed. Measures deterministic rules only, never model quality.
"""
from __future__ import annotations

import copy
import uuid

GLOBAL_FORBIDDEN = [
    r"\bis healthy\b", r"\bno (problems|issues) (found|detected|exist)", r"\bproduction[- ]ready\b",
    r"\bsafe to deploy\b", r"\bguarantee[sd]?\b", r"\broot cause is\b", r"\bwas caused by\b",
    r"(splunk|downstream) (received|indexed|acknowledged)", r"never existed", r"did not exist",
    r"\bdata was lost\b", r"\boutage (occurred|happened)\b",
]


def uid(seed: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "nifimcp-eval:" + seed))


def proc(pid, name, type_="org.apache.nifi.processors.standard.LogAttribute", **kw):
    base = {"identifier": pid, "instanceIdentifier": uid(pid), "name": name, "type": type_,
            "bundle": {"group": "org.apache.nifi", "artifact": "nifi-standard-nar", "version": "2.12.0"},
            "properties": {}, "propertyDescriptors": {}, "schedulingPeriod": "1 sec", "schedulingStrategy": "TIMER_DRIVEN",
            "autoTerminatedRelationships": [], "scheduledState": "ENABLED", "position": {"x": 0.0, "y": 0.0}}
    base.update(kw)
    return base


def conn(cid, src, dst, rels=("success",), **kw):
    base = {"identifier": cid, "instanceIdentifier": uid(cid), "name": cid, "source": {"id": src, "type": "PROCESSOR"},
            "destination": {"id": dst, "type": "PROCESSOR"}, "selectedRelationships": list(rels),
            "backPressureObjectThreshold": 10000, "backPressureDataSizeThreshold": "1 GB", "flowFileExpiration": "0 sec",
            "prioritizers": [], "loadBalanceStrategy": "DO_NOT_LOAD_BALANCE"}
    base.update(kw)
    return base


def flow(name, processors, connections, **kw):
    root = {"identifier": "root-" + name, "instanceIdentifier": uid("root-" + name), "name": name,
            "processGroups": [], "processors": processors, "connections": connections, "inputPorts": [],
            "outputPorts": [], "funnels": [], "labels": [], "controllerServices": [], "remoteProcessGroups": []}
    root.update(kw.pop("root", {}))
    doc = {"flowContents": root, "externalControllerServices": {}, "parameterContexts": kw.pop("contexts", {}),
           "flowEncodingVersion": "1.0"}
    return doc


def status_doc(root_id, processors=(), connections=()):
    return {"collection": {}, "response": {"processGroupStatus": {"aggregateSnapshot": {
        "id": root_id,
        "processorStatusSnapshots": [{"processorStatusSnapshot": p} for p in processors],
        "connectionStatusSnapshots": [{"connectionStatusSnapshot": c} for c in connections]}}}}


def prov_doc(events, total=None):
    return {"collection": {}, "response": {"provenance": {"results": {
        "total": total or str(len(events)), "provenanceEvents": events}}}}


def event(i, etype, component, group, ff, ts, rel=None, **kw):
    base = {"id": str(i), "eventId": i, "eventTimestamp": ts, "eventType": etype, "flowFileUuid": ff,
            "componentId": component, "groupId": group, "relationship": rel, "attributes": [], "parentUuids": [],
            "childUuids": []}
    base.update(kw)
    return base


WIN = {"start": "2026-10-29T01:00:00Z", "end": "2026-10-29T02:00:00Z"}
T0 = "2026-10-29T01:30:00.000Z"
FF = "6ae1e6de-d4a6-4f88-be99-5ac47c13e079"


def basic_router(name):
    procs = [proc("gen", "Source", "org.apache.nifi.processors.standard.GenerateFlowFile"),
             proc("route", "Router", "org.apache.nifi.processors.standard.RouteOnAttribute",
                  properties={"a": "${x:equals('a')}"}),
             proc("sink", "Sink"), proc("hold", "Unmatched review", "org.apache.nifi.processors.attributes.UpdateAttribute")]
    conns = [conn("c1", "gen", "route"), conn("c2", "route", "sink", ("a",)),
             conn("c3", "route", "hold", ("unmatched",))]
    procs[2]["autoTerminatedRelationships"] = ["success"]
    procs[3]["autoTerminatedRelationships"] = ["success"]
    return flow(name, procs, conns)


def case(cid, family, split, doc, calls, required, forbidden=(), extra=None, manifest=None, note=""):
    return {"id": cid, "family": family, "split": split, "flow": doc, "extra_files": extra or {},
            "manifest_overrides": manifest or {}, "calls": calls, "required": required,
            "forbidden": list(forbidden), "label_note": note,
            "label_provenance": "engineer-authored from the specification's mandatory distinctions; not expert-reviewed"}


def build() -> list[dict]:
    cases = []
    # ---------------------------------------------------------------- F1 stopped / invalid
    d = basic_router("f1a")
    d["flowContents"]["processors"][2]["scheduledState"] = "DISABLED"
    cases.append(case("F1-01", "stopped_invalid", "dev", d, [("describe_flow", {})],
                      [{"finding": "NM-STOPPED"}, {"limitation": "not proof of an outage"}],
                      [r"\bis (down|offline|broken)\b"]))
    d = basic_router("f1b")
    rid = d["flowContents"]["instanceIdentifier"]
    st = status_doc(rid, [{"id": uid("sink"), "name": "Sink", "runStatus": "Invalid"}],
                    [{"id": uid("c2"), "name": "c2", "flowFilesQueued": 40, "percentUseCount": 0}])
    cases.append(case("F1-02", "stopped_invalid", "dev", d, [("get_flow_health", {"interval": WIN})],
                      [{"finding": "OBS-INVALID"}, {"finding": "HYP-QUEUE-BLOCKED", "kind": "hypothesis"}],
                      extra={"status.json": ("status", st, None)}))
    rest = {"processGroupFlow": {"id": uid("rest-f1c"), "flow": {"processors": [{"id": uid("p-inv"), "component": {
        "id": uid("p-inv"), "name": "Bad", "type": "org.apache.nifi.processors.standard.PutFile",
        "validationStatus": "INVALID", "validationErrors": ["Directory is required"], "config": {"properties": {}}}}]}}}
    cases.append(case("F1-03", "stopped_invalid", "dev", rest, [("describe_flow", {})],
                      [{"finding": "NM-INVALID", "kind": "observed"}], [r"Directory is required"],
                      note="Validation messages are untrusted and not reproduced."))
    d = basic_router("f1h")
    st = status_doc(d["flowContents"]["instanceIdentifier"], [{"id": uid("hold"), "name": "Unmatched review", "runStatus": "Stopped"}])
    cases.append(case("H1", "stopped_invalid", "holdout", d, [("get_flow_health", {"interval": WIN})],
                      [{"finding": "OBS-STOPPED"}, {"no_finding": "HYP-QUEUE-BLOCKED"}],
                      extra={"status.json": ("status", st, None)}))
    # ---------------------------------------------------------------- F2 back pressure
    d = basic_router("f2a")
    st = status_doc(d["flowContents"]["instanceIdentifier"], [], [{"id": uid("c3"), "name": "c3", "flowFilesQueued": 10000,
                                                                   "percentUseCount": 100, "percentUseBytes": 3}])
    cases.append(case("F2-01", "backpressure", "dev", d, [("get_flow_health", {"interval": WIN})],
                      [{"finding": "OBS-QUEUE", "severity": "warning"}, {"text": "back pressure engaged"}],
                      extra={"status.json": ("status", st, None)}))
    d = basic_router("f2b")
    d["flowContents"]["connections"][2].update(backPressureObjectThreshold=0, backPressureDataSizeThreshold="0 B")
    cases.append(case("F2-02", "backpressure", "dev", d, [("describe_flow", {})],
                      [{"finding": "NM-UNBOUNDED-QUEUE"}, {"limitation": "cannot predict actual queue growth"}],
                      [r"queue (will|is going to) (grow|fill)"]))
    d = basic_router("f2c")
    st = status_doc(d["flowContents"]["instanceIdentifier"], [], [{"id": uid("c3"), "name": "c3", "flowFilesQueued": 8500,
                                                                   "percentUseCount": 85, "percentUseBytes": 1}])
    cases.append(case("F2-03", "backpressure", "dev", d, [("get_flow_health", {"interval": WIN})],
                      [{"finding": "OBS-QUEUE", "severity": "info"}], [r"back pressure engaged"],
                      extra={"status.json": ("status", st, None)}))
    d = basic_router("f2h")
    d["flowContents"]["connections"][1]["flowFileExpiration"] = "30 sec"
    cases.append(case("H2", "backpressure", "holdout", d, [("describe_flow", {})],
                      [{"finding": "NM-QUEUE-EXPIRATION"}], [r"data (was|has been) (lost|discarded)"]))
    # ---------------------------------------------------------------- F3 unmatched
    d = basic_router("f3a")
    cases.append(case("F3-01", "unmatched", "dev", d, [("describe_flow", {})],
                      [{"finding": "NM-UNMATCHED-ROUTE"}, {"limitation": "can be intentional"}],
                      [r"unmatched (means|indicates) (an )?(error|failure|bug)"]))
    d = basic_router("f3b")
    d["flowContents"]["connections"] = d["flowContents"]["connections"][:2]
    d["flowContents"]["processors"][1]["autoTerminatedRelationships"] = ["unmatched"]
    cases.append(case("F3-02", "unmatched", "dev", d, [("describe_flow", {})], [{"finding": "NM-UNMATCHED-DISCARDED"}]))
    d = basic_router("f3c")
    g = d["flowContents"]["instanceIdentifier"]
    ev = [event(1, "ROUTE", uid("route"), g, FF, T0, "unmatched",
                attributes=[{"name": "x", "value": "zzz"}, {"name": "filename", "value": "f.json"}])]
    cases.append(case("F3-03", "unmatched", "dev", d, [("trace_feed", {"selector": {"kind": "flowfile_uuid", "value": FF},
                                                                       "interval": WIN})],
                      [{"finding": "OBS-ROUTE-UNMATCHED"}, {"limitation": "does not reveal why"}],
                      [r"routed to 'unmatched' because"], extra={"prov.json": ("provenance", prov_doc(ev), WIN)}))
    d = basic_router("f3h")
    g = d["flowContents"]["instanceIdentifier"]
    ev = [event(1, "ROUTE", uid("route"), g, FF, "2026-10-29T01:10:00.000Z", "unmatched")]
    cases.append(case("H3", "unmatched", "holdout", d,
                      [("inspect_unmatched", {"connection_id": uid("c3"), "interval": WIN})],
                      [{"finding": "TEMPORAL-MISMATCH"}, {"finding": "OBS-UNMATCHED-EVENTS"}],
                      [r"current (setting|configuration) (caused|explains)"],
                      extra={"prov.json": ("provenance", prov_doc(ev), WIN)},
                      note="Flow definition collected at 02:00 after events at 01:10."))
    # ---------------------------------------------------------------- F4 parameters / services
    d = basic_router("f4a")
    d["flowContents"]["processors"][2]["properties"] = {"Log prefix": "#{undefined.prefix}"}
    cases.append(case("F4-01", "parameter_service_gaps", "dev", d, [("describe_flow", {})],
                      [{"finding": "NM-PARAM-UNRESOLVED"}, {"gap": "PARAMETER_UNRESOLVED"}],
                      [r"(likely|probably) (set to|equals|is) "]))
    d = basic_router("f4b")
    d["flowContents"]["processors"][2]["properties"] = {"Record Reader": "svc-missing"}
    d["flowContents"]["processors"][2]["propertyDescriptors"] = {"Record Reader": {"name": "Record Reader",
                                                                                  "identifiesControllerService": True}}
    cases.append(case("F4-02", "parameter_service_gaps", "dev", d, [("describe_flow", {})],
                      [{"finding": "NM-SERVICE-UNRESOLVED"}, {"gap": "SERVICE_UNRESOLVED"}]))
    d = basic_router("f4c")
    d["flowContents"]["processors"][2]["properties"] = {"Log prefix": "#{base.prefix}"}
    d["flowContents"]["parameterContextName"] = "child"
    d["parameterContexts"] = {"child": {"name": "child", "parameters": [], "inheritedParameterContexts": ["base"]},
                              "base": {"name": "base", "parameters": [{"name": "base.prefix", "sensitive": False, "value": "p"}]}}
    cases.append(case("F4-03", "parameter_service_gaps", "dev", d, [("describe_flow", {})],
                      [{"no_finding": "NM-PARAM-UNRESOLVED"}, {"no_gap": "PARAMETER_UNRESOLVED"}],
                      note="Negative control: inherited parameter resolves."))
    d = basic_router("f4h")
    d["flowContents"]["processors"][2]["bundle"] = {"group": "com.example", "artifact": "custom-nar", "version": "1.0"}
    d["flowContents"]["processors"][2]["type"] = "com.example.CustomSink"
    cases.append(case("H4", "parameter_service_gaps", "holdout", d, [("describe_flow", {})],
                      [{"gap": "CUSTOM_COMPONENT_UNRESOLVED"}], [r"CustomSink (writes|sends|stores)"]))
    # ---------------------------------------------------------------- F5 provenance limits
    d = basic_router("f5a")
    cases.append(case("F5-01", "provenance_limits", "dev", d,
                      [("trace_feed", {"selector": {"kind": "flowfile_uuid", "value": FF}, "interval": WIN})],
                      [{"gap": "NO_MATCHING_EVENTS"}, {"text": "retention"}],
                      extra={"prov.json": ("provenance", prov_doc([]), WIN)}))
    d = basic_router("f5b")
    g = d["flowContents"]["instanceIdentifier"]
    ev = [event(i, "ROUTE", uid("route"), g, FF, T0, "a") for i in range(3)]
    cases.append(case("F5-02", "provenance_limits", "dev", d,
                      [("trace_feed", {"selector": {"kind": "flowfile_uuid", "value": FF}, "interval": WIN})],
                      [{"gap": "EVENTS_TRUNCATED_AT_COLLECTION"}, {"status": "partial"}],
                      extra={"prov.json": ("provenance", prov_doc(ev, total="200+"), WIN)}))
    d = basic_router("f5c")
    cases.append(case("F5-03", "provenance_limits", "dev", d,
                      [("trace_feed", {"selector": {"kind": "flowfile_uuid", "value": FF},
                                       "interval": {"start": "2026-10-28T01:00:00Z", "end": "2026-10-28T02:00:00Z"}})],
                      [{"gap": "INTERVAL_NOT_COVERED"}, {"status": "partial"}, {"gap": "NO_MATCHING_EVENTS"}],
                      extra={"prov.json": ("provenance", prov_doc([]), WIN)}))
    d = basic_router("f5h")
    g = d["flowContents"]["instanceIdentifier"]
    ev = [event(1, "SEND", uid("sink"), g, FF, T0, transitUri="https://hec.example.invalid:8088/services/collector")]
    cases.append(case("H5", "provenance_limits", "holdout", d,
                      [("trace_feed", {"selector": {"kind": "flowfile_uuid", "value": FF}, "interval": WIN})],
                      [{"finding": "OBS-SEND"}, {"limitation": "does not establish that a downstream"}],
                      extra={"prov.json": ("provenance", prov_doc(ev), WIN)}))
    # ---------------------------------------------------------------- F6 permission / scope
    d = basic_router("f6a")
    cases.append(case("F6-01", "permission_scope", "dev", d,
                      [("inspect_unmatched", {"connection_id": "11111111-2222-3333-4444-555555555555"})],
                      [{"error": "OUT_OF_SCOPE"}]))
    d = basic_router("f6b")
    cases.append(case("F6-02", "permission_scope", "dev", d, [("describe_flow", {"scope_id": "other-scope"})],
                      [{"error": "OUT_OF_SCOPE"}, {"envelope_scope": "global"}]))
    d = basic_router("f6c")
    cases.append(case("F6-03", "permission_scope", "dev", d,
                      [("trace_feed", {"selector": {"kind": "indexed_attribute", "name": "x", "value": "a"}, "interval": WIN})],
                      [{"error": "INVALID_ARGUMENT"}]))
    d = basic_router("f6h")
    bb = {"collection": {}, "response": {"bulletinBoard": {"bulletins": [{"canRead": False, "id": 1}]}}}
    cases.append(case("H6", "permission_scope", "holdout", d, [("get_flow_health", {"interval": WIN})],
                      [{"gap": "BULLETINS_NOT_READABLE"}], extra={"bulletins.json": ("bulletins", bb, None)}))
    # ---------------------------------------------------------------- F7 conflicting / partial
    d = basic_router("f7a")
    cases.append(case("F7-01", "conflicting_partial", "dev", d, [("describe_flow", {})],
                      [{"gap": "BUNDLE_PARTIAL"}, {"gap": "NODE_NOT_INCLUDED"}, {"status": "partial"}],
                      manifest={"nodes": [{"node_id": "standalone", "included": True}, {"node_id": "node-2", "included": False}],
                                "completeness": {"status": "partial", "missing": ["node-2 unreachable"]}}))
    d = basic_router("f7b")
    st = status_doc(d["flowContents"]["instanceIdentifier"], [], [])
    cases.append(case("F7-02", "conflicting_partial", "dev", d,
                      [("get_flow_health", {"interval": {"start": "2026-10-28T01:00:00Z", "end": "2026-10-28T02:00:00Z"}})],
                      [{"gap": "STATUS_OUTSIDE_INTERVAL"}], [r"currently (running|healthy|stopped)"],
                      extra={"status.json": ("status", st, None)}))
    d = basic_router("f7c")
    notes = {"notes_schema": "nifimcp-notes/1", "notes": [{"note_id": "old", "author": "ops", "created_at": T0,
             "source_file": "flow-definition.json", "source_sha256": "0" * 64, "pointer": "/flowContents/connections/2",
             "component_id": uid("c3"), "text": "Unmatched is empty in normal operation.", "origin": "operator_note"}]}
    cases.append(case("F7-03", "conflicting_partial", "dev", d, [("describe_flow", {})],
                      [{"gap": "STALE_NOTE"}, {"no_finding": "NOTE:old"}], [r"empty in normal operation"],
                      extra={"notes.json": ("operator_notes", notes, None)}))
    d = basic_router("f7h")
    g = d["flowContents"]["instanceIdentifier"]
    ev = [event(1, "ROUTE", uid("route"), g, FF, T0, "a"),
          event(2, "ROUTE", uid("foreign-proc"), uid("foreign-group"), FF, T0, "x")]
    cases.append(case("H7", "conflicting_partial", "holdout", d,
                      [("trace_feed", {"selector": {"kind": "flowfile_uuid", "value": FF}, "interval": WIN})],
                      [{"gap": "EVENTS_OUTSIDE_SCOPE_DROPPED"}, {"events": 1}],
                      extra={"prov.json": ("provenance", prov_doc(ev), WIN)}))
    # ---------------------------------------------------------------- healthy controls
    d = basic_router("c1")
    cases.append(case("C-01", "healthy_control", "dev", d, [("describe_flow", {})],
                      [{"max_severity": "info"}], note="Clean configuration: only informational routing facts."))
    d = basic_router("c2")
    st = status_doc(d["flowContents"]["instanceIdentifier"],
                    [{"id": uid(p), "name": p, "runStatus": "Running"} for p in ("gen", "route", "sink", "hold")],
                    [{"id": uid(c), "name": c, "flowFilesQueued": 0, "percentUseCount": 0} for c in ("c1", "c2", "c3")])
    empty_board = {"collection": {}, "response": {"bulletinBoard": {"bulletins": []}}}
    cases.append(case("C-02", "healthy_control", "dev", d, [("get_flow_health", {"interval": WIN})],
                      [{"no_finding": "OBS-QUEUE"}, {"no_finding": "OBS-INVALID"}, {"max_severity": "info"},
                       {"gap": "HISTORY_NOT_ESTABLISHED"}],
                      extra={"status.json": ("status", st, None), "bulletins.json": ("bulletins", empty_board, None)},
                      note="Revised after first run: originally required status ok without supplying bulletins; "
                           "partial is the correct contract when bulletin evidence is absent. Bulletins added and "
                           "the status label replaced by severity and history-gap labels."))
    d = basic_router("c3")
    g = d["flowContents"]["instanceIdentifier"]
    ev = [event(1, "CREATE", uid("gen"), g, FF, "2026-10-29T01:30:00.000Z"),
          event(2, "ROUTE", uid("route"), g, FF, "2026-10-29T01:30:01.000Z", "a"),
          event(3, "DROP", uid("sink"), g, FF, "2026-10-29T01:30:02.000Z")]
    cases.append(case("C-03", "healthy_control", "dev", d,
                      [("trace_feed", {"selector": {"kind": "flowfile_uuid", "value": FF}, "interval": WIN})],
                      [{"no_finding": "OBS-ROUTE-UNMATCHED"}, {"events": 3}, {"limitation": "does not by itself indicate an error"}],
                      extra={"prov.json": ("provenance", prov_doc(ev), WIN)}))
    d = basic_router("ch")
    st = status_doc(d["flowContents"]["instanceIdentifier"],
                    [{"id": uid("route"), "name": "Router", "runStatus": "Running"}], [])
    cases.append(case("HC", "healthy_control", "holdout", d, [("describe_flow", {}), ("get_flow_health", {"interval": WIN})],
                      [{"max_severity": "info"}, {"no_finding": "HYP-QUEUE-BLOCKED"}],
                      extra={"status.json": ("status", st, None)}))
    return cases


def copy_case(c):
    return copy.deepcopy(c)


def write_corpus(folder) -> dict:
    """Write dev.json and holdout.json. Returns their sha256 values."""
    import hashlib
    import json
    from pathlib import Path
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    hashes = {}
    for split in ("dev", "holdout"):
        doc = {"corpus_schema": "nifimcp-eval-corpus/1", "split": split, "global_forbidden": GLOBAL_FORBIDDEN,
               "cases": [c for c in build() if c["split"] == split]}
        data = (json.dumps(doc, indent=1, sort_keys=True) + "\n").encode()
        (folder / f"{split}.json").write_bytes(data)
        hashes[split] = hashlib.sha256(data).hexdigest()
    return hashes


if __name__ == "__main__":
    import sys
    print(write_corpus(sys.argv[1] if len(sys.argv) > 1 else "tests/evals/corpus"))
