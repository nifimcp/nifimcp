"""Turn raw NiFi 2.12.0 observation responses into evidence, findings and gaps.

The same parsers serve offline bundles (files wrapping the raw response) and live
mode (responses fetched through the allowlisted adapter), so both modes cite the
same structure. Content is never read; attributes are allowlisted; text fields
are scrubbed before they become facts.
"""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from typing import Any, Iterable

from ..util import iso, parse_iso, parse_nifi_time
from . import pointer as jp
from .evidence import EvidenceSet, make_evidence, make_finding
from .redact import Redactor

LIM_STATUS = ("Status describes the moment of collection only. It is not a current health claim and does not "
              "explain past events.")
LIM_SEND = ("A NiFi SEND event establishes the observed NiFi handoff only. It does not establish that a downstream "
            "system received, indexed or acted on the data.")
LIM_EMPTY = ("No matching events can reflect provenance retention, indexing, permissions, scope or the time window. "
             "It does not prove the data never existed.")
LIM_SAMPLE = ("A queue sample describes the sampled entries at collection time. It does not describe the whole "
              "queue or establish past routing causes.")
LIM_UNMATCHED = ("Unmatched is a routing outcome and can be intentional; the relationship name does not reveal why a "
                 "record took that route.")


@dataclass
class Source:
    source_id: str
    source_hash: str
    base_pointer: str          # pointer of the raw response inside the source document
    collected_at: str
    node_id: str | None


def _ev(src: Source, kind: str, ptr: str, facts: dict, *, component_id: str | None = None,
        event_time: str | None = None, extra: str = "") -> dict:
    return make_evidence(kind=kind, source_id=src.source_id, source_hash=src.source_hash, source_pointer=ptr,
                         facts=facts, collected_at=src.collected_at, component_id=component_id,
                         node_id=src.node_id, event_time=event_time, extra=extra)


# ---------------------------------------------------------------------- status
def walk_status(snapshot: dict, ptr: str) -> Iterable[tuple[str, dict, str]]:
    """Yield (kind, snapshot dict, pointer) for every component in a recursive status snapshot."""
    for field_name, kind, inner in (
        ("processorStatusSnapshots", "processor", "processorStatusSnapshot"),
        ("connectionStatusSnapshots", "connection", "connectionStatusSnapshot"),
        ("inputPortStatusSnapshots", "input_port", "portStatusSnapshot"),
        ("outputPortStatusSnapshots", "output_port", "portStatusSnapshot"),
    ):
        for i, entry in enumerate(snapshot.get(field_name) or []):
            if isinstance(entry, dict) and isinstance(entry.get(inner), dict):
                yield kind, entry[inner], jp.join(ptr, field_name, i, inner)
    for i, entry in enumerate(snapshot.get("processGroupStatusSnapshots") or []):
        if isinstance(entry, dict) and isinstance(entry.get("processGroupStatusSnapshot"), dict):
            child_ptr = jp.join(ptr, "processGroupStatusSnapshots", i, "processGroupStatusSnapshot")
            yield "process_group", entry["processGroupStatusSnapshot"], child_ptr
            yield from walk_status(entry["processGroupStatusSnapshot"], child_ptr)


def status_root(response: dict) -> tuple[dict, str]:
    pgs = response.get("processGroupStatus") if isinstance(response, dict) else None
    if not isinstance(pgs, dict) or not isinstance(pgs.get("aggregateSnapshot"), dict):
        raise ValueError("not a ProcessGroupStatusEntity")
    return pgs["aggregateSnapshot"], "/processGroupStatus/aggregateSnapshot"


def status_inventory(response: dict) -> dict[str, dict]:
    """Component id -> {'kind', 'group_id', 'name'} from a recursive status response (scope inventory)."""
    root, _ = status_root(response)
    inventory = {root.get("id"): {"kind": "process_group", "group_id": None, "name": root.get("name")}}
    for kind, snap, _ptr in walk_status(root, ""):
        if isinstance(snap.get("id"), str):
            inventory[snap["id"]] = {"kind": kind, "group_id": snap.get("groupId"), "name": snap.get("name"),
                                     "source_id": snap.get("sourceId"), "destination_id": snap.get("destinationId")}
    return inventory


def parse_status(response: dict, src: Source, redactor: Redactor, out: EvidenceSet,
                 *, now: dt.datetime, only_ids: set[str] | None = None,
                 links: dict[str, tuple[str | None, str | None]] | None = None) -> dict:
    """``links`` maps connection id -> (source id, destination id) from the flow model, because
    NiFi 2.12.0 connection status snapshots carry endpoint names but not endpoint ids."""
    root, root_ptr = status_root(response)
    base = src.base_pointer + root_ptr
    age = (now - parse_iso(src.collected_at)).total_seconds()
    summary = {"observed_at": src.collected_at, "age_seconds": round(age, 1), "processors": {}, "queues": [],
               "invalid": [], "stopped": [], "backpressure_engaged": []}
    by_id: dict[str, dict] = {}
    for kind, snap, ptr in walk_status(root, base):
        cid = snap.get("id")
        if not isinstance(cid, str) or (only_ids is not None and cid not in only_ids):
            continue
        by_id[cid] = snap
        if kind == "processor":
            run = snap.get("runStatus")
            summary["processors"][run] = summary["processors"].get(run, 0) + 1
            if run in ("Invalid", "Stopped", "Disabled", "Validating"):
                facts = {"component_kind": "processor", "name": redactor.name(snap.get("name")), "type": snap.get("type"),
                         "runStatus": run, "flowFilesIn": snap.get("flowFilesIn"), "flowFilesOut": snap.get("flowFilesOut"),
                         "activeThreadCount": snap.get("activeThreadCount")}
                ev = out.add_evidence(_ev(src, "status", ptr, facts, component_id=cid))
                label = f"processor '{facts['name']}' ({cid})" if facts["name"] else f"processor {cid}"
                if run == "Invalid":
                    summary["invalid"].append(cid)
                    out.add_finding(make_finding(
                        finding_id=f"OBS-INVALID:{cid}", kind="observed", severity="warning", evidence_ids=[ev],
                        statement=f"NiFi reported {label} as Invalid at {src.collected_at}; it cannot run while invalid.",
                        limitations=[LIM_STATUS, "Validation messages are not reproduced; inspect the component in NiFi."]))
                elif run in ("Stopped", "Disabled"):
                    summary["stopped"].append(cid)
                    out.add_finding(make_finding(
                        finding_id=f"OBS-STOPPED:{cid}", kind="observed", severity="info", evidence_ids=[ev],
                        statement=f"NiFi reported {label} as {run} at {src.collected_at}.",
                        limitations=[LIM_STATUS, "A stopped component can be intentional."]))
        elif kind == "connection":
            queued = snap.get("flowFilesQueued") or 0
            pct = snap.get("percentUseCount")
            pct_bytes = snap.get("percentUseBytes")
            link = (links or {}).get(cid, (snap.get("sourceId"), snap.get("destinationId")))
            entry = {"connection_id": cid, "name": redactor.name(snap.get("name")), "queued": queued,
                     "bytes_queued": snap.get("bytesQueued"), "percent_use_count": pct, "percent_use_bytes": pct_bytes,
                     "source_id": link[0], "destination_id": link[1]}
            snap = {**snap, "destinationId": link[1]}
            by_id[cid] = snap
            if queued:
                summary["queues"].append(entry)
                facts = {"component_kind": "connection", **{k: v for k, v in entry.items() if k != "connection_id"}}
                ev = out.add_evidence(_ev(src, "status", ptr, facts, component_id=cid))
                label = f"connection '{entry['name']}' ({cid})" if entry["name"] else f"connection {cid}"
                engaged = (isinstance(pct, (int, float)) and pct >= 100) or (isinstance(pct_bytes, (int, float)) and pct_bytes >= 100)
                if engaged:
                    summary["backpressure_engaged"].append(cid)
                if pct is None and pct_bytes is None:
                    text = f"{label} held {queued} FlowFiles at {src.collected_at}; no back-pressure threshold applies."
                else:
                    text = (f"{label} held {queued} FlowFiles at {src.collected_at} "
                            f"({pct if pct is not None else 'n/a'}% of the object threshold"
                            + ("; back pressure engaged)." if engaged else ")."))
                out.add_finding(make_finding(finding_id=f"OBS-QUEUE:{cid}", kind="observed",
                                             severity="warning" if engaged else "info", evidence_ids=[ev],
                                             statement=text, limitations=[LIM_STATUS]))
    summary["queues"].sort(key=lambda q: (-(q["queued"] or 0), q["connection_id"]))
    _status_hypotheses(by_id, src, out)
    return summary


def _status_hypotheses(by_id: dict[str, dict], src: Source, out: EvidenceSet) -> None:
    """Server-generated, clearly labelled hypotheses linking queues to blocked destinations."""
    for cid, snap in by_id.items():
        if "destinationId" not in snap or not snap.get("flowFilesQueued"):
            continue
        dest = by_id.get(snap.get("destinationId"))
        if not dest or dest.get("runStatus") not in ("Invalid", "Stopped", "Disabled"):
            continue
        q_ev = f"OBS-QUEUE:{cid}"
        d_ev = f"OBS-{'INVALID' if dest.get('runStatus') == 'Invalid' else 'STOPPED'}:{dest.get('id')}"
        if q_ev not in out.findings or d_ev not in out.findings:
            continue
        evidence = out.findings[q_ev]["evidence_ids"] + out.findings[d_ev]["evidence_ids"]
        out.add_finding(make_finding(
            finding_id=f"HYP-QUEUE-BLOCKED:{cid}", kind="hypothesis", severity="review", evidence_ids=evidence,
            statement=(f"Plausible explanation: FlowFiles queued on connection {cid} are waiting because its destination "
                       f"was {dest.get('runStatus')} at {src.collected_at}."),
            limitations=["Hypothesis generated by a fixed rule; not verified.", LIM_STATUS,
                         "The queue may also contain data that arrived before the destination stopped."]))


# ------------------------------------------------------------------- bulletins
def parse_bulletins(response: dict, src: Source, redactor: Redactor, out: EvidenceSet, *,
                    scope_ids: set[str], interval: tuple[dt.datetime, dt.datetime] | None) -> dict:
    board = response.get("bulletinBoard") if isinstance(response, dict) else None
    if not isinstance(board, dict):
        raise ValueError("not a BulletinBoardEntity")
    base = src.base_pointer + "/bulletinBoard/bulletins"
    kept, unreadable, out_scope, out_window = [], 0, 0, 0
    for i, entity in enumerate(board.get("bulletins") or []):
        if not isinstance(entity, dict):
            continue
        if entity.get("canRead") is False or not isinstance(entity.get("bulletin"), dict):
            # Count only unreadable bulletins that are in scope or whose component is unknown; never
            # disclose activity in components outside the configured scope.
            where = {entity.get("sourceId"), entity.get("groupId")} - {None}
            if not where or where & scope_ids:
                unreadable += 1
            continue
        b = entity["bulletin"]
        if b.get("sourceId") not in scope_ids and b.get("groupId") not in scope_ids:
            out_scope += 1
            continue
        when = None
        if isinstance(b.get("timestampIso"), str):
            try:
                when = parse_iso(b["timestampIso"])
            except ValueError:
                when = None
        if interval and (when is None or not (interval[0] <= when <= interval[1])):
            out_window += 1
            continue
        facts = {"level": b.get("level"), "category": b.get("category"), "source_name": redactor.name(b.get("sourceName")),
                 "source_type": b.get("sourceType"), "message": redactor.bulletin_message(b.get("message")),
                 "untrusted_text": True}
        ev = out.add_evidence(_ev(src, "bulletin", jp.join(base, i, "bulletin"), facts,
                                  component_id=b.get("sourceId"), event_time=iso(when) if when else None))
        kept.append({"evidence_id": ev, "source_id": b.get("sourceId"), "level": b.get("level"),
                     "time": iso(when) if when else None})
    groups: dict[tuple, list] = {}
    for item in kept:
        groups.setdefault((item["source_id"], item["level"]), []).append(item)
    for (sid, level), items in sorted(groups.items(), key=lambda kv: (str(kv[0][0]), str(kv[0][1]))):
        times = sorted(t["time"] for t in items if t["time"])
        out.add_finding(make_finding(
            finding_id=f"OBS-BULLETINS:{sid}:{level}", kind="observed",
            severity="warning" if level in ("ERROR", "WARNING") else "info",
            evidence_ids=[t["evidence_id"] for t in items],
            statement=(f"{len(items)} {level} bulletin(s) from component {sid}"
                       + (f" between {times[0]} and {times[-1]}." if times else ".")),
            limitations=["Bulletin text is untrusted data and was scrubbed; NiFi keeps only recent bulletins.",
                         "Bulletins show what NiFi reported, not the root cause."]))
    if unreadable:
        out.add_gap("BULLETINS_NOT_READABLE", f"{unreadable} bulletin(s) were not readable with this identity.")
    if out_window:
        out.add_gap("BULLETINS_OUTSIDE_INTERVAL", f"{out_window} in-scope bulletin(s) fell outside the requested interval.")
    return {"count": len(kept), "excluded_unreadable": unreadable, "excluded_outside_interval": out_window}


# ------------------------------------------------------------------ provenance
def provenance_events(response: dict) -> tuple[list[dict], str, dict]:
    prov = response.get("provenance") if isinstance(response, dict) else None
    if not isinstance(prov, dict) or not isinstance(prov.get("results"), dict):
        raise ValueError("not a ProvenanceEntity")
    results = prov["results"]
    events = results.get("provenanceEvents") or []
    return [e for e in events if isinstance(e, dict)], "/provenance/results/provenanceEvents", results


def event_time(event: dict) -> dt.datetime | None:
    if isinstance(event.get("eventTimestamp"), str):
        try:
            return parse_iso(event["eventTimestamp"])
        except ValueError:
            pass
    return parse_nifi_time(event.get("eventTime")) if isinstance(event.get("eventTime"), str) else None


def event_matches(event: dict, selector: dict) -> bool:
    kind = selector["kind"]
    if kind == "flowfile_uuid":
        return event.get("flowFileUuid") == selector["value"]
    attrs = {a.get("name"): a.get("value") for a in event.get("attributes") or [] if isinstance(a, dict)}
    if kind == "filename":
        return attrs.get("filename") == selector["value"]
    return attrs.get(selector["name"]) == selector["value"]


def parse_provenance(events: list[tuple[dict, str, Source]], redactor: Redactor, out: EvidenceSet, *,
                     scope_ids: set[str], interval: tuple[dt.datetime, dt.datetime]) -> dict:
    """events: (event dict, pointer, source). Returns timeline, lineage and exclusion counts."""
    timeline, outside_scope, outside_window, seen = [], 0, 0, set()
    for event, ptr, src in events:
        when = event_time(event)
        if event.get("groupId") not in scope_ids and event.get("componentId") not in scope_ids:
            outside_scope += 1
            continue
        if when is None or not (interval[0] <= when <= interval[1]):
            outside_window += 1
            continue
        node = event.get("clusterNodeId") or src.node_id
        key = (node, event.get("eventId"), event.get("id"))
        if key in seen:
            continue
        seen.add(key)
        transit = event.get("transitUri")
        facts = {
            "event_id": event.get("eventId"), "event_type": event.get("eventType"),
            "component_type": event.get("componentType"), "component_name": redactor.name(event.get("componentName")),
            "group_id": event.get("groupId"), "relationship": event.get("relationship"),
            "flowfile_uuid": event.get("flowFileUuid"),
            "parent_uuids": [u for u in event.get("parentUuids") or [] if isinstance(u, str)][:50],
            "child_uuids": [u for u in event.get("childUuids") or [] if isinstance(u, str)][:50],
            "transit_uri": redactor.endpoint(transit, ptr) if isinstance(transit, str) else None,
            "file_size_bytes": event.get("fileSizeBytes"),
            "lineage_duration_ms": event.get("lineageDuration"),
            "attributes": redactor.attributes(event.get("attributes")),
            "filename": redactor.filename(next((a.get("value") for a in event.get("attributes") or []
                                                if isinstance(a, dict) and a.get("name") == "filename"), None)),
        }
        ev = out.add_evidence(_ev(src, "provenance", ptr, facts, component_id=event.get("componentId"),
                                  event_time=iso(when), extra=str(node)))
        timeline.append({"evidence_id": ev, "time": iso(when), "node_id": node, **{k: facts[k] for k in (
            "event_id", "event_type", "component_type", "component_name", "relationship", "flowfile_uuid",
            "parent_uuids", "child_uuids", "transit_uri")}, "component_id": event.get("componentId")})
    timeline.sort(key=lambda e: (e["time"], str(e["node_id"]), e["event_id"] or 0))
    edges = []
    for item in timeline:
        for parent in item["parent_uuids"]:
            edges.append({"from": parent, "to": item["flowfile_uuid"], "via": item["event_type"], "evidence_id": item["evidence_id"]})
        for child in item["child_uuids"]:
            edges.append({"from": item["flowfile_uuid"], "to": child, "via": item["event_type"], "evidence_id": item["evidence_id"]})
    by_ff: dict[str, list[dict]] = {}
    for item in timeline:
        by_ff.setdefault(item["flowfile_uuid"], []).append(item)
    for ff, items in by_ff.items():
        for a, b in zip(items, items[1:]):
            edges.append({"from": a["component_id"], "to": b["component_id"], "via": "component_sequence",
                          "flowfile_uuid": ff, "evidence_id": b["evidence_id"]})
    for item in timeline:
        if item["event_type"] == "SEND":
            out.add_finding(make_finding(
                finding_id=f"OBS-SEND:{item['node_id']}:{item['event_id']}", kind="observed", severity="info",
                evidence_ids=[item["evidence_id"]],
                statement=f"NiFi recorded a SEND by component {item['component_id']} at {item['time']}.",
                limitations=[LIM_SEND]))
        elif item["event_type"] == "ROUTE" and item["relationship"] == "unmatched":
            out.add_finding(make_finding(
                finding_id=f"OBS-ROUTE-UNMATCHED:{item['node_id']}:{item['event_id']}", kind="observed", severity="info",
                evidence_ids=[item["evidence_id"]],
                statement=f"FlowFile {item['flowfile_uuid']} was routed to 'unmatched' by component {item['component_id']} at {item['time']}.",
                limitations=[LIM_UNMATCHED]))
        elif item["event_type"] == "DROP":
            out.add_finding(make_finding(
                finding_id=f"OBS-DROP:{item['node_id']}:{item['event_id']}", kind="observed", severity="info",
                evidence_ids=[item["evidence_id"]],
                statement=f"NiFi recorded a DROP of FlowFile {item['flowfile_uuid']} at {item['time']}.",
                limitations=["DROP ends NiFi's tracking (for example an auto-terminated relationship); "
                             "it does not by itself indicate an error."]))
    # Stated on every provenance result, with no count, so its presence never reveals out-of-scope activity.
    out.add_gap("EVENTS_OUTSIDE_SCOPE_DROPPED",
                "Events from components outside the configured scope are discarded before any evidence is created; "
                "they are not counted or disclosed. If the NiFi identity can read components outside the scope, "
                "their events also count against the event limit, so use an identity scoped to these groups.")
    if outside_window:
        out.add_gap("EVENTS_OUTSIDE_INTERVAL", f"{outside_window} event(s) fell outside the requested interval.")
    if not timeline:
        out.add_gap("NO_MATCHING_EVENTS", LIM_EMPTY)
    return {"timeline": timeline, "lineage_edges": edges[:2000], "events": len(timeline),
            "excluded_outside_interval": outside_window}


# ------------------------------------------------------------------ queue sample
def parse_queue_sample(summaries: list[dict], ptr: str, src: Source, redactor: Redactor, out: EvidenceSet, *,
                       connection_id: str, sample_size: int) -> dict:
    sample = []
    for i, s in enumerate(summaries[:sample_size]):
        if not isinstance(s, dict):
            continue
        facts = {"uuid": s.get("uuid"), "position": s.get("position"), "size": s.get("size"),
                 "queued_duration_ms": s.get("queuedDuration"), "lineage_duration_ms": s.get("lineageDuration"),
                 "penalized": s.get("penalized"), "filename": redactor.filename(s.get("filename"))}
        ev = out.add_evidence(_ev(src, "queue_sample", jp.join(ptr, i), facts, component_id=connection_id))
        sample.append({"evidence_id": ev, **facts})
    if summaries[sample_size:]:
        out.add_gap("QUEUE_SAMPLE_TRUNCATED", f"Only the first {sample_size} queue entries were sampled.")
    if sample:
        out.add_finding(make_finding(
            finding_id=f"OBS-QUEUE-SAMPLE:{connection_id}", kind="observed", severity="info",
            evidence_ids=[s["evidence_id"] for s in sample],
            statement=f"Sampled metadata for {len(sample)} queued FlowFile(s) on connection {connection_id} at {src.collected_at}.",
            limitations=[LIM_SAMPLE, "Content and attributes were not read."]))
    return {"sampled": len(sample), "entries": sample}


def in_interval(ts: str | None, interval: tuple[dt.datetime, dt.datetime]) -> bool:
    if ts is None:
        return False
    try:
        when = parse_iso(ts)
    except ValueError:
        return False
    return interval[0] <= when <= interval[1]


def jp_join(*args: Any) -> str:
    return jp.join(*args)
