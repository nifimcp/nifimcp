"""A05: exact source hash and pointers bind findings; stale notes invalidated; partial stays partial."""
import json

import pytest

from helpers import DEMO, connection, definition, demo_info, demo_session, group, processor, raw, run, sha
from nifimcp.config import RedactionPolicy
from nifimcp.core import pointer as jp
from nifimcp.core.evidence import CitationError, verify_citation
from nifimcp.core.flowmodel import normalize
from nifimcp.core.notes import Note, note_status
from nifimcp.core.redact import Redactor
from nifimcp.core.rules import analyze


def test_every_finding_cites_resolvable_evidence_in_exact_bytes():
    data = (DEMO / "telemetry-intake/flow-definition.json").read_bytes()
    doc = json.loads(data)
    model = normalize(doc, source_id="demo", source_hash=sha(data))
    out = analyze(model, Redactor(RedactionPolicy()), "2026-10-29T00:00:00.000Z")
    assert out.findings
    for finding in out.findings.values():
        assert finding["evidence_ids"]
        for ev_id in finding["evidence_ids"]:
            record = out.evidence[ev_id]
            value = verify_citation(record, data, doc)
            facts = record["facts"]
            if "field" in facts and isinstance(facts["value"], (int, list)):
                assert value == facts["value"]
            if "field" in facts and isinstance(facts["value"], dict) and facts["value"].get("state") == "value":
                assert value == facts["value"]["value"]


def test_changed_bytes_break_citations():
    data = (DEMO / "telemetry-intake/flow-definition.json").read_bytes()
    model = normalize(json.loads(data), source_id="demo", source_hash=sha(data))
    record = next(iter(analyze(model, Redactor(RedactionPolicy()), "2026-10-29T00:00:00.000Z").evidence.values()))
    with pytest.raises(CitationError):
        verify_citation(record, data.replace(b"Route by level", b"Route by LEVEL"))
    with pytest.raises(CitationError):
        verify_citation({**record, "source_pointer": "/flowContents/nope"}, data)


def test_pointer_escaping_round_trip():
    doc = {"a/b": {"c~d": [10, 20]}}
    ptr = jp.join("", "a/b", "c~d", 1)
    assert ptr == "/a~1b/c~0d/1"
    assert jp.resolve(doc, ptr) == 20
    for bad in ("/a~1b/c~0d/01", "/a~1b/c~0d/9", "nope"):
        with pytest.raises(jp.PointerError):
            jp.resolve(doc, bad)


def test_stale_and_missing_notes_are_not_current():
    data = raw(definition(group("root", processors=[processor("p1")])))
    doc = json.loads(data)
    note = Note(note_id="n1", author="a", created_at="2026-10-29T00:00:00Z", source_file="flow.json",
                source_sha256=sha(data), pointer="/flowContents/processors/0", text="t", origin="operator_note")
    assert note_status(note, {"flow.json": (sha(data), doc)}) == "current"
    changed = data.replace(b'"p"', b'"p2"')
    assert note_status(note, {"flow.json": (sha(changed), json.loads(changed))}) == "stale_source"
    moved = note.model_copy(update={"pointer": "/flowContents/processors/5"})
    assert note_status(moved, {"flow.json": (sha(data), doc)}) == "missing_reference"
    assert note_status(note, {}) == "source_unavailable"


def test_demo_stale_note_reported_as_gap_not_finding(tmp_path):
    svc = demo_session(tmp_path)
    info = demo_info()
    env = run(svc, "describe_flow", {"scope_id": info["scope"]})
    assert any(f["finding_id"] == "NOTE:note-unmatched-purpose" for f in env["findings"])
    assert not any(f["finding_id"] == "NOTE:note-old-threshold" for f in env["findings"])
    assert any(g["code"] == "STALE_NOTE" and "note-old-threshold" in g["detail"] for g in env["gaps"])
    note_finding = next(f for f in env["findings"] if f["kind"] == "operator_assertion")
    assert any("cannot override" in lim for lim in note_finding["limitations"])


def test_partial_collection_stays_partial_through_export(tmp_path):
    svc = demo_session(tmp_path)
    info = demo_info()
    # A window the bundle's provenance queries do not cover makes the trace partial.
    env = run(svc, "trace_feed", {"scope_id": info["scope"], "interval": {"start": "2026-10-01T00:00:00Z",
                                                                          "end": "2026-10-01T12:00:00Z"},
                                  "selector": {"kind": "flowfile_uuid", "value": info["trace_flowfile_uuid"]}})
    assert env["status"] == "partial"
    run(svc, "describe_flow", {"scope_id": info["scope"]})
    exp = run(svc, "export_investigation", {"investigation_id": env["data"]["investigation_id"], "format": "json"})
    assert exp["data"]["investigation_status"] == "partial" and exp["status"] == "partial"
    rec, data = svc.s.store.read_bytes(exp["data"]["artifact"]["artifact_id"], svc.s.session_id)
    doc = json.loads(data)
    assert doc["status"] == "partial"
    assert any(g["code"] == "PARTIAL_INVESTIGATION" for g in doc["gaps"])


def test_contradictory_times_are_surfaced(tmp_path):
    svc = demo_session(tmp_path)
    info = demo_info()
    env = run(svc, "inspect_unmatched", {"connection_id": info["unmatched_connection_id"], "interval": info["interval"]})
    mismatch = [f for f in env["findings"] if f["finding_id"].startswith("TEMPORAL-MISMATCH")]
    assert mismatch and "not known" in mismatch[0]["statement"]
