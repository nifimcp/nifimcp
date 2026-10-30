"""A08: foreign group, component, connection and artifact IDs rejected before dependent reads.

Client-side behavior is proven with a recording fake; the real-lab equivalent is
tests/integration/test_live_nifi.py::test_foreign_ids_rejected_before_any_dependent_read.
"""
import anyio

from fakenifi import FOREIGN, ROUTER, SCOPE_PG, UNMATCHED_CONN, FakeNiFi, fake_service
from helpers import demo_session, run
from nifimcp.service import call_tool


def test_foreign_connection_rejected_without_using_the_id(tmp_path):
    fake = FakeNiFi()
    svc, _ = fake_service(tmp_path, fake)
    env = run(svc, "inspect_unmatched", {"connection_id": FOREIGN, "sample_metadata": True})
    assert env["error"]["code"] == "OUT_OF_SCOPE"
    assert not fake.touched(FOREIGN)
    assert not any(m == "POST" for m, _ in fake.requests)   # no listing or provenance request created


def test_in_scope_connection_allowed(tmp_path):
    fake = FakeNiFi()
    svc, _ = fake_service(tmp_path, fake)
    env = run(svc, "inspect_unmatched", {"connection_id": UNMATCHED_CONN, "sample_metadata": True})
    assert env["status"] in ("ok", "partial"), env["error"]
    assert fake.touched(f"/flowfile-queues/{UNMATCHED_CONN}/listing-requests")


def test_unconfigured_scope_and_foreign_group_rejected_before_any_request(tmp_path):
    fake = FakeNiFi()
    svc, _ = fake_service(tmp_path, fake)
    for scope in ("scope-b", FOREIGN):
        env = run(svc, "describe_flow", {"scope_id": scope})
        assert env["error"]["code"] == "OUT_OF_SCOPE"
        assert env["scope"] == "global"
    assert fake.requests == []


def test_foreign_processor_id_rejected_before_provenance(tmp_path):
    fake = FakeNiFi()
    svc, source = fake_service(tmp_path, fake)
    import datetime as dt
    from nifimcp.errors import NiFiMCPError
    now = dt.datetime.now(dt.timezone.utc)

    async def go():
        try:
            await source.provenance("scope-a", selector=None, processor_id=FOREIGN, relationship="unmatched",
                                    interval=(now - dt.timedelta(minutes=5), now), max_events=10)
        except NiFiMCPError as err:
            return err.code
    assert anyio.run(go) == "OUT_OF_SCOPE"
    assert not fake.touched(FOREIGN) and not any(m == "POST" for m, _ in fake.requests)


def test_foreign_and_unknown_artifact_ids_rejected(tmp_path):
    a = demo_session(tmp_path / "a")
    b = demo_session(tmp_path / "a")      # same artifact directory, different session
    caps_a = run(a, "get_capabilities", {})
    own = [x["artifact_id"] for x in caps_a["data"]["artifacts"] if x["kind"] == "flow_definition"]
    env = run(b, "compare_flow_snapshots", {"baseline_artifact_id": own[0], "candidate_artifact_id": own[1]})
    assert env["error"]["code"] == "OUT_OF_SCOPE"
    env = run(a, "compare_flow_snapshots", {"baseline_artifact_id": "art_" + "A" * 24, "candidate_artifact_id": own[1]})
    assert env["error"]["code"] == "OUT_OF_SCOPE"
    inv = run(a, "export_investigation", {"investigation_id": "inv-from-elsewhere", "format": "json"})
    assert inv["error"]["code"] == "OUT_OF_SCOPE"


def test_tampered_artifact_is_stale(tmp_path):
    a = demo_session(tmp_path)
    own = [x for x in run(a, "get_capabilities", {})["data"]["artifacts"] if x["kind"] == "flow_definition"]
    rec = a.s.store.get(own[0]["artifact_id"], a.s.session_id)
    path = a.s.store.path_of(rec)
    path.write_bytes(path.read_bytes() + b" ")
    env = run(a, "compare_flow_snapshots", {"baseline_artifact_id": own[0]["artifact_id"],
                                            "candidate_artifact_id": own[1]["artifact_id"]})
    assert env["error"]["code"] == "STALE_ARTIFACT"


def test_trace_does_not_reveal_out_of_scope_activity(tmp_path):
    """A selector that only matches events in a foreign group must look exactly like one that matches nothing."""
    from helpers import bundle_session, connection, definition, group, processor, uid, write_bundle
    root = group("scope-root", "Scoped", processors=[processor("p1", "Router")], connections=[])
    flow = definition(root)
    window = {"start": "2026-10-29T01:00:00Z", "end": "2026-10-29T02:00:00Z"}
    foreign_ff, absent_ff = "6ae1e6de-d4a6-4f88-be99-5ac47c13e079", "7be1e6de-d4a6-4f88-be99-5ac47c13e070"
    events = [{"id": str(i), "eventId": i, "eventTimestamp": "2026-10-29T01:30:00.000Z", "eventType": "ROUTE",
               "flowFileUuid": foreign_ff, "componentId": uid("foreign-proc"), "groupId": uid("foreign-group"),
               "relationship": "x", "attributes": [], "parentUuids": [], "childUuids": []} for i in range(3)]
    prov = {"collection": {}, "response": {"provenance": {"results": {"total": "3", "provenanceEvents": events}}}}
    bundle = write_bundle(tmp_path / "b", flow, scope_id="s", extra_files={"prov.json": ("provenance", prov, window)})
    svc = bundle_session(tmp_path, bundle)

    def shape(ff):
        env = run(svc, "trace_feed", {"scope_id": "s", "interval": window,
                                      "selector": {"kind": "flowfile_uuid", "value": ff}})
        return env["status"], env["findings"], env["gaps"], {k: v for k, v in env["data"].items() if k not in ("query", "selector")}
    assert shape(foreign_ff) == shape(absent_ff)


def test_capabilities_never_list_raw_responses_or_stored_results(tmp_path):
    svc, _ = fake_service(tmp_path, FakeNiFi())
    store, sid = svc.s.store, svc.s.session_id
    store.put(sid, "raw_observation", b'{"bulletins": []}', filename="raw.json", media_type="application/json")
    store.put(sid, "result", b"{}", filename="r.json", media_type="application/json")
    kinds = {a["kind"] for a in run(svc, "get_capabilities", {})["data"]["artifacts"]}
    assert not kinds & {"raw_observation", "result"}
    assert any(r.kind == "raw_observation" for r in store._records.values())   # still kept operator-local


def test_event_limit_gap_ignores_out_of_scope_events(tmp_path):
    """Foreign events filling the provenance cap must not change the in-scope result."""
    from helpers import bundle_session, definition, group, processor, uid, write_bundle
    root = group("scope-root2", "Scoped", processors=[processor("p1", "Router")], connections=[])
    window = {"start": "2026-10-29T01:00:00Z", "end": "2026-10-29T02:00:00Z"}
    ff = "6ae1e6de-d4a6-4f88-be99-5ac47c13e079"
    events = [{"id": str(i), "eventId": i, "eventTimestamp": "2026-10-29T01:30:00.000Z", "eventType": "ROUTE",
               "flowFileUuid": ff, "componentId": uid("foreign-proc"), "groupId": uid("foreign-group"),
               "relationship": "x", "attributes": [], "parentUuids": [], "childUuids": []} for i in range(250)]
    prov = {"collection": {}, "response": {"provenance": {"results": {"total": "250", "provenanceEvents": events}}}}
    bundle = write_bundle(tmp_path / "b", definition(root), scope_id="s",
                          extra_files={"prov.json": ("provenance", prov, window)})
    svc = bundle_session(tmp_path, bundle)
    env = run(svc, "trace_feed", {"scope_id": "s", "interval": window, "selector": {"kind": "flowfile_uuid", "value": ff}})
    assert env["status"] == "ok" and "EVENT_LIMIT_REACHED" not in {g["code"] for g in env["gaps"]}
