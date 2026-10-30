"""A18, A19 and real-lab A08: secure stock NiFi 2.12.0 with a restricted observer identity."""
import datetime as dt
import json

import anyio
import pytest

from integration_fixtures import Recorder, identity_client, service_for
from nifimcp.core.evidence import verify_citation
from nifimcp.service import call_tool

pytestmark = pytest.mark.integration


def window(minutes=50):
    now = dt.datetime.now(dt.timezone.utc)
    return {"start": (now - dt.timedelta(minutes=minutes)).isoformat(), "end": (now + dt.timedelta(minutes=1)).isoformat()}


def run(svc, tool, args):
    return anyio.run(call_tool, svc, tool, args)


def test_lab_is_secure_stock_2_12_0_with_separate_identities(lab, admin):
    m = lab["manifest"]
    assert m["origin"].startswith("https://127.0.0.1:")
    assert m["image"]["digest"] == "sha256:6f7f2840dbf178c6dd3fa13435b9b358f3be3c6fb7417de467a35a267f4d28ad"
    assert admin.get("/flow/about")["about"]["version"] == "2.12.0"
    assert "21." in m["runtime"]["java_version"]
    dns = {name: i["dn"] for name, i in m["pki"]["identities"].items()}
    assert len(set(dns.values())) == 4 and dns["admin"] != dns["observer"]
    # Plain HTTP is not served and an unauthenticated client is refused.
    import ssl, httpx2
    ctx = ssl.create_default_context(cafile=m["pki"]["ca_path"])
    with httpx2.Client(base_url=m["origin"] + "/nifi-api", verify=ctx, trust_env=False) as anon:
        try:
            status = anon.get("/flow/process-groups/root").status_code
        except httpx2.TransportError:
            status = "tls-rejected"     # NiFi requires a client certificate at the TLS layer
        assert status in (401, 403, "tls-rejected")


def test_observer_has_read_only_policies(lab, admin):
    users = {u["component"]["identity"]: u["id"] for u in admin.get("/tenants/users")["users"]}
    observer = users[lab["manifest"]["pki"]["identities"]["observer"]["dn"]]
    detail = admin.get(f"/tenants/users/{observer}")
    actions = {(p["component"]["action"], p["component"]["resource"]) for p in detail["component"]["accessPolicies"]}
    assert actions and all(a == "read" for a, _ in actions)
    with identity_client(lab, "observer") as obs:
        cu = obs.get("/flow/current-user").json()
        assert not any(isinstance(v, dict) and v.get("canWrite") for v in cu.values())
        fx = lab["fx"]
        entity = obs.get(f"/processors/{fx['generator_id']}").json()
        denied = obs.put(f"/processors/{fx['generator_id']}/run-status",
                         json={"revision": entity["revision"], "state": "RUNNING"})
        assert denied.status_code == 403


def test_capabilities_live(lab, tmp_path):
    svc = service_for(lab, "observer", tmp_path)
    env = run(svc, "get_capabilities", {})
    data = env["data"]
    assert data["runtime"]["nifi_version"] == "2.12.0" and data["runtime"]["qualified"]
    assert data["topology"]["clustered"] is False
    assert data["permissions"]["provenance_query"] is True
    assert data["permissions"]["scope_read"] == {"lab-scope": True}


def test_describe_flow_cites_exact_live_bytes(lab, tmp_path):
    svc = service_for(lab, "observer", tmp_path)
    env = run(svc, "describe_flow", {"scope_id": "lab-scope", "depth": 4})
    assert env["status"] in ("ok", "partial") and env["error"] is None
    names = {n.get("name") for n in env["data"]["graph"]["nodes"]}
    assert {"Route by status", "Normalize status", "Unmatched review"} <= names
    raw = [r for r in svc.s.store.listing(svc.s.session_id) if r["kind"] == "raw_observation"]
    assert raw
    rec, data = svc.s.store.read_bytes(raw[0]["artifact_id"], svc.s.session_id)
    doc = json.loads(data)
    finding = next(f for f in env["findings"] if f["finding_id"].startswith("NM-UNMATCHED-ROUTE"))
    for ev_id in finding["evidence_ids"]:
        ev = next(e for e in env["evidence"] if e["evidence_id"] == ev_id)
        verify_citation(ev, data, doc)


def test_health_status_and_bulletins_live(lab, tmp_path, fresh_activity):
    svc = service_for(lab, "observer", tmp_path)
    env = run(svc, "get_flow_health", {"scope_id": "lab-scope", "interval": window(10)})
    assert env["error"] is None
    ids = {f["finding_id"].split(":")[0] for f in env["findings"]}
    assert {"OBS-INVALID", "OBS-QUEUE", "OBS-BULLETINS"} <= ids
    bulletins = [e for e in env["evidence"] if e["kind"] == "bulletin"]
    assert bulletins and all(e["facts"]["untrusted_text"] for e in bulletins)
    unm = next(q for s in env["data"]["status"] for q in s["queues"] if q["connection_id"] == lab["fx"]["unmatched_connection_id"])
    assert unm["queued"] >= 1 and unm["percent_use_count"] == 100


def test_trace_and_unmatched_live_without_extra_authority(lab, tmp_path, fresh_activity):
    svc = service_for(lab, "observer", tmp_path)
    rec = Recorder(svc)
    unm = run(svc, "inspect_unmatched", {"connection_id": lab["fx"]["unmatched_connection_id"],
                                         "interval": window(60), "sample_metadata": True})
    assert unm["error"] is None, unm["error"]
    assert unm["data"]["unmatched_events"]["events"] >= 1
    sample = unm["data"]["queue_sample"]["entries"]
    assert sample
    first = sample[0]
    trace = run(svc, "trace_feed", {"scope_id": "lab-scope", "interval": window(60),
                                    "selector": {"kind": "flowfile_uuid", "value": first["uuid"]}})
    assert trace["error"] is None
    types = [e["event_type"] for e in trace["data"]["timeline"]]
    assert "ROUTE" in types and any(e["relationship"] == "unmatched" for e in trace["data"]["timeline"])
    by_name = run(svc, "trace_feed", {"scope_id": "lab-scope", "interval": window(60),
                                      "selector": {"kind": "filename", "value": first["filename"]["value"]}})
    assert by_name["data"]["events"] >= 1
    methods = {(m, ep) for m, ep, _ in rec.calls}
    assert all(m == "GET" or ep in ("provenance_submit", "provenance_delete", "listing_submit", "listing_delete")
               for m, ep in methods)
    posts = sum(1 for m, _, _ in rec.calls if m == "POST")
    deletes = sum(1 for m, _, _ in rec.calls if m == "DELETE")
    assert posts == deletes                       # every owned request was cleaned up
    assert svc.s.source.registry.active == []


def test_foreign_ids_rejected_before_any_dependent_read(lab, tmp_path):
    svc = service_for(lab, "observer", tmp_path)
    rec = Recorder(svc)
    fx = lab["fx"]
    env = run(svc, "inspect_unmatched", {"connection_id": fx["foreign_connection_id"], "sample_metadata": True})
    assert env["error"]["code"] == "OUT_OF_SCOPE"
    assert not any(fx["foreign_connection_id"] in params for _, _, params in rec.calls)
    env = run(svc, "describe_flow", {"scope_id": fx["foreign_group_id"]})
    assert env["error"]["code"] == "OUT_OF_SCOPE"
    assert not any(fx["foreign_group_id"] in params for _, _, params in rec.calls)


def test_indexed_attribute_not_assumed(lab, tmp_path):
    svc = service_for(lab, "observer", tmp_path)
    env = run(svc, "trace_feed", {"scope_id": "lab-scope", "interval": window(30),
                                  "selector": {"kind": "indexed_attribute", "name": "status", "value": "unknown"}})
    assert env["error"]["code"] == "INVALID_ARGUMENT"
    assert "not indexed" in env["error"]["message"]
