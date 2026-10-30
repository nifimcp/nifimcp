"""A20: denied policy remains denied and produces actionable partial capability."""
import anyio
import pytest

from integration_fixtures import service_for
from nifimcp.service import call_tool
from test_live_nifi import window

pytestmark = pytest.mark.integration


def run(svc, tool, args):
    return anyio.run(call_tool, svc, tool, args)


def test_restricted_identity_partial_capability(lab, tmp_path):
    svc = service_for(lab, "restricted", tmp_path)
    caps = run(svc, "get_capabilities", {})["data"]
    assert caps["permissions"]["provenance_query"] is False and caps["permissions"]["provenance_note"]
    described = run(svc, "describe_flow", {"scope_id": "lab-scope"})
    assert described["error"] is None
    trace = run(svc, "trace_feed", {"scope_id": "lab-scope", "interval": window(30),
                                    "selector": {"kind": "flowfile_uuid", "value": "6ae1e6de-d4a6-4f88-be99-5ac47c13e079"}})
    assert trace["error"]["code"] == "PERMISSION_DENIED"
    assert "policy" in trace["error"]["message"] or "policy" in trace["error"]["next_step"]
    unm = run(svc, "inspect_unmatched", {"connection_id": lab["fx"]["unmatched_connection_id"], "sample_metadata": True})
    assert unm["status"] == "partial"
    codes = {g["code"] for g in unm["gaps"]}
    assert "PERMISSION_DENIED_PARTIAL" in codes
    assert unm["data"]["routing"]["router_type"] == "RouteOnAttribute"   # topology context still provided


def test_outsider_is_denied_without_fallback(lab, tmp_path):
    svc = service_for(lab, "outsider", tmp_path)
    env = run(svc, "describe_flow", {"scope_id": "lab-scope"})
    assert env["error"]["code"] == "PERMISSION_DENIED"
    caps = run(svc, "get_capabilities", {})["data"]
    assert caps["permissions"]["scope_read"]["lab-scope"] is not True
    assert caps["permissions"]["provenance_query"] is False
