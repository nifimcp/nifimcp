"""A21: cluster detected and unsupported live scope blocked; no implicit multi-node claim.

The standalone case runs against the real lab. A real cluster is gate A34 (P1); here a
clustered summary is simulated to prove the fail-closed path, which is labelled as such.
"""
import anyio
import pytest

from integration_fixtures import service_for
from fakenifi import FakeNiFi, fake_service
from nifimcp.service import call_tool

pytestmark = pytest.mark.integration


def test_real_lab_detected_as_standalone(lab, tmp_path):
    svc = service_for(lab, "observer", tmp_path)
    caps = anyio.run(call_tool, svc, "get_capabilities", {})["data"]
    assert caps["topology"]["clustered"] is False
    assert caps["topology"]["live_investigation"] == "standalone: supported"
    assert "multi" not in str(caps["topology"]).lower()


def test_clustered_instance_fails_closed(tmp_path):
    svc, _ = fake_service(tmp_path, FakeNiFi(clustered=True))
    caps = anyio.run(call_tool, svc, "get_capabilities", {})["data"]
    assert caps["topology"]["live_investigation"] == "blocked (clustered)"
    for tool, args in (("describe_flow", {"scope_id": "scope-a"}), ("get_flow_health", {"scope_id": "scope-a"})):
        env = anyio.run(call_tool, svc, tool, args)
        assert env["error"]["code"] == "UNSUPPORTED_TOPOLOGY"


def test_unqualified_version_fails_closed(tmp_path):
    svc, _ = fake_service(tmp_path, FakeNiFi(version="2.13.0"))
    env = anyio.run(call_tool, svc, "describe_flow", {"scope_id": "scope-a"})
    assert env["error"]["code"] == "UNSUPPORTED_VERSION"
