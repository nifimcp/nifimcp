"""A11: owned query lifecycle completes and cleans up on success and failure (real NiFi 2.12.0)."""
import datetime as dt

import anyio
import pytest

from integration_fixtures import identity_client, service_for
from nifimcp.errors import ErrorCode, NiFiMCPError

pytestmark = pytest.mark.integration
NOW = dt.datetime.now(dt.timezone.utc)
IV = (NOW - dt.timedelta(minutes=90), NOW + dt.timedelta(minutes=5))


def provenance_cancelled(lab, query_id):
    """NiFi 2.12.0 cancels (not removes) a deleted provenance query; it stays readable until expiry.
    Verify the query is known to NiFi and that NiFiMCP recorded an acknowledged delete."""
    with identity_client(lab, "observer") as obs:
        return obs.get(f"/provenance/{query_id}").status_code == 200


def test_success_lifecycle_deletes_query(lab, tmp_path, fresh_activity):
    svc = service_for(lab, "observer", tmp_path)
    src = svc.s.source

    async def go():
        return await src.provenance("lab-scope", selector=None, processor_id=lab["fx"]["router_id"],
                                    relationship="unmatched", interval=IV, max_events=50)
    events, meta, gaps = anyio.run(go)
    assert meta["finished"] and meta["cleanup"] == "delete_acknowledged"
    assert events
    assert any(g["code"] == "NIFI_RETAINS_CANCELLED_QUERY" for g in gaps)
    assert provenance_cancelled(lab, meta["request"])


def test_failure_after_creation_still_deletes(lab, tmp_path):
    svc = service_for(lab, "observer", tmp_path)
    src = svc.s.source
    original = src.http.call

    async def failing(endpoint, **kw):
        if endpoint == "provenance_get":
            raise NiFiMCPError(ErrorCode.QUERY_FAILED, "injected poll failure")
        result = await original(endpoint, **kw)
        if endpoint == "provenance_submit":
            result.data["provenance"]["finished"] = False   # force at least one poll
        return result
    src.http.call = failing

    async def go():
        with pytest.raises(NiFiMCPError):
            await src.provenance("lab-scope", selector=None, processor_id=lab["fx"]["router_id"],
                                 relationship="unmatched", interval=IV, max_events=50)
    created = []
    real_register = src.registry._register

    def remember(*a, **k):
        req = real_register(*a, **k)
        created.append(req.request_id)
        return req
    src.registry._register = remember
    anyio.run(go)
    assert created and src.registry.history[-1].deleted
    assert src.registry.history[-1].state == "delete_acknowledged"


def test_cancellation_mid_poll_deletes_real_query(lab, tmp_path):
    svc = service_for(lab, "observer", tmp_path)
    src = svc.s.source
    original = src.http.call

    async def slow_submit(endpoint, **kw):
        result = await original(endpoint, **kw)
        if endpoint == "provenance_submit":
            result.data["provenance"]["finished"] = False   # force the poll loop
        if endpoint == "provenance_get":
            await anyio.sleep(30)
        return result
    src.http.call = slow_submit

    async def go():
        with anyio.move_on_after(2):
            await src.provenance("lab-scope", selector=None, processor_id=lab["fx"]["router_id"],
                                 relationship="unmatched", interval=IV, max_events=10)
    anyio.run(go)
    req = src.registry.history[-1]
    assert req.deleted and req.state == "delete_acknowledged"


def test_listing_lifecycle(lab, tmp_path):
    svc = service_for(lab, "observer", tmp_path)

    async def go():
        return await svc.s.source.queue_sample("lab-scope", lab["fx"]["unmatched_connection_id"], 5)
    summaries, ptr, src, gaps = anyio.run(go)
    assert summaries is not None and len(summaries) >= 1
    req = svc.s.source.registry.history[-1]
    assert req.state == "deleted"
    with identity_client(lab, "observer") as obs:   # listing deletion really removes it on 2.12.0
        url = f"/flowfile-queues/{lab['fx']['unmatched_connection_id']}/listing-requests/{req.request_id}"
        assert obs.get(url).status_code == 404
