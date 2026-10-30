"""A12: cancellation, ambiguous POST timeout, foreign query ID and failed cleanup handled honestly.

Client-side lifecycle edge cases use a recording fake (they cannot be forced on a
healthy NiFi). The real-lab lifecycle is covered by tests/integration/test_queries.py.
"""
import datetime as dt

import anyio
import pytest

from fakenifi import QUERY_ID, UNMATCHED_CONN, FakeNiFi, fake_service
from helpers import run
from nifimcp.errors import NiFiMCPError

NOW = dt.datetime.now(dt.timezone.utc)
WINDOW = {"start": (NOW - dt.timedelta(minutes=30)).isoformat(), "end": NOW.isoformat()}
SEL = {"kind": "flowfile_uuid", "value": "6ae1e6de-d4a6-4f88-be99-5ac47c13e079"}


def test_success_path_creates_polls_and_deletes(tmp_path):
    fake = FakeNiFi(prov_finish_after=2)
    svc, source = fake_service(tmp_path, fake)
    env = run(svc, "trace_feed", {"scope_id": "scope-a", "selector": SEL, "interval": WINDOW})
    assert env["status"] in ("ok", "partial") and env["error"] is None
    methods = [m for m, p in fake.requests if "/provenance" in p and "search-options" not in p]
    assert methods.count("POST") == 1 and methods.count("DELETE") == 1 and methods.count("GET") >= 2
    assert QUERY_ID in fake.deleted
    assert source.registry.history[-1].state == "delete_acknowledged"
    assert any(g["code"] == "NO_MATCHING_EVENTS" for g in env["gaps"])


def test_cancellation_still_cleans_up(tmp_path):
    fake = FakeNiFi(prov_finish_after=10_000)
    svc, source = fake_service(tmp_path, fake)

    async def go():
        with anyio.move_on_after(1.5):
            await source.provenance("scope-a", selector=SEL, processor_id=None, relationship=None,
                                    interval=(NOW - dt.timedelta(minutes=30), NOW), max_events=10)
    anyio.run(go)
    assert QUERY_ID in fake.deleted
    assert source.registry.history[-1].deleted is True
    assert source.registry.active == []


def test_time_budget_exhaustion_cleans_up_and_is_partial(tmp_path):
    fake = FakeNiFi(prov_finish_after=10_000)
    svc, source = fake_service(tmp_path, fake, limits={"tool_timeout_seconds": 10, "queue_sampling_enabled": True})
    env = run(svc, "trace_feed", {"scope_id": "scope-a", "selector": SEL, "interval": WINDOW})
    assert env["status"] == "partial"
    assert any(g["code"] == "QUERY_INCOMPLETE" for g in env["gaps"])
    assert QUERY_ID in fake.deleted


def test_ambiguous_post_timeout_is_not_retried(tmp_path):
    fake = FakeNiFi(fail={"provenance_submit": "timeout"})
    svc, source = fake_service(tmp_path, fake)
    env = run(svc, "trace_feed", {"scope_id": "scope-a", "selector": SEL, "interval": WINDOW})
    assert env["error"]["code"] == "TIMEOUT"
    posts = [p for m, p in fake.requests if m == "POST"]
    assert posts == ["/provenance"]                      # exactly one attempt
    assert not any(m in ("GET", "DELETE") and QUERY_ID in p for m, p in fake.requests)
    assert source.registry.history == []                 # nothing claimed as owned


def test_foreign_query_ids_are_never_polled_or_deleted(tmp_path):
    fake = FakeNiFi()
    svc, source = fake_service(tmp_path, fake)
    with pytest.raises(NiFiMCPError) as err:
        source.registry.owned("cccccccc-0000-0000-0000-000000000003", "provenance")
    assert err.value.code == "OUT_OF_SCOPE"
    from nifimcp.models import TOOL_ARG_MODELS
    for model in TOOL_ARG_MODELS.values():
        assert not any("query" in f or "request_id" in f for f in model.model_fields)


def test_failed_cleanup_is_reported_as_gap(tmp_path):
    fake = FakeNiFi(fail={"provenance_delete": 500})
    svc, source = fake_service(tmp_path, fake)
    env = run(svc, "trace_feed", {"scope_id": "scope-a", "selector": SEL, "interval": WINDOW})
    assert env["status"] == "partial"
    gap = next(g for g in env["gaps"] if g["code"] == "CLEANUP_FAILED")
    assert QUERY_ID in gap["detail"]
    assert source.registry.history[-1].state == "cleanup_failed"


def test_poll_error_still_cleans_up(tmp_path):
    fake = FakeNiFi(prov_finish_after=5, fail={"provenance_get": 403})
    svc, source = fake_service(tmp_path, fake)
    env = run(svc, "trace_feed", {"scope_id": "scope-a", "selector": SEL, "interval": WINDOW})
    assert env["error"]["code"] == "PERMISSION_DENIED"
    assert QUERY_ID in fake.deleted


def test_active_request_limit(tmp_path):
    fake = FakeNiFi(prov_finish_after=3)
    svc, source = fake_service(tmp_path, fake, limits={"concurrency": 1, "queue_sampling_enabled": True})
    peak = {"n": 0}
    original = source.registry.http.call

    async def counting(endpoint, **kw):
        peak["n"] = max(peak["n"], len(source.registry.active))
        return await original(endpoint, **kw)
    source.registry.http.call = counting

    async def go():
        async with anyio.create_task_group() as tg:
            for _ in range(3):
                tg.start_soon(lambda: source.provenance("scope-a", selector=SEL, processor_id=None, relationship=None,
                                                        interval=(NOW - dt.timedelta(minutes=30), NOW), max_events=5))
    anyio.run(go)
    assert peak["n"] <= 1


def test_listing_cleanup(tmp_path):
    fake = FakeNiFi()
    svc, source = fake_service(tmp_path, fake)
    env = run(svc, "inspect_unmatched", {"connection_id": UNMATCHED_CONN, "sample_metadata": True})
    assert env["error"] is None
    assert "bbbbbbbb-0000-0000-0000-000000000002" in fake.deleted
