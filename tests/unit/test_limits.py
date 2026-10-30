"""A13: time, count, depth, size, concurrency and wall-time budgets enforced."""
import json
import time

import anyio
import pytest
from pydantic import ValidationError

from helpers import (bundle_session, definition, demo_info, demo_session, group, processor, run, write_bundle)
from nifimcp.limits import HARD, LimitsConfig
from nifimcp.service import call_tool
from nifimcp.util import canonical_bytes


def test_operator_cannot_exceed_hard_maxima():
    for key, value in (("maximum_time_window_minutes", 1441), ("maximum_provenance_events", 1001),
                       ("maximum_components", 2001), ("maximum_depth", 9), ("maximum_sample_size", 26),
                       ("maximum_concurrency", 3), ("maximum_timeout_seconds", 61),
                       ("maximum_result_bytes", 262145), ("maximum_bundle_expanded_bytes", 100 * 1024 * 1024 + 1)):
        with pytest.raises(ValidationError):
            LimitsConfig(**{key: value})
    with pytest.raises(ValidationError):
        LimitsConfig(time_window_minutes=120, maximum_time_window_minutes=60)
    assert LimitsConfig().as_public()["model_visible_result_bytes"] == HARD["result_bytes"]


def test_interval_limits(tmp_path):
    svc = demo_session(tmp_path)
    scope = demo_info()["scope"]
    long = run(svc, "get_flow_health", {"scope_id": scope, "interval": {"start": "2026-10-01T00:00:00Z",
                                                                       "end": "2026-10-02T00:00:01Z"}})
    assert long["error"]["code"] == "LIMIT_EXCEEDED"
    backwards = run(svc, "get_flow_health", {"scope_id": scope, "interval": {"start": "2026-10-02T00:00:00Z",
                                                                            "end": "2026-10-01T00:00:00Z"}})
    assert backwards["error"]["code"] == "INVALID_ARGUMENT"
    naive = run(svc, "get_flow_health", {"scope_id": scope, "interval": {"start": "2026-10-01T00:00:00",
                                                                        "end": "2026-10-01T01:00:00"}})
    assert naive["error"]["code"] == "INVALID_ARGUMENT"
    tight = demo_session(tmp_path / "t", limits={"maximum_time_window_minutes": 30, "time_window_minutes": 30,
                                                 "queue_sampling_enabled": True})
    over = run(tight, "get_flow_health", {"scope_id": scope, "interval": {"start": "2026-10-01T00:00:00Z",
                                                                         "end": "2026-10-01T00:31:00Z"}})
    assert over["error"]["code"] == "LIMIT_EXCEEDED"


def test_depth_bounds(tmp_path):
    svc = demo_session(tmp_path)
    scope = demo_info()["scope"]
    assert run(svc, "describe_flow", {"scope_id": scope, "depth": 9})["error"]["code"] == "INVALID_ARGUMENT"
    shallow = run(svc, "describe_flow", {"scope_id": scope, "depth": 1})
    assert any(g["code"] == "DEPTH_LIMITED" for g in shallow["gaps"])
    deep = run(svc, "describe_flow", {"scope_id": scope, "depth": 8})
    assert not any(g["code"] == "DEPTH_LIMITED" for g in deep["gaps"])


def test_component_cap_is_partial(tmp_path):
    root = group("root", processors=[processor(f"p{i:03d}") for i in range(40)])
    svc = bundle_session(tmp_path, write_bundle(tmp_path / "b", definition(root)),
                         limits={"components": 10})
    env = run(svc, "describe_flow", {"scope_id": "test-scope"})
    assert env["status"] == "partial"
    assert any(g["code"] == "COMPONENT_LIMIT_REACHED" for g in env["gaps"])
    assert len(env["data"]["graph"]["nodes"]) <= 10


def test_provenance_event_cap(tmp_path):
    root = group("root", processors=[processor("p1")])
    events = [{"id": str(i), "eventId": i, "eventTimestamp": f"2026-10-29T01:{i % 60:02d}:00.000Z", "eventType": "ROUTE",
               "relationship": "unmatched", "flowFileUuid": "6ae1e6de-d4a6-4f88-be99-5ac47c13e079",
               "groupId": root["instanceIdentifier"], "componentId": root["processors"][0]["instanceIdentifier"]}
              for i in range(30)]
    prov = {"collection": {}, "response": {"provenance": {"results": {"total": "30", "provenanceEvents": events}}}}
    window = {"start": "2026-10-29T01:00:00Z", "end": "2026-10-29T02:00:00Z"}
    svc = bundle_session(tmp_path, write_bundle(tmp_path / "b", definition(root),
                                                extra_files={"p.json": ("provenance", prov, window)}),
                         limits={"provenance_events": 5})
    env = run(svc, "trace_feed", {"scope_id": "test-scope", "interval": window,
                                  "selector": {"kind": "flowfile_uuid", "value": "6ae1e6de-d4a6-4f88-be99-5ac47c13e079"}})
    assert env["data"]["events"] == 5
    assert any(g["code"] == "EVENT_LIMIT_REACHED" for g in env["gaps"]) and env["status"] == "partial"


def test_result_size_cap_and_pagination(tmp_path):
    small = demo_session(tmp_path, limits={"maximum_result_bytes": 16384, "queue_sampling_enabled": True})
    info = demo_info()
    env = run(small, "describe_flow", {"scope_id": info["scope"], "depth": 8})
    assert len(canonical_bytes(env)) <= 16384
    pages, cursor = 1, env["data"].get("page", {}).get("next_cursor")
    seen = {n["id"] for n in env["data"].get("graph", {}).get("nodes", [])}
    while cursor:
        nxt = run(small, "describe_flow", {"scope_id": info["scope"], "depth": 8, "cursor": cursor})
        assert nxt["status"] != "error" and len(canonical_bytes(nxt)) <= 16384
        seen |= {n["id"] for n in nxt["data"].get("graph", {}).get("nodes", [])}
        cursor = nxt["data"]["page"]["next_cursor"]
        pages += 1
        assert pages < 50
    assert pages > 1
    unm = run(small, "inspect_unmatched", {"connection_id": info["unmatched_connection_id"],
                                           "interval": info["interval"], "sample_metadata": True})
    assert len(canonical_bytes(unm)) <= 16384
    if unm["status"] == "partial":
        gap = next(g for g in unm["gaps"] if g["code"] == "RESULT_TRUNCATED")
        aid = unm["limits_applied"]["full_result_artifact_id"]
        assert aid in gap["detail"]
        _, full = small.s.store.read_bytes(aid, small.s.session_id)
        assert len(json.loads(full)["evidence"]) > len(unm["evidence"])


def test_cursor_binding(tmp_path):
    small = demo_session(tmp_path, limits={"maximum_result_bytes": 16384})
    scope = demo_info()["scope"]
    cursor = run(small, "describe_flow", {"scope_id": scope, "depth": 8})["data"]["page"]["next_cursor"]
    assert run(small, "describe_flow", {"scope_id": scope, "depth": 7, "cursor": cursor})["error"]["code"] == "INVALID_ARGUMENT"
    tampered = cursor[:-2] + ("aa" if not cursor.endswith("aa") else "bb")
    assert run(small, "describe_flow", {"scope_id": scope, "depth": 8, "cursor": tampered})["error"]["code"] == "INVALID_ARGUMENT"
    other = demo_session(tmp_path / "other", limits={"maximum_result_bytes": 16384})
    assert run(other, "describe_flow", {"scope_id": scope, "depth": 8, "cursor": cursor})["error"]["code"] == "INVALID_ARGUMENT"


class SlowSource:
    def __init__(self, inner, delay):
        self.inner, self.delay = inner, delay

    def __getattr__(self, name):
        return getattr(self.inner, name)

    async def flow(self, scope_id):
        await anyio.sleep(self.delay)
        return await self.inner.flow(scope_id)


def test_wall_time_limit(tmp_path):
    svc = demo_session(tmp_path, limits={"tool_timeout_seconds": 1, "queue_sampling_enabled": True})
    svc.s.source = SlowSource(svc.s.source, 3)
    start = time.monotonic()
    env = run(svc, "describe_flow", {"scope_id": demo_info()["scope"]})
    assert env["error"]["code"] == "TIMEOUT"
    assert time.monotonic() - start < 2.5


def test_concurrency_limit_serializes_calls(tmp_path):
    svc = demo_session(tmp_path, limits={"concurrency": 1, "queue_sampling_enabled": True})
    svc.s.source = SlowSource(svc.s.source, 0.5)
    scope = demo_info()["scope"]

    async def both():
        start = time.monotonic()
        async with anyio.create_task_group() as tg:
            tg.start_soon(call_tool, svc, "describe_flow", {"scope_id": scope})
            tg.start_soon(call_tool, svc, "describe_flow", {"scope_id": scope})
        return time.monotonic() - start
    assert anyio.run(both) >= 1.0
    svc2 = demo_session(tmp_path / "two", limits={"concurrency": 2, "queue_sampling_enabled": True})
    svc2.s.source = SlowSource(svc2.s.source, 0.5)

    async def parallel():
        start = time.monotonic()
        async with anyio.create_task_group() as tg:
            tg.start_soon(call_tool, svc2, "describe_flow", {"scope_id": scope})
            tg.start_soon(call_tool, svc2, "describe_flow", {"scope_id": scope})
        return time.monotonic() - start
    assert anyio.run(parallel) < 1.0
