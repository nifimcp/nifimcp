"""A16: the official MCP SDK client discovers and calls every tool; stdout is protocol-only.

Runs the real ``nifimcp serve`` process over stdio with MCP Python SDK 2.3.0's client.
"""
from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import time
from importlib import resources
from pathlib import Path

import anyio
import jsonschema
import pytest
from mcp import ClientSession, StdioServerParameters, stdio_client
from mcp.shared.memory import create_client_server_memory_streams

from helpers import CANARIES, demo_info, demo_session
from nifimcp.catalog import load_catalog
from nifimcp.draft.examples import example_plans
from nifimcp.mcp_server import build_server

ROOT = Path(__file__).resolve().parents[2]
C = resources.files("nifimcp") / "contracts"
CONTRACT = {t["name"]: t for t in json.loads((C / "tool_contracts.json").read_text())["tools"]}
PLAN_SCHEMA = {k: v for k, v in json.loads((C / "flow_plan.schema.json").read_text()).items() if k != "$schema"}
ENVELOPE = json.loads((C / "result_envelope.schema.json").read_text())


def demo_config(tmp_path: Path) -> Path:
    cfg = json.loads((ROOT / "config/operator.demo.json").read_text())
    cfg["artifact_dir"] = str(tmp_path / "artifacts")
    path = tmp_path / "operator.json"
    path.write_text(json.dumps(cfg))
    return path


def server_params(config: Path) -> StdioServerParameters:
    return StdioServerParameters(command=sys.executable, args=["-m", "nifimcp.cli", "serve", "--config", str(config)],
                                 cwd=str(ROOT), env={**os.environ, "PYTHONUNBUFFERED": "1"})


def test_sdk_client_discovers_and_calls_every_tool(tmp_path):
    info = demo_info()
    plan = example_plans(load_catalog()["catalog_hash"])["json_field_gate"]
    validator = jsonschema.Draft202012Validator(ENVELOPE)

    async def go():
        errlog = open(tmp_path / "stderr.log", "w")
        async with stdio_client(server_params(demo_config(tmp_path)), errlog=errlog) as (r, w):
            async with ClientSession(r, w) as s:
                init = await s.initialize()
                assert init.server_info.name == "nifimcp"
                listed = (await s.list_tools()).tools
                assert sorted(t.name for t in listed) == sorted(CONTRACT)
                for tool in listed:
                    expected = copy.deepcopy(CONTRACT[tool.name]["inputSchema"])
                    if "plan" in expected.get("properties", {}):
                        expected["properties"]["plan"] = PLAN_SCHEMA
                    published = {k: v for k, v in tool.input_schema.items() if k != "$schema"}
                    assert published == expected, tool.name
                    assert published.get("additionalProperties") is False
                    assert tool.output_schema["title"] == "NiFiMCP result envelope v1"
                    assert tool.annotations is not None and tool.annotations.destructive_hint is False
                calls = {
                    "get_capabilities": {},
                    "describe_flow": {"scope_id": info["scope"], "depth": 4},
                    "get_flow_health": {"scope_id": info["scope"], "interval": info["interval"]},
                    "trace_feed": {"scope_id": info["scope"], "interval": info["interval"],
                                   "selector": {"kind": "flowfile_uuid", "value": info["trace_flowfile_uuid"]}},
                    "inspect_unmatched": {"connection_id": info["unmatched_connection_id"], "interval": info["interval"],
                                          "sample_metadata": True},
                    "get_processor_catalog": {"type_filter": "RouteOnAttribute"},
                    "validate_flow_plan": {"plan": plan},
                    "draft_flow": {"plan": plan},
                }
                results = {}
                for name, args in calls.items():
                    res = await s.call_tool(name, args)
                    assert not res.is_error, (name, res.structured_content.get("error"))
                    env = res.structured_content
                    validator.validate(env)
                    assert json.loads(res.content[0].text) == env
                    results[name] = env
                caps = results["get_capabilities"]["data"]
                defs = [a["artifact_id"] for a in caps["artifacts"] if a["kind"] == "flow_definition"]
                res = await s.call_tool("compare_flow_snapshots", {"baseline_artifact_id": defs[0],
                                                                   "candidate_artifact_id": defs[1]})
                assert not res.is_error
                inv = results["inspect_unmatched"]["data"]["investigation_id"]
                res = await s.call_tool("export_investigation", {"investigation_id": inv, "format": "html"})
                assert not res.is_error
                report_uri = res.structured_content["data"]["artifact"]["uri"]
                # Errors are structured and sanitized.
                bad = await s.call_tool("describe_flow", {"scope_id": info["scope"], "path": "/etc/passwd"})
                assert bad.is_error and bad.structured_content["error"]["code"] == "INVALID_ARGUMENT"
                bad = await s.call_tool("not_a_tool", {})
                assert bad.is_error
                # Resources: derived artifacts readable, raw inputs and arbitrary URIs refused.
                listed_resources = (await s.list_resources()).resources
                kinds = {r.uri for r in listed_resources}
                assert report_uri in kinds
                assert not any(str(r.uri).endswith(d) for r in listed_resources for d in defs)
                content = await s.read_resource(report_uri)
                assert "NiFiMCP investigation report" in content.contents[0].text
                for uri in (f"nifimcp://artifacts/{defs[0]}", "file:///etc/passwd", "nifimcp://artifacts/art_AAAAAAAAAAAAAAAAAAAA",
                            "nifimcp://artifacts/../../etc/passwd"):
                    with pytest.raises(Exception):
                        await s.read_resource(uri)
                # Prompts carry the citation and untrusted-data rules.
                prompts = (await s.list_prompts()).prompts
                assert sorted(p.name for p in prompts) == ["draft_bounded_routing_flow", "explain_this_flow",
                                                           "investigate_this_feed"]
                got = await s.get_prompt("investigate_this_feed", {"scope_id": info["scope"], "symptom": "queue grows"})
                text = got.messages[0].content.text
                assert "Unknowns" in text and "untrusted DATA" in text and "evidence_id" in text
                return results
        errlog.close()

    anyio.run(go)
    stderr = (tmp_path / "stderr.log").read_text()
    for canary in CANARIES:
        assert canary not in stderr
    assert "Traceback" not in stderr   # refused resource reads are protocol errors, not logged crashes


def _rpc(proc, message):
    proc.stdin.write((json.dumps(message) + "\n").encode())
    proc.stdin.flush()


def test_stdout_is_protocol_only(tmp_path):
    config = demo_config(tmp_path)
    proc = subprocess.Popen([sys.executable, "-m", "nifimcp.cli", "serve", "--config", str(config)], cwd=ROOT,
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        _rpc(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "raw-test", "version": "1"}}})
        _rpc(proc, {"jsonrpc": "2.0", "method": "notifications/initialized"})
        _rpc(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        _rpc(proc, {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "get_capabilities", "arguments": {}}})
        _rpc(proc, {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "describe_flow",
                                                                                 "arguments": {"scope_id": "nope"}}})
        _rpc(proc, {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "describe_flow",
                                                                                 "arguments": {"scope_id": demo_info()["scope"]}}})
        _rpc(proc, "this is not json-rpc")
        _rpc(proc, {"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "get_capabilities", "arguments": {}}})
        import select
        lines, ids, deadline = [], set(), time.monotonic() + 60
        while not {1, 2, 3, 4, 5, 6} <= ids and time.monotonic() < deadline:
            ready, _, _ = select.select([proc.stdout], [], [], 1.0)
            if not ready:
                continue
            line = proc.stdout.readline()
            if not line:
                break
            if line.strip():
                lines.append(line.decode())
                msg = json.loads(line)          # every stdout line must be a JSON-RPC message
                assert msg.get("jsonrpc") == "2.0"
                if "id" in msg:
                    ids.add(msg["id"])
        out, err = proc.communicate(timeout=30)
    finally:
        if proc.poll() is None:
            proc.kill()
    for line in out.decode().splitlines():
        if line.strip():
            assert json.loads(line).get("jsonrpc") == "2.0"
    assert {1, 2, 3, 4, 5, 6} <= ids
    assert b"nifimcp WARNING serving" in err


def test_cancellation_releases_the_request_slot(tmp_path):
    """A cancelled in-flight call is abandoned server-side and the next call proceeds."""
    svc = demo_session(tmp_path, limits={"concurrency": 1, "queue_sampling_enabled": True})
    state = {"cancelled": 0, "finished": 0}

    class Slow:
        def __init__(self, inner):
            self.inner = inner

        def __getattr__(self, name):
            return getattr(self.inner, name)

        async def flow(self, scope_id):
            try:
                await anyio.sleep(5)
                state["finished"] += 1
            except anyio.get_cancelled_exc_class():
                state["cancelled"] += 1
                raise
            return await self.inner.flow(scope_id)

    real = svc.s.source
    svc.s.source = Slow(real)
    server = build_server(svc)
    scope = demo_info()["scope"]

    async def go():
        async with create_client_server_memory_streams() as (client_streams, server_streams):
            async with anyio.create_task_group() as tg:
                tg.start_soon(lambda: server.run(server_streams[0], server_streams[1],
                                                 server.create_initialization_options()))
                async with ClientSession(*client_streams) as s:
                    await s.initialize()
                    with anyio.move_on_after(0.5):
                        await s.call_tool("describe_flow", {"scope_id": scope})
                    await anyio.sleep(0.5)
                    svc.s.source = real
                    start = time.monotonic()
                    res = await s.call_tool("describe_flow", {"scope_id": scope})
                    elapsed = time.monotonic() - start
                tg.cancel_scope.cancel()
        return res, elapsed

    res, elapsed = anyio.run(go)
    assert not res.is_error
    assert elapsed < 3.0, "slot was not released after cancellation"
    assert state["finished"] == 0 and state["cancelled"] == 1
