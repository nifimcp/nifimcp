"""A09: content, replay, queue-drop, config-write and arbitrary HTTP paths unreachable."""
import ast
import json
import re
from importlib import resources
from pathlib import Path

import anyio
import httpx2
import pytest

from fakenifi import FakeNiFi, live_config
from nifimcp.errors import NiFiMCPError
from nifimcp.live.http import NiFiHTTP, load_allowlist

SRC = Path(__file__).resolve().parents[2] / "src" / "nifimcp"
FORBIDDEN_PATH = re.compile(r"(content|replays?|drop-requests|run-status|/flowfiles/|lineage|threads|state|"
                            r"clear-requests|empty-all|parameter-contexts|policies|tenants|controller|templates|"
                            r"versions|/processors/\{id\}/config|backlog|diagnostics|search-results)", re.I)


def test_allowlist_is_minimal_and_observational():
    entries = load_allowlist()
    assert len(entries) == 14
    assert "connection" not in entries and "processor" not in entries   # unused reads are not allowlisted
    methods = {(e["method"], e["path"]) for e in entries.values()}
    for method, path in methods:
        assert not FORBIDDEN_PATH.search(path), path
        if method == "POST":
            assert path in ("/provenance", "/flowfile-queues/{id}/listing-requests")
        if method == "DELETE":
            assert path in ("/provenance/{id}", "/flowfile-queues/{id}/listing-requests/{listing-request-id}")
        assert method in ("GET", "POST", "DELETE")
    assert entries["group_download"]["query"] == {"includeReferencedServices": ["true", "false"]}
    doc = json.loads((resources.files("nifimcp") / "contracts" / "nifi-2.12.0-rest-allowlist.json").read_text())
    assert doc["nifi_version"] == "2.12.0" and len(doc["source"]["sha256"]) == 64


def _http(tmp_path):
    fake = FakeNiFi()
    return NiFiHTTP(live_config(tmp_path), transport=httpx2.MockTransport(fake.handler)), fake


@pytest.mark.parametrize("call", [
    ("drop", {}, None),
    ("processor_run_status", {"id": "6ae1e6de-d4a6-4f88-be99-5ac47c13e079"}, None),
    ("group_flow", {"id": "../flowfile-queues/x/drop-requests"}, None),
    ("group_flow", {"id": "6ae1e6de-d4a6-4f88-be99-5ac47c13e079/../../controller"}, None),
    ("connection", {"id": "6ae1e6de-d4a6-4f88-be99-5ac47c13e079"}, None),
    ("group_download", {"id": "6ae1e6de-d4a6-4f88-be99-5ac47c13e079"}, {"includeComponentState": "true"}),
    ("group_status", {"id": "6ae1e6de-d4a6-4f88-be99-5ac47c13e079"}, {"recursive": "true", "clusterNodeId": "n1"}),
    ("provenance_get", {"id": "6ae1e6de-d4a6-4f88-be99-5ac47c13e079"}, {"summarize": "true"}),
    ("group_flow", {}, None),
])
def test_non_allowlisted_requests_refused_before_sending(tmp_path, call):
    http, fake = _http(tmp_path)
    name, params, query = call

    async def go():
        with pytest.raises(NiFiMCPError):
            await http.call(name, params=params, query=query)
    anyio.run(go)
    assert fake.requests == []


def test_bodies_only_on_allowlisted_posts(tmp_path):
    http, fake = _http(tmp_path)

    async def go():
        with pytest.raises(NiFiMCPError):
            await http.call("about", body={"x": 1})
        with pytest.raises(NiFiMCPError):
            await http.call("provenance_submit")
    anyio.run(go)
    assert fake.requests == []


def test_only_the_http_module_performs_http():
    importers = []
    for path in SRC.rglob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            names = [a.name for a in node.names] if isinstance(node, (ast.Import, ast.ImportFrom)) else []
            module = node.module if isinstance(node, ast.ImportFrom) else ""
            if any(n.startswith(("httpx", "urllib.request", "http.client", "requests", "socket", "aiohttp"))
                   for n in names + [module or ""]):
                importers.append(path.relative_to(SRC).as_posix())
    assert importers == ["live/http.py"]


def test_runtime_never_imports_lab_tooling():
    for path in SRC.rglob("*.py"):
        text = path.read_text()
        assert "nifimcp_lab" not in text, path


def test_no_mutation_tool_exists():
    contract = json.loads((resources.files("nifimcp") / "contracts" / "tool_contracts.json").read_text())
    names = {t["name"] for t in contract["tools"]}
    assert names == {"get_capabilities", "describe_flow", "get_flow_health", "trace_feed", "inspect_unmatched",
                     "compare_flow_snapshots", "export_investigation", "get_processor_catalog", "validate_flow_plan",
                     "draft_flow"}
    from nifimcp.mcp_server import tool_definitions
    assert {t.name for t in tool_definitions()} == names
