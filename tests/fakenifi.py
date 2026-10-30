"""A recording fake NiFi used ONLY for client-side security unit tests.

This is not a native integration test. It lets tests prove what requests the
NiFiMCP client does or does not send (scope pre-checks, cleanup, retries).
Native behavior is covered by tests/integration against the real lab.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import anyio
import httpx2

from helpers import NATIVE, ROOT
from nifimcp.config import OperatorConfig
from nifimcp.live.http import NiFiHTTP
from nifimcp.live.source import LiveSource

DEF = json.loads(NATIVE.read_bytes())
SCOPE_PG = DEF["flowContents"]["instanceIdentifier"]
CONNS = [c["instanceIdentifier"] for c in DEF["flowContents"]["connections"]]
ROUTER = next(p["instanceIdentifier"] for p in DEF["flowContents"]["processors"] if p["name"] == "route")
UNMATCHED_CONN = next(c["instanceIdentifier"] for c in DEF["flowContents"]["connections"]
                      if c["selectedRelationships"] == ["unmatched"])
FOREIGN = "11111111-2222-3333-4444-555555555555"
QUERY_ID = "aaaaaaaa-0000-0000-0000-000000000001"
LISTING_ID = "bbbbbbbb-0000-0000-0000-000000000002"


class FakeNiFi:
    def __init__(self, *, clustered=False, version="2.12.0", prov_finish_after=1, fail=None):
        self.requests: list[tuple[str, str]] = []
        self.clustered = clustered
        self.version = version
        self.prov_polls = 0
        self.prov_finish_after = prov_finish_after
        self.fail = fail or {}            # endpoint key -> status or "timeout"
        self.deleted: set[str] = set()

    def _maybe_fail(self, key: str):
        mode = self.fail.get(key)
        if mode == "timeout":
            raise httpx2.ReadTimeout("simulated timeout")
        if isinstance(mode, int):
            return httpx2.Response(mode, text="simulated")
        return None

    async def handler(self, request: httpx2.Request) -> httpx2.Response:
        path = request.url.path.removeprefix("/nifi-api")
        self.requests.append((request.method, path + ("?" + request.url.query.decode() if request.url.query else "")))
        m = request.method
        if (m, path) == ("GET", "/flow/about"):
            return httpx2.Response(200, json={"about": {"version": self.version, "buildTag": "rel/nifi-" + self.version,
                                                        "uri": "https://evil.invalid/nifi-api/"}})
        if (m, path) == ("GET", "/flow/cluster/summary"):
            return httpx2.Response(200, json={"clusterSummary": {"clustered": self.clustered,
                                                                 "connectedToCluster": self.clustered,
                                                                 "totalNodeCount": 2 if self.clustered else 0}})
        if (m, path) == ("GET", "/flow/current-user"):
            return httpx2.Response(200, json={"identity": "CN=observer", "anonymous": False,
                                              "provenancePermissions": {"canRead": True, "canWrite": False}})
        if m == "GET" and path == f"/process-groups/{SCOPE_PG}/download":
            return httpx2.Response(200, content=NATIVE.read_bytes(), headers={"content-type": "application/json"})
        if m == "GET" and path == f"/flow/process-groups/{SCOPE_PG}":
            return httpx2.Response(200, json={"permissions": {"canRead": True}, "processGroupFlow": {"id": SCOPE_PG}})
        if m == "GET" and path == f"/flow/process-groups/{SCOPE_PG}/status":
            return httpx2.Response(200, json={"processGroupStatus": {"aggregateSnapshot": {"id": SCOPE_PG}}})
        if (m, path) == ("GET", "/flow/bulletin-board"):
            return httpx2.Response(200, json={"bulletinBoard": {"bulletins": []}})
        if (m, path) == ("GET", "/provenance/search-options"):
            return httpx2.Response(200, json={"provenanceOptions": {"searchableFields": [
                {"id": f, "field": f, "label": f, "type": "STRING"} for f in
                ("EventType", "FlowFileUUID", "Filename", "ProcessorID", "Relationship")]}})
        if (m, path) == ("POST", "/provenance"):
            failed = self._maybe_fail("provenance_submit")
            if failed:
                return failed
            return httpx2.Response(201, json={"provenance": {"id": QUERY_ID, "finished": False}})
        if m == "GET" and path == f"/provenance/{QUERY_ID}":
            failed = self._maybe_fail("provenance_get")
            if failed:
                return failed
            self.prov_polls += 1
            if self.fail.get("provenance_slow"):
                await anyio.sleep(10)
            done = self.prov_polls >= self.prov_finish_after
            return httpx2.Response(200, json={"provenance": {"id": QUERY_ID, "finished": done, "results": {
                "total": "0", "provenanceEvents": []}}})
        if m == "DELETE" and path == f"/provenance/{QUERY_ID}":
            failed = self._maybe_fail("provenance_delete")
            if failed:
                return failed
            self.deleted.add(QUERY_ID)
            return httpx2.Response(200, json={})
        if m == "POST" and re.fullmatch(r"/flowfile-queues/[0-9a-f-]{36}/listing-requests", path):
            return httpx2.Response(202, json={"listingRequest": {"id": LISTING_ID, "finished": True,
                                                                 "flowFileSummaries": []}})
        if m == "DELETE" and path.endswith(f"/listing-requests/{LISTING_ID}"):
            self.deleted.add(LISTING_ID)
            return httpx2.Response(200, json={})
        return httpx2.Response(404, text="not found in fake")

    def touched(self, needle: str) -> bool:
        return any(needle in p for _m, p in self.requests)


def live_config(tmp_path: Path, **overrides) -> OperatorConfig:
    ca = tmp_path / "ca.pem"
    ca.write_text("unused by mock transport")
    cfg = {"schema_version": "1", "mode": "live", "artifact_dir": str(tmp_path / "art"), "base_dir": str(tmp_path),
           "live": {"origin": "https://nifi.example.invalid:8443", "ca_file": str(ca),
                    "auth": {"kind": "bearer_token_file", "token_file": str(tmp_path / "token")},
                    "scopes": [{"scope_id": "scope-a", "process_group_id": SCOPE_PG}],
                    "provenance": {"enabled": True, "approved_indexed_attributes": []}},
           "limits": {"queue_sampling_enabled": True}}
    (tmp_path / "token").write_text("fake-token-value-not-secret")
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(cfg.get(key), dict):
            cfg[key] = {**cfg[key], **value}
        else:
            cfg[key] = value
    return OperatorConfig.model_validate(cfg)


def fake_service(tmp_path: Path, fake: FakeNiFi, **overrides):
    from nifimcp.service import Service, Session
    config = live_config(tmp_path, **overrides)
    http = NiFiHTTP(config, transport=httpx2.MockTransport(fake.handler))
    source = LiveSource(config, http=http)
    return Service(Session(config, source=source)), source
