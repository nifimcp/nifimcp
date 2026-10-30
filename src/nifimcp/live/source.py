"""Live source: one operator-configured NiFi 2.12.0 origin, one scoped observer identity.

Authorization happens before every dependent read: identifiers supplied by a
model are checked against the scope inventory (built from the configured scope
group itself) before any NiFi request uses them. Clusters fail closed. Only
metadata is read: there is no route to content, attributes, replay or mutation.
"""
from __future__ import annotations

import datetime as dt
import time
from typing import Any

from ..config import OperatorConfig
from ..core.flowmodel import FlowImportError, FlowModel, normalize
from ..core.jsonsafe import UnsafeJSON, loads_bounded
from ..core.observations import Source, provenance_events
from ..errors import ErrorCode, NiFiMCPError
from ..limits import MAX_SINGLE_JSON_BYTES
from ..util import iso, nifi_time, sha256_hex, utc_now
from .http import NiFiHTTP
from .queries import QueryRegistry, deadline_after

INVENTORY_TTL = 30.0
SELECTOR_FIELDS = {"flowfile_uuid": "FlowFileUUID", "filename": "Filename"}


class LiveSource:
    mode = "live"

    def __init__(self, config: OperatorConfig, *, http: NiFiHTTP | None = None, raw_sink=None):
        self.config = config
        self.live = config.live
        self.http = http or NiFiHTTP(config)
        self.registry = QueryRegistry(self.http, config.limits.concurrency)
        self._scopes = {s.scope_id: s for s in self.live.scopes}
        self._models: dict[str, tuple[float, FlowModel, str]] = {}
        self._about: dict | None = None
        self._topology: tuple[float, dict] | None = None
        self._search_fields: set[str] | None = None
        self.raw_sink = raw_sink   # callable(label, bytes) storing raw observations operator-locally
        self.origin_tag = sha256_hex(self.live.origin.encode())[:10]

    # ------------------------------------------------------------- discovery
    def scopes(self) -> list[dict]:
        return [{"scope_id": s.scope_id, "label": s.label, "process_group_id": s.process_group_id}
                for s in self._scopes.values()]

    def scope_cfg(self, scope_id: str):
        cfg = self._scopes.get(scope_id)
        if cfg is None:
            raise NiFiMCPError(ErrorCode.OUT_OF_SCOPE, "the requested scope is not configured")
        return cfg

    async def about(self) -> dict:
        if self._about is None:
            resp = await self.http.call("about")
            self._about = (resp.data or {}).get("about") or {}
        return self._about

    async def check_version(self) -> str:
        version = (await self.about()).get("version")
        if version != self.live.expected_version:
            raise NiFiMCPError(ErrorCode.UNSUPPORTED_VERSION,
                               f"connected NiFi reports version {version!s:.40}; this release is qualified on 2.12.0 only")
        return version

    async def topology(self) -> dict:
        now = time.monotonic()
        if self._topology and now - self._topology[0] < INVENTORY_TTL:
            return self._topology[1]
        resp = await self.http.call("cluster_summary")
        summary = (resp.data or {}).get("clusterSummary") or {}
        topo = {"clustered": bool(summary.get("clustered")), "connected_to_cluster": bool(summary.get("connectedToCluster")),
                "total_node_count": summary.get("totalNodeCount"), "observed_at": iso(utc_now())}
        self._topology = (now, topo)
        return topo

    async def preflight(self) -> None:
        """Version and topology gates before any live investigation."""
        await self.check_version()
        topo = await self.topology()
        if topo["clustered"] or topo["connected_to_cluster"]:
            raise NiFiMCPError(ErrorCode.UNSUPPORTED_TOPOLOGY,
                               "the connected NiFi is clustered; live investigation is qualified on standalone "
                               "NiFi only in this release")

    async def capabilities(self) -> dict:
        about = await self.about()
        topo = await self.topology()
        user = (await self.http.call("current_user")).data or {}
        prov = (user.get("provenancePermissions") or {}).get("canRead")
        scope_access = {}
        for scope in self._scopes.values():
            try:
                flow = (await self.http.call("group_flow", params={"id": scope.process_group_id})).data or {}
                scope_access[scope.scope_id] = bool((flow.get("permissions") or {}).get("canRead"))
            except NiFiMCPError as err:
                scope_access[scope.scope_id] = f"error: {err.code.value}"
        return {
            "runtime": {"source": "live", "origin": self.live.origin, "nifi_version": about.get("version"),
                        "build_tag": about.get("buildTag"), "qualified": about.get("version") == "2.12.0"},
            "topology": {**topo, "live_investigation": "blocked (clustered)" if topo["clustered"] else "standalone: supported"},
            "permissions": {
                "identity_kind": self.http.identity_kind,
                "identity": "(withheld)" if user.get("anonymous") is False else "anonymous",
                "scope_read": scope_access,
                "provenance_query": bool(prov),
                "provenance_note": None if prov else "The identity lacks the 'query provenance' policy; trace_feed and "
                                                     "unmatched event history are unavailable (partial capability).",
                "queue_metadata": "operator-enabled" if self.config.limits.queue_sampling_enabled else "disabled by operator",
                "mutation": "none (no mutation route exists in this runtime)",
            },
            "observation_requests": self.registry.report(),
        }

    def source_version(self, scope_id: str) -> str | None:
        return (self._about or {}).get("version")

    # ------------------------------------------------------------- inventory
    async def flow(self, scope_id: str) -> tuple[FlowModel, str, list[dict]]:
        scope = self.scope_cfg(scope_id)
        cached = self._models.get(scope_id)
        if cached and time.monotonic() - cached[0] < INVENTORY_TTL:
            return cached[1], cached[2], []
        await self.preflight()
        resp = await self.http.call("group_download", params={"id": scope.process_group_id},
                                    query={"includeReferencedServices": "true"})
        collected = iso(utc_now())
        if self.raw_sink:
            self.raw_sink(f"download-{scope_id}", resp.raw)
        try:
            doc = loads_bounded(resp.raw, max_bytes=MAX_SINGLE_JSON_BYTES)
            model = normalize(doc, source_id=f"live:{self.origin_tag}:download:{scope.process_group_id}"[:128],
                              source_hash=resp.sha256, max_components=self.config.limits.maximum_components)
        except (UnsafeJSON, FlowImportError) as exc:
            code = ErrorCode.LIMIT_EXCEEDED if "more than" in str(exc) else ErrorCode.QUERY_FAILED
            raise NiFiMCPError(code, f"the scope's flow definition could not be read: {exc}") from exc
        if scope.process_group_id not in model.root.ids:
            raise NiFiMCPError(ErrorCode.QUERY_FAILED, "NiFi returned a definition for a different process group")
        self._models[scope_id] = (time.monotonic(), model, collected)
        return model, collected, []

    async def scope_ids(self, scope_id: str) -> set[str]:
        model, _, _ = await self.flow(scope_id)
        return {i for c in model.components for i in c.ids}

    async def locate_connection(self, connection_id: str) -> str | None:
        """Pre-check: which configured scope contains this connection? No request uses the ID itself."""
        for scope_id in self._scopes:
            model, _, _ = await self.flow(scope_id)
            comp = model.find(connection_id)
            if comp is not None and comp.kind == "connection":
                return scope_id
        return None

    # ------------------------------------------------------------- observations
    def _source(self, label: str, resp, collected_at: str, base: str = "") -> Source:
        if self.raw_sink:
            self.raw_sink(label, resp.raw)
        return Source(source_id=f"live:{self.origin_tag}:{label}"[:128], source_hash=resp.sha256,
                      base_pointer=base, collected_at=collected_at, node_id="standalone")

    async def status(self, scope_id: str) -> list[tuple[dict, Source]]:
        scope = self.scope_cfg(scope_id)
        await self.preflight()
        resp = await self.http.call("group_status", params={"id": scope.process_group_id}, query={"recursive": "true"})
        return [(resp.data, self._source(f"status:{scope.process_group_id}", resp, iso(utc_now())))]

    async def bulletins(self, scope_id: str) -> list[tuple[dict, Source]]:
        self.scope_cfg(scope_id)
        await self.preflight()
        resp = await self.http.call("bulletin_board", query={"limit": "500"})
        return [(resp.data, self._source("bulletins", resp, iso(utc_now())))]

    async def search_fields(self) -> set[str]:
        if self._search_fields is None:
            resp = await self.http.call("provenance_options")
            fields = ((resp.data or {}).get("provenanceOptions") or {}).get("searchableFields") or []
            self._search_fields = {f.get("id") for f in fields if isinstance(f, dict)} | \
                                  {f.get("field") for f in fields if isinstance(f, dict)}
        return self._search_fields

    async def provenance(self, scope_id: str, *, selector: dict | None, processor_id: str | None,
                         relationship: str | None, interval: tuple[dt.datetime, dt.datetime],
                         max_events: int) -> tuple[list[tuple[dict, str, Source]], dict, list[dict]]:
        if not self.live.provenance.enabled:
            raise NiFiMCPError(ErrorCode.PERMISSION_DENIED, "provenance queries are disabled by the operator")
        await self.preflight()
        ids = await self.scope_ids(scope_id)
        if processor_id is not None and processor_id not in ids:
            raise NiFiMCPError(ErrorCode.OUT_OF_SCOPE, "processor is not inside the configured scope")
        fields = await self.search_fields()
        terms: dict[str, dict] = {}
        if selector is not None:
            if selector["kind"] == "indexed_attribute":
                name = selector["name"]
                if name not in self.live.provenance.approved_indexed_attributes:
                    raise NiFiMCPError(ErrorCode.INVALID_ARGUMENT, "attribute is not operator-approved for search")
                if name not in fields:
                    raise NiFiMCPError(ErrorCode.INVALID_ARGUMENT,
                                       "attribute is approved but not indexed on this NiFi instance",
                                       "Ask the NiFi administrator to add it to nifi.provenance.repository.indexed.attributes.")
                terms[name] = {"value": selector["value"], "inverse": False}
            else:
                field_name = SELECTOR_FIELDS[selector["kind"]]
                if field_name not in fields:
                    raise NiFiMCPError(ErrorCode.INVALID_ARGUMENT, f"{field_name} is not searchable on this instance")
                terms[field_name] = {"value": selector["value"], "inverse": False}
        if processor_id is not None:
            terms["ProcessorID"] = {"value": processor_id, "inverse": False}
        if relationship is not None:
            terms["Relationship"] = {"value": relationship, "inverse": False}
        if not terms:
            raise NiFiMCPError(ErrorCode.INVALID_ARGUMENT, "an exact selector is required")
        body = {"provenance": {"request": {
            "maxResults": max_events, "summarize": False, "incrementalResults": False,
            "startDate": nifi_time(interval[0]), "endDate": nifi_time(interval[1]),
            "searchTerms": terms}}}
        budget = max(5.0, self.config.limits.tool_timeout_seconds - 8.0)
        outcome = await self.registry.run_provenance(scope_id=scope_id, body=body, deadline=deadline_after(budget))
        gaps = list(outcome.gaps)
        if outcome.request is not None and outcome.request.deleted:
            gaps.append({"code": "NIFI_RETAINS_CANCELLED_QUERY", "detail": (
                "NiFi 2.12.0 acknowledged the DELETE of this server's provenance query by cancelling it; NiFi keeps "
                "the finished query for its own expiration period (about 30 minutes) and NiFiMCP never reuses it.")})
        meta = {"query_kind": "live_owned_provenance_query", "search_fields": sorted(terms),
                "request": outcome.request.request_id if outcome.request else None,
                "finished": outcome.finished, "cleanup": outcome.request.state if outcome.request else None}
        if outcome.final is None:
            return [], meta, gaps
        events, ptr, results = provenance_events(outcome.final.data)
        total = results.get("total")
        # EVENT_LIMIT_REACHED is decided after scope filtering (see Service), never from NiFi's raw total,
        # so events outside the scope cannot change the result.
        src = self._source(f"provenance:{meta['request']}", outcome.final, iso(utc_now()))
        return [(e, f"{ptr}/{i}", src) for i, e in enumerate(events)], meta, gaps

    async def queue_sample(self, scope_id: str, connection_id: str, sample_size: int):
        ids = await self.scope_ids(scope_id)
        if connection_id not in ids:
            raise NiFiMCPError(ErrorCode.OUT_OF_SCOPE, "connection is not inside the configured scope")
        await self.preflight()
        budget = max(5.0, self.config.limits.tool_timeout_seconds - 8.0)
        outcome = await self.registry.run_listing(scope_id=scope_id, connection_id=connection_id,
                                                  deadline=deadline_after(budget))
        gaps = list(outcome.gaps)
        gaps.append({"code": "LISTING_SERVER_WORK", "detail": (
            "NiFi evaluates a queue listing server-side (up to its own listing size) even when only a small sample "
            "is returned; NiFiMCP keeps only the first entries and drops the rest immediately.")})
        if outcome.final is None:
            return None, None, None, gaps
        summaries = (outcome.final.data.get("listingRequest") or {}).get("flowFileSummaries") or []
        src = self._source(f"listing:{connection_id}", outcome.final, iso(utc_now()))
        return summaries, "/listingRequest/flowFileSummaries", src, gaps

    def notes_files(self, scope_id: str) -> list:
        return []

    def flow_sources(self, scope_id: str) -> dict:
        return {}

    async def aclose(self) -> None:
        await self.http.aclose()
