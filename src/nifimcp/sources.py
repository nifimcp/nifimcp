"""Evidence sources: packaged demo, operator-registered bundles (offline) and live NiFi.

Bundle and demo sources make no network requests. The live source is defined in
``nifimcp.live.source`` and implements the same interface.
"""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

from .bundle.importer import BundleFileData, ImportedBundle, import_bundle
from .core.flowmodel import FlowImportError, FlowModel, normalize
from .core.observations import Source, provenance_events
from .errors import ErrorCode, NiFiMCPError
from .util import parse_iso

DEMO_BUNDLE = "telemetry-intake"
DEMO_CANDIDATE = "telemetry-intake-candidate.json"


def demo_data_dir() -> Path:
    return Path(str(resources.files("nifimcp") / "demo_data"))


@dataclass
class ScopeData:
    scope_id: str
    label: str
    process_group_id: str
    bundle: ImportedBundle
    flow_file: BundleFileData
    model: FlowModel
    artifact_id: str | None = None
    extra: dict = field(default_factory=dict)

    @property
    def collected_at(self) -> str:
        return self.flow_file.meta.collected_at


def _src(f: BundleFileData, base: str = "/response") -> Source:
    return Source(source_id=f"bundle:{f.path}"[:128], source_hash=f.sha256, base_pointer=base,
                  collected_at=f.meta.collected_at, node_id=f.meta.node_id)


def load_scope(bundle: ImportedBundle, *, max_components: int, artifact_id: str | None = None) -> ScopeData:
    flows = bundle.of_kind("flow_definition")
    if len(flows) != 1:
        raise NiFiMCPError(ErrorCode.INVALID_BUNDLE, "bundle must contain exactly one flow_definition file in this release")
    flow = flows[0]
    try:
        model = normalize(flow.document, source_id=f"bundle:{flow.path}", source_hash=flow.sha256,
                          max_components=max_components)
    except FlowImportError as exc:
        code = ErrorCode.LIMIT_EXCEEDED if "more than" in str(exc) else ErrorCode.INVALID_BUNDLE
        raise NiFiMCPError(code, f"flow definition rejected: {exc}") from exc
    declared = bundle.manifest.declared_scope
    if declared.process_group_id not in model.root.ids:
        raise NiFiMCPError(ErrorCode.INVALID_BUNDLE,
                           "declared scope process group does not match the flow definition's root group")
    return ScopeData(scope_id=declared.scope_id, label=declared.label, process_group_id=declared.process_group_id,
                     bundle=bundle, flow_file=flow, model=model, artifact_id=artifact_id)


class BundleSource:
    """Offline source over one or more imported bundles. No network access."""

    def __init__(self, mode: str, scopes: list[ScopeData]):
        self.mode = mode
        self._scopes = {s.scope_id: s for s in scopes}
        if len(self._scopes) != len(scopes):
            raise NiFiMCPError(ErrorCode.INVALID_BUNDLE, "two registered bundles declare the same scope_id",
                               "Remove one with `nifimcp unregister --config <config> <artifact_id>`.")

    def collection_end(self, scope_id: str):
        """Latest collection time recorded for the scope's files (anchors default windows offline)."""
        s = self._scopes.get(scope_id)
        if s is None:
            return None
        times = []
        for f in s.bundle.manifest.files:
            try:
                times.append(parse_iso(f.interval.end if f.interval else f.collected_at))
            except (ValueError, AttributeError):
                continue
        return max(times) if times else None

    # ------------------------------------------------------------ discovery
    def scopes(self) -> list[dict]:
        return [{"scope_id": s.scope_id, "label": s.label, "process_group_id": s.process_group_id,
                 "bundle_id": s.bundle.manifest.bundle_id, "nifi_version": s.bundle.manifest.nifi.version,
                 "completeness": s.bundle.manifest.completeness.status,
                 "node_coverage": [{"node_id": n.node_id, "included": n.included} for n in s.bundle.manifest.nodes],
                 "evidence_kinds": sorted(s.bundle.manifest.source_kinds)} for s in self._scopes.values()]

    def scope(self, scope_id: str) -> ScopeData:
        data = self._scopes.get(scope_id)
        if data is None:
            raise NiFiMCPError(ErrorCode.OUT_OF_SCOPE, "the requested scope is not configured")
        return data

    async def capabilities(self) -> dict:
        versions = sorted({s.bundle.manifest.nifi.version for s in self._scopes.values()})
        return {"runtime": {"source": "offline bundle", "nifi_versions": versions, "network": "none"},
                "topology": {"live": False, "bundle_nodes": {s.scope_id: [n.node_id for n in s.bundle.manifest.nodes]
                                                             for s in self._scopes.values()}},
                "permissions": {"flow": True, "provenance": None, "queue_metadata": None,
                                "note": "Offline bundles carry whatever evidence the collector captured."}}

    def source_version(self, scope_id: str) -> str:
        return self.scope(scope_id).bundle.manifest.nifi.version

    # ------------------------------------------------------------ evidence
    async def flow(self, scope_id: str) -> tuple[FlowModel, str, list[dict]]:
        data = self.scope(scope_id)
        return data.model, data.collected_at, list(data.bundle.gaps)

    async def scope_ids(self, scope_id: str) -> set[str]:
        model = self.scope(scope_id).model
        return {i for c in model.components for i in c.ids}

    async def status(self, scope_id: str) -> list[tuple[dict, Source]]:
        return [(f.document["response"], _src(f)) for f in self.scope(scope_id).bundle.of_kind("status")
                if isinstance(f.document, dict) and "response" in f.document]

    async def bulletins(self, scope_id: str) -> list[tuple[dict, Source]]:
        return [(f.document["response"], _src(f)) for f in self.scope(scope_id).bundle.of_kind("bulletins")
                if isinstance(f.document, dict) and "response" in f.document]

    def _provenance_files(self, scope_id: str):
        for f in self.scope(scope_id).bundle.of_kind("provenance"):
            if isinstance(f.document, dict) and isinstance(f.document.get("response"), dict):
                yield f

    async def provenance(self, scope_id: str, *, selector: dict | None, processor_id: str | None,
                         relationship: str | None, interval: tuple[dt.datetime, dt.datetime],
                         max_events: int) -> tuple[list[tuple[dict, str, Source]], dict, list[dict]]:
        from .core.observations import event_matches
        events: list[tuple[dict, str, Source]] = []
        gaps: list[dict] = [{"code": "BUNDLE_PROVENANCE_ONLY",
                             "detail": "Offline mode can only search provenance events captured in the bundle; "
                                       "events outside the collector's recorded queries are unknown."}]
        covered = False
        truncated = False
        in_scope = await self.scope_ids(scope_id)
        for f in self._provenance_files(scope_id):
            meta_interval = f.meta.interval
            if meta_interval is not None:
                start, end = parse_iso(meta_interval.start), parse_iso(meta_interval.end)
                if start <= interval[0] and interval[1] <= end:
                    covered = True
            results_doc = f.document["response"]
            try:
                evs, ptr, results = provenance_events(results_doc)
            except ValueError:
                gaps.append({"code": "PROVENANCE_FILE_UNREADABLE", "detail": f"{f.path} is not a provenance result."})
                continue
            if isinstance(results.get("total"), str) and results["total"].endswith("+"):
                truncated = True
            for i, ev in enumerate(evs):
                if selector is not None and not event_matches(ev, selector):
                    continue
                if processor_id is not None and ev.get("componentId") != processor_id:
                    continue
                if relationship is not None and ev.get("relationship") != relationship:
                    continue
                if ev.get("groupId") not in in_scope and ev.get("componentId") not in in_scope:
                    continue   # dropped before the event limit, so out-of-scope events never affect the result
                events.append((ev, f"/response{ptr}/{i}", _src(f)))
        if not covered:
            gaps.append({"code": "INTERVAL_NOT_COVERED",
                         "detail": "The requested interval is not fully covered by the bundle's recorded provenance queries."})
        if truncated:
            gaps.append({"code": "EVENTS_TRUNCATED_AT_COLLECTION",
                         "detail": "At least one recorded provenance query reached its result limit when collected."})
        meta = {"query_kind": "bundle_search"}
        if len(events) > max_events:
            events = events[:max_events]
            gaps.append({"code": "EVENT_LIMIT_REACHED", "detail": f"Only the first {max_events} matching events are returned."})
        return events, meta, gaps

    async def locate_connection(self, connection_id: str) -> str | None:
        for scope_id, data in self._scopes.items():
            comp = data.model.find(connection_id)
            if comp is not None and comp.kind == "connection":
                return scope_id
        return None

    async def queue_sample(self, scope_id: str, connection_id: str, sample_size: int):
        for f in self.scope(scope_id).bundle.of_kind("queue_sample"):
            resp = f.document.get("response") if isinstance(f.document, dict) else None
            if isinstance(resp, dict) and resp.get("connection_id") == connection_id:
                summaries = resp.get("flowFileSummaries") or []
                return summaries, "/response/flowFileSummaries", _src(f), []
        return None, None, None, [{"code": "QUEUE_SAMPLE_NOT_IN_BUNDLE",
                                   "detail": "The bundle has no queue metadata sample for this connection."}]

    def notes_files(self, scope_id: str) -> list[BundleFileData]:
        return self.scope(scope_id).bundle.of_kind("operator_notes")

    def flow_sources(self, scope_id: str) -> dict[str, tuple[str, Any]]:
        data = self.scope(scope_id)
        return {f.path: (f.sha256, f.document) for f in data.bundle.of_kind("flow_definition")}


def load_demo_scopes(max_components: int, max_expanded: int) -> list[ScopeData]:
    bundle = import_bundle(demo_data_dir() / DEMO_BUNDLE, max_expanded_bytes=max_expanded)
    return [load_scope(bundle, max_components=max_components)]
