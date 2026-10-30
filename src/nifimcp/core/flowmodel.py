"""Normalize NiFi flow documents into a component inventory with exact source pointers.

Accepted shapes (all JSON):
  * flow definition download / versioned snapshot: ``{"flowContents": {...}}``
  * runtime flow (``flow.json.gz`` contents): ``{"rootGroup": {...}}``
  * REST ``ProcessGroupFlowEntity``: ``{"processGroupFlow": {"flow": {...}}}``
  * a bare process group object containing component arrays

Every component keeps the JSON pointer of its object in the original document,
so any fact can be traced back to exact source bytes via the source hash.
Unknown fields are preserved in ``raw``. Nothing is guessed or filled in.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterator

from ..limits import HARD, MAX_GROUP_NESTING
from . import pointer as jp

COLLECTIONS = {
    "processors": "processor",
    "connections": "connection",
    "inputPorts": "input_port",
    "outputPorts": "output_port",
    "funnels": "funnel",
    "labels": "label",
    "controllerServices": "controller_service",
    "remoteProcessGroups": "remote_process_group",
}
PARAM_REF = re.compile(r"(?<!#)#\{\s*('(?:[^']|'')+'|[^}]+?)\s*\}")


class FlowImportError(ValueError):
    """The document cannot be normalized. Message never echoes document content."""


@dataclass
class Component:
    key: str                       # JSON pointer of the component object
    id: str                        # identifier as written in the document
    instance_id: str | None        # runtime identifier when known
    kind: str
    name: str | None
    type: str | None
    group_key: str | None          # pointer of the parent process group (None for root)
    group_id: str | None
    depth: int                     # process-group nesting depth of the parent (root contents = 1)
    raw: dict = field(repr=False)

    def field(self, name: str) -> tuple[Any, str | None]:
        """Read a field that may live at the top level (definitions) or under config (REST)."""
        if name in self.raw:
            return self.raw[name], jp.join(self.key, name)
        config = self.raw.get("config")
        if isinstance(config, dict) and name in config:
            return config[name], jp.join(self.key, "config", name)
        return None, None

    def properties(self) -> tuple[dict, str]:
        props = self.raw.get("properties")
        if isinstance(props, dict):
            return props, jp.join(self.key, "properties")
        config = self.raw.get("config")
        if isinstance(config, dict) and isinstance(config.get("properties"), dict):
            return config["properties"], jp.join(self.key, "config", "properties")
        return {}, jp.join(self.key, "properties")

    def descriptors(self) -> dict:
        d = self.raw.get("propertyDescriptors")
        if isinstance(d, dict):
            return d
        config = self.raw.get("config")
        if isinstance(config, dict) and isinstance(config.get("descriptors"), dict):
            return config["descriptors"]
        return {}

    @property
    def ids(self) -> set[str]:
        return {i for i in (self.id, self.instance_id) if i}


@dataclass
class FlowModel:
    source_id: str
    source_hash: str
    format: str
    document: Any = field(repr=False)
    root_key: str
    components: list[Component]
    by_id: dict[str, Component]
    contexts: dict[str, dict]
    context_pointers: dict[str, str]
    external_services: dict[str, dict]
    gaps: list[dict]

    @property
    def root(self) -> Component:
        return self.components[0]

    def of_kind(self, *kinds: str) -> Iterator[Component]:
        return (c for c in self.components if c.kind in kinds)

    def find(self, identifier: str | None) -> Component | None:
        if not identifier:
            return None
        return self.by_id.get(str(identifier))

    def group_of(self, component: Component) -> Component | None:
        if component.group_key is None:
            return None
        return next((g for g in self.components if g.key == component.group_key), None)

    def group_path(self, component: Component) -> list[str]:
        names: list[str] = []
        current = self.group_of(component) if component.kind != "process_group" else component
        while current is not None:
            names.append(current.name or "(unnamed group)")
            current = self.group_of(current)
        return list(reversed(names))

    def descendant_group_ids(self, group: Component) -> set[str]:
        keys = {group.key}
        ids = set(group.ids)
        for comp in self.components:
            if comp.kind == "process_group" and comp.group_key in keys:
                keys.add(comp.key)
                ids |= comp.ids
        return ids

    def parameter_context_for(self, component: Component) -> str | None:
        group = component if component.kind == "process_group" else self.group_of(component)
        if group is None:
            return None
        raw = group.raw
        name = raw.get("parameterContextName")
        if isinstance(name, str):
            return name
        ctx = raw.get("parameterContext")
        if isinstance(ctx, dict):
            inner = ctx.get("component") if isinstance(ctx.get("component"), dict) else ctx
            for key in ("name", "id", "identifier"):
                if isinstance(inner.get(key), str):
                    return self._context_name(inner[key])
        if isinstance(raw.get("parameterContextId"), str):
            return self._context_name(raw["parameterContextId"])
        return None

    def _context_name(self, ref: str) -> str:
        for name, ctx in self.contexts.items():
            if ref in (name, ctx.get("identifier"), ctx.get("id")):
                return name
        return ref

    def resolve_parameters(self, context_name: str | None) -> dict[str, tuple[dict, str]]:
        """Parameters visible through a context and its inherited contexts.

        Returns name -> (parameter dict, pointer). Direct parameters win over inherited.
        """
        result: dict[str, tuple[dict, str]] = {}
        seen: set[str] = set()

        def gather(name: str | None, depth: int = 0) -> None:
            if not name or name in seen or depth > 16:
                return
            seen.add(name)
            ctx = self.contexts.get(name)
            if ctx is None:
                return
            base = self.context_pointers[name]
            params = ctx.get("parameters") or []
            for i, entry in enumerate(params if isinstance(params, list) else []):
                param = entry.get("parameter") if isinstance(entry, dict) and isinstance(entry.get("parameter"), dict) else entry
                ptr = jp.join(base, "parameters", i) + ("/parameter" if param is not entry else "")
                if isinstance(param, dict) and isinstance(param.get("name"), str):
                    result.setdefault(param["name"], (param, ptr))
            for ref in ctx.get("inheritedParameterContexts") or []:
                if isinstance(ref, str):
                    gather(self._context_name(ref), depth + 1)
                elif isinstance(ref, dict):
                    inner = ref.get("component") if isinstance(ref.get("component"), dict) else ref
                    gather(self._context_name(str(inner.get("name") or inner.get("id") or "")), depth + 1)

        gather(context_name)
        return result


def parameter_refs(value: Any) -> list[str]:
    if not isinstance(value, str):
        return []
    names = []
    for match in PARAM_REF.finditer(value):
        name = match.group(1)
        if name.startswith("'") and name.endswith("'"):
            name = name[1:-1].replace("''", "'")
        names.append(name)
    return sorted(set(names))


def _unwrap(item: Any, ptr: str) -> tuple[dict, str, dict]:
    """Return (component dict, its pointer, outer entity)."""
    if not isinstance(item, dict):
        raise FlowImportError("component entries must be JSON objects")
    if isinstance(item.get("component"), dict):
        return item["component"], ptr + "/component", item
    return item, ptr, item


def _locate_root(document: Any) -> tuple[dict, str, str]:
    if not isinstance(document, dict):
        raise FlowImportError("expected a JSON object at the top level")
    if isinstance(document.get("flowContents"), dict):
        fmt = "versioned_snapshot" if "snapshotMetadata" in document else "flow_definition"
        return document["flowContents"], "/flowContents", fmt
    if isinstance(document.get("rootGroup"), dict):
        return document["rootGroup"], "/rootGroup", "runtime_flow"
    pgf = document.get("processGroupFlow")
    if isinstance(pgf, dict) and isinstance(pgf.get("flow"), dict):
        return pgf["flow"], "/processGroupFlow/flow", "rest_process_group_flow"
    if any(isinstance(document.get(k), list) for k in ("processors", "processGroups", "connections")):
        return document, "", "process_group"
    raise FlowImportError(
        "NiFi structure not recognized; supply a flow definition download, versioned snapshot, "
        "runtime flow.json or REST process group flow")


def normalize(document: Any, *, source_id: str, source_hash: str,
              max_components: int = HARD["components"]) -> FlowModel:
    root, root_key, fmt = _locate_root(document)
    components: list[Component] = []
    by_id: dict[str, Component] = {}
    gaps: list[dict] = []

    def register(comp: Component) -> None:
        if len(components) >= max_components:
            raise FlowImportError(f"flow contains more than {max_components} components")
        for ident in comp.ids:
            if ident in by_id:
                raise FlowImportError("duplicate component identifier")
        components.append(comp)
        for ident in comp.ids:
            by_id[ident] = comp

    def make(raw: dict, ptr: str, entity: dict, kind: str, group: Component | None, depth: int) -> Component:
        ident = raw.get("identifier") or raw.get("id") or entity.get("id")
        if not isinstance(ident, str) or not ident or len(ident) > 128:
            raise FlowImportError("every component needs a non-empty string identifier (max 128 chars)")
        instance = raw.get("instanceIdentifier") if isinstance(raw.get("instanceIdentifier"), str) else None
        if instance == ident:
            instance = None
        name = raw.get("name") if isinstance(raw.get("name"), str) else (raw.get("label") if isinstance(raw.get("label"), str) else None)
        ctype = raw.get("type") if isinstance(raw.get("type"), str) else None
        return Component(key=ptr, id=ident, instance_id=instance, kind=kind,
                         name=name, type=ctype, group_key=group.key if group else None,
                         group_id=group.id if group else None, depth=depth, raw=raw)

    def visit(group_raw: dict, ptr: str, entity: dict, parent: Component | None, depth: int) -> None:
        if depth > MAX_GROUP_NESTING:
            raise FlowImportError(f"process groups nested deeper than {MAX_GROUP_NESTING} levels")
        if fmt == "rest_process_group_flow" and parent is None:
            pgf = document["processGroupFlow"]
            crumb = pgf.get("breadcrumb") if isinstance(pgf.get("breadcrumb"), dict) else {}
            inner = crumb.get("breadcrumb") if isinstance(crumb.get("breadcrumb"), dict) else {}
            if not isinstance(pgf.get("id"), str):
                raise FlowImportError("REST process group flow has no id")
            group = Component(key="/processGroupFlow", id=pgf["id"], instance_id=None, kind="process_group",
                              name=inner.get("name") if isinstance(inner.get("name"), str) else None,
                              type=None, group_key=None, group_id=None, depth=0, raw=pgf)
        else:
            group = make(group_raw, ptr, entity, "process_group", parent, depth)
        register(group)
        for field_name, kind in COLLECTIONS.items():
            entries = group_raw.get(field_name, [])
            if entries is None:
                continue
            if not isinstance(entries, list):
                raise FlowImportError("component collections must be arrays")
            for i, item in enumerate(entries):
                raw, cptr, outer = _unwrap(item, jp.join(ptr, field_name, i))
                comp = make(raw, cptr, outer, kind, group, depth + 1)
                register(comp)
                if kind == "remote_process_group":
                    contents = raw.get("contents") if isinstance(raw.get("contents"), dict) else raw
                    base = cptr + ("/contents" if contents is not raw else "")
                    for port_field, port_kind in (("inputPorts", "remote_input_port"), ("outputPorts", "remote_output_port")):
                        ports = contents.get(port_field, [])
                        if not isinstance(ports, list):
                            raise FlowImportError("remote ports must be arrays")
                        for j, port in enumerate(ports):
                            praw, pptr, pouter = _unwrap(port, jp.join(base, port_field, j))
                            register(make(praw, pptr, pouter, port_kind, group, depth + 1))
        children = group_raw.get("processGroups", [])
        if children is None:
            children = []
        if not isinstance(children, list):
            raise FlowImportError("processGroups must be an array")
        for i, child in enumerate(children):
            craw, cptr, outer = _unwrap(child, jp.join(ptr, "processGroups", i))
            if fmt == "rest_process_group_flow":
                # REST flow lists child groups as summaries only; contents need a separate read.
                register(make(craw, cptr, outer, "process_group", group, depth + 1))
                gaps.append({"code": "CHILD_GROUP_CONTENTS_NOT_INCLUDED",
                             "detail": "A REST process group flow lists child groups without their contents."})
                continue
            visit(craw, cptr, outer, group, depth + 1)

    visit(root, root_key, root, None, 0)

    contexts: dict[str, dict] = {}
    context_pointers: dict[str, str] = {}
    raw_contexts = document.get("parameterContexts") if isinstance(document, dict) else None
    if isinstance(raw_contexts, dict):
        iterable = [(jp.join("/parameterContexts", k), v) for k, v in raw_contexts.items()]
    elif isinstance(raw_contexts, list):
        iterable = [(jp.join("/parameterContexts", i), v) for i, v in enumerate(raw_contexts)]
    else:
        iterable = []
    for ptr, ctx in iterable:
        if isinstance(ctx, dict) and isinstance(ctx.get("component"), dict):
            ctx, ptr = ctx["component"], ptr + "/component"
        if not isinstance(ctx, dict) or not isinstance(ctx.get("name"), str):
            gaps.append({"code": "PARAMETER_CONTEXT_UNREADABLE",
                         "detail": "A parameter context entry has no name and was not used."})
            continue
        if ctx["name"] in contexts:
            raise FlowImportError("duplicate parameter context name")
        contexts[ctx["name"]] = ctx
        context_pointers[ctx["name"]] = ptr

    external: dict[str, dict] = {}
    raw_ext = document.get("externalControllerServices") if isinstance(document, dict) else None
    if isinstance(raw_ext, dict):
        for key, svc in raw_ext.items():
            if isinstance(svc, dict):
                external[str(key)] = {"pointer": jp.join("/externalControllerServices", key), "raw": svc}

    if fmt == "flow_definition" or fmt == "versioned_snapshot":
        gaps.append({"code": "RUN_STATE_NOT_EXPORTED",
                     "detail": "Flow definitions record ENABLED/DISABLED, not whether components were running. "
                               "Current run state needs live status evidence."})
    return FlowModel(source_id=source_id, source_hash=source_hash, format=fmt, document=document,
                     root_key=root_key, components=components, by_id=by_id, contexts=contexts,
                     context_pointers=context_pointers, external_services=external,
                     gaps=_dedupe(gaps))


def _dedupe(gaps: list[dict]) -> list[dict]:
    seen, out = set(), []
    for gap in gaps:
        key = (gap["code"], gap["detail"])
        if key not in seen:
            seen.add(key)
            out.append(gap)
    return out


def endpoint_ref(endpoint: Any) -> str | None:
    if isinstance(endpoint, dict):
        for key in ("id", "identifier", "instanceIdentifier"):
            if isinstance(endpoint.get(key), str):
                return endpoint[key]
    return None


def connection_endpoints(model: FlowModel, conn: Component) -> tuple[Component | None, Component | None]:
    src = conn.raw.get("source")
    dst = conn.raw.get("destination")
    s = model.find(endpoint_ref(src))
    if s is None and isinstance(src, dict):
        s = model.find(src.get("instanceIdentifier"))
    d = model.find(endpoint_ref(dst))
    if d is None and isinstance(dst, dict):
        d = model.find(dst.get("instanceIdentifier"))
    return s, d


def relationships_of(conn: Component) -> list[str]:
    rels = conn.raw.get("selectedRelationships")
    return [r for r in rels if isinstance(r, str)] if isinstance(rels, list) else []
