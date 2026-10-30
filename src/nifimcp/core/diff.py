"""Value-safe structural and configuration diff of two flow sources.

Adapted from NiFi Flow Checkride (Apache-2.0, see ATTRIBUTION.md): cosmetic fields
are ignored, collections of identified objects are compared order-insensitively,
while order-sensitive arrays (prioritizers, relationship lists written as lists)
remain visible. Values are never emitted: only field paths that changed.
Regenerated identifiers appear as add/remove pairs and are flagged.
"""
from __future__ import annotations

from typing import Any

from .flowmodel import FlowModel

COSMETIC = {"position", "bends", "labelIndex", "zIndex", "instanceIdentifier", "style", "styles",
            "positionX", "positionY", "groupIdentifier"}
STRUCTURAL = {"processors", "connections", "inputPorts", "outputPorts", "funnels", "labels", "controllerServices",
              "remoteProcessGroups", "processGroups"}
ENDPOINT_COSMETIC = {"name", "comments", "instanceIdentifier"}


def _normalize(value: Any, parent_key: str = "") -> Any:
    if isinstance(value, dict):
        drop = COSMETIC | (ENDPOINT_COSMETIC if parent_key in ("source", "destination") else set())
        return {k: _normalize(v, k) for k, v in value.items() if k not in drop}
    if isinstance(value, list):
        items = [_normalize(v, parent_key) for v in value]
        if items and all(isinstance(v, dict) and isinstance(v.get("identifier"), str) for v in items):
            return sorted(items, key=lambda v: v["identifier"])
        if parent_key in ("selectedRelationships", "autoTerminatedRelationships") and all(isinstance(v, str) for v in items):
            return sorted(items)
        return items
    return value


def _changed_paths(a: Any, b: Any, path: str, out: list[str], limit: int = 200) -> None:
    if len(out) >= limit:
        return
    if isinstance(a, dict) and isinstance(b, dict):
        for key in sorted(set(a) | set(b)):
            sub = f"{path}/{key}"
            if key not in a or key not in b:
                out.append(sub)
            elif a[key] != b[key]:
                _changed_paths(a[key], b[key], sub, out, limit)
        return
    out.append(path or "/")


def diff_models(before: FlowModel, after: FlowModel) -> dict:
    a = {c.id: c for c in before.components}
    b = {c.id: c for c in after.components}
    changed, layout_only = [], 0
    for key in sorted(a.keys() & b.keys()):
        ca, cb = a[key], b[key]
        exclude = STRUCTURAL if ca.kind == cb.kind == "process_group" else set()
        ra = {k: v for k, v in ca.raw.items() if k not in exclude}
        rb = {k: v for k, v in cb.raw.items() if k not in exclude}
        na, nb = _normalize(ra), _normalize(rb)
        if na == nb:
            if ra != rb:
                layout_only += 1
            continue
        paths: list[str] = []
        _changed_paths(na, nb, "", paths)
        if ca.kind != cb.kind:
            paths.append("/componentKind")
        changed.append({"component_id": cb.instance_id or cb.id, "identifier": key, "kind": cb.kind,
                        "changed_fields": paths, "before_pointer": ca.key, "after_pointer": cb.key})
    added = [{"identifier": k, "component_id": b[k].instance_id or k, "kind": b[k].kind, "after_pointer": b[k].key}
             for k in sorted(b.keys() - a.keys())]
    removed = [{"identifier": k, "component_id": a[k].instance_id or k, "kind": a[k].kind, "before_pointer": a[k].key}
               for k in sorted(a.keys() - b.keys())]
    da = before.document if isinstance(before.document, dict) else {}
    db = after.document if isinstance(after.document, dict) else {}
    root_keys = {"flowContents", "rootGroup", "processGroupFlow"}
    metadata = [k for k in sorted((da.keys() | db.keys()) - root_keys)
                if (k in da) != (k in db) or _normalize(da.get(k)) != _normalize(db.get(k))]
    regenerated = bool(added and removed and {x["kind"] for x in added} & {x["kind"] for x in removed})
    return {
        "added": added, "removed": removed, "changed": changed,
        "layout_only_changes_ignored": layout_only,
        "snapshot_fields_changed": metadata,
        "possible_regenerated_identifiers": regenerated,
        "notes": [
            "Values are omitted; only field paths are reported.",
            "Layout (position, bends, label index) and collection ordering of identified objects are ignored.",
            "Order-sensitive lists such as prioritizers remain visible.",
            "Components are matched by exact identifier; regenerated identifiers appear as removed plus added.",
        ],
    }
