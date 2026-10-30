"""Graph view of a normalized flow: map, entry/exit points, routing and dependencies."""
from __future__ import annotations

from collections import defaultdict
from typing import Any

from . import pointer as jp
from .flowmodel import Component, FlowModel, connection_endpoints, parameter_refs, relationships_of
from .redact import Redactor

SOURCE_HINTS = ("Generate", "Listen", "Consume", "Get", "List", "Fetch", "Query", "Tail")
SINK_HINTS = ("Put", "Publish", "Send", "Post", "Invoke", "Log")


def cid(comp: Component) -> str:
    return comp.instance_id or comp.id


class Adjacency:
    def __init__(self, model: FlowModel):
        self.model = model
        self.out: dict[str, list[tuple[Component, Component | None]]] = defaultdict(list)
        self.into: dict[str, list[tuple[Component, Component | None]]] = defaultdict(list)
        for conn in model.of_kind("connection"):
            src, dst = connection_endpoints(model, conn)
            if src is not None:
                self.out[src.key].append((conn, dst))
            if dst is not None:
                self.into[dst.key].append((conn, src))

    def upstream(self, comp: Component, limit: int = 200) -> list[Component]:
        seen, order, stack = {comp.key}, [], [comp]
        while stack and len(order) < limit:
            node = stack.pop()
            for _conn, src in self.into.get(node.key, []):
                if src is not None and src.key not in seen:
                    seen.add(src.key)
                    order.append(src)
                    stack.append(src)
        return order


def ordered_components(model: FlowModel, root: Component, depth: int) -> tuple[list[Component], int]:
    """Components inside ``root`` up to ``depth`` group levels, in deterministic order.

    Returns (components, excluded_count). depth=1 means the root group's direct contents.
    """
    root_depth = root.depth
    descendants = model.descendant_group_ids(root)
    group_keys = {g.key for g in model.of_kind("process_group") if g.ids & descendants}
    selected, excluded = [], 0
    for comp in model.components:
        if comp is root:
            continue
        if comp.group_key not in group_keys:
            continue
        rel_depth = comp.depth - root_depth
        if rel_depth <= depth:
            selected.append(comp)
        else:
            excluded += 1
    kind_order = {"process_group": 0, "input_port": 1, "processor": 2, "funnel": 3, "output_port": 4,
                  "connection": 5, "controller_service": 6, "remote_process_group": 7,
                  "remote_input_port": 8, "remote_output_port": 9, "label": 10}
    selected.sort(key=lambda c: (c.depth, model.group_path(c), kind_order.get(c.kind, 99), c.name or "", cid(c)))
    return [root, *selected], excluded


def graph_view(model: FlowModel, root: Component, components: list[Component], redactor: Redactor,
               evidence_for: dict[str, str]) -> dict[str, Any]:
    adj = Adjacency(model)
    keys = {c.key for c in components}
    nodes, edges = [], []
    for comp in components:
        if comp.kind == "connection":
            src, dst = connection_endpoints(model, comp)
            edges.append({
                "id": cid(comp),
                "source_id": cid(src) if src else None,
                "destination_id": cid(dst) if dst else None,
                "relationships": sorted(relationships_of(comp)),
                "name": redactor.name(comp.name) if comp.name else None,
                "evidence_id": evidence_for.get(comp.key),
                "endpoint_outside_view": not (src and src.key in keys and dst and dst.key in keys),
            })
        else:
            group = model.group_of(comp)
            nodes.append({
                "id": cid(comp),
                "kind": comp.kind,
                "type": comp.type.rsplit(".", 1)[-1] if comp.type else None,
                "name": redactor.name(comp.name) if comp.name else None,
                "group_id": cid(group) if group else None,
                "evidence_id": evidence_for.get(comp.key),
            })

    entry, exit_ = [], []
    root_ids = root.ids
    for comp in components:
        if comp.kind == "input_port" and model.group_of(comp) is root:
            entry.append({"id": cid(comp), "kind": "input_port", "reason": "input port of the scope group"})
        elif comp.kind == "output_port" and model.group_of(comp) is root:
            exit_.append({"id": cid(comp), "kind": "output_port", "reason": "output port of the scope group"})
        elif comp.kind == "processor":
            short = (comp.type or "").rsplit(".", 1)[-1]
            if not adj.into.get(comp.key):
                entry.append({"id": cid(comp), "kind": "processor", "type": short,
                              "reason": "no incoming connection in this source"})
            if not adj.out.get(comp.key):
                exit_.append({"id": cid(comp), "kind": "processor", "type": short,
                              "reason": "no outgoing connection in this source"})
            elif short.startswith(SINK_HINTS):
                exit_.append({"id": cid(comp), "kind": "processor", "type": short,
                              "reason": "type name suggests an external handoff; behavior not verified"})
        elif comp.kind == "remote_output_port":
            entry.append({"id": cid(comp), "kind": comp.kind, "reason": "remote output port feeds this flow"})
        elif comp.kind == "remote_input_port":
            exit_.append({"id": cid(comp), "kind": comp.kind, "reason": "remote input port receives from this flow"})
    del root_ids

    routing = []
    for comp in components:
        if comp.kind != "processor":
            continue
        auto, _ = comp.field("autoTerminatedRelationships")
        auto = sorted(a for a in auto if isinstance(a, str)) if isinstance(auto, list) else []
        rels: dict[str, list[str]] = defaultdict(list)
        for conn, dst in adj.out.get(comp.key, []):
            for rel in relationships_of(conn):
                rels[rel].append(cid(dst) if dst else "outside-source")
        conditions = {}
        short = (comp.type or "").rsplit(".", 1)[-1]
        if short in ("RouteOnAttribute", "RouteOnContent", "RouteText"):
            props, base = comp.properties()
            descriptors = comp.descriptors()
            for key, value in sorted(props.items()):
                desc = descriptors.get(key) if isinstance(descriptors.get(key), dict) else {}
                dynamic = desc.get("dynamic") is True or key in rels or (key not in ("Routing Strategy",) and short == "RouteOnAttribute")
                if dynamic and isinstance(key, str):
                    conditions[key] = redactor.property_value(key, value, desc, jp.join(base, key))
        if rels or auto or conditions:
            routing.append({
                "processor_id": cid(comp), "type": short,
                "relationships": {k: sorted(v) for k, v in sorted(rels.items())},
                "auto_terminated": auto,
                "route_conditions": conditions,
            })

    params: dict[str, dict] = {}
    services, endpoints = [], []
    for comp in components:
        if comp.kind not in ("processor", "controller_service"):
            continue
        props, base = comp.properties()
        descriptors = comp.descriptors()
        context = model.parameter_context_for(comp)
        resolved = model.resolve_parameters(context)
        for key, value in props.items():
            if not isinstance(value, str):
                continue
            for name in parameter_refs(value):
                entry_ = params.setdefault(name, {"name": redactor.name(name), "context": redactor.name(context),
                                                  "resolved": name in resolved, "referenced_by": []})
                if name in resolved:
                    param, pptr = resolved[name]
                    entry_.update(redactor.parameter(name, param, pptr))
                    entry_["name"] = redactor.name(name)
                entry_["referenced_by"].append(cid(comp))
            desc = descriptors.get(key) if isinstance(descriptors.get(key), dict) else {}
            if desc.get("identifiesControllerService") and value and not parameter_refs(value):
                services.append({"referenced_by": cid(comp), "property": key, "service_id": value,
                                 "present_in_source": model.find(value) is not None or value in model.external_services})
            lowered = value.lower()
            if "://" in lowered and not lowered.startswith("${"):
                endpoints.append({"component_id": cid(comp), "property": key,
                                  "value": redactor.property_value(key, value, desc, jp.join(base, key))})
    return {
        "nodes": nodes,
        "edges": edges,
        "entry_points": entry,
        "exit_points": exit_,
        "routing": routing,
        "dependencies": {
            "parameters": sorted(params.values(), key=lambda p: str(p.get("name"))),
            "controller_services": services,
            "external_endpoints": endpoints[:200],
        },
    }
