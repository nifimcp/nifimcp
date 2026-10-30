"""Static validation of a bounded FlowPlan against the pinned NiFi 2.12.0 catalog.

Layers: structure -> catalog -> properties -> relationships. Errors, warnings and
unknowns are returned separately. Expression Language and JSONPath strings are
preserved and never evaluated. Static checks cannot establish expression
semantics, native importability or record outcomes; those stay ``unknown`` until
the separate lab verification runs against the exact compiled artifact.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict, deque

from ..core.flowmodel import parameter_refs
from ..core.redact import BEARER, KEY_VALUE_SECRET, URL_USERINFO, is_secret_name
from ..models import FlowPlan
from ..util import canonical_hash

PORT_REL = "port"
URL_SCHEME = re.compile(r"\b[a-z][a-z0-9+.-]{1,20}://", re.I)
ATTR_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9._-]{0,127}$")
UNKNOWNS = [
    {"code": "NATIVE_IMPORTABILITY", "detail": "Whether stock NiFi 2.12.0 imports this artifact is unknown until lab verification."},
    {"code": "EXPRESSION_SEMANTICS", "detail": "Expression Language and JSONPath are not evaluated by NiFiMCP."},
    {"code": "RECORD_OUTCOMES", "detail": "Which records reach which output is unknown until labeled lab cases run."},
]


def plan_hash(plan: FlowPlan) -> str:
    return canonical_hash(plan.model_dump(mode="json"))


def _err(items: list, code: str, path: str, message: str) -> None:
    items.append({"code": code, "path": path, "message": message})


def relationships_for(comp, entry: dict) -> set[str]:
    if comp.kind != "processor":
        return set()
    rels = set(entry.get("relationships") or [])
    if entry.get("dynamic_property_semantics") == "route_condition":
        rels |= {k for k in comp.properties if k not in entry["properties"]}
    return rels


def validate_plan(plan: FlowPlan, catalog: dict) -> dict:
    errors: list[dict] = []
    warnings: list[dict] = []
    stage = "structure"
    entries = {e["type_id"]: e for e in catalog["entries"]}
    blueprint = catalog["blueprints"][plan.blueprint]
    comps = {c.id: c for c in plan.components}

    # ---------------------------------------------------------------- structure
    ids = [c.id for c in plan.components] + [c.id for c in plan.connections]
    for ident, count in Counter(ids).items():
        if count > 1:
            _err(errors, "DUPLICATE_ID", ident, "identifiers must be unique across components and connections")
    if len(plan.components) > 20 or len(plan.connections) > 50:
        _err(errors, "LIMIT_EXCEEDED", "/", "at most 20 components and 50 connections")
    seen_edges = set()
    incoming, outgoing = defaultdict(list), defaultdict(list)
    for i, conn in enumerate(plan.connections):
        path = f"/connections/{i}"
        if conn.source not in comps:
            _err(errors, "UNKNOWN_SOURCE", path, f"source '{conn.source}' is not a component in the plan")
        if conn.destination not in comps:
            _err(errors, "UNKNOWN_DESTINATION", path, f"destination '{conn.destination}' is not a component in the plan")
        if conn.source == conn.destination:
            _err(errors, "SELF_LOOP", path, "self-loops are not supported in the preview")
        key = (conn.source, conn.relationship, conn.destination)
        if key in seen_edges:
            _err(errors, "DUPLICATE_CONNECTION", path, "the same source, relationship and destination appear twice")
        seen_edges.add(key)
        outgoing[conn.source].append(conn)
        incoming[conn.destination].append(conn)
    if not errors:
        stage = "catalog"
    # ---------------------------------------------------------------- catalog
    if plan.catalog_hash != catalog["catalog_hash"]:
        _err(errors, "STALE_CATALOG", "/catalog_hash",
             "catalog_hash does not match the pinned NiFi 2.12.0 catalog; call get_processor_catalog")
    if plan.target_version != catalog["nifi_version"]:
        _err(errors, "UNSUPPORTED_VERSION", "/target_version", "only NiFi 2.12.0 drafts are supported")
    type_counts = Counter()
    for i, comp in enumerate(plan.components):
        path = f"/components/{i}"
        entry = entries.get(comp.type_id)
        if entry is None:
            _err(errors, "UNSUPPORTED_TYPE", path + "/type_id",
                 f"'{comp.type_id}' is not in the pinned catalog; no substitution is made")
            continue
        if comp.type_id not in blueprint["allowed_types"]:
            _err(errors, "TYPE_NOT_IN_BLUEPRINT", path + "/type_id", f"'{comp.type_id}' is not allowed in {plan.blueprint}")
        if entry["kind"] != comp.kind:
            _err(errors, "KIND_MISMATCH", path + "/kind", f"type '{comp.type_id}' is a {entry['kind']}, not a {comp.kind}")
        type_counts[comp.type_id] += 1
    for type_id, (low, high) in blueprint["required_types"].items():
        if not (low <= type_counts.get(type_id, 0) <= high):
            _err(errors, "BLUEPRINT_SHAPE", "/components",
                 f"{plan.blueprint} needs between {low} and {high} component(s) of type {type_id}")
    if errors and stage == "catalog":
        return _report(plan, catalog, stage, errors, warnings)
    stage = "properties"
    # ---------------------------------------------------------------- properties
    declared = {p.name: p for p in plan.parameter_references}
    if len(declared) != len(plan.parameter_references):
        _err(errors, "DUPLICATE_PARAMETER", "/parameter_references", "parameter names must be unique")
    used_params: set[str] = set()
    for i, comp in enumerate(plan.components):
        entry = entries.get(comp.type_id)
        if entry is None:
            continue
        path = f"/components/{i}/properties"
        if comp.kind != "processor":
            if comp.properties:
                _err(errors, "PORT_PROPERTIES", path, "ports take no properties")
            continue
        static = entry["properties"]
        dynamic = {k: v for k, v in comp.properties.items() if k not in static}
        for key, value in comp.properties.items():
            ppath = f"{path}/{key}"
            if URL_SCHEME.search(value):
                _err(errors, "EXTERNAL_URL", ppath, "external URLs are not allowed in a preview draft")
            if URL_USERINFO.search(value) or KEY_VALUE_SECRET.search(value) or BEARER.search(value):
                _err(errors, "EMBEDDED_SECRET", ppath, "the value looks like an embedded credential; use a parameter reference")
            if is_secret_name(key) and not re.fullmatch(r"\s*#\{[^}]+\}\s*", value):
                _err(errors, "EMBEDDED_SECRET", ppath, "a secret-like property must be a parameter reference, never a literal")
            for name in parameter_refs(value):
                used_params.add(name)
                ref = declared.get(name)
                if ref is None:
                    _err(errors, "UNDECLARED_PARAMETER", ppath, f"parameter '{name}' is not declared in parameter_references")
                elif ref.sensitive:
                    _err(errors, "SENSITIVE_PARAMETER_IN_NONSENSITIVE_PROPERTY", ppath,
                         "NiFi rejects sensitive parameters in non-sensitive properties; the supported processors "
                         "have no sensitive properties")
            if value.count("${") > value.count("}"):
                _err(warnings, "EXPRESSION_BRACES", ppath, "expression braces look unbalanced (not evaluated)")
        for key, spec in static.items():
            if key in comp.properties:
                value = comp.properties[key]
                allowed = spec.get("allowable_values")
                if allowed and value not in allowed:
                    _err(errors, "INVALID_VALUE", f"{path}/{key}", f"'{key}' must be one of {allowed}")
                if spec.get("sensitive") and not re.fullmatch(r"\s*#\{[^}]+\}\s*", value):
                    _err(errors, "EMBEDDED_SECRET", f"{path}/{key}", "sensitive properties must be parameter references")
            elif spec.get("required") and spec.get("default") is None:
                _err(errors, "MISSING_REQUIRED", f"{path}/{key}", f"required property '{key}' has no default")
        for key, fixed in (entry.get("fixed_properties") or {}).items():
            if key in comp.properties and comp.properties[key] != fixed:
                _err(errors, "UNSUPPORTED_SETTING", f"{path}/{key}", f"the preview requires '{key}' = '{fixed}'")
        semantics = entry.get("dynamic_property_semantics")
        if dynamic and not entry.get("supports_dynamic_properties"):
            _err(errors, "UNKNOWN_PROPERTY", path, f"unknown properties: {sorted(dynamic)}")
        for key in dynamic:
            if not ATTR_NAME.fullmatch(key):
                _err(errors, "INVALID_DYNAMIC_NAME", f"{path}/{key}", "dynamic property names must be simple identifiers")
        if semantics == "route_condition":
            if not dynamic:
                _err(errors, "NO_ROUTES", path, "RouteOnAttribute needs at least one route condition")
            for key, value in dynamic.items():
                if key == "unmatched":
                    _err(errors, "RESERVED_ROUTE", f"{path}/{key}", "'unmatched' is reserved by NiFi")
                if not value.strip().startswith("${"):
                    _err(warnings, "ROUTE_NOT_EXPRESSION", f"{path}/{key}", "route conditions are normally ${...} expressions")
        elif semantics == "json_path_extraction":
            if not dynamic:
                _err(errors, "NO_JSON_PATHS", path, "EvaluateJsonPath needs at least one attribute = JsonPath entry")
            for key, value in dynamic.items():
                if not value.strip().startswith("$"):
                    _err(warnings, "JSONPATH_SHAPE", f"{path}/{key}", "JsonPath expressions normally start with '$'")
        elif semantics == "attribute_assignment":
            for key in dynamic:
                if key in ("uuid", "path", "filename"):
                    _err(warnings, "CORE_ATTRIBUTE", f"{path}/{key}", f"overwriting core attribute '{key}' is discouraged")
    for name in declared:
        if name not in used_params:
            _err(warnings, "UNUSED_PARAMETER", "/parameter_references", f"parameter '{name}' is declared but unused")
    if errors:
        return _report(plan, catalog, stage, errors, warnings)
    stage = "relationships"
    # ---------------------------------------------------------------- relationships
    for i, comp in enumerate(plan.components):
        entry = entries[comp.type_id]
        path = f"/components/{i}"
        valid = relationships_for(comp, entry)
        connected = {c.relationship for c in outgoing[comp.id]}
        auto = set(comp.auto_terminated_relationships)
        if comp.kind == "input_port":
            if incoming[comp.id]:
                _err(errors, "INPUT_PORT_HAS_INPUT", path, "input ports receive data from outside the subflow only")
            if not outgoing[comp.id]:
                _err(errors, "INPUT_PORT_UNCONNECTED", path, "the input port must feed the subflow")
            if any(c.relationship != PORT_REL for c in outgoing[comp.id]):
                _err(errors, "PORT_RELATIONSHIP", path, f"connections from ports use the relationship '{PORT_REL}'")
            if auto:
                _err(errors, "PORT_AUTO_TERMINATE", path, "ports cannot auto-terminate")
            continue
        if comp.kind == "output_port":
            if outgoing[comp.id]:
                _err(errors, "OUTPUT_PORT_HAS_OUTPUT", path, "output ports hand data to the outside only")
            if not incoming[comp.id]:
                _err(errors, "OUTPUT_PORT_UNCONNECTED", path, "every output port needs at least one incoming connection")
            if auto:
                _err(errors, "PORT_AUTO_TERMINATE", path, "ports cannot auto-terminate")
            continue
        for rel in connected | auto:
            if rel not in valid:
                _err(errors, "UNKNOWN_RELATIONSHIP", path, f"'{rel}' is not a relationship of {comp.type_id.rsplit('.', 1)[-1]} here")
        for rel in sorted(valid - connected - auto):
            _err(errors, "UNHANDLED_RELATIONSHIP", path, f"relationship '{rel}' must be connected or auto-terminated")
        for rel in sorted(connected & auto):
            _err(errors, "CONNECTED_AND_TERMINATED", path, f"relationship '{rel}' is both connected and auto-terminated")
        if not incoming[comp.id]:
            _err(errors, "PROCESSOR_UNREACHABLE", path, "processor has no incoming connection")
    starts = [c.id for c in plan.components if c.kind == "input_port"]
    reach, queue = set(starts), deque(starts)
    while queue:
        node = queue.popleft()
        for conn in outgoing[node]:
            if conn.destination not in reach:
                reach.add(conn.destination)
                queue.append(conn.destination)
    for comp in plan.components:
        if comp.id not in reach:
            _err(errors, "UNREACHABLE", comp.id, "component is not reachable from the input port")
    if _has_cycle(plan):
        _err(errors, "CYCLE", "/connections", "cycles are not supported in the preview")
    out_ports = {c.id for c in plan.components if c.kind == "output_port"}
    for i, exp in enumerate(plan.output_expectations):
        if exp.port_id not in out_ports:
            _err(errors, "EXPECTATION_PORT", f"/output_expectations/{i}", "expectations must name an output port")
    for port in sorted(out_ports - {e.port_id for e in plan.output_expectations}):
        _err(warnings, "NO_EXPECTATION", port, "this output port has no declared output expectation")
    if not errors:
        stage = "static_complete"
    return _report(plan, catalog, stage, errors, warnings)


def _has_cycle(plan: FlowPlan) -> bool:
    graph = defaultdict(list)
    for c in plan.connections:
        graph[c.source].append(c.destination)
    state: dict[str, int] = {}

    def visit(n: str) -> bool:
        state[n] = 1
        for m in graph[n]:
            if state.get(m) == 1 or (state.get(m) is None and visit(m)):
                return True
        state[n] = 2
        return False
    return any(state.get(c.id) is None and visit(c.id) for c in plan.components)


def _report(plan: FlowPlan, catalog: dict, stage: str, errors: list, warnings: list) -> dict:
    return {
        "valid": not errors and stage == "static_complete",
        "stage_reached": stage,
        "stages": ["structure", "catalog", "properties", "relationships", "static_complete"],
        "errors": errors[:200],
        "warnings": warnings[:200],
        "unknowns": UNKNOWNS,
        "plan_sha256": plan_hash(plan),
        "catalog_hash": catalog["catalog_hash"],
        "runtime_validity": "unknown until the separate lab verification runs on the compiled artifact",
    }
