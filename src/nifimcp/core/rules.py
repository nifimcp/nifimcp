"""Deterministic configuration rules.

Adapted from NiFi Flow Doctor and Checkride (Apache-2.0, see ATTRIBUTION.md), with
review-pattern semantics re-implemented from the author's earlier tooling (no code
copied; see ATTRIBUTION.md). Every finding cites field-level evidence. Statements
describe configuration review concerns; they never claim a measured incident.
"""
from __future__ import annotations

import re
from typing import Any

from . import pointer as jp
from .evidence import EvidenceSet, make_evidence, make_finding
from .flowmodel import Component, FlowModel, connection_endpoints, parameter_refs, relationships_of
from .graph import Adjacency
from .redact import PARAM_ONLY, Redactor, secret_like_unknown

ZERO_DURATION = re.compile(r"^\s*0+(?:\.0+)?\s*(?:ns|nanos?|ms|millis?|s|secs?|seconds?|min|mins?|minutes?|h|hrs?|hours?|d|days?)?\s*$", re.I)
ZERO_SIZE = re.compile(r"^\s*0+(?:\.0+)?\s*(?:b|kb|mb|gb|tb|bytes?)?\s*$", re.I)
CUSTOM_CODE_TYPES = ("ExecuteScript", "ExecuteGroovyScript", "ExecuteStreamCommand", "ExecuteProcess",
                     "InvokeScriptedProcessor", "ExecuteScriptedProcessor")
STANDARD_BUNDLE_GROUP = "org.apache.nifi"

LIM_CONFIG = "Configuration fact from the cited source; it does not establish runtime behavior or a current incident."
LIM_UNMATCHED = ("Unmatched is a routing outcome and can be intentional. The relationship name does not reveal "
                 "why a record took that route.")


def _cid(comp: Component) -> str:
    return comp.instance_id or comp.id


def component_facts(model: FlowModel, comp: Component, redactor: Redactor) -> dict:
    facts: dict[str, Any] = {
        "component_kind": comp.kind,
        "identifier": comp.id,
        "instance_identifier": comp.instance_id,
        "name": redactor.name(comp.name, jp.join(comp.key, "name")),
        "group_path": [redactor.name(n) for n in model.group_path(comp)] if redactor.policy.include_component_names else None,
    }
    if comp.type:
        facts["type"] = comp.type
    bundle = comp.raw.get("bundle")
    if isinstance(bundle, dict):
        facts["bundle"] = {k: bundle.get(k) for k in ("group", "artifact", "version") if isinstance(bundle.get(k), str)}
    if comp.kind == "processor":
        for name in ("scheduledState", "state", "schedulingStrategy", "schedulingPeriod",
                     "concurrentlySchedulableTaskCount", "executionNode", "validationStatus"):
            value, _ = comp.field(name)
            if isinstance(value, (str, int, float, bool)):
                facts[name] = value
        auto, _ = comp.field("autoTerminatedRelationships")
        if isinstance(auto, list):
            facts["autoTerminatedRelationships"] = sorted(a for a in auto if isinstance(a, str))
        rels = comp.raw.get("relationships")
        if isinstance(rels, list):
            facts["relationships"] = sorted(r.get("name") for r in rels if isinstance(r, dict) and isinstance(r.get("name"), str))
        errors = comp.raw.get("validationErrors")
        if isinstance(errors, list):
            facts["validation_error_count"] = len(errors)
        props, base = comp.properties()
        descriptors = comp.descriptors()
        facts["properties"] = {
            str(k): redactor.property_value(str(k), v, descriptors.get(k) if isinstance(descriptors.get(k), dict) else None,
                                            jp.join(base, k))
            for k, v in sorted(props.items())[:100]
        }
        if len(props) > 100:
            facts["properties_omitted"] = len(props) - 100
    elif comp.kind == "connection":
        src, dst = connection_endpoints(model, comp)
        facts.update({
            "source_id": _cid(src) if src else _raw_endpoint(comp, "source"),
            "source_kind": src.kind if src else None,
            "destination_id": _cid(dst) if dst else _raw_endpoint(comp, "destination"),
            "destination_kind": dst.kind if dst else None,
            "relationships": sorted(relationships_of(comp)),
        })
        for name in ("backPressureObjectThreshold", "backPressureDataSizeThreshold", "flowFileExpiration",
                     "loadBalanceStrategy", "partitioningAttribute"):
            value = comp.raw.get(name)
            if isinstance(value, (str, int, float)):
                facts[name] = value
        prio = comp.raw.get("prioritizers")
        if isinstance(prio, list):
            facts["prioritizers"] = [p for p in prio if isinstance(p, str)]
    elif comp.kind == "process_group":
        facts["parameter_context"] = redactor.name(model.parameter_context_for(comp))
    elif comp.kind in ("input_port", "output_port"):
        for name in ("scheduledState", "state", "allowRemoteAccess"):
            value = comp.raw.get(name)
            if isinstance(value, (str, bool)):
                facts[name] = value
    elif comp.kind == "controller_service":
        props, base = comp.properties()
        descriptors = comp.descriptors()
        facts["properties"] = {
            str(k): redactor.property_value(str(k), v, descriptors.get(k) if isinstance(descriptors.get(k), dict) else None,
                                            jp.join(base, k))
            for k, v in sorted(props.items())[:100]
        }
    elif comp.kind == "remote_process_group":
        uris = comp.raw.get("targetUris") or comp.raw.get("targetUri")
        if isinstance(uris, str):
            facts["target_uris"] = redactor.endpoint(uris, jp.join(comp.key, "targetUris"))
    return facts


def _raw_endpoint(conn: Component, side: str) -> str | None:
    ep = conn.raw.get(side)
    if isinstance(ep, dict):
        for key in ("instanceIdentifier", "id"):
            if isinstance(ep.get(key), str):
                return ep[key]
    return None


class RuleContext:
    def __init__(self, model: FlowModel, redactor: Redactor, collected_at: str, out: EvidenceSet):
        self.model, self.redactor, self.collected_at, self.out = model, redactor, collected_at, out
        self.component_evidence: dict[str, str] = {}
        self.adj = Adjacency(model)

    def component(self, comp: Component) -> str:
        if comp.key not in self.component_evidence:
            rec = make_evidence(kind="configuration", source_id=self.model.source_id,
                                source_hash=self.model.source_hash, source_pointer=comp.key,
                                facts=component_facts(self.model, comp, self.redactor),
                                collected_at=self.collected_at, component_id=_cid(comp))
            self.component_evidence[comp.key] = self.out.add_evidence(rec)
        return self.component_evidence[comp.key]

    def field(self, comp: Component, pointer: str, field_name: str, value: Any, *, masked: bool = False) -> str:
        if masked:
            shown: Any = {"state": "masked"}
        elif isinstance(value, str):
            shown = self.redactor.property_value(field_name, value, None, pointer)
        else:
            shown = value
        rec = make_evidence(kind="configuration", source_id=self.model.source_id, source_hash=self.model.source_hash,
                            source_pointer=pointer, facts={"field": field_name, "value": shown},
                            collected_at=self.collected_at, component_id=_cid(comp))
        return self.out.add_evidence(rec)

    def finding(self, rule: str, comp: Component, statement: str, severity: str, evidence: list[str],
                limitations: list[str], kind: str = "deterministic_rule", suffix: str = "") -> None:
        fid = f"{rule}:{_cid(comp)}" + (f":{suffix}" if suffix else "")
        self.out.add_finding(make_finding(finding_id=fid, statement=statement, kind=kind, severity=severity,
                                          evidence_ids=[self.component(comp), *evidence], limitations=limitations))


def _label(ctx: RuleContext, comp: Component) -> str:
    name = ctx.redactor.name(comp.name) if comp.name else None
    kind = comp.kind.replace("_", " ")
    return f"{kind} '{name}' ({_cid(comp)})" if name else f"{kind} {_cid(comp)}"


def analyze(model: FlowModel, redactor: Redactor, collected_at: str, *, components: list[Component] | None = None) -> EvidenceSet:
    out = EvidenceSet()
    for g in model.gaps:
        out.add_gap(g["code"], g["detail"])
    ctx = RuleContext(model, redactor, collected_at, out)
    selected = components if components is not None else model.components
    for comp in selected:
        ctx.component(comp)
        if comp.kind == "processor":
            _processor_rules(ctx, comp)
        elif comp.kind == "connection":
            _connection_rules(ctx, comp)
        elif comp.kind == "controller_service":
            _property_rules(ctx, comp)
    return out


def _processor_rules(ctx: RuleContext, comp: Component) -> None:
    model = ctx.model
    label = _label(ctx, comp)
    state, sptr = comp.field("scheduledState")
    if state is None:
        state, sptr = comp.field("state")
    if isinstance(state, str) and state.upper() in ("STOPPED", "DISABLED"):
        when = ("at collection time" if model.format in ("rest_process_group_flow", "runtime_flow") else "in this export")
        ev = ctx.field(comp, sptr, "scheduledState", state)
        ctx.finding("NM-STOPPED", comp, f"{label} is recorded as {state.upper()} {when}.", "info", [ev],
                    [LIM_CONFIG, "A recorded stopped state is not proof of an outage or of when it stopped."])
    vstatus = comp.raw.get("validationStatus")
    verrors = comp.raw.get("validationErrors")
    if (isinstance(vstatus, str) and vstatus.upper() == "INVALID") or (isinstance(verrors, list) and verrors):
        ptr = jp.join(comp.key, "validationStatus" if "validationStatus" in comp.raw else "validationErrors")
        ev = ctx.field(comp, ptr, "validationStatus",
                       vstatus if isinstance(vstatus, str) else f"{len(verrors)} validation errors")
        ctx.finding("NM-INVALID", comp, f"NiFi reported {label} as INVALID when this source was collected.",
                    "warning", [ev], ["Validation messages are not reproduced; inspect the component in NiFi.",
                                      "Validity can change after collection."], kind="observed")
    strategy, _ = comp.field("schedulingStrategy")
    period, pptr = comp.field("schedulingPeriod")
    if strategy == "TIMER_DRIVEN" and isinstance(period, str) and ZERO_DURATION.fullmatch(period):
        ev = ctx.field(comp, pptr, "schedulingPeriod", period)
        ctx.finding("NM-ZERO-TIMER", comp,
                    f"{label} is timer-driven with a zero run schedule, so it can run continuously whenever work is available.",
                    "review", [ev], [LIM_CONFIG, "This is a CPU-demand review concern, not a measured load problem."])
    auto, aptr = comp.field("autoTerminatedRelationships")
    if isinstance(auto, list):
        dropped = sorted(a for a in auto if isinstance(a, str) and re.search(r"fail|retry", a, re.I))
        if dropped:
            ev = ctx.field(comp, aptr, "autoTerminatedRelationships", [a for a in auto if isinstance(a, str)])
            ctx.finding("NM-AUTOTERM-FAILURE", comp,
                        f"{label} auto-terminates {', '.join(dropped)}; FlowFiles routed there are discarded.",
                        "review", [ev], [LIM_CONFIG, "Auto-termination may be intentional; confirm the discard policy."])
    if comp.type and comp.type.rsplit(".", 1)[-1] in CUSTOM_CODE_TYPES:
        ev = ctx.field(comp, jp.join(comp.key, "type"), "type", comp.type)
        ctx.finding("NM-CUSTOM-CODE", comp, f"{label} runs custom code or commands ({comp.type.rsplit('.', 1)[-1]}).",
                    "review", [ev], [LIM_CONFIG, "NiFiMCP never executes or models imported scripts; review them separately."])
        ctx.out.add_gap("CUSTOM_CODE_NOT_MODELED", f"Behavior of {_cid(comp)} depends on custom code that is not modeled.")
    bundle = comp.raw.get("bundle")
    if isinstance(bundle, dict) and isinstance(bundle.get("group"), str) and bundle["group"] != STANDARD_BUNDLE_GROUP:
        ctx.out.add_gap("CUSTOM_COMPONENT_UNRESOLVED",
                        f"Component {_cid(comp)} comes from a non-Apache bundle; its behavior is not modeled.")
    _property_rules(ctx, comp)
    _unmatched_rules(ctx, comp)


def _property_rules(ctx: RuleContext, comp: Component) -> None:
    model = ctx.model
    label = _label(ctx, comp)
    props, base = comp.properties()
    descriptors = comp.descriptors()
    params = model.resolve_parameters(model.parameter_context_for(comp))
    for key, value in sorted(props.items()):
        if not isinstance(value, str) or not isinstance(key, str):
            continue
        ptr = jp.join(base, key)
        desc = descriptors.get(key) if isinstance(descriptors.get(key), dict) else {}
        for name in parameter_refs(value):
            if name not in params:
                ev = ctx.field(comp, ptr, key, value)
                ctx.finding("NM-PARAM-UNRESOLVED", comp,
                            f"Property '{key}' of {label} references parameter '{ctx.redactor.name(name)}', "
                            "which this source does not define.", "review", [ev],
                            ["The parameter may come from a context that was not exported. No value is assumed."],
                            suffix=f"{key}:{name}"[:60])
                ctx.out.add_gap("PARAMETER_UNRESOLVED",
                                "One or more parameter references cannot be resolved from the supplied source.")
        if value.lower().startswith("http://"):
            ev = ctx.field(comp, ptr, key, value)
            ctx.finding("NM-HTTP-ENDPOINT", comp, f"Property '{key}' of {label} uses an unencrypted http:// endpoint.",
                        "review", [ev], [LIM_CONFIG, "This may be an intentional trusted hop; it is not proof of exposure."],
                        suffix=key[:60])
        sensitive_desc = desc.get("sensitive") is True
        if value and secret_like_unknown(key, desc) and not sensitive_desc and not PARAM_ONLY.fullmatch(value) \
                and not value.strip().startswith("${"):
            ev = ctx.field(comp, ptr, key, value, masked=True)
            ctx.finding("NM-SECRET-LITERAL", comp,
                        f"Property '{key}' of {label} holds a literal value under a secret-like name. The value was masked.",
                        "warning", [ev], ["Name-based heuristic; the value may be harmless.",
                                          "Review before sharing the source export."], suffix=key[:60])
        if desc.get("identifiesControllerService") and value and not parameter_refs(value):
            if model.find(value) is None and value not in model.external_services:
                ev = ctx.field(comp, ptr, key, value)
                ctx.finding("NM-SERVICE-UNRESOLVED", comp,
                            f"Property '{key}' of {label} references a controller service that is not in this source.",
                            "review", [ev], ["The service may be defined outside the exported scope. Its configuration is unknown."],
                            suffix=key[:60])
                ctx.out.add_gap("SERVICE_UNRESOLVED", "One or more referenced controller services are absent from the source.")


def _unmatched_rules(ctx: RuleContext, comp: Component) -> None:
    model = ctx.model
    outgoing = [conn for conn, _dst in ctx.adj.out.get(comp.key, [])]
    routes_unmatched = [c for c in outgoing if "unmatched" in relationships_of(c)]
    auto, aptr = comp.field("autoTerminatedRelationships")
    auto_unmatched = isinstance(auto, list) and "unmatched" in auto
    label = _label(ctx, comp)
    for conn in routes_unmatched:
        _, dst = connection_endpoints(model, conn)
        ev = ctx.component(conn)
        target = _label(ctx, dst) if dst else "a component outside this source"
        ctx.finding("NM-UNMATCHED-ROUTE", comp, f"{label} sends its 'unmatched' relationship to {target}.",
                    "info", [ev], [LIM_UNMATCHED, LIM_CONFIG], suffix=_cid(conn)[:40])
    if auto_unmatched:
        ev = ctx.field(comp, aptr, "autoTerminatedRelationships", [a for a in auto if isinstance(a, str)])
        ctx.finding("NM-UNMATCHED-DISCARDED", comp, f"{label} auto-terminates 'unmatched'; unmatched FlowFiles are discarded.",
                    "review", [ev], [LIM_UNMATCHED, "Discarding unmatched data may be intentional."])


def _connection_rules(ctx: RuleContext, comp: Component) -> None:
    model = ctx.model
    label = _label(ctx, comp)
    src, dst = connection_endpoints(model, comp)
    for side, found in (("source", src), ("destination", dst)):
        if found is None:
            ev = ctx.field(comp, jp.join(comp.key, side), side, _raw_endpoint(comp, side))
            ctx.finding("NM-ENDPOINT-OUTSIDE", comp,
                        f"The {side} of {label} is not in this source; the topology shown is incomplete.",
                        "review", [ev], ["Supply a wider export before concluding the connection is broken."], suffix=side)
            ctx.out.add_gap("TOPOLOGY_INCOMPLETE", "At least one connection endpoint lies outside the supplied source.")
    exp = comp.raw.get("flowFileExpiration")
    if isinstance(exp, str) and exp.strip() and not ZERO_DURATION.fullmatch(exp):
        ev = ctx.field(comp, jp.join(comp.key, "flowFileExpiration"), "flowFileExpiration", exp)
        ctx.finding("NM-QUEUE-EXPIRATION", comp, f"{label} expires queued FlowFiles after {exp}.", "review", [ev],
                    [LIM_CONFIG, "Expiration can discard queued data; confirm against delivery requirements."])
    count = comp.raw.get("backPressureObjectThreshold")
    size = comp.raw.get("backPressureDataSizeThreshold")
    if count == 0 and isinstance(size, str) and ZERO_SIZE.fullmatch(size):
        ev = ctx.field(comp, jp.join(comp.key, "backPressureObjectThreshold"), "backPressureObjectThreshold", count)
        ev2 = ctx.field(comp, jp.join(comp.key, "backPressureDataSizeThreshold"), "backPressureDataSizeThreshold", size)
        ctx.finding("NM-UNBOUNDED-QUEUE", comp, f"{label} has both back-pressure thresholds set to zero (unbounded queue).",
                    "warning", [ev, ev2], [LIM_CONFIG, "A static source cannot predict actual queue growth."])
    lb = comp.raw.get("loadBalanceStrategy")
    if isinstance(lb, str) and lb in ("PARTITION_BY_ATTRIBUTE", "SINGLE_NODE"):
        ev = ctx.field(comp, jp.join(comp.key, "loadBalanceStrategy"), "loadBalanceStrategy", lb)
        ctx.finding("NM-NODE-AFFINITY", comp, f"{label} uses {lb} load balancing, which can hold data on one node during an outage.",
                    "info", [ev], [LIM_CONFIG, "Only relevant in clustered deployments; not a statement about event ordering."])
