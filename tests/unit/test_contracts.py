"""Pydantic models and the public JSON Schemas accept and reject the same instances."""
import copy
import json
from importlib import resources

import jsonschema
import pytest
from pydantic import ValidationError

from helpers import demo_info, demo_session, run
from nifimcp.catalog import load_catalog
from nifimcp.draft.examples import example_plans
from nifimcp.models import Envelope, FlowPlan, TOOL_ARG_MODELS

C = resources.files("nifimcp") / "contracts"
TOOLS = {t["name"]: t for t in json.loads((C / "tool_contracts.json").read_text())["tools"]}
PLAN_SCHEMA = json.loads((C / "flow_plan.schema.json").read_text())
ENVELOPE_SCHEMA = json.loads((C / "result_envelope.schema.json").read_text())
FC = jsonschema.Draft202012Validator.FORMAT_CHECKER


def tool_validator(name):
    schema = copy.deepcopy(TOOLS[name]["inputSchema"])
    if "plan" in schema.get("properties", {}):
        schema["properties"]["plan"] = {k: v for k, v in PLAN_SCHEMA.items() if k != "$schema"}
    return jsonschema.Draft202012Validator(schema, format_checker=FC)


def both(name, args):
    js = tool_validator(name).is_valid(args)
    try:
        TOOL_ARG_MODELS[name].model_validate(args)
        py = True
    except ValidationError:
        py = False
    return js, py


PLAN = example_plans(load_catalog()["catalog_hash"])["attribute_router"]
UUID = "6ae1e6de-d4a6-4f88-be99-5ac47c13e079"
IV = {"start": "2026-10-29T01:00:00Z", "end": "2026-10-29T02:00:00Z"}
CASES = [
    ("get_capabilities", {}, True), ("get_capabilities", {"x": 1}, False),
    ("describe_flow", {"scope_id": "a"}, True), ("describe_flow", {"scope_id": "a", "depth": 8, "cursor": "c"}, True),
    ("describe_flow", {"scope_id": "-bad"}, False), ("describe_flow", {"scope_id": "a", "depth": 0}, False),
    ("describe_flow", {"scope_id": "a", "depth": 9}, False), ("describe_flow", {}, False),
    ("describe_flow", {"scope_id": "a", "depth": "4"}, False), ("describe_flow", {"scope_id": "a", "extra": 1}, False),
    ("get_flow_health", {"scope_id": "a", "interval": IV}, True), ("get_flow_health", {"scope_id": "a"}, True),
    ("get_flow_health", {"scope_id": "a", "interval": {"start": IV["start"]}}, False),
    ("trace_feed", {"scope_id": "a", "interval": IV, "selector": {"kind": "flowfile_uuid", "value": UUID}}, True),
    ("trace_feed", {"scope_id": "a", "interval": IV, "selector": {"kind": "filename", "value": "f"}}, True),
    ("trace_feed", {"scope_id": "a", "interval": IV, "selector": {"kind": "indexed_attribute", "name": "n", "value": "v"}}, True),
    ("trace_feed", {"scope_id": "a", "interval": IV, "selector": {"kind": "flowfile_uuid", "value": "nope"}}, False),
    ("trace_feed", {"scope_id": "a", "interval": IV, "selector": {"kind": "regex", "value": ".*"}}, False),
    ("trace_feed", {"scope_id": "a", "interval": IV, "selector": {"kind": "filename", "value": "f", "x": 1}}, False),
    ("trace_feed", {"scope_id": "a", "selector": {"kind": "filename", "value": "f"}}, False),
    ("inspect_unmatched", {"connection_id": UUID}, True),
    ("inspect_unmatched", {"connection_id": UUID, "interval": IV, "sample_metadata": True}, True),
    ("inspect_unmatched", {"connection_id": "not-a-uuid"}, False),
    ("inspect_unmatched", {"connection_id": UUID, "sample_metadata": "yes"}, False),
    ("compare_flow_snapshots", {"baseline_artifact_id": "art_" + "a" * 16, "candidate_artifact_id": "art_" + "b" * 20}, True),
    ("compare_flow_snapshots", {"baseline_artifact_id": "art_short", "candidate_artifact_id": "art_" + "b" * 20}, False),
    ("compare_flow_snapshots", {"baseline_artifact_id": "/etc/passwd", "candidate_artifact_id": "art_" + "b" * 20}, False),
    ("export_investigation", {"investigation_id": "i", "format": "html"}, True),
    ("export_investigation", {"investigation_id": "i", "format": "pdf"}, False),
    ("get_processor_catalog", {}, True), ("get_processor_catalog", {"type_filter": "RouteOnAttribute"}, True),
    ("get_processor_catalog", {"type_filter": ""}, False),
    ("validate_flow_plan", {"plan": PLAN}, True), ("draft_flow", {"plan": PLAN}, True),
]


@pytest.mark.parametrize("name,args,expected", CASES)
def test_tool_inputs_equivalent(name, args, expected):
    js, py = both(name, args)
    assert js == expected and py == expected, (js, py)


def plan_variants():
    out = []
    for path, value in ((("automatic_start",), True), (("target_version",), "2.11.0"), (("extra",), 1),
                        (("blueprint",), "anything"), (("catalog_hash",), "XYZ"), (("schema_version",), "2"),
                        (("intent",), ""), (("components", 0, "properties", "k"), 5),
                        (("components", 0, "kind"), "funnel"), (("components", 0, "id"), "-x"),
                        (("connections", 0, "relationship"), ""),
                        (("components", 0, "auto_terminated_relationships"), ["a", "a"])):
        plan = copy.deepcopy(PLAN)
        target = plan
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value
        out.append(plan)
    big = copy.deepcopy(PLAN)
    big["components"] = big["components"] * 4
    out.append(big)
    return out


@pytest.mark.parametrize("plan", plan_variants())
def test_invalid_plans_rejected_by_both(plan):
    validator = jsonschema.Draft202012Validator(PLAN_SCHEMA)
    assert not validator.is_valid(plan)
    with pytest.raises(ValidationError):
        FlowPlan.model_validate(plan)


def test_example_plans_valid_in_both():
    for plan in example_plans(load_catalog()["catalog_hash"]).values():
        jsonschema.Draft202012Validator(PLAN_SCHEMA).validate(plan)
        FlowPlan.model_validate(plan)


def test_every_demo_envelope_matches_the_public_schema(tmp_path):
    svc = demo_session(tmp_path)
    info = demo_info()
    validator = jsonschema.Draft202012Validator(ENVELOPE_SCHEMA, format_checker=FC)
    calls = [("get_capabilities", {}), ("describe_flow", {"scope_id": info["scope"]}),
             ("get_flow_health", {"scope_id": info["scope"], "interval": info["interval"]}),
             ("trace_feed", {"scope_id": info["scope"], "interval": info["interval"],
                             "selector": {"kind": "flowfile_uuid", "value": info["trace_flowfile_uuid"]}}),
             ("inspect_unmatched", {"connection_id": info["unmatched_connection_id"], "sample_metadata": True}),
             ("get_processor_catalog", {}), ("validate_flow_plan", {"plan": PLAN}), ("draft_flow", {"plan": PLAN}),
             ("describe_flow", {"scope_id": "missing-scope"}), ("draft_flow", {"plan": {**PLAN, "components": PLAN["components"][:2]}})]
    for name, args in calls:
        env = run(svc, name, args)
        errors = sorted(validator.iter_errors(env), key=str)
        assert not errors, (name, [e.message for e in errors[:3]])
        Envelope.model_validate(env)
