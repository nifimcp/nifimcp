"""A22: catalog hash, types, required properties, graph references and relationships validated."""
import copy

import pytest

from nifimcp.catalog import load_catalog
from nifimcp.draft.examples import example_plans
from nifimcp.draft.validate import validate_plan
from nifimcp.models import FlowPlan

CAT = load_catalog()


def plan(name="attribute_router"):
    return copy.deepcopy(example_plans(CAT["catalog_hash"])[name])


def check(doc):
    return validate_plan(FlowPlan.model_validate(doc), CAT)


def codes(report):
    return {e["code"] for e in report["errors"]}


def comp(doc, cid):
    return next(c for c in doc["components"] if c["id"] == cid)


@pytest.mark.parametrize("name", ["attribute_router", "json_field_gate"])
def test_reference_plans_valid(name):
    r = check(plan(name))
    assert r["valid"] and r["stage_reached"] == "static_complete" and not r["errors"]
    assert {u["code"] for u in r["unknowns"]} == {"NATIVE_IMPORTABILITY", "EXPRESSION_SEMANTICS", "RECORD_OUTCOMES"}


def test_stale_catalog_hash():
    doc = plan()
    doc["catalog_hash"] = "0" * 64
    assert "STALE_CATALOG" in codes(check(doc))


def test_unknown_type_not_substituted():
    doc = plan()
    comp(doc, "normalize")["type_id"] = "org.apache.nifi.processors.attributes.UpdateAttributeX"
    r = check(doc)
    assert "UNSUPPORTED_TYPE" in codes(r) and not r["valid"]


def test_type_outside_blueprint_and_kind_mismatch():
    doc = plan()
    comp(doc, "normalize")["type_id"] = "org.apache.nifi.processors.standard.EvaluateJsonPath"
    assert "TYPE_NOT_IN_BLUEPRINT" in codes(check(doc))
    doc = plan()
    comp(doc, "normalize")["kind"] = "output_port"
    assert "KIND_MISMATCH" in codes(check(doc))


def test_graph_references():
    doc = plan()
    doc["connections"][0]["destination"] = "ghost"
    assert "UNKNOWN_DESTINATION" in codes(check(doc))
    doc = plan()
    doc["connections"].append(dict(doc["connections"][1], id="dup"))
    assert "DUPLICATE_CONNECTION" in codes(check(doc))
    doc = plan()
    doc["connections"][1]["destination"] = doc["connections"][1]["source"]
    assert "SELF_LOOP" in codes(check(doc))
    doc = plan()
    doc["components"].append(dict(comp(doc, "normalize")))
    assert "DUPLICATE_ID" in codes(check(doc))


def test_properties_exact_and_allowable():
    doc = plan("json_field_gate")
    comp(doc, "extract")["properties"]["Return Type"] = "xml"
    assert "INVALID_VALUE" in codes(check(doc))
    doc = plan("json_field_gate")
    comp(doc, "extract")["properties"]["Destination"] = "flowfile-content"
    assert {"UNSUPPORTED_SETTING"} <= codes(check(doc))
    doc = plan()
    comp(doc, "route")["properties"] = {"Routing Strategy": "Route to Property name"}
    assert "NO_ROUTES" in codes(check(doc))
    doc = plan()
    comp(doc, "route")["properties"]["unmatched"] = "${x:equals('y')}"
    assert "RESERVED_ROUTE" in codes(check(doc))
    doc = plan()
    comp(doc, "route")["properties"]["bad name!"] = "${x}"
    assert "INVALID_DYNAMIC_NAME" in codes(check(doc))


def test_parameters_declared():
    doc = plan()
    comp(doc, "normalize")["properties"]["route.key"] = "#{undeclared}"
    assert "UNDECLARED_PARAMETER" in codes(check(doc))
    doc = plan()
    doc["parameter_references"] = [{"name": "unused.param", "sensitive": False}]
    r = check(doc)
    assert r["valid"] and any(w["code"] == "UNUSED_PARAMETER" for w in r["warnings"])


def test_every_relationship_connected_or_terminated():
    doc = plan()
    doc["connections"] = [c for c in doc["connections"] if c["relationship"] != "audit"]
    r = check(doc)
    assert "UNHANDLED_RELATIONSHIP" in codes(r) and "OUTPUT_PORT_UNCONNECTED" in codes(r)
    doc = plan()
    comp(doc, "route")["auto_terminated_relationships"] = ["unmatched"]
    assert "CONNECTED_AND_TERMINATED" in codes(check(doc))
    doc = plan()
    doc["connections"][1]["relationship"] = "sucess"
    assert "UNKNOWN_RELATIONSHIP" in codes(check(doc))
    doc = plan()
    doc["connections"][0]["relationship"] = "success"
    assert "PORT_RELATIONSHIP" in codes(check(doc))


def test_reachability_cycles_and_ports():
    doc = plan()
    doc["connections"].append({"id": "back", "source": "out_audit", "relationship": "port", "destination": "normalize"})
    r = check(doc)
    assert "OUTPUT_PORT_HAS_OUTPUT" in codes(r)
    doc = plan()
    doc["components"].append({"id": "orphan", "type_id": "org.apache.nifi.processors.attributes.UpdateAttribute",
                              "kind": "processor", "properties": {}, "auto_terminated_relationships": ["success"]})
    r = check(doc)
    assert {"PROCESSOR_UNREACHABLE", "UNREACHABLE"} <= codes(r)
    doc = plan()
    doc["connections"].append({"id": "loop", "source": "route", "relationship": "standard", "destination": "normalize"})
    assert "CYCLE" in codes(check(doc))


def test_blueprint_shape():
    doc = plan()
    doc["components"] = [c for c in doc["components"] if c["kind"] != "input_port"]
    doc["connections"] = [c for c in doc["connections"] if c["source"] != "in"]
    assert "BLUEPRINT_SHAPE" in codes(check(doc))


def test_expectations_reference_output_ports():
    doc = plan()
    doc["output_expectations"].append({"port_id": "route", "condition": "x"})
    assert "EXPECTATION_PORT" in codes(check(doc))
