"""A23: different supported plans create different deterministic graphs; no canned substitution."""
import copy
import json

from helpers import NATIVE, demo_session, run
from nifimcp.catalog import load_catalog
from nifimcp.draft.compiler import build_native, native_bytes
from nifimcp.draft.examples import example_plans
from nifimcp.models import FlowPlan

CAT = load_catalog()


def compile_doc(doc):
    native, ids = build_native(FlowPlan.model_validate(doc), CAT)
    return native, ids, native_bytes(native)


def test_same_plan_same_bytes_and_uuids():
    doc = example_plans(CAT["catalog_hash"])["attribute_router"]
    a, ids_a, raw_a = compile_doc(doc)
    b, ids_b, raw_b = compile_doc(copy.deepcopy(doc))
    assert raw_a == raw_b and ids_a == ids_b


def test_different_plans_different_graphs():
    plans = example_plans(CAT["catalog_hash"])
    a = compile_doc(plans["attribute_router"])
    b = compile_doc(plans["json_field_gate"])
    assert a[2] != b[2]
    assert set(a[1].values()).isdisjoint(b[1].values())
    types_a = sorted(p["type"] for p in a[0]["flowContents"]["processors"])
    types_b = sorted(p["type"] for p in b[0]["flowContents"]["processors"])
    assert types_a != types_b


def test_compiled_graph_reflects_the_plan_exactly():
    doc = copy.deepcopy(example_plans(CAT["catalog_hash"])["attribute_router"])
    route = next(c for c in doc["components"] if c["id"] == "route")
    route["properties"]["priority"] = "${route.key:equals('p1')}"
    doc["components"].append({"id": "out_priority", "type_id": "nifi:OutputPort", "kind": "output_port",
                              "properties": {}, "auto_terminated_relationships": []})
    doc["connections"].append({"id": "c_prio", "source": "route", "relationship": "priority", "destination": "out_priority"})
    native, ids, _ = compile_doc(doc)
    fc = native["flowContents"]
    proc = next(p for p in fc["processors"] if p["name"] == "route")
    assert proc["properties"]["priority"] == "${route.key:equals('p1')}"
    assert proc["propertyDescriptors"]["priority"]["dynamic"] is True
    assert sorted(p["name"] for p in fc["outputPorts"]) == sorted(
        c["id"] for c in doc["components"] if c["kind"] == "output_port")
    rels = sorted(r for c in fc["connections"] for r in c["selectedRelationships"])
    assert rels == sorted(c["relationship"] for c in doc["connections"] if c["relationship"] != "port")
    for conn in fc["connections"]:
        endpoints = {conn["source"]["id"], conn["destination"]["id"]}
        assert endpoints <= set(ids.values())


def test_native_shape_matches_stock_export_fields():
    stock = json.loads(NATIVE.read_bytes())
    native, _, _ = compile_doc(example_plans(CAT["catalog_hash"])["attribute_router"])
    assert set(native) == set(stock)
    s_proc = stock["flowContents"]["processors"][0]
    n_proc = native["flowContents"]["processors"][0]
    assert set(n_proc) == set(s_proc) - {"instanceIdentifier"}
    assert set(native["flowContents"]["connections"][0]) >= set(stock["flowContents"]["connections"][0]) - {"instanceIdentifier"}
    assert all(p["scheduledState"] == "ENABLED" for p in native["flowContents"]["processors"])   # stopped on import


def test_draft_tool_outputs_and_artifacts(tmp_path):
    svc = demo_session(tmp_path)
    doc = example_plans(CAT["catalog_hash"])["json_field_gate"]
    env = run(svc, "draft_flow", {"plan": doc})
    data = env["data"]
    assert data["experimental"] is True and data["deployed"] is False and data["all_components_stopped"]
    assert set(data["artifacts"]) == {"native_flow_definition", "plan", "review_report", "validation_receipt"}
    _, raw = svc.s.store.read_bytes(data["artifacts"]["native_flow_definition"]["artifact_id"], svc.s.session_id)
    import hashlib
    assert hashlib.sha256(raw).hexdigest() == data["native_artifact_sha256"] == data["receipt"]["native_artifact_sha256"]
    _, review = svc.s.store.read_bytes(data["artifacts"]["review_report"]["artifact_id"], svc.s.session_id)
    assert b"NOT DEPLOYED" in review and b"<script" not in review.lower()
