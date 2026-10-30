"""A02: nested groups, all supported export wrappers, ports and remote references normalized."""
import json

import pytest

from helpers import NATIVE, connection, definition, group, processor, raw, sha, uid
from nifimcp.core import pointer as jp
from nifimcp.core.flowmodel import connection_endpoints, normalize


def _model(doc):
    data = raw(doc)
    return normalize(json.loads(data), source_id="t", source_hash=sha(data))


def nested_doc():
    inner = group("inner", "Inner", processors=[processor("p2", "Leaf")],
                  inputPorts=[{"identifier": "in1", "instanceIdentifier": uid("in1"), "name": "in", "type": "INPUT_PORT"}])
    rpg = {"identifier": "rpg1", "instanceIdentifier": uid("rpg1"), "name": "Remote", "targetUris": "https://remote.example.invalid/nifi",
           "inputPorts": [{"identifier": "rin", "name": "remote-in"}], "outputPorts": [{"identifier": "rout", "name": "remote-out"}]}
    root = group("root", "Root", processGroups=[inner], processors=[processor("p1", "Source")],
                 connections=[connection("c1", "p1", "in1", rels=("success",)), connection("c2", "rout", "p1", rels=())],
                 remoteProcessGroups=[rpg],
                 outputPorts=[{"identifier": "out1", "name": "out", "type": "OUTPUT_PORT", "customField": {"kept": True}}])
    return definition(root)


def test_native_stock_definition_normalizes_with_exact_pointers():
    data = NATIVE.read_bytes()
    doc = json.loads(data)
    model = normalize(doc, source_id="native", source_hash=sha(data))
    assert model.format == "flow_definition"
    kinds = sorted(c.kind for c in model.components)
    assert kinds.count("processor") == 3 and kinds.count("connection") == 5
    assert kinds.count("input_port") == 1 and kinds.count("output_port") == 2
    for comp in model.components:
        assert jp.resolve(doc, comp.key) is comp.raw
    # versioned identifiers and runtime instance identifiers are both indexed
    for comp in model.of_kind("processor"):
        assert model.find(comp.id) is comp and model.find(comp.instance_id) is comp
    for conn in model.of_kind("connection"):
        src, dst = connection_endpoints(model, conn)
        assert src is not None and dst is not None


def test_nested_groups_ports_and_remote_ports():
    model = _model(nested_doc())
    kinds = {c.id: c.kind for c in model.components}
    assert kinds["inner"] == "process_group" and kinds["p2"] == "processor"
    assert kinds["rin"] == "remote_input_port" and kinds["rout"] == "remote_output_port"
    leaf = model.find("p2")
    assert model.group_path(leaf) == ["Root", "Inner"]
    assert leaf.depth == 2
    conn = model.find("c1")
    src, dst = connection_endpoints(model, conn)
    assert src.id == "p1" and dst.id == "in1"
    src2, _ = connection_endpoints(model, model.find("c2"))
    assert src2.kind == "remote_output_port"


def test_unknown_fields_are_preserved():
    model = _model(nested_doc())
    assert model.find("out1").raw["customField"] == {"kept": True}


@pytest.mark.parametrize("wrapper", ["versioned_snapshot", "runtime_flow", "rest", "bare"])
def test_supported_wrappers(wrapper):
    root = group("root", "Root", processors=[processor("p1", "One")], connections=[])
    if wrapper == "versioned_snapshot":
        doc = definition(root, snapshotMetadata={"version": 3})
        fmt = "versioned_snapshot"
    elif wrapper == "runtime_flow":
        doc = {"encodingVersion": {"majorVersion": 2}, "rootGroup": root, "parameterContexts": [
            {"identifier": "ctx", "name": "ctx", "parameters": [{"name": "a", "sensitive": False, "value": "1"}]}]}
        fmt = "runtime_flow"
    elif wrapper == "rest":
        doc = {"processGroupFlow": {"id": uid("rest-root"), "breadcrumb": {"breadcrumb": {"name": "Rest Root"}},
                                    "flow": {"processors": [{"id": uid("rp1"), "component": {
                                        "id": uid("rp1"), "name": "Rest proc", "type": "x.Y",
                                        "config": {"properties": {"k": "v"}, "autoTerminatedRelationships": ["failure"]}}}],
                                        "processGroups": [{"id": uid("child"), "component": {"id": uid("child"), "name": "Child"}}]}}}
        fmt = "rest_process_group_flow"
    else:
        doc = root
        fmt = "process_group"
    model = _model(doc)
    assert model.format == fmt
    assert any(c.kind == "processor" for c in model.components)
    if wrapper == "rest":
        proc = model.find(uid("rp1"))
        assert proc.key.endswith("/component")
        props, ptr = proc.properties()
        assert props == {"k": "v"} and ptr.endswith("/config/properties")
        assert any(g["code"] == "CHILD_GROUP_CONTENTS_NOT_INCLUDED" for g in model.gaps)
    if wrapper == "runtime_flow":
        assert "ctx" in model.contexts


def test_parameter_inheritance_resolves_and_unresolved_stays_unresolved():
    root = group("root", "Root", processors=[processor("p1", properties={"a": "#{base.host}", "b": "#{missing}"})],
                 parameterContextName="child")
    doc = definition(root, parameterContexts={
        "child": {"name": "child", "parameters": [{"name": "local", "sensitive": False}],
                  "inheritedParameterContexts": ["base"]},
        "base": {"name": "base", "parameters": [{"name": "base.host", "sensitive": False, "value": "h"}]}})
    model = _model(doc)
    params = model.resolve_parameters(model.parameter_context_for(model.find("p1")))
    assert set(params) == {"local", "base.host"}
    assert "missing" not in params
