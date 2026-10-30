"""A24: unsupported types, embedded secrets, external destinations and auto-start rejected."""
import copy

import pytest

from fakenifi import FakeNiFi, fake_service
from helpers import demo_session, run
from nifimcp.catalog import load_catalog
from nifimcp.draft.examples import example_plans

CAT = load_catalog()


def base():
    return copy.deepcopy(example_plans(CAT["catalog_hash"])["attribute_router"])


def normalize(doc):
    return next(c for c in doc["components"] if c["id"] == "normalize")


@pytest.mark.parametrize("type_id", ["org.apache.nifi.processors.script.ExecuteScript",
                                     "org.apache.nifi.processors.standard.InvokeHTTP",
                                     "org.apache.nifi.processors.standard.PutFile",
                                     "org.apache.nifi.processors.standard.ExecuteStreamCommand",
                                     "com.example.CustomProcessor"])
def test_unsupported_types_rejected(tmp_path, type_id):
    doc = base()
    normalize(doc)["type_id"] = type_id
    env = run(demo_session(tmp_path), "draft_flow", {"plan": doc})
    assert env["error"]["code"] == "VALIDATION_FAILED"
    assert any(e["code"] == "UNSUPPORTED_TYPE" for e in env["data"]["validation"]["errors"])


@pytest.mark.parametrize("key,value,code", [
    ("api.password", "hunter2-literal", "EMBEDDED_SECRET"),
    ("auth.header", "Bearer abcdefghijklmnopqrstuvwxyz", "EMBEDDED_SECRET"),
    ("target", "https://user:pw@collector.invalid/in", "EXTERNAL_URL"),
    ("target", "sftp://files.invalid/drop", "EXTERNAL_URL"),
    ("secret.token", "#{token}", "SENSITIVE_PARAMETER_IN_NONSENSITIVE_PROPERTY"),
])
def test_secrets_and_external_destinations_rejected(tmp_path, key, value, code):
    doc = base()
    normalize(doc)["properties"][key] = value
    if value == "#{token}":
        doc["parameter_references"] = [{"name": "token", "sensitive": True}]
    env = run(demo_session(tmp_path), "draft_flow", {"plan": doc})
    assert env["error"]["code"] == "VALIDATION_FAILED"
    assert code in {e["code"] for e in env["data"]["validation"]["errors"]}
    assert value not in str(env["error"])


def test_auto_start_rejected_by_contract(tmp_path):
    doc = base()
    doc["automatic_start"] = True
    env = run(demo_session(tmp_path), "draft_flow", {"plan": doc})
    assert env["error"]["code"] == "INVALID_ARGUMENT"


def test_limits_enforced_by_contract_and_code(tmp_path):
    doc = base()
    doc["components"] = doc["components"] + [dict(normalize(doc), id=f"x{i}") for i in range(20)]
    env = run(demo_session(tmp_path), "validate_flow_plan", {"plan": doc})
    assert env["error"]["code"] == "INVALID_ARGUMENT"


def test_draft_never_contacts_nifi_even_in_live_mode(tmp_path):
    fake = FakeNiFi()
    svc, _ = fake_service(tmp_path, fake)
    env = run(svc, "draft_flow", {"plan": base()})
    assert env["status"] == "ok"
    assert fake.requests == []


def test_secret_parameters_stay_unresolved_references(tmp_path):
    doc = base()
    doc["parameter_references"] = [{"name": "region", "sensitive": False}]
    normalize(doc)["properties"]["region"] = "#{region}"
    env = run(demo_session(tmp_path), "draft_flow", {"plan": doc})
    assert env["status"] == "ok"
    svc_art = env["data"]["artifacts"]["native_flow_definition"]["artifact_id"]
    svc = None
    import json
    from pathlib import Path
    native = json.loads(next(Path(tmp_path).rglob("flow-definition.json")).read_text())
    ctx = next(iter(native["parameterContexts"].values()))
    assert ctx["parameters"] == [{"name": "region", "description": "", "sensitive": False, "provided": False}]
    assert all("value" not in p for p in ctx["parameters"])
