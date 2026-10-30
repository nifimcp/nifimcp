"""A26/A27: reference drafts import into stock NiFi 2.12.0 and meet labeled output cases.

Includes a negative control: a deliberately wrong plan must FAIL the same cases, proving the
gate can detect misrouting even when the native import itself is valid.
"""
import copy
import json

import anyio
import pytest

from helpers import demo_session, run
from nifimcp.draft.examples import example_cases, example_plans

pytestmark = pytest.mark.lab


def compile_plan(svc, plan):
    env = run(svc, "draft_flow", {"plan": plan})
    assert env["status"] == "ok", env.get("error")
    return env["data"]["artifacts"]["native_flow_definition"]["artifact_id"]


@pytest.mark.parametrize("blueprint", ["attribute_router", "json_field_gate"])
def test_reference_draft_passes_natively(lab, tmp_path, blueprint):
    from nifimcp_lab.verify import run_verification
    svc = demo_session(tmp_path)
    plan = example_plans(svc.s.catalog["catalog_hash"])[blueprint]
    aid = compile_plan(svc, plan)
    result = run_verification(lab["dir"], svc.s.store.root, aid, cases=None, out_dir=tmp_path / "out")
    assert result["native_validation"]["status"] == "PASS"
    assert result["native_validation"]["fidelity"]["all_stopped"]
    assert result["cases"]["status"] == "PASS", [c for c in result["cases"]["cases"] if c["status"] != "PASS"]
    assert result["overall"] == "PASS"
    assert result["runtime"]["nifi_version"] == "2.12.0"
    assert len(result["cases"]["cases"]) == len(example_cases()[blueprint]["cases"])
    receipt = json.loads((tmp_path / "out" / "lab-receipt.json").read_text())
    assert receipt["kind"] == "native_lab_verification" and receipt["native_artifact_sha256"] == result["native_artifact_sha256"]


def test_wrong_plan_fails_even_though_it_imports(lab, tmp_path):
    from nifimcp_lab.verify import run_verification
    svc = demo_session(tmp_path)
    plan = copy.deepcopy(example_plans(svc.s.catalog["catalog_hash"])["attribute_router"])
    route = next(c for c in plan["components"] if c["id"] == "route")
    route["properties"]["standard"] = "${route.key:equals('standard')}"     # bug: forgets low and medium
    aid = compile_plan(svc, plan)
    result = run_verification(lab["dir"], svc.s.store.root, aid, cases=example_cases()["attribute_router"],
                              out_dir=tmp_path / "out")
    assert result["native_validation"]["status"] == "PASS"          # NiFi imports and validates it fine
    assert result["overall"] == "FAIL"
    failed = {c["case_id"] for c in result["cases"]["cases"] if c["status"] == "FAIL"}
    assert failed == {"ar-03-medium", "ar-04-low"}
