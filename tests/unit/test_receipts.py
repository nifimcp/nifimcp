"""A29: edited artifact, plan, catalog or target invalidates the validation receipt."""
import copy
import json
import sys

import pytest

from helpers import ROOT, demo_session, run
from nifimcp.catalog import load_catalog
from nifimcp.draft.examples import example_plans
from nifimcp.draft.receipts import make_lab_receipt, verify_receipt

CAT = load_catalog()


def drafted(tmp_path):
    svc = demo_session(tmp_path)
    env = run(svc, "draft_flow", {"plan": example_plans(CAT["catalog_hash"])["attribute_router"]})
    data = env["data"]
    _, native = svc.s.store.read_bytes(data["artifacts"]["native_flow_definition"]["artifact_id"], svc.s.session_id)
    return svc, data, native


def test_receipt_binds_all_inputs(tmp_path):
    _, data, native = drafted(tmp_path)
    r = data["receipt"]
    ok = dict(plan_sha=data["plan_sha256"], native_bytes=native, catalog_hash=CAT["catalog_hash"], target_version="2.12.0")
    assert verify_receipt(r, **ok) == []
    assert "native artifact changed" in verify_receipt(r, **{**ok, "native_bytes": native + b" "})
    assert "plan changed" in verify_receipt(r, **{**ok, "plan_sha": "0" * 64})
    assert "catalog changed" in verify_receipt(r, **{**ok, "catalog_hash": "1" * 64})
    assert "target version changed" in verify_receipt(r, **{**ok, "target_version": "2.11.0"})
    edited = dict(r, validation_stage="native_validated")
    assert "receipt content was edited" in verify_receipt(edited, **ok)


def test_lab_receipt_binds_runtime(tmp_path):
    _, data, native = drafted(tmp_path)
    lab = make_lab_receipt(static_receipt=data["receipt"], native_bytes=native,
                           runtime={"nifi_version": "2.12.0", "image_digest": "sha256:abc"},
                           native_validation={"status": "PASS"}, cases={"status": "PASS"}, exported_definition_sha256=None)
    ok = dict(plan_sha=data["plan_sha256"], native_bytes=native, catalog_hash=CAT["catalog_hash"], target_version="2.12.0")
    assert verify_receipt(lab, **ok, runtime={"nifi_version": "2.12.0", "image_digest": "sha256:abc"}) == []
    assert "runtime image_digest changed" in verify_receipt(lab, **ok, runtime={"nifi_version": "2.12.0",
                                                                                 "image_digest": "sha256:other"})


def test_lab_verifier_refuses_edited_artifact_or_plan(tmp_path):
    sys.path.insert(0, str(ROOT / "lab"))
    from nifimcp_lab.verify import VerificationError, find_draft, run_verification
    svc, data, native = drafted(tmp_path)
    aid = data["artifacts"]["native_flow_definition"]["artifact_id"]
    found = find_draft(svc.s.store.root, aid)
    assert found["native_sha"] == data["native_artifact_sha256"]
    path = found["path"]
    path.write_bytes(native.replace(b'"route"', b'"r0ute"'))
    with pytest.raises(VerificationError):          # no receipt binds the edited bytes; fails before any lab use
        run_verification(tmp_path / "no-lab", svc.s.store.root, aid, cases=None)
    path.write_bytes(native)
    plan_path = next(p for p in svc.s.store.root.rglob("plan.json"))
    plan = json.loads(plan_path.read_text())
    plan["intent"] = plan["intent"] + " (edited)"
    plan_path.write_text(json.dumps(plan))
    with pytest.raises(VerificationError):
        find_draft(svc.s.store.root, aid)
