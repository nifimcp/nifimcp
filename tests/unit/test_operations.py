"""Operational behavior: registration, artifact rotation, size limits, default windows and CLI exit codes."""
import json

import anyio
import pytest

from helpers import DEMO, bundle_session, demo_info, demo_session, run
from nifimcp.artifacts import ArtifactStore
from nifimcp.cli import main
from nifimcp.config import LiveConfig, OperatorConfig
from nifimcp.errors import NiFiMCPError
from nifimcp.limits import MAX_RAW_OBSERVATIONS_PER_SESSION
from nifimcp.service import register_input

BUNDLE = DEMO / "telemetry-intake"


def _bundle_config(tmp_path, **extra):
    return OperatorConfig.model_validate({"schema_version": "1", "mode": "bundle", "artifact_dir": str(tmp_path / "art"),
                                          "base_dir": str(tmp_path), **extra})


def test_registering_the_same_bundle_twice_is_idempotent(tmp_path):
    cfg = _bundle_config(tmp_path)
    store = ArtifactStore(cfg.artifact_path, cfg.retention_days)
    first = register_input(cfg, store, BUNDLE, "bundle", "a")
    second = register_input(cfg, store, BUNDLE, "bundle", "b")
    assert first.artifact_id == second.artifact_id
    assert len(store.operator_records("bundle")) == 1


def test_a_different_bundle_for_the_same_scope_is_refused_with_a_fix(tmp_path):
    cfg = _bundle_config(tmp_path)
    store = ArtifactStore(cfg.artifact_path, cfg.retention_days)
    rec = register_input(cfg, store, BUNDLE, "bundle", "a")
    changed = tmp_path / "changed"
    changed.mkdir()
    for f in BUNDLE.iterdir():
        (changed / f.name).write_bytes(f.read_bytes())
    notes = json.loads((changed / "operator-notes.json").read_text())
    (changed / "operator-notes.json").write_text(json.dumps(notes) + " ")
    manifest = json.loads((changed / "manifest.json").read_text())
    import hashlib
    for entry in manifest["files"]:
        data = (changed / entry["path"]).read_bytes()
        entry["sha256"], entry["bytes"] = hashlib.sha256(data).hexdigest(), len(data)
    (changed / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(NiFiMCPError) as exc:
        register_input(cfg, store, changed, "bundle", "b")
    assert rec.artifact_id in exc.value.message and "unregister" in exc.value.next_step
    store.unregister(rec.artifact_id)
    assert register_input(cfg, store, changed, "bundle", "b").artifact_id != rec.artifact_id


def test_cli_register_unregister_and_exit_codes(tmp_path, capsys):
    cfg = tmp_path / "op.json"
    cfg.write_text(json.dumps({"schema_version": "1", "mode": "bundle", "artifact_dir": str(tmp_path / "art")}))
    assert main(["register", "--config", str(cfg), "--kind", "bundle", str(BUNDLE)]) == 0
    aid = json.loads(capsys.readouterr().out)["registered"]["artifact_id"]
    assert main(["report", "--config", str(cfg), "--scope", "demo-telemetry-intake",
                 "--output", str(tmp_path / "r.html")]) == 0
    assert (tmp_path / "r.html").is_file()
    assert main(["report", "--config", str(cfg), "--scope", "unknown-scope", "--output", str(tmp_path / "x.html")]) == 2
    assert not (tmp_path / "x.html").exists()
    assert main(["investigate", "--config", str(cfg), "--scope", "unknown-scope"]) == 2
    assert main(["unregister", "--config", str(cfg), aid]) == 0
    capsys.readouterr()
    assert main(["catalog", "--type", "RouteOnAttribute"]) == 0
    assert [e["type_id"].rsplit(".", 1)[-1] for e in json.loads(capsys.readouterr().out)["entries"]] == ["RouteOnAttribute"]


def test_bundle_default_window_ends_at_collection_time(tmp_path):
    svc = bundle_session(tmp_path, BUNDLE)
    env = run(svc, "get_flow_health", {"scope_id": demo_info()["scope"]})
    gaps = {g["code"] for g in env["gaps"]}
    assert "STATUS_OUTSIDE_INTERVAL" not in gaps
    assert any(f["finding_id"].startswith("OBS-BULLETINS") for f in env["findings"])
    assert env["data"]["interval"]["defaulted"] is True


def test_raw_observations_rotate_instead_of_exhausting_the_session(tmp_path):
    store = ArtifactStore(tmp_path / "art", 30)
    for i in range(MAX_RAW_OBSERVATIONS_PER_SESSION + 25):
        store.put("ses_x", "raw_observation", b"{}", filename=f"r{i}.json", media_type="application/json")
    raws = [r for r in store.listing("ses_x") if r["kind"] == "raw_observation"]
    assert len(raws) == MAX_RAW_OBSERVATIONS_PER_SESSION
    store.put("ses_x", "result", b"{}", filename="result.json", media_type="application/json")


def test_raw_observations_can_be_switched_off(tmp_path):
    cfg = OperatorConfig.model_validate({"schema_version": "1", "mode": "demo", "artifact_dir": str(tmp_path / "a"),
                                         "keep_raw_observations": False})
    assert cfg.keep_raw_observations is False


@pytest.mark.parametrize("tool,args", [("get_processor_catalog", {}), ("get_capabilities", {})])
def test_result_size_limit_applies_to_every_tool(tmp_path, tool, args):
    svc = demo_session(tmp_path, limits={"maximum_result_bytes": 4096})
    env = run(svc, tool, args)
    assert len(json.dumps(env, separators=(",", ":"), sort_keys=True).encode()) <= 4096
    if tool == "get_processor_catalog":   # larger than the limit, so it must be trimmed, not sent whole
        assert any(g["code"] == "RESULT_TRUNCATED" for g in env["gaps"])


def test_ipv6_origin_keeps_brackets(tmp_path):
    live = LiveConfig.model_validate({
        "origin": "https://[::1]:8443", "ca_file": "ca.pem",
        "auth": {"kind": "client_certificate", "cert_file": "c.pem", "key_file": "k.pem"},
        "scopes": [{"scope_id": "s", "process_group_id": "8576d8b1-01a1-1000-04e0-e29605fa7003"}]})
    assert live.origin == "https://[::1]:8443"
