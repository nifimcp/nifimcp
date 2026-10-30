"""The packaged demo runs with no NiFi, model or network and is deterministic apart from collection metadata."""
import json
import socket

import anyio

from nifimcp.cli import run_demo

VOLATILE = {"exported_at", "request_id", "created_at", "investigation_id", "age_seconds", "artifact_id",
            "collected_at", "next_cursor", "uri", "full_result_artifact_id",
            "fingerprint"}   # hidden-value labels are keyed per session by design


def scrub(value):
    if isinstance(value, dict):
        return {k: ("<volatile>" if k in VOLATILE else scrub(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [scrub(v) for v in value]
    return value


def test_demo_is_deterministic_and_offline(tmp_path, monkeypatch):
    def deny(*a, **k):
        raise AssertionError("network access attempted during demo")
    monkeypatch.setattr(socket.socket, "connect", deny)
    monkeypatch.setattr(socket, "create_connection", deny)
    a = anyio.run(run_demo, tmp_path / "a")
    b = anyio.run(run_demo, tmp_path / "b")
    ja = json.loads((tmp_path / "a/investigation.json").read_text())
    jb = json.loads((tmp_path / "b/investigation.json").read_text())
    assert scrub(ja["findings"]) == scrub(jb["findings"])
    assert scrub(ja["evidence"]) == scrub(jb["evidence"])
    assert ja["integrity"]["findings_sha256"] == jb["integrity"]["findings_sha256"]
    assert [t["status"] for t in a["tools"]] == [t["status"] for t in b["tools"]]
    assert all(t["status"] in ("ok", "partial") for t in a["tools"])
    assert [d["status"] for d in a["drafts"]] == ["ok", "ok"]
