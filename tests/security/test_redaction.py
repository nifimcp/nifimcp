"""A07: secret canaries absent from outputs, logs, reports, exceptions and bundle exports."""
import json
import logging

import anyio

from helpers import CANARIES, DEMO, definition, demo_info, demo_session, group, processor, run, write_bundle, bundle_session
from nifimcp.cli import run_demo
from nifimcp.core.redact import Redactor, scrub_text
from nifimcp.config import RedactionPolicy

EXTRA = ["CANARY-PARAM-VALUE-77", "CANARY-ATTR-VALUE-88", "CANARY-BULLETIN-PW-99", "CANARY-SENSITIVE-PROP-55"]


def _assert_clean(text: str, extra=()):
    for canary in [*CANARIES, *extra]:
        assert canary not in text, canary


def test_demo_bundle_really_contains_planted_canaries():
    raw = (DEMO / "telemetry-intake/flow-definition.json").read_text()
    assert sum(c in raw for c in CANARIES) == 3   # NiFi itself withheld the sensitive token (canary 0001)


def test_canaries_absent_from_every_demo_output_and_log(tmp_path, capsys, caplog):
    caplog.set_level(logging.DEBUG)
    summary = anyio.run(run_demo, tmp_path / "demo")
    captured = capsys.readouterr()
    _assert_clean(captured.out + captured.err + caplog.text)
    for name in ("report.html", "investigation.json", "transcript.json", "summary.json"):
        _assert_clean((tmp_path / "demo" / name).read_text())
    # every session artifact a tool can expose (reports, drafts, results) is clean;
    # raw registered inputs are excluded from MCP resource reads (tested in protocol suite)
    for path in (tmp_path / "demo" / "artifacts" / "sessions").rglob("*"):
        if path.is_file() and path.name not in ("flow.json",):
            _assert_clean(path.read_text(errors="replace"))
    assert summary["investigation_status"] in ("ok", "partial")


def test_every_tool_envelope_is_clean(tmp_path):
    svc = demo_session(tmp_path)
    info = demo_info()
    envs = [run(svc, "get_capabilities", {}),
            run(svc, "describe_flow", {"scope_id": info["scope"], "depth": 8}),
            run(svc, "get_flow_health", {"scope_id": info["scope"], "interval": info["interval"]}),
            run(svc, "trace_feed", {"scope_id": info["scope"], "interval": info["interval"],
                                    "selector": {"kind": "flowfile_uuid", "value": info["trace_flowfile_uuid"]}}),
            run(svc, "inspect_unmatched", {"connection_id": info["unmatched_connection_id"], "interval": info["interval"],
                                           "sample_metadata": True})]
    for env in envs:
        _assert_clean(json.dumps(env))
    masked = [e for env in envs for e in env["evidence"] if "properties" in e["facts"]]
    states = [v["state"] for e in masked for k, v in e["facts"]["properties"].items() if k in ("api.key", "X-Debug-Token")]
    assert states and set(states) == {"masked"}


def test_canaries_absent_from_exceptions(tmp_path):
    svc = demo_session(tmp_path)
    bad = run(svc, "describe_flow", {"scope_id": CANARIES[1]})
    _assert_clean(json.dumps(bad))
    bad2 = run(svc, "trace_feed", {"scope_id": "x", "selector": {"kind": "filename", "value": CANARIES[2]},
                                   "interval": {"start": "2026-01-01T00:00:00Z", "end": "2026-01-03T00:00:00Z"}})
    assert bad2["status"] == "error"
    _assert_clean(json.dumps(bad2))
    bad3 = run(svc, "describe_flow", {"scope_id": "ok", "unexpected": CANARIES[0]})
    assert bad3["error"]["code"] == "INVALID_ARGUMENT"
    _assert_clean(json.dumps(bad3))


def test_bundle_with_all_secret_shapes(tmp_path):
    proc = processor("p1", "Leaky", properties={
        "Password": "CANARY-SENSITIVE-PROP-55",
        "url": "https://user:DEMO-CANARY-USERINFO-0004@h.invalid/x",
        "plain": "keep-me",
    }, propertyDescriptors={"Password": {"name": "Password", "sensitive": True, "dynamic": False}})
    root = group("root", "Root", processors=[proc], parameterContextName="ctx")
    doc = definition(root, parameterContexts={"ctx": {"name": "ctx", "parameters": [
        {"name": "secret.thing", "sensitive": True, "value": "CANARY-PARAM-VALUE-77"},
        {"name": "public.thing", "sensitive": False, "value": "CANARY-PARAM-VALUE-77"}]}})
    status = {"collection": {}, "response": {"processGroupStatus": {"aggregateSnapshot": {"id": root["instanceIdentifier"],
              "processorStatusSnapshots": [], "connectionStatusSnapshots": []}}}}
    bulletins = {"collection": {}, "response": {"bulletinBoard": {"bulletins": [{"canRead": True, "bulletin": {
        "sourceId": proc["instanceIdentifier"], "groupId": root["instanceIdentifier"], "level": "ERROR",
        "message": "login failed password=CANARY-BULLETIN-PW-99 token: DEMO-CANARY-BEARER-TOKEN-00000003",
        "timestampIso": "2026-10-29T01:30:00.000Z"}}]}}}
    prov = {"collection": {}, "response": {"provenance": {"results": {"total": "1", "provenanceEvents": [{
        "id": "1", "eventId": 1, "eventTimestamp": "2026-10-29T01:30:00.000Z", "eventType": "SEND",
        "flowFileUuid": "6ae1e6de-d4a6-4f88-be99-5ac47c13e079", "groupId": root["instanceIdentifier"],
        "componentId": proc["instanceIdentifier"], "transitUri": "https://u:DEMO-CANARY-USERINFO-0004@dest.invalid/in",
        "attributes": [{"name": "secret.attr", "value": "CANARY-ATTR-VALUE-88"}, {"name": "filename", "value": "f.json"}]}]}}}}
    window = {"start": "2026-10-29T01:00:00Z", "end": "2026-10-29T02:00:00Z"}
    folder = write_bundle(tmp_path / "b", doc, extra_files={"status.json": ("status", status, None),
                                                           "bulletins.json": ("bulletins", bulletins, None),
                                                           "prov.json": ("provenance", prov, window)})
    svc = bundle_session(tmp_path, folder)
    envs = [run(svc, "describe_flow", {"scope_id": "test-scope"}),
            run(svc, "get_flow_health", {"scope_id": "test-scope", "interval": window}),
            run(svc, "trace_feed", {"scope_id": "test-scope", "interval": window,
                                    "selector": {"kind": "flowfile_uuid", "value": "6ae1e6de-d4a6-4f88-be99-5ac47c13e079"}})]
    text = json.dumps(envs)
    _assert_clean(text, EXTRA)
    assert "keep-me" in text
    exp = run(svc, "export_investigation", {"investigation_id": envs[0]["data"]["investigation_id"], "format": "html"})
    _, html = svc.s.store.read_bytes(exp["data"]["artifact"]["artifact_id"], svc.s.session_id)
    _assert_clean(html.decode(), EXTRA)
    exp2 = run(svc, "export_investigation", {"investigation_id": envs[0]["data"]["investigation_id"], "format": "json"})
    _, js = svc.s.store.read_bytes(exp2["data"]["artifact"]["artifact_id"], svc.s.session_id)
    _assert_clean(js.decode(), EXTRA)


def test_scrubber_patterns():
    for text in ("https://a:b@host/x", "password=hunter2", "Authorization: Bearer abcdefghijklmnop",
                 'api_key: "zzzzzz"', "token=abc123"):
        out, changed = scrub_text(text)
        assert changed, text
    out, changed = scrub_text("${route.key:equals('critical')}")
    assert not changed and out == "${route.key:equals('critical')}"


def test_attribute_allowlist_is_exact():
    r = Redactor(RedactionPolicy(attribute_allowlist=["status"]))
    kept = r.attributes([{"name": "status", "value": "ok"}, {"name": "status2", "value": "no"},
                         {"name": "password", "value": "no"}])
    assert kept == {"status": "ok"}
    assert r.ledger.omitted_fields["attribute_values_not_allowlisted"] == 2


def test_hidden_value_fingerprints_are_session_keyed():
    """A fingerprint correlates equal hidden values within a session but cannot confirm a guess across sessions."""
    from nifimcp.core.redact import fingerprint
    a, b = Redactor(RedactionPolicy(), b"k" * 32), Redactor(RedactionPolicy(), b"j" * 32)
    assert a.filename("orders-0001.json") == a.filename("orders-0001.json")
    assert a.filename("orders-0001.json") != b.filename("orders-0001.json")
    import hashlib
    plain = hashlib.sha256(b"orders-0001.json").hexdigest()[:16]
    assert plain not in a.filename("orders-0001.json")["fingerprint"]
    assert fingerprint("x", b"k" * 32).startswith("hmac:")


def test_common_url_credentials_are_masked():
    from nifimcp.core.redact import scrub_text
    cases = {
        "https://acct.blob.core.windows.net/c/b?sv=2022-11-02&sig=abcDEF123%2Bxyz&sp=r": "abcDEF123",
        "https://b.s3.amazonaws.com/o?X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F2026&X-Amz-Signature=deadbeef1234": "deadbeef",
        "https://hooks.slack.com/services/T000/B000/XXXXXXXXXXXXXXXX": "XXXXXXXXXXXXXXXX",
        "https://maps.googleapis.com/maps/api?key=AIzaSyA1234567890abcdefghijklmnopqrstu": "AIzaSyA",
        "token ghp_abcdefghijklmnopqrstuvwxyz0123456789": "ghp_abc",
    }
    for text, secret in cases.items():
        out, changed = scrub_text(text, opaque=False)
        assert changed and secret not in out, text
    assert scrub_text("https://example.com/api?page=2&limit=10") == ("https://example.com/api?page=2&limit=10", False)


def test_expression_and_parameter_references_are_not_masked():
    from nifimcp.core.redact import scrub_text
    for text in ("https://x/api?key=${route.key}&code=${status.code}", "https://x?token=#{api.token}",
                 "token: ${secret.ref}"):
        assert scrub_text(text) == (text, False), text
    for text, secret in (("https://discord.com/api/webhooks/123/abcDEF_ghi", "abcDEF"),
                         ("https://acme.webhook.office.com/webhookb2/abc@def/IncomingWebhook/xyz", "IncomingWebhook"),
                         ("token glpat-abcdefghijklmnopqrstuv", "glpat-abc"), ("password=hunter2", "hunter2")):
        out, changed = scrub_text(text)
        assert changed and secret not in out, text
