"""A10: bad CA, hostname, redirect, userinfo and unapproved origin rejected.

Uses real local TLS servers (no mocks) so certificate and hostname verification
are exercised end to end.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import json
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import anyio
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from pydantic import ValidationError

from nifimcp.config import OperatorConfig
from nifimcp.errors import NiFiMCPError
from nifimcp.live.http import NiFiHTTP

TOKEN = "TOKEN-CANARY-DO-NOT-ECHO-1234567890"


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _ca(cn):
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(_name(cn)).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(hours=1))
            .not_valid_after(now + dt.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True).sign(key, hashes.SHA256()))
    return key, cert


def _leaf(ca_key, ca_cert, sans):
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.timezone.utc)
    names = []
    for s in sans:
        try:
            names.append(x509.IPAddress(ipaddress.ip_address(s)))
        except ValueError:
            names.append(x509.DNSName(s))
    cert = (x509.CertificateBuilder().subject_name(_name(sans[0])).issuer_name(ca_cert.subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(hours=1))
            .not_valid_after(now + dt.timedelta(days=1)).add_extension(x509.SubjectAlternativeName(names), critical=False)
            .sign(ca_key, hashes.SHA256()))
    return key, cert


def _write(path: Path, key, cert):
    pem = serialization.Encoding.PEM
    path.with_suffix(".crt").write_bytes(cert.public_bytes(pem))
    path.with_suffix(".key").write_bytes(key.private_bytes(pem, serialization.PrivateFormat.PKCS8,
                                                           serialization.NoEncryption()))
    return path.with_suffix(".crt"), path.with_suffix(".key")


class Server:
    def __init__(self, cert, key, routes):
        self.hits = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                outer.hits.append(self.path)
                status, headers, body = routes.get(self.path, (404, {}, b"{}"))
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(cert), str(key))
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()


ABOUT = json.dumps({"about": {"version": "2.12.0", "uri": "https://127.0.0.1:1/evil"}}).encode()


@pytest.fixture
def pki(tmp_path):
    ca_key, ca_cert = _ca("Test CA")
    rogue_key, rogue_cert = _ca("Rogue CA")
    (tmp_path / "ca.pem").write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    good = _write(tmp_path / "good", *_leaf(ca_key, ca_cert, ["127.0.0.1", "localhost"]))
    wrong_host = _write(tmp_path / "wronghost", *_leaf(ca_key, ca_cert, ["other.invalid"]))
    rogue = _write(tmp_path / "rogue", *_leaf(rogue_key, rogue_cert, ["127.0.0.1"]))
    (tmp_path / "token").write_text(TOKEN)
    return {"dir": tmp_path, "good": good, "wrong_host": wrong_host, "rogue": rogue}


def config(pki, port, **live):
    return OperatorConfig.model_validate({
        "schema_version": "1", "mode": "live", "artifact_dir": str(pki["dir"] / "art"), "base_dir": str(pki["dir"]),
        "live": {"origin": f"https://127.0.0.1:{port}", "ca_file": str(pki["dir"] / "ca.pem"),
                 "auth": {"kind": "bearer_token_file", "token_file": str(pki["dir"] / "token")},
                 "scopes": [{"scope_id": "s", "process_group_id": "6ae1e6de-d4a6-4f88-be99-5ac47c13e079"}], **live}})


def call(cfg, endpoint="about"):
    async def go():
        http = NiFiHTTP(cfg)
        try:
            return await http.call(endpoint)
        finally:
            await http.aclose()
    return anyio.run(go)


def test_valid_chain_and_hostname_succeed_and_absolute_uris_are_not_followed(pki):
    srv = Server(*pki["good"], {"/nifi-api/flow/about": (200, {}, ABOUT)})
    try:
        resp = call(config(pki, srv.port))
        assert resp.data["about"]["version"] == "2.12.0"
        assert srv.hits == ["/nifi-api/flow/about"]
    finally:
        srv.close()


@pytest.mark.parametrize("which", ["rogue", "wrong_host"])
def test_bad_ca_and_hostname_rejected(pki, which):
    srv = Server(*pki[which], {"/nifi-api/flow/about": (200, {}, ABOUT)})
    try:
        with pytest.raises(NiFiMCPError) as err:
            call(config(pki, srv.port))
        assert err.value.code == "QUERY_FAILED"
        assert "TLS" in err.value.message or "connect" in err.value.message
        assert TOKEN not in err.value.message and TOKEN not in err.value.next_step
    finally:
        srv.close()


def test_redirect_refused_and_target_never_contacted(pki):
    target = Server(*pki["good"], {"/steal": (200, {}, b"{}")})
    srv = Server(*pki["good"], {"/nifi-api/flow/about": (302, {"Location": f"https://127.0.0.1:{target.port}/steal"}, b"")})
    try:
        with pytest.raises(NiFiMCPError) as err:
            call(config(pki, srv.port))
        assert "redirect" in err.value.message
        assert target.hits == []
    finally:
        srv.close()
        target.close()


def test_ambient_proxy_settings_are_ignored(pki, monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("https_proxy", "http://127.0.0.1:9")
    monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:9")
    srv = Server(*pki["good"], {"/nifi-api/flow/about": (200, {}, ABOUT)})
    try:
        assert call(config(pki, srv.port)).status == 200
    finally:
        srv.close()


@pytest.mark.parametrize("origin", ["http://127.0.0.1:8443", "https://user:pw@127.0.0.1:8443",
                                    "https://127.0.0.1:8443/nifi", "https://127.0.0.1:8443?x=1", "ftp://127.0.0.1",
                                    "https://127.0.0.1:8443#frag"])
def test_unapproved_origin_shapes_rejected(pki, origin):
    with pytest.raises(ValidationError):
        OperatorConfig.model_validate({
            "schema_version": "1", "mode": "live", "artifact_dir": "a", "base_dir": str(pki["dir"]),
            "live": {"origin": origin, "ca_file": "ca.pem", "auth": {"kind": "bearer_token_file", "token_file": "t"},
                     "scopes": [{"scope_id": "s", "process_group_id": "6ae1e6de-d4a6-4f88-be99-5ac47c13e079"}]}})


def test_no_skip_tls_option_exists():
    from nifimcp.config import LiveConfig
    fields = set(LiveConfig.model_fields)
    assert not any(k in fields for k in ("verify", "insecure", "skip_tls", "verify_tls", "tls_verify"))
    with pytest.raises(ValidationError):
        LiveConfig.model_validate({"origin": "https://h:1", "ca_file": "c", "insecure": True,
                                   "auth": {"kind": "bearer_token_file", "token_file": "t"},
                                   "scopes": [{"scope_id": "s", "process_group_id": "6ae1e6de-d4a6-4f88-be99-5ac47c13e079"}]})
