"""A25: the lab mutation client cannot target arbitrary origins; ownership and identity enforced."""
import ast
import copy
import json
from pathlib import Path

import pytest

from helpers import ROOT
from nifimcp_lab import boundary, dockerctl
from nifimcp_lab.boundary import LabBoundaryError, check_origin, validate_manifest_shape, verify_lab_target
from nifimcp_lab.client import LabClient

MANIFEST = {
    "schema": "nifimcp-lab-manifest/1", "lab_id": "lab-0123456789ab", "origin": "https://127.0.0.1:34567",
    "port": 34567, "container_name": "nifimcp-lab-0123456789ab", "container_id": "c" * 64,
    "image": {"digest": dockerctl.NIFI_IMAGE_DIGEST}, "pki": {"ca_path": "/nonexistent", "server_fingerprint_sha256": "f" * 64,
                                                             "identities": {}},
}
INFO = {"Id": "c" * 64, "Image": dockerctl.NIFI_IMAGE_DIGEST, "State": {"Running": True, "StartedAt": "x"},
        "Config": {"Labels": {dockerctl.LAB_LABEL: "lab-0123456789ab"}},
        "HostConfig": {"PortBindings": {"8443/tcp": [{"HostIp": "127.0.0.1", "HostPort": "34567"}]}}}


@pytest.mark.parametrize("origin,port", [("https://nifi.customer.example:8443", 8443), ("https://10.0.0.5:34567", 34567),
                                         ("http://127.0.0.1:34567", 34567), ("https://user:pw@127.0.0.1:34567", 34567),
                                         ("https://localhost:34567", 34567), ("https://127.0.0.1:34567/nifi", 34567),
                                         ("https://127.0.0.1:1", 34567)])
def test_only_exact_loopback_origins(origin, port):
    with pytest.raises(LabBoundaryError):
        check_origin(origin, port)


def test_manifest_required_and_strict(tmp_path):
    with pytest.raises(LabBoundaryError):
        boundary.load_manifest(tmp_path)
    for key in ("schema", "lab_id", "container_id"):
        bad = dict(MANIFEST)
        bad[key] = "x"
        with pytest.raises(LabBoundaryError):
            validate_manifest_shape(bad)


@pytest.mark.parametrize("mutate", [
    lambda i: i.update(Id="d" * 64),
    lambda i: i["Config"]["Labels"].update({dockerctl.LAB_LABEL: "lab-ffffffffffff"}),
    lambda i: i.update(Image="sha256:" + "0" * 64),
    lambda i: i["State"].update(Running=False),
    lambda i: i["HostConfig"]["PortBindings"].update({"8443/tcp": [{"HostIp": "0.0.0.0", "HostPort": "34567"}]}),
])
def test_container_identity_enforced(monkeypatch, mutate):
    info = copy.deepcopy(INFO)
    mutate(info)
    monkeypatch.setattr(dockerctl, "inspect_container", lambda name: info)
    with pytest.raises(LabBoundaryError):
        verify_lab_target(MANIFEST, check_tls=False)


def test_missing_container_rejected(monkeypatch):
    monkeypatch.setattr(dockerctl, "inspect_container", lambda name: None)
    with pytest.raises(LabBoundaryError):
        verify_lab_target(MANIFEST, check_tls=False)


def test_tls_pin_enforced(monkeypatch):
    monkeypatch.setattr(dockerctl, "inspect_container", lambda name: copy.deepcopy(INFO))
    monkeypatch.setattr(boundary, "peer_fingerprint", lambda origin, ca: "0" * 64)
    with pytest.raises(LabBoundaryError):
        verify_lab_target(MANIFEST)
    monkeypatch.setattr(boundary, "peer_fingerprint", lambda origin, ca: "f" * 64)
    assert verify_lab_target(MANIFEST)["server_fingerprint_sha256"] == "f" * 64


def test_environment_variables_cannot_create_a_lab(tmp_path, monkeypatch):
    monkeypatch.setenv("NIFI_URL", "https://prod.example:8443")
    monkeypatch.setenv("NIFIMCP_LAB_ORIGIN", "https://prod.example:8443")
    with pytest.raises(LabBoundaryError):
        LabClient(tmp_path)


def test_lab_client_rejects_absolute_paths(monkeypatch, tmp_path):
    (tmp_path / "lab-manifest.json").write_text(json.dumps({**MANIFEST, "pki": {**MANIFEST["pki"], "identities": {
        "admin": {"cert_path": "x", "key_path": "y", "dn": "CN=a"}}}}))
    monkeypatch.setattr(boundary, "verify_lab_target", lambda m: {})
    import nifimcp_lab.client as client_mod
    monkeypatch.setattr(client_mod, "verify_lab_target", lambda m: {})
    monkeypatch.setattr(client_mod, "_ssl_context", lambda *a: None)
    c = LabClient(tmp_path)
    with pytest.raises(LabBoundaryError):
        c.request("GET", "https://prod.example:8443/nifi-api/flow/about")
    with pytest.raises(LabBoundaryError):
        c.request("GET", "flow/about")


def test_runtime_package_never_imports_lab_code():
    src = ROOT / "src" / "nifimcp"
    for path in src.rglob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names = [a.name for a in node.names] + [getattr(node, "module", "") or ""]
                assert not any(n.startswith("nifimcp_lab") for n in names), path
