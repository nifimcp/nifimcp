"""Fixtures for tests against the owned, disposable, secure stock NiFi 2.12.0 lab.

These tests are marked ``integration``. If no lab exists they are SKIPPED, and the
acceptance runner records the corresponding gates as BLOCKED (never PASS).
Resume: uv run python scripts/lab_bootstrap.py --create-owned-lab
"""
from __future__ import annotations

import json
import ssl
import time
from pathlib import Path

import anyio
import httpx2
import pytest

ROOT = Path(__file__).resolve().parents[1]
LAB_ROOT = ROOT / ".lab"


def _lab_dir() -> Path | None:
    marker = LAB_ROOT / "CURRENT"
    if not marker.is_file():
        return None
    path = LAB_ROOT / marker.read_text().strip()
    return path if (path / "lab-manifest.json").is_file() else None


@pytest.fixture(scope="session")
def lab():
    lab_dir = _lab_dir()
    if lab_dir is None:
        pytest.skip("BLOCKED: no owned lab; run scripts/lab_bootstrap.py --create-owned-lab")
    from nifimcp_lab.boundary import load_manifest, verify_lab_target
    manifest = load_manifest(lab_dir)
    try:
        verify_lab_target(manifest)
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"BLOCKED: lab not reachable ({type(exc).__name__}); recreate with scripts/lab_bootstrap.py")
    from nifimcp_lab.fixtures import write_operator_configs
    write_operator_configs(lab_dir)
    return {"dir": lab_dir, "manifest": manifest, "fx": manifest["fixtures"]}


@pytest.fixture(scope="session")
def admin(lab):
    from nifimcp_lab.client import LabClient
    client = LabClient(lab["dir"])
    yield client
    client.close()


@pytest.fixture(scope="session")
def fresh_activity(lab, admin):
    """Lab-only setup: run the synthetic sources briefly so bulletins (kept ~5 minutes by NiFi),
    provenance and queues are recent. Uses the separate lab client, never NiFiMCP."""
    from nifimcp_lab.fixtures import refresh_activity
    refresh_activity(admin)
    return time.time()


def identity_client(lab, name: str) -> httpx2.Client:
    ident = lab["manifest"]["pki"]["identities"][name]
    ctx = ssl.create_default_context(cafile=lab["manifest"]["pki"]["ca_path"])
    ctx.load_cert_chain(ident["cert_path"], ident["key_path"])
    return httpx2.Client(base_url=lab["manifest"]["origin"] + "/nifi-api", verify=ctx, trust_env=False,
                         follow_redirects=False, timeout=20)


def service_for(lab, name: str, tmp_path: Path, **limits):
    from nifimcp.config import load_config
    from nifimcp.service import Service, Session
    cfg_path = lab["dir"] / f"operator.{name}.json"
    data = json.loads(cfg_path.read_text())
    data["artifact_dir"] = str(tmp_path / f"art-{name}")
    if limits:
        data["limits"] = {**data.get("limits", {}), **limits}
    path = tmp_path / f"operator.{name}.json"
    path.write_text(json.dumps(data))
    return Service(Session(load_config(path)))


class Recorder:
    """Wraps NiFiHTTP.call to record every request NiFiMCP sends (method, endpoint id, params)."""

    def __init__(self, service):
        self.calls = []
        http = service.s.source.http
        original = http.call

        async def call(endpoint, **kw):
            entry = http.allowlist[endpoint]
            self.calls.append((entry["method"], endpoint, json.dumps(kw.get("params") or {}, sort_keys=True)))
            return await original(endpoint, **kw)
        http.call = call
