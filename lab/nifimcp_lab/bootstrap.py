"""Create, inspect and destroy a disposable secure NiFi 2.12.0 lab."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import secrets
import shutil
import socket
import ssl
import sys
import tempfile
import time
from pathlib import Path

import httpx2

from . import LAB_VERSION, dockerctl
from .boundary import MANIFEST_NAME, MANIFEST_SCHEMA, LabBoundaryError, load_manifest, verify_lab_target
from .pki import create_lab_pki

CONTAINER_KEYSTORE = "/opt/nifi/nifi-current/conf/lab-pki/keystore.p12"
CONTAINER_TRUSTSTORE = "/opt/nifi/nifi-current/conf/lab-pki/truststore.p12"


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def log(msg: str) -> None:
    print(f"[lab] {msg}", file=sys.stderr, flush=True)


def _write_json_private(path: Path, value) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")


def _build_truststore(pki_dir: Path, password: str) -> Path:
    """Use keytool from the pinned NiFi image so the host needs no Java."""
    staging = Path(tempfile.mkdtemp(prefix="nifimcp-trust-"))
    try:
        shutil.copy(pki_dir / "ca.pem", staging / "ca.pem")
        os.chmod(staging, 0o777)
        os.chmod(staging / "ca.pem", 0o644)
        dockerctl.docker(
            "run", "--rm", "--network", "none", "--entrypoint", "keytool",
            "-v", f"{staging}:/work", dockerctl.NIFI_IMAGE_REF,
            "-importcert", "-noprompt", "-alias", "nifimcp-lab-ca", "-file", "/work/ca.pem",
            "-keystore", "/work/truststore.p12", "-storetype", "PKCS12", "-storepass", password,
            timeout=300,
        )
        target = pki_dir / "truststore.p12"
        shutil.copy(staging / "truststore.p12", target)
        os.chmod(target, 0o600)
        return target
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def _wait_ready(origin: str, ca: str, cert: str, key: str, timeout: float = 420.0) -> dict:
    ctx = ssl.create_default_context(cafile=ca)
    ctx.load_cert_chain(cert, key)
    deadline = time.monotonic() + timeout
    last = ""
    with httpx2.Client(base_url=origin + "/nifi-api", verify=ctx, trust_env=False,
                       follow_redirects=False, timeout=10.0) as client:
        while time.monotonic() < deadline:
            try:
                resp = client.get("/flow/about")
                if resp.status_code == 200:
                    return resp.json()
                last = f"HTTP {resp.status_code}"
            except httpx2.HTTPError as exc:
                last = type(exc).__name__
            time.sleep(3)
    raise TimeoutError(f"NiFi did not become ready ({last})")


def create_owned_lab(lab_root: Path, *, heap: str = "1536m") -> Path:
    ok, version = dockerctl.daemon_available()
    if not ok:
        raise RuntimeError(f"Docker daemon unavailable: {version}")
    image = dockerctl.ensure_image()
    lab_id = "lab-" + secrets.token_hex(6)
    lab_dir = Path(lab_root).resolve() / lab_id
    lab_dir.mkdir(parents=True, exist_ok=False)
    os.chmod(lab_dir, 0o700)
    port = _free_port()
    origin = f"https://127.0.0.1:{port}"
    container_name = f"nifimcp-{lab_id}"
    store_password = secrets.token_urlsafe(24)
    sensitive_key = secrets.token_urlsafe(24)
    log(f"creating {lab_id} on {origin}")
    pki = create_lab_pki(lab_dir / "pki", server_sans=["127.0.0.1", "localhost", container_name],
                         store_password=store_password)
    _build_truststore(lab_dir / "pki", store_password)
    _write_json_private(lab_dir / "secrets.json", {"store_password": store_password,
                                                   "sensitive_props_key": sensitive_key})
    env = {
        "AUTH": "tls",
        "KEYSTORE_PATH": CONTAINER_KEYSTORE, "KEYSTORE_TYPE": "PKCS12", "KEYSTORE_PASSWORD": store_password,
        "TRUSTSTORE_PATH": CONTAINER_TRUSTSTORE, "TRUSTSTORE_TYPE": "PKCS12", "TRUSTSTORE_PASSWORD": store_password,
        "INITIAL_ADMIN_IDENTITY": pki["identities"]["admin"]["dn"],
        "NIFI_WEB_HTTPS_PORT": "8443",
        "NIFI_WEB_HTTPS_HOST": "0.0.0.0",
        "NIFI_WEB_PROXY_HOST": f"127.0.0.1:{port},localhost:{port}",
        "NIFI_SENSITIVE_PROPS_KEY": sensitive_key,
        "NIFI_JVM_HEAP_INIT": "768m", "NIFI_JVM_HEAP_MAX": heap,
    }
    # Pass secrets through an env file readable only by the current user.
    env_file = lab_dir / "container.env"
    fd = os.open(env_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        for k, v in env.items():
            handle.write(f"{k}={v}\n")
    container_id = dockerctl.docker(
        "create", "--name", container_name, "--hostname", container_name,
        "--label", f"{dockerctl.LAB_LABEL}={lab_id}",
        "--env-file", str(env_file),
        "-p", f"127.0.0.1:{port}:8443",
        "--security-opt", "no-new-privileges:true", "--cap-drop", "ALL",
        "--pids-limit", "2048", "--memory", "3g",
        dockerctl.NIFI_IMAGE_REF,
    ).strip()
    os.remove(env_file)
    staging = Path(tempfile.mkdtemp(prefix="nifimcp-pki-"))
    try:
        (staging / "lab-pki").mkdir()
        for name in ("keystore.p12", "truststore.p12"):
            shutil.copy(lab_dir / "pki" / name, staging / "lab-pki" / name)
            os.chmod(staging / "lab-pki" / name, 0o644)  # password-protected stores; container user must read
        os.chmod(staging / "lab-pki", 0o755)
        dockerctl.docker("cp", str(staging / "lab-pki"), f"{container_id}:/opt/nifi/nifi-current/conf/")
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    manifest = {
        "schema": MANIFEST_SCHEMA,
        "lab_version": LAB_VERSION,
        "lab_id": lab_id,
        "created_at": _now(),
        "origin": origin,
        "port": port,
        "container_name": container_name,
        "container_id": container_id,
        "image": image,
        "pki": {k: v for k, v in pki.items() if k != "keystore_path"},
        "fixtures": {},
        "owned_group_ids": [],
        "notes": "Disposable synthetic lab. Never point this tooling at a non-lab NiFi.",
    }
    _write_json_private(lab_dir / MANIFEST_NAME, manifest)
    dockerctl.docker("start", container_id)
    log("container started; waiting for NiFi to accept mutual-TLS requests")
    admin = pki["identities"]["admin"]
    about = _wait_ready(origin, pki["ca_path"], admin["cert_path"], admin["key_path"])
    facts = verify_lab_target(manifest)
    java = dockerctl.docker("exec", container_id, "java", "-version", check=False)
    java_version = dockerctl.docker("exec", container_id, "sh", "-c", "java -version 2>&1 | head -3").strip()
    manifest["runtime"] = {
        "nifi_about": about.get("about", {}),
        "java_version": java_version or java.strip(),
        "boundary_facts": facts,
        "verified_at": _now(),
    }
    _write_json_private(lab_dir / MANIFEST_NAME, manifest)
    (Path(lab_root).resolve() / "CURRENT").write_text(lab_id + "\n")
    log(f"lab ready: NiFi {about.get('about', {}).get('version')}")
    return lab_dir


def current_lab_dir(lab_root: Path) -> Path:
    marker = Path(lab_root).resolve() / "CURRENT"
    if not marker.is_file():
        raise LabBoundaryError("no current lab; run scripts/lab_bootstrap.py --create-owned-lab")
    lab_id = marker.read_text().strip()
    return Path(lab_root).resolve() / lab_id


def destroy_lab(lab_dir: Path) -> None:
    manifest = load_manifest(lab_dir)
    verify_lab_target(manifest, check_tls=False)
    dockerctl.docker("rm", "-f", manifest["container_id"])
    log(f"removed container for {manifest['lab_id']}")


def manifest_digest(lab_dir: Path) -> str:
    return hashlib.sha256((Path(lab_dir) / MANIFEST_NAME).read_bytes()).hexdigest()
