"""Minimal Docker CLI wrapper for the disposable lab (fixed argument vectors, no shell)."""
from __future__ import annotations

import json
import shutil
import subprocess

# Pinned official image. Tag is informational; the digest is authoritative.
NIFI_IMAGE_TAG = "apache/nifi:2.12.0"
NIFI_IMAGE_DIGEST = "sha256:6f7f2840dbf178c6dd3fa13435b9b358f3be3c6fb7417de467a35a267f4d28ad"
NIFI_IMAGE_REF = f"apache/nifi@{NIFI_IMAGE_DIGEST}"
LAB_LABEL = "io.nifimcp.lab_id"


class DockerError(RuntimeError):
    pass


def docker(*args: str, check: bool = True, timeout: float = 600, input_bytes: bytes | None = None) -> str:
    exe = shutil.which("docker")
    if not exe:
        raise DockerError("docker CLI not found on PATH")
    proc = subprocess.run(
        [exe, *args], capture_output=True, timeout=timeout, input=input_bytes, check=False
    )
    if check and proc.returncode != 0:
        raise DockerError(f"docker {args[0]} failed: {proc.stderr.decode(errors='replace').strip()[:500]}")
    return proc.stdout.decode(errors="replace")


def daemon_available() -> tuple[bool, str]:
    try:
        out = docker("version", "--format", "{{.Server.Version}}", timeout=20)
        return True, out.strip()
    except (DockerError, subprocess.TimeoutExpired, OSError) as exc:
        return False, str(exc)


def ensure_image() -> dict:
    """Make the pinned image available locally and return its verified identity."""
    try:
        info = json.loads(docker("image", "inspect", NIFI_IMAGE_REF, timeout=60))[0]
    except DockerError:
        docker("pull", NIFI_IMAGE_REF, timeout=1800)
        info = json.loads(docker("image", "inspect", NIFI_IMAGE_REF, timeout=60))[0]
    image_id = info.get("Id")
    digests = info.get("RepoDigests") or []
    if not any(d.endswith(NIFI_IMAGE_DIGEST) for d in digests) and image_id != NIFI_IMAGE_DIGEST:
        raise DockerError("local image does not match the pinned digest")
    return {
        "reference": NIFI_IMAGE_REF,
        "tag": NIFI_IMAGE_TAG,
        "digest": NIFI_IMAGE_DIGEST,
        "image_id": image_id,
        "architecture": info.get("Architecture"),
        "os": info.get("Os"),
    }


def inspect_container(name: str) -> dict | None:
    try:
        return json.loads(docker("container", "inspect", name, timeout=30))[0]
    except DockerError:
        return None
