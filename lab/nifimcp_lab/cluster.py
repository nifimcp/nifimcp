"""A disposable two-node secure NiFi 2.12.0 cluster (plus ZooKeeper) for topology qualification.

Node 1 is published on 127.0.0.1 and recorded in a standard lab manifest, so the usual boundary
checks (container identity, label, image digest, loopback binding, TLS pin) apply to every write.
Node 2 and ZooKeeper are reachable only on the lab's private Docker network. Both nodes share one
server certificate, so a single ``NODE_IDENTITY`` authorizes cluster traffic.
"""
from __future__ import annotations

import json
import os
import secrets
import shutil
import ssl
import tempfile
import time
from pathlib import Path

import httpx2

from . import LAB_VERSION, dockerctl
from .boundary import MANIFEST_NAME, MANIFEST_SCHEMA, load_manifest, verify_lab_target
from .bootstrap import (CONTAINER_KEYSTORE, CONTAINER_TRUSTSTORE, _build_truststore, _free_port, _now,
                        _wait_ready, _write_json_private, log)
from .pki import create_lab_pki

ZK_IMAGE_REF = "mirror.gcr.io/library/zookeeper@sha256:17d9b6af91d97ad4feec7b088102d34f1c42df52d6320fd794af5d01d48883a0"


def _env_file(path: Path, env: dict) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        for k, v in env.items():
            handle.write(f"{k}={v}\n")


def _copy_stores(lab_dir: Path, container_id: str) -> None:
    staging = Path(tempfile.mkdtemp(prefix="nifimcp-pki-"))
    try:
        (staging / "lab-pki").mkdir()
        for name in ("keystore.p12", "truststore.p12"):
            shutil.copy(lab_dir / "pki" / name, staging / "lab-pki" / name)
            os.chmod(staging / "lab-pki" / name, 0o644)
        os.chmod(staging / "lab-pki", 0o755)
        dockerctl.docker("cp", str(staging / "lab-pki"), f"{container_id}:/opt/nifi/nifi-current/conf/")
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def _seed_node_user(container_id: str, node_dn: str) -> None:
    """The image's secure.sh sets 'Node Identity 1' for the policy provider only. The node must also exist
    in the file user group provider, or NiFi refuses to start ("Unable to locate node ... to seed policies").
    Add it as 'Initial User Identity 2' before first start; secure.sh leaves non-empty properties alone."""
    conf = "/opt/nifi/nifi-current/conf/authorizers.xml"
    staging = Path(tempfile.mkdtemp(prefix="nifimcp-authz-"))
    try:
        dockerctl.docker("cp", f"{container_id}:{conf}", str(staging / "authorizers.xml"))
        text = (staging / "authorizers.xml").read_text(encoding="utf-8")
        anchor = '<property name="Initial User Identity 1"></property>'
        if text.count(anchor) != 1:
            raise RuntimeError("unexpected authorizers.xml layout in the pinned image")
        text = text.replace(anchor, anchor + f'\n        <property name="Initial User Identity 2">{node_dn}</property>')
        (staging / "authorizers.xml").write_text(text, encoding="utf-8")
        os.chmod(staging / "authorizers.xml", 0o644)
        dockerctl.docker("cp", str(staging / "authorizers.xml"), f"{container_id}:{conf}")
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def cluster_summary(manifest: dict, identity: str = "admin") -> dict:
    ident = manifest["pki"]["identities"][identity]
    ctx = ssl.create_default_context(cafile=manifest["pki"]["ca_path"])
    ctx.load_cert_chain(ident["cert_path"], ident["key_path"])
    with httpx2.Client(base_url=manifest["origin"] + "/nifi-api", verify=ctx, trust_env=False,
                       follow_redirects=False, timeout=15) as c:
        resp = c.get("/flow/cluster/summary")
        resp.raise_for_status()
        return resp.json()["clusterSummary"]


def wait_connected(manifest: dict, nodes: int, timeout: float = 600.0) -> dict:
    deadline = time.monotonic() + timeout
    last = {}
    while time.monotonic() < deadline:
        try:
            last = cluster_summary(manifest)
            if last.get("connectedNodeCount") == nodes and last.get("totalNodeCount", nodes) >= nodes:
                return last
        except httpx2.HTTPError as exc:
            last = {"error": type(exc).__name__}
        time.sleep(5)
    raise TimeoutError(f"cluster did not reach {nodes} connected node(s): {last}")


def create_cluster_lab(lab_root: Path, *, heap: str = "1g") -> Path:
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
    n1, n2, zk, net = (f"nifimcp-{lab_id}", f"nifimcp-{lab_id}-n2", f"nifimcp-{lab_id}-zk", f"nifimcp-{lab_id}-net")
    store_password, sensitive_key = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
    log(f"creating two-node cluster {lab_id}; node 1 on {origin}")
    pki = create_lab_pki(lab_dir / "pki", server_sans=["127.0.0.1", "localhost", n1, n2],
                         store_password=store_password)
    _build_truststore(lab_dir / "pki", store_password)
    _write_json_private(lab_dir / "secrets.json", {"store_password": store_password,
                                                   "sensitive_props_key": sensitive_key})
    label = f"{dockerctl.LAB_LABEL}={lab_id}"
    dockerctl.docker("network", "create", "--label", label, net)
    zk_id = dockerctl.docker("run", "-d", "--name", zk, "--hostname", zk, "--network", net, "--label", label,
                             "--memory", "512m", "--security-opt", "no-new-privileges:true",
                             "-e", "ZOO_4LW_COMMANDS_WHITELIST=ruok,srvr", ZK_IMAGE_REF, timeout=600).strip()
    node_ids = {}
    for name in (n1, n2):
        env = {
            "AUTH": "tls",
            "KEYSTORE_PATH": CONTAINER_KEYSTORE, "KEYSTORE_TYPE": "PKCS12", "KEYSTORE_PASSWORD": store_password,
            "TRUSTSTORE_PATH": CONTAINER_TRUSTSTORE, "TRUSTSTORE_TYPE": "PKCS12", "TRUSTSTORE_PASSWORD": store_password,
            "INITIAL_ADMIN_IDENTITY": pki["identities"]["admin"]["dn"],
            "NODE_IDENTITY": "CN=localhost",
            "NIFI_WEB_HTTPS_PORT": "8443", "NIFI_WEB_HTTPS_HOST": name,
            "NIFI_WEB_PROXY_HOST": f"127.0.0.1:{port},localhost:{port}",
            "NIFI_SENSITIVE_PROPS_KEY": sensitive_key,
            "NIFI_CLUSTER_IS_NODE": "true", "NIFI_CLUSTER_ADDRESS": name,
            "NIFI_CLUSTER_NODE_PROTOCOL_PORT": "11443", "NIFI_CLUSTER_LOAD_BALANCE_HOST": name,
            "NIFI_ZK_CONNECT_STRING": f"{zk}:2181",
            "NIFI_ELECTION_MAX_CANDIDATES": "2", "NIFI_ELECTION_MAX_WAIT": "1 min",
            "NIFI_JVM_HEAP_INIT": "512m", "NIFI_JVM_HEAP_MAX": heap,
        }
        env_path = lab_dir / "container.env"
        _env_file(env_path, env)
        args = ["create", "--name", name, "--hostname", name, "--network", net, "--label", label,
                "--env-file", str(env_path), "--security-opt", "no-new-privileges:true", "--cap-drop", "ALL",
                "--pids-limit", "2048", "--memory", "2g"]
        if name == n1:
            args += ["-p", f"127.0.0.1:{port}:8443"]
        node_ids[name] = dockerctl.docker(*args, dockerctl.NIFI_IMAGE_REF).strip()
        os.remove(env_path)
        _copy_stores(lab_dir, node_ids[name])
        _seed_node_user(node_ids[name], "CN=localhost")
    manifest = {
        "schema": MANIFEST_SCHEMA, "lab_version": LAB_VERSION, "lab_id": lab_id, "created_at": _now(),
        "origin": origin, "port": port, "container_name": n1, "container_id": node_ids[n1], "image": image,
        "pki": {k: v for k, v in pki.items() if k != "keystore_path"}, "fixtures": {}, "owned_group_ids": [],
        "cluster": {"network": net, "zookeeper": {"name": zk, "container_id": zk_id, "image": ZK_IMAGE_REF},
                    "nodes": [{"name": n, "container_id": cid, "published": n == n1} for n, cid in node_ids.items()]},
        "notes": "Disposable synthetic two-node cluster lab. Never point this tooling at a non-lab NiFi.",
    }
    _write_json_private(lab_dir / MANIFEST_NAME, manifest)
    for name in (n1, n2):
        dockerctl.docker("start", node_ids[name])
    log("nodes started; waiting for mutual TLS and two connected nodes")
    admin = pki["identities"]["admin"]
    about = _wait_ready(origin, pki["ca_path"], admin["cert_path"], admin["key_path"], timeout=600)
    summary = wait_connected(manifest, 2)
    manifest["runtime"] = {"nifi_about": about.get("about", {}), "cluster_summary": summary,
                           "boundary_facts": verify_lab_target(manifest), "verified_at": _now()}
    _write_json_private(lab_dir / MANIFEST_NAME, manifest)
    log(f"cluster ready: {summary.get('connectedNodes')} connected")
    return lab_dir


def _owned(name: str, lab_id: str) -> bool:
    info = dockerctl.inspect_container(name)
    return bool(info) and ((info.get("Config") or {}).get("Labels") or {}).get(dockerctl.LAB_LABEL) == lab_id


def stop_node(lab_dir: Path, index: int) -> str:
    manifest = load_manifest(lab_dir)
    node = manifest["cluster"]["nodes"][index]
    if not _owned(node["name"], manifest["lab_id"]):
        raise RuntimeError("node is not owned by this lab")
    dockerctl.docker("stop", "-t", "20", node["container_id"])
    return node["name"]


def destroy_cluster_lab(lab_dir: Path) -> None:
    manifest = load_manifest(lab_dir)
    lab_id = manifest["lab_id"]
    names = [n["name"] for n in manifest["cluster"]["nodes"]] + [manifest["cluster"]["zookeeper"]["name"]]
    for name in names:
        if _owned(name, lab_id):
            dockerctl.docker("rm", "-f", name)
    net = manifest["cluster"]["network"]
    out = dockerctl.docker("network", "inspect", net, check=False)
    if out.strip() and json.loads(out)[0].get("Labels", {}).get(dockerctl.LAB_LABEL) == lab_id:
        dockerctl.docker("network", "rm", net)
    log(f"removed cluster lab {lab_id}")
