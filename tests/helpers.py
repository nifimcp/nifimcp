"""Shared test builders. All data is synthetic."""
from __future__ import annotations

import copy
import hashlib
import json
import uuid
from pathlib import Path

import anyio

from nifimcp.config import OperatorConfig
from nifimcp.service import Service, Session, call_tool

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "tests/fixtures/native/stock-2.12.0-probe-definition.json"
DEMO = ROOT / "src/nifimcp/demo_data"
CANARIES = ["DEMO-CANARY-HEC-TOKEN-0001", "DEMO-CANARY-LITERAL-KEY-0002", "DEMO-CANARY-BEARER-TOKEN-00000003",
            "DEMO-CANARY-USERINFO-0004"]


def uid(seed: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "nifimcp-test:" + seed))


def processor(ident: str, name: str = "p", type_: str = "org.apache.nifi.processors.standard.LogAttribute", **extra):
    base = {"identifier": ident, "instanceIdentifier": uid(ident), "name": name, "type": type_,
            "bundle": {"group": "org.apache.nifi", "artifact": "nifi-standard-nar", "version": "2.12.0"},
            "properties": {}, "propertyDescriptors": {}, "schedulingPeriod": "1 sec",
            "schedulingStrategy": "TIMER_DRIVEN", "autoTerminatedRelationships": [], "scheduledState": "ENABLED",
            "position": {"x": 0.0, "y": 0.0}, "componentType": "PROCESSOR"}
    base.update(extra)
    return base


def connection(ident: str, src: str, dst: str, rels=("success",), **extra):
    base = {"identifier": ident, "instanceIdentifier": uid(ident), "name": ident,
            "source": {"id": src, "type": "PROCESSOR"}, "destination": {"id": dst, "type": "PROCESSOR"},
            "selectedRelationships": list(rels), "backPressureObjectThreshold": 10000,
            "backPressureDataSizeThreshold": "1 GB", "flowFileExpiration": "0 sec", "prioritizers": [],
            "loadBalanceStrategy": "DO_NOT_LOAD_BALANCE", "bends": [], "labelIndex": 1, "zIndex": 0}
    base.update(extra)
    return base


def group(ident: str, name: str = "g", **contents):
    base = {"identifier": ident, "instanceIdentifier": uid(ident), "name": name, "position": {"x": 0.0, "y": 0.0},
            "processGroups": [], "processors": [], "connections": [], "inputPorts": [], "outputPorts": [],
            "funnels": [], "labels": [], "controllerServices": [], "remoteProcessGroups": []}
    base.update(contents)
    return base


def definition(root: dict, **extra) -> dict:
    doc = {"flowContents": root, "externalControllerServices": {}, "parameterContexts": {},
           "flowEncodingVersion": "1.0", "parameterProviders": {}, "latest": False}
    doc.update(extra)
    return doc


def raw(doc) -> bytes:
    return (json.dumps(doc, indent=1, sort_keys=True) + "\n").encode()


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_bundle(folder: Path, flow_doc: dict, *, scope_id="test-scope", extra_files: dict | None = None,
                 manifest_overrides: dict | None = None, collected_at="2026-10-29T02:00:00.000Z") -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    files = []
    data = raw(flow_doc)
    (folder / "flow-definition.json").write_bytes(data)
    files.append({"path": "flow-definition.json", "kind": "flow_definition", "sha256": sha(data), "bytes": len(data),
                  "collected_at": collected_at, "node_id": "standalone"})
    for name, (kind, doc, interval) in (extra_files or {}).items():
        d = raw(doc)
        (folder / name).write_bytes(d)
        entry = {"path": name, "kind": kind, "sha256": sha(d), "bytes": len(d), "collected_at": collected_at,
                 "node_id": "standalone"}
        if interval:
            entry["interval"] = interval
        files.append(entry)
    manifest = {
        "bundle_schema": "nifimcp-bundle/1", "bundle_id": "test-bundle", "created_at": collected_at,
        "collector": {"name": "tests", "version": "1"},
        "nifi": {"version": "2.12.0", "profile": "synthetic test"},
        "declared_scope": {"scope_id": scope_id, "process_group_id": flow_doc["flowContents"]["instanceIdentifier"]},
        "nodes": [{"node_id": "standalone", "included": True}],
        "source_kinds": sorted({f["kind"] for f in files}), "files": files,
        "redaction": {"policy": "test", "sensitive_values_present": False},
        "completeness": {"status": "complete", "missing": []},
    }
    if manifest_overrides:
        manifest.update(manifest_overrides)
    (folder / "manifest.json").write_bytes(raw(manifest))
    return folder


def demo_session(tmp_path: Path, **overrides) -> Service:
    cfg = {
        "schema_version": "1", "mode": "demo", "artifact_dir": str(tmp_path / "art"), "base_dir": str(tmp_path),
        "redaction": {"attribute_allowlist": ["event.level", "sensor.id"]},
        "limits": {"queue_sampling_enabled": True},
    }
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(cfg.get(key), dict):
            cfg[key] = {**cfg[key], **value}
        else:
            cfg[key] = value
    return Service(Session(OperatorConfig.model_validate(cfg)))


def bundle_session(tmp_path: Path, bundle_dir: Path, **overrides) -> Service:
    from nifimcp.service import register_input
    from nifimcp.artifacts import ArtifactStore
    cfg_dict = {"schema_version": "1", "mode": "bundle", "artifact_dir": str(tmp_path / "art"),
                "base_dir": str(tmp_path)}
    cfg_dict.update(overrides)
    cfg = OperatorConfig.model_validate(cfg_dict)
    store = ArtifactStore(cfg.artifact_path, cfg.retention_days)
    register_input(cfg, store, bundle_dir, "bundle", "test")
    return Service(Session(cfg))


def run(service: Service, tool: str, args: dict) -> dict:
    return anyio.run(call_tool, service, tool, args)


def demo_info() -> dict:
    info = json.loads((DEMO / "build-info.json").read_text())
    manifest = json.loads((DEMO / "telemetry-intake/manifest.json").read_text())
    info["scope"] = manifest["declared_scope"]["scope_id"]
    info["interval"] = next(f["interval"] for f in manifest["files"] if f.get("interval"))
    return info


def deepcopy(x):
    return copy.deepcopy(x)
