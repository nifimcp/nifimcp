#!/usr/bin/env python3
"""Milestone 0: capture the exact NiFi 2.12.0 compatibility capsule from the owned lab.

Writes (committed, compact, public-safe):
  src/nifimcp/contracts/nifi-2.12.0-rest-allowlist.json  - allowlisted endpoints + DTO schemas
  src/nifimcp/catalog/nifi-2.12.0-catalog.json           - pinned Flow Draft Preview catalog
  evidence/capsule/version-capsule.json                  - versions, digests and hashes

The full OpenAPI document and runtime manifest are hashed, not committed.

    uv run python scripts/capture_capsule.py
"""
from __future__ import annotations

import datetime as dt
import hashlib
import importlib.metadata as md
import json
import platform
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lab"))
sys.path.insert(0, str(ROOT / "src"))

from nifimcp_lab import dockerctl  # noqa: E402
from nifimcp_lab.bootstrap import current_lab_dir  # noqa: E402
from nifimcp_lab.client import LabClient  # noqa: E402

SWAGGER_IN_IMAGE = "/opt/nifi/nifi-current/work/jetty/nifi-web-api-2.12.0.war/webapp/docs/rest-api/swagger.json"

# id, method, path template, allowed query parameters (name -> allowed values or "int"/"uuid"), purpose
ALLOWLIST = [
    ("about", "GET", "/flow/about", {}, "Runtime version for capability and version checks"),
    ("cluster_summary", "GET", "/flow/cluster/summary", {}, "Topology detection; clusters fail closed"),
    ("current_user", "GET", "/flow/current-user", {}, "Effective identity and coarse permissions"),
    ("group_flow", "GET", "/flow/process-groups/{id}", {}, "One level of a process group; permissions checked"),
    ("group_status", "GET", "/flow/process-groups/{id}/status", {"recursive": ["true", "false"]},
     "Current status snapshot for scope inventory and health"),
    ("bulletin_board", "GET", "/flow/bulletin-board", {"limit": "int", "after": "int"},
     "Recent bulletins; filtered to scope client-side"),
    ("group_download", "GET", "/process-groups/{id}/download", {"includeReferencedServices": ["true", "false"]},
     "Flow definition of an allowed scope (never with component state)"),
    ("provenance_options", "GET", "/provenance/search-options", {}, "Discover indexed provenance fields"),
    ("provenance_submit", "POST", "/provenance", {}, "Create an owned, exact-selector provenance query"),
    ("provenance_get", "GET", "/provenance/{id}", {"summarize": ["false"], "incrementalResults": ["false"]},
     "Poll an owned provenance query"),
    ("provenance_delete", "DELETE", "/provenance/{id}", {}, "Clean up an owned provenance query"),
    ("listing_submit", "POST", "/flowfile-queues/{id}/listing-requests", {},
     "Create an owned queue metadata listing (explicitly enabled only)"),
    ("listing_get", "GET", "/flowfile-queues/{id}/listing-requests/{listing-request-id}", {},
     "Poll an owned queue listing"),
    ("listing_delete", "DELETE", "/flowfile-queues/{id}/listing-requests/{listing-request-id}", {},
     "Clean up an owned queue listing"),
]

SCHEMAS = [
    "AboutDTO", "ClusterSummaryDTO", "CurrentUserEntity", "ProcessGroupFlowEntity", "ProcessGroupStatusEntity",
    "ProcessGroupStatusSnapshotDTO", "ConnectionStatusSnapshotDTO", "ProcessorStatusSnapshotDTO",
    "PortStatusSnapshotDTO", "BulletinBoardDTO", "BulletinEntity", "BulletinDTO", "ConnectionEntity",
    "ConnectionDTO", "ProcessorEntity", "ProvenanceRequestDTO", "ProvenanceSearchValueDTO", "ProvenanceDTO",
    "ProvenanceResultsDTO", "ProvenanceEventDTO", "ProvenanceSearchableFieldDTO", "ProvenanceOptionsDTO",
    "ListingRequestDTO", "FlowFileSummaryDTO", "QueueSizeDTO", "PermissionsDTO",
]

CATALOG_TYPES = {
    "org.apache.nifi.processors.attributes.UpdateAttribute": {
        "dynamic_property_semantics": "attribute_assignment",
        "fixed_properties": {"Store State": "Do not store state"},
    },
    "org.apache.nifi.processors.standard.RouteOnAttribute": {
        "dynamic_property_semantics": "route_condition",
        "fixed_properties": {"Routing Strategy": "Route to Property name"},
    },
    "org.apache.nifi.processors.standard.EvaluateJsonPath": {
        "dynamic_property_semantics": "json_path_extraction",
        "fixed_properties": {"Destination": "flowfile-attribute"},
    },
}


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def collect_refs(node, out: set[str]) -> None:
    if isinstance(node, dict):
        ref = node.get("$ref")
        if isinstance(ref, str) and ref.startswith("#/components/schemas/"):
            out.add(ref.rsplit("/", 1)[-1])
        for value in node.values():
            collect_refs(value, out)
    elif isinstance(node, list):
        for value in node:
            collect_refs(value, out)


def main() -> int:
    lab_dir = current_lab_dir(ROOT / ".lab")
    with LabClient(lab_dir) as client:
        manifest = client.manifest
        about = client.get("/flow/about")["about"]
        runtime_raw = client._client.get("/flow/runtime-manifest").content
    if about.get("version") != "2.12.0":
        raise SystemExit(f"lab runtime is {about.get('version')}, expected 2.12.0")
    with tempfile.TemporaryDirectory() as tmp:
        target = Path(tmp) / "swagger.json"
        dockerctl.docker("cp", f"{manifest['container_id']}:{SWAGGER_IN_IMAGE}", str(target))
        swagger_raw = target.read_bytes()
    swagger = json.loads(swagger_raw)
    if swagger["info"]["version"] != "2.12.0":
        raise SystemExit("OpenAPI document version mismatch")

    endpoints = []
    for eid, method, path, query, purpose in ALLOWLIST:
        op = swagger["paths"][path][method.lower()]
        endpoints.append({
            "id": eid, "method": method, "path": path, "query": query, "purpose": purpose,
            "operation_id": op.get("operationId"),
            "security": [list(s.keys())[0] for s in op.get("security", [])],
            "documented_parameters": sorted(p["name"] for p in op.get("parameters", [])),
            "documented_responses": sorted(op.get("responses", {}).keys()),
        })
    schemas: dict = {}
    pending = set(SCHEMAS)
    while pending:
        name = pending.pop()
        if name in schemas or name not in swagger["components"]["schemas"]:
            continue
        schema = swagger["components"]["schemas"][name]
        schemas[name] = schema
        refs: set[str] = set()
        collect_refs(schema, refs)
        if name.startswith(("Provenance", "Listing", "FlowFileSummary", "Bulletin", "ClusterSummary", "About",
                            "QueueSize", "Permissions")):
            pending |= refs - set(schemas)
    allowlist = {
        "allowlist_version": "1",
        "nifi_version": "2.12.0",
        "source": {
            "image_digest": dockerctl.NIFI_IMAGE_DIGEST,
            "path_in_image": SWAGGER_IN_IMAGE,
            "openapi_version": swagger.get("openapi"),
            "document_version": swagger["info"]["version"],
            "sha256": hashlib.sha256(swagger_raw).hexdigest(),
            "bytes": len(swagger_raw),
            "path_count": len(swagger["paths"]),
            "captured_at": now(),
        },
        "endpoints": endpoints,
        "schemas": dict(sorted(schemas.items())),
        "excluded_by_design": [
            "Any PUT, PATCH or DELETE other than owned query cleanup",
            "/flowfile-queues/{id}/flowfiles/{flowfile-uuid} and /content (attributes and payload)",
            "/flowfile-queues/{id}/drop-requests (queue drop)",
            "/provenance-events/** (event detail, content, replay)",
            "/provenance/lineage (unbounded lineage expansion)",
            "/processors/{id}/run-status and every run-status route",
            "includeComponentState=true on downloads (requires write)",
            "clusterNodeId routing (clusters fail closed in this release)",
        ],
    }
    (ROOT / "src/nifimcp/contracts/nifi-2.12.0-rest-allowlist.json").write_text(
        json.dumps(allowlist, indent=1, sort_keys=True) + "\n")

    runtime = json.loads(runtime_raw)["runtimeManifest"]
    entries = []
    for bundle in runtime["bundles"]:
        for proc in bundle["componentManifest"].get("processors", []):
            if proc["type"] not in CATALOG_TYPES:
                continue
            props = {}
            for key, d in sorted(proc.get("propertyDescriptors", {}).items()):
                props[key] = {
                    "display_name": d.get("displayName"),
                    "required": bool(d.get("required")),
                    "sensitive": bool(d.get("sensitive")),
                    "default": d.get("defaultValue"),
                    "allowable_values": [a.get("value") for a in d.get("allowableValues") or []] or None,
                    "expression_language_scope": d.get("expressionLanguageScope"),
                    "identifies_controller_service": bool(d.get("typeProvidedByValue")),
                }
            entries.append({
                "type_id": proc["type"],
                "kind": "processor",
                "bundle": {"group": proc["group"], "artifact": proc["artifact"], "version": proc["version"]},
                "relationships": sorted(r["name"] for r in proc.get("supportedRelationships", [])),
                "supports_dynamic_properties": bool(proc.get("supportsDynamicProperties")),
                "supports_dynamic_relationships": bool(proc.get("supportsDynamicRelationships")),
                "supports_sensitive_dynamic_properties": bool(proc.get("supportsSensitiveDynamicProperties")),
                "input_requirement": proc.get("inputRequirement"),
                "default_scheduling_period": (proc.get("defaultSchedulingPeriodBySchedulingStrategy") or {}).get("TIMER_DRIVEN"),
                "default_penalty_duration": proc.get("defaultPenaltyDuration"),
                "default_yield_duration": proc.get("defaultYieldDuration"),
                "default_bulletin_level": proc.get("defaultBulletinLevel"),
                "properties": props,
                **CATALOG_TYPES[proc["type"]],
            })
    if sorted(e["type_id"] for e in entries) != sorted(CATALOG_TYPES):
        raise SystemExit("runtime manifest did not contain exactly one entry per catalog type")
    entries.append({"type_id": "nifi:InputPort", "kind": "input_port", "bundle": None, "relationships": [],
                    "properties": {}, "supports_dynamic_properties": False,
                    "supports_dynamic_relationships": False, "port_relationship": "port"})
    entries.append({"type_id": "nifi:OutputPort", "kind": "output_port", "bundle": None, "relationships": [],
                    "properties": {}, "supports_dynamic_properties": False,
                    "supports_dynamic_relationships": False, "port_relationship": None})
    catalog = {
        "catalog_version": "1",
        "nifi_version": "2.12.0",
        "provenance": {
            "source": "GET /nifi-api/flow/runtime-manifest on stock apache/nifi 2.12.0",
            "image_digest": dockerctl.NIFI_IMAGE_DIGEST,
            "runtime_manifest_sha256": hashlib.sha256(runtime_raw).hexdigest(),
            "runtime_manifest_version": runtime.get("version"),
            "captured_at": now(),
            "extracted_by": "scripts/capture_capsule.py",
        },
        "entries": sorted(entries, key=lambda e: e["type_id"]),
    }
    catalog_hash = hashlib.sha256(canonical({k: v for k, v in catalog.items()})).hexdigest()
    catalog["catalog_hash"] = catalog_hash
    (ROOT / "src/nifimcp/catalog/nifi-2.12.0-catalog.json").write_text(json.dumps(catalog, indent=1, sort_keys=True) + "\n")

    lock = (ROOT / "uv.lock").read_bytes()
    uv_version = subprocess.run(["uv", "--version"], capture_output=True, text=True).stdout.strip()
    capsule = {
        "capsule_version": "1",
        "captured_at": now(),
        "nifi": {
            "version": about.get("version"),
            "build_tag": about.get("buildTag"),
            "distribution_profile": "Official apache/nifi Docker image, stock, standalone (single node), secure two-way TLS",
            "image_tag": dockerctl.NIFI_IMAGE_TAG,
            "image_digest": dockerctl.NIFI_IMAGE_DIGEST,
            "java_version": manifest.get("runtime", {}).get("java_version"),
        },
        "rest_contract": {k: allowlist["source"][k] for k in ("sha256", "bytes", "path_in_image", "openapi_version", "path_count")},
        "runtime_manifest_sha256": catalog["provenance"]["runtime_manifest_sha256"],
        "catalog_hash": catalog_hash,
        "python": {"implementation": platform.python_implementation(), "version": platform.python_version()},
        "mcp_sdk": {"distribution": "mcp", "version": md.version("mcp"), "types": md.version("mcp-types")},
        "pinned_runtime_dependencies": {name: md.version(name) for name in ("pydantic", "httpx2", "anyio")},
        "uv": uv_version,
        "uv_lock_sha256": hashlib.sha256(lock).hexdigest(),
        "lab_id": manifest["lab_id"],
        "notes": [
            "The legacy /docs/nifi-docs/rest-api/index.html page identifies itself as 1.28.0 and was not used.",
            "Contract taken from the OpenAPI document shipped inside the pinned image's nifi-web-api-2.12.0.war.",
            "nifi-api library versions are not used as the application version.",
        ],
    }
    out = ROOT / "evidence/capsule/version-capsule.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(capsule, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"catalog_hash": catalog_hash, "openapi_sha256": allowlist["source"]["sha256"],
                      "endpoints": len(endpoints), "schemas": len(schemas)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
