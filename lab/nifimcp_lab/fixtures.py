"""Provision synthetic fixtures, identities and least-privilege policies in an owned lab.

All data is synthetic. The observer identity receives only:
  * READ /flow                                  (view the user interface / flow API)
  * READ /process-groups/<scope>               (view components in the scope)
  * READ /provenance                           (query provenance)
  * READ /provenance-data/process-groups/<scope>  (view provenance events in scope)
  * READ /data/process-groups/<scope>          (required by NiFi 2.12.0 for provenance
                                                event visibility and queue listing)
No write policy is granted to any non-admin identity.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

from .boundary import MANIFEST_NAME, load_manifest
from .client import LabClient

GEN = "org.apache.nifi.processors.standard.GenerateFlowFile"
UPDATE = "org.apache.nifi.processors.attributes.UpdateAttribute"
ROUTE = "org.apache.nifi.processors.standard.RouteOnAttribute"
EJP = "org.apache.nifi.processors.standard.EvaluateJsonPath"
LOGATTR = "org.apache.nifi.processors.standard.LogAttribute"
PUTFILE = "org.apache.nifi.processors.standard.PutFile"

SCOPE_NAME = "NiFiMCP Lab Scope"
FOREIGN_NAME = "NiFiMCP Lab Foreign"
DRAFTS_NAME = "NiFiMCP Lab Drafts"


def _log(msg: str) -> None:
    import sys
    print(f"[lab] {msg}", file=sys.stderr, flush=True)


def _ref(entity: dict, group: str, kind: str) -> dict:
    return {"id": entity["id"], "groupId": group, "type": kind}


def _save_manifest(lab_dir: Path, manifest: dict) -> None:
    path = Path(lab_dir) / MANIFEST_NAME
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)
        handle.write("\n")


def ensure_admin_policies(c: LabClient, root: str) -> str:
    admin = c.find_user(c.manifest["pki"]["identities"]["admin"]["dn"])
    if admin is None:
        raise RuntimeError("initial admin identity not present in NiFi")
    for action, res in [("read", f"/process-groups/{root}"), ("write", f"/process-groups/{root}"),
                        ("read", f"/data/process-groups/{root}"), ("write", f"/data/process-groups/{root}"),
                        ("read", f"/provenance-data/process-groups/{root}"), ("read", "/provenance"),
                        ("read", "/system")]:
        c.grant(action, res, admin["id"])
    return admin["id"]


def _user(c: LabClient, dn: str) -> str:
    existing = c.find_user(dn)
    return (existing or c.create_user(dn))["id"]


def _build_scope(c: LabClient, root: str) -> dict:
    scope = c.create_group(root, SCOPE_NAME, 0, 0)["id"]
    ingest = c.create_group(scope, "Ingest", 0, 0)["id"]
    route = c.create_group(scope, "Route", 0, 400)["id"]
    broken = c.create_group(scope, "Review Examples", 600, 0)["id"]

    gen = c.create_processor(ingest, GEN, "Synthetic telemetry", x=0, y=0, scheduling_period="500 ms", properties={
        "Custom Text": '{"level":"${random():mod(3)}","source":"lab-sensor","synthetic":true}',
        "status": "${random():mod(3):equals(0):ifElse('critical', ${random():mod(2):equals(0):ifElse('standard','unknown')})}",
        "filename": "lab-event-${nextInt()}.json",
        "lab.synthetic": "true",
    })
    ingest_out = c.create_port(ingest, "output", "to-route", x=0, y=300)
    c.connect(ingest, _ref(gen, ingest, "PROCESSOR"), _ref(ingest_out, ingest, "OUTPUT_PORT"), ["success"],
              name="generated")

    route_in = c.create_port(route, "input", "from-ingest", x=0, y=0)
    norm = c.create_processor(route, UPDATE, "Normalize status", x=0, y=200,
                              properties={"route.key": "${status:toLower()}"})
    router = c.create_processor(route, ROUTE, "Route by status", x=0, y=400, properties={
        "critical": "${route.key:equals('critical')}",
        "standard": "${route.key:equals('standard')}",
    })
    deliver_crit = c.create_processor(route, LOGATTR, "Deliver critical", x=-400, y=650,
                                      auto_terminate=["success"], properties={"Log Level": "debug"})
    deliver_std = c.create_processor(route, LOGATTR, "Deliver standard", x=0, y=650,
                                     auto_terminate=["success"], properties={"Log Level": "debug"})
    review = c.create_processor(route, UPDATE, "Unmatched review", x=400, y=650, auto_terminate=["success"])
    c.connect(route, _ref(route_in, route, "INPUT_PORT"), _ref(norm, route, "PROCESSOR"), [], name="incoming")
    c.connect(route, _ref(norm, route, "PROCESSOR"), _ref(router, route, "PROCESSOR"), ["success"], name="normalized")
    c_crit = c.connect(route, _ref(router, route, "PROCESSOR"), _ref(deliver_crit, route, "PROCESSOR"), ["critical"],
                       name="critical")
    c_std = c.connect(route, _ref(router, route, "PROCESSOR"), _ref(deliver_std, route, "PROCESSOR"), ["standard"],
                      name="standard")
    c_unm = c.connect(route, _ref(router, route, "PROCESSOR"), _ref(review, route, "PROCESSOR"), ["unmatched"],
                      name="Unmatched hold", object_threshold=10, size_threshold="1 MB")
    c.connect(scope, {"id": ingest_out["id"], "groupId": ingest, "type": "OUTPUT_PORT"},
              {"id": route_in["id"], "groupId": route, "type": "INPUT_PORT"}, [], name="ingest to route")

    gen_bad = c.create_processor(broken, GEN, "Malformed sample source", x=0, y=0, scheduling_period="2 sec",
                                 properties={"Custom Text": "this is not json", "filename": "lab-malformed-${nextInt()}.txt"})
    ejp = c.create_processor(broken, EJP, "Extract level", x=0, y=250, auto_terminate=["failure", "unmatched", "matched"],
                             properties={"Destination": "flowfile-attribute", "event.level": "$.level"})
    c.connect(broken, _ref(gen_bad, broken, "PROCESSOR"), _ref(ejp, broken, "PROCESSOR"), ["success"], name="samples")
    invalid = c.create_processor(broken, PUTFILE, "Archive (unconfigured)", x=400, y=250, auto_terminate=["success", "failure"])
    return {
        "scope_group_id": scope, "ingest_group_id": ingest, "route_group_id": route,
        "review_group_id": broken, "generator_id": gen["id"], "router_id": router["id"],
        "normalize_id": norm["id"], "unmatched_review_id": review["id"],
        "unmatched_connection_id": c_unm["id"], "critical_connection_id": c_crit["id"],
        "standard_connection_id": c_std["id"], "malformed_source_id": gen_bad["id"],
        "extract_level_id": ejp["id"], "invalid_processor_id": invalid["id"],
        "deliver_critical_id": deliver_crit["id"], "deliver_standard_id": deliver_std["id"],
    }


def _build_foreign(c: LabClient, root: str) -> dict:
    foreign = c.create_group(root, FOREIGN_NAME, 900, 0)["id"]
    gen = c.create_processor(foreign, GEN, "Foreign source", x=0, y=0, scheduling_period="1 sec",
                             properties={"filename": "foreign-${nextInt()}.txt"})
    sink = c.create_processor(foreign, UPDATE, "Foreign sink", x=0, y=250, auto_terminate=["success"])
    conn = c.connect(foreign, _ref(gen, foreign, "PROCESSOR"), _ref(sink, foreign, "PROCESSOR"), ["success"],
                     name="foreign queue")
    return {"foreign_group_id": foreign, "foreign_processor_id": gen["id"], "foreign_connection_id": conn["id"]}


def _run_for(c: LabClient, group: str, seconds: float) -> None:
    c.schedule_group(group, "RUNNING")
    time.sleep(seconds)


def provision(lab_dir: Path) -> dict:
    lab_dir = Path(lab_dir)
    with LabClient(lab_dir) as c:
        manifest = c.manifest
        root = c.root_id()
        ensure_admin_policies(c, root)
        if manifest.get("fixtures", {}).get("scope_group_id"):
            _log("fixtures already provisioned")
            return manifest["fixtures"]
        ids = {"root_group_id": root}
        ids.update(_build_scope(c, root))
        ids.update(_build_foreign(c, root))
        ids["drafts_group_id"] = c.create_group(root, DRAFTS_NAME, 0, 900)["id"]

        users = {name: _user(c, ident["dn"]) for name, ident in manifest["pki"]["identities"].items()
                 if name != "admin"}
        scope = ids["scope_group_id"]
        grants = {
            "observer": [("read", "/flow"), ("read", f"/process-groups/{scope}"), ("read", "/provenance"),
                         ("read", f"/provenance-data/process-groups/{scope}"),
                         ("read", f"/data/process-groups/{scope}")],
            "restricted": [("read", "/flow"), ("read", f"/process-groups/{scope}")],
            "outsider": [("read", "/flow")],
        }
        # A component-specific policy REPLACES the inherited one in NiFi, so the lab
        # admin must be added explicitly to every scoped policy it still needs.
        admin_id = c.find_user(manifest["pki"]["identities"]["admin"]["dn"])["id"]
        for action, resource in sorted({p for v in grants.values() for p in v}):
            if resource != "/flow" and resource != "/provenance":
                c.grant(action, resource, admin_id)
        for name, policy_list in grants.items():
            for action, resource in policy_list:
                c.grant(action, resource, users[name])
        ids["user_ids"] = users
        ids["granted_policies"] = {k: [f"{a}:{r}" for a, r in v] for k, v in grants.items()}

        # Generate bounded synthetic activity: status, bulletins, provenance, back pressure.
        _log("running synthetic flows to create status, bulletins and provenance")
        # Start components individually so the unmatched review processor stays stopped
        # (its queue accumulates and engages back pressure) and the invalid one is untouched.
        start: list[tuple[str, str]] = []
        flow = c.get(f"/flow/process-groups/{ids['route_group_id']}")["processGroupFlow"]["flow"]
        route_in_port = flow["inputPorts"][0]["id"]
        ingest_flow = c.get(f"/flow/process-groups/{ids['ingest_group_id']}")["processGroupFlow"]["flow"]
        ingest_out_port = ingest_flow["outputPorts"][0]["id"]
        start += [("input", route_in_port), ("output", ingest_out_port)]
        start += [("processor", ids[k]) for k in ("normalize_id", "router_id", "deliver_critical_id",
                                                   "deliver_standard_id", "extract_level_id")]
        for kind, cid in start:
            c.set_run_state(kind, cid, "RUNNING")
        for pid in (ids["generator_id"], ids["malformed_source_id"], ids["foreign_processor_id"]):
            c.set_run_state("processor", pid, "RUNNING")
        time.sleep(25)
        for pid in (ids["generator_id"], ids["malformed_source_id"], ids["foreign_processor_id"]):
            c.set_run_state("processor", pid, "STOPPED")
        time.sleep(3)
        ids["unmatched_queue_count_at_provision"] = c.connection_queue_count(ids["unmatched_connection_id"])
        ids["provisioned_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        ids["owned_group_ids"] = [scope, ids["foreign_group_id"], ids["drafts_group_id"]]
        manifest["fixtures"] = ids
        manifest["owned_group_ids"] = ids["owned_group_ids"]
        _save_manifest(lab_dir, manifest)
    write_operator_configs(lab_dir)
    _log(f"fixtures ready; unmatched queue holds {ids['unmatched_queue_count_at_provision']} FlowFiles")
    return ids


def write_operator_configs(lab_dir: Path) -> None:
    """Write live-mode operator configs (observer, restricted, outsider). Observer-only rights."""
    manifest = load_manifest(lab_dir)
    fx = manifest["fixtures"]
    for name in ("observer", "restricted", "outsider"):
        ident = manifest["pki"]["identities"][name]
        art = Path(lab_dir) / f"artifacts-{name}"
        config = {
            "schema_version": "1",
            "mode": "live",
            "artifact_dir": str(art),
            "registered_inputs": [],
            "live": {
                "origin": manifest["origin"],
                "ca_file": manifest["pki"]["ca_path"],
                "auth": {"kind": "client_certificate", "cert_file": ident["cert_path"], "key_file": ident["key_path"]},
                "scopes": [{"scope_id": "lab-scope", "process_group_id": fx["scope_group_id"],
                            "label": "Synthetic lab scope"}],
                "provenance": {"enabled": True, "approved_indexed_attributes": ["status"]},
            },
            "telemetry": False,
            "updates": False,
            "redaction": {"include_component_names": True, "include_bulletin_messages": True,
                          "include_filenames": True, "include_parameter_values": False,
                          "attribute_allowlist": ["status", "route.key", "lab.synthetic"]},
            "limits": {"queue_sampling_enabled": True},
        }
        path = Path(lab_dir) / f"operator.{name}.json"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(config, handle, indent=2)
            handle.write("\n")


def refresh_activity(client: LabClient, *, refill: int = 10, timeout: float = 120.0) -> None:
    """Lab-only: create fresh, recent activity (status, bulletins, provenance, a full unmatched hold).

    The unmatched hold fills to its back-pressure threshold and NiFi then stops scheduling the router,
    so it is drained first and refilled; otherwise no recent unmatched events exist once the
    provisioning run ages out of a query window.
    """
    fx = client.manifest["fixtures"]
    client.empty_queue(fx["unmatched_connection_id"])
    sources = (fx["generator_id"], fx["malformed_source_id"])
    for pid in sources:
        client.set_run_state("processor", pid, "RUNNING")
    try:
        client.wait(lambda: client.connection_queue_count(fx["unmatched_connection_id"]) >= refill,
                    timeout=timeout, interval=1.0, what="unmatched hold to refill")
        time.sleep(3)
    finally:
        for pid in sources:
            client.set_run_state("processor", pid, "STOPPED")
    time.sleep(2)
