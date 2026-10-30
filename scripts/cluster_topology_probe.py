#!/usr/bin/env python3
"""Topology qualification against a REAL two-node secure NiFi 2.12.0 cluster (gate A21, cluster half).

    uv run python scripts/cluster_topology_probe.py [--keep] [--output evidence/cluster]

1. Creates a disposable two-node cluster with ZooKeeper (lab CLI, loopback only).
2. Grants a dedicated observer identity read access only (/flow and one scoped group).
3. Runs NiFiMCP's live tools as that observer and records every request NiFiMCP sends.
4. Stops node 2 and repeats, to observe a partially connected cluster.
5. Destroys every container and the network unless --keep.

Expected (fail closed): get_capabilities reports clustered topology with live investigation blocked;
every investigation tool returns UNSUPPORTED_TOPOLOGY; NiFiMCP sends no POST or DELETE request.
Exit 0 only when all expectations hold.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path

import anyio

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lab"))

from nifimcp_lab.client import LabClient  # noqa: E402
from nifimcp_lab.cluster import cluster_summary, create_cluster_lab, destroy_cluster_lab, stop_node  # noqa: E402
from nifimcp_lab.fixtures import ensure_admin_policies  # noqa: E402

from nifimcp.config import load_config  # noqa: E402
from nifimcp.service import Service, Session, call_tool  # noqa: E402

WINDOW = 30


def observer_config(lab_dir: Path, manifest: dict, scope_group: str) -> Path:
    ident = manifest["pki"]["identities"]["observer"]
    cfg = {"schema_version": "1", "mode": "live", "artifact_dir": str(lab_dir / "artifacts-observer"),
           "live": {"origin": manifest["origin"], "ca_file": manifest["pki"]["ca_path"],
                    "auth": {"kind": "client_certificate", "cert_file": ident["cert_path"],
                             "key_file": ident["key_path"]},
                    "scopes": [{"scope_id": "cluster-scope", "process_group_id": scope_group,
                                "label": "Synthetic cluster probe scope"}]}}
    path = lab_dir / "operator.observer.json"
    path.write_text(json.dumps(cfg, indent=1))
    return path


def run_tools(cfg_path: Path) -> tuple[list[dict], list[tuple]]:
    svc = Service(Session(load_config(cfg_path)))
    calls = []
    http = svc.s.source.http
    original = http.call

    async def recorder(endpoint, **kw):
        calls.append((http.allowlist[endpoint]["method"], endpoint))
        return await original(endpoint, **kw)
    http.call = recorder
    now = dt.datetime.now(dt.timezone.utc)
    interval = {"start": (now - dt.timedelta(minutes=WINDOW)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "end": now.strftime("%Y-%m-%dT%H:%M:%SZ")}
    plan = [("get_capabilities", {}), ("describe_flow", {"scope_id": "cluster-scope"}),
            ("get_flow_health", {"scope_id": "cluster-scope", "interval": interval}),
            ("trace_feed", {"scope_id": "cluster-scope", "interval": interval,
                            "selector": {"kind": "flowfile_uuid", "value": "6ae1e6de-d4a6-4f88-be99-5ac47c13e079"}})]
    results = []
    for tool, args in plan:
        env = anyio.run(call_tool, svc, tool, args)
        results.append({"tool": tool, "status": env["status"], "error": (env.get("error") or {}).get("code"),
                        "topology": (env.get("data") or {}).get("topology") if tool == "get_capabilities" else None})
    return results, calls


def check(results: list[dict], calls: list[tuple]) -> list[str]:
    problems = []
    caps = results[0]
    topo = caps.get("topology") or {}
    if not topo.get("clustered") or topo.get("live_investigation") != "blocked (clustered)":
        problems.append(f"capabilities did not report a blocked clustered topology: {topo}")
    for r in results[1:]:
        if r["error"] != "UNSUPPORTED_TOPOLOGY":
            problems.append(f"{r['tool']} returned {r['status']}/{r['error']}, expected UNSUPPORTED_TOPOLOGY")
    writes = [c for c in calls if c[0] != "GET"]
    if writes:
        problems.append(f"NiFiMCP sent non-GET requests to a cluster it refuses: {writes}")
    return problems


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--keep", action="store_true")
    p.add_argument("--output", type=Path, default=ROOT / "evidence" / "cluster")
    p.add_argument("--lab-root", type=Path, default=ROOT / ".lab" / "clusters")
    args = p.parse_args(argv)
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = args.output / stamp
    out.mkdir(parents=True, exist_ok=True)
    lab_dir = None
    record = {"gate": "A21 (cluster half)", "started_at": stamp}
    try:
        lab_dir = create_cluster_lab(args.lab_root)
        with LabClient(lab_dir) as admin:
            manifest = admin.manifest
            root = admin.root_id()
            ensure_admin_policies(admin, root)
            scope = admin.create_group(root, "Cluster probe scope", 0, 0)["id"]
            observer_dn = manifest["pki"]["identities"]["observer"]["dn"]
            observer = (admin.find_user(observer_dn) or admin.create_user(observer_dn))["id"]
            admin_id = admin.find_user(manifest["pki"]["identities"]["admin"]["dn"])["id"]
            admin.grant("read", f"/process-groups/{scope}", admin_id)
            admin.grant("write", f"/process-groups/{scope}", admin_id)
            for action, resource in (("read", "/flow"), ("read", f"/process-groups/{scope}")):
                admin.grant(action, resource, observer)
        cfg = observer_config(lab_dir, manifest, scope)
        record["nifi"] = manifest["runtime"]["nifi_about"].get("version")
        record["image"] = manifest["image"]["reference"]
        record["zookeeper_image"] = manifest["cluster"]["zookeeper"]["image"]
        record["observer_policies"] = ["read /flow", "read scoped process group"]
        record["connected"] = {"summary": cluster_summary(manifest)}
        results, calls = run_tools(cfg)
        record["connected"].update(results=results, nifimcp_requests=calls, problems=check(results, calls))
        stopped = stop_node(lab_dir, 1)
        record["partial"] = {"stopped_node": stopped}
        for _ in range(36):
            summary = cluster_summary(manifest)
            if summary.get("connectedNodeCount", 2) < 2:
                break
            anyio.run(anyio.sleep, 5)
        record["partial"]["summary"] = summary
        results, calls = run_tools(cfg)
        record["partial"].update(results=results, nifimcp_requests=calls, problems=check(results, calls))
        problems = record["connected"]["problems"] + record["partial"]["problems"]
        record["result"] = "PASS" if not problems else "FAIL"
    except Exception as exc:  # noqa: BLE001 - record environmental failures as BLOCKED, never PASS
        record["result"] = "BLOCKED"
        record["reason"] = f"{type(exc).__name__}: {str(exc)[:500]}"
    finally:
        if lab_dir is not None and not args.keep:
            try:
                destroy_cluster_lab(lab_dir)
                record["cleanup"] = "containers and network removed"
            except Exception as exc:  # noqa: BLE001
                record["cleanup"] = f"FAILED: {exc}"
    (out / "cluster-probe.json").write_text(json.dumps(record, indent=1, default=str))
    print(json.dumps({k: record.get(k) for k in ("result", "reason", "cleanup")} | {"output": str(out)}, indent=1))
    return {"PASS": 0, "FAIL": 1}.get(record["result"], 3)


if __name__ == "__main__":
    raise SystemExit(main())
