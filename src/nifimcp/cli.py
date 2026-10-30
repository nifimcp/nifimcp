"""NiFiMCP command line: demo, doctor, serve, register, describe, investigate, draft, report, catalog.

The CLI is operator-controlled: it may read operator-supplied paths. The MCP
transport never accepts filesystem paths from a model.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

import anyio

from . import __version__
from .config import OperatorConfig, load_config
from .errors import NiFiMCPError
from .service import Service, Session, call_tool, register_input

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2


def _print(obj) -> None:
    sys.stdout.write(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n")


def _demo_config(artifact_dir: Path) -> OperatorConfig:
    return OperatorConfig.model_validate({
        "schema_version": "1", "mode": "demo", "artifact_dir": str(artifact_dir), "base_dir": str(artifact_dir),
        "redaction": {"include_component_names": True, "include_property_values": True,
                      "include_parameter_values": False, "include_bulletin_messages": True,
                      "include_filenames": False, "attribute_allowlist": ["event.level", "sensor.id", "source.system"]},
        "limits": {"queue_sampling_enabled": True},
    })


async def run_demo(output: Path, *, include_drafts: bool = True) -> dict:
    from .sources import DEMO_BUNDLE, demo_data_dir
    output.mkdir(parents=True, exist_ok=True)
    os.chmod(output, 0o700)
    session = Session(_demo_config(output / "artifacts"))
    service = Service(session)
    info = json.loads((demo_data_dir() / "build-info.json").read_text())
    manifest = json.loads((demo_data_dir() / DEMO_BUNDLE / "manifest.json").read_text())
    scope = manifest["declared_scope"]["scope_id"]
    window = next(f["interval"] for f in manifest["files"] if f.get("interval"))
    transcript = []

    async def call(name, args):
        env = await call_tool(service, name, args)
        transcript.append({"tool": name, "arguments": args, "status": env["status"],
                           "error": env["error"], "findings": len(env["findings"]),
                           "evidence": len(env["evidence"]), "gaps": [g["code"] for g in env["gaps"]]})
        return env

    caps = await call("get_capabilities", {})
    await call("describe_flow", {"scope_id": scope, "depth": 4})
    await call("get_flow_health", {"scope_id": scope, "interval": window})
    await call("trace_feed", {"scope_id": scope, "interval": window,
                              "selector": {"kind": "flowfile_uuid", "value": info["trace_flowfile_uuid"]}})
    unmatched = await call("inspect_unmatched", {"connection_id": info["unmatched_connection_id"], "interval": window,
                                                 "sample_metadata": True})
    arts = [a["artifact_id"] for a in caps["data"]["artifacts"] if a["kind"] == "flow_definition"]
    await call("compare_flow_snapshots", {"baseline_artifact_id": arts[0], "candidate_artifact_id": arts[1]})
    inv = unmatched["data"]["investigation_id"]
    html_env = await call("export_investigation", {"investigation_id": inv, "format": "html"})
    json_env = await call("export_investigation", {"investigation_id": inv, "format": "json"})
    drafts = []
    if include_drafts:
        from .draft.examples import example_plans
        for name, plan in example_plans(session.catalog["catalog_hash"]).items():
            await call("validate_flow_plan", {"plan": plan})
            env = await call("draft_flow", {"plan": plan})
            drafts.append({"blueprint": name, "status": env["status"],
                           "artifact_id": (env["data"].get("artifacts") or {}).get("native_flow_definition", {}).get("artifact_id")})
    report_rec = session.store.get(html_env["data"]["artifact"]["artifact_id"], session.session_id)
    json_rec = session.store.get(json_env["data"]["artifact"]["artifact_id"], session.session_id)
    (output / "report.html").write_bytes(session.store.path_of(report_rec).read_bytes())
    (output / "investigation.json").write_bytes(session.store.path_of(json_rec).read_bytes())
    (output / "transcript.json").write_text(json.dumps(transcript, indent=1) + "\n")
    summary = {"demo": "NiFiMCP offline demo (synthetic data from stock NiFi 2.12.0; no NiFi, model or network used)",
               "scope": scope, "report_html": str(output / "report.html"),
               "investigation_json": str(output / "investigation.json"),
               "investigation_status": json_env["data"]["investigation_status"],
               "tools": [{k: t[k] for k in ("tool", "status", "findings", "evidence")} for t in transcript],
               "drafts": drafts}
    (output / "summary.json").write_text(json.dumps(summary, indent=1) + "\n")
    return summary


def cmd_demo(args) -> int:
    summary = anyio.run(run_demo, Path(args.output).resolve())
    _print(summary)
    return EXIT_OK


def cmd_doctor(args) -> int:
    from .doctor import run_doctor
    result = anyio.run(run_doctor, load_config(args.config))
    _print(result)
    return EXIT_OK if result["status"] == "ok" else EXIT_ERROR


def cmd_serve(args) -> int:
    from .mcp_server import serve
    config = load_config(args.config)
    anyio.run(serve, config)
    return EXIT_OK


def cmd_register(args) -> int:
    config = load_config(args.config)
    if config.mode != "bundle":
        raise NiFiMCPError("INVALID_ARGUMENT", "registration is only used in bundle mode")
    from .artifacts import ArtifactStore
    store = ArtifactStore(config.artifact_path, config.retention_days)
    rec = register_input(config, store, Path(args.path).resolve(), args.kind, args.label or Path(args.path).name)
    _print({"registered": rec.public()})
    return EXIT_OK


def cmd_unregister(args) -> int:
    config = load_config(args.config)
    from .artifacts import ArtifactStore
    store = ArtifactStore(config.artifact_path, config.retention_days)
    rec = store.unregister(args.artifact_id)
    _print({"unregistered": rec.public()})
    return EXIT_OK


def cmd_catalog(args) -> int:
    from .catalog import load_catalog
    catalog = load_catalog()
    if args.type:
        entries = [e for e in catalog["entries"] if args.type in (e["type_id"], e["type_id"].rsplit(".", 1)[-1])]
        if not entries:
            raise NiFiMCPError("INVALID_ARGUMENT", "no catalog entry matches that exact type")
        catalog = {**catalog, "entries": entries}
    _print(catalog)
    return EXIT_OK


def _session(config_path: str) -> Service:
    return Service(Session(load_config(config_path)))


def cmd_tool(name: str, build_args):
    def run(args) -> int:
        service = _session(args.config)
        env = anyio.run(call_tool, service, name, build_args(args))
        _print(env)
        return EXIT_ERROR if env["status"] == "error" else EXIT_OK
    return run


def _interval_arg(args):
    if bool(args.start) != bool(args.end):
        raise NiFiMCPError("INVALID_ARGUMENT", "give both --start and --end, or neither")
    return {"start": args.start, "end": args.end} if args.start else None


def cmd_investigate(args) -> int:
    service = _session(args.config)
    interval = _interval_arg(args)

    async def go():
        results = [await call_tool(service, "get_flow_health", {"scope_id": args.scope, **({"interval": interval} if interval else {})})]
        if args.trace_uuid or args.trace_filename:
            if not interval:
                raise NiFiMCPError("INVALID_ARGUMENT", "--start and --end are required for a trace")
            sel = ({"kind": "flowfile_uuid", "value": args.trace_uuid} if args.trace_uuid
                   else {"kind": "filename", "value": args.trace_filename})
            results.append(await call_tool(service, "trace_feed", {"scope_id": args.scope, "selector": sel,
                                                                   "interval": interval}))
        if args.unmatched:
            results.append(await call_tool(service, "inspect_unmatched", {
                "connection_id": args.unmatched, "sample_metadata": args.sample,
                **({"interval": interval} if interval else {})}))
        inv = next((r["data"].get("investigation_id") for r in results if r["status"] != "error"), None)
        if args.html and inv:
            exp = await call_tool(service, "export_investigation", {"investigation_id": inv, "format": "html"})
            rec = service.s.store.get(exp["data"]["artifact"]["artifact_id"], service.s.session_id)
            Path(args.html).write_bytes(service.s.store.path_of(rec).read_bytes())
        return results
    results = anyio.run(go)
    _print(results)
    return EXIT_ERROR if any(r["status"] == "error" for r in results) else EXIT_OK


def cmd_report(args) -> int:
    service = _session(args.config)

    interval = _interval_arg(args)

    async def go():
        d = await call_tool(service, "describe_flow", {"scope_id": args.scope, "depth": args.depth})
        if d["status"] == "error":
            return d
        await call_tool(service, "get_flow_health", {"scope_id": args.scope, **({"interval": interval} if interval else {})})
        exp = await call_tool(service, "export_investigation", {"investigation_id": d["data"]["investigation_id"],
                                                                "format": "html"})
        rec = service.s.store.get(exp["data"]["artifact"]["artifact_id"], service.s.session_id)
        Path(args.output).write_bytes(service.s.store.path_of(rec).read_bytes())
        return {"report": str(Path(args.output).resolve()), "status": exp["data"]["investigation_status"]}
    result = anyio.run(go)
    _print(result)
    return EXIT_ERROR if result.get("status") == "error" else EXIT_OK


def cmd_draft(args) -> int:
    if args.example:
        from .catalog import load_catalog
        from .draft.examples import example_plans
        plans = example_plans(load_catalog()["catalog_hash"])
        if args.example not in plans:
            raise NiFiMCPError("INVALID_ARGUMENT", f"examples: {', '.join(sorted(plans))}")
        _print(plans[args.example])
        return EXIT_OK
    if not args.plan:
        raise NiFiMCPError("INVALID_ARGUMENT", "--plan is required (or --example NAME to print a sample plan)")
    if not args.config:
        with tempfile.TemporaryDirectory(prefix="nifimcp-draft-") as tmp:
            return _draft(args, Service(Session(_demo_config(Path(tmp)))))
    return _draft(args, _session(args.config))


def _draft(args, service) -> int:
    plan = json.loads(Path(args.plan).read_text())

    async def go():
        validation = await call_tool(service, "validate_flow_plan", {"plan": plan})
        if validation["status"] == "error" or not validation["data"]["validation"]["valid"]:
            return {"validation": validation}
        draft = await call_tool(service, "draft_flow", {"plan": plan})
        if args.output and draft["status"] != "error":
            out = Path(args.output)
            out.mkdir(parents=True, exist_ok=True)
            for key, item in draft["data"]["artifacts"].items():
                rec = service.s.store.get(item["artifact_id"], service.s.session_id)
                (out / Path(rec.relpath).name.replace("flow.json", f"{key}.json")).write_bytes(
                    service.s.store.path_of(rec).read_bytes())
        return {"validation": validation, "draft": draft}
    result = anyio.run(go)
    _print(result)
    ok = result.get("draft", {}).get("status") not in (None, "error")
    return EXIT_OK if ok else EXIT_FINDINGS


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="nifimcp", description="NiFiMCP: an independent MCP server for Apache NiFi.")
    p.add_argument("--version", action="version", version=f"nifimcp {__version__}")
    sub = p.add_subparsers(dest="command", required=True)
    d = sub.add_parser("demo", help="run the offline demo (no NiFi, model or network)")
    d.add_argument("--output", required=True)
    d.set_defaults(func=cmd_demo)
    d = sub.add_parser("doctor", help="check configuration, workspace and (live) connectivity")
    d.add_argument("--config", required=True)
    d.set_defaults(func=cmd_doctor)
    d = sub.add_parser("serve", help="serve MCP over stdio")
    d.add_argument("--config", required=True)
    d.set_defaults(func=cmd_serve)
    d = sub.add_parser("register", help="register an offline bundle or flow definition (bundle mode)")
    d.add_argument("--config", required=True)
    d.add_argument("--kind", choices=("bundle", "flow_definition"), required=True)
    d.add_argument("--label", default="")
    d.add_argument("path")
    d.set_defaults(func=cmd_register)
    d = sub.add_parser("unregister", help="remove a registered bundle or flow definition (bundle mode)")
    d.add_argument("--config", required=True)
    d.add_argument("artifact_id")
    d.set_defaults(func=cmd_unregister)
    d = sub.add_parser("capabilities", help="print get_capabilities")
    d.add_argument("--config", required=True)
    d.set_defaults(func=cmd_tool("get_capabilities", lambda a: {}))
    d = sub.add_parser("describe", help="describe a scope")
    d.add_argument("--config", required=True)
    d.add_argument("--scope", required=True)
    d.add_argument("--depth", type=int, default=4)
    d.set_defaults(func=cmd_tool("describe_flow", lambda a: {"scope_id": a.scope, "depth": a.depth}))
    d = sub.add_parser("investigate", help="health, optional trace and unmatched inspection")
    d.add_argument("--config", required=True)
    d.add_argument("--scope", required=True)
    d.add_argument("--start")
    d.add_argument("--end")
    d.add_argument("--trace-uuid")
    d.add_argument("--trace-filename")
    d.add_argument("--unmatched", help="connection id")
    d.add_argument("--sample", action="store_true", help="request queue metadata sampling")
    d.add_argument("--html", help="write the investigation report here")
    d.set_defaults(func=cmd_investigate)
    d = sub.add_parser("report", help="describe + health and write an HTML report")
    d.add_argument("--config", required=True)
    d.add_argument("--scope", required=True)
    d.add_argument("--depth", type=int, default=4)
    d.add_argument("--start", help="health interval start (RFC 3339); default: 60 minutes before collection or now")
    d.add_argument("--end", help="health interval end (RFC 3339)")
    d.add_argument("--output", required=True)
    d.set_defaults(func=cmd_report)
    d = sub.add_parser("draft", help="validate a FlowPlan JSON file and compile a stopped local draft")
    d.add_argument("--config")
    d.add_argument("--plan")
    d.add_argument("--example", help="print a sample FlowPlan: attribute_router or json_field_gate")
    d.add_argument("--output")
    d.set_defaults(func=cmd_draft)
    d = sub.add_parser("catalog", help="print the pinned processor catalog")
    d.add_argument("--type", help="exact processor type, e.g. RouteOnAttribute")
    d.set_defaults(func=cmd_catalog)
    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except NiFiMCPError as err:
        sys.stderr.write(json.dumps({"error": err.as_dict()}) + "\n")
        return EXIT_ERROR
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
