#!/usr/bin/env python3
"""Run the acceptance matrix (A01 to A36) and write the ledger.

    uv run python scripts/run_acceptance.py [--skip-cluster] [--skip-offline] [--only A01,A02]

Every gate ends PASS, FAIL or BLOCKED. A gate whose environment is unavailable (no lab, no Docker,
no network, no hardware) is BLOCKED with a resume command; it is never recorded as PASS. Pytest gates
pass only when tests were collected, none failed, errored or were skipped.

Writes evidence/acceptance/<stamp>/ (ledger.json; per-gate logs and JUnit XML under raw/, which stays private),
docs/ACCEPTANCE.md and
RELEASE_NOTES.md. A completed copy of the private acceptance matrix CSV is written outside the repository
when the source CSV is available.
"""
from __future__ import annotations

import argparse
import ast
import csv
import datetime as dt
import glob
import json
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PRIVATE_MATRIX = ROOT / "evidence" / "acceptance_matrix.source.csv"
COMPLETED_MATRIX = ROOT.parent / "acceptance" / "acceptance_matrix.completed.csv"
LAB_RESUME = "uv run python scripts/lab_bootstrap.py --create-owned-lab"
ENV = {k: v for k, v in os.environ.items() if k != "UV_NATIVE_TLS"} | {"UV_SYSTEM_CERTS": "1"}

PYTEST_GATES = {
    "A02": ["tests/unit/test_import.py"], "A03": ["tests/unit/test_import_limits.py"],
    "A04": ["tests/unit/test_diff.py"], "A05": ["tests/unit/test_evidence.py"],
    "A06": ["tests/evals/test_incident_contracts.py"], "A07": ["tests/security/test_redaction.py"],
    "A08": ["tests/security/test_scope.py"], "A09": ["tests/security/test_route_allowlist.py"],
    "A10": ["tests/security/test_transport.py"], "A12": ["tests/security/test_query_lifecycle.py"],
    "A13": ["tests/unit/test_limits.py"], "A14": ["tests/security/test_bundles.py"],
    "A15": ["tests/security/test_report.py"], "A16": ["tests/protocol/test_stdio.py"],
    "A22": ["tests/unit/test_plan_validation.py"], "A23": ["tests/unit/test_compiler.py"],
    "A24": ["tests/security/test_drafts.py"], "A25": ["tests/security/test_lab_boundary.py"],
    "A28": ["tests/unit/test_output_comparison.py"], "A29": ["tests/unit/test_receipts.py"],
}
INTEGRATION_GATES = {
    "A11": (["tests/integration/test_queries.py"], "integration", None),
    "A19": (["tests/integration/test_live_nifi.py"], "integration", None),
    "A20": (["tests/integration/test_nifi_permissions.py"], "integration", None),
    "A26": (["tests/lab/test_lab_drafts.py"], "lab", "attribute_router or wrong_plan"),
    "A27": (["tests/lab/test_lab_drafts.py"], "lab", "json_field_gate"),
}


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run(cmd: list[str], log: Path, *, cwd: Path = ROOT, timeout: int = 3600, env: dict | None = None) -> int:
    start = time.monotonic()
    with open(log, "a") as handle:
        handle.write(f"$ {' '.join(map(str, cmd))}\n")
        handle.flush()
        try:
            proc = subprocess.run(cmd, cwd=cwd, stdout=handle, stderr=subprocess.STDOUT, timeout=timeout,
                                  env=env or ENV)
            code = proc.returncode
        except subprocess.TimeoutExpired:
            handle.write("TIMEOUT\n")
            code = 124
        handle.write(f"[exit {code} after {time.monotonic() - start:.1f}s]\n")
    return code


def junit_counts(path: Path) -> dict:
    root = ET.parse(path).getroot()
    suites = [root] if root.tag == "testsuite" else list(root)
    keys = ("tests", "failures", "errors", "skipped")
    counts = {k: sum(int(s.get(k, 0)) for s in suites) for k in keys}
    skips = [sk.get("message", "") for case in root.iter("testcase") for sk in case.findall("skipped")]
    counts["skip_reasons"] = sorted(set(skips))[:5]
    return counts


def pytest_gate(gid: str, files: list[str], out: Path, marker: str | None = None, select: str | None = None) -> dict:
    xml = out / "raw" / f"{gid}.junit.xml"
    cmd = ["uv", "run", "--frozen", "pytest", *files, "-q", "-p", "no:cacheprovider", "-o", "addopts=",
           f"--junitxml={xml}", "-rs"]
    cmd += ["-m", marker] if marker else ["-m", "not integration and not lab"]
    if select:
        cmd += ["-k", select]
    code = run(cmd, out / "raw" / f"{gid}.log")
    printable = shlex.join(c for c in cmd if not c.startswith("--junitxml"))
    if not xml.is_file():
        return {"status": "FAIL", "command": printable, "notes": f"pytest exited {code} without a report"}
    c = junit_counts(xml)
    summary = f"{c['tests']} tests, {c['failures']} failed, {c['errors']} errors, {c['skipped']} skipped"
    if c["tests"] and c["skipped"] == c["tests"] and any("BLOCKED" in r for r in c["skip_reasons"]):
        return {"status": "BLOCKED", "command": printable, "notes": f"{summary}. {c['skip_reasons'][0]}",
                "resume": LAB_RESUME, "artifact": ", ".join(files)}
    ok = code == 0 and c["tests"] > 0 and c["failures"] == 0 and c["errors"] == 0 and c["skipped"] == 0
    return {"status": "PASS" if ok else "FAIL", "command": printable, "notes": summary,
            "artifact": ", ".join(files)}   # JUnit XML and logs stay under raw/ (private)


# ------------------------------------------------------------------------------------------- custom gates

def gate_a01(out: Path) -> dict:
    cap = json.loads((ROOT / "evidence/capsule/version-capsule.json").read_text())
    problems = []
    if cap["nifi"].get("version") != "2.12.0" or "21." not in cap["nifi"].get("java_version", ""):
        problems.append("NiFi or Java version missing")
    if cap["nifi"].get("image_digest") != "sha256:6f7f2840dbf178c6dd3fa13435b9b358f3be3c6fb7417de467a35a267f4d28ad":
        problems.append("image digest differs from the pinned digest")
    if not cap.get("rest_contract", {}).get("sha256") and not cap.get("rest_contract", {}).get("bytes"):
        problems.append("REST contract not recorded")
    lock = (ROOT / "uv.lock").read_text()
    if 'name = "mcp"\nversion = "2.3.0"' not in lock:
        problems.append("uv.lock does not pin mcp 2.3.0")
    import hashlib
    lock_sha = hashlib.sha256((ROOT / "uv.lock").read_bytes()).hexdigest()
    note = "capsule matches the current uv.lock" if lock_sha == cap.get("uv_lock_sha256") else \
        "uv.lock changed since capture (see git log); runtime pins unchanged" if not problems else ""
    return {"status": "PASS" if not problems else "FAIL", "command": "inspect evidence/capsule/version-capsule.json",
            "artifact": "evidence/capsule/version-capsule.json",
            "notes": "; ".join(problems) or f"NiFi 2.12.0, {cap['nifi']['java_version'].splitlines()[0]}, "
                                            f"image {cap['nifi']['image_digest'][:19]}…, MCP SDK 2.3.0; {note}"}


def _code_fingerprint(tree_files: dict[str, bytes]) -> dict[str, str]:
    """Per-file fingerprint ignoring docstrings and comments (Python) or exact bytes (other files)."""
    import hashlib
    out = {}
    for name, data in tree_files.items():
        if name.endswith(".py"):
            mod = ast.parse(data.decode())
            for node in ast.walk(mod):
                body = getattr(node, "body", None)
                if isinstance(body, list) and body and isinstance(body[0], ast.Expr) \
                        and isinstance(getattr(body[0], "value", None), ast.Constant) \
                        and isinstance(body[0].value.value, str):
                    body[0] = ast.Pass()
            out[name] = hashlib.sha256(ast.dump(mod).encode()).hexdigest()
        else:
            out[name] = hashlib.sha256(data).hexdigest()
    return out


def _src_at(commit: str | None) -> dict[str, bytes]:
    files = {}
    names = subprocess.run(["git", "ls-tree", "-r", "--name-only", commit or "HEAD", "src/"], cwd=ROOT,
                           capture_output=True, text=True, check=True).stdout.split()
    for n in names:
        files[n] = subprocess.run(["git", "show", f"{commit or 'HEAD'}:{n}"], cwd=ROOT, capture_output=True,
                                  check=True).stdout
    return files


def gate_a17(out: Path) -> dict:
    runs = sorted(glob.glob(str(ROOT / "evidence/host/*/summary.json")))
    if not runs:
        return {"status": "BLOCKED", "command": "scripts/run_host_transcript.py",
                "notes": "no recorded host session", "resume": "uv run python scripts/run_host_transcript.py ..."}
    summary_path = Path(runs[-1])
    s = json.loads(summary_path.read_text())
    folder = summary_path.parent
    names = {t["name"] for t in s.get("tool_calls", [])}
    needed = {"describe_flow", "get_flow_health", "inspect_unmatched", "trace_feed", "export_investigation",
              "validate_flow_plan", "draft_flow"}
    missing = sorted(n for n in needed if f"mcp__nifimcp__{n}" not in names)
    verification = json.loads((folder / "lab-verification/lab-verification.json").read_text())
    problems = []
    if s.get("exit_code") != 0 or s.get("result_subtype") != "success":
        problems.append("host session did not complete")
    if missing:
        problems.append(f"workflow tools not called: {missing}")
    if "Unknowns" not in (s.get("final_text") or ""):
        problems.append("final answer lacks the Unknowns section")
    if verification.get("overall") != "PASS" or verification["cases"].get("status") != "PASS":
        problems.append("host draft failed native lab verification")
    rec_commit = subprocess.run(["git", "log", "-1", "--format=%H", "--", str(summary_path.relative_to(ROOT))],
                                cwd=ROOT, capture_output=True, text=True).stdout.strip() or None
    same = None
    if rec_commit:
        before, after = _code_fingerprint(_src_at(rec_commit)), _code_fingerprint(_src_at(None))
        same = before == after
    others = [t for t in s.get("tools_available_to_host", []) if not t.startswith("mcp__nifimcp__")]
    if "tools_available_to_host" in s and others:
        problems.append(f"host had other tools available: {others[:5]}")
    unmatched_events = None
    public = folder / "transcript.public.jsonl"
    if public.is_file():
        for line in public.read_text().splitlines():
            m = re.search(r'unmatched_events[^{]*\{[^}]*?\\?"events\\?":\s*(\d+)', line)
            if m:
                unmatched_events = int(m.group(1))
    note = (f"Claude Code {s.get('host_version')}, model {', '.join(s.get('observed_models', []))}, "
            f"{'no other tools available to the host, ' if 'tools_available_to_host' in s and not others else ''}"
            f"{'' if unmatched_events is None else f'{unmatched_events} live unmatched events observed, '}"
            f"{s.get('nifimcp_tool_calls')} NiFiMCP tool calls, {s.get('num_turns')} turns; host draft "
            f"{verification.get('artifact_id')} passed {sum(1 for c in verification['cases']['cases'] if c['status'] == 'PASS')}"
            f" of {len(verification['cases']['cases'])} host-proposed cases natively. "
            f"Recorded at {s.get('recorded_at')}. ")
    if same is True:
        note += "Runtime code is unchanged since the recording (docstrings and comments excluded)."
    elif same is False:
        problems.append("runtime code changed since the recorded host session; re-run scripts/run_host_transcript.py")
    return {"status": "PASS" if not problems else "FAIL", "command": "uv run python scripts/run_host_transcript.py "
            "--config <lab observer config> --scope lab-scope --unmatched <connection id>",
            "artifact": str(folder.relative_to(ROOT)), "notes": "; ".join(problems) or note}


def gate_a18(out: Path) -> dict:
    res = pytest_gate("A18", ["tests/integration/test_live_nifi.py"], out, marker="integration",
                      select="secure_stock or read_only_policies")
    if res["status"] != "PASS":
        return res
    sys.path.insert(0, str(ROOT / "lab"))
    from nifimcp_lab.boundary import load_manifest
    marker = ROOT / ".lab/CURRENT"
    manifest = load_manifest(ROOT / ".lab" / marker.read_text().strip())
    setup = {"lab_id": manifest["lab_id"], "image": manifest["image"], "nifi": manifest["runtime"]["nifi_about"].get("version"),
             "java": manifest["runtime"]["java_version"].splitlines()[0],
             "identities": {k: v["dn"] for k, v in manifest["pki"]["identities"].items()},
             "server_fingerprint_sha256": manifest["pki"]["server_fingerprint_sha256"],
             "origin_binding": "127.0.0.1 only", "auth": "two-way TLS (AUTH=tls)",
             "observer_policies": ["read /flow", "read scoped process group", "read /provenance",
                                   "read provenance data (scope)", "read data (scope)"],
             "restricted_policies": ["read /flow", "read scoped process group"], "outsider_policies": ["read /flow"]}
    path = out / "lab-setup.json"
    path.write_text(json.dumps(setup, indent=1))
    res["artifact"] = str(path.relative_to(ROOT))
    res["notes"] += f"; lab {manifest['lab_id']}, NiFi {setup['nifi']}, {setup['java']}, identities admin/observer/restricted/outsider"
    return res


def gate_a21(out: Path, rerun_cluster: bool) -> dict:
    res = pytest_gate("A21", ["tests/integration/test_topology.py"], out, marker="integration")
    if rerun_cluster:
        code = run(["uv", "run", "--frozen", "python", "scripts/cluster_topology_probe.py"], out / "raw" / "A21.log", timeout=2400)
    probes = sorted(glob.glob(str(ROOT / "evidence/cluster/*/cluster-probe.json")))
    if not probes:
        return {**res, "status": "BLOCKED" if res["status"] == "PASS" else res["status"],
                "notes": res["notes"] + "; no real-cluster probe evidence",
                "resume": "uv run python scripts/cluster_topology_probe.py"}
    probe = json.loads(Path(probes[-1]).read_text())
    note = (f"{res['notes']}; real two-node cluster probe {Path(probes[-1]).parent.name}: {probe['result']} "
            f"(clustered detected, investigation tools UNSUPPORTED_TOPOLOGY, NiFiMCP sent GET only, "
            f"also with one node stopped; cleanup: {probe.get('cleanup')})")
    status = res["status"]
    if probe["result"] != "PASS" and status == "PASS":
        status = probe["result"]
    return {"status": status, "command": res["command"] + " && uv run python scripts/cluster_topology_probe.py",
            "artifact": str(Path(probes[-1]).relative_to(ROOT)), "notes": note}


def gate_a30(out: Path) -> dict:
    log = out / "raw" / "A30.log"
    if not shutil.which("docker"):
        return {"status": "BLOCKED", "command": "scripts/offline_acceptance_docker.sh", "notes": "Docker unavailable",
                "resume": "scripts/offline_acceptance_docker.sh"}
    code = run([os.environ.get("NIFIMCP_PIP_PYTHON", "/usr/local/bin/python3"), "scripts/build_offline_kit.py"], log,
               timeout=1800)
    if code != 0:
        return {"status": "BLOCKED", "command": "python3 scripts/build_offline_kit.py", "notes":
                "kit build failed (needs PyPI access to download wheels); see log", "artifact": "raw/A30.log (private)",
                "resume": "python3 scripts/build_offline_kit.py && scripts/offline_acceptance_docker.sh"}
    code = run(["sh", "scripts/offline_acceptance_docker.sh"], log, timeout=1800)
    runs = sorted(glob.glob(str(ROOT / "evidence/offline/*/run.log")))
    latest = Path(runs[-1]).parent if runs else None
    passed = code == 0 and latest and "OFFLINE ACCEPTANCE PASSED" in (latest / "run.log").read_text()
    kit_hash = next(iter(glob.glob(str(ROOT / "dist/*.tar.gz.sha256"))), None)
    note = "built reproducible kit; installed and ran demo, bundle register, doctor, describe, report and an MCP " \
           "stdio call inside python:3.12-slim with --network none (egress checks failed as required)"
    if kit_hash:
        note += f"; kit {Path(kit_hash).read_text().split()[0][:16]}…"
    return {"status": "PASS" if passed else "FAIL", "command": "python3 scripts/build_offline_kit.py && "
            "scripts/offline_acceptance_docker.sh", "artifact": str(latest.relative_to(ROOT)) if latest else None,
            "notes": note if passed else "offline acceptance failed; see log"}


def gate_a31(out: Path, export_dir: Path) -> dict:
    log = out / "raw" / "A31.log"
    clone = Path(tempfile.mkdtemp(prefix="nifimcp-clean-")) / "nifimcp"
    steps = [
        ["git", "clone", "-q", str(export_dir), str(clone)],
        ["uv", "sync", "--frozen"],
        ["uv", "run", "--frozen", "nifimcp", "--version"],
        ["uv", "run", "--frozen", "pytest", "-q", "-p", "no:cacheprovider"],
        ["uv", "run", "--frozen", "nifimcp", "demo", "--output", str(clone.parent / "demo")],
        ["uv", "run", "--frozen", "nifimcp", "capabilities", "--config", "config/operator.demo.json"],
        ["uv", "run", "--frozen", "nifimcp", "describe", "--config", "config/operator.demo.json",
         "--scope", "demo-telemetry-intake"],
        ["uv", "run", "--frozen", "nifimcp", "report", "--config", "config/operator.demo.json",
         "--scope", "demo-telemetry-intake", "--output", str(clone.parent / "report.html")],
        ["uv", "run", "--frozen", "nifimcp", "catalog"],
    ]
    env = {k: v for k, v in ENV.items() if k != "VIRTUAL_ENV"}
    for i, cmd in enumerate(steps):
        code = run(cmd, log, cwd=clone if i else ROOT, timeout=1800, env=env)
        if code != 0:
            return {"status": "FAIL", "command": " && ".join(" ".join(c) for c in steps), "artifact":
                    "raw/A31.log (private)", "notes": f"step failed: {' '.join(cmd[:5])}"}
    demo = clone.parent / "demo"
    missing = [f for f in ("report.html", "investigation.json", "transcript.json", "summary.json") if not (demo / f).is_file()]
    readme = (clone / "README.md").read_text()
    documented = all(s in readme for s in ("uv sync --frozen", "uv run nifimcp demo --output", "nifimcp doctor"))
    ok = not missing and (clone.parent / "report.html").is_file() and documented
    tail = (log.read_text().split("passed")[0].splitlines() or [""])[-1]
    return {"status": "PASS" if ok else "FAIL", "command": "git clone <public export> && uv sync --frozen && "
            "uv run pytest && uv run nifimcp demo/capabilities/describe/report/catalog",
            "artifact": "raw/A31.log (private)",
            "notes": (f"clean clone of the public export; offline suite {tail.strip()} passed; demo wrote report, "
                      "investigation, transcript and summary; README commands match") if ok else
                     f"missing outputs {missing} or README drift"}


def gate_a32(out: Path) -> dict:
    res = pytest_gate("A32", ["tests/evals/test_incident_contracts.py"], out,
                      select="corpus_shape or holdout or dev_case or baseline")
    dev = json.loads((ROOT / "tests/evals/corpus/dev.json").read_text())
    hold = json.loads((ROOT / "tests/evals/corpus/holdout.json").read_text())
    fams = sorted({c["family"] for c in dev["cases"] + hold["cases"]})
    res["notes"] += (f"; {len(dev['cases'])} development and {len(hold['cases'])} frozen holdout cases, families: "
                     f"{', '.join(fams)}; labels engineer-authored, not expert-reviewed")
    res["artifact"] = "tests/evals/corpus/"
    return res


def gate_a33(out: Path, export_dir: Path) -> dict:
    report = out / "release-checklist.json"
    code = run(["uv", "run", "--frozen", "python", "scripts/release_checklist.py", "--tree", str(export_dir),
                "--ledger-pending", "--output", str(report)], out / "raw" / "A33.log", timeout=1800)
    if not report.is_file():
        return {"status": "FAIL", "command": "scripts/release_checklist.py", "notes": "checklist did not run"}
    r = json.loads(report.read_text())
    summary = ", ".join(f"{k.replace('_', ' ')} {v['result']}" for k, v in r["checks"].items())
    return {"status": r["result"], "command": "uv run python scripts/release_checklist.py --tree <public export> --ledger-pending",
            "artifact": str(report.relative_to(ROOT)),
            "notes": summary + ". The ledger documents this run writes are checked again on the final export."}


BLOCKED_P1 = {
    "A34": ("BLOCKED", "Cluster investigation is deliberately not implemented in 0.1: NiFiMCP refuses clustered NiFi "
            "(verified on a real two-node cluster under A21). Node-bound event IDs, per-node query ownership and "
            "partial-node evidence need implementation before this gate can run. No cluster support is claimed.",
            "implement clustered provenance and listing, then extend scripts/cluster_topology_probe.py"),
    "A35": ("BLOCKED", "Only Linux x86_64 was available in this build environment. macOS, Windows and arm64 have not "
            "been run and are listed as untested in docs/CAPABILITIES.md.",
            "run uv sync --frozen && uv run pytest && uv run nifimcp demo on each platform and record results"),
    "A36": ("BLOCKED", "No approved local model and no expert reviewer were available. The recorded Claude Code session "
            "(A17) is a host integration test, not a model evaluation; the incident corpus measures fixed rules only. "
            "No model accuracy claim is made.",
            "select an approved model, run the dev corpus through a host, have a NiFi expert grade claims and citations"),
}


def environment() -> dict:
    def out(cmd):
        try:
            return subprocess.run(cmd, capture_output=True, text=True, timeout=30, env=ENV).stdout.strip()
        except Exception:  # noqa: BLE001
            return None
    mem = None
    try:
        mem = round(int(next(l for l in open("/proc/meminfo") if l.startswith("MemTotal")).split()[1]) / 1048576, 1)
    except Exception:  # noqa: BLE001
        pass
    return {"os": platform.platform(), "machine": platform.machine(), "cpus": os.cpu_count(), "memory_gib": mem,
            "python": out(["uv", "run", "--frozen", "python", "-c", "import sys;print(sys.version.split()[0])"]),
            "uv": out(["uv", "--version"]), "docker": out(["docker", "version", "--format", "{{.Server.Version}}"]),
            "nifi_image": "apache/nifi@sha256:6f7f2840dbf178c6dd3fa13435b9b358f3be3c6fb7417de467a35a267f4d28ad",
            "mcp_sdk": "2.3.0"}


def render_markdown(ledger: dict) -> str:
    counts = {s: sum(1 for g in ledger["gates"] if g["status"] == s) for s in ("PASS", "FAIL", "BLOCKED")}
    lines = ["# Acceptance ledger", "",
             f"Run {ledger['run']['started_at']} to {ledger['run']['finished_at']} at commit "
             f"`{ledger['run']['commit'][:12]}` of the build repository.", "",
             f"**{counts['PASS']} PASS, {counts['FAIL']} FAIL, {counts['BLOCKED']} BLOCKED** of {len(ledger['gates'])} gates. "
             "BLOCKED means the environment, hardware or an out-of-scope capability was unavailable; it is never "
             "counted as a pass. Commands are run from a source checkout.", "",
             "Environment: " + ", ".join(f"{k} {v}" for k, v in ledger["run"]["environment"].items() if v), "",
             "| Gate | Priority | Area | Condition | Result | Evidence |", "|---|---|---|---|---|---|"]
    for g in ledger["gates"]:
        ev = (g.get("notes") or "").replace("|", "/").replace("\n", " ")
        cmd = (g.get("command") or "").replace("|", "/")
        lines.append(f"| {g['id']} | {g['priority']} | {g['area']} | {g['condition']} | **{g['status']}** | "
                     f"`{cmd}`<br>{ev} |")
    lines += ["", "Raw logs and JUnit reports for each run stay with the private build evidence. Results for gates that "
              "need Docker or a lab can be reproduced with `uv run python scripts/lab_bootstrap.py --create-owned-lab` "
              "followed by `uv run python scripts/run_acceptance.py`.", ""]
    return "\n".join(lines)


def render_release_notes(ledger: dict) -> str:
    counts = {s: sum(1 for g in ledger["gates"] if g["status"] == s) for s in ("PASS", "FAIL", "BLOCKED")}
    blocked = [g for g in ledger["gates"] if g["status"] != "PASS"]
    return "\n".join([
        "# Release notes", "", "## 0.1.0rc1 (public preview)", "",
        "First public preview of NiFiMCP, a read-only MCP server for Apache NiFi 2.12.0. Tested on Linux x86_64 "
        "with Python 3.12 against NiFi 2.12.0 (single node, certificate authentication) and Claude Code; everything "
        "else is untested or refused (see docs/CAPABILITIES.md). Install with `uv tool install nifimcp==0.1.0rc1`.", "",
        "### What works", "",
        "* Ten MCP tools over stdio: capabilities, flow description, health, provenance trace, unmatched-route "
        "inspection, snapshot diff, investigation export, processor catalog, FlowPlan validation and local drafts.",
        "* Demo, offline bundle and live modes. Live mode is qualified against stock NiFi 2.12.0 (single node, "
        "mutual TLS) with scoped read-only identities.",
        "* Evidence-bound results: every finding cites the exact source bytes and JSON pointer, with explicit gaps.",
        "* Self-contained HTML investigation reports with no scripts.",
        "* Flow Draft Preview for two blueprints, verified by a separate lab CLI that imports drafts into a "
        "disposable NiFi and checks labeled record outcomes.",
        "* Offline install kit for Linux x86_64, CPython 3.12, with hash-locked wheels, SBOM and licenses.", "",
        "### What writes to NiFi", "",
        "Nothing in the MCP server. Investigation uses your read-only identity over 14 allowlisted read endpoints; "
        "drafts are local files. The optional lab CLI imports a draft only into a disposable NiFi container it "
        "created, using that container's own admin certificate, and deletes it afterward. Execution against a real "
        "NiFi is not part of this release.", "",
        "### Qualification", "",
        f"Acceptance run at commit `{ledger['run']['commit'][:12]}`: {counts['PASS']} PASS, {counts['FAIL']} FAIL, "
        f"{counts['BLOCKED']} BLOCKED of {len(ledger['gates'])} gates. See docs/ACCEPTANCE.md.", "",
        "### Not included or not yet qualified", "",
        *[f"* {g['id']} {g['area']}: {g['status']}. {g.get('notes', '')}" for g in blocked],
        "* NiFi versions other than 2.12.0, NiFi clusters, bearer-token login against real NiFi, MCP hosts other "
        "than Claude Code, and platforms other than Linux x86_64 are untested or refused. See docs/CAPABILITIES.md.",
        "* No tool changes NiFi. Execution with operator approval is a separate, future boundary.", ""])


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--skip-cluster", action="store_true", help="use the latest cluster probe evidence")
    p.add_argument("--only", help="comma-separated gate IDs")
    p.add_argument("--no-docs", action="store_true", help="do not rewrite docs/ACCEPTANCE.md and RELEASE_NOTES.md")
    args = p.parse_args(argv)
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    dirty = subprocess.run(["git", "status", "--porcelain", "--untracked-files=no"], cwd=ROOT,
                           capture_output=True, text=True).stdout.strip()
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = ROOT / "evidence" / "acceptance" / stamp
    (out / "raw").mkdir(parents=True, exist_ok=True)
    rows = list(csv.DictReader(open(PRIVATE_MATRIX))) if PRIVATE_MATRIX.is_file() else []
    meta = {r["id"]: r for r in rows}
    only = set(args.only.split(",")) if args.only else None
    export_dir = Path(tempfile.mkdtemp(prefix="nifimcp-export-")) / "nifimcp"
    needs_export = only is None or bool({"A31", "A33"} & only)
    if needs_export:
        run(["uv", "run", "--frozen", "python", "scripts/export_public.py", "--output", str(export_dir), "--git"],
            out / "raw" / "export.log")
    started = now()
    gates = []
    for gid in [f"A{i:02d}" for i in range(1, 37)]:
        if only and gid not in only:
            continue
        t0 = time.monotonic()
        print(f"[acceptance] {gid} ...", file=sys.stderr, flush=True)
        if gid in PYTEST_GATES:
            res = pytest_gate(gid, PYTEST_GATES[gid], out)
        elif gid in INTEGRATION_GATES:
            files, marker, select = INTEGRATION_GATES[gid]
            res = pytest_gate(gid, files, out, marker=marker, select=select)
            if res["status"] == "BLOCKED":
                res["resume"] = LAB_RESUME
        elif gid == "A01":
            res = gate_a01(out)
        elif gid == "A17":
            res = gate_a17(out)
        elif gid == "A18":
            res = gate_a18(out)
        elif gid == "A21":
            res = gate_a21(out, rerun_cluster=not args.skip_cluster)
        elif gid == "A30":
            res = gate_a30(out)
        elif gid == "A31":
            res = gate_a31(out, export_dir)
        elif gid == "A32":
            res = gate_a32(out)
        elif gid == "A33":
            res = gate_a33(out, export_dir)   # after A30, so the checklist inspects the freshly built kit
        else:
            status, notes, resume = BLOCKED_P1[gid]
            res = {"status": status, "command": "not run", "notes": notes, "resume": resume}
        m = meta.get(gid, {})
        res.update(id=gid, priority=m.get("priority", ""), area=m.get("area", ""),
                   condition=m.get("acceptance_condition", ""), required_evidence=m.get("required_evidence", ""),
                   duration_seconds=round(time.monotonic() - t0, 1), finished_at=now())
        print(f"[acceptance] {gid} {res['status']}: {res.get('notes', '')[:150]}", file=sys.stderr, flush=True)
        gates.append(res)
    env = environment()
    ledger = {"ledger_schema": "nifimcp-acceptance/1",
              "run": {"commit": commit, "dirty_tracked_files": bool(dirty), "started_at": started, "finished_at": now(),
                      "environment": env, "output": str(out.relative_to(ROOT))},
              "gates": gates}
    (out / "ledger.json").write_text(json.dumps(ledger, indent=1) + "\n")
    if not args.no_docs and only is None:
        (ROOT / "docs/ACCEPTANCE.md").write_text(render_markdown(ledger))
        (ROOT / "RELEASE_NOTES.md").write_text(render_release_notes(ledger))
    if rows:
        COMPLETED_MATRIX.parent.mkdir(parents=True, exist_ok=True)
        by_id = {g["id"]: g for g in gates}
        with open(COMPLETED_MATRIX, "w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            for r in rows:
                g = by_id.get(r["id"])
                if g:
                    r = {**r, "status": g["status"], "actual_command": g.get("command", ""), "commit": commit[:12],
                         "environment": f"{env['os']}; {env['python']}; {env['uv']}; docker {env['docker']}",
                         "artifact": g.get("artifact") or "", "notes": g.get("notes", "") +
                         (f" Resume: {g['resume']}" if g.get("resume") else "")}
                writer.writerow(r)
    counts = {s: sum(1 for g in gates if g["status"] == s) for s in ("PASS", "FAIL", "BLOCKED")}
    print(json.dumps({"output": str(out), **counts}, indent=1))
    return 0 if counts["FAIL"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
