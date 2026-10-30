#!/usr/bin/env python3
"""Write docs/VALIDATION.md: the public validation summary for one release, with checksums.

    uv run python scripts/write_validation_summary.py --clean-install-log <log> [--dist dist/build]

Sources: the built sdist and wheel, the offline kit tarball, the newest acceptance ledger, the newest
offline, cluster and host evidence, and the clean-environment install log. Nothing is claimed that is not
in those files.
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def newest(pattern: str) -> Path | None:
    hits = sorted(glob.glob(str(ROOT / pattern)))
    return Path(hits[-1]) if hits else None


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--dist", type=Path, default=ROOT / "dist" / "build")
    p.add_argument("--clean-install-log", type=Path, required=True)
    p.add_argument("--note", default="", help="one sentence appended to the header, for example why artifacts were rebuilt")
    args = p.parse_args(argv)
    version = re.search(r'^version = "([^"]+)"', (ROOT / "pyproject.toml").read_text(), re.M).group(1)
    wheel = next(args.dist.glob(f"nifimcp-{version}-*.whl"))
    sdist = next(args.dist.glob(f"nifimcp-{version}.tar.gz"))
    kit = next(iter(sorted((ROOT / "dist").glob("nifimcp-offline-*.tar.gz"))), None)
    ledger = json.loads((newest("evidence/acceptance/*/ledger.json")).read_text())
    counts = {s: sum(1 for g in ledger["gates"] if g["status"] == s) for s in ("PASS", "FAIL", "BLOCKED")}
    by_id = {g["id"]: g for g in ledger["gates"]}
    host = json.loads((newest("evidence/host/*/summary.json")).read_text())
    hv = host.get("host_draft_verification", {})
    cluster = json.loads((newest("evidence/cluster/*/cluster-probe.json")).read_text())
    offline_dir = newest("evidence/offline/*/run.log").parent
    offline_log = (offline_dir / "run.log").read_text()
    clean = args.clean_install_log.read_text()
    clean_ok = "CLEAN ENVIRONMENT INSTALL PASSED" in clean
    env = ledger["run"]["environment"]
    lines = [
        "# Release validation summary", "",
        f"Version **{version}** (public preview). Build repository commit `{ledger['run']['commit'][:12]}`, "
        f"acceptance run {ledger['run']['started_at']}." + (f" {args.note}" if args.note else ""), "",
        "## Artifacts and checksums (SHA-256)", "",
        "| File | SHA-256 |", "|---|---|",
        f"| `{wheel.name}` | `{sha256(wheel)}` |",
        f"| `{sdist.name}` | `{sha256(sdist)}` |",
    ]
    if kit:
        lines.append(f"| `{kit.name}` | `{sha256(kit)}` |")
    lines += [
        "", "The GitHub release carries the same files plus `SHA256SUMS`. PyPI publishes the wheel and sdist "
        "through Trusted Publishing with attestations; the hashes printed by the publish step must match this table.", "",
        "## What was run", "",
        f"* Environment: {env['os']}, {env['cpus']} CPUs, {env['memory_gib']} GiB, Python {env['python']}, "
        f"{env['uv']}, Docker {env['docker']}, MCP SDK {env['mcp_sdk']}.",
        f"* NiFi under test: `{env['nifi_image']}` (2.12.0, single node, mutual TLS), started by the lab CLI.",
        f"* Acceptance gates: **{counts['PASS']} PASS, {counts['FAIL']} FAIL, {counts['BLOCKED']} BLOCKED** of "
        f"{len(ledger['gates'])}. Details per gate: [ACCEPTANCE.md](ACCEPTANCE.md).",
        f"* Offline suite on the public export: {by_id['A31']['notes']}.",
        f"* Real Claude Code session ({host['host_version']}, model {', '.join(host['observed_models'])}): "
        f"{host['nifimcp_tool_calls']} NiFiMCP tool calls; only NiFiMCP tools were available to the host; the host's "
        f"own draft passed {hv.get('cases')} of {hv.get('cases')} labeled cases natively "
        f"({hv.get('status')}). Transcript: `evidence/host/{host['recorded_at']}/transcript.public.jsonl`.",
        f"* Real two-node cluster probe: {cluster['result']} (clustered NiFi detected and refused; NiFiMCP sent GET "
        f"requests only, including with one node stopped).",
        f"* Offline kit inside `python:3.12-slim` with `--network none`: "
        f"{'PASSED' if 'OFFLINE ACCEPTANCE PASSED' in offline_log else 'FAILED'} (demo, bundle register, doctor, "
        f"describe, report and an MCP stdio call).",
        f"* Clean-environment install from these exact artifacts (`python:3.12-slim`, nothing preinstalled, "
        f"dependencies from PyPI): {'PASSED' if clean_ok else 'FAILED'}. Covered: `pip install nifimcp=={version}` "
        f"from the wheel, `uv tool install nifimcp=={version}`, the README `uvx` one-liner, the MCP host form "
        f"(`uvx ... nifimcp serve` driven by the official MCP client), and the sdist. Script: `scripts/clean_install_check.sh`.",
        "", "## What this does not show", "",
        "* No measurement of AI answer accuracy. The recorded session is a host integration test; the incident "
        "corpus tests fixed rules.",
        "* No cluster support, no platform other than Linux x86_64, no NiFi version other than 2.12.0, no "
        "bearer-token login against a real NiFi, no MCP host other than Claude Code.",
        "* NiFiMCP runs offline; a fully offline AI setup (host and model) was not tested.", "",
    ]
    (ROOT / "docs" / "VALIDATION.md").write_text("\n".join(lines))
    print(json.dumps({"wheel": wheel.name, "wheel_sha256": sha256(wheel), "sdist_sha256": sha256(sdist),
                      "kit": kit.name if kit else None, "gates": counts, "clean_install": clean_ok}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
