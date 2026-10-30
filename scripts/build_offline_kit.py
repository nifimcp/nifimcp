#!/usr/bin/env python3
"""Build the offline install kit for Linux x86_64, CPython 3.12 (acceptance gate A30).

    uv run python scripts/build_offline_kit.py [--output dist]

Produces dist/nifimcp-offline-<version>-linux-x86_64-cp312/ and a .tar.gz of it containing:
  wheelhouse/          the project wheel and every locked runtime dependency (binary wheels only)
  requirements.lock    uv-exported runtime lock with sha256 hashes
  SHA256SUMS           hashes of every file in the kit
  LICENSES/            license files shipped inside each wheel
  sbom.cdx.json        CycloneDX 1.5 SBOM of the runtime closure
  install.sh verify.sh offline_acceptance.sh INSTALL.md
  examples/            a synthetic bundle and a bundle-mode operator config

Building needs network access to PyPI. Installing and running the kit does not.
"""
from __future__ import annotations

import argparse
import datetime as dt
import email.parser
import gzip
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tomllib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLATFORMS = ["manylinux_2_17_x86_64", "manylinux2014_x86_64", "manylinux_2_28_x86_64", "linux_x86_64"]
LICENSE_HINTS = ("license", "licence", "copying", "notice", "authors")


def sh(cmd, **kw):
    print("+", " ".join(map(str, cmd)), file=sys.stderr)
    proc = subprocess.run(cmd, text=True, capture_output=True, **kw)
    if proc.returncode:
        sys.stderr.write(proc.stdout[-4000:] + proc.stderr[-4000:])
        raise SystemExit(f"command failed with exit status {proc.returncode}")
    return proc.stdout


def pip_python() -> str:
    """An interpreter with pip available; pip only downloads here, it never installs into it."""
    for cand in (os.environ.get("NIFIMCP_PIP_PYTHON"), sys.executable, shutil.which("python3")):
        if cand and subprocess.run([cand, "-m", "pip", "--version"], capture_output=True).returncode == 0:
            return cand
    raise SystemExit("no interpreter with pip found; set NIFIMCP_PIP_PYTHON")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def wheel_metadata(whl: Path) -> dict:
    with zipfile.ZipFile(whl) as z:
        meta_name = next(n for n in z.namelist() if n.endswith(".dist-info/METADATA"))
        msg = email.parser.Parser().parsestr(z.read(meta_name).decode("utf-8", "replace"), headersonly=True)
        licenses = [n for n in z.namelist() if ".dist-info/" in n and not n.endswith("/")
                    and any(h in n.rsplit("/", 1)[-1].lower() for h in LICENSE_HINTS)]
    return {"name": msg["Name"], "version": msg["Version"], "license_expression": msg.get("License-Expression"),
            "license": (msg.get("License") or "").strip()[:200] or None,
            "classifiers": [c for c in msg.get_all("Classifier") or [] if c.startswith("License ::")],
            "license_files": licenses}


def extract_licenses(whl: Path, files: list[str], dest: Path) -> list[str]:
    out = []
    with zipfile.ZipFile(whl) as z:
        for name in files:
            target = dest / name.split(".dist-info/", 1)[1]
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(z.read(name))
            out.append(str(target))
    return out


def sbom(components: list[dict], project: dict, created: str) -> dict:
    def comp(c, scope="required"):
        lic = []
        if c["license_expression"]:
            lic = [{"expression": c["license_expression"]}]
        elif c["license"] and len(c["license"]) < 80:
            lic = [{"license": {"name": c["license"]}}]
        elif c["classifiers"]:
            lic = [{"license": {"name": c["classifiers"][0].split("::")[-1].strip()}}]
        return {"type": "library", "bom-ref": f"pkg:pypi/{c['name'].lower()}@{c['version']}",
                "name": c["name"], "version": c["version"], "purl": f"pkg:pypi/{c['name'].lower()}@{c['version']}",
                "scope": scope, "licenses": lic, "hashes": [{"alg": "SHA-256", "content": c["sha256"]}],
                "properties": [{"name": "nifimcp:wheel", "value": c["file"]}]}
    vendored = []
    for d in sorted((ROOT / "third_party").iterdir()):
        if d.is_dir():
            vendored.append({"type": "library", "bom-ref": f"vendored:{d.name}", "name": d.name, "scope": "excluded",
                             "properties": [{"name": "nifimcp:note",
                                             "value": "unmodified upstream source kept for regression tests; "
                                                      "not installed by the wheel"}]})
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "metadata": {"timestamp": created, "tools": {"components": [{"type": "application",
                                                                         "name": "nifimcp build_offline_kit.py"}]},
                         "component": comp(project, scope="required") | {"type": "application"}},
            "components": [comp(c) for c in components] + vendored,
            "dependencies": [{"ref": f"pkg:pypi/{project['name'].lower()}@{project['version']}",
                              "dependsOn": [f"pkg:pypi/{c['name'].lower()}@{c['version']}" for c in components]}]}


INSTALL_SH = r"""#!/bin/sh
# Install NiFiMCP from this kit without network access.
#   ./install.sh [TARGET_VENV]      default: ./nifimcp-venv
set -eu
KIT="$(cd "$(dirname "$0")" && pwd)"
TARGET="${1:-./nifimcp-venv}"
PY="${PYTHON:-python3.12}"
command -v "$PY" >/dev/null 2>&1 || { echo "python3.12 is required (set PYTHON=/path/to/python3.12)"; exit 2; }
"$PY" -c 'import sys,platform; assert sys.version_info[:2]==(3,12) and platform.machine() in ("x86_64","AMD64"), "kit targets CPython 3.12 on x86_64"'
(cd "$KIT" && sh ./verify.sh)
"$PY" -m venv "$TARGET"
"$TARGET/bin/python" -m pip install --no-index --no-cache-dir --disable-pip-version-check --only-binary=:all: \
    --require-hashes --find-links "$KIT/wheelhouse" -r "$KIT/requirements.lock"
"$TARGET/bin/python" -m pip install --no-index --no-cache-dir --disable-pip-version-check --no-deps \
    "$KIT"/wheelhouse/nifimcp_server-*.whl
"$TARGET/bin/nifimcp" --version
echo "Installed. Try: $TARGET/bin/nifimcp demo --output ./nifimcp-demo"
"""

VERIFY_SH = r"""#!/bin/sh
# Verify every file in the kit against SHA256SUMS.
set -eu
cd "$(dirname "$0")"
sha256sum --quiet -c SHA256SUMS
echo "kit checksums OK"
"""

ACCEPT_SH = r"""#!/bin/sh
# Offline acceptance (A30): install from the kit and run the demo and bundle commands with egress denied.
# Run inside a container started with --network none, for example:
#   docker run --rm --network none -v "$PWD":/kit:ro python:3.12-slim sh /kit/offline_acceptance.sh
set -eu
KIT="$(cd "$(dirname "$0")" && pwd)"
WORK="${WORK:-/tmp/nifimcp-offline}"
mkdir -p "$WORK"
echo "== egress check"
python3.12 - <<'EOF'
import socket
for host, port in (("pypi.org", 443), ("1.1.1.1", 443)):
    try:
        socket.create_connection((host, port), timeout=3).close()
        raise SystemExit(f"FAIL: egress to {host}:{port} succeeded; this run would not prove offline operation")
    except OSError as exc:
        print(f"egress to {host}:{port} denied: {type(exc).__name__}")
EOF
echo "== install"
sh "$KIT/install.sh" "$WORK/venv"
B="$WORK/venv/bin"
echo "== demo"
"$B/nifimcp" demo --output "$WORK/demo"
for f in report.html investigation.json transcript.json summary.json; do test -s "$WORK/demo/$f"; done
echo "== bundle mode"
cp -R "$KIT/examples" "$WORK/examples"
sed "s#__WORK__#$WORK#g" "$KIT/examples/operator.bundle.json" > "$WORK/operator.json"
"$B/nifimcp" register --config "$WORK/operator.json" --kind bundle --label example "$WORK/examples/telemetry-intake"
"$B/nifimcp" doctor --config "$WORK/operator.json"
"$B/nifimcp" describe --config "$WORK/operator.json" --scope demo-telemetry-intake > "$WORK/describe.json"
"$B/nifimcp" report --config "$WORK/operator.json" --scope demo-telemetry-intake --output "$WORK/report.html"
test -s "$WORK/report.html"
"$B/python" - "$WORK/describe.json" <<'EOF'
import json, sys
env = json.load(open(sys.argv[1]))
assert env["status"] in ("ok", "partial") and env["findings"], env.get("error")
print("describe:", env["status"], len(env["findings"]), "findings,", len(env["evidence"]), "evidence records")
EOF
echo "== MCP stdio handshake"
"$B/python" - "$B/nifimcp" "$WORK/operator.json" <<'PYEOF'
import sys, anyio
from mcp import ClientSession, StdioServerParameters, stdio_client

async def main():
    params = StdioServerParameters(command=sys.argv[1], args=["serve", "--config", sys.argv[2]])
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as s:
            init = await s.initialize()
            tools = sorted(t.name for t in (await s.list_tools()).tools)
            res = await s.call_tool("describe_flow", {"scope_id": "demo-telemetry-intake"})
            env = res.structured_content
            assert not res.is_error and env["status"] in ("ok", "partial"), env.get("error")
            print("server", init.server_info.name, init.server_info.version, "-", len(tools), "tools;",
                  "describe_flow over stdio:", env["status"], len(env["findings"]), "findings")

anyio.run(main)
PYEOF
echo "OFFLINE ACCEPTANCE PASSED"
"""


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--output", type=Path, default=ROOT / "dist")
    p.add_argument("--dist", type=Path, default=None,
                   help="use the wheel and sdist already in this directory (for example the files published to PyPI) "
                        "instead of building them")
    args = p.parse_args(argv)
    version = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    kit = (args.output / f"nifimcp-offline-{version}-linux-x86_64-cp312").resolve()
    if kit.exists():
        shutil.rmtree(kit)
    wheelhouse = kit / "wheelhouse"
    wheelhouse.mkdir(parents=True)
    env = {k: v for k, v in os.environ.items() if k != "UV_NATIVE_TLS"} | {"SOURCE_DATE_EPOCH": "1793318400"}
    if args.dist is not None:
        build = args.dist.resolve()
    else:
        build = kit.parent / "build"
        if build.exists():
            shutil.rmtree(build)
        sh(["uv", "build", "--out-dir", str(build)], cwd=ROOT, env=env)
    project_whl = next(build.glob("nifimcp_server-*.whl"))
    shutil.copy2(project_whl, wheelhouse)
    shutil.copy2(next(build.glob("nifimcp_server-*.tar.gz")), kit / project_whl.name.replace(
        "-py3-none-any.whl", ".tar.gz"))
    lock = kit / "requirements.lock"
    sh(["uv", "export", "--frozen", "--no-dev", "--no-emit-project", "--format", "requirements-txt",
        "--output-file", str(lock)], cwd=ROOT, env=env)
    cmd = [pip_python(), "-m", "pip", "download", "--disable-pip-version-check", "--no-deps", "--only-binary=:all:",
           "--require-hashes", "--python-version", "3.12", "--implementation", "cp", "--abi", "cp312",
           "--abi", "abi3", "--abi", "none", "--dest", str(wheelhouse), "-r", str(lock)]
    for plat in PLATFORMS:
        cmd += ["--platform", plat]
    sh(cmd, env=env)
    # Reproducible: the SBOM timestamp is the HEAD commit time, not the wall clock.
    commit_time = subprocess.run(["git", "log", "-1", "--format=%ct"], cwd=ROOT, capture_output=True, text=True)
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH") or commit_time.stdout.strip() or 0)
    created = dt.datetime.fromtimestamp(epoch, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    comps, project = [], None
    lic_root = kit / "LICENSES"
    for whl in sorted(wheelhouse.glob("*.whl")):
        meta = wheel_metadata(whl) | {"sha256": sha256(whl), "file": whl.name}
        extract_licenses(whl, meta["license_files"], lic_root / f"{meta['name']}-{meta['version']}")
        if not meta["license_files"]:
            meta["license_files_missing"] = True
        if meta["name"] in ("nifimcp", "nifimcp-server"):
            project = meta
        else:
            comps.append(meta)
    (kit / "sbom.cdx.json").write_text(json.dumps(sbom(comps, project, created), indent=1) + "\n")
    (kit / "license-inventory.json").write_text(json.dumps(
        [{k: c[k] for k in ("name", "version", "license_expression", "license", "classifiers", "license_files",
                            "sha256", "file") if k in c} | {"license_files_missing": bool(c.get("license_files_missing"))}
         for c in [project] + comps], indent=1) + "\n")
    for name, body in (("install.sh", INSTALL_SH), ("verify.sh", VERIFY_SH), ("offline_acceptance.sh", ACCEPT_SH)):
        (kit / name).write_text(body)
        (kit / name).chmod(0o755)
    examples = kit / "examples"
    shutil.copytree(ROOT / "src/nifimcp/demo_data/telemetry-intake", examples / "telemetry-intake")
    (examples / "operator.bundle.json").write_text(json.dumps({
        "schema_version": "1", "mode": "bundle", "artifact_dir": "__WORK__/artifacts", "live": None,
        "telemetry": False, "updates": False}, indent=1) + "\n")
    shutil.copy2(ROOT / "docs/OFFLINE_INSTALL.md", kit / "INSTALL.md")
    for f in ("LICENSE", "NOTICE"):
        shutil.copy2(ROOT / f, kit / f)
    files = sorted(p for p in kit.rglob("*") if p.is_file() and p.name != "SHA256SUMS")
    (kit / "SHA256SUMS").write_text("".join(f"{sha256(p)}  {p.relative_to(kit)}\n" for p in files))
    tar_path = kit.parent / (kit.name + ".tar.gz")
    def normalize(ti):
        return ti.replace(uid=0, gid=0, uname="", gname="", mtime=1793318400, deep=False)
    with open(tar_path, "wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0, filename="") as gz, \
            tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as tar:
        tar.add(kit, arcname=kit.name, filter=normalize)
    (kit.parent / (tar_path.name + ".sha256")).write_text(f"{sha256(tar_path)}  {tar_path.name}\n")
    summary = {"kit": str(kit), "tarball": str(tar_path), "tarball_sha256": sha256(tar_path),
               "project_wheel": project["file"], "project_wheel_sha256": project["sha256"],
               "dependencies": len(comps), "missing_license_files": [c["name"] for c in comps
                                                                      if c.get("license_files_missing")]}
    print(json.dumps(summary, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
