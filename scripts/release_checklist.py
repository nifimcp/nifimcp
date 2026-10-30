#!/usr/bin/env python3
"""Release checklist (acceptance gate A33).

    uv run python scripts/release_checklist.py [--tree <dir>] [--kit <offline kit dir>] [--output <file>]

Checks the tree that would be published (default: the public export if present, else this repository):

* license provenance: Apache-2.0 LICENSE and NOTICE, every third_party directory licensed and attributed,
  every runtime dependency's declared license is permissive and its license files are shipped;
* secret scan: detect-secrets over every file, each hit classified (hash, synthetic canary, test fixture)
  or reported; no private keys; no private handoff, commercial or personal material;
* SBOM and hashes: CycloneDX SBOM covers every wheel with SHA-256; kit checksums verify;
* honest capability matrix: required untested and unsupported rows present; README links it;
* packaging metadata and MCP Registry: license expression, mcp-name marker, server.json schema;
* public copy style: no em dashes in human-facing documents.

Exit 0 only when every check passes. A check that cannot run (missing tool, no network) is BLOCKED.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PERMISSIVE = re.compile(r"\b(MIT|BSD|Apache|ISC|PSF|Python Software Foundation|Unlicense|0BSD|MPL-2\.0)\b", re.I)
COPYLEFT = re.compile(r"\b(A?GPL|LGPL|SSPL|EUPL|CC-BY-SA|Commons Clause)\b", re.I)
# Private names to keep out of the public tree live in a git-ignored file so the list itself is never published.
PRIVATE_PATTERNS_FILE = ROOT / ".release-local" / "private-patterns.txt"
SCHEMA_URL = "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json"
PUBLIC_DOCS = ["README.md", "SECURITY.md", "CONTRIBUTING.md", "CODE_OF_CONDUCT.md", "docs/CAPABILITIES.md",
               "docs/CONFIGURATION.md", "docs/OFFLINE_INSTALL.md", "docs/LAB.md", "docs/ACCEPTANCE.md",
               "docs/ROADMAP.md", "docs/STARTER_ISSUES.md", "docs/VALIDATION.md", "RELEASE_NOTES.md",
               "evidence/README.md", "tests/evals/corpus/README.md"]


def files_of(tree: Path) -> list[Path]:
    if (tree / ".git").exists():
        out = subprocess.run(["git", "ls-files", "-z"], cwd=tree, capture_output=True, check=True).stdout
        return [tree / p for p in out.decode().split("\0") if p]
    skip = {".git", ".venv", "__pycache__", ".lab", "dist", "private-artifacts", ".pytest_cache"}
    return [p for p in tree.rglob("*") if p.is_file() and not (set(p.relative_to(tree).parts) & skip)]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_licenses(tree: Path, kit: Path | None) -> dict:
    problems = []
    lic = (tree / "LICENSE").read_text(errors="replace") if (tree / "LICENSE").is_file() else ""
    if "Apache License" not in lic or "Version 2.0" not in lic:
        problems.append("LICENSE is not the Apache License 2.0 text")
    if not (tree / "NOTICE").is_file():
        problems.append("NOTICE missing")
    attribution = (tree / "ATTRIBUTION.md").read_text() if (tree / "ATTRIBUTION.md").is_file() else ""
    for d in sorted(p for p in (tree / "third_party").iterdir() if p.is_dir()):
        if not any(f.name.upper().startswith("LICENSE") for f in d.iterdir()):
            problems.append(f"{d.name}: no license file")
        if f"third_party/{d.name}/" not in attribution:
            problems.append(f"{d.name}: not recorded in ATTRIBUTION.md")
    deps = []
    if kit is None:
        return {"result": "BLOCKED", "reason": "offline kit not built; dependency licenses not inspected",
                "problems": problems}
    inventory = json.loads((kit / "license-inventory.json").read_text())
    for item in inventory:
        declared = " ".join(filter(None, [item.get("license_expression") or "", item.get("license") or "",
                                          " ".join(item.get("classifiers") or [])]))
        entry = {"name": item["name"], "version": item["version"], "declared": declared[:120],
                 "license_files": len(item.get("license_files") or [])}
        if COPYLEFT.search(declared) and not PERMISSIVE.search(declared):
            problems.append(f"{item['name']}: copyleft license {declared[:60]}")
        elif not PERMISSIVE.search(declared):
            problems.append(f"{item['name']}: license not recognized as permissive: {declared[:60]!r}")
        if item.get("license_files_missing"):
            problems.append(f"{item['name']}: no license file shipped in its wheel")
        deps.append(entry)
    return {"result": "PASS" if not problems else "FAIL", "problems": problems, "dependencies": deps}


def classify_secret(path: str, line: str, kind: str) -> str | None:
    if kind == "Hex High Entropy String":
        tokens = re.findall(r"[0-9a-fA-F]{16,}", line)
        if tokens and all(len(t) in (16, 24, 32, 40, 64) for t in tokens):
            return "hash or identifier"
    if kind == "Base64 High Entropy String" and path.startswith("evidence/"):
        if re.search(r"(art|req|ev|inv|ses|toolu)_[A-Za-z0-9]{8,}|sha256|[0-9a-f]{64}", line):
            return "artifact, request or evidence identifier in recorded evidence"
    if "DEMO-CANARY" in line or "CANARY" in line.upper():
        return "synthetic canary"
    if path.startswith(("tests/", "third_party/")) or "/tests/" in path:
        return "test fixture"
    if kind == "Basic Auth Credentials" and re.search(r"(example|invalid|user:pass|placeholder)", line, re.I):
        return "documentation placeholder"
    return None


def check_secrets(tree: Path) -> dict:
    uvx = shutil.which("uvx")
    paths = [str(p.relative_to(tree)) for p in files_of(tree)]
    private_keys = []
    for rel in paths:
        try:
            text = (tree / rel).read_text(errors="ignore")
        except OSError:
            continue
        if re.search(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", text):
            private_keys.append(rel)
    if not uvx:
        return {"result": "BLOCKED", "reason": "uvx not available to run detect-secrets", "private_keys": private_keys}
    proc = subprocess.run([uvx, "--from", "detect-secrets==1.5.0", "detect-secrets", "scan", "--all-files", *paths],
                          cwd=tree, capture_output=True, text=True)
    if proc.returncode != 0:
        return {"result": "BLOCKED", "reason": "detect-secrets failed: " + proc.stderr[-300:]}
    results = json.loads(proc.stdout)["results"]
    classified, unexplained = {}, []
    for rel, hits in results.items():
        lines = (tree / rel).read_text(errors="ignore").splitlines()
        for hit in hits:
            line = lines[hit["line_number"] - 1] if hit["line_number"] - 1 < len(lines) else ""
            why = classify_secret(rel, line, hit["type"])
            if why:
                classified[why] = classified.get(why, 0) + 1
            else:
                unexplained.append({"file": rel, "line": hit["line_number"], "type": hit["type"]})
    ok = not unexplained and not private_keys
    return {"result": "PASS" if ok else "FAIL", "tool": "detect-secrets 1.5.0", "files_scanned": len(paths),
            "classified": classified, "unexplained": unexplained, "private_keys": private_keys}


def check_private_material(tree: Path) -> dict:
    if not PRIVATE_PATTERNS_FILE.is_file():
        return {"result": "BLOCKED", "reason": f"{PRIVATE_PATTERNS_FILE.name} not present (kept outside version control)"}
    patterns = [ln.strip() for ln in PRIVATE_PATTERNS_FILE.read_text().splitlines()
                if ln.strip() and not ln.startswith(("#", "file:"))]
    hits = []
    rx = re.compile("|".join(patterns), re.I)
    for p in files_of(tree):
        rel = str(p.relative_to(tree))
        try:
            text = p.read_text(errors="ignore")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            m = rx.search(line)
            if m:
                hits.append({"file": rel, "line": i})   # the matched text is private; never record it
    private_names = {ln.split(":", 1)[1].strip().rsplit("/", 1)[-1] for ln in PRIVATE_PATTERNS_FILE.read_text().splitlines()
                     if ln.startswith("file:")}
    forbidden_files = [str(p.relative_to(tree)) for p in files_of(tree)
                       if p.name in private_names | {"transcript.jsonl"} or p.suffix == ".zip"]
    ok = not hits and not forbidden_files
    return {"result": "PASS" if ok else "FAIL", "hits": hits[:50], "forbidden_files": forbidden_files}


def check_sbom_and_hashes(tree: Path, kit: Path | None) -> dict:
    if kit is None:
        return {"result": "BLOCKED", "reason": "offline kit not built"}
    problems = []
    sbom = json.loads((kit / "sbom.cdx.json").read_text())
    wheels = sorted((kit / "wheelhouse").glob("*.whl"))
    comps = [c for c in sbom.get("components", []) if c.get("scope") != "excluded"]
    if sbom.get("bomFormat") != "CycloneDX" or sbom.get("specVersion") != "1.5":
        problems.append("SBOM is not CycloneDX 1.5")
    if len(comps) != len(wheels) - 1:
        problems.append(f"SBOM lists {len(comps)} dependencies for {len(wheels) - 1} dependency wheels")
    by_file = {w.name: sha256(w) for w in wheels}
    for c in comps:
        wheel = next((p["value"] for p in c.get("properties", []) if p["name"] == "nifimcp:wheel"), None)
        digest = next((h["content"] for h in c.get("hashes", []) if h["alg"] == "SHA-256"), None)
        if wheel not in by_file or by_file[wheel] != digest:
            problems.append(f"SBOM hash mismatch for {c.get('name')}")
    verify = subprocess.run(["sha256sum", "--quiet", "-c", "SHA256SUMS"], cwd=kit, capture_output=True, text=True)
    if verify.returncode != 0:
        problems.append("kit SHA256SUMS does not verify: " + verify.stdout[-300:])
    tarball = kit.parent / (kit.name + ".tar.gz")
    record = {"kit": kit.name, "wheels": len(wheels), "sbom_components": len(comps)}
    if tarball.is_file():
        record["tarball_sha256"] = sha256(tarball)
    for w in wheels:
        if w.name.startswith("nifimcp-"):
            record["project_wheel"] = {"file": w.name, "sha256": by_file[w.name]}
    sdists = sorted(kit.glob("nifimcp-*.tar.gz"))
    if sdists:
        record["project_sdist"] = {"file": sdists[0].name, "sha256": sha256(sdists[0])}
    return {"result": "PASS" if not problems else "FAIL", "problems": problems, **record}


def check_capability_matrix(tree: Path) -> dict:
    problems = []
    path = tree / "docs/CAPABILITIES.md"
    if not path.is_file():
        return {"result": "FAIL", "problems": ["docs/CAPABILITIES.md missing"]}
    text = path.read_text()
    required = [(r"\| macOS[^\n]*\| Untested", "macOS must be listed as untested"),
                (r"\| Windows[^\n]*\| Untested", "Windows must be listed as untested"),
                (r"\| NiFi clusters[^\n]*Not supported", "clusters must be listed as not supported"),
                (r"Language model answer quality[^\n]*Not measured", "model quality must be listed as not measured"),
                (r"Bearer token[^\n]*Unit tested only", "bearer tokens must not be claimed as qualified")]
    for pattern, message in required:
        if not re.search(pattern, text):
            problems.append(message)
    readme = (tree / "README.md").read_text()
    if "docs/CAPABILITIES.md" not in readme:
        problems.append("README does not link the capability matrix")
    # Install commands in the README must name the exact version this tree releases (pre-releases are not
    # picked up by an unpinned install), and the preview label must be present.
    pyproject = (tree / "pyproject.toml").read_text()
    version = re.search(r'^version = "([^"]+)"', pyproject, re.M).group(1)
    for m in re.finditer(r"(pip install|uv tool install|uvx(?: --from)?)\s+nifimcp(==[\w.]+)?", readme):
        if m.group(2) != f"=={version}":
            problems.append(f"README install command is not pinned to {version}: {m.group(0)}")
    if "Public preview" not in readme:
        problems.append("README does not label this release as a public preview")
    for claim in ("production ready", "production-ready", "measured accuracy", "cluster support is available",
                  "air-gapped AI"):
        if re.search(claim, readme, re.I):
            problems.append(f"README makes an unsupported claim: {claim!r}")
    return {"result": "PASS" if not problems else "FAIL", "problems": problems}


def check_packaging(tree: Path, kit: Path | None) -> dict:
    problems, notes = [], []
    readme = (tree / "README.md").read_text()
    server = json.loads((tree / "server.json").read_text())
    marker = f"mcp-name: {server['name']}"
    if not re.search(re.escape(marker) + r"(\s|-->|$)", readme):
        problems.append("README lacks the MCP Registry ownership marker")
    pyproject = (tree / "pyproject.toml").read_text()
    version = re.search(r'^version = "([^"]+)"', pyproject, re.M).group(1)
    if server["packages"][0]["version"] != version:
        problems.append("server.json package version differs from pyproject")
    if kit is not None:
        wheel = next((kit / "wheelhouse").glob("nifimcp-*.whl"))
        with zipfile.ZipFile(wheel) as z:
            meta = z.read(next(n for n in z.namelist() if n.endswith("METADATA"))).decode()
        if "License-Expression: Apache-2.0" not in meta:
            problems.append("wheel metadata lacks License-Expression: Apache-2.0")
        if marker not in meta:
            problems.append("wheel long description lacks the mcp-name marker")
    try:
        with urllib.request.urlopen(SCHEMA_URL, timeout=20) as resp:
            schema = json.loads(resp.read())
        import jsonschema
        errors = [e.message for e in jsonschema.Draft7Validator(schema).iter_errors(server)]
        problems += [f"server.json: {e}" for e in errors]
        notes.append(f"server.json validated against {SCHEMA_URL}")
    except Exception as exc:  # noqa: BLE001 - network may be unavailable
        return {"result": "BLOCKED", "reason": f"could not fetch the registry schema: {type(exc).__name__}",
                "problems": problems}
    notes.append("Registry namespace ownership (io.github.nifimcp) is verified by mcp-publisher at publish "
                 "time against the authenticated GitHub organization; not verifiable before the repository exists.")
    return {"result": "PASS" if not problems else "FAIL", "problems": problems, "notes": notes}


LEDGER_DOCS = ("docs/ACCEPTANCE.md", "RELEASE_NOTES.md", "docs/VALIDATION.md")


def check_published(tree: Path) -> dict:
    version = re.search(r'^version = "([^"]+)"', (tree / "pyproject.toml").read_text(), re.M).group(1)
    try:
        with urllib.request.urlopen(f"https://pypi.org/pypi/nifimcp/{version}/json", timeout=30) as resp:
            data = json.loads(resp.read())
    except Exception as exc:  # noqa: BLE001
        return {"result": "FAIL", "problems": [f"PyPI does not serve nifimcp {version}: {type(exc).__name__}"]}
    files = sorted(u["filename"] for u in data.get("urls", []))
    return {"result": "PASS", "problems": [], "files": files}


def check_style(tree: Path, ledger_pending: bool = False) -> dict:
    hits = []
    for rel in PUBLIC_DOCS:
        p = tree / rel
        if p.is_file():
            for i, line in enumerate(p.read_text().splitlines(), 1):
                if "—" in line or "–" in line:
                    hits.append(f"{rel}:{i}")
    missing = [rel for rel in ("README.md", "SECURITY.md", "CONTRIBUTING.md", "CODE_OF_CONDUCT.md", "LICENSE",
                               "NOTICE", ".github/ISSUE_TEMPLATE/bug_report.yml", "docs/CAPABILITIES.md",
                               *(() if ledger_pending else LEDGER_DOCS))
               if not (tree / rel).is_file()]
    broken = []
    for rel in PUBLIC_DOCS:
        p = tree / rel
        if not p.is_file():
            continue
        for m in re.finditer(r"\]\((?!https?://|mailto:|#)([^)#\s]+)(?:#[^)]*)?\)", p.read_text()):
            target = (p.parent / m.group(1)).resolve()
            if not target.exists() and not (ledger_pending and any(str(target).endswith(d) for d in LEDGER_DOCS)):
                broken.append(f"{rel} -> {m.group(1)}")
    ok = not hits and not missing and not broken
    return {"result": "PASS" if ok else "FAIL", "em_or_en_dashes": hits, "missing_files": missing, "broken_links": broken}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--tree", type=Path)
    p.add_argument("--kit", type=Path)
    p.add_argument("--output", type=Path)
    p.add_argument("--ledger-pending", action="store_true",
                   help="inside an acceptance run: the ledger documents are generated by that run, so do not require them")
    p.add_argument("--published", action="store_true",
                   help="after publication: also verify that PyPI serves the version the README installs")
    args = p.parse_args(argv)
    tree = (args.tree or ROOT).resolve()
    kit = args.kit or next(iter(sorted((ROOT / "dist").glob("nifimcp-offline-*-linux-x86_64-cp312"))), None)
    if kit is not None and not kit.is_dir():
        kit = None
    checks = {
        "license_provenance": check_licenses(tree, kit),
        "secret_scan": check_secrets(tree),
        "private_material": check_private_material(tree),
        "sbom_and_hashes": check_sbom_and_hashes(tree, kit),
        "capability_matrix": check_capability_matrix(tree),
        "packaging_and_registry": check_packaging(tree, kit),
        "public_docs": check_style(tree, args.ledger_pending),
    }
    if args.published:
        checks["published_package"] = check_published(tree)
    states = {c["result"] for c in checks.values()}
    overall = "FAIL" if "FAIL" in states else "BLOCKED" if "BLOCKED" in states else "PASS"
    report = {"gate": "A33", "tree": str(tree), "kit": str(kit) if kit else None, "result": overall,
              "ledger_documents": "generated by this run; required on the final export" if args.ledger_pending
              else "required", "checks": checks}
    text = json.dumps(report, indent=1)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + "\n")
    print(json.dumps({"result": overall, **{k: v["result"] for k, v in checks.items()}}, indent=1))
    return {"PASS": 0, "FAIL": 1}.get(overall, 3)


if __name__ == "__main__":
    raise SystemExit(main())
