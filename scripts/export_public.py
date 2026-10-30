#!/usr/bin/env python3
"""Prepare the proposed public repository from this private build repository. Publishes nothing.

    uv run python scripts/export_public.py --output <dir> [--git] [--archive]

Takes the committed tree (git archive HEAD, so uncommitted and ignored files never leak), then:
* drops private-only files (listed outside version control), raw host transcripts and raw logs (evidence/**/raw/);
* rewrites absolute workspace paths inside recorded evidence to <repo> and <workspace>;
* optionally initializes a fresh Git repository with one commit (no private history) and writes a
  tar.gz plus git bundle next to the export.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import os
import json
import re
import shutil
import subprocess
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# Private-only files are listed as "file: <path>" lines in a git-ignored local file.
PRIVATE_LIST = ROOT / ".release-local" / "private-patterns.txt"
DROP_PATTERNS = [re.compile(r"^evidence/host/[^/]+/transcript\.jsonl$"), re.compile(r"^evidence/(.+/)?raw/"),
                 re.compile(r"\.zip$")]
TEXT_SUFFIXES = {".json", ".jsonl", ".txt", ".log", ".html", ".md", ".csv", ".xml"}


def path_rewrites() -> list[tuple[str, str]]:
    workspace = str(ROOT.parent)
    return [(str(ROOT), "<repo>"), (workspace, "<workspace>"), ("/tmp/claude-0", "<tmp>")]


def export(output: Path) -> dict:
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True)
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()
    dirty = subprocess.run(["git", "status", "--porcelain", "--untracked-files=no"], cwd=ROOT,
                           capture_output=True, text=True, check=True).stdout.strip()
    archive = subprocess.run(["git", "archive", "--format=tar", "HEAD"], cwd=ROOT, capture_output=True, check=True).stdout
    if not PRIVATE_LIST.is_file():
        raise SystemExit(f"{PRIVATE_LIST.name} is required (lists private-only files); refusing to export")
    drop_exact = {ln.split(":", 1)[1].strip() for ln in PRIVATE_LIST.read_text().splitlines() if ln.startswith("file:")}
    dropped, rewritten = [], []
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        for member in tar.getmembers():
            name = member.name
            if member.isdir():
                continue
            if name in drop_exact or any(p.search(name) for p in DROP_PATTERNS):
                dropped.append(name)
                continue
            if not member.isfile():
                raise SystemExit(f"refusing non-regular file in export: {name}")
            data = tar.extractfile(member).read()
            if name.startswith("evidence/") and Path(name).suffix in TEXT_SUFFIXES:
                text = data.decode("utf-8")
                new = text
                for old, repl in path_rewrites():
                    new = new.replace(old, repl)
                if new != text:
                    rewritten.append(name)
                    data = new.encode("utf-8")
            target = output / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            target.chmod(0o755 if member.mode & 0o111 else 0o644)
    return {"source_commit": head, "source_dirty_tracked_files": bool(dirty), "dropped": sorted(dropped),
            "evidence_paths_normalized": sorted(rewritten)}


PUBLIC_AUTHOR = ("Lloyd Clark", "107948402+FlightDeckAI@users.noreply.github.com")


def init_git(output: Path, source_commit: str) -> str:
    source_date = subprocess.run(["git", "log", "-1", "--format=%cI", source_commit], cwd=ROOT,
                                 capture_output=True, text=True).stdout.strip()
    def git(*args):
        return subprocess.run(["git", *args], cwd=output, capture_output=True, text=True, check=True).stdout.strip()
    # The public commit never carries a personal address: author and committer use the GitHub no-reply identity.
    name, email = PUBLIC_AUTHOR
    git("init", "-q", "-b", "main")
    git("config", "user.name", name)
    git("config", "user.email", email)
    git("add", "-A")
    message = ("NiFiMCP 0.1.0rc1: initial public release candidate\n\n"
               f"Exported from the private build repository at {source_commit[:12]}.\n\n"
               "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>\n")
    env = {**os.environ, "GIT_AUTHOR_NAME": name, "GIT_AUTHOR_EMAIL": email,
           "GIT_COMMITTER_NAME": name, "GIT_COMMITTER_EMAIL": email,
           "GIT_AUTHOR_DATE": source_date, "GIT_COMMITTER_DATE": source_date}
    subprocess.run(["git", "commit", "-q", "-m", message], cwd=output, check=True, env=env)
    shown = git("log", "-1", "--format=%an <%ae> | %cn <%ce>")
    if shown != f"{name} <{email}> | {name} <{email}>":
        raise SystemExit(f"public commit identity is wrong: {shown}")
    return git("rev-parse", "HEAD")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--git", action="store_true", help="initialize a fresh repository with one commit")
    p.add_argument("--archive", action="store_true", help="also write <output>.tar.gz and <output>.bundle")
    args = p.parse_args(argv)
    output = args.output.resolve()
    if ROOT in output.parents or output == ROOT:
        raise SystemExit("export must be written outside the private repository")
    record = export(output)
    if args.git or args.archive:
        record["public_commit"] = init_git(output, record["source_commit"])
    if args.archive:
        tar_path = output.parent / (output.name + ".tar.gz")
        subprocess.run(["git", "archive", "--format=tar.gz", f"--prefix={output.name}/", "-o", str(tar_path), "HEAD"],
                       cwd=output, check=True)
        bundle = output.parent / (output.name + ".bundle")
        subprocess.run(["git", "bundle", "create", "-q", str(bundle), "HEAD", "main"], cwd=output, check=True)
        record["artifacts"] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (tar_path, bundle)}
    record["files"] = sum(1 for p in output.rglob("*") if p.is_file() and ".git" not in p.parts)
    (output.parent / (output.name + ".export.json")).write_text(json.dumps(record, indent=1) + "\n")
    print(json.dumps({k: v for k, v in record.items() if k not in ("evidence_paths_normalized",)}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
