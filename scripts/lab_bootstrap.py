#!/usr/bin/env python3
"""Create and provision a disposable, secure, stock Apache NiFi 2.12.0 lab.

Usage:
    uv run python scripts/lab_bootstrap.py --create-owned-lab
    uv run python scripts/lab_bootstrap.py --status
    uv run python scripts/lab_bootstrap.py --destroy

Requires Docker. Generates a private CA, server and client certificates, starts
the pinned official image with two-way TLS, creates separate administrative,
observer, restricted and outsider identities, provisions synthetic fixtures
and writes an observer-only operator config for NiFiMCP.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lab"))

from nifimcp_lab import bootstrap, fixtures  # noqa: E402
from nifimcp_lab.boundary import load_manifest, verify_lab_target  # noqa: E402

DEFAULT_LAB_ROOT = ROOT / ".lab"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--create-owned-lab", action="store_true")
    group.add_argument("--provision", action="store_true", help="(re)provision fixtures in the current lab")
    group.add_argument("--status", action="store_true")
    group.add_argument("--destroy", action="store_true")
    parser.add_argument("--lab-root", type=Path, default=DEFAULT_LAB_ROOT)
    args = parser.parse_args(argv)
    if args.create_owned_lab:
        lab_dir = bootstrap.create_owned_lab(args.lab_root)
        fixtures.provision(lab_dir)
        print(json.dumps({"lab_dir": str(lab_dir), "status": "ready"}, indent=2))
        return 0
    lab_dir = bootstrap.current_lab_dir(args.lab_root)
    if args.provision:
        fixtures.provision(lab_dir)
        print(json.dumps({"lab_dir": str(lab_dir), "status": "provisioned"}, indent=2))
        return 0
    if args.status:
        manifest = load_manifest(lab_dir)
        facts = verify_lab_target(manifest)
        print(json.dumps({"lab_id": manifest["lab_id"], "origin": manifest["origin"],
                          "image": manifest["image"]["digest"], "boundary": facts,
                          "fixtures": manifest.get("fixtures", {})}, indent=2))
        return 0
    bootstrap.destroy_lab(lab_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
