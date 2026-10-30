#!/usr/bin/env python3
"""Verify one exact Flow Draft Preview artifact in the owned NiFi 2.12.0 lab.

    uv run python scripts/lab_verify_draft.py --artifact-id <art_...> \
        [--artifact-dir ./private-artifacts/demo-session | --config config/operator.demo.json] \
        [--cases cases.json] [--keep]

Reference plans (from `nifimcp demo`) use built-in labeled cases; any other plan
needs a --cases file: {"blueprint": "...", "cases": [{"id", "attributes"|"content", "expected": [ports]}]}.
Exit code 0 only when native import, validation and every labeled case pass.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lab"))

from nifimcp_lab.bootstrap import current_lab_dir  # noqa: E402
from nifimcp_lab.verify import VerificationError, run_verification  # noqa: E402


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--artifact-id", required=True)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--artifact-dir", type=Path)
    group.add_argument("--config", type=Path)
    parser.add_argument("--cases", type=Path)
    parser.add_argument("--keep", action="store_true", help="keep the harness group for inspection")
    parser.add_argument("--lab-root", type=Path, default=ROOT / ".lab")
    parser.add_argument("--output", type=Path, help="directory for the verification outputs")
    args = parser.parse_args(argv)
    if args.config:
        sys.path.insert(0, str(ROOT / "src"))
        from nifimcp.config import load_config
        artifact_dir = load_config(args.config).artifact_path
    else:
        artifact_dir = (args.artifact_dir or ROOT / "private-artifacts" / "demo-session").resolve()
    cases = json.loads(args.cases.read_text()) if args.cases else None
    try:
        result = run_verification(current_lab_dir(args.lab_root), artifact_dir, args.artifact_id, cases=cases,
                                  keep=args.keep, out_dir=args.output)
    except VerificationError as exc:
        print(json.dumps({"overall": "ERROR", "reason": str(exc)}, indent=2))
        return 2
    summary = {k: result[k] for k in ("overall", "blueprint", "artifact_id", "native_artifact_sha256", "runtime",
                                      "outputs")}
    summary["native_validation"] = result["native_validation"]["status"]
    summary["cases"] = [(c["case_id"], c["status"]) for c in (result["cases"] or {}).get("cases", [])]
    print(json.dumps(summary, indent=2))
    return 0 if result["overall"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
