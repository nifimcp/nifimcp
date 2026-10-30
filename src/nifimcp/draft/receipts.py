"""Validation receipts bind plan, native artifact, catalog, target and runtime.

Editing any bound input invalidates the receipt. A receipt is evidence about one
exact artifact; it is never permission to deploy it.
"""
from __future__ import annotations

from ..util import canonical_hash, iso, sha256_hex, utc_now

STATEMENT = "Evidence about this exact artifact only. Not permission to deploy it."


def _seal(body: dict) -> dict:
    body = {k: v for k, v in body.items() if k != "receipt_sha256"}
    return {**body, "receipt_sha256": canonical_hash(body)}


def make_static_receipt(*, plan_sha: str, native_sha: str, catalog_hash: str, target_version: str,
                        report: dict, server_version: str) -> dict:
    return _seal({
        "receipt_schema": "nifimcp-draft-receipt/1",
        "kind": "static_validation",
        "plan_sha256": plan_sha,
        "native_artifact_sha256": native_sha,
        "catalog_hash": catalog_hash,
        "target_version": target_version,
        "runtime": None,
        "validation_stage": report["stage_reached"],
        "warnings": len(report["warnings"]),
        "unknowns": [u["code"] for u in report["unknowns"]],
        "tests": [],
        "server_version": server_version,
        "created_at": iso(utc_now()),
        "statement": STATEMENT,
    })


def make_lab_receipt(*, static_receipt: dict, native_bytes: bytes, runtime: dict, native_validation: dict,
                     cases: dict, exported_definition_sha256: str | None) -> dict:
    return _seal({
        "receipt_schema": "nifimcp-draft-receipt/1",
        "kind": "native_lab_verification",
        "plan_sha256": static_receipt["plan_sha256"],
        "native_artifact_sha256": sha256_hex(native_bytes),
        "catalog_hash": static_receipt["catalog_hash"],
        "target_version": static_receipt["target_version"],
        "runtime": runtime,
        "static_receipt_sha256": static_receipt["receipt_sha256"],
        "native_validation": native_validation,
        "tests": cases,
        "exported_definition_sha256": exported_definition_sha256,
        "created_at": iso(utc_now()),
        "statement": STATEMENT,
    })


def verify_receipt(receipt: dict, *, plan_sha: str, native_bytes: bytes, catalog_hash: str,
                   target_version: str, runtime: dict | None = None) -> list[str]:
    """Return the list of mismatches; an empty list means the receipt still binds these inputs."""
    problems = []
    body = {k: v for k, v in receipt.items() if k != "receipt_sha256"}
    if canonical_hash(body) != receipt.get("receipt_sha256"):
        problems.append("receipt content was edited")
    if receipt.get("plan_sha256") != plan_sha:
        problems.append("plan changed")
    if receipt.get("native_artifact_sha256") != sha256_hex(native_bytes):
        problems.append("native artifact changed")
    if receipt.get("catalog_hash") != catalog_hash:
        problems.append("catalog changed")
    if receipt.get("target_version") != target_version:
        problems.append("target version changed")
    if runtime is not None and receipt.get("runtime") is not None:
        for key in ("nifi_version", "image_digest"):
            if receipt["runtime"].get(key) != runtime.get(key):
                problems.append(f"runtime {key} changed")
    return problems
