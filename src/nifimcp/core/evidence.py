"""Evidence records, findings and citation verification.

An evidence record binds sanitized facts to the exact source bytes (SHA-256 of the
raw input) and a JSON pointer into that input. Raw input hashes are preserved
separately from hashes of normalized or redacted artifacts.

A verified citation proves the reference resolves in the cited bytes. It does
NOT prove that reasoning drawn from it is correct.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..util import sha256_hex, short_hash
from . import pointer as jp


def evidence_id(kind: str, source_hash: str, source_pointer: str, extra: str = "") -> str:
    return "ev_" + short_hash(kind, source_hash, source_pointer, extra, length=24)


def make_evidence(*, kind: str, source_id: str, source_hash: str, source_pointer: str, facts: dict,
                  collected_at: str, component_id: str | None = None, node_id: str | None = None,
                  event_time: str | None = None, extra: str = "") -> dict:
    return {
        "evidence_id": evidence_id(kind, source_hash, source_pointer, extra),
        "kind": kind,
        "source_id": source_id[:128],
        "component_id": component_id,
        "node_id": node_id,
        "event_time": event_time,
        "collected_at": collected_at,
        "source_hash": source_hash,
        "source_pointer": source_pointer[:4096],
        "facts": facts,
    }


def make_finding(*, finding_id: str, statement: str, kind: str, severity: str,
                 evidence_ids: list[str], limitations: list[str]) -> dict:
    return {
        "finding_id": finding_id[:128],
        "statement": statement[:4000],
        "kind": kind,
        "severity": severity,
        "evidence_ids": list(dict.fromkeys(evidence_ids))[:100],
        "limitations": [lim[:1000] for lim in limitations][:30],
    }


def gap(code: str, detail: str) -> dict:
    return {"code": code[:128], "detail": detail[:2000]}


@dataclass
class EvidenceSet:
    """Accumulates evidence/findings/gaps with de-duplication and stable order."""

    evidence: dict[str, dict] = field(default_factory=dict)
    findings: dict[str, dict] = field(default_factory=dict)
    gaps: list[dict] = field(default_factory=list)

    def add_evidence(self, record: dict) -> str:
        self.evidence.setdefault(record["evidence_id"], record)
        return record["evidence_id"]

    def add_finding(self, finding: dict) -> None:
        missing = [e for e in finding["evidence_ids"] if e not in self.evidence]
        if missing:
            raise ValueError("finding cites evidence that is not in the result")
        self.findings.setdefault(finding["finding_id"], finding)

    def add_gap(self, code: str, detail: str) -> None:
        item = gap(code, detail)
        if item not in self.gaps:
            self.gaps.append(item)

    def extend(self, other: "EvidenceSet") -> None:
        for rec in other.evidence.values():
            self.add_evidence(rec)
        for fnd in other.findings.values():
            self.findings.setdefault(fnd["finding_id"], fnd)
        for g in other.gaps:
            if g not in self.gaps:
                self.gaps.append(g)


class CitationError(ValueError):
    pass


def verify_citation(record: dict, raw_bytes: bytes, document: Any | None = None) -> Any:
    """Verify that ``record`` cites ``raw_bytes`` exactly. Returns the cited value.

    Raises CitationError when the source hash differs or the pointer does not resolve.
    """
    if sha256_hex(raw_bytes) != record["source_hash"]:
        raise CitationError("source bytes do not match the cited source hash")
    if document is None:
        import json
        document = json.loads(raw_bytes.decode("utf-8"))
    try:
        return jp.resolve(document, record["source_pointer"])
    except jp.PointerError as exc:
        raise CitationError("cited pointer does not resolve in the source") from exc
