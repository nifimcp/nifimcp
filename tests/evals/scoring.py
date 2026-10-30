"""Exact-reference grading for incident answers.

Grading invariants re-implemented in Python (no code copied) from the author's earlier benchmark
tooling (see ATTRIBUTION.md):

* the answer must name the corpus split and its pinned sha256, or grading is refused;
* run metadata (label, model, host, prompt revision) is mandatory;
* unknown or duplicate cases are rejected; an abstained case must carry no findings;
* a finding is a true positive only when its citation resolves exactly (source hash plus JSON pointer
  in that case's source bytes) AND it matches an unmatched expected finding label;
* duplicate (finding, pointer) pairs are ignored and counted;
* cases with no answer count every expected finding as missed;
* healthy controls measure false alarms.

Adaptation: NiFiMCP findings carry a severity. Unlabeled ``info`` findings are context, neither true nor
false positives; unlabeled ``review``/``warning``/``error`` findings are false positives (flags).

A deterministic baseline graded here is a rules regression measure. It is not model accuracy.
"""
from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path

from nifimcp.core.evidence import verify_citation

from harness import materialize

FLAG_SEVERITIES = {"review", "warning", "error"}


class GradingError(ValueError):
    pass


def corpus_sha256(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _expected(case: dict) -> list[str]:
    return [r["finding"] for r in case["required"] if "finding" in r]


def _matches(finding_id: str, prefix: str) -> bool:
    return finding_id == prefix or finding_id.startswith(prefix + ":")


def _citation_ok(citation, bundle_dir: Path) -> bool:
    if not isinstance(citation, dict):
        return False
    sid = str(citation.get("source_id", ""))
    if not sid.startswith("bundle:"):
        return False
    path = bundle_dir / sid.split(":", 1)[1]
    if path.parent != bundle_dir or not path.is_file():
        return False
    try:
        verify_citation({"source_hash": citation.get("source_hash", ""),
                         "source_pointer": citation.get("source_pointer", "")}, path.read_bytes())
        return True
    except Exception:  # noqa: BLE001 - malformed or non-resolving citation
        return False


def grade_run(answer: dict, corpus: dict, corpus_hash: str, origin: str = "Imported answer") -> dict:
    if not isinstance(answer, dict) or answer.get("split") != corpus["split"] or answer.get("corpus_sha256") != corpus_hash:
        raise GradingError("answer does not reference this corpus split and pinned hash")
    for key in ("run_label", "model", "host", "prompt_revision"):
        if not isinstance(answer.get(key), str) or not answer[key] or len(answer[key]) > 500:
            raise GradingError(f"run metadata field {key} is missing or invalid")
    results = answer.get("results")
    cases = {c["id"]: c for c in corpus["cases"]}
    if not isinstance(results, list) or len(results) > len(cases):
        raise GradingError("results must be a list with at most one entry per case")
    tp = fp = fn = valid = submitted = duplicates = abstained = context = 0
    clean_answered = clean_flagged = 0
    seen, details = set(), []
    with tempfile.TemporaryDirectory() as tmp:
        for result in results:
            cid = result.get("case_id") if isinstance(result, dict) else None
            if cid not in cases or cid in seen or not isinstance(result.get("findings"), list) \
                    or len(result["findings"]) > 100 or not isinstance(result.get("abstain"), bool):
                raise GradingError("duplicate, unknown or malformed case result")
            if result["abstain"] and result["findings"]:
                raise GradingError("an abstained case must have no findings")
            seen.add(cid)
            case = cases[cid]
            bundle_dir = materialize(case, Path(tmp) / cid / "bundle")
            expected = _expected(case)
            is_clean = case["family"] == "healthy_control"
            if result["abstain"]:
                abstained += 1
            elif is_clean:
                clean_answered += 1
            matched, dedupe = set(), set()
            ctp = cfp = cvalid = 0
            flagged = False
            for f in result["findings"]:
                if not isinstance(f, dict) or not isinstance(f.get("finding_id"), str) \
                        or f.get("severity") not in {"info"} | FLAG_SEVERITIES:
                    raise GradingError("malformed finding")
                cits = f.get("citations") or []
                key = (f["finding_id"], json.dumps(cits, sort_keys=True))
                if key in dedupe:
                    duplicates += 1
                    continue
                dedupe.add(key)
                submitted += 1
                cited = bool(cits) and all(_citation_ok(c, bundle_dir) for c in cits)
                if cited:
                    valid += 1
                    cvalid += 1
                idx = next((i for i, p in enumerate(expected) if i not in matched and _matches(f["finding_id"], p)), None)
                if cited and idx is not None:
                    tp += 1
                    ctp += 1
                    matched.add(idx)
                elif f["severity"] in FLAG_SEVERITIES or idx is not None:
                    fp += 1
                    cfp += 1
                    flagged = flagged or f["severity"] in FLAG_SEVERITIES
                else:
                    context += 1
            if is_clean and not result["abstain"] and flagged:
                clean_flagged += 1
            missed = len(expected) - len(matched)
            fn += missed
            details.append({"case_id": cid, "abstained": result["abstain"], "true_positives": ctp,
                            "false_positives": cfp, "missed": missed, "valid_citations": cvalid,
                            "expected": len(expected)})
    for cid, case in cases.items():
        if cid not in seen:
            n = len(_expected(case))
            fn += n
            details.append({"case_id": cid, "missing": True, "true_positives": 0, "false_positives": 0,
                            "missed": n, "expected": n})

    def ratio(a, b):
        return round(a / b, 4) if b else None

    return {
        "origin": origin, "run_label": answer["run_label"], "model": answer["model"], "host": answer["host"],
        "prompt_revision": answer["prompt_revision"], "split": corpus["split"], "corpus_sha256": corpus_hash,
        "coverage": ratio(len(seen) - abstained, len(cases)), "received_cases": len(seen), "abstained": abstained,
        "metrics": {"true_positives": tp, "false_positives": fp, "false_negatives": fn,
                    "precision": ratio(tp, tp + fp), "recall": ratio(tp, tp + fn),
                    "citation_validity": ratio(valid, submitted), "false_alarm_rate": ratio(clean_flagged, clean_answered),
                    "clean_answered": clean_answered, "clean_flagged": clean_flagged, "submitted": submitted,
                    "duplicates": duplicates, "context_findings": context},
        "details": details,
    }


def baseline_answer(corpus: dict, corpus_hash: str, envelopes_by_case: dict[str, list[dict]]) -> dict:
    """Turn the deterministic system's own envelopes into an answer (the 'no model' baseline)."""
    results = []
    for case in corpus["cases"]:
        envs = envelopes_by_case[case["id"]]
        findings = []
        for env in envs:
            ev = {e["evidence_id"]: e for e in env.get("evidence") or []}
            for f in env.get("findings") or []:
                cits = [{k: ev[i][k] for k in ("source_id", "source_hash", "source_pointer")}
                        for i in f.get("evidence_ids") or [] if i in ev]
                findings.append({"finding_id": f["finding_id"], "severity": f["severity"], "citations": cits})
        results.append({"case_id": case["id"], "abstain": False, "findings": findings})
    return {"split": corpus["split"], "corpus_sha256": corpus_hash, "run_label": "Deterministic rules baseline",
            "model": "No model", "host": "nifimcp test harness", "prompt_revision": "Not applicable",
            "results": results}
