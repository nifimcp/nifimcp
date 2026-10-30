"""A06 and A32: incident-reasoning contracts over a labeled corpus with a frozen holdout.

Deterministic rules only. Passing these tests is not a model evaluation and is not LLM accuracy.
"""
from __future__ import annotations

import json
import os
from collections import Counter
from pathlib import Path

import pytest

import harness
import scoring

CORPUS = Path(__file__).parent / "corpus"
HOLDOUT_SHA256 = "504ca6a3150569ad6f2ed4d9fd04913cd09faddbaa4f5e8ef40cac577e102a4a"
FAMILIES = {"stopped_invalid", "backpressure", "unmatched", "parameter_service_gaps", "provenance_limits",
            "permission_scope", "conflicting_partial"}


def load(split: str) -> tuple[dict, str]:
    path = CORPUS / f"{split}.json"
    return json.loads(path.read_text()), scoring.corpus_sha256(path)


DEV, DEV_HASH = load("dev")
HOLD, HOLD_HASH = load("holdout")


def test_holdout_is_frozen():
    assert HOLD_HASH == HOLDOUT_SHA256, "holdout changed; a modified holdout is no longer held out"
    assert (CORPUS / "HOLDOUT.sha256").read_text().split()[0] == HOLDOUT_SHA256


def test_corpus_shape_a32():
    all_cases = DEV["cases"] + HOLD["cases"]
    assert len(all_cases) >= 20
    ids = [c["id"] for c in all_cases]
    assert len(ids) == len(set(ids))
    fams = Counter(c["family"] for c in all_cases)
    assert FAMILIES <= set(fams), f"missing families: {FAMILIES - set(fams)}"
    assert fams["healthy_control"] >= 3
    for split in (DEV, HOLD):
        assert FAMILIES <= {c["family"] for c in split["cases"]}
        assert any(c["family"] == "healthy_control" for c in split["cases"])
    assert not set(c["id"] for c in DEV["cases"]) & set(c["id"] for c in HOLD["cases"])
    for c in all_cases:
        assert c["required"], c["id"]
        assert c["label_provenance"]
    # Golden data states required facts AND conclusions the system must not claim.
    assert DEV["global_forbidden"] and HOLD["global_forbidden"]
    assert sum(1 for c in all_cases if c["forbidden"]) >= 10


@pytest.mark.parametrize("case", DEV["cases"], ids=lambda c: c["id"])
def test_dev_case(case, tmp_path):
    envs = harness.run_case(case, tmp_path)
    assert harness.check(case, envs, DEV["global_forbidden"]) == []
    for env in envs:
        ok, total = harness.citations_valid(env, tmp_path / "bundle")
        assert ok == total, f"{total - ok} citation(s) do not resolve exactly"


@pytest.mark.parametrize("case", HOLD["cases"], ids=lambda c: c["id"])
def test_holdout_case(case, tmp_path):
    envs = harness.run_case(case, tmp_path)
    assert harness.check(case, envs, HOLD["global_forbidden"]) == []
    for env in envs:
        ok, total = harness.citations_valid(env, tmp_path / "bundle")
        assert ok == total


# --------------------------------------------------------------------------- A06 explicit contracts

def _case(cid):
    return next(c for c in DEV["cases"] + HOLD["cases"] if c["id"] == cid)


def test_current_settings_never_asserted_as_historical_cause(tmp_path):
    envs = harness.run_case(_case("H3"), tmp_path)
    temporal = [f for e in envs for f in e["findings"] if f["finding_id"].startswith("TEMPORAL-MISMATCH")]
    assert temporal and all(f["kind"] != "observed" for f in temporal)
    assert all("not known" in f["statement"] for f in temporal)
    assert all(any("cannot establish the cause" in x for x in f["limitations"]) for f in temporal)
    text = " ".join(harness.statements(envs[-1])).lower()
    for phrase in ("caused by the current", "current configuration caused", "because the current setting"):
        assert phrase not in text


def test_empty_results_remain_qualified(tmp_path):
    envs = harness.run_case(_case("F5-01"), tmp_path)
    gap = next(g for g in envs[0]["gaps"] if g["code"] == "NO_MATCHING_EVENTS")
    assert "does not prove" in gap["detail"]
    assert envs[0]["findings"] == []


def test_unmatched_remains_qualified(tmp_path):
    for cid in ("F3-01", "F3-03", "H3"):
        envs = harness.run_case(_case(cid), tmp_path / cid)
        unmatched = [f for e in envs for f in e["findings"] if "UNMATCHED" in f["finding_id"]]
        assert unmatched, cid
        for f in unmatched:
            assert f["limitations"], f"{cid} {f['finding_id']} has no qualification"
            assert f["severity"] in ("info", "review"), "unmatched alone is never an error"


def test_hypotheses_are_labeled_hypotheses(tmp_path):
    envs = harness.run_case(_case("F1-02"), tmp_path)
    hyp = [f for e in envs for f in e["findings"] if f["finding_id"].startswith("HYP-")]
    assert hyp and all(f["kind"] == "hypothesis" and f["limitations"] for f in hyp)


# --------------------------------------------------------------------------- exact-reference grading

def _baseline(corpus, corpus_hash, tmp_path):
    envs = {c["id"]: harness.run_case(c, tmp_path / c["id"]) for c in corpus["cases"]}
    return scoring.baseline_answer(corpus, corpus_hash, envs)


def test_deterministic_baseline_grades(tmp_path):
    report = {}
    for name, corpus, h in (("dev", DEV, DEV_HASH), ("holdout", HOLD, HOLD_HASH)):
        answer = _baseline(corpus, h, tmp_path / name)
        graded = scoring.grade_run(answer, corpus, h, origin="Deterministic baseline, no model")
        m = graded["metrics"]
        assert m["false_negatives"] == 0 and m["false_positives"] == 0
        assert m["citation_validity"] == 1.0
        assert m["false_alarm_rate"] == 0.0
        report[name] = graded
    out = os.environ.get("NIFIMCP_EVAL_REPORT")
    if out:
        Path(out).write_text(json.dumps({k: {kk: v[kk] for kk in v if kk != "details"} | {"details": v["details"]}
                                         for k, v in report.items()}, indent=1))


def test_grader_refuses_wrong_corpus_hash(tmp_path):
    answer = _baseline(DEV, DEV_HASH, tmp_path)
    answer["corpus_sha256"] = "0" * 64
    with pytest.raises(scoring.GradingError):
        scoring.grade_run(answer, DEV, DEV_HASH)


def test_grader_rejects_abstain_with_findings_and_duplicates(tmp_path):
    base = {"split": "dev", "corpus_sha256": DEV_HASH, "run_label": "t", "model": "m", "host": "h",
            "prompt_revision": "1"}
    bad = base | {"results": [{"case_id": "F1-01", "abstain": True,
                               "findings": [{"finding_id": "NM-STOPPED:x", "severity": "info", "citations": []}]}]}
    with pytest.raises(scoring.GradingError):
        scoring.grade_run(bad, DEV, DEV_HASH)
    dup = base | {"results": [{"case_id": "F1-01", "abstain": False, "findings": []},
                              {"case_id": "F1-01", "abstain": False, "findings": []}]}
    with pytest.raises(scoring.GradingError):
        scoring.grade_run(dup, DEV, DEV_HASH)


def test_grader_uncited_or_forged_citation_is_not_a_true_positive(tmp_path):
    answer = _baseline(DEV, DEV_HASH, tmp_path)
    target = next(r for r in answer["results"] if r["case_id"] == "F2-02")
    for f in target["findings"]:
        for c in f["citations"]:
            c["source_pointer"] = "/flowContents/does/not/exist"
    first = next(r for r in answer["results"] if r["case_id"] == "F1-02")
    for f in first["findings"]:
        f["citations"] = []
    graded = scoring.grade_run(answer, DEV, DEV_HASH)
    m = graded["metrics"]
    # F2-02 expects one finding and F1-02 two; all three lose their true-positive status.
    assert m["true_positives"] > 0
    assert m["false_negatives"] == 3 and m["false_positives"] == 3
    assert m["citation_validity"] < 1.0


def test_grader_counts_missing_cases_and_clean_false_alarms(tmp_path):
    answer = _baseline(DEV, DEV_HASH, tmp_path)
    answer["results"] = [r for r in answer["results"] if r["case_id"] != "F4-01"]
    clean = next(r for r in answer["results"] if r["case_id"] == "C-01")
    clean["findings"].append({"finding_id": "NM-INVENTED:x", "severity": "warning", "citations": []})
    graded = scoring.grade_run(answer, DEV, DEV_HASH)
    assert graded["metrics"]["clean_flagged"] == 1
    assert any(d.get("missing") and d["case_id"] == "F4-01" for d in graded["details"])
    assert graded["metrics"]["false_negatives"] == 1
