# Incident evaluation corpus

32 labeled synthetic cases: 24 development cases (`dev.json`) and 8 frozen holdout cases
(`holdout.json`, sha256 pinned in `HOLDOUT.sha256` and in `test_incident_contracts.py`).

| Family | Dev | Holdout |
|---|---|---|
| stopped / invalid components | F1-01..03 | H1 |
| back pressure | F2-01..03 | H2 |
| unmatched routing | F3-01..03 | H3 |
| parameter / service gaps | F4-01..03 | H4 |
| provenance retention / index limits | F5-01..03 | H5 |
| permission and scope failures | F6-01..03 | H6 |
| conflicting or partial evidence | F7-01..03 | H7 |
| healthy controls | C-01..03 | HC |

Each case is a self-contained offline bundle (flow definition plus optional status, bulletins, provenance and
operator notes), the tool calls to make, and two kinds of labels:

* **required**: facts the deterministic system must produce (finding ids, gap codes, statuses, error codes,
  qualifying limitations, event counts, a maximum severity for controls);
* **forbidden**: conclusions it must not state (per case, plus a global list such as "root cause is",
  "was caused by", "is healthy", "never existed", "downstream received"). A forbidden pattern counts only
  when asserted; a sentence that negates it before the match ("does not prove the data never existed") is
  the qualified form the contract requires.

Every finding citation is also checked by exact reference: the cited source hash must equal the bundle
file's bytes and the JSON pointer must resolve in that file.

## What this measures, and what it does not

This corpus measures the **deterministic rules and envelope contracts**. The baseline in
`test_deterministic_baseline_grades` grades the system's own findings with the exact-reference grader
(`scoring.py`). The same engineer wrote the rules and the labels, so a full score is a regression check,
not an independent accuracy figure. It says nothing about how well a language model uses the tools.
Model evaluation (gate A36) needs an approved model run, a recorded host transcript and expert review.

## Label provenance and ambiguity

* Labels were authored by the implementing engineer (Claude, Opus 5.5) from the build specification's
  mandatory distinctions. They have **not** been reviewed by a NiFi domain expert.
* All data is synthetic. Flow shapes follow NiFi 2.12.0 flow-definition and REST response structures
  checked against the live lab elsewhere in this repository.
* Ambiguity recorded per case in `label_note` where it exists (for example F1-03 deliberately omits
  untrusted validation text; H3's flow was collected after its events).

## Change log

* First execution (before any freeze): 30 of 32 cases passed. Both failures were label or harness defects,
  not system defects, and the system was not changed:
  1. the forbidden-claim check matched a negated sentence ("does not prove the data never existed");
     the check now ignores negated forms;
  2. C-02 required `status: ok` without supplying bulletin evidence; `partial` is the correct contract
     when bulletins are absent. Bulletins were added and the label replaced (see the case note).
* Holdout cases were not changed after their first run; they passed 8 of 8 on that run. The holdout hash
  was pinned immediately afterwards. Do not tune rules or prompts against the holdout and continue
  calling it held out; add new cases to the development split instead.
