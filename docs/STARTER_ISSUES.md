# Starter issues

Three focused issues for a first contribution. Each is self-contained, has a test to make pass, and needs
no live NiFi. They are opened as GitHub issues when the repository goes public; the text here is the source.

## 1. Bundle collector script (`good first issue`, `help wanted`)

**Goal.** Add `scripts/collect_bundle.py` that turns a NiFi 2.12.0 process group into a
`nifimcp-bundle/1` directory an operator can hand to NiFiMCP in bundle mode.

**Scope.** Given an operator config in live mode and a scope id, collect: the flow definition
(`GET /process-groups/{id}/download`), the group status, the bulletin board, and one provenance query for
the last N minutes, using only the 14 allowlisted endpoints through `nifimcp.live.http.NiFiHTTP`. Write
`manifest.json` with sha256, byte counts, collection times and the query interval, so that
`nifimcp register --kind bundle` accepts it.

**Done when.** A new test in `tests/unit/` builds a bundle from the test suite's fake NiFi
(`tests/fakenifi.py`), registers it and runs `describe_flow` and `get_flow_health` on it. The script must
never call an endpoint outside the allowlist (the route allowlist tests cover this).

## 2. Compatibility report for macOS or Windows (`help wanted`, `compatibility`)

**Goal.** Run the offline suite and the demo on a platform the matrix lists as untested, and report.

**Steps.** `uv sync --frozen`, `uv run pytest -q`, `uv run nifimcp demo --output ./demo`, then open
`demo/report.html`. Record OS version, architecture, Python version, uv version, test counts and anything
that failed, using the compatibility report issue template.

**Done when.** The report is in, and if everything passed, a pull request changes that row in
`docs/CAPABILITIES.md` from Untested to "Reported working (community), not maintained-tested", citing the
issue number. Failures are even more useful; each one becomes its own issue.

## 3. Labeled incident case: expired FlowFiles (`good first issue`)

**Goal.** Add a development-split case to `tests/evals/` for a queue with `flowFileExpiration` set, where
provenance shows `EXPIRE` events, so the rules report expiration as an observed fact without claiming data
loss.

**Scope.** In `tests/evals/corpus_builder.py`, add a case in the `backpressure` family: a connection with
`flowFileExpiration: "30 sec"`, a status snapshot, and a provenance file with two `EXPIRE` events. Required
labels: finding `NM-QUEUE-EXPIRATION`, an observed finding for the EXPIRE events (add the rule if it does
not exist; it belongs in `core/observations.py` next to `OBS-DROP`), and the forbidden claim pattern
`data (was|has been) lost`.

**Done when.** `uv run pytest tests/evals -q` passes with the new case in `dev.json` (regenerate with
`uv run python tests/evals/corpus_builder.py tests/evals/corpus`). Do not touch `holdout.json`; the frozen
holdout hash must not change.
