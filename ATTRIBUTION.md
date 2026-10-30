# Attribution and provenance

New original code in this repository is licensed under Apache-2.0 (see `LICENSE`).
This file records every reused or adapted source.

## Unmodified public sources (regression inputs)

Copied byte-for-byte from the upstream repositories at the commits below, with their license files.
Their original tests run unmodified in `tests/unit/test_third_party_regression.py`.

| Directory | Upstream | Commit | License | SHA-256 of main module |
|---|---|---|---|---|
| `third_party/flow-doctor/` | github.com/FlightDeckAI/nifi-flow-doctor `flightdeck/flow-doctor/` | `edbeb5a47b2e4827a8c71770533099f410fffa67` | Apache-2.0 (`LICENSE.APACHE`, `UPSTREAM.md`) | `24cb531c928fcda0060120052341fbbec8caf7570462d06c7fd16916d5792c34` (`doctor.py`) |
| `third_party/checkride/` | github.com/FlightDeckAI/CLI-Anything-NiFi `nifi/agent-harness/` | `e46f267a4174821c7a41ab1d7c5646bdbf93ea03` | Apache-2.0 (`LICENSE`) | `dcfe1d896c651f6ffc31c00565cd97908d113062b870d9da550fe1d4ce6a18bf` (`checkride.py`) |
| `third_party/flowcheck/` | github.com/FlightDeckAI/FlightDeckAI `tools/nifi-flow-validation/` | `3f61196982f025dce3cd05e095a24aebaecb9645` | MIT (`LICENSE`) | `3ca64d86e6ebaebf03552cf02a3cbcbd72e39f28019eb0e57af3c31ef0f8e028` (`flowcheck.py`) |

Flow Doctor's repository is a fork of strands-agents/harness-sdk and Checkride's is a
fork of HKUDS/CLI-Anything. Only the small NiFi-specific modules were taken; neither
framework is a dependency. Flow Doctor's optional Strands/Ollama model harness is
not used: model execution belongs to the MCP host.

## Adapted public code inside `src/nifimcp`

| NiFiMCP module | Adapted from | What was taken | What changed |
|---|---|---|---|
| `core/rules.py` | Flow Doctor `inspect_flow`; Checkride `check` | Rule ideas: stopped-in-export, zero timer period, expiration, unbounded queue (zero-threshold pattern), unresolved endpoint, discarded failure path, plaintext HTTP | Each finding now cites evidence records (source hash + JSON pointer); property values never emitted unless policy allows; wording states limits explicitly |
| `core/diff.py` | Checkride `normalize`, `diff` | Cosmetic-field set, identifier-sorted collections, order-sensitive scalar lists, values omitted | Pointer-level field paths, layout counted separately, regenerated identifiers surfaced as add/remove pairs |
| `comparator/records.py` | flowcheck `read_records`, `compare` (MIT) | Duplicate-key rejection, ID coverage, content and schema checks, "equal counts cannot hide" invariant | Bounded input (bytes, records, depth), route-membership comparison, no file writes |
| `core/report.py` | Flow Doctor `render`; flowcheck `report_html` | Escape-everything rendering approach | New layout, CSP with no scripts, evidence anchors, print styles |

## Design invariants from the author's earlier tooling (no code copied)

Some invariants were re-implemented in Python after review of the author's earlier, unpublished
NiFi review and lifecycle tools. No file, function body or text was copied. They are: exact RFC 6901
citations bound to source bytes; flow-format normalization that keeps original pointers; parameter
inheritance with unresolved references left unresolved; configuration review patterns; name-based
masking; citation validation; notes invalidated by source changes; exact-reference grading with
abstention and clean-control false alarms; and the separation of planning, static checks, runtime
proof and human promotion for drafts.

## Reference-only (no code copied)

* Apache NiFi 2.12.0 REST contract: the OpenAPI document inside the pinned official
  image (`nifi-web-api-2.12.0.war/webapp/docs/rest-api/swagger.json`, SHA-256
  `d9cce3b0bc45f832a21785eb32c27c11ee2f6a0664254ec82468b295517944e8`). Only a compact
  extract of 14 endpoints and their DTO schemas is committed
  (`src/nifimcp/contracts/nifi-2.12.0-rest-allowlist.json`). Apache-2.0.
* Apache NiFi 2.12.0 runtime manifest (`GET /flow/runtime-manifest`, SHA-256 recorded in
  `evidence/capsule/version-capsule.json`): descriptors for three processors are
  extracted into `src/nifimcp/catalog/nifi-2.12.0-catalog.json`. Apache-2.0.
* `tests/fixtures/native/stock-2.12.0-probe-definition.json` is a flow definition
  exported by stock NiFi 2.12.0 from a synthetic probe group built in the lab.
* Comparable projects (ms82119/NiFiMCP, cloudera/NiFi-MCP-Server, GhidraMCP, n8n-mcp)
  were treated as design inputs only. No code or templates were copied.
