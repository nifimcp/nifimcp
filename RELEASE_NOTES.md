# Release notes

## 0.1.0rc1 (public preview)

First public preview of NiFiMCP, a read-only MCP server for Apache NiFi 2.12.0. Tested on Linux x86_64 with Python 3.12 against NiFi 2.12.0 (single node, certificate authentication) and Claude Code; everything else is untested or refused (see docs/CAPABILITIES.md). Install with `uv tool install nifimcp-server==0.1.0rc1`.

### What works

* Ten MCP tools over stdio: capabilities, flow description, health, provenance trace, unmatched-route inspection, snapshot diff, investigation export, processor catalog, FlowPlan validation and local drafts.
* Demo, offline bundle and live modes. Live mode is qualified against stock NiFi 2.12.0 (single node, mutual TLS) with scoped read-only identities.
* Evidence-bound results: every finding cites the exact source bytes and JSON pointer, with explicit gaps.
* Self-contained HTML investigation reports with no scripts.
* Flow Draft Preview for two blueprints, verified by a separate lab CLI that imports drafts into a disposable NiFi and checks labeled record outcomes.
* Offline install kit for Linux x86_64, CPython 3.12, with hash-locked wheels, SBOM and licenses.

### What writes to NiFi

Nothing in the MCP server. Investigation uses your read-only identity over 14 allowlisted read endpoints; drafts are local files. The optional lab CLI imports a draft only into a disposable NiFi container it created, using that container's own admin certificate, and deletes it afterward. Execution against a real NiFi is not part of this release.

### Qualification

Acceptance run at commit `48af4cafe5a6`: 33 PASS, 0 FAIL, 3 BLOCKED of 36 gates. See docs/ACCEPTANCE.md.

### Not included or not yet qualified

* A34 Cluster: BLOCKED. Cluster investigation is deliberately not implemented in 0.1: NiFiMCP refuses clustered NiFi (verified on a real two-node cluster under A21). Node-bound event IDs, per-node query ownership and partial-node evidence need implementation before this gate can run. No cluster support is claimed.
* A35 Platforms: BLOCKED. Only Linux x86_64 was available in this build environment. macOS, Windows and arm64 have not been run and are listed as untested in docs/CAPABILITIES.md.
* A36 Model evaluation: BLOCKED. No approved local model and no expert reviewer were available. The recorded Claude Code session (A17) is a host integration test, not a model evaluation; the incident corpus measures fixed rules only. No model accuracy claim is made.
* NiFi versions other than 2.12.0, NiFi clusters, bearer-token login against real NiFi, MCP hosts other than Claude Code, and platforms other than Linux x86_64 are untested or refused. See docs/CAPABILITIES.md.
* No tool changes NiFi. Execution with operator approval is a separate, future boundary.
