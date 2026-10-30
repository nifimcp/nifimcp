# Evidence

Records produced while qualifying this release. All NiFi data is synthetic and comes from disposable lab
containers that no longer exist. Absolute workspace paths were replaced with `<repo>` and `<workspace>`.

| Folder | What it shows |
|---|---|
| `capsule/` | Version capsule: NiFi 2.12.0 image digest, Java version, REST contract and runtime manifest hashes, Python and MCP SDK versions |
| `host/<stamp>/` | A real Claude Code session against the lab: prompt, MCP config, sanitized transcript (tool calls, results and answer; host environment metadata and model thinking removed), the host-proposed test cases and the native lab verification of the host's draft. The newest session ran with all built-in host tools disabled and NiFiMCP as the only MCP server; the first session had other host tools available but called none of them |
| `cluster/<stamp>/` | NiFiMCP against a real two-node NiFi 2.12.0 cluster: clustered topology detected, investigation refused, GET requests only, also with one node stopped |
| `offline/<stamp>/` | Offline kit installed and run in a container with networking disabled |
| `acceptance/<stamp>/` | Acceptance runs: ledger, release checklist and lab setup. Per-gate logs and JUnit reports are kept privately with the build (earlier ledgers still name those raw files). Earlier runs with failures are kept as history; the newest run is the one in docs/ACCEPTANCE.md |
