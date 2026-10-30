# Release validation summary

Version **0.1.0rc1** (public preview). Build repository commit `48af4cafe5a6`, acceptance run 2026-10-30T01:46:30Z. The wheel, sdist and offline kit were rebuilt from that commit's source after two packaging-only changes: the README brand header and the PyPI project name nifimcp-server (PyPI rejected nifimcp as too similar to an existing project). The offline kit acceptance and the clean-environment install were repeated on the rebuilt files and are the runs cited below.

## Artifacts and checksums (SHA-256)

| File | SHA-256 |
|---|---|
| `nifimcp_server-0.1.0rc1-py3-none-any.whl` | `f178bf4ace4e0fb9cce39dfe46738c70a934348bc2f6e87cdf4d69ed58c228ff` |
| `nifimcp_server-0.1.0rc1.tar.gz` | `04e96bf3faa579b25b405ba41c0bde906c314453d71660dd1bb89c707e0c67c8` |
| `nifimcp-offline-0.1.0rc1-linux-x86_64-cp312.tar.gz` | `d1d26bea262c5221156816a3a10bd47406fbf3b8fe8b755a9197306ddb640162` |

The GitHub release carries the same files plus `SHA256SUMS`. PyPI publishes the wheel and sdist through Trusted Publishing with attestations; the hashes printed by the publish step must match this table.

## What was run

* Environment: Linux-6.18.44-fc-v185-x86_64-with-glibc2.39, 2 CPUs, 7.8 GiB, Python 3.12.3, uv 0.11.32 (x86_64-unknown-linux-gnu), Docker 29.9.2, MCP SDK 2.3.0.
* NiFi under test: `apache/nifi@sha256:6f7f2840dbf178c6dd3fa13435b9b358f3be3c6fb7417de467a35a267f4d28ad` (2.12.0, single node, mutual TLS), started by the lab CLI.
* Acceptance gates: **33 PASS, 0 FAIL, 3 BLOCKED** of 36. Details per gate: [ACCEPTANCE.md](ACCEPTANCE.md).
* Offline suite on the public export: clean clone of the public export; offline suite 287 passed; demo wrote report, investigation, transcript and summary; README commands match.
* Real Claude Code session (2.1.312 (Claude Code), model claude-opus-5-5): 10 NiFiMCP tool calls; only NiFiMCP tools were available to the host; the host's own draft passed 6 of 6 labeled cases natively (PASS). Transcript: `evidence/host/20261029T050341Z/transcript.public.jsonl`.
* Real two-node cluster probe: PASS (clustered NiFi detected and refused; NiFiMCP sent GET requests only, including with one node stopped).
* Offline kit inside `python:3.12-slim` with `--network none`: PASSED (demo, bundle register, doctor, describe, report and an MCP stdio call).
* Clean-environment install from these exact artifacts (`python:3.12-slim`, nothing preinstalled, dependencies from PyPI): PASSED. Covered: `pip install nifimcp-server==0.1.0rc1` from the wheel, `uv tool install nifimcp-server==0.1.0rc1`, the README `uvx` one-liner, the MCP host form (`uvx ... nifimcp serve` driven by the official MCP client), and the sdist. Script: `scripts/clean_install_check.sh`.

## What this does not show

* No measurement of AI answer accuracy. The recorded session is a host integration test; the incident corpus tests fixed rules.
* No cluster support, no platform other than Linux x86_64, no NiFi version other than 2.12.0, no bearer-token login against a real NiFi, no MCP host other than Claude Code.
* NiFiMCP runs offline; a fully offline AI setup (host and model) was not tested.
