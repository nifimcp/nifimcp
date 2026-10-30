# Compatibility and capability matrix

**Qualified** means exercised against the real thing with recorded evidence in this repository.
**Unit tested** means covered by tests against fakes or fixtures only. **Untested** means no evidence yet;
it may work, but no support is claimed. Details and commands: [ACCEPTANCE.md](ACCEPTANCE.md).

## Platforms

| Item | State |
|---|---|
| Linux x86_64, CPython 3.12 (source checkout with uv) | Qualified |
| Linux x86_64, CPython 3.12, offline kit with networking disabled | Qualified |
| macOS (any architecture) | Untested |
| Windows | Untested |
| Linux arm64 | Untested |
| Python other than 3.12 | Not supported (package requires 3.12) |

## Apache NiFi

| Item | State |
|---|---|
| NiFi 2.12.0, single node, HTTPS with mutual TLS | Qualified (official image pinned by digest) |
| NiFi 2.12.0 policies: scoped read, restricted (no provenance), outsider | Qualified |
| Bearer token authentication | Unit tested only |
| NiFi clusters | Not supported; refused at preflight (cluster qualification not yet run) |
| Other NiFi 2.x versions | Not supported; refused at preflight until qualified |
| NiFi 1.x | Not supported |
| Custom or third-party processors | Shown as unresolved; behavior never inferred |

## MCP hosts

| Host | State |
|---|---|
| Official MCP Python SDK client over stdio | Qualified (protocol tests) |
| Claude Code (headless, stdio) | Qualified (recorded session in `evidence/host/`) |
| Claude Desktop, other IDE hosts | Untested |
| Remote transports (HTTP, SSE) | Not provided; stdio only |

## Features

| Feature | Demo | Bundle | Live |
|---|---|---|---|
| `describe_flow` | Qualified | Qualified | Qualified |
| `get_flow_health` (status, queues, bulletins) | Qualified | Qualified | Qualified |
| `trace_feed` by FlowFile UUID or filename | Qualified | Qualified | Qualified |
| `trace_feed` by approved indexed attribute | Unit tested | Unit tested | Refusal qualified when NiFi does not index the attribute; a successful indexed search is untested |
| `inspect_unmatched` with metadata sample | Qualified | Qualified | Qualified |
| `compare_flow_snapshots` (registered flow definitions or bundles) | Qualified | Qualified | Untested |
| `export_investigation` (JSON, HTML) | Qualified | Qualified | Qualified |
| `validate_flow_plan`, `draft_flow` | Qualified | Qualified | Qualified (local only) |
| Draft import and labeled runtime cases | Separate lab CLI, qualified against a disposable NiFi 2.12.0 |

## Blueprints for drafts

| Blueprint | State |
|---|---|
| `attribute_router` (RouteOnAttribute) | Qualified: imports into stock NiFi and passes 10 labeled cases |
| `json_field_gate` (EvaluateJsonPath and RouteOnAttribute) | Qualified: imports into stock NiFi and passes 10 labeled cases |
| Anything else | Not available; rejected by validation |

## Evaluation

| Item | State |
|---|---|
| Deterministic rules on 32 labeled synthetic cases (24 development, 8 frozen holdout) | Passing; same author wrote rules and labels, so this is a regression check |
| Language model answer quality | Not measured. No accuracy claim is made. |
