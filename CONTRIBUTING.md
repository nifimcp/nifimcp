# Contributing

Thank you for helping. The most useful contributions right now:

1. **Compatibility reports** for NiFi versions, operating systems and MCP hosts not yet in the
   [capability matrix](docs/CAPABILITIES.md). Include versions and the exact commands you ran.
2. **Labeled incident cases** for `tests/evals/`: a small synthetic bundle, the facts the server must report,
   and the conclusions it must not claim. Add them to the development split, never to the holdout.
3. **Bug reports** with a minimal synthetic reproduction. Never attach real flows, credentials or customer data.

## Development setup

```sh
uv sync --frozen
uv run pytest                      # offline unit, security, protocol and evaluation tests
```

Live and lab tests need Docker and create a disposable NiFi 2.12.0 container bound to 127.0.0.1:

```sh
uv run python scripts/lab_bootstrap.py --create-owned-lab
uv run pytest -m integration       # live adapter against the lab
uv run pytest -m lab               # draft import and labeled runtime cases
uv run python scripts/lab_bootstrap.py --destroy
```

## Rules for changes

* **No mutation tools.** Changes that let the runtime create, start, stop, modify or delete anything in NiFi
  will not be accepted. Draft verification belongs in the separate lab CLI.
* **Evidence over claims.** A mocked NiFi is not an integration pass. If an environment is unavailable, mark
  the result BLOCKED and say why; never record it as passing.
* **New endpoints** must be added to `src/nifimcp/contracts/nifi-2.12.0-rest-allowlist.json` with the REST
  contract they come from, and covered by `tests/security/test_route_allowlist.py`.
* **Public contracts** (`tool_contracts.json`, the envelope and FlowPlan schemas) change only with matching
  contract tests.
* **Dependencies** are pinned in `pyproject.toml` and `uv.lock`. Explain any new dependency and its license.
* **Third-party code** keeps its license and notice, and is recorded in `ATTRIBUTION.md`.
* Keep copy concise and plain. Do not imply endorsement by the Apache Software Foundation or anyone else.

By contributing you agree that your contribution is licensed under the Apache License 2.0.
