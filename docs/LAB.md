# The isolated lab

The lab is a development and verification tool, separate from the MCP server. It is the only code in
this repository that writes to NiFi, and it writes only to a disposable container it created itself.
It is not installed by the `nifimcp` package.

## What it does

`scripts/lab_bootstrap.py --create-owned-lab`

1. Generates a private CA and five TLS identities (server, admin, observer, restricted, outsider).
2. Starts the official `apache/nifi` 2.12.0 image, pinned by digest, published only on `127.0.0.1`.
3. Records a lab manifest: lab ID, container ID, image digest, port and server certificate fingerprint.
4. Builds synthetic fixtures (a scoped process group with an unmatched route, a foreign group, a drafts
   group) and grants the policies used by the live tests.
5. Writes operator configs for the observer, restricted and outsider identities.

Before any write, the lab verifies that the target is the recorded container (ID, label, image digest,
loopback binding) and that the TLS certificate matches the recorded fingerprint. A URL or argument alone
can never turn another NiFi into a lab.

## Draft verification

```sh
uv run python scripts/lab_verify_draft.py --artifact-id <art_...> --config operator.json [--cases cases.json]
```

Checks that the draft's static receipt still binds its plan, native definition and catalog, imports the
exact bytes into a new harness group, records NiFi's validation of every component, runs each labeled case
one at a time, captures which output port each record reached and compares membership exactly, then
removes the harness. A valid import with a wrong record outcome is a FAIL. The result is a lab receipt
bound to the draft's hashes. A draft that passes here has passed these cases in this lab only; it is not
approved for production.

Reference plans from `nifimcp demo` carry built-in cases. Any other plan needs a cases file:
`{"blueprint": "...", "cases": [{"id": "...", "attributes": {...}, "expected": ["out_..."]}]}`.

## Clean up

```sh
uv run python scripts/lab_bootstrap.py --destroy
```

## Requirements

Docker, about 2 GB of free memory and roughly one minute to start NiFi.
