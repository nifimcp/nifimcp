# Roadmap

Order matters more than dates. Each item is done when it has evidence of the same kind as the current
release: real NiFi, recorded results, and a capability matrix row that changes from untested to tested.

## 1. Safe read-only cluster support

Today a clustered NiFi is detected and refused. The target is investigation across a cluster with the same
guarantees as single-node mode:

* provenance and listing queries owned per node, with node-bound event IDs in evidence records;
* partial-node results reported as partial, naming the nodes that did not answer;
* cleanup of every query on every node, including after cancellation;
* qualification on a real two-node cluster (the lab already builds one for the refusal test).

No cluster support is claimed until that gate passes.

## 2. External validation

* Compatibility reports from other environments: NiFi versions near 2.12.0, macOS and Windows hosts, other
  MCP hosts. The issue template exists; the capability matrix is updated only from reports with commands.
* A NiFi expert reviews a sample of recorded assistant answers against the evidence (claims supported,
  citations valid, abstentions). That is the first honest statement about model behavior.
* More labeled incident cases from real (anonymized) flows, added to the development split.

## 3. Operator ergonomics

* A bundle collector script for air-gapped sites: export flow definition, status, bulletins and bounded
  provenance for one process group into a `nifimcp-bundle/1` directory.
* `nifimcp report` for bundle mode with the operator notes shown inline.
* Clearer `doctor` output for policy gaps (which NiFi policy is missing for which tool).

## 4. Draft blueprints

* Additional small blueprints only when each has a labeled native case set: a record-field gate and a
  retry-with-backoff pattern are the candidates.
* Lab verification runs from the CLI against a user-supplied disposable NiFi, not only the bundled lab.

## 5. Execution with approval (separate component, later)

An isolated action service with operator approval bound to identity, scope, component revision,
artifact hash, expiry and a one-time nonce. Not part of the read-only server, not scheduled.

## Not planned

* Any tool in the MCP server that modifies NiFi.
* Reading FlowFile content.
* Telemetry or hosted services inside the open-source runtime.
