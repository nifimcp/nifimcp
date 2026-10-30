# Security

## Reporting a vulnerability

Report privately through GitHub: **https://github.com/nifimcp/nifimcp/security/advisories/new**
("Report a vulnerability" on the Security tab). Private vulnerability reporting was enabled and the
route checked by the maintainer on 2026-10-30. Do not open a public issue for a vulnerability.

If you cannot use GitHub, say so through the contact form at https://nifimcp.com/#contact with no
details, and you will get a private channel back.

This is a one-person project. Reports are acknowledged as time allows; no response time is promised.

## Supported versions

Only the latest release candidate receives fixes.

## Security model

NiFiMCP gives an AI assistant read access to parts of Apache NiFi. It is designed so that a confused or
manipulated model cannot change NiFi, reach outside its configured scope or leak more than the operator
allowed.

* **No mutation path.** The runtime has no tool and no HTTP route that modifies NiFi. Live mode can call
  only 14 allowlisted NiFi 2.12.0 endpoints, and the only POST and DELETE requests are for provenance and
  queue-listing queries the server itself created and cleans up.
* **Least privilege.** Use a dedicated NiFi identity with read policies on the scoped process groups only.
  The server checks scope before every dependent read and refuses unknown IDs without confirming whether
  they exist. Results never count or describe events and bulletins dropped for being outside the scope.
* **Transport.** HTTPS only, with an operator-supplied CA file. Redirects, proxy environment variables and
  system trust stores are ignored. Client certificates are presented at the TLS layer.
* **Bounded work.** Hard limits on intervals, events, components, depth, samples, concurrency, run time and
  result size are enforced in code, not only in schemas.
* **Data minimization.** No FlowFile content is read. Attribute values appear only when allowlisted.
  Sensitive properties and parameters are never returned. Secret-like literals, URL credentials and common
  token shapes (presigned URL signatures, webhook paths, API keys) are masked; this pattern masking is
  best-effort and cannot recognize every secret. Hidden values are labeled with per-session keyed hashes.
* **Raw responses stay local.** In live mode the raw NiFi responses are kept in the artifact directory
  (owner-only, rotated, 30-day default retention) so citations can be re-verified. They can include every
  provenance attribute value NiFi returned. They are never sent to the model. Set
  `keep_raw_observations: false` to keep none.
* **Untrusted input.** Names, bulletins, attributes, bundles and operator notes are treated as data. Bundle
  import rejects path traversal, links, duplicates, hash mismatches, oversize and deeply nested content.
  HTML reports carry a restrictive content security policy and no scripts.
* **Local artifacts.** Investigations and drafts are written under the configured artifact directory with
  owner-only permissions, addressed by random IDs, never by caller-supplied paths.
* **No phoning home.** No telemetry, update checks or embedded model.

## Out of scope

* Security of the MCP host, its model provider or the machine it runs on.
* Actions a person takes in NiFi based on the assistant's output.
* The optional lab CLI (`lab/`), which deliberately administers a disposable local NiFi container it created
  and verifies by container identity and certificate pin. Never point it at another system.
