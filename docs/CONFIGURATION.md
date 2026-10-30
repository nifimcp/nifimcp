# Operator configuration

One JSON file controls a NiFiMCP session. Unknown keys are rejected. Relative paths resolve from the file's
own directory. `nifimcp doctor --config <file>` checks it.

```json
{
  "schema_version": "1",
  "mode": "live",
  "artifact_dir": "./nifimcp-artifacts",
  "live": {
    "origin": "https://nifi.example.internal:8443",
    "ca_file": "./pki/nifi-ca.pem",
    "auth": {"kind": "client_certificate", "cert_file": "./pki/nifimcp.crt.pem", "key_file": "./pki/nifimcp.key.pem"},
    "scopes": [
      {"scope_id": "orders-intake", "process_group_id": "8576d8b1-01a1-1000-04e0-e29605fa7003", "label": "Orders intake"}
    ],
    "provenance": {"enabled": true, "approved_indexed_attributes": ["status"]}
  },
  "redaction": {"attribute_allowlist": ["status", "route.key"]},
  "limits": {"queue_sampling_enabled": false}
}
```

## Top level

| Key | Meaning |
|---|---|
| `schema_version` | Always `"1"` |
| `mode` | `demo`, `bundle` or `live` |
| `artifact_dir` | Where investigations, drafts and registered inputs are stored. Created with owner-only permissions (0700). |
| `registered_inputs` | Bundles or flow definitions registered with `nifimcp register` (bundle mode) |
| `live` | Live connection settings (live mode only) |
| `telemetry`, `updates` | Must be `false`. NiFiMCP has no telemetry and no update check. |
| `redaction` | What text may leave NiFi in results |
| `limits` | Operator limits, bounded by hard maxima |
| `retention_days` | Session artifacts older than this are purged (default 30) |
| `keep_raw_observations` | Keep raw live NiFi responses in the artifact directory so citations can be re-verified later (default true). They include every provenance attribute value NiFi returned, are owner-only (0600), rotate oldest-first at 500 per session and are never sent to the model. Set `false` to keep none. |

## `live`

| Key | Meaning |
|---|---|
| `origin` | `https://host[:port]` only. No path, user info or plain HTTP. |
| `ca_file` | PEM bundle used to verify NiFi's server certificate. System trust stores and proxy environment variables are ignored. |
| `auth` | `client_certificate` (`cert_file`, `key_file`) or `bearer_token_file` (`token_file`). Only client certificates are qualified against real NiFi so far. |
| `scopes` | 1 to 20 process groups the assistant may see. Each has a stable `scope_id` that tools use. |
| `provenance.enabled` | Allow provenance queries |
| `provenance.approved_indexed_attributes` | Attribute names the assistant may search by. They must also be indexed in NiFi. |
| `trusted_proxy` | Optional explicit HTTP(S) proxy for the NiFi connection |
| `expected_version` | `2.12.0`, the only qualified version. The server refuses other versions and NiFi clusters. |

## `redaction`

| Key | Default | Meaning |
|---|---|---|
| `include_component_names` | true | Show processor, connection and group names |
| `include_property_values` | true | Show non-sensitive property values. Secret-like literals are still masked. |
| `include_parameter_values` | false | Show non-sensitive parameter values. Sensitive values are never shown. |
| `include_bulletin_messages` | true | Show scrubbed, truncated bulletin text |
| `include_filenames` | false | Show the `filename` attribute in traces and samples |
| `attribute_allowlist` | empty | Exact attribute names whose values may appear |

## `limits`

Most limits have an operator value and an optional lower operator ceiling. Neither may exceed the hard
maximum in code. Use these exact keys:

| Value key | Ceiling key | Default | Hard maximum |
|---|---|---|---|
| `time_window_minutes` | `maximum_time_window_minutes` | 60 | 1440 |
| `provenance_events` | `maximum_provenance_events` | 200 | 1000 |
| `components` | `maximum_components` | 500 | 2000 |
| `depth` | `maximum_depth` | 4 | 8 |
| `sample_size` | `maximum_sample_size` | 10 | 25 |
| `concurrency` | `maximum_concurrency` | 1 | 2 |
| `tool_timeout_seconds` | `maximum_timeout_seconds` | 30 | 60 |
| (none) | `maximum_result_bytes` | 262144 | 262144 |
| `bundle_expanded_bytes` | `maximum_bundle_expanded_bytes` | 26214400 | 104857600 |
| `queue_sampling_enabled` | (switch) | false | |

When a tool is called without an interval, the default window is `time_window_minutes` long and ends now in
live mode, or at the bundle's latest collection time in demo and bundle mode.

## Bundle mode

Bundles are directories or ZIP files with a `manifest.json` (`nifimcp-bundle/1`) listing each file, its
kind, size, sha256 and collection time. Import rejects absolute paths, links, duplicates, hash mismatches,
oversize or deeply nested content. See `src/nifimcp/demo_data/telemetry-intake/` for a complete example.

```sh
nifimcp register --config operator.json --kind bundle --label orders ./orders-bundle
nifimcp register --config operator.json --kind flow_definition --label before ./before.json
nifimcp unregister --config operator.json <artifact_id>      # remove one again
```

Registering the same bundle twice is harmless. A different bundle for a scope that is already registered is
refused; unregister the old one first.
