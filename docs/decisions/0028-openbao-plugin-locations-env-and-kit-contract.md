---
status: accepted
date: 2026-09-16
decision-makers: Paul Otto
---

# The OpenBao plugin addresses KV fields, is configured by environment, and the conformance kit makes malformed Secrets the plugin's error

## Context and Problem Statement

ADR-0008 bundles OpenBao as the default Backend, as a Backend Plugin like any other (ADR-0004). Building it (#18) raised questions the earlier ADRs leave open: what a Backend location means in OpenBao, how a plugin that runs as a separate OS user with no access to the config (ADR-0011) learns its Backend's address and credentials, which library speaks to OpenBao inside the FIPS boundary (ADR-0027), and what the conformance kit should demand of a plugin when a Backend holds something at a location that is not a Secret.

## Considered Options

* Location is a KV record path; the plugin serves the whole record as JSON
* Location is `<path>#<field>`; the plugin serves one string field
* Configure plugins through a per-plugin config file the core writes
* Configure plugins through `backend_plugins.<name>.env` in the server config, with credentials in a file the plugin user can read
* Speak to OpenBao through the OpenBao or Vault API client module
* Speak to OpenBao with the standard library's HTTP client
* The kit accepts any error for a malformed Secret, the SDK's own refusal included
* The kit requires the plugin's own error, never `ErrNotFound` and never a malformed response

## Decision Outcome

Chosen options: "`<path>#<field>`", "`env` in the server config", "standard library", and "the plugin's own error".

* A location is the record's API path and a field in it: `secret/data/openai#key` on a KV v2 mount, `kv/openai#key` on a KV v1 mount. The field must be a non-empty JSON string. Serving a whole record was rejected because a Secret is one value that goes in one header; a JSON document is not what an Injection Template injects, and Courier Keys such as a TLS key and its certificate are naturally two fields of one record. The path is the API path, `data/` included for KV v2, so what an Operator reads with the CLI and what they write in the config line up without the plugin guessing the mount's version. `List` walks every KV mount the token can see and reads each record under the prefix to name its fields, so it is a diagnostic, not a hot path.
* Courier Key writes keep the record's other fields: the plugin reads the record, sets the one field, and writes it back, check-and-set against the version it read on KV v2, retrying a few times when another writer got in between. Replacing the record was rejected because the audit signing key and the TLS pair may share one record. Values must be text: OpenBao KV holds JSON strings, and every Courier Key TrustedCourier stores is PEM or base64url.
* A Backend Plugin's environment is `backend_plugins.<name>.env` in the server config, passed by the Plugin Host beside `GODEBUG`, which stays reserved for the server's FIPS 140-3 mode (ADR-0027). The OpenBao plugin reads `BAO_ADDR`, `BAO_TOKEN_FILE` or `BAO_TOKEN`, `BAO_CACERT`, and `BAO_NAMESPACE`. A file the core writes for the plugin was rejected: it is another file on TrustedCourier's disk to protect, and a plugin that cannot read the config should not depend on the core to arrange its filesystem. The token belongs in a file the plugin user can read, not in the config, which is reviewed in Git.
* The plugin speaks OpenBao's HTTP API with the standard library only: `X-Vault-Token` on every request, TLS 1.2 or later verified against the system roots or `BAO_CACERT`, no redirects followed, no skip-verify. The API client modules were rejected because the plugin needs five endpoints, and each module brings its own HTTP and retry stack, and dependencies, into the FIPS boundary.
* The conformance kit's `Malformed` fixture names locations where the Backend holds something that is not a Secret. A conforming plugin fails `Get` there with its own error saying what is wrong; `ErrNotFound` is wrong because the Backend does hold something, and letting the SDK refuse the value is wrong because the core reports that as a plugin defect (`client.ErrMalformed`, mapped from the SDK's `Internal` status) rather than as a Backend state an Operator can fix. The kit also launches the plugin with `GODEBUG=fips140=on` and `only` whatever mode the kit runs in, so one run covers the FIPS handshake a core in either mode performs, and calls the plugin concurrently, as the core does.

### Consequences

* Good, because the OpenBao plugin's dependencies are the SDK and the standard library, and it follows the core's FIPS mode with nothing to audit.
* Good, because a plugin's error for a bad Secret reaches the Operator through `tc status` and the log as the plugin wrote it.
* Bad, because a Courier Key cannot be binary; anything TrustedCourier stores must be text, which every current Courier Key is.
* Bad, because `List` reads every record under a prefix; a short prefix on a large mount is slow.
* Bad, because the plugin does not renew its token; an expiring token shows in health as a warning an hour out, and an Operator must issue a periodic or long-lived token.
