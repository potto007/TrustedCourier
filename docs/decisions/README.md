# Architecture Decision Records

MADR records of settled, non-obvious decisions. Accepted ADRs are immutable: supersede, never edit.

| ADR | Title | Status |
| --- | --- | --- |
| [0001](0001-no-secrets-or-courier-keys-on-disk.md) | TrustedCourier keeps no Secrets or Courier Keys on its own disk | accepted |
| [0002](0002-v1-scope-is-delivery.md) | v1 scope is Delivery, not encryption-as-a-service or sync | accepted |
| [0003](0003-go-over-rust-core.md) | Go for the whole stack, over a Rust core | accepted |
| [0004](0004-out-of-process-backend-plugins.md) | Backend Plugins run out of process via hashicorp/go-plugin | accepted |
| [0005](0005-proxy-delivery-by-base-url-route.md) | Proxy Delivery uses a base URL route with the Agent Token in the credential slot | accepted |
| [0006](0006-tls-with-built-in-acme.md) | TLS is required, with built-in ACME from v1 | accepted |
| [0007](0007-tamper-evident-audit.md) | Audit Records are hash-chained with signed checkpoints | accepted |
| [0008](0008-bundled-openbao-static-seal.md) | OpenBao is the bundled default Backend, bootstrapped by `tc init` with a static seal | accepted |
| [0009](0009-pure-go-sqlite.md) | Embedded SQLite through the pure-Go modernc.org/sqlite driver | accepted |
| [0010](0010-yaml-config-strict-decoding.md) | The config file is YAML, decoded strictly | accepted |
| [0011](0011-backend-plugin-host-and-protocol.md) | How the core launches and trusts Backend Plugins | accepted |
| [0012](0012-reveal-delivery-api-and-secret-memory.md) | Reveal Delivery's Agent API and how the core holds a Secret | accepted |
| [0013](0013-proxy-delivery-routes-slots-and-upstream-trust.md) | Proxy Delivery's routes, credential slots, and Upstream trust | accepted |
| [0014](0014-redaction-masks-in-place.md) | Redaction masks the Secret in place and reads responses as plain bytes | accepted |
| [0015](0015-proxy-stall-limits-and-query-cleaning.md) | Proxy Delivery's stall limits guard writes, count uploads, and log cut-offs; unparsable query parameters are dropped | accepted |
| [0016](0016-audit-record-stream-chain-and-verify.md) | Audit Records stream on stdout, start at authentication, and chain over their JSON encoding | accepted |
| [0017](0017-injection-template-kinds-presets-and-tc-env.md) | Query and basic auth Injection Templates, Presets as data, and `tc env` | accepted |
| [0018](0018-policy-method-and-path-limits.md) | Policies limit Proxy Delivery by method and by path prefix on whole decoded segments | accepted |
| [0019](0019-signed-audit-checkpoints.md) | Audit checkpoints sign the chain head in a linked binary message, and Deliveries wait for the key | accepted |
| [0020](0020-deliveries-stop-while-audit-records-cannot-be-stored.md) | Deliveries stop while Audit Records cannot be stored (supersedes part of 0016) | accepted |
| [0021](0021-config-reload-swaps-snapshots.md) | Config reload swaps whole snapshots and changes only access | accepted |
| [0022](0022-secret-cache-per-secret-name.md) | The Secret cache is keyed by Secret Name, bounded to an hour, and hands out copies | accepted |
| [0023](0023-agent-listener-tls-and-unix-socket.md) | The Agent listener serves TLS from Courier Keys, or plain HTTP on loopback or a unix socket | accepted |
| [0024](0024-acme-issuance-and-renewal.md) | ACME issues into the TLS Courier Keys, validates on the Agent listener, and renews at two thirds of the lifetime | accepted |
| [0025](0025-acme-dns-01-and-dns-providers.md) | DNS-01 sets records through built-in providers spoken with the standard library, with credentials as Courier Keys per field | accepted |
| [0026](0026-remote-admin-listener-mutual-tls.md) | The remote admin listener requires a client certificate in the handshake and the Operator Credential on every request | accepted |
| [0027](0027-fips-mode-plugin-parity-and-process-hardening.md) | FIPS mode is reported in the plugin's Capabilities response, enforced by the Plugin Host, and the binaries link the validated module | accepted |
| [0028](0028-openbao-plugin-locations-env-and-kit-contract.md) | The OpenBao plugin addresses KV fields, is configured by environment, and the conformance kit makes malformed Secrets the plugin's error | accepted |
| [0029](0029-tc-init-seal-key-hand-off-and-bootstrap-order.md) | tc init writes the seal key OpenBao waits for, then finishes the bootstrap through the Backend Plugin | accepted |
| [0030](0030-public-agent-url-for-tc-env.md) | tc env uses an explicit public Agent API origin when configured | accepted |
