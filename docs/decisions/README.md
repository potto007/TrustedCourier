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
