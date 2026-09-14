---
status: accepted
date: 2026-09-13
decision-makers: Paul Otto
---

# Go for the whole stack, over a Rust core

## Context and Problem Statement

TrustedCourier is security-critical: it holds plaintext Secrets in memory during Deliveries, especially across the full upstream round-trip of a Proxy Delivery. It also wants a contributor-friendly Backend Plugin ecosystem, and may later be used in regulated or classified environments. Which language for the server and plugins?

## Considered Options

* All-Go
* All-Rust
* Rust core with an official Go plugin SDK (out-of-process gRPC plugins)
* Zig, JVM/.NET, Swift (dismissed early: Zig is not memory-safe and pre-1.0; GC runtimes share Go's memory-wiping limits with heavier runtimes; Swift's Linux server ecosystem is thin)

## Decision Outcome

Chosen option: "All-Go", because simplicity, FIPS 140-3 support and fast CI outweigh Rust's stronger memory-wiping guarantees for this product.

A 20-agent research run with adversarial critique (2026-09-13) recommended "Rust core with Go plugins" at medium confidence; its researchers split 8-8 and the Go-advocate critic held for all-Go. The deciding factors for Go were:

* FIPS 140-3: Go's cryptographic module is CMVP-validated, pure Go, selected with `GOFIPS140` and enabled with `GODEBUG=fips140=on`. Rust's path goes through aws-lc (C FFI) and version pinning. Future use in Secret/Top Secret environments makes this near-mandatory. (go.dev/doc/security/fips140)
* Simplicity: one language across core, plugin SDK and plugins; no custom Rust host for go-plugin (none exists off the shelf).
* CI speed: Rust builds are substantially slower; fast iteration is a priority.
* Ecosystem: official Go SDKs for Vault/OpenBao (`hashicorp/vault/api`) and Kubernetes (`client-go`); the Rust equivalents are community-maintained or CNCF Sandbox.
* Track record: the Go secrets and identity servers reviewed (Vault, OpenBao, Teleport, SPIRE) showed no memory-safety or data-race CVEs.

Accepted costs:

* Go cannot guarantee plaintext erasure the way Rust `zeroize`/`secrecy` can. Go's GC is non-moving, but value semantics and goroutine stack growth create copies, and `runtime/secret` is experimental. Mitigations are in ADR-0001.
* No compile-time data-race prevention; rely on the race detector in CI and ownership discipline around Secret buffers.

The research run also surfaced fabricated claims (invented CVE numbers, an unsupported state-actor attribution, an unsourced latency benchmark); none of those informed this decision.

### Consequences

* Good, because FIPS mode is a runtime switch rather than a build-system project.
* Good, because plugin contributors and core contributors share one toolchain.
* Bad, because memory hygiene for Secrets is a discipline enforced by review and types, not by the compiler.
