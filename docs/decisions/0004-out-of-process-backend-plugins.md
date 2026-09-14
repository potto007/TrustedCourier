---
status: accepted
date: 2026-09-13
decision-makers: Paul Otto
---

# Backend Plugins run out of process via hashicorp/go-plugin

## Context and Problem Statement

Backends must be fully pluggable, and a broad contributor ecosystem is a goal. Backend Plugins necessarily handle plaintext Secrets. How are they built, loaded and trusted?

## Considered Options

* Compiled-in Go interface, Backends selected by build tags
* Out-of-process plugins over gRPC via hashicorp/go-plugin, wrapped by a TrustedCourier plugin SDK
* WASM components

## Decision Outcome

Chosen option: "Out-of-process plugins via go-plugin", because it is the proven model for plugin ecosystems in this space (Vault, Terraform), lets plugins release independently of the core, and puts a process boundary around each plugin.

* Plugin authors depend only on the `sdk/plugin` Go module, which wraps go-plugin, and validate their plugin with the conformance kit.
* The bundled OpenBao Backend is the first out-of-process plugin, proving the seam from day one.
* The Operator lists each plugin in config with its path and pinned SHA-256; the core refuses a binary that does not match.
* Plugins run as a separate OS user with no access to the core's SQLite database or config.
* The core treats every plugin response as untrusted input (a compromised plugin can send malformed protobuf).
* When the core runs in FIPS mode, it refuses any plugin whose handshake does not report FIPS mode; each plugin process is inside the FIPS boundary.
* Backend Plugins may optionally implement a write capability, used only for Courier Keys (ADR-0001).

WASM was rejected because Backends need network access and cloud SDKs, where WASI support is still immature. Compiled-in was rejected because every contributed Backend would need to be merged and released with the core, and adding a wire protocol later would break every existing Backend.

### Consequences

* Good, because a crashing or compromised plugin does not share the core's address space.
* Bad, because the core must supervise plugin processes and version the plugin protocol.
* Neutral, because go-plugin is MPL-2.0 (file-level copyleft) while TrustedCourier is Apache-2.0; using it as an unmodified dependency is compatible.
