---
status: accepted
date: 2026-09-14
decision-makers: Paul Otto
---

# Embedded SQLite through the pure-Go modernc.org/sqlite driver

## Context and Problem Statement

TrustedCourier keeps Agent Token hashes, the Operator Credential hash, and Audit Records in embedded SQLite (ADR-0001). It ships as a single static binary, runs its tests with the race detector, and must run in FIPS 140-3 mode on the standard binary (ADR-0003). Which SQLite driver?

## Considered Options

* `modernc.org/sqlite`: SQLite transpiled to Go, no cgo
* `github.com/mattn/go-sqlite3`: cgo bindings to the C amalgamation
* `github.com/ncruces/go-sqlite3`: SQLite compiled to WASM, run in wazero

## Decision Outcome

Chosen option: "modernc.org/sqlite", because it keeps the core cgo-free, so a static binary and cross-compilation need no C toolchain, and it is the most widely used pure-Go driver.

* The driver does no cryptography, so it has no bearing on the FIPS boundary; hashing stays in Go's validated module.
* The database file is created owner-only (0600) before SQLite opens it; its WAL and shared-memory files inherit that mode.
* Schema migrations are ordered SQL statements tracked with `PRAGMA user_version`.

### Consequences

* Good, because `CGO_ENABLED=0` builds work for every target.
* Bad, because the transpiled driver is slower than the C bindings; TrustedCourier's write volume (token issuance, Audit Records) is far below where that matters.
* Neutral, because the race detector itself still needs cgo in CI; that affects the test build only.
