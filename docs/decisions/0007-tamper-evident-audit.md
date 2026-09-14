---
status: accepted
date: 2026-09-13
decision-makers: Paul Otto
---

# Audit Records are hash-chained with signed checkpoints

## Context and Problem Statement

Every Delivery attempt, allowed or denied, produces an Audit Record. A plain log in SQLite can be silently rewritten by anyone with write access to the database. How much tamper evidence does v1 need, and where does a signing key live when TrustedCourier keeps no key material on disk?

## Considered Options

* Append-only records, no tamper evidence
* Hash chain, witnessed only by the external JSON stream
* Hash chain plus Ed25519-signed checkpoints, signing key held as a Courier Key
* Signing performed inside a Backend (e.g. OpenBao Transit)

## Decision Outcome

Chosen option: "Hash chain plus signed checkpoints", because a chain alone can be rebuilt by anyone who can write the database, and checkpoints make the trail verifiable without the external stream.

* Each Audit Record carries the previous record's hash and contains the Agent Token ID, Secret Name, Delivery mode, Upstream host, Policy decision and Upstream status code; never a Secret's value or request/response bodies.
* Every N records or T seconds, TrustedCourier signs the chain head with Ed25519 (FIPS 186-5 approved).
* The signing key is a Courier Key fetched from a Backend at boot and held only in memory (ADR-0001).
* Records are written to SQLite and streamed as JSON lines for shipping off-box (Loki, SIEM).
* Backend-side signing was rejected: it would tie the audit trail to Backends with key operations, breaking backend-agnosticism.

### Consequences

* Good, because tampering with the SQLite trail is detectable from the database alone.
* Bad, because TrustedCourier cannot sign checkpoints until a Backend is reachable.
