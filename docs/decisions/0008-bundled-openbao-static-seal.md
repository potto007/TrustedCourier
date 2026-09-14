---
status: accepted
date: 2026-09-13
decision-makers: Paul Otto
---

# OpenBao is the bundled default Backend, bootstrapped by `tc init` with a static seal

## Context and Problem Statement

TrustedCourier is batteries-included but stores no Secrets itself (ADR-0001). An Operator with no existing secret store needs something working on day one. OpenBao must be initialized and unsealed; who holds that material?

## Considered Options

* Bundled default Backend written by us (encrypted local store)
* Bundle OpenBao, bootstrapped by `tc init` with OpenBao's `static` seal
* Bundle OpenBao in dev mode only
* No default Backend; Operator brings one

## Decision Outcome

Chosen option: "Bundle OpenBao, bootstrapped by `tc init` with a static seal", because it delivers batteries-included without us writing and maintaining encryption at rest, seal/unseal, and a storage engine, and OpenBao also supports the Courier Key write capability.

* `tc init` initializes OpenBao with the `static` seal, generates the unseal key, and shows the Operator the key and recovery material exactly once. TrustedCourier never stores them.
* `tc init --dev` runs OpenBao in in-memory dev mode for demos.
* The docker compose file ships TrustedCourier and OpenBao together.
* OpenBao is a Backend Plugin like any other (ADR-0004); nothing in the core depends on it.

### Consequences

* Good, because a new Operator is running with one compose file and one command.
* Bad, because a static seal key stored on the same host as OpenBao's data is a convenience, not a security boundary; the docs must say so and point to KMS or HSM seals for production.
