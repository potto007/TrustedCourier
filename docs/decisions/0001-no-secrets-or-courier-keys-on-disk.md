---
status: accepted
date: 2026-09-13
decision-makers: Paul Otto
---

# TrustedCourier keeps no Secrets or Courier Keys on its own disk

## Context and Problem Statement

TrustedCourier brokers Secrets from pluggable Backends to Agents. It still needs its own state (Backend connections, Secret Names, Policies, Agent Tokens, Audit Records) and its own key material (TLS private key, ACME account key, audit signing key). Where may secret material live?

## Considered Options

* Nothing secret on TrustedCourier's disk; Backends hold Secrets and Courier Keys
* Encrypted local cache or staging area for Secrets
* TrustedCourier ships its own secret store as one more Backend
* Courier Keys on local disk, encrypted with a key fetched from a Backend

## Decision Outcome

Chosen option: "Nothing secret on TrustedCourier's disk", because Backends stay the only source of truth, which is the strongest trust story and keeps "backend-agnostic" honest.

* Non-secret state lives in a config file (Backends, Secret Names, Policies; reviewable in Git) and embedded SQLite (Agent Token hashes, Audit Records).
* Courier Keys are written to and read from a Backend through an optional Backend Plugin write capability. If the Backend is read-only, the Operator supplies TLS certificates instead.
* An optional per-Secret-Name in-memory cache with an Operator-set TTL is allowed, off by default, wiped on expiry and shutdown. Memory is not "at rest"; enabling the cache is an explicit trade of longer plaintext lifetime for fewer Backend calls.
* In-process plaintext handling: a `Secret` type that never becomes a `string`, is wiped on release and never logged; `mlock` on Secret buffers; core dumps disabled; adopt Go `runtime/secret` once it leaves experiment. memguard was rejected because its enclave crypto (NaCl secretbox, `frand`) is not FIPS-approved.

### Consequences

* Good, because compromising TrustedCourier's disk yields no Secrets or Courier Keys.
* Good, because moving a Secret between Backends never touches TrustedCourier state.
* Bad, because the Backend Plugin contract needs a write method, scoped to Courier Keys.
* Bad, because TrustedCourier cannot start serving TLS until a Backend is reachable.
