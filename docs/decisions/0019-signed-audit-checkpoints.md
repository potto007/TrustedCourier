---
status: accepted
date: 2026-09-15
decision-makers: Paul Otto
---

# Audit checkpoints sign the chain head in a linked binary message, and Deliveries wait for the key

## Context and Problem Statement

ADR-0007 settled that TrustedCourier signs the audit chain head with Ed25519 every N records or T seconds, using an audit signing key held as a Courier Key. Building it (#10) raised questions it left open: what the signature covers, where checkpoints live, how the key is configured and held, what happens before the key loads, and what `tc audit verify` can and cannot catch with checkpoints in place.

## Considered Options

* Sign a JSON encoding of the checkpoint, or a fixed binary message
* Checkpoints on their own, or each naming the checkpoint before it
* Hold the key as an `ed25519.PrivateKey` on the heap, or in locked memory like a Secret
* When the key cannot be loaded: exit at boot, or keep retrying and answer Agents with 503
* Stream checkpoints on stdout beside Audit Records, or keep them in SQLite only

## Decision Outcome

* **Config.** `audit.signing_key` names a `backend` and `location`, like a Secret Name. It is required when `agent_api.listen` is set. `audit.checkpoints.records` (default 1000, at least 1) and `audit.checkpoints.interval` (default `1m`, at least `1s`) set the cadence. A Secret Name mapped to the key's backend and location is refused, since a Courier Key is never delivered to Agents.
* **The key.** The Backend holds one PKCS #8 PEM `PRIVATE KEY` block with an Ed25519 key, as `openssl genpkey -algorithm ed25519` writes, and nothing else. The core parses it into `secret.Ed25519Key`, whose private key sits in locked memory outside the heap and which prints as a placeholder and refuses to marshal, like a Secret (ADR-0012). The fetched PEM is released once parsed.
* **Deliveries wait for the key.** After the Backend Plugins start, the key is fetched in the background, with retries from 250 ms up to 5 s. Until it loads, every Agent API request gets 503 with `Retry-After`, before its Agent Token is checked, so no Audit Record is written. `tc status` reports whether the key is loaded and why not. `POST /v1/audit/verify` also answers 503 without it. Exiting at boot was rejected because a Backend that starts after TrustedCourier, as in docker compose, would need an external restart loop. The admin API stays up to explain the failure.
* **What is signed.** A checkpoint covers record `seq`. Its signature is Ed25519 over `TrustedCourier audit checkpoint\x00`, then `seq`, `prev_seq`, and the time in Unix milliseconds as big-endian 64-bit integers, then the record's 32-byte hash. `prev_seq` is the record the checkpoint before it covered, or 0 for the first. A fixed binary message leaves no encoder choices to disagree on. The context string keeps the key's signatures from being valid for anything else.
* **Where.** Checkpoints live in the `audit_checkpoints` table, one row per covered record: `seq`, `prev_seq`, `time`, `head`, `signature`. They are not streamed. The stream already carries every record, and a stream consumer holding the chain gains little from signatures it would also need the public key to check. They can be added later as a separate line type.
* **When.** A checkpoint is signed in `Append` once `records` records follow the last one, on a ticker every `interval` when any record does, and at shutdown after both APIs drain, before the database closes. A failed checkpoint is logged and retried on the next append or tick.
* **Verify.** After walking the records (ADR-0016), verify walks the checkpoints covering the intact records and reports the first that does not verify with the loaded key, names a `prev_seq` other than the last good checkpoint (a checkpoint was deleted), or does not match its record's hash (the chain was rewritten). Such a break is reported ahead of any record break, since it lies earlier. The reported intact count is then the last good checkpoint's `seq`. A checkpoint past the chain's end reports the first missing record. While the server runs, verify also compares the last checkpoint with the one this process signed.

### Consequences

* Good, because a chain rewritten with recomputed hashes, a record deleted at the tail while the server was stopped, and a deleted checkpoint are all detectable from SQLite and the public key alone.
* Good, because a Backend that comes up late delays Deliveries instead of crashing TrustedCourier.
* Bad, because someone with database write access can still remove the newest records together with every checkpoint after the last one they keep, while the server is stopped. Records after the last surviving checkpoint are signed at the next checkpoint without question, so a rewrite of that tail is not caught either. Only the stream witnesses those.
* Bad, because rotating the audit signing key makes every earlier checkpoint fail verification. Verifying against previous public keys needs its own design.
* Bad, because `crypto/ed25519` caches an expanded copy of the key on the heap per signing call, keyed by a weak pointer that memory outside the heap cannot have. Each call signs with a heap copy that is wiped afterwards, but the cached expansion is not wiped, only dropped when the garbage collector evicts it. Adopt Go `runtime/secret` once it leaves experiment.
