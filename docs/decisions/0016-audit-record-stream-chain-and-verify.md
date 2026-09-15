---
status: accepted
date: 2026-09-15
decision-makers: Paul Otto
---

# Audit Records stream on stdout, start at authentication, and chain over their JSON encoding

## Context and Problem Statement

ADR-0007 settled that Audit Records are hash-chained, stored in SQLite, and streamed as JSON lines. Building them (#9) raised questions it left open: where the stream goes, which requests count as a Delivery attempt, when the record is written, what exactly the hash covers, and how `tc audit verify` reads the chain without stalling Deliveries.

## Considered Options

* Stream to stdout, a configured file, or both
* Record every request to a Delivery route, or only those with an authenticated Agent Token
* Write the record before the Delivery, or when it ends
* Hash a column-by-column binary encoding, or the record's JSON encoding
* Verify by opening the database from `tc`, or inside the server through the admin API

## Decision Outcome

* **Stdout.** The server writes one JSON object per line to stdout, and nothing else once the first-boot Operator Credential banner has been shown. Logs stay on stderr. systemd, docker, and promtail all capture stdout, so shipping needs no extra config key. A file target can be added later without changing the format.
* **An attempt starts when the Agent Token authenticates.** Every request that reaches a Delivery route with a valid Agent Token produces exactly one Audit Record, including 400s for a dot segment or a protocol upgrade, which are recorded as `denied` with that reason. A 401 produces none: there is no Agent Token ID to record, and unauthenticated requests must not be able to fill the database.
* **Written when the Delivery ends.** The record carries the Upstream's status code and, for an allowed Delivery that did not complete, a fixed `failure` text (Secret not fetched, Upstream not reached, response cut off, and so on). It never carries error text from a Backend Plugin or Upstream, which is untrusted and could echo anything. The Agent's cancellation does not stop the write. A failed write is logged at error level. The response has usually been sent by then, so a failed write cannot change it.
* **The hash covers the JSON encoding.** Each record's hash is the SHA-256 of its JSON object without `hash`: fixed fields in a fixed order, time as RFC 3339 in UTC at millisecond precision, `upstream_status` null when there was no response, and `prev_hash` inside it. The first record's `prev_hash` is 32 zero bytes, and `seq` counts up from 1 with no gaps. So a stream consumer can verify the chain with only a JSON encoder and SHA-256. The field list and order are part of the format.
* **Verify runs in the server.** `tc audit verify` calls `POST /v1/audit/verify` on the admin API, and the server walks the chain 1000 records per query, so the one database connection is freed between pages for Deliveries. It reports the first break: a missing `seq`, a record that does not match its hash, or one that does not chain to the record before it.
* **The server holds the chain head in memory.** New records chain to the last record this process appended, not to whatever is last in the database. Removing or replacing records at the end of the chain while the server runs is therefore reported, both by verify and by the next record, which no longer chains.

### Consequences

* Good, because a deleted or altered record anywhere but the tail is detectable from SQLite alone, and the stream is independently checkable.
* Good, because a cut-off or failed Delivery is still one record, so "who used which Secret, where, and when" includes failures.
* Bad, because a tail removed while the server was stopped goes unnoticed until signed checkpoints (#10) exist.
* Bad, because a consumer that does not skip the first-boot banner sees two non-JSON lines at the start of stdout.
