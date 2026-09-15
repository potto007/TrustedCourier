---
status: accepted
date: 2026-09-15
decision-makers: Paul Otto
---

# Deliveries stop while Audit Records cannot be stored

Supersedes the part of ADR-0016 that lets Deliveries go ahead when their Audit Record cannot be stored.

## Context and Problem Statement

ADR-0016 writes each Audit Record when its Delivery ends. A failed write was logged at error level and nothing else changed, so a full disk or a failing volume let TrustedCourier keep delivering Secrets with no record at all. ADR-0019 already refuses Deliveries while the audit signing key is not loaded, which left fail-closed signing next to fail-open recording.

Comparable systems fail closed on recording. Vault refuses a request when no audit device can log it, and Kubernetes' `blocking-strict` audit mode fails the request. NIST SP 800-53 AU-5(4) calls for a shutdown or a degraded mode on audit logging failure unless an alternate audit logging capability exists.

## Considered Options

* Keep going and log the failure (ADR-0016)
* Write a record before each Delivery and another when it ends, and refuse the Delivery when the first write fails
* Keep a record that cannot be stored in memory, retry it, and refuse new Deliveries until every waiting record is stored

## Decision Outcome

Chosen option: "keep it in memory, retry, and refuse new Deliveries", because it closes the gap without changing the record format ADR-0016 and ADR-0019 build on.

* A record that cannot be stored joins a backlog in memory with its original time. Every later record joins behind it, so the chain keeps its order. The backlog is retried with backoff from 250 ms to 5 s, and on every append.
* While the backlog is not empty, the Agent API answers every request with 503 and `Retry-After`, before checking the Agent Token, as it does while the audit signing key is not loaded. So the backlog grows only by Deliveries that were already under way.
* `tc status` reports how many records are waiting and the storage error. Recovery is logged, and Deliveries resume on their own.
* A failure after a record is stored, such as writing it to stdout or signing a checkpoint, does not refuse Deliveries. The record is safe, and checkpoints are retried (ADR-0019).
* At shutdown the backlog gets one last attempt. Each record still waiting is logged at error level as its JSON object, since records hold no Secret values.

Writing a record before each Delivery was rejected. The record would need a second, outcome record, which doubles the records, breaks "one record per Delivery attempt", and changes the chain format stream consumers already check.

### Consequences

* Good, because TrustedCourier no longer delivers Secrets while it cannot record them, and a transient storage failure loses no record.
* Good, because the chain and stream formats are unchanged.
* Bad, because the Deliveries under way when storage fails still complete before their records are stored. Their records are stored later, or only logged if the process stops first.
* Bad, because a crash while records are waiting loses them, logs included.
