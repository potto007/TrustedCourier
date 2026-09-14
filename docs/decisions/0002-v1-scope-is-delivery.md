---
status: accepted
date: 2026-09-13
decision-makers: Paul Otto
---

# v1 scope is Delivery, not encryption-as-a-service or sync

## Context and Problem Statement

TrustedCourier was first framed after HashiCorp Vault's "transit" capability. In Vault, the Transit engine is encryption-as-a-service; moving Secrets between systems is Secrets Sync. The target user is an AI engineer who needs batteries-included secrets for Agents. What does v1 exist to do?

## Considered Options

* Encryption-as-a-service (encrypt/decrypt/sign with keys held in a Backend)
* Sync or replication of Secrets between Backends
* Brokered Delivery of Secrets to Agents
* One-shot migration between Backends

## Decision Outcome

Chosen option: "Brokered Delivery", because it is what Agents actually need (use a credential without it landing in model context, logs or a prompt-injected tool call), and it needs the smallest Backend Plugin contract.

* Proxy Delivery is the default: TrustedCourier injects the Secret into the Agent's outbound request, so the Agent never sees it.
* Reveal Delivery returns the value and must be explicitly permitted by a Policy.
* Encryption-as-a-service was rejected for v1 because only key-manager Backends (Vault/OpenBao Transit, cloud KMS) support it; over plain secret stores TrustedCourier would have to extract key material, breaking the guarantee Transit exists to provide.
* Sync was rejected because it multiplies copies of every Secret, widening blast radius, and serves Operators rather than Agents.

### Non-goals for v1

* Short-lived / leased credentials (dynamic Secrets)
* Sync, migration, encryption-as-a-service
* Multi-tenancy (one deployment serves one Operator's organization)
* High availability / multiple instances
* Human approval of individual Deliveries
* Per-Agent-Token rate limits and quotas
* WebSockets over Proxy Delivery
* Agent-side SDK (OpenAPI spec plus `tc env` instead)
* Web UI

### Consequences

* Good, because every Backend type can serve v1.
* Bad, because users expecting a Vault Transit replacement will not find one in v1.
