---
status: accepted
date: 2026-09-13
decision-makers: Paul Otto
---

# TLS is required, with built-in ACME from v1

## Context and Problem Statement

Agent Tokens and Reveal Deliveries travel between Agents and TrustedCourier. Requiring TLS but leaving certificate management to the Operator pushes most deployments onto plain HTTP, and retrofitting certificate management later would break configs and backward compatibility.

## Considered Options

* TLS required, Operator supplies certificates
* TLS required, auto-generated self-signed certificate
* TLS required, built-in ACME
* Plain HTTP allowed anywhere

## Decision Outcome

Chosen option: "TLS required, built-in ACME", because good certificate management is part of the product, not technical debt to pay down later.

* TLS is required on every listener except loopback and unix sockets.
* Challenge types: TLS-ALPN-01, HTTP-01, and DNS-01. DNS-01 covers private networks, where self-hosted Agents usually run; DNS provider credentials are Secrets fetched from a Backend, and providers come from a built-in set.
* The ACME directory is configurable, defaulting to Let's Encrypt, with External Account Binding support, so internal ACME CAs (step-ca, enterprise PKI, air-gapped networks) work.
* The ACME account key and certificate private keys are Courier Keys stored in a Backend (ADR-0001). Keeping them in memory only was rejected: re-issuing on every restart would hit Let's Encrypt's duplicate-certificate rate limit.
* Operator-supplied certificates remain supported, and are required when the Backend is read-only.
* A self-signed default was rejected: it recreates the CA-trust problem rejected in ADR-0005.

### Consequences

* Good, because a default deployment gets real certificates without Operator effort.
* Bad, because TrustedCourier carries ACME logic and a set of DNS provider integrations.
