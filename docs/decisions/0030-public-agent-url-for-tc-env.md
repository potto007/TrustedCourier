---
status: accepted
date: 2026-09-16
decision-makers: Paul Otto
---

# tc env uses an explicit public Agent API origin when configured

## Context and Problem Statement

The Compose deployment binds the Agent API to `0.0.0.0:8200` and publishes port
443. The listener address cannot tell `tc env` which hostname or external port
an Agent reaches. Issue #46 requires an explicit URL without changing the Agent
Token placeholder chosen in ADR-0017 or the TLS policy in ADR-0006.

## Considered Options

* Infer the hostname from an ACME certificate and reuse the listener port
* Require a URL override on every CLI invocation
* Configure a public origin alongside the Agent API listener

## Decision Outcome

Add optional `agent_api.public_url`. The admin API uses it to build the
`/proxy/<secret-name>/<upstream>` URL returned by `tc env`, including its scheme
and external port. Without it, the actual listener address remains the source.
An ACME hostname cannot identify a mapped port, and storing the origin once
keeps CLI and admin API output consistent.

The URL is an origin with a DNS hostname or IP address and an optional port from
1 to 65535. A trailing root slash is normalized away. Credentials, other paths,
queries, fragments, unspecified IPs, multicast IPs, and scoped IPs are rejected.
HTTPS is required except for literal loopback IPs. Validation does not resolve
hostnames. The setting does not configure forwarding or relax listener TLS.

The setting requires `agent_api.listen` and follows the existing restart rule
for Agent API configuration. Unix socket listeners still have no printable
base URL. No change is made to the Agent Token placeholder.

### Consequences

* Operators can generate Agent configuration for Compose and mapped ports.
* Operators must keep the public URL, forwarding, and certificate names aligned.
* Public URL changes require a restart, like other Agent API configuration.
