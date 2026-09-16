---
status: accepted
date: 2026-09-16
decision-makers: Paul Otto
---

# The remote admin listener requires a client certificate in the handshake and the Operator Credential on every request

## Context and Problem Statement

The admin API is served on a unix socket gated by the connecting user's UID (spec story 62). Story 63 asks for an optional network listener for remote administration that takes two factors: a client certificate plus the Operator Credential. Building it (#16) raised where the listener's own certificate comes from, where the CA that signs Operator client certificates lives, how the two factors are checked, what shares with the Agent listener's TLS (ADR-0023, ADR-0024), and how `tc` targets the listener.

## Considered Options

* Listener certificate: its own Courier Keys, always the Agent API's certificate, or either by naming the same or different locations
* Client CA: a file on disk, or a Courier Key in a Backend
* Client certificate check: in the TLS handshake (`RequireAndVerifyClientCert`), or per request in the handler
* Client identity: map certificate subjects to Operators, or treat any certificate the CA signed as one factor
* `tc` targeting: environment variables, flags, or a config file

## Decision Outcome

Chosen options: "either by naming the same or different locations", "a file on disk", "in the TLS handshake, then again per request", "any certificate the CA signed is one factor", and "environment variables".

* `admin.listen` enables the listener on an IP address and port; it is off when omitted. It needs `admin.tls`, holding `certificate` and `key` as Courier Keys (ADR-0001, ADR-0023) and `client_ca` as a PEM file path. Its port may not be the Agent API's or the HTTP-01 listener's.
* When `admin.tls.certificate` and `key` name the same locations as `agent_api.tls`, the listener shares the Agent API's certificate manager, so an ACME renewal (ADR-0024) covers both. Naming other locations gives the listener its own manager loading an Operator-supplied pair once, with the same retry and expiry behavior as ADR-0023. The listener binds before the Operator Credential is shown and completes no handshake until its certificate is loaded.
* `client_ca` is a file because it holds only public CA certificates: nothing ADR-0001 keeps off the disk, and the same kind of value as an Upstream `ca_bundle`. Changing it takes a restart.
* The listener's `tls.Config` sets `RequireAndVerifyClientCert` with `client_ca` as `ClientCAs`, so a connection without a certificate chaining to it fails in the handshake and no request is read. The handler checks the verified chain again before the Operator Credential, so the admin routes are never served without both. The certificate's subject is not mapped to anything: the CA's signature is the factor, and the Operator Credential is the other. Naming Operators is left to a later version.
* Failed handshakes are logged at Debug, as on the Agent listener: any remote can fail one per connection. A request that reaches the handler without a verified chain is logged at Warn, since the listener should make that impossible.
* `tc` targets the listener with `TC_ADMIN_URL` (`https://host:port`), `TC_ADMIN_CLIENT_CERT` and `TC_ADMIN_CLIENT_KEY` (PEM files on the Operator's machine, which is not TrustedCourier's disk), and optionally `TC_ADMIN_CA_BUNDLE`. With `TC_ADMIN_URL` unset, `tc` uses the socket as before. Environment variables match `TC_ADMIN_SOCKET` and `TC_OPERATOR_CREDENTIAL`; a `tc` config file was not worth adding for four values.

Always sharing the Agent API's certificate was rejected because the admin listener may be enabled without an Agent API on TLS, and a private admin host name may not belong on a public certificate. A client CA in a Backend was rejected because it is not secret and the listener must be able to verify clients before any Backend answers. Checking the certificate only per request was rejected because the handshake check keeps every unauthenticated byte out of the HTTP server.

### Consequences

* Good, because remote administration needs two independent factors, and a leaked Operator Credential alone reaches nothing over the network.
* Good, because one certificate can serve both listeners, renewed by ACME.
* Bad, because revoking one Operator's client certificate means rotating the CA file and restarting; no CRL or OCSP is checked.
* Bad, because the Audit Records do not name which client certificate performed an admin operation; admin operations are logged, not audited.
