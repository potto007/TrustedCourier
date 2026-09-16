---
status: accepted
date: 2026-09-15
decision-makers: Paul Otto
---

# The Agent listener serves TLS from Courier Keys, or plain HTTP on loopback or a unix socket

## Context and Problem Statement

ADR-0006 requires TLS on every listener except loopback and unix sockets, and keeps Operator-supplied certificates alongside ACME. ADR-0001 keeps Courier Keys, the TLS private key among them, out of TrustedCourier's disk. Until now the Agent API served plain HTTP on loopback only (ADR-0012). Where does an Operator-supplied certificate come from, what does the listener do before it arrives, how does a unix socket fit, and what stays for ACME (#14)?

## Considered Options

* Certificate and key as files on disk, like `ca_bundle`
* Certificate as a file, key as a Courier Key in a Backend
* Certificate and key both as Courier Keys in a Backend
* Refuse to start until the certificate is loaded, or bind at once and fail handshakes until it is
* Unix socket as a scheme in `agent_api.listen`, or its own `agent_api.socket` key

## Decision Outcome

Chosen options: "both as Courier Keys", "bind at once and fail handshakes until loaded", and "its own `agent_api.socket` key".

* `agent_api.tls.certificate` and `agent_api.tls.key` each name a `backend` and `location`, like `audit.signing_key`. The certificate location holds the chain as PEM, leaf first; the key location holds the leaf's private key as PEM (PKCS #8, PKCS #1, or SEC 1). No Secret Name may map to either location: a Courier Key is never delivered to Agents.
* `agent_api.listen` accepts any IP address and port. Without `agent_api.tls` it must be loopback; with it, TLS is served there and HTTP/2 is negotiated by ALPN. TLS on loopback is allowed.
* `agent_api.socket` serves plain HTTP on a unix socket, with HTTP/2 by prior knowledge as on loopback. It is connectable by every local user, as a loopback port is; Agent Tokens authenticate Agents on both. `listen` and `socket` are exclusive, `tls` needs `listen`, and the socket may not be the admin socket. `tc env` needs `listen`, since a base URL cannot name a socket.
* The listener binds before the Operator Credential is shown, as before, but the certificate is fetched from its Backend in the background once Backend Plugins run, like the audit signing key. Until it loads, every TLS handshake fails; `tc status` reports `TLS certificate: not loaded` with the reason, and the server retries with backoff from 250 ms to 5 s. A certificate that is expired, not yet valid, not PEM, or whose key does not match is not loaded, and the server keeps retrying the Backend, so a corrected pair takes effect without a restart.
* The certificate manager (`internal/certmanager`) owns the loaded certificate and the `tls.Config`. It is the seam ACME (#14) extends with issuance and renewal; v1 loads an Operator-supplied pair once and never refetches it while running. Rotating the pair in the Backend takes a restart. A loaded certificate that expires while the server runs stops being served, and `tc status` reports the expiry, until a restart loads a new one.
* The parsed private key lives on the Go heap: crypto/tls signs with it there, and a signer backed by locked memory was not worth building for v1. The key is parsed by TrustedCourier's own code rather than `tls.X509KeyPair`, so the PEM and DER copies parsing needs are wiped before it returns, and the Secret buffers are released.
* Failed TLS handshakes are logged at Debug: on a network listener any remote can fail one per connection before an Agent Token is looked at, and the cause (no certificate loaded yet, a client that does not trust the CA) is reported by `tc status` or lies with the client.
* The server logs `Agent API listening url=https://<listen>` with the configured host and the bound port, so `0.0.0.0` stays `0.0.0.0` rather than the dual-stack `[::]` the kernel reports; `tc env` prints that URL. An advertised host name for Agents is left to #19.

Files on disk were rejected for the key by ADR-0001, and for the certificate to keep one rule: everything TLS lives in a Backend, which is where ACME will write it. Refusing to start until the certificate loads was rejected because the Operator Credential is shown once and the admin API must serve regardless, as it does while the audit signing key loads (ADR-0019). A scheme prefix in `listen` was rejected because the admin API already uses a `socket` key, and a socket path is a different kind of value from an address.

### Consequences

* Good, because an Operator with a read-only Backend or their own PKI can serve TLS anywhere, with nothing secret on TrustedCourier's disk.
* Good, because the same status and retry behavior covers the audit signing key and the TLS certificate.
* Bad, because a certificate rotated in its Backend takes a restart until ACME lands.
* Bad, because a public certificate must be placed in a Backend rather than simply pointed at.
