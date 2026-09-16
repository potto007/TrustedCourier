---
status: accepted
date: 2026-09-15
decision-makers: Paul Otto
---

# ACME issues into the TLS Courier Keys, validates on the Agent listener, and renews at two thirds of the lifetime

## Context and Problem Statement

ADR-0006 requires built-in ACME with TLS-ALPN-01, HTTP-01, and DNS-01, an Operator-configurable directory with External Account Binding, and the account key and certificates as Courier Keys in a Backend. ADR-0023 built the certificate manager as the seam. Building TLS-ALPN-01 and HTTP-01 (#14) raised what ADR-0006 does not settle: which ACME client, where the issued pair lives in config, how a challenge is answered, when to renew, what happens with a Backend that cannot store Courier Keys, and how the harness proves any of it.

## Considered Options

* ACME client: `golang.org/x/crypto/acme`, a third-party library such as lego or certmagic, or a hand-written RFC 8555 client
* Issued pair: its own config keys, or the existing `agent_api.tls.certificate` and `key` locations
* Read-only Backend: refuse the config at startup, or report it at runtime and order nothing
* Renewal: at a fixed number of days before expiry, or at a fraction of the lifetime
* Harness: a Pebble binary, or Pebble's packages in the test process

## Decision Outcome

Chosen options: `x/crypto/acme`, the existing locations, report at runtime, a fraction of the lifetime, and in-process Pebble.

* `golang.org/x/crypto/acme` is the client. It signs and hashes with the standard library only, so FIPS mode covers it, and it carries no DNS providers or storage of its own, which would duplicate the Backend. lego and certmagic bring their own storage, CA bundles, and provider trees. A hand-written client was rejected as a source of protocol bugs the library has already fixed. One CA quirk is handled in `internal/acmecert`: a finalize response without a `Location` header (Pebble) leaves the library nothing to poll, so the order is polled by its own URL.
* `agent_api.tls.acme` sits beside `certificate` and `key`. ACME writes the chain and the leaf's PKCS #8 key to those same locations, so the Operator-supplied path and the ACME path read the same config keys, and `tc status` reports the same certificate line. `acme.account_key` names a third Courier Key, generated as ECDSA P-256 and stored on first use. Leaf keys are ECDSA P-256 too, freshly generated per issuance.
* TLS-ALPN-01 is the default and needs no extra listener: the certificate manager's `tls.Config` offers `acme-tls/1` beside `h2` and `http/1.1`, and a ClientHello offering only `acme-tls/1` gets the pending challenge certificate for its server name. The Agent API therefore must be reachable on port 443 of every domain. HTTP-01 binds its own plain HTTP listener, `acme.http_listen`, before the Operator Credential is shown like every listener, and serves nothing but `/.well-known/acme-challenge/`. Wildcards are refused in config: neither challenge can validate them, and DNS-01 is #15.
* Backend Plugin capabilities are known only once the plugin runs, so a read-only Backend cannot be refused by config validation. Instead, before every order, the certificate manager checks that every Backend it will write to has `courier-key-write`; without it, nothing is ordered, `tc status` reports why no certificate is loaded, and the Operator supplies the pair instead. Ordering first and failing to store would burn Let's Encrypt's rate limits on every retry.
* A stored pair is loaded at startup and served when it is valid and names every configured domain, so a restart never re-issues. Renewal is at two thirds of the certificate's lifetime, which is Let's Encrypt's recommendation and scales to short-lived certificates. The loaded certificate is served until it expires while a renewal keeps failing, and the failure is reported beside `loaded` in `tc status`. Failed orders retry from 30 seconds doubling to an hour; failed Backend fetches retry as for an Operator-supplied pair.
* External Account Binding takes `key_id` in config and the base64url MAC key as a Courier Key, decoded in memory only for registration. The directory is verified with the system roots or `ca_bundle`, as an Upstream is.
* The e2e harness runs Pebble's `ca`, `va`, and `wfe` packages in the test process behind an `httptest` TLS server, validating against ports the test chose, with a profile whose validity is seconds long for the renewal test. A Pebble binary would need downloading in CI and a fixed port per test. Pebble is a test-only dependency of the main module.

### Consequences

* Good, because a default deployment on port 443 gets a certificate with three config lines and keeps it across restarts.
* Good, because the same Backend holds everything TLS, and a read-only Backend fails loudly before any CA is contacted.
* Bad, because the main module's `go.mod` carries Pebble and its dependencies for the tests.
* Bad, because a read-only Backend is discovered when the plugin starts, not when the config is validated.
