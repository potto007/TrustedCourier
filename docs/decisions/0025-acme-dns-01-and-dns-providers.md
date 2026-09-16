---
status: accepted
date: 2026-09-15
decision-makers: Paul Otto
---

# DNS-01 sets records through built-in providers spoken with the standard library, with credentials as Courier Keys per field

## Context and Problem Statement

ADR-0006 requires DNS-01 for private networks and wildcards, with DNS provider credentials fetched from a Backend and providers from a built-in set. ADR-0024 chose `x/crypto/acme`, which carries no DNS providers. Building DNS-01 (#15) raised what neither settles: how the providers reach their APIs, how their credentials are configured, how a multi-part credential is stored, when validation is asked for, how many records live at a name at once, and how the harness proves any of it without a real zone.

## Considered Options

* Provider clients: each vendor's SDK, lego's provider tree, or hand-written clients on the standard library
* Credentials: one Secret holding a JSON document, or one Courier Key per credential field
* Provider settings: a nested section per provider, or flat keys under `dns` validated per provider
* Validation timing: accept the challenge at once, wait a fixed delay, or look the record up first
* Records at a name: replace the set, or add to and remove from it
* Harness: real zones, or fake vendor APIs over Pebble's DNS test server

## Decision Outcome

Chosen options: hand-written clients, one Courier Key per field, flat keys, look the record up first, add to and remove from the set, and fake vendor APIs over the DNS test server.

* Cloudflare, Route 53, Azure DNS, and Google Cloud DNS are spoken with `net/http` and the standard library: Route 53 by SigV4 (`internal/dnsprovider/sigv4`, proved against the worked example in AWS's documentation), Azure by the client credentials grant, and Google by a service account JWT signed with RS256. The SDKs would each pull a dependency tree the size of the core, and lego brings its own storage and CA handling (ADR-0024). FIPS mode covers everything, since nothing signs outside the standard library.
* Credentials are Courier Keys: `agent_api.tls.acme.dns.credentials.<field>` names a Backend location per field, as `config.DNSProviders` lists the fields for each provider. A JSON document in one Secret was rejected as a second config format hidden in a Backend. A Secret Name may not map to any of them. They are fetched for each order, held for the order, and wiped with the provider when it closes; the bearer tokens Azure and Google exchange them for are held the same way.
* Provider settings sit flat under `dns`: `tenant_id`, `client_id`, `subscription_id`, and `resource_group` for Azure, `project` for Google, and validation refuses a setting of another provider, so a misplaced key fails at load as the strict decoding of ADR-0010 intends. `zone`, `endpoint`, `authority`, `ca_bundle`, `resolvers`, and `propagation_timeout` are common. `endpoint` and `authority` must be `https`, as the ACME directory and Upstreams must.
* The zone that holds a name is found at the provider by walking the name's parents, longest first, unless `zone` names it; a public zone is preferred over a private one with the same name, since the CA resolves through public DNS.
* Validation is asked for only once the record is seen: every record of the order is set, then each is looked up on the zone's authoritative name servers, found through the system resolver, or on `resolvers`, until it appears or `propagation_timeout` passes. Accepting at once fails at providers that take a minute to publish, and a fixed delay is either too short or wastes minutes on every renewal. One propagation wait covers the whole order, so a certificate for several names is not several waits.
* A record is added to the set at its name and removed from it, never replacing the set. A wildcard and its apex validate at the same name, `_acme-challenge.example.com`, so both values must coexist; and a record left by a crashed order must not break the next. Route 53, Azure, and Google carry the set as a whole and are read before they are written; Cloudflare carries one record per value.
* The records are removed however the order ends, on a context that outlives a cancelled or timed-out order for a minute, and a removal that fails is logged for the Operator to finish. A DNS-01 order gets fifteen minutes rather than five.
* The e2e harness runs Pebble's DNS test server, `challtestsrv`, in the test process as Pebble's resolver and TrustedCourier's, and fakes each vendor's API over TLS in `internal/dnsprovider/providertest`, each checking its credentials (Route 53 by re-signing the request) and mirroring its records into the name server. The same fakes drive the provider unit tests. Real zones would need live credentials in CI and would rate-limit every run.

### Consequences

* Good, because a deployment on a private network gets a certificate, wildcard included, with the DNS credential in the same Backend as everything else, and the certificate is never ordered before the record can be seen.
* Good, because the fakes prove each provider's request shape, authentication, and set handling on every run, and a provider change cannot silently drift from the API it was written against.
* Bad, because the four clients are TrustedCourier's to keep in step with the vendors' APIs, without an SDK to do it.
* Bad, because a fake is not the vendor: an API quirk the fake does not model is found in a real deployment.
