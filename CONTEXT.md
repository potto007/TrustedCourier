# TrustedCourier

A self-hosted, backend-agnostic secrets system that gives AI agents batteries-included access to secrets. It exposes one API over pluggable secret backends and never keeps Secrets or Courier Keys on its own disk.

## Language

### People and workloads

**Operator**:
The AI engineer who self-hosts TrustedCourier and configures its backends and access.
_Avoid_: Admin, user, customer

**Agent**:
An AI agent workload that calls the TrustedCourier API to use secrets.
_Avoid_: Client, consumer, app

**Plugin Author**:
A developer who builds and releases a Backend Plugin against the plugin SDK, inside or outside the TrustedCourier project.
_Avoid_: Contributor (bare), vendor, integrator

### Access

**Agent Token**:
The credential an Operator issues to an Agent, identifying that Agent and carrying the Policies attached to it. Every Agent Token has an expiry and can be revoked.
_Avoid_: Token (bare), API key, access key

**Policy**:
A named, Operator-defined rule set stating which Secret Names an Agent Token may use, in which Delivery modes, and optionally which HTTP methods and path prefixes a Proxy Delivery may reach. Attached to Agent Tokens; reused across Agents.
_Avoid_: Scope, role, permission, grant

**Operator Credential**:
The credential that authenticates an Operator to the admin API, created at first boot. Remote admin access additionally requires a client certificate.
_Avoid_: Root token, admin token, master key

### Secrets

**Secret**:
A sensitive value, such as an API key or database credential, held in a Backend and delivered to Agents.
_Avoid_: Credential, key

**Courier Key**:
Key material TrustedCourier itself needs to operate, such as its TLS private key, ACME account key, and audit signing key. Held in a Backend like a Secret, but never delivered to Agents.
_Avoid_: System key, internal secret, operational key

**Secret Name**:
The Operator-defined name an Agent uses to request a Secret, mapped by the Operator to a location in a Backend, its pinned Upstreams, and its Injection Template. Agents never learn which Backend holds a Secret.
_Avoid_: Path, alias, key, reference

**Backend**:
An external system that holds Secrets and is their source of truth, reached through a Backend Plugin.
_Avoid_: Store, provider, engine, vault

**Backend Plugin**:
A separately built and released program that connects TrustedCourier to one kind of Backend. Its responses are treated as untrusted input.
_Avoid_: Driver, connector, adapter, provider

### Delivery

**Delivery**:
TrustedCourier putting a Secret to use on an Agent's behalf in response to its request, scoped and audited.
_Avoid_: Transit, sync, fetch

**Proxy Delivery**:
A Delivery where TrustedCourier injects the Secret into the Agent's outbound request to an Upstream, so the Agent never sees the value. The default mode.
_Avoid_: Injection, passthrough

**Reveal Delivery**:
A Delivery where TrustedCourier returns the Secret's value to the Agent. Allowed only where a Policy explicitly permits it.
_Avoid_: Read, get, fetch

**Upstream**:
The external service a Proxy Delivery forwards to; each Secret may only be delivered to the Upstreams it is pinned to.
_Avoid_: Target, destination, endpoint

**Injection Template**:
The Operator-defined rule for where a Secret goes in a proxied request, such as a header, query parameter, or basic auth. Never chosen by the Agent.
_Avoid_: Mapping, format

**Preset**:
A built-in Injection Template and Upstream pin for a well-known service, such as OpenAI or GitHub, that an Operator can apply to a Secret Name.
_Avoid_: Profile, integration, connector

**Redaction**:
Removing a Secret's value from an Upstream's response before it reaches the Agent, so a Proxy Delivery never leaks the Secret back.
_Avoid_: Scrubbing, masking, filtering

### Audit

**Audit Record**:
The tamper-evident record of one Delivery attempt, allowed or denied. Never contains a Secret's value or request or response bodies.
_Avoid_: Log entry, event, access log
