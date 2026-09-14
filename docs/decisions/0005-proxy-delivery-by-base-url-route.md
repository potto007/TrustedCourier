---
status: accepted
date: 2026-09-13
decision-makers: Paul Otto
---

# Proxy Delivery uses a base URL route with the Agent Token in the credential slot

## Context and Problem Statement

Proxy Delivery must inject a Secret into an Agent's outbound request without the Agent ever seeing it, with no changes to Agent code where possible. How does the Agent reach TrustedCourier, and how does it authenticate?

## Considered Options

* Base URL route (`https://<tc>/proxy/<secret-name>/...`), Agent Token in the Upstream credential slot
* Base URL route, Agent Token in a separate header
* Forward proxy (`HTTPS_PROXY`) with TLS interception
* Agent Token in the URL path

## Decision Outcome

Chosen option: "Base URL route with the Agent Token in the credential slot", because nearly every AI/API SDK supports a base URL override, and putting the Agent Token where the SDK expects its API key (e.g. `OPENAI_API_KEY=<Agent Token>`, `OPENAI_BASE_URL=<route>`) makes TrustedCourier a drop-in with zero Agent code changes.

* TrustedCourier validates the Agent Token, then replaces it with the real Secret using the Secret Name's Injection Template or Preset.
* A separate header (`X-TC-Agent-Token`) is accepted as a fallback for Upstreams whose credential slot TrustedCourier cannot recognize.
* TLS interception was rejected: every Agent would have to trust a TrustedCourier CA, a large trust ask and attack surface.
* Tokens in URL paths were rejected: they leak into logs.

Rules that follow from this:

* Each Secret Name is pinned to its Upstreams; a Policy may further restrict HTTP methods and path prefixes.
* Redirects are never followed; the 3xx is returned to the Agent so the Secret is never re-sent to a new host.
* Upstream TLS is always verified, with an optional per-Upstream CA bundle; there is no skip-verify setting.
* Redaction removes exact matches of the Secret from response headers and bodies, including streamed (SSE) responses, using a sliding window across chunks.
* v1 supports HTTP/1.1 and HTTP/2 with streaming; WebSockets are out (ADR-0002).

### Consequences

* Good, because the Agent's model, logs and tools never hold the Secret, even when the Upstream echoes it back.
* Bad, because every proxied response is scanned for Redaction.
* Bad, because clients that cannot override a base URL cannot use Proxy Delivery.
