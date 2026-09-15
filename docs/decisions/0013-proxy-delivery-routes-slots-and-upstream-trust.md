---
status: accepted
date: 2026-09-14
decision-makers: Paul Otto
---

# Proxy Delivery's routes, credential slots, and Upstream trust

## Context and Problem Statement

ADR-0005 settled that an Agent reaches Proxy Delivery through a base URL route with its Agent Token in the SDK's credential slot, that redirects are never followed, and that Upstream TLS is always verified. It left open the exact route, how a Secret Name's Upstreams and Injection Template look in the config, how TrustedCourier finds the Agent Token when the slot depends on the Secret Name, and what the proxy does with the paths, headers, and protocols an Agent sends.

## Considered Options

* Read the Agent Token only from the requested Secret Name's credential slot, or from every slot any Injection Template defines
* Mark the Secret in a header template as `{{secret}}`, or as `{secret}`
* A per-Upstream CA bundle that adds to the system roots, or replaces them
* Refuse a Policy that allows Proxy Delivery of a Secret Name with no Upstreams, or deny it at runtime

## Decision Outcome

Chosen options: "every slot", "`{secret}`", "replaces them", and "refuse the Policy".

* The route is `/proxy/{secret_name}/{upstream}/{path}`, where `upstream` names one of the Secret Name's Upstreams. `/proxy/{secret_name}/{upstream}` reaches the Upstream's base URL. The escaped path after the Upstream name is appended to the Upstream URL's path, and the query goes along unchanged. A path with a dot segment, including a percent-encoded one, one behind an encoded slash, or one with `;` parameters such as `..;` (which servlet containers read as `..`), gets 400, so it cannot climb out of a base path.
* A Secret Name declares `upstreams`, a map of name to `url` and optional `ca_bundle`, and `injection_template`, which for now is `header: {name, value}` with `{secret}` exactly once in `value`. The two come together or not at all. `{{secret}}` was rejected because Operators generate configs with Go templates, Helm, and Jinja, which would all try to expand it. Hop-by-hop headers, `Host`, `Content-Length`, and `X-TC-Agent-Token` cannot carry a Secret.
* Upstream URLs must be `https`, with a host and no user information, query, or fragment. A `ca_bundle` replaces the system roots for that Upstream alone, so an internal CA vouches only for the Upstreams it is configured on. Each Upstream gets its own transport. `HTTPS_PROXY` in the server's environment is honored; TLS to the Upstream is still verified end to end through the tunnel.
* The Agent Token is looked for in every credential slot of every header Injection Template, on every route, plus `X-TC-Agent-Token`. A slot counts only when the text where the Secret would go starts with `tcat_`, so an SDK that insists on a placeholder API key still works with the fallback header. The template's literal text matches case-insensitively, like auth schemes. Exactly one Agent Token must be found. Reading only the requested Secret Name's slot was rejected: a guesser without an Agent Token could send a fake token in one header and tell from "required" versus "invalid" which Secret Names read that slot.
* After authentication, an unknown Upstream gets the same 403 as every other denial. The Agent Token's header and `X-TC-Agent-Token` are removed, and the template's header is set to the Secret, replacing any value the Agent sent.
* As with Reveal (ADR-0012), a Policy may not allow `proxy` for a Secret Name with no Upstreams; the config is refused.
* The response reaches the Agent as the Upstream sent it, with `Cache-Control: no-store` in place of the Upstream's own caching headers. 3xx responses and their `Location` are returned unchanged, because the transport never follows redirects. Responses without a length and server-sent event streams are flushed as they arrive.
* A proxied response has no overall time limit, but it may not stall. An Upstream that sends nothing for 5 minutes, before or during its response, ends the Delivery (504 if no response has started), and an Agent that stops reading for 30 seconds fails its writes. The Agent API's fixed write timeout was rejected for proxied responses because it would cut off LLM streams and slow completions. No limit at all was rejected because the request holds the Secret's header copy for as long as it runs.
* Requests asking for a protocol upgrade get 400. WebSockets are out of v1 (ADR-0002), and an upgraded connection would carry bytes Redaction (#6) never sees. An `h2c` offer, as `curl --http2` sends on plain HTTP, is the exception: the server answers in HTTP/1.1, and the offer is not forwarded.
* The Agent listener speaks HTTP/1.1 and HTTP/2 with prior knowledge, since it is plain HTTP on loopback until #13. Upstreams get HTTP/2 when they offer it through ALPN.

### Consequences

* Good, because SDKs work unchanged: the Agent Token goes wherever the Secret would.
* Good, because 401 and 403 responses are the same for every Secret Name and Upstream, so neither can be enumerated from the Agent API.
* Bad, because this narrows ADR-0012's "a Secret never becomes a Go string in the core". `net/http` takes header values only as strings, so Proxy Delivery copies the Secret into a Go string on the heap (and HTTP/2 copies it again into its header encoder). The locked copy is released as soon as the header is built. The request holds the string until the Delivery ends, and after that it stays until the garbage collector reclaims its memory, which it does not wipe.
* Bad, because an Agent whose real API key starts with `tcat_` would be read as presenting an Agent Token.
* Bad, because until Redaction (#6) lands, an Upstream that echoes its credential sends the Secret to the Agent.
