---
status: accepted
date: 2026-09-15
decision-makers: Paul Otto
---

# Query and basic auth Injection Templates, Presets as data, and `tc env`

## Context and Problem Statement

ADR-0013 gave Proxy Delivery one kind of Injection Template, a header, and ruled that the Agent Token is never read from the URL. ADR-0014 made Redaction mask exact matches of the Secret itself. Many APIs take their key as a query parameter or in HTTP basic auth, where the request carries the Secret escaped or base64-encoded, and Operators should not hand-write templates for common services or work out an Agent's environment by hand. How do the new template kinds find the Agent Token, what does Redaction mask, what is a Preset, and what does `tc env` print?

## Considered Options

* For a query template, read the Agent Token from its query parameter, or only from headers
* Allow text around `{secret}` in a basic auth field, or only `{secret}` as the whole username or password
* Keep Redaction's leftmost-first matching per needle, or mask every byte of every match of every needle
* Presets as Go code, or as embedded data in the Secret Name's own format
* Let Upstreams set beside a Preset replace its own, or forbid them
* Have `tc env` print the Agent Token, or a placeholder

## Decision Outcome

Chosen options: "read from the query parameter", "whole field", "mask every byte", "embedded data", "replace", and "a placeholder".

* `injection_template` takes exactly one of `header`, `query: {name}`, or `basic_auth: {username, password}`. A query parameter name is up to 64 bytes a query never escapes. In basic auth, `{secret}` is the whole username or the whole password, never both; the other field is literal, and a literal username cannot contain `:`. A Secret that contains `:` cannot be a basic auth username and fails the Delivery with 502.
* A query template's parameter is a credential slot, read on every route like header slots (ADR-0013), so SDKs that send `?key=` work unchanged. This narrows ADR-0013's "never in the URL" to query parameters an Operator's Injection Template names; a token in any other parameter is not read. The parameter holding the Agent Token is removed before forwarding, and the Secret, query-escaped, replaces any value the Agent sent under the template's name, as the last parameter. The other parameters keep their bytes and order.
* A basic auth slot is `Authorization: Basic` (scheme in any case) whose decoded literal field matches the template exactly. The Upstream gets `Authorization: Basic` with the Secret in place of the Agent Token.
* Redaction masks every form of the Secret the request carried: the Secret, plus the query-escaped Secret for a query template, or the base64 credential for basic auth. Every byte inside any match of any needle is masked, overlapping matches included, with one mask byte no needle contains. This replaces ADR-0014's leftmost-first matching, which could leave part of an overlapping match visible; its other decisions stand. Bytes held back at a stream's edge keep their raw value, so a match they begin is still found.
* A Preset is an entry in `internal/config/presets.yaml`, embedded in the binary: an `injection_template` and `upstreams` in exactly the Secret Name's format, plus `env`, mapping variable names to `base_url`, `agent_token`, or a basic auth template's literal `username` or `password`. The file is decoded strictly and every Preset validated like a Secret Name, without `ca_bundle`. Adding a Preset of any template kind is adding an entry. The first are `openai` (`Authorization: Bearer`, `https://api.openai.com/v1`), `anthropic` (`X-Api-Key`, `https://api.anthropic.com`), and `github` (`Authorization: token`, `https://api.github.com`), each with its Upstream named `api`.
* A Secret Name applies one with `preset: <name>`, which cannot sit beside `injection_template`. `upstreams` set beside a Preset replace the Preset's, for GitHub Enterprise Server or a gateway in front of a service.
* `tc env <secret-name> [--upstream <name>]` asks the admin API and prints one `NAME=value` line per variable: the Proxy Delivery route for `base_url`, `<Agent Token>` for `agent_token`, and a literal basic auth field as is. The server holds only Agent Token hashes, so it cannot print the token. Without a Preset, variables are named after the Secret Name: `<NAME>_BASE_URL` and `<NAME>_API_KEY`, or `<NAME>_USERNAME` and `<NAME>_PASSWORD` for basic auth. A Secret Name with several Upstreams needs `--upstream`.

### Consequences

* Good, because SDKs that send an API key as `?key=` or in basic auth work through Proxy Delivery unchanged, and an echoed encoded credential is masked like the plain one.
* Good, because a Preset needs no code, and `tc env` output pasted with a real Agent Token wires an Agent.
* Bad, because an Agent Token in a query parameter can land in the Agent's own HTTP logs and traces. It stays scoped, expiring, and revocable, and TrustedCourier's logs and Audit Records never contain URLs.
* Bad, because a query template copies the Secret into the request URL string, and basic auth into its plain `username:password` string as well as the header; both live on the heap until the Delivery ends and the garbage collector reclaims them, as ADR-0013 accepts for headers.
* Bad, because masking every overlapping match can mask more text than leftmost-first did when a response happens to repeat the Secret's own patterns.
* Bad, because a Preset's Upstream URL or header changing upstream needs a TrustedCourier release, or an Operator-written template in the meantime.
