---
status: accepted
date: 2026-09-15
decision-makers: Paul Otto
---

# Policies limit Proxy Delivery by method and by path prefix on whole decoded segments

## Context and Problem Statement

A Policy that allows Proxy Delivery of a Secret Name lets the Agent send any request to the pinned Upstream. An Operator who gives an Agent a GitHub Secret to read issues also lets it delete repositories. Policies need to narrow Proxy Delivery to some methods and paths, without a path trick that reaches something the prefix seems to exclude. What does a path prefix match, how is it compared, and how do limits combine across an Agent Token's Policies?

## Considered Options

* Match path prefixes against the path after the route's Upstream name, or against the Upstream URL's full path
* Compare whole percent-decoded segments, or plain string prefixes
* Accept any HTTP method token in `methods`, or a fixed list
* Combine limits per Policy entry, or pool every entry's methods and paths

## Decision Outcome

Chosen options: "after the Upstream name", "whole decoded segments", "a fixed list", and "per entry".

* A Policy entry takes optional `methods` and `paths`. Omitting either allows any method or path, so existing Policies behave as before. An empty list, or a key left without a value (YAML null, as after commenting out every item), is refused rather than read as allowing nothing or everything, and so is either key on an entry without `proxy`.
* `methods` holds any of `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS`, in any case, stored uppercase. Requests match exactly, so a lowercase method is denied. `GET` does not imply `HEAD`. A fixed list turns a typo into a startup error instead of a silent denial; `CONNECT` cannot be proxied and `TRACE` echoes the request, so neither is on it.
* A path prefix matches the escaped path after `/proxy/{secret_name}/{upstream}`. The Upstream URL's base path was rejected because the same Policy then breaks when a Secret Name's Upstreams move, as GitHub Enterprise Server sits under `/api/v3`, and a Policy names a Secret Name, not an Upstream.
* Both prefix and path are split on `/` and each segment is percent-decoded; the prefix must equal the path's first segments. `/repos/o/r` allows `/repos/o/r/issues`, not `/repos/o/rx`, which a string prefix would allow. `/%72epos` counts as `/repos`, since that is what the Upstream reads. A segment with an encoded slash or backslash, `;` parameters, or a different case does not equal a prefix segment, so the request is denied rather than guessed at. A path with a dot segment (in any of ADR-0013's spellings), invalid percent-encoding, or invalid UTF-8, which covers overlong encodings of `.`, matches no prefix, though dot segments are refused with 400 first. The forwarded path is unchanged.
* A prefix must start with `/`, is made of RFC 3986 path characters without `;`, has no empty or dot segments, and decodes to UTF-8 without a slash, backslash, `;`, or control character, so `%3B` cannot put parameters in a prefix. A trailing slash is ignored. `/` allows every path.
* One Policy entry must allow both the method and the path. Pooling every entry's methods and paths was rejected because an Agent Token with a GET-anywhere Policy and a DELETE-on-one-path Policy would get DELETE anywhere. Any allowing entry among the Agent Token's Policies is enough, so an unlimited entry for the same Secret Name wins.
* Denials get the identical 403 and never reach the Upstream. The Audit Record's reason is `no Policy allows the method` when no proxy entry allows the method, otherwise `no Policy allows the path`.

### Consequences

* Good, because the common escapes (encoded characters, encoded slashes, dot segments, servlet parameters, overlong UTF-8) are denied or refused without per-Upstream knowledge.
* Good, because a Policy written for a Preset keeps working when Upstreams are replaced.
* Bad, because an Upstream that treats paths case-insensitively, merges `;` parameters, or folds Unicode (such as fullwidth dots) may read a path differently than the comparison. The comparison only ever denies such paths or matches them byte for byte, but a prefix-allowed path whose tail uses Unicode dot look-alikes is forwarded.
* Bad, because the Operator must list `HEAD` and `OPTIONS` explicitly, which CORS preflights and some SDKs send.
