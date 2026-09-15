---
status: accepted
date: 2026-09-14
decision-makers: Paul Otto
---

# Redaction masks the Secret in place and reads responses as plain bytes

## Context and Problem Statement

ADR-0005 settled that Redaction removes exact matches of the Secret from Upstream response headers and bodies, streamed ones included, with a sliding window across chunks. It left open what takes the Secret's place, what happens to responses Redaction cannot read as plain bytes (compressed bodies, and ranges that carry the Secret in pieces), which parts of a response are covered, and how long a stream may be held back.

## Considered Options

* Mask a match with the same number of bytes, or replace it with a fixed marker such as `[redacted]`
* Ask for gzip and decode it, or ask Upstreams for `identity` only
* Remove `Range` from proxied requests, or forward it and document the gap

## Decision Outcome

Chosen options: "same number of bytes", "decode gzip", and "remove `Range`".

* Every exact match of the Secret's bytes, leftmost first, becomes a run of `*` of the same length. If the Secret contains `*`, the mask is the first of `x-_.~`, digits, and letters it does not contain, so a mask cannot join the bytes around it into a new match, and a masked JSON or HTML document still parses. `Content-Length` stays true, and a response without the Secret reaches the Agent byte for byte with every header. A fixed marker was rejected because it changes the body's length, which cannot be known before the headers go out, so every proxied response would have to drop `Content-Length`, including responses without the Secret.
* Redaction covers the headers of every response the Agent receives (1xx responses such as 103 Early Hints included), the body, and the trailers. A header whose name contains the Secret is dropped, since a masked name is not a valid one.
* A streamed body is held back by no more than the longest trailing run of bytes that could begin the Secret, which is always shorter than the Secret. Everything else is written and flushed as it arrives. Bytes still held when the response ends were never the Secret and are sent then; a response aborted mid-body drops them.
* The Agent's `Accept-Encoding` is replaced with `gzip`, and TrustedCourier decodes a body encoded once with gzip before Redaction. A response that could have a body and names any other `Content-Encoding` than `identity`, or more than one, gets 502, with the encodings in the server log. The transport's own gzip handling was rejected because it decodes one layer and then drops every `Content-Encoding` line, so a body gzipped twice would reach Redaction still compressed. Asking for `identity` only was rejected because gzip costs nothing to decode here and saves the Upstream link on large LLM responses.
* `Range` and `If-Range` are removed from proxied requests. A range lets an Agent fetch a response that echoes the Secret a few bytes at a time, and no single response would hold a match.
* Redaction matches against the part of the Injection Template's header string that holds the Secret, reading it in place, so it adds no heap copy of the Secret beyond the one ADR-0013 accepts.

This closes the gap ADR-0013 records, where an Upstream that echoed its credential sent the Secret to the Agent.

### Consequences

* Good, because response framing is untouched: `Content-Length` stays true, and a Secret inside a JSON string is masked with bytes that keep the JSON valid.
* Good, because streaming latency is bounded by the Secret's length, not by a buffer or a timer.
* Bad, because only exact matches are masked. An Upstream that sends the Secret transformed (base64, JSON or URL escaping, changed case) or split across several responses still leaks it.
* Bad, because the mask shows the Secret's length, and a short Secret masks unrelated text that happens to match it.
* Bad, because every byte of every proxied response is scanned, and a body's `ETag` or digest headers no longer match a masked body.
* Bad, because an Upstream that sends Brotli, zstd, or another encoding it was not asked for cannot be used through Proxy Delivery, and resumable downloads through Proxy Delivery start over.
* Bad, because a Secret that contains every mask candidate (`*x-_.~`, every digit, and every letter) is masked with `*`, which it contains, so a mask and the bytes around it could form a new match.
