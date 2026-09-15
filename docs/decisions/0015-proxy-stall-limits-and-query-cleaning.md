---
status: accepted
date: 2026-09-14
decision-makers: Paul Otto
---

# Proxy Delivery's stall limits guard writes, count uploads, and log cut-offs; unparsable query parameters are dropped

## Context and Problem Statement

ADR-0013 set two stall limits on a proxied Delivery: an Upstream that sends nothing for 5 minutes, before or during its response, ends it, and an Agent that stops reading for 30 seconds fails its writes. It also said the query goes to the Upstream unchanged. Review found the implementation of those limits wrong in four ways, and the query rule unsafe:

* The 30-second limit was a write deadline pushed forward on each write and left armed between writes. On HTTP/2 an armed deadline resets the stream when it passes, even with no write pending, so an Upstream pausing for more than 30 seconds cut off the Agent's stream. On HTTP/1.1, the writes after the last body chunk (trailers and the end of a chunked body) inherited a deadline that could already have passed.
* Only the response reset the 5-minute limit, so an upload taking longer than that ended in 504 while bytes flowed.
* A Delivery ended after its response had started left no failure in the log.
* Go's ReverseProxy drops query parameters it cannot parse, such as ones separated by `;`, which some servers read as a separator (CVE-2022-2880). Forwarding the query unchanged brought them back.

## Decision Outcome

This refines ADR-0013's stall limits and query rule; its other decisions stand.

* The 30-second limit bounds each write and flush to the Agent, and is cleared between them, so it measures an Agent that stops reading, never an Upstream that pauses. The writes that end a response (held-back Redaction bytes, trailers, the end of the body) get one more 30-second deadline.
* The 5-minute limit restarts whenever the Upstream's response or the Agent's request body makes progress. A Delivery ends only when neither has moved for 5 minutes.
* A Delivery that ends after its response started is logged as cut off, with the reason: the Upstream went silent, the Agent's connection could not be written to, or the Upstream's response broke off. An Agent that disconnects is logged as abandoning the Delivery.
* The query goes to the Upstream as ReverseProxy cleans it: when it contains a parameter Go cannot parse, those parameters are dropped and the rest are re-encoded. A query without one goes unchanged.

### Consequences

* Good, because LLM streams that pause for long stretches, and slow uploads, complete on either protocol.
* Good, because an Operator can tell a cut-off Delivery from a completed one in the log.
* Bad, because an Agent that trickles a request body keeps a Delivery, and the Secret's header copy, alive with a byte every 5 minutes, as a trickling Upstream already could.
* Bad, because an Agent that relies on `;` as a query separator loses those parameters without an error.
