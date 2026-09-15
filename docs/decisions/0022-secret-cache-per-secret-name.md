---
status: accepted
date: 2026-09-15
decision-makers: Paul Otto
---

# The Secret cache is keyed by Secret Name, bounded to an hour, and hands out copies

## Context and Problem Statement

ADR-0001 allows an optional per-Secret-Name in-memory cache with an Operator-set TTL, off by default and wiped on expiry and shutdown. Building it raised questions ADR-0001 does not answer: how the Operator sets the TTL and how long it may be, what a reload (ADR-0021) does to a Secret cached under the old config, how a cached Secret survives the Delivery that releases it (copies of a Secret share one buffer, ADR-0012), and how the wiping is tested when it cannot be seen from outside the process.

## Considered Options

* TTL unbounded, or bounded to one hour
* Cache keyed by Secret Name, or by Backend location
* Flush the whole cache on every reload, or check each entry against the snapshot a request uses
* Cache the fetched Secret and hand it out, or hand every Delivery its own locked copy

## Decision Outcome

Chosen options: "bounded to one hour", "keyed by Secret Name", "check each entry against the request's snapshot", and "hand every Delivery its own locked copy".

* `secrets.<name>.cache_ttl` takes a Go duration from `1s` to `1h`. Omitted, the Secret Name fetches on every Delivery. A zero, negative, or longer TTL is refused rather than read as off or clamped, as strict decoding (ADR-0010) refuses other typos.
* The Secret Resolver keeps one entry per Secret Name, recording the Backend and location it was fetched from and when. A request uses the entry only if its own config snapshot still maps the Secret Name to that Backend and location and that snapshot's TTL has not run out since the fetch.
* Once a reload is in effect, the Secret Resolver wipes at once every entry whose Secret Name the new config deletes, moves, or no longer caches, or whose age already exceeds the new TTL, and ends the rest at the new TTL where it is shorter. A request still running on the old snapshot may finish its fetch after the reload; its Secret is cached only if the config in effect maps the Secret Name the same way and caches it, and never for longer than that config's TTL.
* Each entry holds the fetched Secret in locked memory and wipes it with a timer when the TTL ends. Every Delivery gets its own copy in new locked memory (`Secret.Clone`), which it releases as before. When no locked memory is left for that copy, the Delivery gets the fetched Secret and nothing is cached.
* Concurrent requests that miss the cache each fetch; the last one's Secret is cached and the one it replaces is wiped.
* Courier Keys are never cached.
* Once both APIs have drained at shutdown, every cached Secret is wiped; a fetch after that is not cached.
* Audit Records are the same for a Delivery served from the cache as for one fetched from the Backend.
* Wiping cannot be observed through the process, so the cache has a module-level test seam, as the v1 spec allows when a behavior is impractical to reach through Seam 1. Everything an Operator or Agent can see (no Backend call within the TTL, a fresh fetch after it, reloads, validation) is tested end to end.

An unbounded TTL was rejected because the cache trades plaintext lifetime for fewer Backend calls, and a Secret revoked in its Backend keeps being delivered until the TTL ends; an hour caps that. Keying by Backend location was rejected because two Secret Names at one location may set different TTLs. Flushing the whole cache on every reload was rejected because it would also wipe the Secret Names the reload left alone, sending every one of them back to its Backend. Handing out the cached Secret itself was rejected because the first Delivery to release it would wipe it for everyone.

### Consequences

* Good, because caching stays an explicit, per-Secret-Name choice that no reload can silently extend.
* Good, because a cached Secret lives only in locked memory kept out of core dumps, never on disk.
* Bad, because a cached Delivery locks two buffers instead of one, so a low `RLIMIT_MEMLOCK` is reached sooner.
* Bad, because a Secret rotated or revoked in its Backend is still delivered for up to its TTL.
* Bad, because a burst of requests that miss the cache together still reaches the Backend once each.
