---
status: accepted
date: 2026-09-14
decision-makers: Paul Otto
---

# Reveal Delivery's Agent API and how the core holds a Secret

## Context and Problem Statement

Reveal Delivery is the first path that puts a Secret in the core's memory and hands it to an Agent. The spec fixes the outline (401 for a refused Agent Token, one 403 body for every denial, no-store responses, a Secret type backed by locked memory) but not the endpoint, the body format, how Secret Names reach a Backend in the config, where the Agent API may listen before TLS exists, or how the Secret type gets memory Go's garbage collector will not copy.

## Considered Options

* Reveal response as a JSON object with the value, or as the raw value
* Secret buffers on the Go heap with `mlock`, or in an anonymous `mmap` outside the heap
* On a failed `mlock`, fall back to unlocked memory, or refuse the Delivery
* Agent API listener as any address, a loopback host name, or a loopback IP literal only

## Decision Outcome

Chosen options: "raw value", "`mmap` outside the heap", "refuse the Delivery", and "loopback IP literal only".

* `GET /v1/reveal/{secret_name}` returns the Secret as `application/octet-stream`, byte for byte. A JSON body would need the value as a Go string or base64 copy on the heap, and binary values would not survive it. Every Agent API response carries `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`.
* The Agent Token goes in `Authorization: Bearer` or `X-TC-Agent-Token`, exactly once. A missing, unknown, expired, or revoked Agent Token gets 401 with a message saying which. Only someone holding a real Agent Token can see "expired" or "revoked", so the distinction leaks nothing to a guesser.
* After authentication, an unknown Secret Name, a Secret Name no attached Policy lists, and a Policy that lists it without `reveal` all get the same 403 body. The reason goes to the server log, and later to the Audit Record.
* A Backend failure gets 502 with a generic body. Backend Plugin names, locations, and plugin errors stay in the server log.
* Config maps Secret Names under a top-level `secrets` key: `backend` names an entry in `backend_plugins`, and `location` is the location in that Backend.
* `agent_api.listen` must be a loopback IP address and port until the Agent listener has TLS (#13). Host names are rejected because resolving `localhost` is not guaranteed to stay on loopback. The server checks the bound address again after listening.
* `internal/secret.Secret` copies a value into a private anonymous `mmap`, locks it with `mlock`, and wipes the source slice. The only way out is `WriteTo`. `String`, `Format`, and `LogValue` return a placeholder, and `MarshalJSON` and `MarshalText` fail. `Release` wipes, unlocks, and unmaps; copies of a Secret share one buffer, so releasing any copy releases all. A cleanup wipes a Secret dropped without `Release`. When memory cannot be locked, including on platforms without `mlock`, the Delivery fails.
* Every authenticated Agent API request records the Agent Token's last use.

A heap buffer with `mlock` was rejected because the garbage collector may move or copy heap objects, leaving unlocked copies. Falling back to unlocked memory was rejected because it would silently drop the protection ADR-0001 promises.

### Consequences

* Good, because a Secret never becomes a Go string in the core, and a stray `%v` or log attribute prints a placeholder.
* Good, because Agents learn nothing about Secret Names they may not use, or about Backends.
* Bad, because copies outside the Secret type remain: the gRPC buffer the value arrives in and the `net/http` buffer it leaves through. Adopt Go `runtime/secret` once it leaves experiment.
* Bad, because a low `RLIMIT_MEMLOCK` makes concurrent large Reveals fail rather than degrade.
