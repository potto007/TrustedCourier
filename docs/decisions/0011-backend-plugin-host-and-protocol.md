---
status: accepted
date: 2026-09-14
decision-makers: Paul Otto
---

# How the core launches and trusts Backend Plugins

## Context and Problem Statement

ADR-0004 settles that Backend Plugins run out of process through go-plugin, pinned by SHA-256, as a separate OS user, with every response treated as untrusted input. Building the seam raised questions ADR-0004 does not answer: where the response validation lives, how the pinned hash is enforced against a binary swapped after the check, what happens when TrustedCourier cannot switch users, and how a plugin failure affects the running server.

## Considered Options

* Validation in the core only, with the conformance kit re-implementing the rules
* Validation in the plugin SDK module, shared by the core and the conformance kit
* Hash the binary by path, then exec the path
* Hash an open file descriptor, then exec that descriptor
* Run plugins as the server's user when it cannot switch users
* Refuse to start unless the plugin runs as a separate user, with an explicit development opt-out

## Decision Outcome

Chosen options: "validation in the SDK module", "exec the verified descriptor", and "refuse without a separate user, with an explicit opt-out".

* The wire protocol is a gRPC service in `sdk/plugin/protocol`. The `sdk/plugin/client` package launches a plugin and applies the protocol contract (location, value, list, and health detail limits; no control characters; valid UTF-8) to every response. The core's Plugin Host and the conformance kit both use it, so a plugin that passes the kit is held to exactly the rules the core enforces. The SDK's `Serve` applies the same rules before a response leaves the plugin, so Plugin Authors see violations as errors in their own tests. The core depends on the SDK module through a `replace` directive; the SDK never depends on the core.
* On Linux the Plugin Host opens the binary, hashes that open file, and executes it as `/proc/self/fd/3`, so replacing the file at the configured path after the check has no effect. The hash is checked at boot, where a mismatch stops the server, and again before every relaunch, where a mismatch leaves the plugin down. Other platforms exec the path after the check.
* Each Backend Plugin names a `user`. The server refuses to start if that user is its own, can read the config file, owns the data directory, or if the server is not root and so cannot switch to it. `insecure_share_core_user: true` runs the plugin as the server's user, logs a warning, and exists for development and tests.
* A plugin launch failure after boot never stops the server. The Plugin Host restarts an exited plugin with exponential backoff (250 ms doubling to 30 s) and reports state, restarts, health, and capabilities through `tc status`.
* Error text and log output from a plugin are sanitized before the core logs or displays them.

Validation in the core only was rejected because two copies of the contract drift. Falling back to the server's user was rejected because a silent fallback gives a compromised plugin the config and the Agent Token hashes.

### Consequences

* Good, because a replaced plugin binary is never run, even when swapped between the hash check and exec.
* Good, because the conformance kit and the core cannot disagree about what a well-formed response is.
* Bad, because a production server that runs plugins must start as root, and the root-only tests need `sudo` in CI.
* Bad, because a change to the contract rules is an SDK release that the core picks up, not a core-only change.
