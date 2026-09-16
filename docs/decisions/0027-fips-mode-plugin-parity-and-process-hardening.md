---
status: accepted
date: 2026-09-16
decision-makers: Paul Otto
---

# FIPS mode is reported in the plugin's Capabilities response, enforced by the Plugin Host, and the binaries link the validated module

## Context and Problem Statement

ADR-0003 chose Go for its FIPS 140-3 mode as a runtime switch, and ADR-0004 requires a core in FIPS mode to refuse any Backend Plugin not in FIPS mode. Building that (#17) raised three questions: how a plugin reports its mode when go-plugin's handshake line cannot carry it, which module the standard binary links, and how the core and plugin processes keep Secrets out of core dumps.

## Considered Options

* Report FIPS mode in the go-plugin handshake line, by forking or extending go-plugin
* Report it in the plugin's `Capabilities` response, the first RPC after the handshake
* Pass the mode only by environment (`GODEBUG`) and trust that the plugin honors it
* Build against the in-tree FIPS module (`GOFIPS140=off`, the Go default)
* Build against the certified snapshot (`GOFIPS140=certified`)
* Disable core dumps in the core only; in the core and the plugin SDK; leave it to the Operator's `ulimit`

## Decision Outcome

Chosen options: "Capabilities response", "certified snapshot", and "core and plugin SDK".

* The `CapabilitiesResponse` carries `fips140_enabled` and `fips140_version`, filled by the SDK's `Serve` from `crypto/fips140`, so a Plugin Author does nothing. The core reads it right after the handshake, before any Secret call. Extending the go-plugin handshake would mean maintaining a fork of the library that puts the process boundary around plugins (ADR-0004). Trusting the environment alone was rejected: a plugin not built on the SDK, or on an older SDK, would silently run outside the boundary.
* When `crypto/fips140.Enabled()` is true in the core, the Plugin Host kills a plugin that does not report FIPS mode and leaves it down, restarting with the usual backoff as it does after a hash mismatch (ADR-0011); the server keeps serving the plugins that comply. The plugin inherits the core's `GODEBUG`, so a plugin built on the SDK follows the core's mode without configuration. A plugin reporting FIPS mode to a core outside it is accepted.
* CI and release builds set `GOFIPS140=certified`, which links the validated snapshot shipped with the Go toolchain and defaults `fips140` to on. The Operator still chooses the mode at runtime with `GODEBUG=fips140=on`, `only`, or `off`. A plain `go build` links the in-tree copy, whose version reports as `latest`; `tc status` shows the module version so an Operator can tell the two apart. The conformance kit checks the plugin follows the kit's mode; a suite run with `GODEBUG=fips140=only` passes, where a non-approved algorithm would panic.
* Every `tc` process and every plugin built on the SDK sets the core file size limit to zero, hard and soft, and on Linux marks itself not dumpable, before it handles anything. The SDK and the core each hold a copy of this small package: the two modules release independently and the SDK's public surface stays the Backend interface. Leaving it to `ulimit` was rejected because a process that holds plaintext Secrets should not depend on the unit file being right.

### Consequences

* Good, because FIPS parity needs no configuration: the plugin follows the core, and a plugin outside the boundary is refused before it serves a Secret.
* Good, because the module version is visible, so "in FIPS mode on an unvalidated module" is a state an Operator can see.
* Bad, because a plugin built on an SDK from before this field is refused by a core in FIPS mode until rebuilt.
* Bad, because a not-dumpable process cannot be attached with a debugger by its own user; debugging a production core means reproducing elsewhere.
