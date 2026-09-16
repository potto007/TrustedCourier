# Writing a Backend Plugin

A Backend Plugin connects TrustedCourier to one kind of Backend: a secret store that is the source of truth for Secrets. TrustedCourier runs it as a separate binary, out of process, as a separate OS user, and treats every response as untrusted input ([ADR-0004](decisions/0004-out-of-process-backend-plugins.md), [ADR-0011](decisions/0011-backend-plugin-host-and-protocol.md)). This guide is for Plugin Authors: how to build one on the plugin SDK, how to run the conformance kit against it, and what the kit demands.

The bundled OpenBao plugin in [`plugins/openbao`](../plugins/openbao) is the reference: a complete plugin, with its conformance test, in a few hundred lines.

## The SDK

The SDK is the Go module `github.com/potto007/TrustedCourier/sdk/plugin`, versioned on its own (`sdk/plugin/vX.Y.Z` tags). It is the plugin's only dependency on TrustedCourier; nothing in the core is imported, and the kit checks that.

Implement `plugin.Backend` and call `plugin.Serve` from `main`:

```go
// FIPS 140-3 mode follows the core, which sets GODEBUG; standalone, default
// it off as the core does.
//
//go:debug fips140=off
package main

import (
	"context"

	"github.com/potto007/TrustedCourier/sdk/plugin"
)

type myBackend struct{ /* a client for the store */ }

func (b *myBackend) Get(ctx context.Context, location string) ([]byte, error)  { /* ... */ }
func (b *myBackend) List(ctx context.Context, prefix string) ([]string, error) { /* ... */ }
func (b *myBackend) Health(ctx context.Context) (string, error)                { /* ... */ }
func (b *myBackend) Capabilities() plugin.Capabilities                         { return plugin.Capabilities{} }

func main() { plugin.Serve(&myBackend{}) }
```

`Serve` handles go-plugin, gRPC, the handshake, the FIPS 140-3 report, and process hardening (core dumps off, not dumpable on Linux). It does not return.

### Locations

A location is your Backend's own addressing for one Secret: a path, a path and a field, an ARN, an item id. TrustedCourier maps Secret Names to locations in its config and never shows a location to an Agent. Choose a syntax an Operator can read straight off your Backend's own tools, document it, and reject anything else from `Get` with a clear error. Locations are up to 1024 bytes of printable UTF-8; the SDK refuses the rest before your code sees it.

### The methods

- **`Get`** returns the Secret at a location as bytes, non-empty and at most 1 MiB. Return an error wrapping `plugin.ErrNotFound` when the Backend holds nothing there. When it holds something that is not a Secret (an empty value, a value of the wrong type, a record without the named field), return your own error saying so: not `ErrNotFound`, and not the value, since the SDK would refuse it and the core would log a plugin defect rather than a Backend problem the Operator can fix.
- **`List`** returns every location starting with a prefix, without duplicates. An empty prefix means everything. It is a diagnostic for Operators, not a hot path; it may be slow, but it must be complete.
- **`Health`** returns nil when the Backend is reachable and the plugin's credentials work, or an error saying what is wrong. The detail string is shown to the Operator in `tc status` either way: the Backend's version, the address, whether a credential is about to expire. Up to 1024 printable bytes.
- **`Capabilities`** reports optional features. A Backend that can store Courier Keys sets `CourierKeyWrite` and also implements `plugin.CourierKeyWriter`; `Serve` exits at start if one is set without the other. A read-only Backend is a valid plugin: TrustedCourier then needs an Operator-supplied TLS certificate and audit signing key placed in the Backend by other means.
- **`WriteCourierKey`** stores a Courier Key (a TLS certificate and key, the ACME account key, the audit signing key) at a location, so that a later `Get` at that location returns it. Keep whatever else the Backend holds beside it.

Methods are called concurrently, from every Delivery at once. Honor the context: the core gives each call a deadline.

### Errors

Error text reaches the Operator through the server log and `tc status`, sanitized (control characters removed, truncated). Say what is wrong and where, and never include a Secret value. Wrap `plugin.ErrNotFound` and `plugin.ErrUnsupported` where they apply; any other error is reported as the Backend being unavailable for that call.

### Configuration

The plugin runs as a separate OS user with no access to TrustedCourier's config or database, in an empty environment plus what the Operator sets in `backend_plugins.<name>.env`, and `GODEBUG`, which the core sets to carry its FIPS 140-3 mode. Read your configuration from environment variables, and read credentials from a file named by one (`MY_TOKEN_FILE`), so the token is not in the config the Operator keeps in Git. When the configuration is missing or wrong, print why to stderr and exit non-zero; the server reports the launch failure with your message.

### FIPS 140-3 mode

A core in FIPS mode refuses a plugin that is not in at least its mode ([ADR-0027](decisions/0027-fips-mode-plugin-parity-and-process-hardening.md)). A plugin built on the SDK follows the core's `GODEBUG` without any code, and reports its mode in the handshake. Two things are yours: build release binaries with `GOFIPS140=certified`, as the core is built, so the mode runs on the validated module; and use only Go's standard-library cryptography and TLS to reach your Backend, since a third-party crypto library is outside the module. Pin `//go:debug fips140=off` in `main` so a standalone run defaults off as the core does.

## The conformance kit

The kit is the `conformance` package of the SDK module: a Go test that launches your plugin binary the way the core does and checks it against the contract, through the same validating client the core uses. A plugin that passes the kit is held to exactly the rules the core enforces.

Write a test in your plugin's repository that builds the binary, makes the Backend hold a known set of records, and runs the kit:

```go
func TestConformance(t *testing.T) {
	// Build the binary, start or reach the Backend, seed it.
	conformance.Run(t, binary, conformance.Fixture{
		Secrets: map[string][]byte{
			"secret/data/openai#key":   []byte("sk-test"),
			"secret/data/github#token": []byte("ghp-test"),
		},
		Missing:            "secret/data/nothing#key",
		Malformed:          []string{"secret/data/github#empty", "secret/data/github#number"},
		CourierKeyLocation: "secret/data/trustedcourier#tls-key",
		Env:                []string{"MY_ADDR=" + addr, "MY_TOKEN_FILE=" + tokenFile},
	})
}
```

The Fixture describes what the Backend holds while the kit runs:

| Field | What it is |
| --- | --- |
| `Secrets` | Locations and the values the Backend holds there. At least one; include a non-ASCII location if your syntax allows one. |
| `Missing` | A location where the Backend holds nothing. |
| `Malformed` | Locations where the Backend holds something that is not a Secret. Name at least one of each kind your Backend can produce. |
| `CourierKeyLocation` | Where the kit may write Courier Keys. Required when the plugin reports `CourierKeyWrite`; the kit writes there twice and reads back. |
| `Env` | The plugin's environment: how it reaches the Backend. The kit sets `GODEBUG` itself. |

The checks, each a subtest:

| Check | Passes when |
| --- | --- |
| `FIPS140` | The plugin reports a FIPS 140-3 module version and a mode at least the kit's own. |
| `FIPS140Follows` | Launched with `GODEBUG=fips140=on` and then `only`, the plugin reports that mode. |
| `Capabilities` | The reported capabilities are consistent with the Fixture. |
| `Health` | `Health` reports healthy. |
| `Get` | Every Secret in the Fixture is returned byte for byte. |
| `GetMissing` | `Get` at `Missing` fails with `plugin.ErrNotFound`. |
| `GetMalformed` | `Get` at each `Malformed` location fails with the plugin's own error: not `ErrNotFound`, not a value the SDK refused. |
| `List` | `List("")` includes every Secret, as does `List` with the first half of each location. |
| `ListNoMatch` | `List` under `Missing` returns no locations and no error. |
| `Concurrent` | Eight callers getting every Secret and checking health at once all succeed. |
| `CourierKeyWrite` | With the capability, two writes to `CourierKeyLocation` each read back and leave the Secrets untouched. Without it, `WriteCourierKey` fails with `plugin.ErrUnsupported`. |

Run the kit with the race detector, and run it twice as the core's CI does: once as is, and once with `GODEBUG=fips140=on`, which puts the kit and the plugin in FIPS mode for every call, so any use of a non-approved algorithm on the path to your Backend shows up. `GODEBUG=fips140=only` turns such a use into a panic.

### Running against a real Backend

The kit needs a Backend that holds the Fixture. For a Backend with a container image, start one from the test and seed it over its API, as the OpenBao plugin's test does with a dev-mode OpenBao under docker; skip when docker is absent, and fail instead when an environment variable says the test must run, so CI never passes on a skip. For a hosted Backend, read the address and credentials from the environment and skip when unset.

## Releasing

- Build with `CGO_ENABLED=0` and `GOFIPS140=certified`. The core verifies the binary's SHA-256 before every launch, so publish the hash with each release; Operators pin it with `tc plugin sha256`.
- Document the location syntax, the environment variables, and the least privilege the plugin's credential needs (which paths, which operations), so an Operator can issue it.
- Depend on a tagged SDK version. The wire protocol changes only with an incompatible change, and the core's Plugin Host refuses a plugin on a different protocol version at the handshake.
