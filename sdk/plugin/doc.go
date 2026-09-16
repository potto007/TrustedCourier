// Package plugin is the SDK Plugin Authors build Backend Plugins against.
//
// It is its own Go module, versioned independently of the TrustedCourier core
// (tags sdk/plugin/vX.Y.Z), so a Backend Plugin never pulls in the core.
// Implement Backend and call Serve from main:
//
//	func main() { plugin.Serve(&myBackend{}) }
//
// TrustedCourier launches the binary out of process (ADR-0004); Serve
// handles go-plugin, gRPC, the handshake, process hardening, and the FIPS
// 140-3 report a core in FIPS mode requires (ADR-0027). Build release
// binaries with GOFIPS140=certified, as the core is. Validate a plugin
// before releasing it with the conformance package.
package plugin
