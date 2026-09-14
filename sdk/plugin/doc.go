// Package plugin is the SDK Plugin Authors build Backend Plugins against.
//
// It is its own Go module, versioned independently of the TrustedCourier core
// (tags sdk/plugin/vX.Y.Z), so a Backend Plugin never pulls in the core. The
// Backend interface and serve entry point arrive with the Backend Plugin seam
// (ADR-0004).
package plugin
