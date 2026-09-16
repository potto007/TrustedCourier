//go:build !unix

package harden

// disableCoreDumps does nothing: this platform has no core file limit to
// set, and Secrets are not held on it in production.
func disableCoreDumps() error { return nil }
