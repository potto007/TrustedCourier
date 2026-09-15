//go:build unix && !linux

package secret

// excludeFromCoreDumps does nothing: only Linux can exclude a mapping from
// core dumps, so elsewhere process hardening must disable core dumps.
func excludeFromCoreDumps([]byte) error { return nil }
