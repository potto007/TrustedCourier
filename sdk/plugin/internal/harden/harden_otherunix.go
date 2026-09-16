//go:build unix && !linux

package harden

func disableCoreDumps() error { return zeroCoreLimit() }
