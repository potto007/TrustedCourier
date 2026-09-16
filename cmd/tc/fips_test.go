package main

import (
	"crypto/fips140"
	"runtime/debug"
	"testing"
)

// TestBuiltAgainstValidatedModule checks that a build with GOFIPS140 set,
// as CI and release builds are, links Go's validated FIPS 140-3 module
// rather than the unvalidated in-tree copy, whose version is "latest".
// The setting is read from the binary's build info, not the environment,
// which need not match at test time.
func TestBuiltAgainstValidatedModule(t *testing.T) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		t.Fatal("no build info")
	}
	setting := "off"
	for _, s := range info.Settings {
		if s.Key == "GOFIPS140" {
			setting = s.Value
		}
	}
	if setting == "off" {
		t.Skip("built without GOFIPS140; the in-tree module is expected")
	}
	if v := fips140.Version(); v == "latest" || v == "" {
		t.Fatalf("fips140.Version() = %q for a build with GOFIPS140=%s, want a validated module version", v, setting)
	}
}
