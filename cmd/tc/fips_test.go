package main

import (
	"crypto/fips140"
	"os"
	"testing"
)

// TestBuiltAgainstValidatedModule checks that a build with GOFIPS140 set,
// as CI and release builds are, links Go's validated FIPS 140-3 module
// rather than the unvalidated in-tree copy, whose version is "latest".
func TestBuiltAgainstValidatedModule(t *testing.T) {
	setting := os.Getenv("GOFIPS140")
	if setting == "" || setting == "off" {
		t.Skip("GOFIPS140 is not set; the in-tree module is expected")
	}
	if v := fips140.Version(); v == "latest" || v == "" {
		t.Fatalf("fips140.Version() = %q with GOFIPS140=%s, want a validated module version", v, setting)
	}
}
