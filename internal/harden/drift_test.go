package harden

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSDKCopyMatches keeps the plugin SDK's copy of this package identical
// to this one, apart from the package comment that names the other copy,
// so a hardening fix reaches both the core and every plugin (ADR-0027).
func TestSDKCopyMatches(t *testing.T) {
	sdk := filepath.Join("..", "..", "sdk", "plugin", "internal", "harden")
	names, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		if name == "drift_test.go" {
			continue
		}
		core, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		other, err := os.ReadFile(filepath.Join(sdk, name))
		if err != nil {
			t.Errorf("%s has no counterpart in the plugin SDK: %v", name, err)
			continue
		}
		if name == "harden.go" {
			core, other = body(string(core)), body(string(other))
		}
		if string(core) != string(other) {
			t.Errorf("%s differs between internal/harden and sdk/plugin/internal/harden", name)
		}
	}
	sdkNames, err := filepath.Glob(filepath.Join(sdk, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	if len(sdkNames) != len(names)-1 {
		t.Errorf("the plugin SDK copy has %d files, this package %d plus this test", len(sdkNames), len(names)-1)
	}
}

// body is a Go file from its package clause on, without the package
// comment.
func body(src string) []byte {
	_, rest, _ := strings.Cut(src, "\npackage ")
	return []byte(rest)
}
