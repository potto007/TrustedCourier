// Package conformance is the Backend Plugin conformance kit: a Go test suite
// that launches a plugin binary the way TrustedCourier does and checks it
// meets the plugin contract. Run it from a test in the plugin's repository:
//
//	func TestConformance(t *testing.T) {
//		conformance.Run(t, "./bin/my-plugin", conformance.Fixture{
//			Secrets: map[string][]byte{"secret/data/demo#key": []byte("value")},
//			Missing: "secret/data/does-not-exist#key",
//		})
//	}
//
// The kit is a skeleton: it covers the handshake, capabilities, the FIPS
// 140-3 report, health, get, list, and Courier Key write. Run it a second
// time with GODEBUG=fips140=on to check the plugin follows the core into
// FIPS mode.
package conformance

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/potto007/TrustedCourier/sdk/plugin"
	"github.com/potto007/TrustedCourier/sdk/plugin/client"
)

// Fixture is what the Backend behind the plugin holds when the kit runs.
type Fixture struct {
	// Secrets the Backend holds, by location. At least one is required.
	Secrets map[string][]byte
	// Missing is a location where the Backend holds nothing.
	Missing string
	// CourierKeyLocation is where the kit may write a Courier Key. Required
	// when the plugin reports the CourierKeyWrite capability.
	CourierKeyLocation string
	// Env is the plugin's environment, such as Backend addresses and
	// credentials. GODEBUG is set by the kit to the test process's FIPS
	// 140-3 mode.
	Env []string
}

// callTimeout bounds each call the kit makes.
const callTimeout = 10 * time.Second

// Run launches the plugin binary and runs the conformance checks as subtests
// of t.
func Run(t *testing.T, binary string, f Fixture) {
	t.Helper()
	if len(f.Secrets) == 0 || f.Missing == "" {
		t.Fatal("conformance: Fixture needs at least one Secret and a Missing location")
	}
	cmd := exec.Command(binary)
	// The kit's FIPS 140-3 mode reaches the plugin as the core's does.
	cmd.Env = append(slices.Clone(f.Env), "GODEBUG="+client.GODEBUG())
	c, err := client.Start(cmd, nil)
	if err != nil {
		t.Fatalf("launch plugin: %v", err)
	}
	t.Cleanup(c.Kill)

	t.Run("FIPS140", func(t *testing.T) {
		st := c.FIPS140()
		if st.Version == "" {
			t.Error("plugin reports no FIPS 140-3 module version; build it on the current SDK")
		}
		if host := client.HostFIPS140(); !st.Covers(host) {
			t.Errorf("kit runs in FIPS 140-3 mode %s but the plugin reports %s; a core in that mode refuses it", host.Mode(), st.Mode())
		}
	})

	t.Run("Health", func(t *testing.T) {
		if _, err := c.Health(ctx(t)); err != nil {
			t.Errorf("Health: %v", err)
		}
	})

	t.Run("Get", func(t *testing.T) {
		for loc, want := range f.Secrets {
			got, err := c.Get(ctx(t), loc)
			if err != nil {
				t.Errorf("Get(%q): %v", loc, err)
				continue
			}
			if !bytes.Equal(got, want) {
				t.Errorf("Get(%q) returned a different value than the Fixture holds", loc)
			}
		}
	})

	t.Run("GetMissing", func(t *testing.T) {
		_, err := c.Get(ctx(t), f.Missing)
		if !errors.Is(err, plugin.ErrNotFound) {
			t.Errorf("Get(%q) = %v, want an error wrapping plugin.ErrNotFound", f.Missing, err)
		}
	})

	t.Run("List", func(t *testing.T) {
		all, err := c.List(ctx(t), "")
		if err != nil {
			t.Fatalf("List(\"\"): %v", err)
		}
		for loc := range f.Secrets {
			if !slices.Contains(all, loc) {
				t.Errorf("List(\"\") does not include %q", loc)
			}
			prefix := halfPrefix(loc)
			some, err := c.List(ctx(t), prefix)
			if err != nil {
				t.Errorf("List(%q): %v", prefix, err)
				continue
			}
			if !slices.Contains(some, loc) {
				t.Errorf("List(%q) does not include %q", prefix, loc)
			}
		}
	})

	t.Run("CourierKeyWrite", func(t *testing.T) {
		if !c.Capabilities().CourierKeyWrite {
			err := c.WriteCourierKey(ctx(t), f.Missing, []byte("x"))
			if !errors.Is(err, plugin.ErrUnsupported) {
				t.Errorf("WriteCourierKey without the capability = %v, want plugin.ErrUnsupported", err)
			}
			return
		}
		if f.CourierKeyLocation == "" {
			t.Fatal("plugin reports CourierKeyWrite; set Fixture.CourierKeyLocation")
		}
		want := []byte("conformance-courier-key-" + strings.Repeat("k", 32))
		if err := c.WriteCourierKey(ctx(t), f.CourierKeyLocation, want); err != nil {
			t.Fatalf("WriteCourierKey: %v", err)
		}
		got, err := c.Get(ctx(t), f.CourierKeyLocation)
		if err != nil {
			t.Fatalf("Get after WriteCourierKey: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Error("Get after WriteCourierKey returned a different value")
		}
	})
}

// halfPrefix returns about the first half of loc, cut at a character
// boundary so the prefix stays valid UTF-8.
func halfPrefix(loc string) string {
	i := len(loc) / 2
	for i > 0 && !utf8.RuneStart(loc[i]) {
		i--
	}
	return loc[:i]
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(t.Context(), callTimeout)
	t.Cleanup(cancel)
	return c
}
