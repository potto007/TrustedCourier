// Package conformance is the Backend Plugin conformance kit: a Go test suite
// that launches a plugin binary the way TrustedCourier does and checks it
// meets the plugin contract. Run it from a test in the plugin's repository:
//
//	func TestConformance(t *testing.T) {
//		conformance.Run(t, "./bin/my-plugin", conformance.Fixture{
//			Secrets:   map[string][]byte{"secret/data/demo#key": []byte("value")},
//			Missing:   "secret/data/does-not-exist#key",
//			Malformed: []string{"secret/data/demo#empty"},
//		})
//	}
//
// The kit covers the handshake, capability reporting, the FIPS 140-3 report
// in the mode the kit runs in and in the modes the core may set, health,
// get, missing and malformed Secrets, list, concurrent calls, and Courier
// Key write. It runs the plugin with the environment in the Fixture, so the
// Backend behind it must be reachable and hold the Fixture's Secrets. See
// docs/backend-plugins.md in the TrustedCourier repository.
package conformance

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"slices"
	"strings"
	"sync"
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
	// Missing is a location where the Backend holds nothing. Required.
	Missing string
	// Malformed are locations where the Backend holds something that is not
	// a Secret, such as an empty value, a value of the wrong type, or a
	// record without the named field. The plugin must fail a Get there with
	// its own error saying what is wrong: not ErrNotFound, and not by
	// serving the value and leaving the SDK to refuse it, which the core
	// reports as a plugin defect. Optional, but every plugin has such
	// locations, so name at least one.
	Malformed []string
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

// concurrency is how many callers the Concurrent check runs at once.
const concurrency = 8

// Run launches the plugin binary and runs the conformance checks as subtests
// of t.
func Run(t *testing.T, binary string, f Fixture) {
	t.Helper()
	if len(f.Secrets) == 0 || f.Missing == "" {
		t.Fatal("conformance: Fixture needs at least one Secret and a Missing location")
	}
	// The kit's FIPS 140-3 mode reaches the plugin as the core's does.
	c := launch(t, binary, f, client.GODEBUG())

	t.Run("FIPS140", func(t *testing.T) {
		st := c.FIPS140()
		if st.Version == "" {
			t.Error("plugin reports no FIPS 140-3 module version; build it on the current SDK")
		}
		if host := client.HostFIPS140(); !st.Covers(host) {
			t.Errorf("kit runs in FIPS 140-3 mode %s but the plugin reports %s; a core in that mode refuses it", host.Mode(), st.Mode())
		}
	})

	t.Run("FIPS140Follows", func(t *testing.T) {
		// A core in FIPS mode spells the mode out in the plugin's GODEBUG
		// and refuses a plugin that does not follow it, whatever mode the
		// kit itself runs in.
		for _, mode := range []string{"on", "only"} {
			st := launch(t, binary, f, "fips140="+mode).FIPS140()
			if st.Mode() != mode {
				t.Errorf("launched with GODEBUG=fips140=%s, the plugin reports mode %s; a core in mode %s refuses it", mode, st.Mode(), mode)
			}
		}
	})

	t.Run("Capabilities", func(t *testing.T) {
		caps := c.Capabilities()
		t.Logf("plugin reports capabilities %v, FIPS 140-3 mode %s (module %s)", caps.Names(), c.FIPS140().Mode(), c.FIPS140().Version)
		if caps.CourierKeyWrite && f.CourierKeyLocation == "" {
			t.Error("plugin reports CourierKeyWrite; set Fixture.CourierKeyLocation")
		}
	})

	t.Run("Health", func(t *testing.T) {
		detail, err := c.Health(ctx(t))
		if err != nil {
			t.Errorf("Health: %v", err)
		}
		t.Logf("health detail: %q", detail)
	})

	t.Run("Get", func(t *testing.T) {
		for loc, want := range f.Secrets {
			checkGet(t, c, loc, want)
		}
	})

	t.Run("GetMissing", func(t *testing.T) {
		_, err := c.Get(ctx(t), f.Missing)
		if !errors.Is(err, plugin.ErrNotFound) {
			t.Errorf("Get(%q) = %v, want an error wrapping plugin.ErrNotFound", f.Missing, err)
		}
	})

	t.Run("GetMalformed", func(t *testing.T) {
		if len(f.Malformed) == 0 {
			t.Skip("Fixture names no Malformed locations")
		}
		for _, loc := range f.Malformed {
			v, err := c.Get(ctx(t), loc)
			switch {
			case err == nil:
				clear(v)
				t.Errorf("Get(%q) returned a value; the Backend holds something that is not a Secret there, so Get must fail", loc)
			case errors.Is(err, plugin.ErrNotFound):
				t.Errorf("Get(%q) = %v; the Backend holds something there, so the error must not be plugin.ErrNotFound", loc, err)
			case errors.Is(err, client.ErrMalformed):
				t.Errorf("Get(%q) = %v; the core treats that as a plugin defect, so Get must return its own error saying what is wrong with the Secret", loc, err)
			default:
				t.Logf("Get(%q) failed as it should: %v", loc, err)
			}
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

	t.Run("ListNoMatch", func(t *testing.T) {
		locs, err := c.List(ctx(t), f.Missing)
		if err != nil {
			t.Fatalf("List(%q): %v", f.Missing, err)
		}
		if len(locs) != 0 {
			t.Errorf("List(%q) = %q, want no locations under a location that holds nothing", f.Missing, locs)
		}
	})

	t.Run("Concurrent", func(t *testing.T) {
		// The core calls a plugin from every Delivery at once.
		var wg sync.WaitGroup
		for range concurrency {
			wg.Go(func() {
				for loc, want := range f.Secrets {
					checkGet(t, c, loc, want)
				}
				if _, err := c.Health(ctx(t)); err != nil {
					t.Errorf("Health: %v", err)
				}
			})
		}
		wg.Wait()
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
		// Written twice, so a Backend that keeps versions must serve the
		// newest, and a written key must not disturb the Secrets.
		for _, want := range [][]byte{
			[]byte("conformance-courier-key-" + strings.Repeat("k", 32)),
			[]byte("-----BEGIN PRIVATE KEY-----\nconformance\n-----END PRIVATE KEY-----\n"),
		} {
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
		}
		for loc, want := range f.Secrets {
			checkGet(t, c, loc, want)
		}
	})
}

// launch starts the plugin with the Fixture's environment and the given
// GODEBUG, killed when t ends.
func launch(t *testing.T, binary string, f Fixture, godebug string) *client.Client {
	t.Helper()
	cmd := exec.Command(binary)
	cmd.Env = append(slices.Clone(f.Env), "GODEBUG="+godebug)
	c, err := client.Start(cmd, nil)
	if err != nil {
		t.Fatalf("launch plugin with GODEBUG=%s: %v", godebug, err)
	}
	t.Cleanup(c.Kill)
	return c
}

func checkGet(t *testing.T, c *client.Client, loc string, want []byte) {
	t.Helper()
	got, err := c.Get(ctx(t), loc)
	if err != nil {
		t.Errorf("Get(%q): %v", loc, err)
		return
	}
	if !bytes.Equal(got, want) {
		t.Errorf("Get(%q) returned a different value than the Fixture holds", loc)
	}
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
