// Package e2e holds the Seam 1 tests: a real TrustedCourier process driven
// through its config file, admin socket, and the tc CLI.
package e2e

import (
	"testing"

	"github.com/potto007/TrustedCourier/e2e/harness"

	// The harness builds tc in a subprocess, which the go test cache cannot
	// see. Importing the CLI makes core changes invalidate cached results.
	_ "github.com/potto007/TrustedCourier/internal/cli"
)

func TestMain(m *testing.M) { harness.Main(m) }
