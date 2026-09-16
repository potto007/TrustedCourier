// Command tc runs the TrustedCourier server and administers it.
//
// FIPS 140-3 mode is off unless the Operator sets GODEBUG=fips140=on or
// only, even in a build against the validated module, whose default would
// be on (ADR-0027).
//
//go:debug fips140=off
package main

import (
	"os"

	"github.com/potto007/TrustedCourier/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:], os.Stdout, os.Stderr))
}
