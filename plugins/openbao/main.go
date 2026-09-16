// Command openbao is the bundled OpenBao Backend Plugin (ADR-0008).
//
// Placeholder: the plugin is built on the plugin SDK once the Backend Plugin
// seam exists.
//
// FIPS 140-3 mode follows the core, which sets GODEBUG; on its own the
// plugin defaults to off, as the core does (ADR-0027).
//
//go:debug fips140=off
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "openbao Backend Plugin: not implemented yet")
	os.Exit(2)
}
