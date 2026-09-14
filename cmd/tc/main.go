// Command tc runs the TrustedCourier server and administers it.
package main

import (
	"os"

	"github.com/potto007/TrustedCourier/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:], os.Stdout, os.Stderr))
}
