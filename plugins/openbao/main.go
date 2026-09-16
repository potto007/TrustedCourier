// Command openbao is the bundled OpenBao Backend Plugin (ADR-0008): it
// serves Secrets from OpenBao's KV secrets engine and stores Courier Keys
// there. TrustedCourier launches it; it is not run by hand.
//
// It is configured by its environment, set in the server config under
// backend_plugins.<name>.env:
//
//	BAO_ADDR        OpenBao's URL, such as https://openbao.internal:8200 (required)
//	BAO_TOKEN_FILE  a file holding the token, readable by the plugin's user
//	BAO_TOKEN       the token itself; BAO_TOKEN_FILE is preferred
//	BAO_CACERT      a PEM file of CA certificates that verify OpenBao's certificate
//	BAO_NAMESPACE   the OpenBao namespace the paths are under
//
// Locations are "<path>#<field>", such as secret/data/openai#key on a KV v2
// mount; see the openbao package.
//
// FIPS 140-3 mode follows the core, which sets GODEBUG; on its own the
// plugin defaults to off, as the core does (ADR-0027).
//
//go:debug fips140=off
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/potto007/TrustedCourier/plugins/openbao/internal/openbao"
	"github.com/potto007/TrustedCourier/sdk/plugin"
)

func main() {
	cfg, err := configFromEnv()
	if err != nil {
		fail(err)
	}
	b, err := openbao.New(cfg)
	if err != nil {
		fail(err)
	}
	plugin.Serve(b) // exits the process when the core stops the plugin
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "openbao Backend Plugin:", err)
	os.Exit(2)
}

func configFromEnv() (openbao.Config, error) {
	cfg := openbao.Config{
		Address:    os.Getenv("BAO_ADDR"),
		Token:      os.Getenv("BAO_TOKEN"),
		Namespace:  os.Getenv("BAO_NAMESPACE"),
		CACertFile: os.Getenv("BAO_CACERT"),
	}
	if cfg.Address == "" {
		return cfg, fmt.Errorf("BAO_ADDR is required; set it in backend_plugins.<name>.env")
	}
	if file := os.Getenv("BAO_TOKEN_FILE"); file != "" {
		if cfg.Token != "" {
			return cfg, fmt.Errorf("set BAO_TOKEN or BAO_TOKEN_FILE, not both")
		}
		data, err := os.ReadFile(file)
		if err != nil {
			return cfg, fmt.Errorf("BAO_TOKEN_FILE: %w", err)
		}
		cfg.Token = strings.TrimSpace(string(data))
		if cfg.Token == "" {
			return cfg, fmt.Errorf("BAO_TOKEN_FILE %s is empty", file)
		}
	}
	return cfg, nil
}
