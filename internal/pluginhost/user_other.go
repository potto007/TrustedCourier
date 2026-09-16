//go:build !unix

package pluginhost

import (
	"errors"
	"os/exec"

	"github.com/potto007/TrustedCourier/internal/config"
)

type credential struct{}

var errNoSeparateUser = errors.New("running a Backend Plugin as a separate OS user is not supported on this platform")

func pluginCredential(_ *config.Config, pc config.BackendPlugin) (*credential, error) {
	if pc.InsecureShareCoreUser {
		return nil, nil
	}
	return nil, errNoSeparateUser
}

// checkSeparation has nothing to check: no plugin runs as a separate user
// here.
func checkSeparation(_ *config.Config, _ *credential, _ string) error { return nil }

func setCredential(_ *exec.Cmd, cred *credential) error {
	if cred != nil {
		return errNoSeparateUser
	}
	return nil
}

// GiveFile has no user to give the file to: no plugin runs as a separate
// user here.
func GiveFile(_ string, pc config.BackendPlugin) error {
	if pc.InsecureShareCoreUser {
		return nil
	}
	return errNoSeparateUser
}
