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

func setCredential(_ *exec.Cmd, cred *credential) error {
	if cred != nil {
		return errNoSeparateUser
	}
	return nil
}
