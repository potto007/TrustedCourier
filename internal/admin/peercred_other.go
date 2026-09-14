//go:build !linux && !darwin

package admin

import (
	"errors"
	"net"
)

// peerUID fails closed where TrustedCourier cannot read peer credentials.
func peerUID(*net.UnixConn) (int, error) {
	return 0, errors.New("peer credentials are not supported on this platform")
}
