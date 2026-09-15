//go:build !unix

package secret

import "errors"

var (
	munlock = func([]byte) error { return nil }
	munmap  = func([]byte) error { return nil }
)

// allocate fails: without locked memory a Secret could reach swap, so the
// core refuses to hold one.
func allocate(int) ([]byte, error) {
	return nil, errors.New("locked memory is not supported on this platform")
}
