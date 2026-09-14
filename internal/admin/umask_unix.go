//go:build unix

package admin

import "syscall"

// withUmask runs f with the process umask set to mask. The umask is
// process-wide, so call this only while no other goroutine creates files.
func withUmask(mask int, f func() error) error {
	old := syscall.Umask(mask)
	defer syscall.Umask(old)
	return f()
}
