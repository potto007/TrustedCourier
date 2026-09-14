//go:build unix

package secret

import "golang.org/x/sys/unix"

// Variables so tests can inspect a buffer after Release.
var (
	munlock = unix.Munlock
	munmap  = unix.Munmap
)

// allocate maps size bytes of private anonymous memory outside the Go heap,
// where the garbage collector never copies it, and locks them into RAM so the
// value never reaches swap.
func allocate(size int) ([]byte, error) {
	buf, err := unix.Mmap(-1, 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		return nil, err
	}
	if err := unix.Mlock(buf); err != nil {
		_ = unix.Munmap(buf)
		return nil, err
	}
	return buf, nil
}
