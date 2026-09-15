package secret

import "golang.org/x/sys/unix"

// excludeFromCoreDumps keeps buf out of any core dump the process writes.
func excludeFromCoreDumps(buf []byte) error {
	return unix.Madvise(buf, unix.MADV_DONTDUMP)
}
