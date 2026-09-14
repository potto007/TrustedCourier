//go:build !linux

package pluginhost

import (
	"os"
	"os/exec"
)

// verifiedCommand runs the binary by path, since this platform cannot
// execute the verified file descriptor. The binary could in principle be
// swapped between the hash check and exec.
func verifiedCommand(_ *os.File, path string) *exec.Cmd {
	return exec.Command(path)
}
