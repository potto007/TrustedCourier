package pluginhost

import (
	"os"
	"os/exec"
)

// verifiedCommand executes the already-verified open file f rather than
// looking path up again. f becomes descriptor 3 in the child, which execs
// /proc/self/fd/3, so replacing the file at path after verification has no
// effect.
func verifiedCommand(f *os.File, path string) *exec.Cmd {
	cmd := exec.Command("/proc/self/fd/3")
	cmd.Args[0] = path
	cmd.ExtraFiles = []*os.File{f}
	return cmd
}
