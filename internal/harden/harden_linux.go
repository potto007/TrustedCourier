package harden

import "syscall"

func disableCoreDumps() error {
	if err := zeroCoreLimit(); err != nil {
		return err
	}
	if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_SET_DUMPABLE, 0, 0); errno != 0 {
		return errno
	}
	return nil
}

// dumpable reports the process's dumpable flag, for tests.
func dumpable() (int, error) {
	r, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_GET_DUMPABLE, 0, 0)
	if errno != 0 {
		return 0, errno
	}
	return int(r), nil
}
