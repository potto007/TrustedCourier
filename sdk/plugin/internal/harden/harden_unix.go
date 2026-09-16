//go:build unix

package harden

import "syscall"

func zeroCoreLimit() error {
	return syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0})
}
