package harden

import (
	"syscall"
	"testing"
)

func TestDisableCoreDumps(t *testing.T) {
	if err := DisableCoreDumps(); err != nil {
		t.Fatal(err)
	}
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_CORE, &lim); err != nil {
		t.Fatal(err)
	}
	if lim.Cur != 0 || lim.Max != 0 {
		t.Errorf("RLIMIT_CORE = %+v, want 0/0", lim)
	}
	d, err := dumpable()
	if err != nil {
		t.Fatal(err)
	}
	if d != 0 {
		t.Errorf("PR_GET_DUMPABLE = %d, want 0", d)
	}
	// Once the hard limit is zero, the process cannot raise it.
	if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 1, Max: 1}); err == nil {
		t.Error("core file size limit could be raised after DisableCoreDumps")
	}
}
