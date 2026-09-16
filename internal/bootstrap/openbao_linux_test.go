package bootstrap_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/potto007/TrustedCourier/internal/bootstrap"
)

// A file-size limit produces a real partial write. Run it in a subprocess
// because the limit and SIGXFSZ disposition affect the whole process.
func TestSealKeyWriteFailureRemovesIncompleteFile(t *testing.T) {
	const pathEnv = "TC_TEST_SEAL_WRITE_PATH"
	path := os.Getenv(pathEnv)
	if path == "" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSealKeyWriteFailureRemovesIncompleteFile$")
		cmd.Env = append(os.Environ(), pathEnv+"="+filepath.Join(t.TempDir(), "seal.key"))
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("seal-key subprocess: %v\n%s", err, out)
		}
		return
	}

	signal.Ignore(syscall.SIGXFSZ)
	var original syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &original); err != nil {
		t.Fatal(err)
	}
	limited := original
	limited.Cur = 1
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &limited); err != nil {
		t.Fatal(err)
	}
	key, created, err := bootstrap.EnsureSealKey(path)
	if !errors.Is(err, syscall.EFBIG) || key != nil || created {
		t.Fatalf("partial write returned key length %d, created %v, error %v; want no key and EFBIG", len(key), created, err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("incomplete seal-key file remains: %v", err)
	}

	// Once storage works again, retry must create a complete reusable key.
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &original); err != nil {
		t.Fatal(err)
	}
	key, created, err = bootstrap.EnsureSealKey(path)
	if err != nil || !created || len(key) != bootstrap.SealKeySize {
		t.Fatalf("retry: key length %d, created %v, error %v", len(key), created, err)
	}
	persisted, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(persisted, key) {
		t.Fatalf("retry did not persist the returned key: %v", err)
	}
}
