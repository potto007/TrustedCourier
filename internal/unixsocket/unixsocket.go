// Package unixsocket binds unix sockets for TrustedCourier's listeners.
package unixsocket

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"syscall"
)

// Listen binds the unix socket at path, creating its directory with dirMode
// and leaving the socket with sockMode. A stale socket file left by a crashed
// process is replaced; a live one is an error. what names the socket in
// errors, such as "admin socket".
//
// The socket is bound owner-only and widened to sockMode afterwards, so it
// is never more open than intended.
func Listen(path string, dirMode, sockMode os.FileMode, what string) (net.Listener, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return nil, fmt.Errorf("create %s directory: %w", what, err)
	}
	// MkdirAll leaves an existing directory's mode alone, so one created
	// owner-only for another socket would keep everyone else from reaching
	// this one: widen it to at least dirMode.
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("inspect %s directory: %w", what, err)
	}
	if mode := info.Mode().Perm(); mode|dirMode != mode {
		if err := os.Chmod(dir, mode|dirMode); err != nil {
			return nil, fmt.Errorf("set %s directory mode: %w", what, err)
		}
	}
	if err := removeStale(path, what); err != nil {
		return nil, err
	}
	var ln net.Listener
	err = withUmask(0o177, func() error {
		var err error
		ln, err = net.Listen("unix", path)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", what, err)
	}
	if err := os.Chmod(path, sockMode); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("set %s mode: %w", what, err)
	}
	return ln, nil
}

// removeStale removes path only when it is a socket nothing listens on. Any
// other dial failure (a full backlog, a permission error) may mean a live
// server, so it is reported rather than unlinked.
func removeStale(path, what string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect %s: %w", what, err)
	}
	if info.Mode().Type() != os.ModeSocket {
		return fmt.Errorf("%s path %s exists and is not a socket", what, path)
	}
	conn, err := net.Dial("unix", path)
	switch {
	case err == nil:
		_ = conn.Close()
		return fmt.Errorf("another process is serving the %s %s", what, path)
	case errors.Is(err, syscall.ECONNREFUSED):
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("remove stale %s: %w", what, err)
		}
		return nil
	default:
		return fmt.Errorf("%s %s may be in use: %w", what, path, err)
	}
}
