package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"golang.org/x/sys/unix"
)

// Preflight every existing file before changing the profile. Publish complete
// files by no-replace rename; never follow an existing or dangling symlink.
func publishProfile(path string, files map[string][]byte) error {
	dir, err := openDir(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	fd := int(dir.Fd())
	if err = unix.Flock(fd, unix.LOCK_EX); err != nil {
		return err
	}
	names := make([]string, 0, len(files))
	for name := range files {
		if name == "." || name == ".." || filepath.Base(name) != name {
			return fmt.Errorf("invalid profile filename")
		}
		names = append(names, name)
	}
	sort.Strings(names)
	missing := make([]string, 0, len(files))
	for _, name := range names {
		fileFD, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err == unix.ENOENT {
			missing = append(missing, name)
			continue
		}
		if err != nil {
			return err
		}
		file := os.NewFile(uintptr(fileFD), name)
		_, err = privateFD(fileFD, unix.S_IFREG)
		if err != nil {
			file.Close()
			return err
		}
		old, err := io.ReadAll(io.LimitReader(file, 1<<20+1))
		file.Close()
		if err != nil {
			return err
		}
		if !bytes.Equal(old, files[name]) {
			return fmt.Errorf("%s exists with different contents", filepath.Join(path, name))
		}
	}
	for _, name := range missing {
		nonce := make([]byte, 24)
		if _, err = rand.Read(nonce); err != nil {
			return err
		}
		temporary := ".tc-setup-" + hex.EncodeToString(nonce)
		fileFD, err := unix.Openat(fd, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
		if err != nil {
			return err
		}
		file := os.NewFile(uintptr(fileFD), temporary)
		_, err = file.Write(files[name])
		if err == nil {
			err = file.Sync()
		}
		closeErr := file.Close()
		if err == nil {
			err = closeErr
		}
		if err == nil {
			err = unix.Renameat2(fd, temporary, fd, name, unix.RENAME_NOREPLACE)
		}
		if err != nil {
			unix.Unlinkat(fd, temporary, 0)
			return err
		}
	}
	return nil
}
