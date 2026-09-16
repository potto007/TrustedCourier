//go:build unix

package pluginhost

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"slices"
	"strconv"
	"syscall"

	"github.com/potto007/TrustedCourier/internal/config"
)

type credential = syscall.Credential

// pluginCredential resolves the OS user a Backend Plugin runs as and checks
// the separation ADR-0004 requires. It returns nil when the Operator chose
// insecure_share_core_user.
func pluginCredential(cfg *config.Config, pc config.BackendPlugin) (*credential, error) {
	if pc.InsecureShareCoreUser {
		return nil, nil
	}
	u, err := lookupUser(pc.User)
	if err != nil {
		return nil, err
	}
	cred, err := toCredential(u)
	if err != nil {
		return nil, fmt.Errorf("user %q: %w", pc.User, err)
	}
	if int(cred.Uid) == os.Geteuid() {
		return nil, fmt.Errorf("user %q is the server's own user; a Backend Plugin must run as a separate OS user (insecure_share_core_user: true allows this for development only)", pc.User)
	}
	if err := checkSeparation(cfg, cred, pc.User); err != nil {
		return nil, err
	}
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("running it as user %q requires TrustedCourier to run as root", pc.User)
	}
	return cred, nil
}

// checkSeparation checks that cred, the OS user named userName, can neither
// read cfg's config file nor owns its data directory.
func checkSeparation(cfg *config.Config, cred *credential, userName string) error {
	readable, err := readableBy(cfg.Path, cred)
	if err != nil {
		return err
	}
	if readable {
		return fmt.Errorf("the config file %s is readable by user %q; restrict it, for example with chmod 600", cfg.Path, userName)
	}
	if owned, err := ownedBy(cfg.DataDir, cred.Uid); err != nil {
		return err
	} else if owned {
		return fmt.Errorf("the data directory %s is owned by user %q", cfg.DataDir, userName)
	}
	return nil
}

func lookupUser(name string) (*user.User, error) {
	u, err := user.Lookup(name)
	if err == nil {
		return u, nil
	}
	if _, numErr := strconv.ParseUint(name, 10, 32); numErr == nil {
		if u, idErr := user.LookupId(name); idErr == nil {
			return u, nil
		}
	}
	return nil, fmt.Errorf("unknown user %q", name)
}

func toCredential(u *user.User) (*credential, error) {
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return nil, err
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return nil, err
	}
	cred := &credential{Uid: uint32(uid), Gid: uint32(gid)}
	groups, err := u.GroupIds()
	if err != nil {
		return nil, fmt.Errorf("list groups: %w", err)
	}
	for _, g := range groups {
		id, err := strconv.ParseUint(g, 10, 32)
		if err != nil {
			return nil, err
		}
		cred.Groups = append(cred.Groups, uint32(id))
	}
	return cred, nil
}

// readableBy reports whether the file at path is readable by cred going by
// its owner and mode bits. Owning a file counts, since the owner can change
// its mode.
func readableBy(path string, cred *credential) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false, errors.New("file ownership is not available on this platform")
	}
	perm := info.Mode().Perm()
	switch {
	case st.Uid == cred.Uid:
		return true, nil
	case st.Gid == cred.Gid || slices.Contains(cred.Groups, st.Gid):
		return perm&0o040 != 0, nil
	default:
		return perm&0o004 != 0, nil
	}
}

func ownedBy(path string, uid uint32) (bool, error) {
	info, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == uid, nil
}

func setCredential(cmd *exec.Cmd, cred *credential) error {
	if cred != nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
	}
	return nil
}

// GiveFile hands the file at path to the Backend Plugin's OS user, for a
// file the plugin must read, such as its Backend's token. It does nothing
// when the plugin shares the server's user.
func GiveFile(path string, pc config.BackendPlugin) error {
	if pc.InsecureShareCoreUser {
		return nil
	}
	u, err := lookupUser(pc.User)
	if err != nil {
		return err
	}
	cred, err := toCredential(u)
	if err != nil {
		return fmt.Errorf("user %q: %w", pc.User, err)
	}
	if err := os.Chown(path, int(cred.Uid), int(cred.Gid)); err != nil {
		return fmt.Errorf("give %s to user %q: %w", path, pc.User, err)
	}
	return nil
}
