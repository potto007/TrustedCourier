package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// FIFO identities prevent a replacement path from impersonating the endpoints
// returned by the broker. The command never crosses this transport: it remains
// in the broker's bounded, expiring, single-use in-memory job table.
type mailboxRef struct {
	Path     string `json:"path"`
	Device   uint64 `json:"device"`
	Request  uint64 `json:"request_inode"`
	Response uint64 `json:"response_inode"`
}

func codexSandboxConfig(workspace, mailbox, executable, codexBinary, tokenFile string) []byte {
	return []byte(fmt.Sprintf(`default_permissions = "trustedcourier"

[permissions.trustedcourier.filesystem]
":root" = "deny"
":minimal" = "read"
%q = "deny"
%q = "deny"
%q = "write"
%q = "write"
%q = "read"
%q = "read"

[permissions.trustedcourier.network]
enabled = false
`, filepath.Dir(mailbox), tokenFile, workspace, mailbox, executable, codexBinary))
}

func privateFD(fd int, kind uint32) (unix.Stat_t, error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return st, err
	}
	if st.Mode&unix.S_IFMT != kind || st.Uid != uint32(os.Geteuid()) || st.Mode&0077 != 0 {
		return st, errors.New("mailbox endpoint must be private, owned, and of the expected type")
	}
	return st, nil
}

func openDir(path string) (*os.File, error) {
	clean, err := canonical(path, true)
	if err != nil || clean != path {
		return nil, errors.New("mailbox directory must be a canonical absolute path")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	if _, err = privateFD(fd, unix.S_IFDIR); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

func (b *broker) openMailbox() error {
	if !separated(b.cfg.Workspace, b.cfg.Mailbox) {
		return errors.New("mailbox must be outside workspace")
	}
	parent, err := openDir(b.cfg.Mailbox)
	if err != nil {
		return err
	}
	nonce := make([]byte, 24)
	if _, err = rand.Read(nonce); err != nil {
		parent.Close()
		return err
	}
	name := "session-" + hex.EncodeToString(nonce)
	if err = unix.Mkdirat(int(parent.Fd()), name, 0700); err != nil {
		parent.Close()
		return err
	}
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		unix.Unlinkat(int(parent.Fd()), name, unix.AT_REMOVEDIR)
		parent.Close()
		return err
	}
	b.mailboxParent, b.mailboxName = parent, name
	b.mailboxRoot = os.NewFile(uintptr(fd), name)
	b.mailboxPath = filepath.Join(b.cfg.Mailbox, name)
	parentContext := b.ctx
	if parentContext == nil {
		parentContext = context.Background()
	}
	b.mailboxContext, b.mailboxCancel = context.WithCancel(parentContext)
	return nil
}

func (b *broker) closeMailbox() {
	b.mu.Lock()
	b.mailboxClosing = true
	b.mailboxCancel()
	b.mu.Unlock()
	b.mailboxWG.Wait()
	b.mailboxRoot.Close()
	// Only remove our empty session directory. A replacement or unexpected entry
	// causes failure; never recursively follow or delete an Agent-supplied path.
	unix.Unlinkat(int(b.mailboxParent.Fd()), b.mailboxName, unix.AT_REMOVEDIR)
	b.mailboxParent.Close()
}

func validJobID(id string) bool {
	if len(id) != 48 {
		return false
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func (b *broker) newMailboxJob(id string) (*mailboxRef, error) {
	if b.mailboxClosing {
		return nil, errors.New("broker shutting down")
	}
	rootFD := int(b.mailboxRoot.Fd())
	name := ".pending-" + id
	if err := unix.Mkdirat(rootFD, name, 0700); err != nil {
		return nil, err
	}
	fd, err := unix.Openat(rootFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		unix.Unlinkat(rootFD, name, unix.AT_REMOVEDIR)
		return nil, err
	}
	cleanup := func() {
		unix.Unlinkat(fd, "request", 0)
		unix.Unlinkat(fd, "response", 0)
		unix.Close(fd)
		unix.Unlinkat(rootFD, name, unix.AT_REMOVEDIR)
	}
	for _, name := range []string{"request", "response"} {
		if err = unix.Mkfifoat(fd, name, 0600); err != nil {
			cleanup()
			return nil, err
		}
	}
	requestFD, err := unix.Openat(fd, "request", unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		cleanup()
		return nil, err
	}
	responseFD, err := unix.Openat(fd, "response", unix.O_RDWR|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		unix.Close(requestFD)
		cleanup()
		return nil, err
	}
	req, err := privateFD(requestFD, unix.S_IFIFO)
	if err != nil {
		unix.Close(requestFD)
		unix.Close(responseFD)
		cleanup()
		return nil, err
	}
	resp, err := privateFD(responseFD, unix.S_IFIFO)
	if err != nil {
		unix.Close(requestFD)
		unix.Close(responseFD)
		cleanup()
		return nil, err
	}
	if err = unix.Renameat2(rootFD, name, rootFD, id, unix.RENAME_NOREPLACE); err != nil {
		unix.Close(requestFD)
		unix.Close(responseFD)
		cleanup()
		return nil, err
	}
	name = id
	ref := &mailboxRef{filepath.Join(b.mailboxPath, id), req.Dev, req.Ino, resp.Ino}
	b.mailboxActive++
	b.mailboxWG.Add(1)
	go func() {
		defer b.mailboxWG.Done()
		defer cleanup()
		defer unix.Close(requestFD)
		defer unix.Close(responseFD)
		defer func() { b.mu.Lock(); delete(b.jobs, id); b.mailboxActive--; b.mu.Unlock() }()
		b.serveMailbox(id, requestFD, responseFD)
	}()
	return ref, nil
}

// Requests are single bytes: D starts the immutable job; any subsequent byte
// cancels it. A closed request writer cancels a running worker too. There is no
// command, path, credential, or response filename to reinterpret from disk.
func (b *broker) serveMailbox(id string, requestFD, responseFD int) {
	pending, stop := context.WithTimeout(b.mailboxContext, jobTTL)
	defer stop()
	started := false
	buf := make([]byte, 1)
	for !started {
		b.mu.Lock()
		_, stillPending := b.jobs[id]
		b.mu.Unlock()
		if !stillPending {
			return
		} // consumed through the legacy socket or expired
		if pending.Err() != nil {
			return
		}
		n, err := unix.Read(requestFD, buf)
		if n == 1 {
			if buf[0] != 'D' {
				return
			}
			started = true
		} else if err != nil && err != unix.EAGAIN && err != unix.EINTR {
			return
		}
		if !started {
			time.Sleep(20 * time.Millisecond)
		}
	}
	ctx, cancel := context.WithCancel(b.mailboxContext)
	defer cancel()
	done := make(chan reply, 1)
	go func() { done <- b.processContext(ctx, message{Action: "dispatch", Job: id}) }()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	var result reply
	for {
		select {
		case result = <-done:
			data, err := json.Marshal(result)
			if err == nil {
				writeCtx, stopWrite := context.WithTimeout(ctx, 5*time.Second)
				writeFIFO(writeCtx, responseFD, append(data, '\n'))
				stopWrite()
			}
			return
		case <-ctx.Done():
			<-done // processContext kills and reaps the bounded worker before cleanup.
			return
		case <-ticker.C:
			n, err := unix.Read(requestFD, buf)
			if n > 0 || (n == 0 && err == nil) {
				cancel()
			}
			if err != nil && err != unix.EAGAIN && err != unix.EINTR {
				cancel()
			}
		}
	}
}

func writeFIFO(ctx context.Context, fd int, data []byte) error {
	for len(data) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := unix.Write(fd, data)
		if n > 0 {
			data = data[n:]
		}
		if err != nil && err != unix.EAGAIN && err != unix.EINTR {
			return err
		}
		if n <= 0 {
			time.Sleep(10 * time.Millisecond)
		}
	}
	return nil
}

func dispatchMailbox(parent context.Context, ref mailboxRef, id string) (reply, error) {
	var result reply
	if !validJobID(id) || filepath.Base(ref.Path) != id || ref.Request == 0 || ref.Response == 0 {
		return result, errors.New("invalid mailbox job reference")
	}
	dir, err := openDir(ref.Path)
	if err != nil {
		return result, err
	}
	defer dir.Close()
	open := func(name string, flags int, inode uint64) (int, error) {
		fd, err := unix.Openat(int(dir.Fd()), name, flags|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return -1, err
		}
		st, err := privateFD(fd, unix.S_IFIFO)
		if err != nil || st.Dev != ref.Device || st.Ino != inode {
			unix.Close(fd)
			return -1, errors.New("mailbox endpoint was replaced")
		}
		return fd, nil
	}
	// Keep this writer open until the result is received. Its close signals
	// cancellation even when the dispatcher is killed without running defers.
	responseFD, err := open("response", unix.O_RDONLY, ref.Response)
	if err != nil {
		return result, err
	}
	defer unix.Close(responseFD)
	requestFD, err := open("request", unix.O_WRONLY, ref.Request)
	if err != nil {
		return result, err
	}
	defer unix.Close(requestFD)
	if err = unix.Flock(requestFD, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return result, errors.New("job already has a dispatcher")
	}
	ctx, cancel := context.WithTimeout(parent, 3*time.Minute)
	defer cancel()
	if err = writeFIFO(ctx, requestFD, []byte{'D'}); err != nil {
		return result, err
	}
	var output bytes.Buffer
	buf := make([]byte, 8192)
	for {
		if err = ctx.Err(); err != nil {
			return result, err
		}
		n, readErr := unix.Read(responseFD, buf)
		if n > 0 {
			output.Write(buf[:n])
			// JSON can expand each bounded output byte into six escaped bytes.
			if output.Len() > outputLimit*6+4096 {
				return result, errors.New("oversized mailbox reply")
			}
			if buf[n-1] == '\n' {
				break
			}
		}
		if n == 0 && readErr == nil {
			return result, errors.New("broker closed mailbox before replying")
		}
		if readErr != nil && readErr != unix.EAGAIN && readErr != unix.EINTR {
			return result, readErr
		}
		if n <= 0 {
			time.Sleep(10 * time.Millisecond)
		}
	}
	decoder := json.NewDecoder(&output)
	if err = decoder.Decode(&result); err != nil {
		return result, err
	}
	var extra any
	if err = decoder.Decode(&extra); err != io.EOF {
		return reply{}, errors.New("trailing mailbox reply data")
	}
	if len(result.Output) > outputLimit || strings.ContainsRune(result.Job, '\x00') {
		return reply{}, errors.New("invalid mailbox reply")
	}
	return result, nil
}
