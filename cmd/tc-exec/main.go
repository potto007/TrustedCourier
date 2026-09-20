// tc-exec is an experimental, Linux-only Codex CLI tool execution bridge.
// It never accepts an Operator Credential or a Backend credential.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type config struct {
	Workspace      string              `json:"workspace"`
	Socket         string              `json:"socket"`
	AgentURL       string              `json:"agent_url"`
	AgentTokenFile string              `json:"agent_token_file"`
	Resources      map[string]resource `json:"resources"`
	Mailbox        string              `json:"mailbox,omitempty"`
}
type resource struct {
	SecretName   string   `json:"secret_name"`
	Upstream     string   `json:"upstream"`
	Methods      []string `json:"methods"`
	PathPrefixes []string `json:"path_prefixes"`
}
type message struct {
	Action   string `json:"action"`
	Command  string `json:"command,omitempty"`
	Workdir  string `json:"workdir,omitempty"`
	Job      string `json:"job,omitempty"`
	Resource string `json:"resource,omitempty"`
	Method   string `json:"method,omitempty"`
	Path     string `json:"path,omitempty"`
}
type reply struct {
	Job       string      `json:"job,omitempty"`
	Mailbox   *mailboxRef `json:"mailbox,omitempty"`
	Status    int         `json:"status,omitempty"`
	Output    string      `json:"output,omitempty"`
	Truncated bool        `json:"truncated,omitempty"`
	Error     string      `json:"error,omitempty"`
}
type job struct {
	command, workdir string
	created          time.Time
}
type broker struct {
	cfg            config
	configPath     string
	token          string
	mu             sync.Mutex
	jobs           map[string]job
	workers        chan struct{}
	connections    chan struct{}
	workspaceDir   *os.File
	mailboxRoot    *os.File
	mailboxPath    string
	ctx            context.Context
	mailboxParent  *os.File
	mailboxName    string
	mailboxContext context.Context
	mailboxCancel  context.CancelFunc
	mailboxWG      sync.WaitGroup
	mailboxClosing bool
	mailboxActive  int
	events         *brokerEvents
}

const (
	maxJobs        = 128
	maxWorkers     = 8
	maxConnections = 32
	jobTTL         = 10 * time.Minute
	outputLimit    = 1 << 20
)

func canonical(path string, existing bool) (string, error) {
	p, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if existing {
		return filepath.EvalSymlinks(p)
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(p))
	if err != nil {
		return "", err
	}
	return filepath.Join(parent, filepath.Base(p)), nil
}

func separated(root, path string) bool {
	return path != root && !strings.HasPrefix(path, root+string(os.PathSeparator))
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "tc-exec:", err)
		os.Exit(1)
	}
}
func run(args []string) error {
	if runtime.GOOS != "linux" {
		return errors.New("Linux/WSL only")
	}
	if len(args) == 0 {
		return errors.New("usage: tc-exec setup|serve|hook|dispatch|request")
	}
	switch args[0] {
	case "setup":
		return setup(args[1:])
	case "serve":
		return serve(args[1:])
	case "hook":
		return hook(args[1:])
	case "dispatch":
		return dispatch(args[1:])
	case "request":
		return request(args[1:])
	default:
		return errors.New("unknown command")
	}
}
func flags(name string) *flag.FlagSet {
	f := flag.NewFlagSet(name, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	return f
}
func load(path string) (config, error) {
	var c config
	b, e := os.ReadFile(path)
	if e != nil {
		return c, e
	}
	e = json.Unmarshal(b, &c)
	if e != nil {
		return c, e
	}
	c.Workspace, e = canonical(c.Workspace, true)
	if e != nil {
		return c, e
	}
	if c.Workspace == "/" || c.Socket == "" || c.AgentURL == "" || c.AgentTokenFile == "" {
		return c, errors.New("incomplete config")
	}
	for _, protected := range []struct {
		path     string
		existing bool
	}{{path, true}, {c.Socket, false}, {c.AgentTokenFile, true}} {
		p, er := canonical(protected.path, protected.existing)
		if er != nil {
			return c, er
		}
		if !separated(c.Workspace, p) {
			return c, errors.New("config, socket, and Agent Token file must be outside workspace")
		}
		if protected.path == c.Socket {
			c.Socket = p
		}
		if protected.path == c.AgentTokenFile {
			c.AgentTokenFile = p
		}
	}
	u, e := url.Parse(c.AgentURL)
	if e != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" && u.Hostname() != "::1") {
		return c, errors.New("agent_url must be local loopback HTTP(S)")
	}
	return c, nil
}
func setup(args []string) error {
	f := flags("setup")
	dir := f.String("dir", "", "profile directory")
	workspace := f.String("workspace", "", "workspace directory")
	agentURL := f.String("agent-url", "", "local TC Agent API URL")
	tokenFile := f.String("agent-token-file", "", "Operator-owned Agent Token file")
	secret := f.String("secret-name", "", "Secret Name")
	upstream := f.String("upstream", "", "Upstream name")
	resourceName := f.String("resource", "", "logical resource name")
	codexBinary := f.String("codex-binary", "", "absolute Linux Codex executable for the sandbox allowlist")
	codexSandbox := f.Bool("codex-sandbox", false, "generate network-off Codex read allowlist and FIFO dispatch")
	pathPrefix := f.String("path-prefix", "", "allowed GET path prefix")
	if e := f.Parse(args); e != nil {
		return e
	}
	if *dir == "" || *workspace == "" || *agentURL == "" || *tokenFile == "" || *secret == "" || *upstream == "" || *resourceName == "" || *pathPrefix == "" {
		return errors.New("setup needs --dir, --workspace, --agent-url, --agent-token-file, --secret-name, --upstream, --resource, --path-prefix")
	}
	if !strings.HasPrefix(*pathPrefix, "/") || strings.Contains(*pathPrefix, "..") || strings.ContainsAny(*pathPrefix, "?#") {
		return errors.New("invalid path prefix")
	}
	abs, e := filepath.Abs(*dir)
	if e != nil {
		return e
	}
	ws, e := canonical(*workspace, true)
	if e != nil {
		return e
	}
	profileParent, e := filepath.EvalSymlinks(filepath.Dir(abs))
	if e != nil {
		return e
	}
	abs = filepath.Join(profileParent, filepath.Base(abs))
	if !separated(ws, abs) {
		return errors.New("profile must be outside workspace")
	}
	protectedToken, e := canonical(*tokenFile, true)
	if e != nil {
		return e
	}
	if !separated(ws, protectedToken) {
		return errors.New("Agent Token file must be outside workspace")
	}
	if e = os.MkdirAll(abs, 0700); e != nil {
		return e
	}
	abs, e = canonical(abs, true)
	if e != nil {
		return e
	}
	if !separated(ws, abs) {
		return errors.New("profile must be outside workspace")
	}
	exe, e := os.Executable()
	if e != nil {
		return e
	}
	exe, e = filepath.EvalSymlinks(exe)
	if e != nil {
		return e
	}
	cfg := config{Workspace: ws, Socket: filepath.Join(abs, "broker.sock"), AgentURL: *agentURL, AgentTokenFile: protectedToken, Resources: map[string]resource{*resourceName: {SecretName: *secret, Upstream: *upstream, Methods: []string{"GET"}, PathPrefixes: []string{*pathPrefix}}}}
	if *codexSandbox {
		if !filepath.IsAbs(*codexBinary) {
			return errors.New("--codex-sandbox requires an absolute --codex-binary")
		}
		*codexBinary, e = canonical(*codexBinary, true)
		if e != nil {
			return e
		}
		cfg.Mailbox = filepath.Join(abs, "mailbox")
		if e = os.MkdirAll(cfg.Mailbox, 0700); e != nil {
			return e
		}
		for _, path := range []string{abs, cfg.Mailbox} {
			protectedDir, err := openDir(path)
			if err != nil {
				return err
			}
			protectedDir.Close()
		}
		if !separated(cfg.Mailbox, protectedToken) || protectedToken == exe || protectedToken == *codexBinary {
			return errors.New("Agent Token must be outside mailbox and executable paths")
		}
		info, err := os.Stat(*codexBinary)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
			return errors.New("--codex-binary must name an executable regular file")
		}
		if !separated(ws, exe) || !separated(ws, *codexBinary) {
			return errors.New("sandbox executables must be outside workspace")
		}
	}
	data, e := json.MarshalIndent(cfg, "", "  ")
	if e != nil {
		return e
	}
	data = append(data, '\n')
	hookData := []byte(fmt.Sprintf("{\"hooks\":{\"PreToolUse\":[{\"matcher\":\"^Bash$\",\"hooks\":[{\"type\":\"command\",\"command\":%q,\"timeout\":10}]}]}}\n", shellQuote(exe)+" hook --config "+shellQuote(filepath.Join(abs, "tc-exec.json"))))
	files := map[string][]byte{"tc-exec.json": data, "hooks.json": hookData}
	if *codexSandbox {
		files["config.toml"] = codexSandboxConfig(ws, cfg.Mailbox, exe, *codexBinary, protectedToken)
	}
	if e = publishProfile(abs, files); e != nil {
		return e
	}
	fmt.Println("Profile ready:", abs)
	fmt.Println("Start broker: ", exe, "serve --config", filepath.Join(abs, "tc-exec.json"))
	fmt.Println("Run Codex with CODEX_HOME=", abs, " and review/trust the hook as required by Codex. This bridge is experimental; see docs/integrations/codex-cli.md.")
	return nil
}
func serve(args []string) error {
	f := flags("serve")
	cfgPath := f.String("config", "", "")
	eventsPath := f.String("events-file", "", "new private file for metadata-only JSONL events")
	if e := f.Parse(args); e != nil {
		return e
	}
	c, e := load(*cfgPath)
	if e != nil {
		return e
	}
	if _, e = exec.LookPath("bwrap"); e != nil {
		return e
	}
	st, e := os.Stat(c.AgentTokenFile)
	if e != nil {
		return e
	}
	if st.Mode().Perm()&0077 != 0 {
		return errors.New("Agent Token file must have mode 0600 or stricter")
	}
	tb, e := os.ReadFile(c.AgentTokenFile)
	if e != nil {
		return e
	}
	token := strings.TrimSpace(string(tb))
	if token == "" {
		return errors.New("empty Agent Token file")
	}
	if e = os.MkdirAll(filepath.Dir(c.Socket), 0700); e != nil {
		return e
	}
	if _, e = os.Stat(c.Socket); e == nil {
		return errors.New("socket already exists; another broker may be running")
	}
	ln, e := net.Listen("unix", c.Socket)
	if e != nil {
		return e
	}
	defer os.Remove(c.Socket)
	defer ln.Close()
	if e = os.Chmod(c.Socket, 0600); e != nil {
		return e
	}
	validatedConfig, e := canonical(*cfgPath, true)
	if e != nil {
		return e
	}
	b := &broker{cfg: c, configPath: validatedConfig, token: token, jobs: make(map[string]job), workers: make(chan struct{}, maxWorkers), connections: make(chan struct{}, maxConnections)}
	if *eventsPath != "" {
		b.events, e = openBrokerEvents(*eventsPath)
		if e != nil {
			return e
		}
		defer b.events.file.Close()
	}
	b.workspaceDir, e = os.Open(c.Workspace)
	if e != nil {
		return e
	}
	defer b.workspaceDir.Close()
	openedPath, e := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", b.workspaceDir.Fd()))
	if e != nil || openedPath != c.Workspace {
		return errors.New("workspace changed during broker startup")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() { <-ctx.Done(); ln.Close() }()
	b.ctx = ctx
	if c.Mailbox != "" {
		if e = b.openMailbox(); e != nil {
			return e
		}
		defer b.closeMailbox()
	}
	go b.sweep(ctx)
	fmt.Println("tc-exec broker ready:", c.Socket)
	for {
		conn, er := ln.Accept()
		if er != nil {
			if ctx.Err() != nil {
				return nil
			}
			return er
		}
		select {
		case b.connections <- struct{}{}:
			go func() { defer func() { <-b.connections }(); b.handle(conn) }()
		default:
			conn.SetWriteDeadline(time.Now().Add(time.Second))
			json.NewEncoder(conn).Encode(reply{Error: "broker busy"})
			conn.Close()
		}
	}
}
func (b *broker) handle(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Minute))
	var m message
	if e := json.NewDecoder(io.LimitReader(conn, 1<<20)).Decode(&m); e != nil {
		json.NewEncoder(conn).Encode(reply{Error: "invalid request"})
		return
	}
	r := b.process(m)
	json.NewEncoder(conn).Encode(r)
}
func (b *broker) expire(now time.Time) {
	for id, j := range b.jobs {
		if now.Sub(j.created) > jobTTL {
			delete(b.jobs, id)
		}
	}
}
func (b *broker) sweep(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			b.mu.Lock()
			b.expire(now)
			b.mu.Unlock()
		}
	}
}
func (b *broker) process(m message) reply {
	ctx := b.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	return b.processContext(ctx, m)
}
func (b *broker) processContext(ctx context.Context, m message) reply {
	b.events.record("begin", m, reply{})
	r := b.processJobContext(ctx, m)
	b.events.record("end", m, r)
	return r
}
func (b *broker) processJobContext(ctx context.Context, m message) reply {
	switch m.Action {
	case "submit":
		if m.Command == "" || len(m.Command) > 1<<16 {
			return reply{Error: "invalid command"}
		}
		if !within(b.cfg.Workspace, m.Workdir) {
			return reply{Error: "workdir outside workspace"}
		}
		workdir, err := canonical(m.Workdir, true)
		if err != nil {
			return reply{Error: "invalid workdir"}
		}
		id := make([]byte, 24)
		if _, e := rand.Read(id); e != nil {
			return reply{Error: "random source unavailable"}
		}
		s := hex.EncodeToString(id)
		b.mu.Lock()
		b.expire(time.Now())
		if len(b.jobs) >= maxJobs || b.mailboxActive >= maxJobs {
			b.mu.Unlock()
			return reply{Error: "broker busy"}
		}
		b.jobs[s] = job{m.Command, workdir, time.Now()}
		if b.mailboxRoot != nil {
			ref, err := b.newMailboxJob(s)
			if err != nil {
				delete(b.jobs, s)
				b.mu.Unlock()
				return reply{Error: "cannot create job mailbox"}
			}
			b.mu.Unlock()
			return reply{Job: s, Mailbox: ref}
		}
		b.mu.Unlock()
		return reply{Job: s}
	case "dispatch":
		select {
		case b.workers <- struct{}{}:
			defer func() { <-b.workers }()
		default:
			return reply{Error: "broker busy"}
		}
		b.mu.Lock()
		j, ok := b.jobs[m.Job]
		delete(b.jobs, m.Job)
		b.mu.Unlock()
		if !ok || time.Since(j.created) > jobTTL {
			return reply{Error: "unknown or expired job"}
		}
		return b.shellContext(ctx, j)
	case "request":
		return b.httpRequest(m)
	default:
		return reply{Error: "unknown action"}
	}
}
func within(root, path string) bool {
	p, e := filepath.Abs(path)
	if e != nil {
		return false
	}
	r, e := filepath.EvalSymlinks(root)
	if e != nil {
		return false
	}
	p, e = filepath.EvalSymlinks(p)
	return e == nil && (p == r || strings.HasPrefix(p, r+string(os.PathSeparator)))
}
func (b *broker) shell(j job) reply { return b.shellContext(context.Background(), j) }
func (b *broker) shellContext(parent context.Context, j job) reply {
	rel, e := filepath.Rel(b.cfg.Workspace, j.workdir)
	if e != nil {
		return reply{Error: "invalid workdir"}
	}
	wd := filepath.Join("/workspace", rel)
	// Some unprivileged kernels refuse bubblewrap's network-namespace loopback
	// setup. A required seccomp filter denies network-capable socket families.
	// This experimental profile does not isolate host abstract Unix sockets.
	args := []string{"--unshare-all", "--share-net", "--die-with-parent", "--new-session", "--ro-bind", "/usr", "/usr", "--ro-bind", "/bin", "/bin", "--ro-bind", "/lib", "/lib"}
	if _, e = os.Stat("/lib64"); e == nil {
		args = append(args, "--ro-bind", "/lib64", "/lib64")
	}
	workspaceSource := b.cfg.Workspace
	if b.workspaceDir != nil {
		workspaceSource = "/proc/self/fd/3"
	}
	args = append(args, "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp", "--tmpfs", "/home", "--bind", workspaceSource, "/workspace")
	if b.configPath != "" {
		exe, err := os.Executable()
		if err != nil {
			return reply{Error: "cannot locate tc-exec binary"}
		}
		args = append(args, "--ro-bind", b.configPath, "/tc-exec.json", "--bind", b.cfg.Socket, "/tc-broker.sock", "--ro-bind", exe, "/tc-exec")
	}
	filter, err := networkSocketFilter()
	if err != nil {
		return reply{Error: "cannot create network filter"}
	}
	defer filter.Close()
	filterFD := 3
	if b.workspaceDir != nil {
		filterFD++
	}
	args = append(args, "--chdir", wd, "--setenv", "HOME", "/home", "--setenv", "PATH", "/usr/bin:/bin", "--setenv", "TC_EXEC_CONFIG", "/tc-exec.json", "--setenv", "TC_EXEC_SOCKET", "/tc-broker.sock", "--seccomp", fmt.Sprint(filterFD), "--", "/bin/bash", "--noprofile", "--norc", "-c", j.command)
	ctx, cancel := context.WithTimeout(parent, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bwrap", args...)
	if b.workspaceDir != nil {
		cmd.ExtraFiles = []*os.File{b.workspaceDir}
	}
	cmd.ExtraFiles = append(cmd.ExtraFiles, filter)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/home", "LANG=C.UTF-8"}
	out := &boundedOutput{}
	cmd.Stdout, cmd.Stderr = out, out
	e = cmd.Run()
	code := 0
	if e != nil {
		var ee *exec.ExitError
		if errors.As(e, &ee) {
			code = ee.ExitCode()
		} else {
			code = 1
		}
	}
	if ctx.Err() != nil {
		return reply{Status: 124, Error: "command timed out"}
	}
	return reply{Status: code, Output: out.String(), Truncated: out.truncated}
}

// networkSocketFilter permits only AF_UNIX sockets in the shell worker.
// The broker's HTTP client runs outside this filter. No Internet socket is
// inherited by the worker, and io_uring is denied to prevent asynchronous
// socket creation from bypassing this syscall policy.
func networkSocketFilter() (*os.File, error) {
	var arch uint32
	switch runtime.GOARCH {
	case "amd64":
		arch = unix.AUDIT_ARCH_X86_64
	case "arm64":
		arch = unix.AUDIT_ARCH_AARCH64
	default:
		return nil, errors.New("unsupported seccomp architecture")
	}
	load := uint16(unix.BPF_LD | unix.BPF_W | unix.BPF_ABS)
	jeq := uint16(unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K)
	jset := uint16(unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K)
	ret := uint16(unix.BPF_RET | unix.BPF_K)
	deny := uint32(unix.SECCOMP_RET_ERRNO | uint32(syscall.EPERM))
	filter := []unix.SockFilter{
		{Code: load, K: 4},          // seccomp_data.arch
		{Code: jeq, K: arch, Jt: 1}, // reject other ABIs
		{Code: ret, K: unix.SECCOMP_RET_KILL_PROCESS},
		{Code: load, K: 0},                 // seccomp_data.nr
		{Code: jset, K: 0x40000000, Jf: 1}, // reject x32 syscall ABI
		{Code: ret, K: unix.SECCOMP_RET_KILL_PROCESS},
		{Code: jeq, K: uint32(unix.SYS_SOCKET), Jt: 3},         // socket -> family check
		{Code: jeq, K: uint32(unix.SYS_SOCKETPAIR), Jt: 2},     // socketpair -> family check
		{Code: jeq, K: uint32(unix.SYS_IO_URING_SETUP), Jt: 3}, // io_uring -> deny
		{Code: ret, K: unix.SECCOMP_RET_ALLOW},
		{Code: load, K: 16},                         // seccomp_data.args[0] low word
		{Code: jeq, K: uint32(unix.AF_UNIX), Jt: 1}, // allow Unix sockets only
		{Code: ret, K: deny},
		{Code: ret, K: unix.SECCOMP_RET_ALLOW},
	}
	fd, err := unix.MemfdCreate("tc-exec-network-filter", 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "tc-exec-network-filter")
	if err = binary.Write(f, binary.LittleEndian, filter); err != nil {
		f.Close()
		return nil, err
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

type boundedOutput struct {
	buf       bytes.Buffer
	truncated bool
}

func (w *boundedOutput) Write(p []byte) (int, error) {
	n := len(p)
	written := 0
	if remaining := outputLimit - w.buf.Len(); remaining > 0 {
		if remaining > n {
			remaining = n
		}
		_, _ = w.buf.Write(p[:remaining])
		written = remaining
	}
	if written < n {
		w.truncated = true
	}
	return n, nil
}
func (w *boundedOutput) String() string { return w.buf.String() }
func (b *broker) httpRequest(m message) reply {
	r, ok := b.cfg.Resources[m.Resource]
	if !ok {
		return reply{Error: "unknown resource"}
	}
	allowed := false
	for _, method := range r.Methods {
		if m.Method == method {
			allowed = true
		}
	}
	if !allowed {
		return reply{Error: "method denied"}
	}
	u, e := url.ParseRequestURI(m.Path)
	if e != nil || !strings.HasPrefix(m.Path, "/") || u.IsAbs() || u.Fragment != "" || strings.Contains(m.Path, "..") {
		return reply{Error: "invalid path"}
	}
	allowed = false
	for _, p := range r.PathPrefixes {
		if p == "/" || u.Path == p || strings.HasPrefix(u.Path, strings.TrimSuffix(p, "/")+"/") {
			allowed = true
		}
	}
	if !allowed {
		return reply{Error: "path denied"}
	}
	base, e := url.Parse(b.cfg.AgentURL)
	if e != nil {
		return reply{Error: "invalid Agent API URL"}
	}
	basePath := strings.TrimSuffix(base.Path, "/")
	baseRawPath := strings.TrimSuffix(base.EscapedPath(), "/")
	base.Path = basePath + "/proxy/" + r.SecretName + "/" + r.Upstream + u.Path
	base.RawPath = baseRawPath + "/proxy/" + url.PathEscape(r.SecretName) + "/" + url.PathEscape(r.Upstream) + u.EscapedPath()
	base.RawQuery = u.RawQuery
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, e := http.NewRequestWithContext(ctx, m.Method, base.String(), nil)
	if e != nil {
		return reply{Error: "invalid request"}
	}
	req.Header.Set("X-TC-Agent-Token", b.token)
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, e := client.Do(req)
	if e != nil {
		return reply{Error: "TC request failed"}
	}
	defer resp.Body.Close()
	body, e := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if e != nil {
		return reply{Error: "response read failed"}
	}
	return reply{Status: resp.StatusCode, Output: string(body)}
}
func call(socket string, m message) (reply, error) {
	var r reply
	c, e := net.DialTimeout("unix", socket, 3*time.Second)
	if e != nil {
		return r, e
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Minute))
	if e = json.NewEncoder(c).Encode(m); e != nil {
		return r, e
	}
	e = json.NewDecoder(c).Decode(&r)
	return r, e
}
func hook(args []string) error {
	f := flags("hook")
	p := f.String("config", "", "")
	if e := f.Parse(args); e != nil {
		return e
	}
	c, e := load(*p)
	if e != nil {
		return e
	}
	var h struct {
		ToolName  string                     `json:"tool_name"`
		CWD       string                     `json:"cwd"`
		ToolInput map[string]json.RawMessage `json:"tool_input"`
	}
	if e = json.NewDecoder(io.LimitReader(os.Stdin, 1<<20)).Decode(&h); e != nil {
		return e
	}
	if h.ToolName != "Bash" {
		return errors.New("expected Bash")
	}
	var command, wd string
	if e = json.Unmarshal(h.ToolInput["command"], &command); e != nil {
		return errors.New("Bash command missing")
	}
	if raw := h.ToolInput["workdir"]; len(raw) > 0 {
		json.Unmarshal(raw, &wd)
	}
	if wd == "" {
		wd = h.CWD
	}
	if !filepath.IsAbs(wd) {
		wd = filepath.Join(h.CWD, wd)
	}
	r, e := call(c.Socket, message{Action: "submit", Command: command, Workdir: wd})
	if e != nil {
		return e
	}
	if r.Error != "" {
		return errors.New(r.Error)
	}
	exe, e := os.Executable()
	if e != nil {
		return e
	}
	dispatchCommand := shellQuote(exe) + " dispatch --config " + shellQuote(*p) + " --job " + shellQuote(r.Job)
	if r.Mailbox != nil {
		ref, err := json.Marshal(r.Mailbox)
		if err != nil {
			return err
		}
		dispatchCommand = shellQuote(exe) + " dispatch --mailbox " + shellQuote(string(ref)) + " --job " + shellQuote(r.Job)
	}
	replacement, e := json.Marshal(dispatchCommand)
	if e != nil {
		return e
	}
	h.ToolInput["command"] = replacement
	out := map[string]any{"hookSpecificOutput": map[string]any{"hookEventName": "PreToolUse", "permissionDecision": "allow", "updatedInput": h.ToolInput}}
	return json.NewEncoder(os.Stdout).Encode(out)
}
func dispatch(args []string) error {
	f := flags("dispatch")
	refJSON := f.String("mailbox", "", "broker-created FIFO reference")
	p := f.String("config", "", "")
	id := f.String("job", "", "")
	if e := f.Parse(args); e != nil {
		return e
	}
	var r reply
	var e error
	if *refJSON != "" {
		var ref mailboxRef
		if e = json.Unmarshal([]byte(*refJSON), &ref); e != nil {
			return errors.New("invalid mailbox reference")
		}
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		r, e = dispatchMailbox(ctx, ref, *id)
	} else {
		var c config
		c, e = load(*p)
		if e != nil {
			return e
		}
		r, e = call(c.Socket, message{Action: "dispatch", Job: *id})
	}
	if e != nil {
		return e
	}
	if r.Error != "" {
		return errors.New(r.Error)
	}
	fmt.Print(r.Output)
	if r.Truncated {
		fmt.Fprintln(os.Stderr, "\n[tc-exec output truncated at 1 MiB]")
	}
	if r.Status != 0 {
		os.Exit(r.Status)
	}
	return nil
}
func request(args []string) error {
	f := flags("request")
	p := f.String("config", os.Getenv("TC_EXEC_CONFIG"), "")
	res := f.String("resource", "", "")
	method := f.String("method", "GET", "")
	path := f.String("path", "", "")
	if e := f.Parse(args); e != nil {
		return e
	}
	socket := os.Getenv("TC_EXEC_SOCKET")
	if socket == "" {
		c, e := load(*p)
		if e != nil {
			return e
		}
		socket = c.Socket
	}
	r, e := call(socket, message{Action: "request", Resource: *res, Method: *method, Path: *path})
	if e != nil {
		return e
	}
	if r.Error != "" {
		return errors.New(r.Error)
	}
	fmt.Print(r.Output)
	if r.Status < 200 || r.Status >= 300 {
		return fmt.Errorf("HTTP %d", r.Status)
	}
	return nil
}
