# Codex CLI tool execution bridge (experimental Linux/WSL profile)

`tc-exec` routes ordinary Codex Bash commands through a local broker. The broker
runs a confined worker and performs registered HTTP reads through TrustedCourier
Proxy Delivery. The worker receives neither the Agent Token nor the upstream
Secret. Codex provider authentication stays separate; this does not proxy model
traffic.

The optional `--codex-sandbox` setup uses **filesystem dispatch and a network-off
Codex command sandbox**. It denies filesystem reads by default, allowing only
the workspace, minimal runtime paths, two executable files, and the mailbox.
Keeping credentials outside the workspace alone is insufficient because the
standard Codex workspace profile permits broad reads.

This protects the tested command path, **not the whole harness**. Other tools,
connectors, browsers, the desktop app, Codex itself, and malicious unsandboxed
processes sharing the OS identity are outside this boundary. Hook failure may
let Codex execute the original command; the independent command sandbox remains
necessary. Native interactive approval behavior is unverified.

## Disposable setup

Use Linux Codex CLI, Go, and `bubblewrap` on the Linux/WSL machine. Install both
executables outside the workspace:

```sh
go build -o "$HOME/.local/bin/tc-exec" ./cmd/tc-exec
```

Configure a local TC Agent API, a Secret Name pinned to an Upstream, and a
proxy-only Policy limited to GET and the intended path. Keep its private Agent
Token file, TC configuration, Backend credentials, and Operator configuration
outside all allowed workspace, runtime, and mailbox paths. The broker reads the
Agent Token; the sandbox dispatcher never loads it or the broker configuration.

```sh
tc-exec setup \
  --codex-sandbox \
  --codex-binary /absolute/path/to/linux/codex \
  --dir "$HOME/tc-codex-demo" \
  --workspace "$HOME/src/my-project" \
  --agent-url http://127.0.0.1:8200 \
  --agent-token-file "$HOME/tc-agent-token" \
  --resource github-work \
  --secret-name github-work \
  --upstream api \
  --path-prefix /repos/example/project/issues

tc-exec serve --config "$HOME/tc-codex-demo/tc-exec.json"
```

Setup creates private `tc-exec.json`, `hooks.json`, `config.toml`, and a mailbox
directory. It refuses differing existing files and symlink or publicly
accessible mailbox directories. It never edits the normal `~/.codex` profile.
Without `--codex-sandbox`, setup retains the Unix-socket configuration used by
other adapters, including Claude Code.

In another shell, authenticate using Codex's normal login flow inside the
dedicated `CODEX_HOME`, then start the same executable:

```sh
CODEX_HOME="$HOME/tc-codex-demo" /absolute/path/to/linux/codex --strict-config \
  -C "$HOME/src/my-project"
```

Review and trust the hook when prompted. The generated `default_permissions`
selects `trustedcourier`. Do not replace it with a legacy `--sandbox` option,
add unrelated writable roots, or disable the sandbox. Executable paths are
exact; regenerate a fresh profile when an installation moves. Generated shape:

```toml
default_permissions = "trustedcourier"

[permissions.trustedcourier.filesystem]
":root" = "deny"
":minimal" = "read"
"/absolute/profile" = "deny"
"/absolute/agent-token" = "deny"
"/absolute/workspace" = "write"
"/absolute/profile/mailbox" = "write"
"/absolute/tc-exec" = "read"
"/absolute/codex" = "read"

[permissions.trustedcourier.network]
enabled = false
```

Policy, hooks, broker configuration, and Agent Token stay outside the command
allowlist. Put no credentials in allowed paths. Codex's host process still uses
its own provider login; this profile does not disable that connection.

## Dispatch and protected operations

The host-side hook submits a command over the existing broker socket. The broker
keeps command and working directory in memory and atomically publishes two
private FIFOs in a fresh session directory. The hook rewrites Bash to
`tc-exec dispatch --mailbox ... --job ...`. The sandbox dispatcher sends only
a start signal; changing a file cannot replace the stored command.

A random 192-bit job identifier and device/inode identities bind the reference.
Opens reject traversal, symlinks, wrong owners, public permissions, non-FIFOs,
and replaced endpoints. The broker pins directory/FIFO descriptors and consumes
each job once. Pending jobs expire after ten minutes; admission and worker
concurrency are bounded. Command output is capped at 1 MiB. Closing the request
pipe cancels and reaps a running worker, including when the dispatcher is killed.
Workers also have a two-minute limit.

Restart creates a fresh session; old references cannot replay jobs. Graceful
shutdown removes its empty session directory. Crashes can leave inert FIFOs.
Stop the broker before inspecting and removing the dedicated profile. Cleanup
never recursively follows Agent-created paths. Mailbox mutations can deny
service but cannot replace the command in memory.

Inside the worker, `/tc-exec` and the Unix broker socket remain mounted:

```sh
/tc-exec request --resource github-work --method GET \
  --path /repos/example/project/issues
```

The broker attaches its Agent Token. TC checks its Policy, injects the Secret,
redacts the response, and records the Delivery. The broker independently checks
its resource/method/path registration. Arbitrary `curl` and `gh` commands are
not translated. Only one-shot GET responses up to 1 MiB are supported.

`serve --events-file /private/new-events.jsonl` creates an optional new mode-0600
diagnostic file, refusing an existing path. Timestamped records contain actions,
job identifiers, statuses, and outcome flags, never commands, request paths,
bodies, or credentials. They supplement TC Audit Records; they are not an
authorization mechanism or durable audit guarantee.

## Verification and remaining scope

Actual model-driven Linux Codex CLI 0.154.0 and 0.155.1 tests used a synthetic Backend, real
TC, and TLS Upstream. Hook, FIFO dispatch, worker, authenticated Proxy Delivery,
and response completed. Forbidden paths and methods were denied. Outer probes
could not read Agent Token, synthetic Backend/Operator credentials, broker
config, TC config, or Codex policy, including workspace symlink and
`/proc/<broker>/root` aliases. Unrelated Unix and direct IPv4/IPv6 host listeners
were unreachable; host controls proved they were live. Worker probes separately
verified credential absence and denied Internet socket creation.

A separately authorized disposable run used
`--dangerously-bypass-approvals-and-sandbox`. Delivery worked, but outer commands
could read protected synthetic files and reach all listeners. The worker stayed
confined. This is functionality evidence without the outer boundary, not proof
of sandbox or approval enforcement.

```sh
go test -race ./cmd/tc-exec ./cmd/tc-claude-hook
go test -race -run 'TestTCExecAuthenticatedReadThroughProxyDelivery|TestClaude' ./e2e
TC_CODEX_BINARY=/absolute/path/to/linux/codex \
  go test -race -count=1 -run TestTCExecAuthenticatedReadThroughProxyDelivery ./e2e
```

The last command also tests the rewritten dispatcher and protected-file checks
in the actual Codex sandbox without login or model calls. Interactive approvals,
background jobs, PTYs, stdin continuation, streaming, and full harness confinement
remain unverified or unsupported. The hook's `permissionDecision: "allow"`
rewrite is not a fail-closed approval mechanism.

The worker has an empty home, minimal environment, private process namespace,
read-only runtime binaries, workspace mount, and seccomp denial of Internet
socket families. It shares the host network namespace because some unprivileged
kernels refuse loopback setup. **Host abstract Unix sockets and sockets already
in the workspace remain a worker limitation.** Use a separate identity and
stronger OS boundary for mandatory mediation. Contents already in the workspace,
including hard-linked credentials, are accessible; do not put sensitive data there.

## Original socket incompatibility

Linux Codex 0.154.0 and 0.155.1 reject the legacy direct Unix dispatcher. Managed
proxy mode denies direct `AF_UNIX` creation. Their Unix proxy is
[macOS-only](https://github.com/openai/codex/blob/rust-v0.155.1/codex-rs/network-proxy/src/runtime.rs#L1047),
and Linux forwarding returned HTTP 501. The broker's newline-delimited JSON
also differs from that HTTP proxy protocol. No unrestricted network exception
was used to solve this incompatibility.

The original `scripts/diagnose-codex-sandbox.py --codex /absolute/path/to/codex
--out /new/evidence-directory` checks that legacy policy, not the new FIFO
profile. Its zero exit means collection completed; inspect its outcomes.
Failed baseline evidence stays separate from successful filesystem dispatch.

See [ADR-0031](../decisions/0031-fifo-dispatch-and-codex-read-allowlist.md), the
[official permission reference](https://learn.chatgpt.com/docs/permissions),
[hook reference](https://developers.openai.com/codex/hooks#pretooluse),
[ADR-0005](../decisions/0005-proxy-delivery-by-base-url-route.md), and
[ADR-0018](../decisions/0018-policy-method-and-path-limits.md).
