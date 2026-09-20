# Codex CLI tool execution bridge (experimental Linux/WSL prototype)

`tc-exec` lets a Codex CLI Bash hook send ordinary commands to a local broker. The broker runs those commands with `bubblewrap` in a workspace mount with an empty home, minimal environment, private process namespace, and a seccomp rule that denies Internet socket families. A registered HTTP read operation runs in the broker through **local TrustedCourier Proxy Delivery**. TrustedCourier can use a shared remote OpenBao Backend; no Backend or Operator credential goes into Codex.

This is a bounded prototype, **not an enforced Codex profile**. Codex's documented hook failure behavior can continue the original host tool call; other local tools, hosted tools, MCP servers, and the desktop app are not covered. Do not put host credentials or a TC Agent Token in Codex's environment or workspace. Use a separate unprivileged execution identity and OS controls before relying on this for mandatory mediation. In particular, Codex model/provider authentication remains Codex's own configuration and is outside this bridge.

## Verified Linux limitation

**The current socket dispatcher does not work inside the Linux Codex command sandbox.**
Model-driven runs with Linux Codex CLI 0.154.0 and 0.155.1 on WSL2 reached
`PreToolUse`, but the rewritten dispatcher could not connect to the broker and
no request reached TrustedCourier's synthetic Upstream. The command reported
`dial unix .../broker.sock: connect: operation not permitted` with network off,
or `socket: operation not permitted` with Codex's network proxy enabled.

Do not disable the sandbox or enable unrestricted command networking to work
around this failure. Adding a socket allow rule does not make a direct Unix
connection work on these versions. The [official network policy documentation](https://learn.chatgpt.com/docs/agent-approvals-security#network-policy)
describes proxy-mediated socket access; the implementation of both tested
releases restricts that feature to macOS. Linux requests carrying
`x-unix-socket` receive HTTP 501, `unix sockets unsupported`.

The exact [0.155.1 platform capability check](https://github.com/openai/codex/blob/rust-v0.155.1/codex-rs/network-proxy/src/runtime.rs#L1047)
and [0.154.0 sandbox regression](https://github.com/openai/codex/blob/rust-v0.154.0/codex-rs/linux-sandbox/tests/suite/managed_proxy.rs#L663)
show why accepted configuration is insufficient: Linux managed proxy mode
intentionally denies direct `AF_UNIX` socket creation. Moreover, TrustedCourier's
broker speaks newline-delimited JSON, not the HTTP protocol required by that
socket proxy.

These are compatibility failures, not successful integration tests. The broker
worker and its direct integration tests can succeed independently. A safe Linux
integration needs a supported narrow dispatch transport; it cannot be delivered
by changing only the network settings shown in the Codex documentation.

To reproduce the sandbox capability check without model calls or real credentials:

```sh
python3 scripts/diagnose-codex-sandbox.py \
  --codex /absolute/path/to/linux/codex \
  --out /absolute/path/to/new-evidence-directory
```

The probe starts synthetic broker, unrelated Unix, IPv4, and IPv6 listeners,
confirms they work from the host, then checks them through the actual Codex
sandbox. It also tests the proxy socket route and readability of a synthetic
Agent Token file outside the workspace. It records versions, binary hashes,
configuration, outcomes, and timestamped listener events. No Codex login or
model request is needed. A zero script exit means evidence collection completed;
inspect `summary.json` for the capability result. It does not test hooks,
interactive approvals, broker worker isolation, or full harness confinement.

In these runs, the outer `:workspace` profile could read the synthetic file.
That profile restricts writes but retains broad read access. The broker worker's
empty home and narrower mounts are a separate boundary; do not treat its tests
as proof that Codex itself cannot read an Operator's Agent Token file. Use a
separate execution identity and independently verified filesystem policy.

## Set up a disposable profile

On the Linux/WSL execution machine, install Go and `bubblewrap`, then build:

```sh
go build -o "$HOME/.local/bin/tc-exec" ./cmd/tc-exec
```

Use a local TC Agent API listener (`127.0.0.1` or `::1`) with a Secret Name pinned to an Upstream, a proxy-only Policy limited to GET and the desired path, and an Agent Token issued for that Policy. Store the Agent Token in an Operator-controlled file outside the workspace and profile, mode `0600`. This prototype reads the Agent Token into the broker process; it never sends it to ordinary shell jobs. The Operator should use a dedicated token for this one resource and revoke it when finished.

```sh
tc-exec setup \
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

`setup` creates only `tc-exec.json` and `hooks.json` in the named profile. It refuses to overwrite differing files, so rerunning the same command is safe. To uninstall, stop the broker and remove this dedicated profile directory after checking its contents. It never edits the normal `~/.codex` profile. The profile must be outside the workspace. The broker refuses a non-loopback TC URL and an Agent Token file with group or world permissions.

In another shell, run a **Linux Codex CLI** with the dedicated profile:

```sh
CODEX_HOME="$HOME/tc-codex-demo" codex -C "$HOME/src/my-project"
```

Log in to Codex inside this profile using Codex's normal flow. Review and trust the hook when Codex asks. No model provider or authentication setting is changed by `tc-exec`. Linux Codex CLI 0.154.0 and 0.155.1 have been exercised end to end with a synthetic Backend and TLS Upstream. Both invoked the hook but failed at sandbox-to-broker dispatch as described above. Successful Linux Codex execution remains unverified.

Ordinary Bash calls are rewritten to `tc-exec dispatch --job …`. The sandbox mounts only the broker socket and a non-secret copy of the profile config, so an ordinary Bash call can perform the registered read operation explicitly:

```sh
/tc-exec request --resource github-work --method GET \
  --path /repos/example/project/issues
```

`/tc-exec` is a read-only mount of the installed binary inside the shell worker. The request command talks to the local broker. The broker attaches the Agent Token to the local TC Proxy Delivery route; TC applies its Policy, injects the Secret for the pinned Upstream, redacts the response, and records the Delivery. This client currently supports response bodies up to 1 MiB and one-shot GET requests. It does not translate arbitrary `curl` or `gh` syntax.

## Boundary and current gaps

The local socket accepts requests from the OS identity that owns the socket and applies registered resource, method, and path rules independently of the hook. Other host processes with that same identity can also reach the socket and may be able to alter the profile or workspace; this prototype does not protect against a malicious same-UID host process. The random job reference is single-use and expires after ten minutes, allowing time for a human approval prompt. The broker caps pending jobs and concurrent workers, and expires abandoned jobs. The broker does not grant a raw Secret retrieval method. Direct calls to the socket have only the same registered operations.

The ordinary shell cannot create Internet sockets and has no access to host home or the Agent Token file. Bubblewrap shares the host network namespace because some unprivileged kernels refuse its loopback setup; the required seccomp filter permits only Unix sockets. The mounted broker socket remains accessible and applies policy independently of the hook. **Host abstract Unix sockets remain reachable** under this prototype, and privileged Unix sockets inside the workspace are also reachable. Run it only on a host without such endpoints exposed to the Agent's OS identity; a separate network namespace or stronger launcher is required to close this gap. Commands can use only files inside the mounted workspace and read-only system binaries/libraries. The broker resolves the workspace before validation and holds its directory open for each mount, so replacing its path after startup cannot redirect the mount. Anything sensitive already present *inside the workspace* remains accessible. Test commands requiring public network, package downloads, Docker, or host tools outside the mounted paths will fail. Child processes inherit the same filter. Each command starts a new Bash process with startup files disabled and has a two-minute limit. There is no PTY, stdin continuation, streaming output, or background job support; interactive `write_stdin` paths are therefore not supported. Output is bounded while it is collected to 1 MiB, stdout/stderr are combined, and the broker marks a truncated reply explicitly.

Codex's `PreToolUse` accepts a Bash argument rewrite with `permissionDecision: "allow"` and `updatedInput`; native Linux approval behavior for the original command remains unverified. The rewrite does **not** make hook failure fail closed. If the hook is missing, times out, or returns malformed JSON, Codex may run the original host command. Other tools can also execute outside this bridge. Thus the bridge shows a working TC HTTP use path and secret-free *brokered* shell, but cannot claim all Codex tool execution is mediated. An enforced release needs a launcher/runtime boundary that confines every tool worker and prevents a skipped hook or alternate tool from reaching host credentials or the protected service. It also needs cancellation and interactive session support, approval semantics, workload identity stronger than same-UID socket ownership, immutable Operator-owned installation, and a verified Linux Codex CLI matrix.

The wire protocol is intentionally harness-neutral: one JSON request per Unix socket connection, returning one JSON reply. `{ "action": "submit", "command": "…", "workdir": "…" }` returns a `job`, `dispatch` consumes that job and returns `status` and `output`, and `{ "action": "request", "resource": "…", "method": "GET", "path": "/…" }` invokes a registered protected operation. Adapters for other harnesses can translate their own hook payloads to these messages without reading an Operator Credential or Backend token.

Codex hook behavior described above follows the [official hook reference](https://developers.openai.com/codex/hooks#pretooluse). TrustedCourier's route and policy behavior is defined in [ADR-0005](../decisions/0005-proxy-delivery-by-base-url-route.md) and [ADR-0018](../decisions/0018-policy-method-and-path-limits.md).
