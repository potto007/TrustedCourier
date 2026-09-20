---
status: proposed
date: 2026-09-20
---

# FIFO dispatch and a Codex read allowlist preserve the command sandbox

## Context and Problem Statement

Linux Codex CLI 0.154.0 and 0.155.1 invoke the TrustedCourier Bash hook but reject
the rewritten dispatcher's direct Unix socket connection. Their Unix proxy
feature is macOS-only. Disabling the sandbox or enabling unrestricted networking
would remove the intended outer boundary. Standard workspace-write permissions
also allow reading a same-identity Agent Token file outside the workspace.

## Decision Outcome

Proposed: opt-in FIFO dispatch with a generated named Codex permission profile.
The default socket protocol remains compatible with Claude Code and existing
profiles. The new profile denies networking and filesystem reads by default,
granting only minimal runtime reads, workspace and mailbox writes, and reads of
the installed Codex and tc-exec executables. Broker, Backend, Operator, and Agent
Token files must stay outside those allowed paths. Sandboxed shell commands inherit no
host environment variables; only explicit runtime values are set. The bounded YOLO comparison retained an inherited synthetic credential marker, so that mode has no such verified boundary. Codex provider
authentication remains in its separate host process.

The host hook submits a bounded command over the existing socket. The broker
retains it in memory, creates a random 192-bit job reference, and atomically
publishes private request/response FIFOs in a fresh session directory. The
dispatcher receives path, device, and inode identities. It sends only a start
byte, never a command payload. Opens require canonical paths, no-follow
endpoints, expected type, ownership, permissions, and identity. The broker pins
its directory and FIFO descriptors. Path replacement can deny service but cannot
replace the stored command or redirect broker writes to arbitrary files.

Jobs retain admission limits, ten-minute pending expiry, single consumption,
eight concurrent workers, a two-minute execution limit, and bounded output.
The request writer stays open during dispatch: close or cancellation cancels
the worker. Shutdown stops admission and reaps mailbox workers before closing
descriptors. Restart creates a new session and never reloads jobs from disk.
Cleanup removes only known endpoints and empty owned directories; it never
recursively traverses unexpected replacements or contents.

## Consequences

* Actual model-driven commands can use TC while outer networking stays off.
  Read denial independently protects host credentials from the tested outer
  command path, including a skipped hook.
* Credential values and command payloads never enter persistent mailbox files.
  The existing worker and Proxy Delivery Policy remain independent checks.
* Same-identity malicious unsandboxed processes remain outside the boundary.
  Mailbox mutation can deny service. Crashes can leave inert FIFO directories.
* Exact executable paths need review when an installation moves. This profile
  does not confine every Codex capability or protect secrets in allowed paths.
  A separate OS identity remains preferable for mandatory workload isolation.
* Interactive approval semantics remain unverified; hook rewriting is not
  fail-closed. Worker abstract Unix and workspace sockets remain a limitation.
  PTYs, streaming, background execution, and continuation are unsupported.

Unrestricted networking and disabling the sandbox were rejected. A TCP bridge
would require additional network policy; waiting for upstream Linux socket
support would leave the integration unusable. The integration guide contains
reproduction and separate sandbox/unsandboxed evidence. An unsandboxed success
is never accepted as isolation proof. This ADR awaits human review.
