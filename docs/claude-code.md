# Claude Code development adapter

This repository contains a public, experimental Claude Code CLI plugin and a `tc-claude-hook` adapter for Linux and WSL2. The hook translates documented `PreToolUse` Bash input into a `tc-exec` broker job, then replaces the Bash command with a dispatch command. It retains the other Bash fields and does not return a permission approval. The broker handles named HTTP requests through TrustedCourier Proxy Delivery when an Operator has separately enrolled a resource and Agent Token.

**This is routing, not a protected Claude profile.** Claude Code hooks can fail open. The current broker confines jobs it receives, but no launcher confines the entire Claude Code process. A missing, disabled, malformed, or timed-out hook may let Bash run on the host; file tools, MCP servers, subagents, and computer tools do not pass through this hook. The adapter denies requested background Bash jobs; interactive PTY/stdin continuation is not implemented. Do not use this development adapter as the boundary that keeps Secrets away from arbitrary agent tool code.

## Build and inspect locally

From this checkout on Linux or WSL2:

```sh
go build -o /absolute/path/to/tc-claude-hook ./cmd/tc-claude-hook
go build -o /absolute/path/to/tc-exec ./cmd/tc-exec
claude plugin validate .
claude plugin validate ./plugins/claude-trustedcourier
```

`claude plugin validate` requires an installed Claude Code CLI. The plugin is a development source bundle and does not contain signed platform binaries. Build instructions do not install or change a host service. The runtime profile and broker service must be configured and started by the Operator according to the `tc-exec` documentation. The profile contains a workspace, Unix socket, Agent API URL, a path to an Agent Token file, and registered resources. Keep the Agent Token file inaccessible to arbitrary tool code. This plugin never reads it.

For a local plugin trial, add this checkout as a marketplace and install the plugin:

```sh
claude plugin marketplace add /absolute/path/to/TrustedCourier
claude plugin install trustedcourier@trustedcourier
```

The hook requires these environment variables in the Claude Code process:

| Variable | Value |
| --- | --- |
| `TC_EXEC_CONFIG` | Absolute path to the broker profile JSON |
| `TC_EXEC_BINARY` | Absolute path to `tc-exec` |
| `TC_CLAUDE_HOOK_BINARY` | Absolute path to `tc-claude-hook` |

The plugin hook path resolves from `${CLAUDE_PLUGIN_ROOT}`. It submits `{ "action": "submit", "command": "...", "workdir": "..." }` over the profile's Unix socket, receives a job identifier, and rewrites Bash to `tc-exec dispatch --config ... --job ...`. The broker must validate the workspace and job ownership independently; hook output does not confer authority. Named requests use `tc-exec request --config ... --resource NAME --method GET --path /allowed/path`. Do not assume an arbitrary `curl` or `gh` call gains credentials.

The `/trustedcourier:setup` skill checks prerequisites and points the Operator to the manual profile setup. The `/trustedcourier:use` skill describes named requests. Neither skill performs Backend enrollment, issues an Agent Token, or changes Claude model authentication. For an existing shared OpenBao, do not run `tc init` against the initialized Backend; that path requires separate Operator enrollment work. Starter local OpenBao follows the existing documented `tc init` flow and shows one-time material directly to the Operator.

Remove the plugin through Claude Code's `claude plugin uninstall trustedcourier@trustedcourier` command. Broker/service cleanup and Agent Token revocation are separate Operator actions. This development version has no automatic upgrade, rollback, or uninstall of TC state.
