# TrustedCourier

TrustedCourier is a self-hosted secrets broker for AI agents. An Agent calls one API, and TrustedCourier uses the Secret on the Agent's behalf, pulling it from whichever secret store the Operator runs. The goal is that an Agent can call OpenAI or GitHub with a real key without the key ever entering the model's context, its traces, or a prompt-injected tool call.

> **Status: early development.** Operator bootstrap and Agent Tokens work today. Secret Delivery, Backends, TLS, and audit do not exist yet. See [what works today](#what-works-today) and the [v1 spec](https://github.com/potto007/TrustedCourier/issues/1).

## Why

The usual way to give an Agent a Secret is an environment variable or a fetch from a secret store. Once the Agent holds the value, it can end up anywhere the Agent's text goes. Vault, OpenBao, AWS Secrets Manager, 1Password, and the rest solve storage. They don't solve safe use by an Agent, and each has its own API, so Agents end up coupled to whatever store the Operator happened to pick.

TrustedCourier sits between the Agent and the service it calls. In the default mode (Proxy Delivery), the Agent points its SDK's base URL at a TrustedCourier route and puts its Agent Token where the API key normally goes. TrustedCourier checks the token against its Policies, swaps in the real Secret, forwards the request to the pinned Upstream over verified TLS, and strips the Secret from the response. The Agent never sees the value. The planned v1 setup for an OpenAI Agent is two environment variables.

```sh
OPENAI_BASE_URL=https://tc.example.com/proxy/openai/v1   # route syntax not final
OPENAI_API_KEY=tcat_...                                  # an Agent Token, not the OpenAI key
```

Where a Policy explicitly allows it, Reveal Delivery returns the value itself, for things like database connections that can't be proxied.

## Design principles

These are settled and recorded as ADRs in [`docs/decisions/`](docs/decisions/README.md).

- **No Secrets or Courier Keys on TrustedCourier's disk** ([ADR-0001](docs/decisions/0001-no-secrets-or-courier-keys-on-disk.md)). Backends are the source of truth. Even TrustedCourier's own TLS key and audit signing key live in a Backend.
- **Delivery only** ([ADR-0002](docs/decisions/0002-v1-scope-is-delivery.md)). No encryption-as-a-service, no sync between Backends.
- **Backend Plugins run out of process** ([ADR-0004](docs/decisions/0004-out-of-process-backend-plugins.md)) through hashicorp/go-plugin, pinned by SHA-256, with their responses treated as untrusted input.
- **TLS everywhere, with built-in ACME** ([ADR-0006](docs/decisions/0006-tls-with-built-in-acme.md)).
- **Tamper-evident audit** ([ADR-0007](docs/decisions/0007-tamper-evident-audit.md)). Audit Records are hash-chained with signed checkpoints and never contain Secret values or bodies.
- **Batteries included** ([ADR-0008](docs/decisions/0008-bundled-openbao-static-seal.md)). `tc init` and one docker compose file will bring up TrustedCourier with a bundled OpenBao Backend.
- **All Go** ([ADR-0003](docs/decisions/0003-go-over-rust-core.md)), with FIPS 140-3 mode as a runtime switch.

[`CONTEXT.md`](CONTEXT.md) defines the vocabulary (Operator, Agent, Agent Token, Policy, Secret Name, Backend, Delivery, and so on). The code, docs, and issues use those terms exactly.

## What works today

| Area | State |
| --- | --- |
| `tc server run` with a YAML config | done |
| Operator Credential created at first boot, shown once | done |
| Admin API on a unix socket, gated by local user and Operator Credential | done |
| `tc token issue`, `list`, `revoke` | done |
| Policies declared and validated in config | done |
| Backend Plugin seam, OpenBao plugin | [#3](https://github.com/potto007/TrustedCourier/issues/3), [#18](https://github.com/potto007/TrustedCourier/issues/18) |
| Reveal Delivery, Proxy Delivery, Redaction | [#4](https://github.com/potto007/TrustedCourier/issues/4), [#5](https://github.com/potto007/TrustedCourier/issues/5), [#6](https://github.com/potto007/TrustedCourier/issues/6) |
| Audit Records and checkpoints | [#9](https://github.com/potto007/TrustedCourier/issues/9), [#10](https://github.com/potto007/TrustedCourier/issues/10) |
| TLS and ACME | [#13](https://github.com/potto007/TrustedCourier/issues/13), [#14](https://github.com/potto007/TrustedCourier/issues/14), [#15](https://github.com/potto007/TrustedCourier/issues/15) |
| `tc init` and docker compose | [#19](https://github.com/potto007/TrustedCourier/issues/19) |

An Agent Token can be issued, listed, and revoked, but nothing accepts one yet. Delivery comes next.

## Quickstart

You need Go 1.26.5 or newer, on Linux or macOS. The admin socket reads the connecting user's credentials from the kernel, and on other platforms it refuses every connection.

Build the CLI:

```sh
go build -o tc ./cmd/tc
```

Write a config file, say `trustedcourier.yaml`:

```yaml
data_dir: ./data
admin:
  socket: /run/user/1000/trustedcourier/admin.sock
policies:
  openai-proxy:
    secrets:
      - name: openai
        delivery: [proxy]
```

Start the server:

```sh
./tc server run --config trustedcourier.yaml
```

On first boot it prints the Operator Credential to stdout, once:

```
Operator Credential (shown once; store it now, it cannot be shown again):
tcoc_...
```

TrustedCourier stores only a hash of it, and `tc` has no command to reset it, so save it before you close the terminal. Logs go to stderr, so `2>server.log` keeps them apart.

In another shell, point `tc` at the socket and issue an Agent Token:

```sh
export TC_ADMIN_SOCKET=/run/user/1000/trustedcourier/admin.sock
export TC_OPERATOR_CREDENTIAL=tcoc_...

./tc token issue --policy openai-proxy --expires-in 30d
```

```
Agent Token (shown once; store it now, it cannot be shown again):
tcat_...

ID:        emqckmg73t6p2xaj
Policies:  openai-proxy
Expires:   2026-10-14T16:42:39Z
```

List and revoke:

```sh
./tc token list
./tc token revoke emqckmg73t6p2xaj
```

```
ID                POLICIES      EXPIRES               LAST USED  STATUS
emqckmg73t6p2xaj  openai-proxy  2026-10-14T16:42:39Z  never      revoked
```

`token issue` and `token list` take `--json` for scripting. Every Agent Token needs an expiry, given as `--expires-in` (a Go duration such as `12h`, or whole days such as `30d`) or `--expires-at` (RFC 3339). `--policy` repeats to attach several Policies, and an unknown Policy name is rejected.

Stop the server with Ctrl-C or SIGTERM.

## CLI

```
tc server run --config <path>
tc token issue --policy <name> [--policy <name>...] (--expires-in <lifetime> | --expires-at <RFC 3339>) [--json]
tc token list [--json]
tc token revoke <id>
```

| Variable | Meaning |
| --- | --- |
| `TC_ADMIN_SOCKET` | Admin socket path. Defaults to `/run/trustedcourier/admin.sock`. |
| `TC_OPERATOR_CREDENTIAL` | The Operator Credential. Every `token` command requires it. |

Exit codes are 0 for success, 1 for a failed operation, and 2 for a malformed command line.

## Configuration

The config is a single YAML document. Decoding is strict ([ADR-0010](docs/decisions/0010-yaml-config-strict-decoding.md)), so a misspelled key stops the server at startup instead of being silently ignored. Relative paths resolve against the config file's directory, not the working directory.

| Key | Required | Meaning |
| --- | --- | --- |
| `data_dir` | yes | Directory for the SQLite database. Created with mode 0700. |
| `admin.socket` | no | Admin socket path. Defaults to `/run/trustedcourier/admin.sock`. |
| `admin.allowed_uids` | no | Local user IDs allowed to connect to the socket. Defaults to the server's own user. An empty list is an error, since nobody could administer the server. |
| `policies` | no | Map of Policy name to Policy. |
| `policies.<name>.secrets` | yes | List of `{name, delivery}` entries, one per Secret Name. |
| `policies.<name>.secrets[].delivery` | yes | One or both of `proxy` and `reveal`. |

Policy names and Secret Names are 1 to 64 characters of letters, digits, `.`, `_`, and `-`, starting with a letter or digit. A Policy must list at least one Secret Name, and can list each only once.

Two things trip people up with the admin socket. The default `/run/trustedcourier/` usually needs root to create, so for a non-root server pick a path you own, such as one under `$XDG_RUNTIME_DIR`. And unix socket paths are limited to about 104 to 108 bytes depending on the OS, so a deeply nested path fails with `bind: invalid argument`.

## Security properties today

- The Operator Credential and Agent Tokens come from 32 random bytes. The database keeps only their SHA-256 hashes, and comparison is constant-time.
- Both are shown exactly once. If the first boot fails before the server is listening, the credential is not kept, and the next boot shows a fresh one.
- Credentials carry prefixes (`tcoc_` for the Operator Credential, `tcat_` for Agent Tokens) so secret scanners can spot a leak.
- The data directory is 0700 and the database files are 0600. The server tightens them again at every start, in case a backup restore loosened them.
- The admin socket checks the connecting process's UID against `admin.allowed_uids` before it looks at the Operator Credential. The socket file is owner-only unless other users are allowed.
- A second server pointed at a live socket refuses to start. A stale socket left by a crash is replaced.
- Revoking an Agent Token twice succeeds and keeps the first revocation time.

## Repository layout

The repository holds three Go modules. The plugin SDK is versioned on its own (`sdk/plugin/vX.Y.Z` tags), so a Backend Plugin never depends on the core.

| Path | Contents |
| --- | --- |
| `cmd/tc` | The `tc` binary. |
| `internal/access` | Operator Credential and Agent Token issue, verify, revoke. |
| `internal/admin` | Admin API server and client over the unix socket. |
| `internal/cli` | Command-line parsing and output. |
| `internal/config` | Config loading and validation. |
| `internal/server` | Wires config, database, and admin API into a running process. |
| `internal/store` | SQLite database and migrations, through pure-Go `modernc.org/sqlite` ([ADR-0009](docs/decisions/0009-pure-go-sqlite.md)). |
| `e2e` | Black-box tests that build `tc` and drive a real server through its config, socket, and CLI. |
| `sdk/plugin` | Plugin SDK module for Plugin Authors. A placeholder until [#3](https://github.com/potto007/TrustedCourier/issues/3). |
| `plugins/openbao` | OpenBao Backend Plugin module. A placeholder until [#18](https://github.com/potto007/TrustedCourier/issues/18). |

## Development

Run the checks CI runs, in each module (`.`, `sdk/plugin`, `plugins/openbao`):

```sh
test -z "$(gofmt -l .)"
go vet ./...
go test -race ./...
```

CI runs every module twice, once with `GODEBUG=fips140=off` and once with `fips140=on`. The race detector is required, not optional ([ADR-0003](docs/decisions/0003-go-over-rust-core.md) relies on it).

Tests go through the process, not internal types. The `e2e` harness builds `tc` (with `-race` when the tests run with it), starts it from a config file, and asserts only what an Operator or Agent could observe. New behavior should get a test there first.

Work is tracked in [GitHub Issues](https://github.com/potto007/TrustedCourier/issues), with the full v1 spec in [#1](https://github.com/potto007/TrustedCourier/issues/1). When you make or reverse an architecture decision, add an ADR to `docs/decisions/`. Accepted ADRs are never edited, only superseded.

## License

[Apache License 2.0](LICENSE).
