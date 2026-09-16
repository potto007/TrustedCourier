# TrustedCourier

TrustedCourier is a self-hosted secrets broker for AI agents. An Agent calls one API, and TrustedCourier uses the Secret on the Agent's behalf, pulling it from whichever secret store the Operator runs. The goal is that an Agent can call OpenAI or GitHub with a real key without the key ever entering the model's context, its traces, or a prompt-injected tool call.

> **Status: early development.** Operator bootstrap, Agent Tokens, the Backend Plugin seam, Proxy and Reveal Delivery over TLS with Operator-supplied or ACME certificates, Redaction, and hash-chained Audit Records under signed checkpoints work today. A real Backend does not exist yet. See [what works today](#what-works-today) and the [v1 spec](https://github.com/potto007/TrustedCourier/issues/1).

## Why

The usual way to give an Agent a Secret is an environment variable or a fetch from a secret store. Once the Agent holds the value, it can end up anywhere the Agent's text goes. Vault, OpenBao, AWS Secrets Manager, 1Password, and the rest solve storage. They don't solve safe use by an Agent, and each has its own API, so Agents end up coupled to whatever store the Operator happened to pick.

TrustedCourier sits between the Agent and the service it calls. In the default mode (Proxy Delivery), the Agent points its SDK's base URL at a TrustedCourier route and puts its Agent Token where the API key normally goes. TrustedCourier checks the token against its Policies, swaps in the real Secret, forwards the request to the pinned Upstream over verified TLS, and strips the Secret from the response. The Agent never sees the value. The planned v1 setup for an OpenAI Agent is two environment variables.

```sh
OPENAI_BASE_URL=https://tc.example.com/proxy/openai/api  # Secret Name, then Upstream name
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
- **All Go** ([ADR-0003](docs/decisions/0003-go-over-rust-core.md)), with FIPS 140-3 mode as a runtime switch that every Backend Plugin must follow ([ADR-0027](docs/decisions/0027-fips-mode-plugin-parity-and-process-hardening.md)).

[`CONTEXT.md`](CONTEXT.md) defines the vocabulary (Operator, Agent, Agent Token, Policy, Secret Name, Backend, Delivery, and so on). The code, docs, and issues use those terms exactly.

## What works today

| Area | State |
| --- | --- |
| `tc server run` with a YAML config | done |
| Operator Credential created at first boot, shown once | done |
| Admin API on a unix socket, gated by local user and Operator Credential | done |
| `tc token issue`, `list`, `revoke` | done |
| Policies declared and validated in config | done |
| `tc reload` for Policies, Secret Names, and Upstreams | done |
| Backend Plugins pinned by SHA-256, run as a separate user, supervised | done |
| `tc status`, `tc plugin sha256` | done |
| Plugin SDK and conformance kit skeleton | done |
| Secret Names mapped to Backend locations in config | done |
| Reveal Delivery on a loopback Agent API | done |
| TLS on the Agent API with Operator-supplied certificates, Agent API on a unix socket | done |
| Proxy Delivery with header, query, and basic auth Injection Templates, OpenAPI spec for the Agent API | done |
| Presets for OpenAI, Anthropic, and GitHub, `tc env` | done |
| Redaction | done |
| OpenBao Backend Plugin, full conformance kit | [#18](https://github.com/potto007/TrustedCourier/issues/18) |
| Method and path limits in Policies | done |
| Hash-chained Audit Records, `tc audit verify` | done |
| Signed audit checkpoints | done |
| ACME with TLS-ALPN-01 and HTTP-01, certificates as Courier Keys | done |
| ACME DNS-01 with built-in DNS providers | done |
| Remote admin listener with mutual TLS | done |
| `tc init` and docker compose | [#19](https://github.com/potto007/TrustedCourier/issues/19) |

An Agent can call a pinned Upstream through TrustedCourier with its Agent Token in place of the API key, over TLS with an Operator-supplied or ACME certificate or plain HTTP on loopback or a unix socket, and can ask for a Secret by Secret Name where a Policy allows Reveal Delivery. The only Backend Plugin so far is the fake one the tests use, so a real deployment waits on [#18](https://github.com/potto007/TrustedCourier/issues/18).

## Quickstart

You need Go 1.26.5 or newer, on Linux or macOS. The admin socket reads the connecting user's credentials from the kernel, and on other platforms it refuses every connection.

Build the CLI, and the fake Backend Plugin the tests use. It stands in until the OpenBao Backend Plugin lands ([#18](https://github.com/potto007/TrustedCourier/issues/18)) and holds made-up Secrets at `kv/openai` and `kv/github`.

```sh
go build -o tc ./cmd/tc
go -C sdk/plugin build -o ../../fakebackend ./internal/fakebackend
./tc plugin sha256 fakebackend
```

Write a config file, say `trustedcourier.yaml`, with the hash `tc` printed:

```yaml
data_dir: ./data
admin:
  socket: /run/user/1000/trustedcourier/admin.sock
backend_plugins:
  fake:
    path: ./fakebackend
    sha256: <the hash tc printed>
    insecure_share_core_user: true
secrets:
  openai:
    backend: fake
    location: kv/openai
    injection_template:
      header:
        name: Authorization
        value: Bearer {secret}
    upstreams:
      api:
        url: https://api.openai.com/v1
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

TrustedCourier stores only a hash of it, and `tc` has no command to reset it, so save it before you close the terminal. Logs go to stderr, so `2>server.log` keeps them apart. After that, stdout carries only [Audit Records](#audit).

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

### Backend Plugins

A Backend Plugin is a separate binary. Pin it by hash:

```sh
./tc plugin sha256 /opt/trustedcourier/plugins/openbao
```

```
sha256: 3f7a...
```

Paste that line into the config with the binary's path and the OS user it runs as:

```yaml
backend_plugins:
  openbao:
    path: /opt/trustedcourier/plugins/openbao
    sha256: 3f7a...
    user: trustedcourier-plugin
```

The plugin user must differ from the server's user and must not be able to read the config file, so a server that runs plugins starts as root. For development, `insecure_share_core_user: true` in place of `user` runs the plugin as the server's own user and logs a warning.

`tc status` shows the server's [FIPS 140-3 mode](#fips-140-3-mode), each plugin's state, health, and capabilities, whether the [audit signing key](#audit) is loaded, and, when the Agent API serves TLS, whether its [certificate](#tls-on-the-agent-api) is:

```
FIPS 140-3 mode: on (module v1.0.0)

BACKEND PLUGIN  STATE    HEALTH   CAPABILITIES       RESTARTS  DETAIL
openbao         running  healthy  courier-key-write  0         ...

Audit signing key: loaded
TLS certificate: loaded (expires 2026-12-14T00:00:00Z, renews 2026-11-14T00:00:00Z)
```

`tc status --json` also reports, per plugin, whether it runs in FIPS mode.

### FIPS 140-3 mode

TrustedCourier uses Go's cryptographic module, so FIPS 140-3 mode is a runtime switch on the standard binary ([ADR-0003](docs/decisions/0003-go-over-rust-core.md)): set `GODEBUG=fips140=on` in the server's environment, or `GODEBUG=fips140=only` to make any use of a non-approved algorithm a panic rather than a fallback. Release and CI binaries are built with `GOFIPS140=certified`, which links the validated module and turns the mode on by default; `GODEBUG=fips140=off` turns it off. A plain `go build` links the in-tree copy of the module, reported as module `latest`, which is the same code without the validation. `tc status` shows both the mode and the module.

Every process that touches Secrets is inside the boundary ([ADR-0027](docs/decisions/0027-fips-mode-plugin-parity-and-process-hardening.md)). The server passes its `GODEBUG` to each Backend Plugin, a plugin built on the SDK reports its mode right after the handshake, and a server in FIPS mode refuses to run a plugin that does not report FIPS mode: the plugin stays down, `tc status` shows why, and the other plugins keep serving. The [conformance kit](#repository-layout) checks a plugin follows the kit's mode.

### Proxy Delivery

Pin a Secret Name to its Upstreams, say where the Secret goes with an Injection Template, let a Policy proxy it, and turn on the Agent API with the key that signs its [audit trail](#audit):

```yaml
agent_api:
  listen: 127.0.0.1:8200
audit:
  signing_key:
    backend: openbao
    location: secret/data/trustedcourier#audit-signing-key
secrets:
  openai:
    backend: openbao
    location: secret/data/openai#key
    injection_template:
      header:
        name: Authorization
        value: Bearer {secret}
    upstreams:
      api:
        url: https://api.openai.com/v1
policies:
  openai-proxy:
    secrets:
      - name: openai
        delivery: [proxy]
```

Issue an Agent Token with that Policy and give it to the Agent in place of the API key:

```sh
OPENAI_BASE_URL=http://127.0.0.1:8200/proxy/openai/api
OPENAI_API_KEY=tcat_...
```

The route is `/proxy/<Secret Name>/<Upstream name>`. The rest of the path is appended to the Upstream's URL, so `/proxy/openai/api/chat/completions` goes to `https://api.openai.com/v1/chat/completions`, and the query goes along unchanged, except that parameters Go cannot parse, such as ones separated by `;`, are dropped. A Secret Name pinned to several Upstreams has one route for each.

TrustedCourier finds the Agent Token where the Injection Template would put the Secret (here `Authorization: Bearer tcat_...`) or in `X-TC-Agent-Token`, never in the URL. It fetches the Secret from the Backend, puts it in the header, removes the Agent Token, and forwards the request. The Agent never sees the Secret, and the Upstream never sees the Agent Token.

- Upstream URLs must be `https`, and TLS is always verified. There is no setting to skip it. For an internal CA, set `ca_bundle` on the Upstream to a PEM file; it replaces the system roots for that Upstream only.
- Redirects are never followed. The 3xx and its `Location` reach the Agent unchanged, so the Secret is never re-sent to another host.
- HTTP/1.1 and HTTP/2 both work, to the Agent API (HTTP/2 by ALPN over TLS, or with prior knowledge on a plain HTTP listener) and to the Upstream. Server-sent event streams pass through as they arrive.
- WebSockets and other protocol upgrades are refused. An `h2c` offer, as `curl --http2` sends, is answered over HTTP/1.1.
- A response may stream for as long as the Upstream keeps sending, pauses included. The Delivery ends when neither the Upstream's response nor the Agent's request body moves for 5 minutes, or when a write to the Agent is stuck for 30 seconds. A Delivery cut off mid-response is logged as such.
- Redaction: an Upstream that echoes the Secret back, as some do in a 401 body, sends the Agent a run of `*` of the same length instead, in headers, body, and trailers. Only exact matches are caught, not a base64 or escaped copy. A stream is held back only by trailing bytes that could begin the Secret.
- So Redaction can read every response, TrustedCourier asks the Upstream for gzip in place of the Agent's `Accept-Encoding` and does not forward `Range` or `If-Range`. A gzip response arrives decoded; any other or repeated `Content-Encoding` gets 502.

| Status | When |
| --- | --- |
| Upstream's | The request reached the Upstream. Its response comes back with `Cache-Control: no-store`. |
| 400 | The path contains a dot segment (`..`, `%2e%2e`, `..;`), or the request asks for a protocol upgrade. |
| 401 | The Agent Token is missing, presented twice, unknown, expired, or revoked. |
| 403 | Anything else, including an unknown Upstream name or a method or path the Policy does not allow. The body is the same as Reveal Delivery's 403. |
| 502 | The Backend could not return the Secret, the Upstream could not be reached or its certificate did not verify, or its response has a `Content-Encoding` Redaction cannot read. Details go to the server log only. |
| 503 | The server has no locked memory left to hold the Secret, has not loaded the audit signing key yet, or cannot store Audit Records. |
| 504 | Neither the Upstream's response nor the Agent's request body moved for 5 minutes before the response started. |

The Agent API is described by an OpenAPI 3.1 spec in [`docs/api/agent-api.openapi.yaml`](docs/api/agent-api.openapi.yaml). Routes, credential slots, and Upstream trust are recorded in [ADR-0013](docs/decisions/0013-proxy-delivery-routes-slots-and-upstream-trust.md), and Redaction in [ADR-0014](docs/decisions/0014-redaction-masks-in-place.md).

#### Method and path limits

A Policy entry can limit Proxy Delivery to some HTTP methods and path prefixes, so an Agent with a GitHub Secret can read issues but cannot delete a repository:

```yaml
policies:
  github-issues:
    secrets:
      - name: github
        delivery: [proxy]
        methods: [GET, HEAD]
        paths: [/repos/acme/app/issues, /user]
```

- `methods` lists any of `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`, and `OPTIONS`, in any case. Requests must use the uppercase method. `GET` does not imply `HEAD`.
- `paths` match the path after `/proxy/<Secret Name>/<Upstream name>`, not the Upstream URL's own path, so the same Policy works for GitHub Enterprise Server at `/api/v3`. A prefix matches whole segments after percent-decoding: `/repos/acme/app/issues` allows `/repos/acme/app/issues` and `/repos/acme/app/issues/7`, not `/repos/acme/app/issuesx`, and `/%72epos/...` counts as `/repos/...`. A path with an encoded slash, a `;` parameter, an empty segment, or invalid UTF-8 inside the prefix's segments does not match. Dot segments still get 400.
- One entry must allow both the method and the path. Among an Agent Token's Policies, any entry that allows the request is enough, and an entry without `methods` or `paths` allows any method or path.
- Everything else gets the same 403 as every other denial and never reaches the Upstream. The Audit Record's reason is `no Policy allows the method` or `no Policy allows the path`.

Recorded in [ADR-0018](docs/decisions/0018-policy-method-and-path-limits.md).

#### Injection Templates

An Injection Template is one of three kinds:

```yaml
injection_template:
  header:
    name: X-Api-Key
    value: "{secret}"        # {secret} once, with any text around it
---
injection_template:
  query:
    name: key                # ?key=<Secret>
---
injection_template:
  basic_auth:
    username: AC123          # literal
    password: "{secret}"     # {secret} is the whole username or the whole password
```

The Agent presents its Agent Token where the Secret would go: `X-Api-Key: tcat_...`, `?key=tcat_...`, or basic auth with username `AC123` and password `tcat_...`. For a query template, TrustedCourier removes the Agent Token's parameter and adds the Secret, escaped, as the last parameter, replacing any value the Agent sent under that name. A query parameter no Injection Template names is never read for an Agent Token.

Redaction masks every form of the Secret the request carried: the Secret itself, the escaped Secret for a query template, and the base64 credential for basic auth.

#### Presets

A Preset supplies the Injection Template and Upstream for a well-known service:

```yaml
secrets:
  openai:
    backend: openbao
    location: secret/data/openai#key
    preset: openai
```

| Preset | Injection Template | Upstream `api` |
| --- | --- | --- |
| `openai` | `Bearer {secret}` in the `Authorization` header | `https://api.openai.com/v1` |
| `anthropic` | `X-Api-Key: {secret}` | `https://api.anthropic.com` |
| `github` | `token {secret}` in the `Authorization` header | `https://api.github.com` |

`preset` cannot sit beside `injection_template`. `upstreams` beside a Preset replace its Upstreams, for GitHub Enterprise Server or a gateway. Presets live in [`internal/config/presets.yaml`](internal/config/presets.yaml), in the Secret Name's own format, so adding one is adding an entry. Recorded in [ADR-0017](docs/decisions/0017-injection-template-kinds-presets-and-tc-env.md).

#### `tc env`

`tc env` prints what an Agent needs for a Secret Name:

```sh
./tc env openai
```

```
OPENAI_BASE_URL=http://127.0.0.1:8200/proxy/openai/api
OPENAI_API_KEY=<Agent Token>
```

Replace `<Agent Token>` with a token from `tc token issue`; the server keeps only hashes, so it cannot print one. Presets name their SDK's variables. Other Secret Names get `<NAME>_BASE_URL` and `<NAME>_API_KEY`, or `<NAME>_USERNAME` and `<NAME>_PASSWORD` for basic auth, with the literal field filled in and left out when it is empty. Values are printed as is, without shell quoting. A Secret Name with several Upstreams needs `--upstream <name>`. `--json` prints an object of variable to value.

### Reveal Delivery

Map a Secret Name to its location in a Backend, let a Policy reveal it, and turn on the Agent API with its audit signing key:

```yaml
agent_api:
  listen: 127.0.0.1:8200
audit:
  signing_key:
    backend: openbao
    location: secret/data/trustedcourier#audit-signing-key
secrets:
  github:
    backend: openbao
    location: secret/data/github#token
policies:
  github-reveal:
    secrets:
      - name: github
        delivery: [reveal]
```

Issue an Agent Token with that Policy, and the Agent asks for the Secret by name:

```sh
curl -H "Authorization: Bearer tcat_..." http://127.0.0.1:8200/v1/reveal/github
```

The body is the Secret, byte for byte, with `Cache-Control: no-store`. TrustedCourier fetches it from the Backend on every request, unless the Secret Name sets `cache_ttl`. The Agent sees only the Secret Name, never the Backend or location.

| Status | When |
| --- | --- |
| 200 | A Policy on the Agent Token lists the Secret Name with `reveal`. |
| 401 | The Agent Token is missing, unknown, expired, or revoked. The message says which. |
| 403 | Anything else: the Secret Name does not exist, no attached Policy lists it, or the Policy allows only `proxy`. The body is identical in every case, so Agents cannot discover Secret Names. |
| 405 | Any method but `GET`, including `HEAD`. |
| 502 | The Backend could not return the Secret. Details go to the server log only. |
| 503 | The server has no locked memory left to hold the Secret (raise `RLIMIT_MEMLOCK`), or has not loaded the audit signing key yet or cannot store Audit Records (`tc status` says why). |

The Agent Token may go in `X-TC-Agent-Token` instead of `Authorization`. The Agent API serves plain HTTP only on a loopback IP address or a unix socket; anywhere else it serves TLS ([ADR-0006](docs/decisions/0006-tls-with-built-in-acme.md)).

### TLS on the Agent API

Agent Tokens and Reveal Deliveries never cross a network in plaintext. To serve Agents beyond loopback, put a certificate chain and its private key in a Backend and name them under `agent_api.tls`; the server refuses a non-loopback `listen` without it:

```yaml
agent_api:
  listen: 0.0.0.0:8443
  tls:
    certificate:
      backend: openbao
      location: secret/data/trustedcourier#tls-certificate
    key:
      backend: openbao
      location: secret/data/trustedcourier#tls-key
```

The certificate location holds the PEM chain, leaf first; the key location holds the leaf's private key as PEM. Both are Courier Keys: they live in the Backend, never on TrustedCourier's disk, and no Secret Name may map to the key's location. The listener binds at startup, but no TLS handshake completes until the pair is loaded from the Backend; the server retries every few seconds, and `tc status` reports `TLS certificate: not loaded` with the reason, including an expired certificate or a key that does not match. HTTP/2 is negotiated by ALPN. Rotating an Operator-supplied pair in the Backend takes a restart ([ADR-0023](docs/decisions/0023-agent-listener-tls-and-unix-socket.md)).

#### Automatic certificates with ACME

Add `acme` under `agent_api.tls` and TrustedCourier obtains the pair itself, stores it at the `certificate` and `key` locations, and renews it at two thirds of its lifetime. The default directory is Let's Encrypt, the default challenge is TLS-ALPN-01, which is validated on the Agent API listener itself, so it must be reachable on port 443 of every name in `domains`:

```yaml
agent_api:
  listen: 0.0.0.0:443
  tls:
    certificate:
      backend: openbao
      location: secret/data/trustedcourier#tls-certificate
    key:
      backend: openbao
      location: secret/data/trustedcourier#tls-key
    acme:
      domains: [tc.example.com]
      contact: ops@example.com
      account_key:
        backend: openbao
        location: secret/data/trustedcourier#acme-account-key
```

`challenge: http-01` validates over plain HTTP instead, on a separate listener that serves nothing but challenge responses, `http_listen` (default `0.0.0.0:80`). For an internal CA such as step-ca, set `directory` to its URL, `ca_bundle` to the PEM file that verifies it, and, where the CA hands out External Account Binding credentials, `external_account_binding.key_id` with the base64url MAC key stored in a Backend as `hmac_key`.

`challenge: dns-01` validates by a TXT record instead, so it works on a private network where the CA cannot reach the Agent API, and it is the only challenge that validates a wildcard. TrustedCourier sets the record itself through one of the built-in DNS providers, `cloudflare`, `route53`, `azure`, or `google`, with credentials that are Courier Keys in a Backend, never values in the config:

```yaml
    acme:
      domains: ['*.example.com', example.com]
      challenge: dns-01
      dns:
        provider: cloudflare
        credentials:
          api_token:
            backend: openbao
            location: secret/data/trustedcourier#cloudflare-token
      account_key:
        backend: openbao
        location: secret/data/trustedcourier#acme-account-key
```

Each provider takes its own credential fields: `api_token` for Cloudflare (a token with Zone:Read and DNS:Edit on the zone); `access_key_id` and `secret_access_key` for Route 53 (allowed `route53:ListHostedZonesByName`, `route53:ListResourceRecordSets`, and `route53:ChangeResourceRecordSets`); `client_secret` for Azure DNS, with `tenant_id`, `client_id`, `subscription_id`, and `resource_group` beside `provider` (the service principal needs DNS Zone Contributor on the zone); and `service_account_key`, the JSON key file, for Google Cloud DNS (the account needs DNS Administrator, and `project` overrides the key's project). The credentials are fetched from the Backend for each order and wiped after it. The zone that holds each name is found at the provider, or `zone` names it. Before validation is requested, the record is looked up on the zone's authoritative name servers, or on `resolvers`, until it appears or `propagation_timeout` (default `2m`) passes; the records are removed once the order is done. `endpoint` (and, for Azure, `authority`) point a sovereign cloud or a test at another API URL, verified with `ca_bundle` ([ADR-0025](docs/decisions/0025-acme-dns-01-and-dns-providers.md)).

The account key, the certificate, and its key are all Courier Keys, so the Backend must have the `courier-key-write` capability; with a read-only Backend, `tc status` reports why no certificate is loaded and nothing is ordered. Supply the pair yourself instead. A restart reuses the stored pair, so nothing is re-issued against a CA's rate limits. Until the first certificate is obtained, and while a renewal keeps failing, `tc status` shows the CA's reason; the server retries from 30 seconds up to hourly, and keeps serving the loaded certificate until it expires ([ADR-0024](docs/decisions/0024-acme-issuance-and-renewal.md)).

Agents on the same host can use a unix socket instead, which needs no certificate:

```yaml
agent_api:
  socket: /run/trustedcourier/agent.sock
```

The socket is connectable by every local user, as a loopback port is; Agent Tokens do the authenticating. `tc env` needs `agent_api.listen`, since a base URL cannot name a socket.

### Remote administration

The admin API lives on a unix socket, unreachable from the network. To administer from another machine, enable the remote admin listener. It is off by default, and when on it takes two factors: a client certificate signed by a CA you name, checked in the TLS handshake before any request is read, and the Operator Credential on every request ([ADR-0026](docs/decisions/0026-remote-admin-listener-mutual-tls.md)).

```yaml
admin:
  socket: /run/trustedcourier/admin.sock
  listen: 0.0.0.0:8300
  tls:
    certificate:
      backend: openbao
      location: secret/data/trustedcourier#tls-certificate
    key:
      backend: openbao
      location: secret/data/trustedcourier#tls-key
    client_ca: /etc/trustedcourier/operators-ca.pem
```

The listener's own certificate and key are Courier Keys in a Backend, like the Agent API's. Naming the same locations as `agent_api.tls` serves one certificate on both listeners, so an ACME renewal covers both; naming others serves an Operator-supplied pair that a restart picks up. Until the pair is loaded from its Backend, no handshake completes. `client_ca` is a file: it holds only public CA certificates, and every client certificate must chain to one of them. Issue Operator client certificates from a CA of your own, such as one made with `step` or `openssl`, with the client authentication extended key usage; revocation is by rotating `client_ca` and restarting.

Point `tc` at the listener with `TC_ADMIN_URL`, and give it the client certificate and key as PEM files:

```sh
export TC_ADMIN_URL=https://courier.example.com:8300
export TC_ADMIN_CLIENT_CERT=~/.config/trustedcourier/operator.pem
export TC_ADMIN_CLIENT_KEY=~/.config/trustedcourier/operator-key.pem
export TC_OPERATOR_CREDENTIAL=tcoc_...

tc status
```

`TC_ADMIN_CA_BUNDLE` names a CA file when the listener's certificate is not signed by a system root. The socket keeps working beside the listener, and `tc` uses it whenever `TC_ADMIN_URL` is unset.

### Audit

Every Delivery attempt made with a valid Agent Token, allowed or denied, produces one Audit Record. That includes Deliveries that failed or were cut off, and 400s for a dot segment or a protocol upgrade. A 401 produces none. The server stores each record in SQLite and writes it to stdout as one JSON line, ready for Loki or a SIEM:

```json
{"seq":2,"time":"2026-09-15T06:12:03.418Z","agent_token_id":"emqckmg73t6p2xaj","secret_name":"openai","delivery":"proxy","upstream":"api","upstream_host":"api.openai.com","decision":"allowed","reason":"","upstream_status":200,"failure":"","prev_hash":"a7dc...","hash":"a227..."}
```

| Field | Meaning |
| --- | --- |
| `seq` | Position in the chain, from 1, with no gaps. |
| `delivery` | `proxy` or `reveal`. |
| `upstream`, `upstream_host` | The Upstream name the Agent asked for, and the host it is pinned to. Empty for Reveal Delivery or an unknown Upstream. |
| `decision`, `reason` | `allowed`, or `denied` with the reason the Agent never sees, such as `no Policy allows it` or `unknown Upstream`. |
| `upstream_status` | The Upstream's status code, or `null` when it never answered. |
| `failure` | Why an allowed Delivery did not complete, such as `the Secret could not be fetched` or `the Upstream's response broke off`. |
| `prev_hash`, `hash` | The previous record's hash, and this record's: the SHA-256 of the line with its final `,"hash":"..."` member removed. The first `prev_hash` is 64 zeros. |

Records never contain a Secret's value, request or response bodies, paths, or error text from a Backend or Upstream. To check a streamed record, hash the line exactly as received, minus the `hash` member. Re-encoding the JSON can change the bytes. A Proxy Delivery still streaming 5 seconds after SIGTERM is cut off and recorded with the failure `cut off by server shutdown`.

If a record cannot be stored, say because the disk is full, TrustedCourier keeps it in memory, retries it every few seconds, and answers every new Agent API request with 503 until it and every record behind it are stored in order. Deliveries already under way finish. `tc status` shows how many records are waiting and why, and Deliveries resume on their own. A record still waiting at shutdown is logged to stderr as its JSON object ([ADR-0020](docs/decisions/0020-deliveries-stop-while-audit-records-cannot-be-stored.md)).

`tc audit verify` walks the chain in SQLite and reports the first break. A deleted record, an altered one, or one that no longer chains all count:

```
Audit chain broken at record 2: record 2 does not match its hash
1 Audit Record before it intact
```

It exits 0 when the chain is intact and 1 when it is broken, and takes `--json`. Removing or replacing records at the end of the chain, or adding one after it, is caught while the server that wrote them runs. The stream, the chain's format, and which requests count are recorded in [ADR-0016](docs/decisions/0016-audit-record-stream-chain-and-verify.md).

#### Signed checkpoints

Anyone who can write the database could rebuild the whole chain with fresh hashes. So TrustedCourier signs the chain head with an Ed25519 audit signing key, a Courier Key it fetches from a Backend and holds only in locked memory. Create one and store it in the Backend:

```sh
openssl genpkey -algorithm ed25519
```

The Backend's value is that PKCS #8 PEM block and nothing else. Point `audit.signing_key` at it, which the Agent API requires:

```yaml
audit:
  signing_key:
    backend: openbao
    location: secret/data/trustedcourier#audit-signing-key
  checkpoints:
    records: 1000   # sign once this many records follow the last checkpoint
    interval: 1m    # and at least this often while any do
```

A checkpoint is also signed at shutdown. Until the key loads, the Agent API answers every request with 503 and writes no Audit Records; the server retries every few seconds, and `tc status` says what went wrong. `tc audit verify` then checks every checkpoint against the key:

```
Audit chain intact: 5210 Audit Records, 6 signed checkpoints
```

A chain rewritten with recomputed hashes, a checkpoint that was deleted or does not verify, and records removed at the end while the server was stopped all break verification, from the database and key alone. Two things stay out of reach without the stream: records removed together with every checkpoint after them, and a rewrite of the records after the last checkpoint. Rotating the key makes earlier checkpoints fail. Checkpoints live in the `audit_checkpoints` table, and what each signature covers is in [ADR-0019](docs/decisions/0019-signed-audit-checkpoints.md).

## CLI

```
tc server run --config <path>
tc token issue --policy <name> [--policy <name>...] (--expires-in <lifetime> | --expires-at <RFC 3339>) [--json]
tc token list [--json]
tc token revoke <id>
tc env <secret-name> [--upstream <name>] [--json]
tc reload [--json]
tc status [--json]
tc audit verify [--json]
tc plugin sha256 <path>
```

| Variable | Meaning |
| --- | --- |
| `TC_ADMIN_SOCKET` | Admin socket path. Defaults to `/run/trustedcourier/admin.sock`. |
| `TC_OPERATOR_CREDENTIAL` | The Operator Credential. Every `token` command, `env`, `reload`, `status`, and `audit verify` require it. |
| `TC_ADMIN_URL` | The [remote admin listener](#remote-administration), as `https://host:port`, used instead of the socket when set. |
| `TC_ADMIN_CLIENT_CERT`, `TC_ADMIN_CLIENT_KEY` | PEM files holding the client certificate and its private key `tc` presents to `TC_ADMIN_URL`. Both are required with it. |
| `TC_ADMIN_CA_BUNDLE` | PEM file of CA certificates that verify the listener's certificate. Defaults to the system roots. |

Exit codes are 0 for success, 1 for a failed operation, and 2 for a malformed command line.

## Configuration

The config is a single YAML document. Decoding is strict ([ADR-0010](docs/decisions/0010-yaml-config-strict-decoding.md)), so a misspelled key stops the server at startup instead of being silently ignored. Relative paths resolve against the config file's directory, not the working directory.

| Key | Required | Meaning |
| --- | --- | --- |
| `data_dir` | yes | Directory for the SQLite database. Created with mode 0700. |
| `admin.socket` | no | Admin socket path. Defaults to `/run/trustedcourier/admin.sock`. |
| `admin.allowed_uids` | no | Local user IDs allowed to connect to the socket. Defaults to the server's own user. An empty list is an error, since nobody could administer the server. |
| `admin.listen` | no | IP address and port for the [remote admin listener](#remote-administration), such as `0.0.0.0:8300`. Off when omitted. Needs `admin.tls`, and its own port apart from the Agent API and HTTP-01. |
| `admin.tls.certificate.backend`, `.location` | with `admin.listen` | Where the listener's certificate chain lives, as PEM with the leaf first, in a Backend. Naming the Agent API's certificate and key shares them, ACME renewals included. No Secret Name may map to it. |
| `admin.tls.key.backend`, `.location` | with `admin.listen` | Where the certificate's private key lives, as PKCS #8, PKCS #1, or SEC 1 PEM. No Secret Name may map to it. |
| `admin.tls.client_ca` | with `admin.listen` | PEM file of CA certificates that Operator client certificates must chain to. A connection without one is refused at the TLS layer. |
| `policies` | no | Map of Policy name to Policy. |
| `policies.<name>.secrets` | yes | List of `{name, delivery}` entries, one per Secret Name. |
| `policies.<name>.secrets[].delivery` | yes | One or both of `proxy` and `reveal`. |
| `policies.<name>.secrets[].methods` | no | HTTP methods Proxy Delivery may send: any of `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS`. Omit to allow any method. |
| `policies.<name>.secrets[].paths` | no | Path prefixes, starting with `/`, that Proxy Delivery may reach below the route. Omit to allow any path. |
| `backend_plugins` | no | Map of Backend Plugin name to Backend Plugin. |
| `backend_plugins.<name>.path` | yes | Path to the plugin binary. |
| `backend_plugins.<name>.sha256` | yes | The binary's SHA-256 as `tc plugin sha256` prints it. |
| `backend_plugins.<name>.user` | one of these two | OS user name or ID the plugin runs as. |
| `backend_plugins.<name>.insecure_share_core_user` | one of these two | `true` runs the plugin as the server's own user. Development only. |
| `secrets` | no | Map of Secret Name to where its Secret lives. |
| `secrets.<name>.backend` | yes | The `backend_plugins` entry that holds the Secret. |
| `secrets.<name>.location` | yes | The Secret's location in that Backend, up to 1024 bytes without control characters. |
| `secrets.<name>.cache_ttl` | no | Keep the Secret in locked memory and deliver it without calling the Backend for this long after each fetch, as a Go duration from `1s` to `1h`. Omit it to fetch on every Delivery. |
| `secrets.<name>.preset` | no | A built-in Preset (`openai`, `anthropic`, `github`) supplying the Injection Template and Upstreams. Not with `injection_template`. `upstreams` beside it replace the Preset's. |
| `secrets.<name>.injection_template` | with `upstreams`, unless `preset` | Exactly one of `header`, `query`, and `basic_auth`. |
| `secrets.<name>.injection_template.query.name` | for `query` | The query parameter the Secret goes in: up to 64 letters, digits, `.`, `_`, `~`, and `-`. |
| `secrets.<name>.injection_template.basic_auth.username`, `.password` | for `basic_auth` | One is exactly `{secret}`, the other literal (may be omitted for empty). A literal username cannot contain `:`. |
| `secrets.<name>.injection_template.header.name` | for `header` | The header Proxy Delivery puts the Secret in. Hop-by-hop headers, `Host`, `Content-Length`, and `X-TC-Agent-Token` are refused. |
| `secrets.<name>.injection_template.header.value` | for `header` | The header's value, with `{secret}` exactly once where the Secret goes, such as `Bearer {secret}`. |
| `secrets.<name>.upstreams` | with `injection_template`; optional with `preset` | Map of Upstream name to Upstream. Each is served at `/proxy/<Secret Name>/<Upstream name>`. |
| `secrets.<name>.upstreams.<name>.url` | yes | The Upstream's `https` base URL, optionally with a path. No user information, query, or fragment. |
| `secrets.<name>.upstreams.<name>.ca_bundle` | no | PEM file of CA certificates that replace the system roots for this Upstream. |
| `agent_api.listen` | no | IP address and port for the Agent API, such as `127.0.0.1:8200`, `[::1]:8200`, or `0.0.0.0:8443`. Plain HTTP is served only on a loopback address; anywhere else needs `agent_api.tls`. Not with `agent_api.socket`. Omit both to serve no Agent API. |
| `agent_api.socket` | no | Unix socket path for the Agent API, serving plain HTTP. Connectable by every local user, as a loopback port is; Agent Tokens authenticate Agents. |
| `agent_api.tls.certificate.backend`, `.location` | for TLS | Where the Operator-supplied certificate chain lives, as PEM with the leaf first, in a Backend ([ADR-0023](docs/decisions/0023-agent-listener-tls-and-unix-socket.md)). Needs `agent_api.listen`. No Secret Name may map to it. |
| `agent_api.tls.key.backend`, `.location` | for TLS | Where the certificate's private key lives, as PKCS #8, PKCS #1, or SEC 1 PEM. No Secret Name may map to it. |
| `agent_api.tls.acme.domains` | for ACME | DNS names the certificate is issued for, the first as its subject. No IP addresses. A wildcard such as `*.example.com` needs `challenge: dns-01`. |
| `agent_api.tls.acme.account_key.backend`, `.location` | for ACME | Where the ACME account key lives; generated and stored there on first use. No Secret Name may map to it. |
| `agent_api.tls.acme.directory` | no | ACME directory `https` URL. Defaults to Let's Encrypt. |
| `agent_api.tls.acme.contact` | no | Email address registered with the account. |
| `agent_api.tls.acme.challenge` | no | `tls-alpn-01` (default), validated on the Agent API listener; `http-01`, validated on `http_listen`; or `dns-01`, validated by a TXT record set through `dns`. |
| `agent_api.tls.acme.http_listen` | with `http-01` | IP address and port of the plain HTTP challenge listener. Defaults to `0.0.0.0:80`. Must differ from `agent_api.listen`. |
| `agent_api.tls.acme.dns.provider` | with `dns-01` | The DNS provider that sets the records: `cloudflare`, `route53`, `azure`, or `google`. |
| `agent_api.tls.acme.dns.credentials.<field>.backend`, `.location` | with `dns-01` | Where each of the provider's credentials lives: `api_token` for `cloudflare`; `access_key_id` and `secret_access_key` for `route53`; `client_secret` for `azure`; `service_account_key` (the JSON key file) for `google`. Courier Keys: no Secret Name may map to them. |
| `agent_api.tls.acme.dns.zone` | no | The zone the records go in. Must hold every domain. Omit it to find the zone at the provider. |
| `agent_api.tls.acme.dns.resolvers` | no | IP addresses, with an optional port (default 53), the record is looked up on before validation is requested. Omit them to use the zone's authoritative name servers. |
| `agent_api.tls.acme.dns.propagation_timeout` | no | How long the record may take to appear, as a Go duration from `1s` to `30m`. Defaults to `2m`. |
| `agent_api.tls.acme.dns.endpoint` | no | `https` URL that replaces the provider's API, for a sovereign cloud or a test. |
| `agent_api.tls.acme.dns.ca_bundle` | no | PEM file of CA certificates that replace the system roots for the provider's API and token endpoint. |
| `agent_api.tls.acme.dns.tenant_id`, `.client_id`, `.subscription_id`, `.resource_group` | for `azure` | The service principal and the resource group that holds the zone. |
| `agent_api.tls.acme.dns.authority` | no, `azure` only | `https` URL that replaces `https://login.microsoftonline.com`. |
| `agent_api.tls.acme.dns.project` | no, `google` only | The project that holds the zone. Defaults to the service account key's. |
| `agent_api.tls.acme.ca_bundle` | no | PEM file of CA certificates that replace the system roots for the ACME directory. |
| `agent_api.tls.acme.external_account_binding.key_id` | no | External Account Binding key identifier the CA issued. Needs `hmac_key`. |
| `agent_api.tls.acme.external_account_binding.hmac_key.backend`, `.location` | with `key_id` | Where the base64url MAC key the CA issued lives. No Secret Name may map to it. |
| `audit.signing_key.backend` | with `agent_api` | The `backend_plugins` entry that holds the audit signing key. |
| `audit.signing_key.location` | with `agent_api` | The key's location in that Backend: an Ed25519 private key as PKCS #8 PEM. No Secret Name may map to it. |
| `audit.checkpoints.records` | no | Sign a checkpoint once this many Audit Records follow the last one. At least 1; defaults to 1000. |
| `audit.checkpoints.interval` | no | Sign a checkpoint at least this often while records are waiting for one, as a Go duration. At least `1s`; defaults to `1m`. |

Policy names, Backend Plugin names, and Secret Names are 1 to 64 characters of letters, digits, `.`, `_`, and `-`, starting with a letter or digit. A Policy must list at least one Secret Name, can list each only once, may list only Secret Names defined under `secrets`, and may allow `proxy` only for Secret Names with `upstreams`. `methods` and `paths` need `proxy` in `delivery`, cannot be empty lists or keys without a value, and are refused when they hold an unknown method or a path prefix with a dot segment, an empty segment, `?`, `#`, `;` (raw or `%3B`), or an encoded slash or backslash. A typo there stops the server at startup instead of denying Agents at runtime. Upstream names follow the same rules as Secret Names.

Two things trip people up with the admin socket. The default `/run/trustedcourier/` usually needs root to create, so for a non-root server pick a path you own, such as one under `$XDG_RUNTIME_DIR`. And unix socket paths are limited to about 104 to 108 bytes depending on the OS, so a deeply nested path fails with `bind: invalid argument`.

### Reloading

`tc reload` has the server reload the config file it started from, without a restart:

```sh
./tc reload
Config reloaded from /etc/trustedcourier/trustedcourier.yaml (Policies: 3, Secret Names: 4)
```

Policies, Secret Names, Upstreams, Injection Templates, and Presets take effect for every request that starts after the reload. A Delivery already under way finishes on the config it started with. Removing a Policy removes its access from every Agent Token that names it at once, though `tc token list` still shows the name. The file is validated as at startup; if anything is wrong, `tc reload` exits 1 with the reason and the running config stays in effect. `data_dir`, `admin`, `agent_api`, `backend_plugins`, and `audit` change only on restart, so a file that changes any of them is refused whole, naming them ([ADR-0021](docs/decisions/0021-config-reload-swaps-snapshots.md)).

## Security properties today

- The Operator Credential and Agent Tokens come from 32 random bytes. The database keeps only their SHA-256 hashes, and comparison is constant-time.
- Both are shown exactly once. If the first boot fails before the server is listening, the credential is not kept, and the next boot shows a fresh one.
- Credentials carry prefixes (`tcoc_` for the Operator Credential, `tcat_` for Agent Tokens) so secret scanners can spot a leak.
- The data directory is 0700 and the database files are 0600. The server tightens them again at every start, in case a backup restore loosened them.
- The admin socket checks the connecting process's UID against `admin.allowed_uids` before it looks at the Operator Credential. The socket file is owner-only unless other users are allowed.
- The remote admin listener is off by default. When enabled, every connection must present a client certificate chaining to `admin.tls.client_ca` or the TLS handshake fails, and every request must then carry the Operator Credential ([ADR-0026](docs/decisions/0026-remote-admin-listener-mutual-tls.md)).
- A second server pointed at a live socket refuses to start. A stale socket left by a crash is replaced.
- The Agent API serves plain HTTP only on loopback or a unix socket. Anywhere else it serves TLS from a certificate and key held in a Backend, never on disk, and completes no handshake until they are loaded ([ADR-0023](docs/decisions/0023-agent-listener-tls-and-unix-socket.md)). With ACME, the account key and the issued pair are written to the Backend, and nothing is ordered from the CA while the Backend cannot store them ([ADR-0024](docs/decisions/0024-acme-issuance-and-renewal.md)). With DNS-01, the DNS provider credentials are read from the Backend for each order and wiped after it, and the validation records are removed however the order ends ([ADR-0025](docs/decisions/0025-acme-dns-01-and-dns-providers.md)).
- Revoking an Agent Token twice succeeds and keeps the first revocation time.
- A Backend Plugin binary whose SHA-256 differs from the pinned hash stops the server at boot and is never relaunched after boot. On Linux the server executes the file descriptor it hashed, so swapping the binary after the check does not work ([ADR-0011](docs/decisions/0011-backend-plugin-host-and-protocol.md)).
- Backend Plugins run as a separate OS user that cannot read the config file or own the data directory, with an empty environment apart from `GODEBUG`. Core and plugin talk over go-plugin's automatic mutual TLS.
- In FIPS 140-3 mode the server refuses any Backend Plugin whose first response does not report FIPS mode, so no Secret is served through a process outside the boundary ([ADR-0027](docs/decisions/0027-fips-mode-plugin-parity-and-process-hardening.md)).
- Every `tc` process and every plugin built on the SDK sets its core file size limit to zero, hard and soft, before it does anything else, and on Linux marks itself not dumpable, so its memory cannot be read by another process of the same user through ptrace or `/proc`.
- Every plugin response is checked against the protocol contract (size limits, valid UTF-8, no control characters) before the server uses it, and plugin error text and log output are sanitized.
- A plugin that crashes is restarted with exponential backoff, from 250 ms to 30 s. It never takes the server down.
- In the core, a Secret lives in `mlock`ed memory outside the Go heap, is wiped when the response is written, and prints as a placeholder if formatted or logged. A Delivery fails rather than hold a Secret in memory that could be swapped. The e2e harness fails any test whose server output, the audit stream included, contains a Secret value.
- Caching is off unless a Secret Name sets `cache_ttl`, at most an hour. A cached Secret stays in locked memory, never on disk, and is wiped when its TTL ends, when a reload moves the Secret Name or turns its cache off, and at shutdown. Until then it is delivered even if rotated or revoked in its Backend ([ADR-0022](docs/decisions/0022-secret-cache-per-secret-name.md)).
- Audit Records are hash-chained, so `tc audit verify` detects a record deleted or altered in SQLite ([ADR-0016](docs/decisions/0016-audit-record-stream-chain-and-verify.md)).
- The chain head is signed with an Ed25519 audit signing key held in locked memory and never on disk, so a chain rebuilt with fresh hashes fails verification. No Delivery is served until the key is loaded ([ADR-0019](docs/decisions/0019-signed-audit-checkpoints.md)), nor while Audit Records cannot be stored ([ADR-0020](docs/decisions/0020-deliveries-stop-while-audit-records-cannot-be-stored.md)).

## Repository layout

The repository holds three Go modules. The plugin SDK is versioned on its own (`sdk/plugin/vX.Y.Z` tags), so a Backend Plugin never depends on the core.

| Path | Contents |
| --- | --- |
| `cmd/tc` | The `tc` binary. |
| `internal/access` | Operator Credential and Agent Token issue, verify, revoke; Policy evaluation. |
| `internal/admin` | Admin API server and client over the unix socket. |
| `internal/agentapi` | Agent API server: Proxy Delivery and Reveal Delivery. |
| `internal/audit` | Audit Records: appended to SQLite, hash-chained, streamed as JSON lines, covered by signed checkpoints, and verified. |
| `internal/cli` | Command-line parsing and output. |
| `internal/config` | Config loading and validation. |
| `internal/pluginhost` | Plugin Host: verifies, launches, supervises, and reports Backend Plugins, and fetches Secrets through them. |
| `internal/resolver` | Secret Resolver: Secret Name to Backend location to Secret. |
| `internal/secret` | The Secret type and the Ed25519 audit signing key: locked, unprintable, wiped on release. |
| `internal/server` | Wires config, database, admin API, and Agent API into a running process. |
| `internal/store` | SQLite database and migrations, through pure-Go `modernc.org/sqlite` ([ADR-0009](docs/decisions/0009-pure-go-sqlite.md)). |
| `e2e` | Black-box tests that build `tc` and drive a real server through its config, socket, CLI, and Agent API, against a fake TLS Upstream. |
| `docs/api` | OpenAPI spec for the Agent API. |
| `sdk/plugin` | Plugin SDK module: the `Backend` interface and `Serve` for Plugin Authors, the wire protocol (`protocol`), the validating client (`client`), the conformance kit (`conformance`), and the fake Backend Plugin used by tests. |
| `plugins/openbao` | OpenBao Backend Plugin module. A placeholder until [#18](https://github.com/potto007/TrustedCourier/issues/18). |

## Development

Run the checks CI runs, in each module (`.`, `sdk/plugin`, `plugins/openbao`):

```sh
test -z "$(gofmt -l .)"
go vet ./...
go test -race ./...
```

The full suite takes several minutes, and `go test` prints nothing for a package until it finishes. To watch a run live in Claude Code's work-band plugin, run it through `scripts/testprogress`, which writes the readable output to a log, progress (tests run out of the total, passed, failed, skipped, and the current test; a package that fails to build or fails outside a test counts as one failure) to `<log>.progress.jsonl`, and `DONE` or `FAILED` as the log's last line:

```sh
go run ./scripts/testprogress -log /tmp/tc-tests.log -label "TrustedCourier tests" -- go test -race -json ./...
```

CI builds with `GOFIPS140=certified`, the validated FIPS 140-3 module, and runs every module twice, once with `GODEBUG=fips140=off` and once with `fips140=on`. Set both the same way to reproduce a CI leg locally; `fips140=only` also passes and catches any non-approved algorithm as a panic. The race detector is required, not optional ([ADR-0003](docs/decisions/0003-go-over-rust-core.md) relies on it).

`TestBackendPluginRunsAsSeparateUser` needs a root server to switch the plugin's user and skips otherwise. CI runs it, with the separate-user refusal tests, a second time under `sudo`.

The plugin protocol's Go code is generated. After editing `sdk/plugin/protocol/backend.proto`, run `buf generate` in that directory with `protoc-gen-go` and `protoc-gen-go-grpc` on `PATH`.

Tests go through the process, not internal types. The `e2e` harness builds `tc` (with `-race` when the tests run with it), starts it from a config file, and asserts only what an Operator or Agent could observe. New behavior should get a test there first.

Work is tracked in [GitHub Issues](https://github.com/potto007/TrustedCourier/issues), with the full v1 spec in [#1](https://github.com/potto007/TrustedCourier/issues/1). When you make or reverse an architecture decision, add an ADR to `docs/decisions/`. Accepted ADRs are never edited, only superseded.

## License

[Apache License 2.0](LICENSE).
