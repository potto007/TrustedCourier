# Contributing to TrustedCourier

Bug reports, fixes, tests, documentation, and Backend Plugins are welcome.
TrustedCourier is in early development; the [v1 spec](https://github.com/potto007/TrustedCourier/issues/1)
tracks its intended scope.

## Find or propose work

Search [existing issues](https://github.com/potto007/TrustedCourier/issues) before
opening one. Describe the problem you want to solve and how someone can reproduce
it. For a substantial feature or architecture change, discuss the approach in an
issue before implementing it. Small fixes and documentation changes can go
straight to a pull request.

Issues labeled [good first issue](https://github.com/potto007/TrustedCourier/labels/good%20first%20issue)
or [help wanted](https://github.com/potto007/TrustedCourier/labels/help%20wanted)
are places to look for work. Comment on an issue you plan to take so others can
coordinate with you. New bug reports and feature requests start with
`needs-triage`; maintainers handle the triage labels.

Use made-up Secrets in examples and remove Operator Credentials, Agent Tokens,
Courier Keys, and Backend credentials from logs before posting them.

## Development setup

Use Linux or macOS, Git, and the Go version in [go.mod](../go.mod) or newer.
The race detector also needs a C compiler. Docker is needed for the OpenBao
integration tests; Docker Compose is needed for the optional compose test.

Fork the repository, clone your fork, and create a branch for your change:

```sh
git clone https://github.com/YOUR_USERNAME/TrustedCourier.git
cd TrustedCourier
git remote add upstream https://github.com/potto007/TrustedCourier.git
git switch -c fix/describe-the-change
go build ./...
```

The repository has three Go modules, each with its own tests:

| Directory | Module |
| --- | --- |
| `.` | TrustedCourier core and CLI |
| `sdk/plugin` | Backend Plugin SDK and conformance kit |
| `plugins/openbao` | Bundled OpenBao Backend Plugin |

See the [quickstart](../README.md#quickstart) to run the server locally. Plugin
Authors should start with the [Backend Plugin guide](../docs/backend-plugins.md).

## Make and check your change

Use the terms in [CONTEXT.md](../CONTEXT.md) and consult the relevant
[architecture decisions](../docs/decisions/README.md). When a change makes or
reverses an architecture decision, add an ADR. Supersede accepted ADRs rather
than editing them.

Keep a pull request focused on one change. Format Go code with `gofmt`. For a
behavior change, add a regression that exercises what an Operator or Agent can
observe through the process, CLI, or API; the existing `e2e` tests show the
pattern. Backend Plugins should pass the SDK's conformance kit.

From the repository root, run the checks below with Docker available. They cover
the six module/FIPS combinations required by CI and stop at the first failure:

```sh
(
  set -eu
  export GOFIPS140=certified
  export TC_REQUIRE_OPENBAO=1
  for module in . sdk/plugin plugins/openbao; do
    (
      cd "$module"
      test -z "$(gofmt -l .)"
      go vet ./...
      GODEBUG=fips140=off go test -race -timeout 30m ./...
      GODEBUG=fips140=on go test -race -timeout 30m ./...
    )
  done
)
```

For a focused core change, start with
`go test -race -run 'TestName' ./e2e` from the repository root. For SDK or plugin
changes, run the affected tests from that module's directory. The full suite
takes several minutes. Without Docker, omit `TC_REQUIRE_OPENBAO=1` for a partial
local run and report the skipped integration tests in your PR.

CI also runs the Backend Plugin user-separation tests as root. The compose test
is opt-in with `TC_COMPOSE_TEST=1`. See [Development](../README.md#development)
and the [CI workflow](workflows/ci.yml) for these checks and protocol generation.
For documentation-only changes, check examples and links and say that no code
tests were needed.

## Submit a pull request

1. Use a short, imperative Conventional Commit subject, such as
   `fix: reject invalid backend locations`, within 50 characters. When a commit
   addresses an issue, add its trailer with
   `git commit --trailer "Github-Issue:#123"`.
2. Push your branch to your fork and open a PR against `potto007/TrustedCourier`'s
   `main` branch. Draft PRs are useful for work that needs early feedback.
3. Explain the change, link the issue, and list the checks you ran. Use
   `Closes #123` only when the PR fully addresses that issue.
4. Keep your branch current with `main` and respond to review comments. All six
   CI checks must pass and review conversations must be resolved before merge.

Discuss the code and its behavior respectfully. Be specific when reporting a
problem or suggesting a change, and allow time for maintainer review.

The project uses the [Apache License 2.0](../LICENSE).
