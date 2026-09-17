# Contributing to TrustedCourier

Bug reports, fixes, tests, documentation, and Backend Plugins are welcome.
TrustedCourier is in early development; the [v1 spec](https://github.com/potto007/TrustedCourier/issues/1)
tracks its intended scope.

Participation follows the [Code of Conduct](CODE_OF_CONDUCT.md). Report suspected
vulnerabilities through the private route in the [security policy](SECURITY.md).

## Contributor signoff

Human authors, including the maintainer, must certify their contributions under
the [Developer Certificate of Origin 1.1](https://developercertificate.org/).
Read it before adding a `Signed-off-by` trailer to each authored commit:

```sh
git commit -s -m "fix: describe the change" --trailer "Github-Issue:#123"
```

Omit the issue trailer when no issue applies. `-s` records your name and email
from Git configuration. Check that they identify you before committing. The
signoff is a public, lasting record; a GitHub noreply email is acceptable when
it matches your commit identity. A DCO signoff is a rights attestation, separate
from a cryptographic commit signature or GitHub's Verified badge.

By signing off, you certify that you may submit the work under the applicable
license. Code and documentation use [Apache-2.0](../LICENSE) unless a file states
another license; the Code of Conduct retains its CC BY-SA 4.0 license. Confirm
any required employer permission. Preserve third-party licenses and attribution,
and raise unclear rights with the maintainer before submitting the material.

For AI-assisted contributions, a human must review the result, its sources and
licenses, and their authority to submit it, then authorize their own signoff.
A tool must not add someone else's certification without that authorization.

Each human co-author must supply a signoff as well as any `Co-authored-by` credit.
The DCO app checks commit metadata; it does not establish ownership or verify
every co-author's certification. Maintainers review those cases before merge.

If your latest commit is missing your signoff, and you can make the certification:

```sh
git commit --amend --no-edit --signoff
git push --force-with-lease
```

For several unsigned commits, use interactive rebase to edit and sign only the
commits you can certify, then push with `--force-with-lease`. Coordinate before
rewriting a shared contribution branch. Keep the original authors and their
signoffs; never sign for someone else. Published `main` history is not rewritten.

The DCO check must pass alongside CI before merge. Web commits require signoff
through GitHub's editor. When squashing a PR, preserve the authors' signoffs in
the final commit message. Automated bot and merge commits are exempt from the
app's metadata check; human-authored material still needs a human certification.

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
   `git commit -s --trailer "Github-Issue:#123"`.
2. Push your branch to your fork and open a PR against `potto007/TrustedCourier`'s
   `main` branch. Draft PRs are useful for work that needs early feedback.
3. Explain the change, link the issue, and list the checks you ran. Use
   `Closes #123` only when the PR fully addresses that issue.
4. Keep your branch current with `main` and respond to review comments. The DCO
   check and all six CI checks must pass, and review conversations must be
   resolved before merge.

Discuss the code and its behavior respectfully. Be specific when reporting a
problem or suggesting a change, and allow time for maintainer review.

Maintainers should follow the [contribution and security procedures](../docs/maintainers/community-policies.md).
