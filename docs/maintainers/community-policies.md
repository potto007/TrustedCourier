# Contribution and security procedures

## Before merging a contribution

- Require the DCO app's `DCO` check and the six existing GitHub Actions CI checks.
  Inspect an unexpected neutral or missing DCO result; confirm that the app
  actually checked the PR commits.
- Check every human co-author's certification, third-party attribution, and any
  employer-permission concern raised by the contributor. Automated metadata
  checks cannot resolve a rights dispute.
- Preserve author and signoff trailers when squashing. Do not manufacture a
  signoff or rewrite published `main` history to add one.
- The app exempts bot and merge commits. Identify the human certification for
  human-authored material submitted through a bot.
- Do not use the DCO app's override button to bypass a missing certification.
  If a documented certification requires an exception to the app's metadata
  check, record its basis and the approving maintainer in the PR before merge.

The repository's `.github/dco.yml` applies the checks to the owner too and
disables remediation commits that sign for earlier commits. Authors repair
their own signoffs as described in the [contributor guide](../../.github/CONTRIBUTING.md#contributor-signoff).
For an app outage, the [DCO app](https://github.com/dcoapp/app) documents a recheck
request through a PR review containing `@dcoapp recheck` on its own line.

## Maintain the reporting channels

- Keep the conduct contact in the [Code of Conduct](../../.github/CODE_OF_CONDUCT.md)
  monitored. Update the policy before handing that role to another person.
- Keep GitHub private vulnerability reporting enabled. In the repository's Watch
  menu, choose Custom > Security alerts or All Activity, and enable notifications
  for the repository. Confirm the corresponding email or inbox preferences under
  account notification settings. Check the Advisories inbox during triage too.
- Review the [security policy](../../.github/SECURITY.md) when publishing the first
  release, changing supported versions, or changing component ownership.

GitHub's [notification instructions](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/configure-vulnerability-reporting/configure-for-a-repository#configuring-notifications-for-private-vulnerability-reporting)
explain the per-account settings needed to receive private reports.

## Handle a private vulnerability report

1. Review the private report, identify affected components and commits, and ask
   for missing reproduction details. Keep real credentials and personal data
   out of reproductions and test fixtures.
2. Accept a valid report into a draft advisory, or close it privately with an
   explanation. Invite only people needed for investigation or remediation.
   Keep any reporter's credit preferences with the advisory.
3. Develop and test the fix privately. GitHub temporary private advisory forks
   do not run the normal CI integrations, and advisory merges do not enforce
   the normal branch protections. Run the six module/FIPS test combinations
   and applicable privileged tests from [CI](../../.github/workflows/ci.yml) in
   an isolated environment. Record the tested commit and results privately.
4. Review the fix and any integration with current `main` before publication.
   Preserve provenance and obtain human signoffs even when the DCO app cannot
   run in the private fork. Do not post an early public PR that exposes the flaw.
5. Coordinate disclosure with the reporter. Publish the fix or mitigation and
   advisory with the affected component, commits or versions, and fix reference.
   The SDK and bundled plugin have separate Go module names; identify the
   affected package accurately when preparing an advisory or CVE request.

See GitHub's [private report handling](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/fix-reported-vulnerabilities/manage-vulnerability-reports)
and [temporary private fork limitations](https://docs.github.com/en/code-security/security-advisories/collaborating-in-a-temporary-private-fork-to-resolve-a-security-vulnerability).
