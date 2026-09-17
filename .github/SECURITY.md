# Security policy

## Supported code

TrustedCourier is in early development and has no tagged releases yet. We
investigate suspected vulnerabilities in the current `main` branch. Include
the commit or build you tested so we can identify the affected code.

There is no maintained release series or backport commitment. When releases
exist, this section will identify which versions receive security fixes.

## Report a vulnerability privately

Use [GitHub private vulnerability reporting](https://github.com/potto007/TrustedCourier/security/advisories/new).
Do not open a public issue or pull request with exploit details or live
credentials. Reports are reviewed by the maintainer, `potto007`, through the
private advisory; people needed to investigate or fix the problem may be invited.

Include what you know:

- Affected component and tested commit or build.
- Required configuration, access, and other prerequisites.
- Security impact and steps to reproduce.
- A minimal proof using made-up Secrets and tokens.
- Any mitigation you have found.

Remove Operator Credentials, Agent Tokens, Courier Keys, Backend credentials,
seal material, and personal or customer data from attachments. Test only on
systems you control or have permission to assess. Avoid accessing other people's
data or disrupting live deployments.

If details have already been posted publicly, link that post in the private
report and avoid adding further exploit detail there.

## Scope

Reports about these components belong here:

- TrustedCourier's core server and CLI.
- The Backend Plugin SDK and protocol.
- The bundled OpenBao Backend Plugin.
- `tc init` and the bundled deployment configuration.

Report a fault in OpenBao itself through [OpenBao's security channel](https://openbao.org/community/policies/cve/).
Report it here too if TrustedCourier's integration creates or worsens the
exposure. For another Backend Plugin, contact its maintainer; report problems
in TrustedCourier's plugin isolation or protocol here.

Ordinary bugs, usage questions, and feature requests belong in
[GitHub Issues](https://github.com/potto007/TrustedCourier/issues).
Conduct concerns follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Triage and disclosure

The maintainer reviews reports, asks for missing details, and coordinates fixes
and disclosure with the reporter through the private advisory. Timing depends
on severity and maintainer availability; there is no guaranteed acknowledgement
or fix deadline and no bug bounty.

For a confirmed issue, we aim to publish an advisory alongside a fix or useful
mitigation, with affected commits or versions and a fix reference. Reporter
credit is included when the reporter wants it. Keep exploit details and proposed
fixes in the private advisory while we coordinate publication.
