---
name: use
description: Use registered TrustedCourier operations from an experimental Claude Code Linux session.
---

# Use TrustedCourier

In a development session, the hook submits ordinary Bash calls to the local execution broker. Claude evaluates permissions for the rewritten dispatch command; rules for the original Bash command may not carry over. Do not grant a blanket permission for dispatch. A hook error can fall through to host execution, so do not treat this adapter as a Secret security boundary.

For a registered HTTP resource in a rewritten Bash call, use `/tc-exec request --resource RESOURCE --method GET --path PATH`. Replace `RESOURCE` and `PATH` with values from Operator-provided documentation; do not guess an Agent Token, Secret Name, or Backend location. `/tc-exec` is the broker-mounted worker path. Host-side manual commands use the installed `tc-exec` path with `--config`. Protected requests go through TrustedCourier Proxy Delivery. If an operation is unavailable, report the denial and ask the Operator to update the Policy or profile. Never request or print a raw Secret.

Do not use an interactive shell, browser, computer-use tool, host MCP server, or subagent as a substitute for a protected operation. Those surfaces need separate confinement validation. Do not use this development integration for a workload that requires Secrets to be inaccessible from arbitrary Claude tools.
