---
name: use
description: Use registered TrustedCourier operations from a protected Claude Code Linux session.
---

# Use TrustedCourier

In a development session, the hook submits ordinary Bash calls to the local execution broker. Claude's usual tool permission prompt still applies. A hook error can fall through to host execution, so do not treat this adapter as a Secret security boundary.

For a registered HTTP resource, use `tc-exec request --config "$TC_EXEC_CONFIG" --resource NAME --method GET --path /allowed/path`. Choose a resource name and path from Operator-provided documentation; do not guess an Agent Token, Secret Name, or Backend location. Protected requests go through TrustedCourier Proxy Delivery. If an operation is unavailable, report the denial and ask the Operator to update the Policy or profile. Never request or print a raw Secret.

Do not use an interactive shell, browser, computer-use tool, host MCP server, or subagent as a substitute for a protected operation. Those surfaces need separate confinement validation. Do not use this development integration for a workload that requires Secrets to be inaccessible from arbitrary Claude tools.
