---
name: setup
description: Check and explain the Operator-controlled TrustedCourier Claude Code setup on Linux or WSL2.
---

# Set up TrustedCourier for Claude Code

Explain that this development plugin routes Bash calls but does not confine a Claude process by itself. The current hook can fail open and file, MCP, interactive, and other tool paths remain outside the broker. Do not claim a normal `claude` launch is protected or safe for Secret-bearing workloads.

Check the installed `tc-exec` and `tc-claude-hook` binaries, then check `TC_EXEC_CONFIG`, `TC_EXEC_BINARY`, and `TC_CLAUDE_HOOK_BINARY` as paths only. Do not read Agent Token files or display credentials. Use the local profile documentation to confirm its workspace and permitted resource names. Ask the Operator to perform Backend enrollment and Agent Token issuance in their own channel; never ask for those values in chat. Preserve the existing model authentication and Claude settings.

If prerequisites are missing, point the Operator to `docs/claude-code.md` in the TrustedCourier repository. Do not create a profile with fake production credentials or silently turn on a partially configured hook. For a shared OpenBao, do not run `tc init` against an already initialized Backend. This iteration does not provide an automated enrollment, upgrade, or uninstall flow.
