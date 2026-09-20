#!/usr/bin/env python3
"""Smoke-test packaged Linux helpers without credentials or a broker service."""
import json
import os
from pathlib import Path
import subprocess
import sys

root = Path(sys.argv[1]).resolve()
env = dict(os.environ, GODEBUG="fips140=on")
result = subprocess.run([str(root / "tc-exec")], capture_output=True, text=True, env=env)
assert result.returncode == 1 and "usage: tc-exec" in result.stderr, result
# A background request is denied before reading any profile or contacting a
# broker, so this verifies the installed plugin shim and binary safely.
event = json.dumps({"tool_name": "Bash", "tool_input": {"command": "true", "run_in_background": True}})
env["TC_CLAUDE_HOOK_BINARY"] = str(root / "tc-claude-hook")
result = subprocess.run([str(root / "plugins/claude-trustedcourier/bin/tc-claude-hook")],
                        input=event, capture_output=True, text=True, env=env, check=True)
assert json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
print("packaged tc-exec and Claude plugin shim/binary: PASS")
