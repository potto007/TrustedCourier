#!/usr/bin/env bash
# Runs go test through scripts/testprogress so the run shows in the work
# band, with DONE or FAILED as the log's last line.
#
#   scripts/test-band.sh <log> <label> [go test args...]
#
# Example: scripts/test-band.sh /tmp/tc-tests.log "TrustedCourier tests" -race ./...
# Bash's pipefail preserves failures from the runner as well as tee.
set -uo pipefail
log=$1; label=$2; shift 2
rm -f "$log" "$log.progress.jsonl"
cd "$(dirname "$0")/.." || exit 1
(
  go run ./scripts/testprogress -log "$log" -label "$label" -- go test -json "$@" 2>&1
  rc=$?
  [ "$rc" -eq 0 ] && echo DONE || echo FAILED
  exit "$rc"
) | tee -a "$log"
