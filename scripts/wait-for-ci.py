#!/usr/bin/env python3
"""Fail closed unless the exact release commit passed all six main CI jobs."""
import json
import datetime as dt
import os
import re
import runpy
from pathlib import Path
import subprocess
import sys
import time

REQUIRED = {f"test ({module}, fips140={mode})"
            for module in (".", "sdk/plugin", "plugins/openbao")
            for mode in ("off", "on")}


def select_run(runs, sha, repo):
    eligible = [run for run in runs
                if run.get("head_sha") == sha
                and run.get("event") == "push"
                and run.get("head_branch") == "main"
                and run.get("path") == ".github/workflows/ci.yml"
                and run.get("head_repository", {}).get("full_name") == repo]
    return max(eligible, key=lambda run: run["id"], default=None)


def passed_jobs(jobs):
    # Exactly one completed successful job per required name. Skips, cancellation,
    # duplicate names, and a superficially successful empty run are not evidence.
    for name in REQUIRED:
        matches = [job for job in jobs if job.get("name") == name]
        if len(matches) != 1 or matches[0].get("status") != "completed" or matches[0].get("conclusion") != "success":
            return False
    return True


def api(path):
    return json.loads(subprocess.check_output(["gh", "api", path], text=True))


def main():
    sha = sys.argv[1]
    repo = os.environ["GH_REPO"]
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise SystemExit("Expected a resolved commit SHA")
    deadline = time.monotonic() + 40 * 60
    while time.monotonic() < deadline:
        response = api(f"repos/{repo}/actions/workflows/ci.yml/runs?event=push&head_sha={sha}&per_page=100")
        run = select_run(response["workflow_runs"], sha, repo)
        if run and run["status"] == "completed":
            if run["conclusion"] != "success":
                raise SystemExit(f"Main CI failed: {run['html_url']}")
            result = api(f"repos/{repo}/actions/runs/{run['id']}/attempts/{run['run_attempt']}/jobs?per_page=100")
            if result["total_count"] != len(result["jobs"]):
                raise SystemExit("Truncated main job evidence")
            if not passed_jobs(result["jobs"]):
                gates = [j for j in result["jobs"] if j.get("name") == "acceptance evidence"]
                if len(gates) != 1 or gates[0].get("conclusion") != "success" or gates[0].get("status") != "completed":
                    raise SystemExit("Main CI has neither full acceptance nor a successful evidence gate")
                # Reconstruct the chain independently; do not trust main's log
                # message, output flag, or an uploaded PR artifact.
                proof = runpy.run_path(str(Path(__file__).with_name("ci-evidence.py")))["prove_pr"](
                    sha, repo, now=dt.datetime.fromisoformat(run["created_at"].replace("Z", "+00:00")))
                print(f"Verified prior PR acceptance: {proof['url']}")
            print(f"Verified main CI for {sha}: {run['html_url']}")
            return
        print(f"Waiting for main push CI at {sha}", flush=True)
        time.sleep(30)
    raise SystemExit("No completed exact-commit main CI within 40 minutes; rerun existing main push CI or prepare a new tested main commit and tag")


if __name__ == "__main__":
    main()
