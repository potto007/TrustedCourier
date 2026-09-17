#!/usr/bin/env python3
"""Fail closed unless the exact release commit passed all six main CI jobs."""
import json
import os
import re
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
            if result["total_count"] != len(result["jobs"]) or not passed_jobs(result["jobs"]):
                raise SystemExit("Main CI did not successfully execute all six required jobs")
            print(f"Verified main CI for {sha}: {run['html_url']}")
            return
        print(f"Waiting for main push CI at {sha}", flush=True)
        time.sleep(30)
    raise SystemExit("No completed exact-commit main CI within 40 minutes; rerun existing main push CI or prepare a new tested main commit and tag")


if __name__ == "__main__":
    main()
