#!/usr/bin/env python3
"""Reuse recent acceptance only for a proven, unchanged normal merge result.

No artifacts or log claims are evidence. GitHub supplies run/job identity; Git
supplies full content identity. Unsupported cases deliberately run full tests.
"""
import datetime as dt
import json
import io
import zipfile
import os
import re
import subprocess
import sys
import time

REQUIRED = {f"test ({module}, fips140={mode})"
            for module in (".", "sdk/plugin", "plugins/openbao")
            for mode in ("off", "on")}
GUARDS = (".github/workflows", "scripts/ci-evidence.py", "scripts/wait-for-ci.py")


def api(path):
    return json.loads(subprocess.check_output(["gh", "api", path], text=True))


def git(*args):
    return subprocess.check_output(["git", *args], text=True).strip()


def all_jobs_passed(jobs):
    for name in REQUIRED:
        matches = [job for job in jobs if job.get("name") == name]
        if len(matches) != 1 or matches[0].get("status") != "completed" or matches[0].get("conclusion") != "success":
            return False
    return True


def jobs_for(run, repo):
    result = api(f"repos/{repo}/actions/runs/{run['id']}/attempts/{run['run_attempt']}/jobs?per_page=100")
    if result["total_count"] != len(result["jobs"]):
        raise ValueError("truncated jobs response")
    return result["jobs"]


def newest_pr_run(runs, head, repo):
    eligible = [run for run in runs
                if run.get("head_sha") == head and run.get("event") == "pull_request"
                and run.get("path") == ".github/workflows/ci.yml"
                and run.get("head_repository", {}).get("full_name") == repo]
    return max(eligible, key=lambda run: run["id"], default=None)


def merge_identity(sha):
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("invalid commit SHA")
    parents = git("rev-list", "--parents", "-n", "1", sha).split()
    if len(parents) != 3:
        raise ValueError("not a normal two-parent merge")
    _, base, head = parents
    subprocess.run(["git", "merge-base", "--is-ancestor", base, head], check=True)
    tree = git("rev-parse", f"{sha}^{{tree}}")
    if git("rev-parse", f"{head}^{{tree}}") != tree:
        raise ValueError("main and tested head have different source trees")
    # The PR cannot change its acceptance or provenance implementation and then
    # use its own changed implementation as trusted proof. Bootstrap runs full.
    git("cat-file", "-e", f"{base}:scripts/ci-evidence.py")
    if git("diff", "--name-only", base, sha, "--", *GUARDS):
        raise ValueError("acceptance/provenance definitions changed")
    entries = git("ls-tree", "-r", sha).splitlines()
    if any(line.startswith("160000 ") or line.endswith("\t.gitmodules")
           or line.endswith("\t.gitattributes") or line.endswith("/.gitattributes") for line in entries):
        raise ValueError("submodule/filter inputs require full validation")
    return base, head, tree


def receipt_for(run, pr, base, head, repo):
    # GitHub clears run->PR associations after merge. A default-branch-only
    # workflow_run producer captures the server event before that happens.
    # It executes no PR code and consumes no PR artifacts. Restrict the artifact
    # to that producer's run, not an attacker-selected download URL or name.
    response = api(f"repos/{repo}/actions/workflows/acceptance-receipt.yml/runs?event=workflow_run&per_page=100")
    for producer in response["workflow_runs"]:
        if producer.get("event") != "workflow_run" or producer.get("path") != ".github/workflows/acceptance-receipt.yml" or producer.get("status") != "completed" or producer.get("conclusion") != "success":
            continue
        artifacts = api(f"repos/{repo}/actions/runs/{producer['id']}/artifacts?per_page=100")
        matches = [a for a in artifacts["artifacts"] if a.get("name") == f"acceptance-{run['id']}-{run['run_attempt']}" and not a.get("expired")]
        if len(matches) != 1:
            continue
        artifact = matches[0]
        if artifact.get("size_in_bytes", 0) > 100_000 or artifact.get("workflow_run", {}).get("id") != producer["id"]:
            continue
        raw = subprocess.check_output(["gh", "api", f"repos/{repo}/actions/artifacts/{artifact['id']}/zip"])
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            if archive.namelist() != ["receipt.json"] or archive.getinfo("receipt.json").file_size > 100_000:
                continue
            receipt = json.loads(archive.read("receipt.json"))
        recorded = receipt["run"]
        if recorded.get("id") != run["id"] or recorded.get("run_attempt") != run["run_attempt"]:
            continue
        producer_sha = receipt["producer_sha"]
        if not re.fullmatch(r"[0-9a-f]{40}", producer_sha):
            continue
        subprocess.run(["git", "merge-base", "--is-ancestor", producer_sha, base], check=True)
        if git("diff", "--name-only", producer_sha, base, "--", *GUARDS):
            continue
        associations = recorded.get("pull_requests", [])
        valid = [p for p in associations if p.get("number") == pr["number"]
                 and p.get("head", {}).get("sha") == head
                 and p.get("base", {}).get("sha") == base
                 and p.get("base", {}).get("ref") == "main"]
        if len(valid) == 1 and recorded.get("event") == "pull_request" and recorded.get("head_sha") == head:
            return producer["id"]
    raise ValueError("no trusted completion receipt for this PR run and base")


def prove_pr(sha, repo, now=None):
    base, head, tree = merge_identity(sha)
    prs = api(f"repos/{repo}/commits/{sha}/pulls?per_page=100")
    matches = [pr for pr in prs if pr.get("merged_at") and pr.get("merge_commit_sha") == sha
               and pr.get("base", {}).get("ref") == "main"
               and pr.get("base", {}).get("sha") == base
               and pr.get("head", {}).get("sha") == head
               and pr.get("head", {}).get("repo", {}).get("full_name") == repo]
    if len(matches) != 1:
        raise ValueError("no unique same-repository merged PR")
    response = api(f"repos/{repo}/actions/workflows/ci.yml/runs?event=pull_request&head_sha={head}&per_page=100")
    run = newest_pr_run(response["workflow_runs"], head, repo)
    if not run or run.get("status") != "completed" or run.get("conclusion") != "success":
        raise ValueError("latest PR run did not succeed")
    finished = dt.datetime.fromisoformat(run["updated_at"].replace("Z", "+00:00"))
    now = now or dt.datetime.now(dt.timezone.utc)
    if not dt.timedelta(0) <= now - finished <= dt.timedelta(hours=24):
        raise ValueError("PR evidence is older than 24 hours or future-dated")
    if not all_jobs_passed(jobs_for(run, repo)):
        raise ValueError("PR did not execute all six acceptance jobs")
    receipt_id = receipt_for(run, matches[0], base, head, repo)
    return {"receipt_id": receipt_id, "run_id": run["id"], "attempt": run["run_attempt"], "head": head,
            "tree": tree, "url": run["html_url"]}


def plan(sha):
    proof = None
    for attempt in range(4):
        try:
            proof = prove_pr(sha, os.environ["GH_REPO"])
            break
        except (ValueError, KeyError, TypeError, OSError, zipfile.BadZipFile, subprocess.SubprocessError) as error:
            # A maintainer may merge immediately after CI completes, before the
            # independent default-branch receipt finishes. Bound that race.
            if str(error).startswith("no trusted completion receipt") and attempt < 3:
                time.sleep(20)
                continue
            print(f"Full acceptance required: {error}")
            break
    with open(os.environ["GITHUB_OUTPUT"], "a") as output:
        output.write(f"reuse={'true' if proof else 'false'}\n")
    if proof:
        message = f"Acceptance reused from {proof['url']} attempt {proof['attempt']}; tested head {proof['head']}, identical tree {proof['tree']}"
        print(message)
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as summary:
            summary.write(message + "\n")


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "plan":
        raise SystemExit("usage: ci-evidence.py plan COMMIT")
    plan(sys.argv[2])
