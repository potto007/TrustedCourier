#!/usr/bin/env python3
"""Exercise real Git merge identities with adversarial GitHub API fixtures."""
import copy
import datetime as dt
import json
import io
import zipfile
import os
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest
from unittest.mock import patch

code = runpy.run_path(str(Path(__file__).with_name("ci-evidence.py")))
REPO = "owner/repo"
NOW = dt.datetime(2026, 9, 17, tzinfo=dt.timezone.utc)


class MergeEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.old = os.getcwd()
        os.chdir(self.temp.name)
        self.addCleanup(os.chdir, self.old)
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.name", "Fixture")
        self.git("config", "user.email", "fixture@example.test")
        Path("scripts").mkdir()
        Path("scripts/ci-evidence.py").write_text("trusted contract")
        Path(".github/workflows").mkdir(parents=True)
        Path(".github/workflows/ci.yml").write_text("trusted workflow")
        Path(".github/workflows/acceptance-receipt.yml").write_text("trusted receipt producer")
        self.git("add", ".")
        self.git("commit", "-qm", "base")
        self.base = self.git("rev-parse", "HEAD")
        self.git("checkout", "-qb", "feature")
        Path("code.txt").write_text("new source")
        self.git("add", ".")
        self.git("commit", "-qm", "feature")
        self.head = self.git("rev-parse", "HEAD")
        self.merge()
        self.pr = dict(number=1, merged_at="2026-09-17T00:00:00Z", merge_commit_sha=self.sha,
                       base=dict(ref="main", sha=self.base),
                       head=dict(sha=self.head, repo=dict(full_name=REPO)))
        self.run = dict(id=10, run_attempt=2, event="pull_request", head_sha=self.head,
                        path=".github/workflows/ci.yml", head_repository=dict(full_name=REPO),
                        status="completed", conclusion="success", updated_at="2026-09-17T00:00:00Z",
                        html_url="https://example.test/run/10")
        self.jobs = [dict(name=n, status="completed", conclusion="success") for n in code["REQUIRED"]]

    def git(self, *args):
        return subprocess.check_output(["git", *args], text=True, stderr=subprocess.DEVNULL).strip()

    def merge(self):
        self.git("checkout", "-q", "main")
        self.git("merge", "--no-ff", "-qm", "merge", "feature")
        self.sha = self.git("rev-parse", "HEAD")

    def api(self, path):
        if "acceptance-receipt.yml/runs?" in path:
            return {"workflow_runs": [dict(id=20, event="workflow_run", path=".github/workflows/acceptance-receipt.yml", status="completed", conclusion="success")]}
        if "/artifacts?" in path:
            return {"artifacts": [dict(id=30, name="acceptance-10-2", size_in_bytes=1000, expired=False, workflow_run=dict(id=20))]}
        if "/pulls?" in path:
            return [self.pr]
        if "/runs?" in path:
            return {"workflow_runs": [self.run]}
        self.assertIn("/attempts/2/jobs?", path)
        return {"total_count": len(self.jobs), "jobs": self.jobs}

    def archive(self):
        run = dict(self.run, pull_requests=[dict(number=1, head=dict(sha=self.head), base=dict(sha=self.base, ref="main"))])
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w") as archive:
            archive.writestr("receipt.json", json.dumps(dict(producer_sha=self.base, run=run)))
        return out.getvalue()

    def prove(self, now=NOW):
        original = subprocess.check_output
        def output(args, **kwargs):
            if args[0] == "gh" and args[-1].endswith("/zip"):
                return self.archive()
            return original(args, **kwargs)
        with patch("subprocess.check_output", side_effect=output), patch.dict(code["prove_pr"].__globals__, {"api": self.api}):
            return code["prove_pr"](self.sha, REPO, now=now)

    def test_distinct_commit_identical_tree_reuses(self):
        self.assertNotEqual(self.sha, self.head)
        self.assertEqual(self.prove()["tree"], self.git("rev-parse", "HEAD^{tree}"))

    def test_pr_finishing_after_main_start_valid_at_gate_completion(self):
        self.run["updated_at"] = "2026-09-17T00:00:02Z"
        with self.assertRaisesRegex(ValueError, "future-dated"):
            self.prove(now=NOW)
        self.assertEqual(self.prove(now=NOW + dt.timedelta(seconds=5))["run_id"], 10)

    def test_different_tree_falls_back(self):
        Path("code.txt").write_text("different merge result")
        self.git("add", ".")
        self.git("commit", "--amend", "--no-edit", "-q")
        self.sha = self.git("rev-parse", "HEAD")
        with self.assertRaisesRegex(ValueError, "different source trees"):
            self.prove()

    def test_changed_workflow_rejected_even_when_trees_match(self):
        self.git("reset", "--hard", self.base)
        self.git("checkout", "-q", "feature")
        Path(".github/workflows/ci.yml").write_text("fake pass")
        self.git("add", ".")
        self.git("commit", "-qm", "change checks")
        self.merge()
        with self.assertRaisesRegex(ValueError, "definitions changed"):
            self.prove()

    def test_squash_and_rebase_fall_back(self):
        self.sha = self.head
        with self.assertRaisesRegex(ValueError, "two-parent"):
            self.prove()

    def test_filter_or_submodule_inputs_fall_back(self):
        self.git("reset", "--hard", self.base)
        self.git("checkout", "-q", "feature")
        Path(".gitattributes").write_text("*.dat filter=lfs")
        self.git("add", ".")
        self.git("commit", "-qm", "add filter")
        self.merge()
        with self.assertRaisesRegex(ValueError, "submodule/filter"):
            self.prove()

    def test_external_symlink_rejected(self):
        self.git("reset", "--hard", self.base)
        self.git("checkout", "-q", "feature")
        Path("external").symlink_to("/outside-input")
        self.git("add", ".")
        self.git("commit", "-qm", "add external input")
        self.merge()
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.prove()

    def test_deleted_fork_metadata_falls_back(self):
        self.pr["head"]["repo"] = None
        with self.assertRaisesRegex(ValueError, "unique"):
            self.prove()

    def test_fork_wrong_sha_wrong_workflow_and_event_rejected(self):
        for key, value in [("head_repository", {"full_name": "fork/repo"}),
                           ("head_sha", "a" * 40), ("event", "push"),
                           ("path", ".github/workflows/fake.yml")]:
            with self.subTest(key=key):
                original = copy.deepcopy(self.run)
                self.run[key] = value
                with self.assertRaises(ValueError): self.prove()
                self.run = original
        self.pr["head"]["repo"]["full_name"] = "fork/repo"
        with self.assertRaisesRegex(ValueError, "unique"):
            self.prove()

    def test_failed_skipped_missing_and_stale_evidence_rejected(self):
        self.run["conclusion"] = "failure"
        with self.assertRaises(ValueError): self.prove()
        self.run["conclusion"] = "success"
        self.jobs[0]["conclusion"] = "skipped"
        with self.assertRaises(ValueError): self.prove()
        self.jobs.pop(0)
        with self.assertRaises(ValueError): self.prove()
        self.run["updated_at"] = "2026-09-15T00:00:00Z"
        with self.assertRaisesRegex(ValueError, "24 hours"): self.prove()

    def test_receipt_with_wrong_base_or_attempt_rejected(self):
        original_archive = self.archive
        def altered_archive():
            with zipfile.ZipFile(io.BytesIO(original_archive())) as z:
                receipt = json.loads(z.read("receipt.json"))
            receipt["run"]["pull_requests"][0]["base"]["sha"] = "b" * 40
            out = io.BytesIO()
            with zipfile.ZipFile(out, "w") as z:
                z.writestr("receipt.json", json.dumps(receipt))
            return out.getvalue()
        with patch.object(self, "archive", side_effect=altered_archive):
            with self.assertRaisesRegex(ValueError, "trusted completion receipt"):
                self.prove()

    def test_receipt_from_wrong_workflow_event_rejected(self):
        original_api = self.api
        def altered_api(path):
            result = original_api(path)
            if "acceptance-receipt.yml/runs?" in path:
                result["workflow_runs"][0]["event"] = "pull_request"
            return result
        with patch.object(self, "api", side_effect=altered_api):
            with self.assertRaisesRegex(ValueError, "trusted completion receipt"):
                self.prove()

    def test_api_failure_produces_full_test_plan(self):
        with tempfile.TemporaryDirectory() as outputs:
            target = str(Path(outputs)/"output")
            with patch.dict(code["plan"].__globals__, {"prove_pr": lambda *_: (_ for _ in ()).throw(subprocess.CalledProcessError(1, "gh"))}), \
                 patch.dict(os.environ, GH_REPO=REPO, GITHUB_OUTPUT=target):
                code["plan"](self.sha)
            self.assertEqual(Path(target).read_text(), "reuse=false\n")


if __name__ == "__main__":
    unittest.main()
