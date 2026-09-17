#!/usr/bin/env python3
import copy
import runpy
import unittest
from unittest.mock import patch
from pathlib import Path

code = runpy.run_path(str(Path(__file__).with_name("wait-for-ci.py")))
select_run, passed_jobs = code["select_run"], code["passed_jobs"]
SHA, REPO = "a" * 40, "owner/repo"


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.run = dict(id=10, head_sha=SHA, event="push", head_branch="main",
                        path=".github/workflows/ci.yml", head_repository={"full_name": REPO})
        self.jobs = [dict(name=name, status="completed", conclusion="success") for name in code["REQUIRED"]]

    def test_exact_main_only(self):
        self.assertEqual(select_run([self.run], SHA, REPO), self.run)
        for field, value in [("head_sha", "b" * 40), ("event", "pull_request"),
                             ("event", "merge_group"), ("head_branch", "feature"),
                             ("path", ".github/workflows/other.yml"),
                             ("head_repository", {"full_name": "fork/repo"})]:
            with self.subTest(field=field, value=value):
                candidate = dict(self.run, **{field: value})
                self.assertIsNone(select_run([candidate], SHA, REPO))

    def test_latest_attempt_run_not_old_success(self):
        newer = dict(self.run, id=11, conclusion="failure")
        self.assertEqual(select_run([newer, self.run], SHA, REPO), newer)

    def test_all_jobs_required(self):
        self.assertTrue(passed_jobs(self.jobs))
        self.assertFalse(passed_jobs([]))
        self.assertFalse(passed_jobs(self.jobs[:-1]))
        self.assertFalse(passed_jobs(self.jobs + [self.jobs[0]]))
        for conclusion in ("skipped", "failure", "cancelled", None):
            altered = copy.deepcopy(self.jobs)
            altered[0]["conclusion"] = conclusion
            self.assertFalse(passed_jobs(altered))
        altered = copy.deepcopy(self.jobs)
        altered[0]["status"] = "in_progress"
        self.assertFalse(passed_jobs(altered))

    def invoke(self, response, jobs, clock=(0, 1)):
        run_api = iter([response, jobs])
        with patch.dict(code["main"].__globals__, {"api": lambda path: next(run_api)}), \
             patch.dict("os.environ", {"GH_REPO": REPO}), \
             patch("sys.argv", ["wait-for-ci.py", SHA]), \
             patch("time.monotonic", side_effect=clock):
            code["main"]()

    def test_successful_run_checks_current_attempt(self):
        completed = dict(self.run, status="completed", conclusion="success", run_attempt=2, html_url="https://example.test/run")
        paths = []
        def fake_api(path):
            paths.append(path)
            if len(paths) == 1:
                return {"workflow_runs": [completed]}
            return {"total_count": len(self.jobs), "jobs": self.jobs}
        with patch.dict(code["main"].__globals__, {"api": fake_api}), \
             patch.dict("os.environ", {"GH_REPO": REPO}), \
             patch("sys.argv", ["wait-for-ci.py", SHA]):
            code["main"]()
        self.assertIn("/attempts/2/jobs?", paths[1])

    def test_failed_run_and_truncated_jobs_fail_closed(self):
        completed = dict(self.run, status="completed", conclusion="failure", run_attempt=1, html_url="https://example.test/run")
        with self.assertRaises(SystemExit):
            self.invoke({"workflow_runs": [completed]}, {})
        completed["conclusion"] = "success"
        with self.assertRaises(SystemExit):
            self.invoke({"workflow_runs": [completed]}, {"total_count": 1000, "jobs": self.jobs})

    def test_main_reuse_requires_reconstructed_chain(self):
        completed = dict(self.run, status="completed", conclusion="success", run_attempt=1,
                         created_at="2026-09-17T00:00:00Z", html_url="https://example.test/main")
        jobs = {"total_count": 1, "jobs": [dict(name="acceptance evidence", status="completed", conclusion="success", completed_at="2026-09-17T00:00:05Z")]}
        calls = []
        def proof(sha, repo, now):
            calls.append((sha, repo, now.isoformat()))
            return {"url": "https://example.test/pr"}
        with patch("runpy.run_path", return_value={"prove_pr": proof}):
            self.invoke({"workflow_runs": [completed]}, jobs)
        self.assertEqual(calls, [(SHA, REPO, "2026-09-17T00:00:05+00:00")])
        def reject(*args, **kwargs):
            raise ValueError("forged provenance")
        with patch("runpy.run_path", return_value={"prove_pr": reject}), self.assertRaises(ValueError):
            self.invoke({"workflow_runs": [completed]}, jobs)

    def test_missing_evidence_times_out(self):
        with patch("time.sleep"), self.assertRaisesRegex(SystemExit, "No completed exact-commit"):
            self.invoke({"workflow_runs": []}, {}, clock=(0, 1, 2500))


if __name__ == "__main__":
    unittest.main()
