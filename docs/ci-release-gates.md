# CI and release gates

## Current pipeline

| Event | Work | Safety gate |
| --- | --- | --- |
| Draft PR opened or updated | Format, vet, build in all three modules; evidence-policy tests; release packaging when affected | Drafts cannot merge; deferred jobs have different names and do not satisfy required tests |
| PR ready for review or updated while ready | Full race, FIPS off/on, real OpenBao, and root user-separation tests | Existing six required checks and strict up-to-date rules |
| Merge group (if supported in the future) | Same full suite against the queue's synthetic commit | Same six required names |
| Main push | Full suite against the actual resulting commit | Records trustworthy release evidence for that commit |
| Release tag | Four native builds, packaging and smoke tests; wait for exact-commit main CI | All six main jobs must have actually succeeded before publication |
| Manual release workflow | Preview builds and assembly only | Does not publish, preserving existing behavior |

Keep a PR in draft while assembling related changes, including DCO and release
policy updates. Mark it ready once those changes are complete. Moving it back to
draft stops obsolete PR work and restores cheap feedback. Ready PR updates still
run all tests: there is no path-based or docs-only bypass of the merge gate.
Only obsolete PR runs are canceled. Main and merge-group validation are never
canceled by a newer PR or main push. Required checks retain their existing names;
draft-deferred checks deliberately do not use those names.

## Why not a merge queue now?

GitHub's merge queue is available for organization-owned public repositories
(and eligible organization private repositories). TrustedCourier is currently
owned by the personal account `potto007`. Its active Protect main ruleset requires
the six module/FIPS checks, DCO, and an up-to-date branch. No settings were changed.

The fallback retains full premerge testing and separately verifies the resulting
main commit. These commits can differ, especially for squash/rebase or concurrent
merges; a previous PR success alone does not prove the merge result is good.
Removing that validation requires stronger evidence, not a check-name shortcut.

If the repository moves to an eligible organization, `merge_group` is already
handled. Enabling a queue and changing when acceptance runs is a separate ruleset
migration: verify the required check contexts on both PR and merge-group events
before moving the expensive gate. This change does not pretend that queue support
is currently enabled or defer ready-PR acceptance to postmerge.

## Release evidence

The tag is resolved to a commit, still required to be an ancestor of main.
`scripts/wait-for-ci.py` looks up the CI workflow for that exact commit and accepts
only a `push` to `main` from this repository using `.github/workflows/ci.yml`.
It selects the newest matching run, waits up to 40 minutes, and checks the actual
jobs of that run attempt. All six names must appear exactly once, completed and
successful. Skips, failures, missing jobs, forks, PR checks, and another commit's
success do not count. API errors fail closed. The release never downloads or
executes artifacts from the earlier CI run; binaries and checksums are built in
the release run as before.

If evidence is absent (for example, CI was skipped on the main commit), the
release fails. Rerun an existing main push CI run for that exact commit, then rerun the release.
If no such run exists, do not waive the gate: prepare a new reviewed main commit
and release tag that receive normal push CI.
A tag on an older commit requires successful evidence for that older commit;
success on the latest main is insufficient. Deleted or inaccessible evidence is
not a reason to waive the gate. Workflow edits remain trusted only through the
repository's review and merge protections; this is not protection against a
maintainer deliberately replacing those protections or workflows.

The six checks preserve the existing release test coverage. The workflow-policy
regressions also run in CI. Native platform smoke tests and same-run assembly
checks remain mandatory. No release tags, settings, credentials, or current runs
were modified as part of implementing this change.

## Cost and validation

On September 17, 2026, full PR runs 35243225122 and 35245239002 took 15m36s
and 16m21s respectively. The old release then ran the same six suites again
alongside main CI. Waiting on exact-commit main CI removes that duplicate workload;
when main CI is already complete, release publication only waits for packaging.
It does not promise zero latency when main CI has just started.

Draft feedback also prevents repeated 15-minute acceptance runs during work in
progress. Four native packaging builds remain on relevant release PR changes,
since cross-platform packaging is not covered by the Linux test matrix.

Local workflow validation:

```sh
python3 scripts/test-wait-for-ci.py
actionlint .github/workflows/ci.yml .github/workflows/release.yml
```

References:
- [GitHub merge queue availability](https://docs.github.com/en/pull-requests/how-tos/merge-and-close-pull-requests/merging-a-pull-request-with-a-merge-queue)
- [Merge queue and merge_group checks](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/configuring-pull-request-merges/managing-a-merge-queue)
