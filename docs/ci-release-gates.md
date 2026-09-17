# CI and release gates

## Normal path: acceptance once per unchanged merge result

| Event | Work |
| --- | --- |
| Draft PR opened or updated | Format, vet, build; evidence-policy regression tests; packaging when affected |
| PR marked ready or updated while ready | All six race/FIPS acceptance jobs, including real OpenBao and root separation |
| PR CI completes | Independent default-branch workflow records GitHub's completion event; no PR code execution |
| Main push after normal merge | Prove the tested source and test contract are unchanged; reuse or fall back to full acceptance |
| Release tag | Build and smoke-test four native packages; verify exact-commit main evidence, following its PR provenance if reused |
| Merge group | Full acceptance on the synthetic queue commit |
| Manual release workflow | Preview builds only; does not publish |

Keep related work in draft until ready for full acceptance. Draft-deferred jobs
have different names and cannot satisfy existing required checks. Ready PRs must
pass the same six check names and DCO, with the branch up to date. Only obsolete
PR runs cancel; main/queue work is not canceled by newer runs. No path-based bypass
makes documentation changes automatically pass acceptance.

## Source equivalence contract

A commit SHA difference alone does not require another full run. The initial
supported reuse case is a normal two-parent GitHub merge where:

1. The first parent is an ancestor of the tested PR head (second parent).
2. The whole Git tree of actual main equals that tested head, including every
   tracked file, mode, module manifest, lockfile, script and test.
3. The PR and main acceptance/provenance definitions are byte-identical to those
   already on the first parent. Changing a gate cannot authorize its own reuse.
4. GitHub identifies one same-repository PR merged into main with these commits.
5. Its newest CI run succeeded and each of the six required jobs actually ran
   successfully in the current attempt. Skipped, duplicate, missing or canceled
   jobs are not evidence. Evidence is at most 24 hours old when main validates it.
6. A trusted completion receipt confirms that this CI run targeted this base,
   not another branch with a different workflow.

PR acceptance explicitly checks out the head SHA recorded by GitHub's run API,
and rejects a head that does not include its event's base. This deliberately
avoids attempting to infer a now-deleted synthetic merge ref. With the base
included, its source tree is the merge result; main verifies that independently.

Acceptance removes `.git`, disables Go VCS stamping, and supplies an allowlisted
environment to tests. Tests therefore do not get branch/event/SHA metadata.
The existing build-info test checks the FIPS module, not VCS revision. No existing
Go test was found reading Git history or GitHub event metadata. A test requiring
those inputs must revise this contract, triggering full validation on that change.
Release binaries retain their ordinary packaging and version checks.

Squash/rebase merges, forks, conflicting or changed merge results, submodules,
Git attributes/filters (including LFS), changed workflow/evidence definitions,
stale or missing evidence, ambiguous associations and API errors fall back to
full acceptance. Full-tree identity is conservative: unrelated docs changes also
change the tree. Reuse does not claim a hermetic build: hosted runner images and
external services can change. The declared runner is Ubuntu 24.04, Go is selected
from the exact tracked module version, dependencies remain checksum-controlled,
and the 24-hour window bounds freshness. Scheduled external-drift qualification
would be separate work; this change reuses a source acceptance result.

## Trusted receipt and release chain

GitHub clears a completed run's PR associations after merge. Merely finding six
successful check names at a head SHA cannot prove which base/workflow was tested.
`acceptance-receipt.yml` runs only through `workflow_run` on the default branch.
It reads GitHub's server-supplied completion event and uploads a receipt. It
checks out no code, executes no PR code and consumes no PR artifacts or caches.
It has only read contents permission; the upload action uses its own runtime
artifact permission. There is no `pull_request_target` execution of PR code.

The main verifier only downloads the specifically named artifact from a completed
run of that producer workflow/event, checks artifact/run identity, limits size,
reads only receipt.json without extracting paths, and checks the producer's
workflow commit against trusted premerge definitions. It then independently
checks Git trees and live CI jobs. An unsigned artifact uploaded by the PR itself
cannot substitute for this receipt. The trust root remains reviewed default-
branch workflows and GitHub's API/artifact access controls, not arbitrary files
or check names supplied by PR authors. Deliberate compromise of trusted main
workflows is outside that boundary, as with the existing release publisher.

Main waits at most one minute for a receipt racing an immediate merge, then
runs full tests if proof is unavailable. Receipts retain for 90 days. A release
requires successful main CI at its exact tag commit. It accepts either six actual
main test successes or a successful main evidence gate plus an independently
reconstructed PR/receipt/tree chain. Reused tests are reported as provenance in
the main job summary; they are not relabeled as newly executed tests.

Receipt age is evaluated at the main run's start for later releases, not at the
release date. If old receipts were deleted or expired, rerun that main CI: absent
proof makes it execute full acceptance, which release can verify normally. An
API error or unknown state never authorizes publication. Binaries and checksums
are always built in the release run; no PR binary artifact is promoted.

The first merge introducing this contract must run full main acceptance: its
parent has neither the trusted receipt workflow nor the new contract. Subsequent
unchanged normal merges can use the fast path. The receipt workflow cannot be
exercised live from a draft PR until its initial reviewed merge installs it on
main; real-Git/API-fixture regressions cover both reuse and adversarial fallback.

## Merge queue

GitHub merge queues require an eligible organization-owned repository.
TrustedCourier is currently owned by the personal account potto007. Its active
Protect main ruleset requires all six checks, DCO and an up-to-date branch.
No settings were changed. `merge_group` is handled for future organization/queue
adoption, but no queue is assumed or enabled here.

## Cost and validation

On September 17, full PR runs 35243225122 and 35245239002 took 15m36s and
16m21s. Previously the ready PR, main push and release tag each ran acceptance.
The normal unchanged-tree path now runs it once on the ready PR; main checks
provenance and release checks that chain while building native archives. Fallback
cases rerun on main, but still avoid a third tag suite. Draft feedback measured
37 seconds for core, 18 seconds for SDK and 17 seconds for OpenBao in the first
revision's live CI. Packaging remains independently validated.

```sh
python3 scripts/test-ci-evidence.py
python3 scripts/test-wait-for-ci.py
actionlint .github/workflows/*.yml
```

References:
- [Strict required checks](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches)
- [Explicit PR head checkout](https://github.com/actions/checkout#checkout-pull-request-head-commit-instead-of-merge-commit)
- [workflow_run default-branch behavior](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#workflow_run)
- [Merge queue availability](https://docs.github.com/en/pull-requests/how-tos/merge-and-close-pull-requests/merging-a-pull-request-with-a-merge-queue)
