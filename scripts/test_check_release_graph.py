#!/usr/bin/env python3
"""Expectations for scripts/check-release-graph.py (F07), written before the checker.

The checker is a STRUCTURAL check of the workflow graph, run locally. It runs no
workflow (act needs docker); it proves the shape of ci.yml and release.yml, not
that GitHub behaves. Interface the builder must implement:

    python3 scripts/check-release-graph.py <root>

where <root> holds .github/workflows/ci.yml, .github/workflows/release.yml,
rust-toolchain.toml and docs/RELEASE_CHECKLIST.md. Exit 0 when every rule holds.
Otherwise exit 1 and print one line per violation containing the rule id on
stdout or stderr. The pass output says repository settings are not checked.

THE SHAPE (round 3, from the independent check Y1-Y3)

release.yml is a workflow_dispatch workflow meant to run on main, taking the
input `tag`. No workflow that a tag push (or any push) starts can publish,
because a tag push reads the workflow files from the tagged commit, which
anyone with write access can choose. Jobs: on-main -> quality -> build-release
-> verify-artifacts -> publish-release (environment release). Every job but
on-main needs on-main, directly or through other jobs.

GATE STEPS. A "gate step" is a step whose run script is a gate: in ci.yml the
`cargo fmt`, `cargo clippy` and `cargo test` steps, and in release.yml every
step of the on-main job except its checkout. The run script of a gate step is
exactly one command on one line, optionally preceded by a first line that is
only `set -euo pipefail`. Anything else (a second command, here-doc, `&&`,
`||`, `;`, a pipe, `if`, `exit`, a comment line) fails gate-step-shape. The
verify and package steps are not gate steps (they may loop). A step that fails
gate-step-shape is reported ONLY under gate-step-shape; it still counts as
carrying its command for the presence rules below, so one defect gives one
finding.

Rule ids kept from rounds 1-2: no-quality-gate, quality-job-uncovered,
not-tagged-commit, unpinned-action, toolchain-not-exact, no-artifact-verification,
verification-after-publish, no-on-main-gate, job-skips-on-main-gate,
publish-no-release-environment, no-build-provenance, provenance-not-verified,
attestation-permissions-misplaced, prerelease-not-from-tag.

Rule ids new in round 3:
  publish-reachable-from-push  a workflow with a push (any filter), pull_request
                           or other non-dispatch, non-workflow_call trigger that
                           contains a publishing job (softprops/action-gh-release,
                           `gh release create`, or `environment: release`).
                           release.yml's only triggers are workflow_dispatch.
  no-main-ref-check        the on-main job lacks a gate step whose one command
                           compares $GITHUB_REF (or ${{ github.ref }}) with
                           refs/heads/main and fails otherwise (`test` / `[ ]`
                           / `[[ ]]`); an echo of it or another ref is a miss.
  no-on-main-gate          (changed meaning) the on-main job lacks the git fetch
                           ... main step or the `git merge-base --is-ancestor
                           <the tag's commit> origin/main` step, each as a
                           gate step. Swallowed failures (|| true, exit 0) are
                           no longer this rule: they are gate-step-shape.
  on-main-shallow          the on-main job's checkout lacks `fetch-depth: 0`.
  quality-not-on-tag       main's gate does not run on the input tag: ci.yml has
                           workflow_call but no `inputs.ref` input, or a checkout
                           in ci.yml lacks `ref: ${{ inputs.ref }}`, or release.yml's
                           quality job does not pass `with: ref: ${{ inputs.tag }}`.
                           Judged only when ci.yml is reusable (else
                           quality-job-uncovered alone).
  not-tagged-commit        (widened) any checkout in release.yml with a ref other
                           than ${{ inputs.tag }}, or build-release's checkout
                           without a ref (it would build main, not the tag).
  attestation-verify-unscoped  a `gh attestation verify` lacks --signer-workflow
                           <repo>/.github/workflows/release.yml, or lacks
                           --source-ref refs/heads/main, or gives another ref.
  attest-subject-not-archive  the attest step's subject-path is not the path
                           the Package step's `tar -czf` writes.
  gate-step-shape          see GATE STEPS.
  tag-pattern-mismatch     the glob in the on-main step `[[ "$TAG" == <glob> ]]`
                           differs from the one on the "Tag ruleset pattern:"
                           line of docs/RELEASE_CHECKLIST.md.

A "comment" fake of a quality command is `run: "true" # <command>`: one command
(true) with the quality command only in a YAML comment, so it trips
quality-job-uncovered alone.

Deliberate change to the eval (round 3): bad-on-main-gate-or-true used to expect
no-on-main-gate; swallowing a failure is now gate-step-shape for every gate
step, so it expects that. The old multi-line "# comment, then cargo test" Tests
step in the good fixtures became one line, because a comment line is no longer
an allowed shape.

The checker cannot see repository settings. docs/RELEASE_CHECKLIST.md says which
are load-bearing (environment release with required reviewers AND deployment
branches limited to main; branch protection on main; a tag ruleset) and why.

Each bad fixture must trip its own rule and no other. Fixture action SHAs are
made-up 40-hex placeholders: the checker checks form, not that the commit exists.

ROUND 4 (the independent check's Z1-Z6, closed by the suite PM)
  gate-step-shell          a gate step with any `shell:` other than none or bash, or
                           a gate-holding job (on-main; ci.yml's test job) or the
                           workflow with `defaults.run.shell` other than bash (Z1).
  gate-continue-on-error   `continue-on-error` that is not the literal false (an
                           expression such as ${{ true }} counts) on a gate step, a
                           gate-holding job, or publish-release (Z2).
  gate-env-override        an `env` name that is GITHUB_*, GIT_*, PATH, or GH_* other
                           than GH_TOKEN, at step, job or workflow level on a gate
                           step or its job or the workflow; or `working-directory`
                           on a gate step (Z3).
  release-graph-job-incomplete  ci.yml's `release-graph` job is absent or lacks the
                           checker step or the checker's-own-tests step, each a gate
                           step (Z5). Every fixture's ci.yml now carries that job.
  Z4 reuses rules: extra flags on `gh attestation verify` (--bundle,
  --cert-oidc-issuer) -> attestation-verify-unscoped; verifying the .sha256 file
  instead of the archive -> provenance-not-verified; a bare `$TAG` or
  `refs/tags/$TAG` (no ^{commit}) in the ancestor check, and `git fetch --dry-run`
  -> no-on-main-gate. Z6 is the checklist test in RealRepo.
Good fixture good-gate-shell-bash-and-gh-token: `shell: bash`, defaults shell bash
and env GH_TOKEN on the gate side must still pass.
ROUND 4 FINAL (W1-W6). New rule ids:
  chain-job-continue-on-error  `continue-on-error` on a whole job of the publish chain
                           (on-main, quality, ci.yml's quality jobs, build-release,
                           verify-artifacts, publish-release) must be absent or the
                           literal false; true and expressions (${{ false }}) fail (W1).
  gate-writes-env-file     any mention of GITHUB_ENV or GITHUB_PATH in a run script of a
                           gate job (W2).
  gate-job-environment     a gate job with container:, services:, a runs-on outside
                           GitHub-hosted labels (ubuntu-*, macos-*, windows-*, or matrix
                           values that are all such), or a timeout-minutes that is not a
                           positive number (W3).
  release-graph-command-inexact  the release-graph job's checker step is not exactly
                           `python3 scripts/check-release-graph.py .` or its tests step
                           not exactly `python3 -m unittest scripts/test_check_release_graph.py` (W4).
  ci-no-pull-request-trigger     ci.yml lacks its pull_request trigger (W4).
W2's allowlist keeps the id gate-env-override: gate steps, gate jobs and the workflow
may set no env except GH_TOKEN (as ${{ github.token }}) and, in release.yml at workflow
level, TAG (as ${{ inputs.tag }}). Anything else, a different GH_TOKEN or TAG value, or
TAG anywhere else, trips it.
DELIBERATE FIXTURE CHANGE: the allowlist forbids workflow-level env in ci.yml, so the
`env: CARGO_TERM_COLOR` block was removed from every fixture's ci.yml (the real ci.yml
must lose it too). No expectation was loosened.
DELIBERATE EVAL CHANGES (W5, GitHub's labels): "Deployment branches and tags" ->
"Deployment branches"; the immutable-releases click path is now "Settings, scroll to
Releases, select Enable release immutability" (no "General").

ROUND 6 (the independent review H1, M2, M3-M4 and L5-L8, closed by the suite PM)
DELIBERATE EVAL CHANGE (H1): the gate resolves refs/tags/$TAG^{commit}, but a checkout of
the bare `${{ inputs.tag }}` prefers a BRANCH of that name (the pinned actions/checkout
tries origin/<ref> first). A writer pushes branch v0.1.0 with bad code beside tag v0.1.0
on a main ancestor, dispatches from main, the gate passes, and quality and build use the
branch. So on-main now resolves the tag ONCE, as the job output `sha`, and the commit
used everywhere is that output. Meaning changes, applied to every fixture:
  on-main                  has `outputs: sha: ${{ steps.resolve.outputs.sha }}` and, as its
                           last step (a gate step), `id: resolve` running exactly
                           echo "sha=$(git rev-parse "refs/tags/$TAG^{commit}")" >> "$GITHUB_OUTPUT"
  quality / build checkout ref is `${{ needs.on-main.outputs.sha }}` (quality-not-on-tag
                           and not-tagged-commit now mean "not that expression"; a
                           missing ref stays what it was)
No expectation was loosened: the old good ref (the bare tag) is now the shadowing bug.
New rule ids:
  tag-ref-shadowable       any `ref:` in release.yml (the quality `with:` or a checkout)
                           that is the bare `${{ inputs.tag }}`. Other wrong refs stay
                           not-tagged-commit.
  on-main-no-sha-output    on-main lacks the `sha` job output, or the resolve step is not
                           the tag's commit (`git rev-parse refs/tags/$TAG^{commit}`
                           written to $GITHUB_OUTPUT; $GITHUB_SHA is main's HEAD, a miss).
  publish-no-tag-recheck   (M2) publish-release lacks, before its release step, two gate
                           steps: `git fetch ... --tags ...` and one comparing
                           `git rev-parse "refs/tags/$TAG^{commit}"` with
                           `${{ needs.on-main.outputs.sha }}` (test / [ ] / [[ ]]).
  release-before-tag-recheck  the recheck exists but a release step (softprops, so its
                           tag_name) comes before it.
  archive-includes-test-fixtures  (L7) the Package step copies the scripts directory
                           (`cp -r scripts`) and does not drop test-fixtures (an rm -rf
                           of it, or tar --exclude naming it). Judged only when the step
                           copies scripts.
  tag-check-loose         (L8) the on-main tag-name check is not exactly
                           [[ "$TAG" =~ ^v[0-9]+\\.[0-9]+\\.[0-9]+(-[A-Za-z0-9.]+)?$ ]]. Order:
                           if the workflow's pattern differs from the checklist's "Tag name
                           check:" line that is tag-pattern-mismatch ONLY; if they agree and
                           are not the required regex, that is tag-check-loose.
DELIBERATE EVAL CHANGE (L8): tag-pattern-mismatch now compares the workflow's pattern with
the checklist's "Tag name check:" line (the regex), not the "Tag ruleset pattern:" line:
GitHub's ruleset pattern is a glob (`v*.*.*`) that cannot hold the regex, so it stays,
broader, as the line the RealRepo test still wants. The two mismatch fixtures were updated.

ROUND 7 (the independent check S1-S3). New rule ids, one bad fixture each (two for the first):
  needs-output-not-direct  a job (a `uses:` caller included) reads needs.<job>.outputs.* but
                           does not list <job> directly in its own `needs`. GitHub's needs
                           context holds direct dependencies only, so the value is an empty
                           string and a checkout falls back to main's head. Fixtures (verify-artifacts reads it with needs
                           build-release only; the quality one also trips no-quality-gate, see ALSO): build-release
                           needs only quality; quality needs a middle job instead of on-main.
  build-checkout-unasserted  build-release lacks, after its checkout, a gate step
                           test "$(git rev-parse HEAD)" = "${{ needs.on-main.outputs.sha }}".
  ci-checkout-unasserted   ci.yml has a checkout not followed by a gate step
                           test "$(git rev-parse HEAD)" = "${{ inputs.ref }}" (the fixtures give it
                           `if: inputs.ref != ''` so pushes and pull requests, where ref is empty,
                           skip it; the builder may choose the single-job alternative, in which
                           case the fixtures change as their own deliberate eval change).
  sha-shape-unasserted     on-main lacks, after the resolve step, a gate step asserting the output
                           matches ^[0-9a-f]{40}$ (echo "sha=$(...)" succeeds even when rev-parse
                           fails, so an empty or garbage sha would pass through).
  target-commitish-not-sha softprops `target_commitish` is absent or is not
                           ${{ needs.on-main.outputs.sha }} (the fixture with `main` is the bad one).
Every fixture's workflows were updated mechanically to carry the new asserts and the
target_commitish line; no expectation was loosened.
Run: python3 -m unittest scripts/test_check_release_graph.py
"""
import re
import subprocess
import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
REPO = SCRIPTS.parent
CHECKER = SCRIPTS / "check-release-graph.py"
FIX = SCRIPTS / "test-fixtures" / "release-graph"
RULES = ["no-quality-gate", "quality-job-uncovered", "not-tagged-commit",
         "unpinned-action", "toolchain-not-exact", "no-artifact-verification",
         "verification-after-publish", "no-on-main-gate", "job-skips-on-main-gate",
         "publish-no-release-environment", "no-build-provenance",
         "provenance-not-verified", "attestation-permissions-misplaced",
         "prerelease-not-from-tag",
         "publish-reachable-from-push", "no-main-ref-check", "on-main-shallow",
         "quality-not-on-tag", "attestation-verify-unscoped",
         "attest-subject-not-archive", "gate-step-shape", "tag-pattern-mismatch",
         "gate-step-shell", "gate-continue-on-error", "gate-env-override",
         "release-graph-job-incomplete",
         "chain-job-continue-on-error", "gate-writes-env-file", "gate-job-environment",
         "release-graph-command-inexact", "ci-no-pull-request-trigger",
         "tag-ref-shadowable", "on-main-no-sha-output", "publish-no-tag-recheck",
         "release-before-tag-recheck", "archive-includes-test-fixtures", "tag-check-loose",
         "needs-output-not-direct", "build-checkout-unasserted", "ci-checkout-unasserted",
         "sha-shape-unasserted", "target-commitish-not-sha"]
PINNED_TOOLCHAIN = "1.98.1"  # hetzner and the Pi both report rustc 1.98.1

# fixture directory -> the one rule it must trip
BAD = {
    # round 1
    "bad-publish-without-quality": "no-quality-gate",
    "bad-quality-job-uncovered": "quality-job-uncovered",
    "bad-quality-not-reusable": "quality-job-uncovered",
    "bad-not-tagged-commit": "not-tagged-commit",
    "bad-build-checkout-without-ref": "not-tagged-commit",
    "bad-action-pinned-by-tag": "unpinned-action",
    "bad-ci-action-pinned-by-tag": "unpinned-action",
    "bad-toolchain-channel-file": "toolchain-not-exact",
    "bad-toolchain-channel-workflow": "toolchain-not-exact",
    "bad-no-verification": "no-artifact-verification",
    "bad-verification-after-publish": "verification-after-publish",
    # round 2, ported to the dispatch shape
    "bad-no-on-main-gate": "no-on-main-gate",
    "bad-no-ancestor-check": "no-on-main-gate",
    "bad-on-main-gate-echo": "no-on-main-gate",
    "bad-job-skips-on-main-gate": "job-skips-on-main-gate",
    "bad-publish-without-environment": "publish-no-release-environment",
    "bad-publish-wrong-environment": "publish-no-release-environment",
    "bad-no-provenance-attestation": "no-build-provenance",
    "bad-publish-without-attestation-verify": "provenance-not-verified",
    "bad-verify-artifacts-without-attestation-verify": "provenance-not-verified",
    "bad-attestation-verify-after-release": "provenance-not-verified",
    "bad-attestation-permissions-top-level": "attestation-permissions-misplaced",
    "bad-attestation-permissions-on-publish": "attestation-permissions-misplaced",
    "bad-attestation-permissions-only-on-publish": "attestation-permissions-misplaced",
    "bad-prerelease-constant-false": "prerelease-not-from-tag",
    "bad-prerelease-absent": "prerelease-not-from-tag",
    # Y1: a tag push must not be able to publish; main's gate runs on the tag
    "bad-tag-push-trigger-on-release": "publish-reachable-from-push",
    "bad-no-main-ref-check": "no-main-ref-check",
    "bad-main-ref-check-echo": "no-main-ref-check",
    "bad-main-ref-check-wrong-ref": "no-main-ref-check",
    "bad-quality-ci-without-ref-input": "quality-not-on-tag",
    "bad-quality-ci-checkout-ignores-ref": "quality-not-on-tag",
    "bad-quality-call-without-ref": "quality-not-on-tag",
    "bad-verify-without-signer-workflow": "attestation-verify-unscoped",
    "bad-verify-without-source-ref": "attestation-verify-unscoped",
    "bad-verify-source-ref-wrong": "attestation-verify-unscoped",
    "bad-prerelease-from-ref-name": "prerelease-not-from-tag",
    # Y2: every gate step is exactly one command
    "bad-gate-heredoc": "gate-step-shape",
    "bad-gate-false-and": "gate-step-shape",
    "bad-gate-if-false": "gate-step-shape",
    "bad-gate-exit-0-before": "gate-step-shape",
    "bad-gate-exit-0-after": "gate-step-shape",
    "bad-gate-semicolon-true": "gate-step-shape",
    "bad-gate-two-commands": "gate-step-shape",
    "bad-on-main-gate-or-true": "gate-step-shape",
    "bad-on-main-gate-exit-0-after": "gate-step-shape",
    "bad-main-ref-check-semicolon-true": "gate-step-shape",
    # Y3
    "bad-on-main-shallow-checkout": "on-main-shallow",
    "bad-attest-subject-checksum-file": "attest-subject-not-archive",
    "bad-attest-subject-binary": "attest-subject-not-archive",
    "bad-tag-pattern-checklist-differs": "tag-pattern-mismatch",
    "bad-tag-pattern-workflow-differs": "tag-pattern-mismatch",
}
# Z1: no custom shell on a gate step or in a gate job's or the workflow's defaults
for _c in ("bad-gate-step-shell-release", "bad-gate-step-shell-ci", "bad-gate-job-default-shell",
           "bad-gate-job-default-shell-ci", "bad-gate-workflow-default-shell"):
    BAD[_c] = "gate-step-shell"
# Z2: continue-on-error as an expression
for _c in ("bad-coe-expression-gate-step-release", "bad-coe-expression-gate-step-ci",
           "bad-coe-expression-gate-job-release", "bad-coe-expression-gate-job-ci",
           "bad-coe-expression-publish"):
    BAD[_c] = "gate-continue-on-error"
# Z3: env overrides at step, job and workflow level; working-directory on a gate step
for _n in ("github-ref", "path", "git-dir", "gh-host"):
    for _lvl in ("step", "job", "workflow"):
        BAD[f"bad-env-{_n}-{_lvl}"] = "gate-env-override"
BAD["bad-gate-working-directory"] = "gate-env-override"
# Z4
BAD["bad-verify-extra-flag-bundle"] = "attestation-verify-unscoped"
BAD["bad-verify-extra-flag-cert-oidc-issuer"] = "attestation-verify-unscoped"
BAD["bad-verify-target-sha256"] = "provenance-not-verified"
BAD["bad-ancestor-bare-tag-name"] = "no-on-main-gate"
BAD["bad-ancestor-tag-ref-not-commit"] = "no-on-main-gate"
BAD["bad-fetch-dry-run"] = "no-on-main-gate"
# Z5
for _c in ("bad-ci-release-graph-without-checker", "bad-ci-release-graph-without-tests",
           "bad-ci-release-graph-job-absent"):
    BAD[_c] = "release-graph-job-incomplete"
# X2 fakes: a quality command that is only an echo, printf, comment or string
for _tool in ("fmt", "clippy", "test"):
    for _disguise in ("echo", "printf", "comment", "quoted"):
        BAD[f"bad-fake-{_tool}-{_disguise}"] = "quality-job-uncovered"

# W1: continue-on-error on a whole chain job (literal true, or an expression). Release's
# quality and on-main jobs and ci.yml's quality jobs are already caught by older rules.
for _c in ("bad-chain-coe-build-release", "bad-chain-coe-verify-artifacts",
           "bad-chain-coe-expression-build-release"):
    BAD[_c] = "chain-job-continue-on-error"
# W2: env allowlist (rule id gate-env-override kept) and env-file writes
for _c in ("bad-env-allowlist-step-release", "bad-env-allowlist-job-ci", "bad-env-allowlist-workflow-ci",
           "bad-env-allowlist-workflow-release", "bad-env-gh-token-secret", "bad-env-tag-job-level",
           "bad-env-tag-in-ci"):
    BAD[_c] = "gate-env-override"
for _c in ("bad-gate-job-writes-github-env-verify", "bad-gate-job-writes-github-path-publish",
           "bad-gate-job-writes-github-env-ci-install", "bad-gate-job-writes-github-path-build-release"):
    BAD[_c] = "gate-writes-env-file"
# W3: container, services, non-hosted runners, non-positive timeout
for _c in ("bad-job-container-release", "bad-job-container-ci", "bad-job-services-ci",
           "bad-job-services-release", "bad-runs-on-self-hosted-release", "bad-runs-on-list-ci",
           "bad-runs-on-matrix-ci", "bad-runs-on-group-release",
           "bad-timeout-zero-release", "bad-timeout-negative-ci", "bad-timeout-expression-release"):
    BAD[_c] = "gate-job-environment"
# W4: the release-graph job runs exactly the two commands; ci.yml keeps pull_request
for _c in ("bad-ci-checker-other-root", "bad-ci-checker-extra-argument", "bad-ci-tests-with-k",
           "bad-ci-tests-extra-path"):
    BAD[_c] = "release-graph-command-inexact"
BAD["bad-ci-no-pull-request-trigger"] = "ci-no-pull-request-trigger"

# H1: one commit, resolved once by the gate; the bare tag name is shadowable by a branch
for _c in ("bad-quality-ref-bare-tag", "bad-build-checkout-ref-bare-tag", "bad-tag-shadowed-by-branch"):
    BAD[_c] = "tag-ref-shadowable"
for _c in ("bad-on-main-no-sha-output", "bad-on-main-sha-output-from-main-head"):
    BAD[_c] = "on-main-no-sha-output"
# M2: the tag must still name that commit when the release is created
for _c in ("bad-publish-no-tag-recheck", "bad-publish-recheck-without-fetch",
           "bad-publish-recheck-compares-wrong-value"):
    BAD[_c] = "publish-no-tag-recheck"
BAD["bad-publish-tag-recheck-after-release"] = "release-before-tag-recheck"
# L7, L8
BAD["bad-archive-includes-test-fixtures"] = "archive-includes-test-fixtures"
for _c in ("bad-tag-check-loose-glob", "bad-tag-check-regex-unanchored"):
    BAD[_c] = "tag-check-loose"

# S1-S3 (independent check, round 7): see ROUND 7 in the module docstring
for _c in ("bad-needs-output-not-direct-build", "bad-needs-output-not-direct-quality",
           "bad-needs-output-not-direct-verify"):
    BAD[_c] = "needs-output-not-direct"
BAD["bad-build-no-head-assert"] = "build-checkout-unasserted"
BAD["bad-ci-no-head-assert"] = "ci-checkout-unasserted"
BAD["bad-on-main-no-sha-shape-assert"] = "sha-shape-unasserted"
BAD["bad-target-commitish-main"] = "target-commitish-not-sha"

# A fixture that cannot avoid a second rule: quality must be reached from on-main, and any middle job
# must itself need quality (no-quality-gate), which is a cycle. So the quality case also trips this.
ALSO = {"bad-needs-output-not-direct-quality": {"no-quality-gate"}}

GOOD = ["good", "good-verify-in-publish-job", "good-gate-with-pipefail-line",
        "good-gate-shell-bash-and-gh-token",
        "good-chain-coe-literal-false", "good-gate-timeout-positive-and-hosted-runners",
        "good-archive-excludes-test-fixtures"]
TAG_REGEX = r"^v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?$"


def run(root):
    p = subprocess.run([sys.executable, str(CHECKER), str(root)],
                       capture_output=True, text=True, timeout=60)
    return p.returncode, p.stdout + p.stderr


class Fixtures(unittest.TestCase):
    def test_every_rule_has_a_bad_fixture(self):
        self.assertEqual(sorted(set(BAD.values())), sorted(RULES))

    def test_every_fixture_directory_is_listed(self):
        on_disk = {p.name for p in FIX.iterdir() if p.is_dir()}
        self.assertEqual(on_disk, set(BAD) | set(GOOD))

    def test_good_fixtures_pass(self):
        for case in GOOD:
            with self.subTest(case=case):
                rc, out = run(FIX / case)
                self.assertEqual(rc, 0, f"{case} should pass:\n{out}")

    def test_pass_output_says_repository_settings_are_not_checked(self):
        _, out = run(FIX / "good")
        self.assertIn("repository settings", out.lower())

    def test_each_bad_fixture_trips_only_its_own_rule(self):
        for case, rule in sorted(BAD.items()):
            with self.subTest(case=case, rule=rule):
                rc, out = run(FIX / case)
                self.assertNotEqual(rc, 0, f"{case} should fail:\n{out}")
                self.assertIn(rule, out, f"{case} did not trip {rule}:\n{out}")
                for other in RULES:
                    if other != rule and other not in ALSO.get(case, ()):
                        self.assertNotIn(other, out, f"{case} tripped {other} too:\n{out}")

    def test_missing_root_is_an_error_not_a_pass(self):
        rc, _ = run(FIX / "does-not-exist")
        self.assertNotEqual(rc, 0)


class RealRepo(unittest.TestCase):
    """Red until the builder changes the real workflows; then these hold them to F07."""

    def test_checker_passes_on_real_workflows(self):
        rc, out = run(REPO)
        self.assertEqual(rc, 0, out)

    def test_release_workflow_is_dispatch_only(self):
        text = (REPO / ".github" / "workflows" / "release.yml").read_text()
        on = re.search(r"(?m)^on:\n((?:[ \t]+.*\n|\n)+)", text)
        self.assertIsNotNone(on)
        self.assertIn("workflow_dispatch", on.group(1))
        self.assertNotRegex(on.group(1), r"(?m)^  (push|pull_request|release|create)\b")

    def test_toolchain_file_pins_what_hetzner_and_pi_run(self):
        text = (REPO / "rust-toolchain.toml").read_text()
        self.assertRegex(text, r'channel\s*=\s*"%s"' % re.escape(PINNED_TOOLCHAIN))

    def test_checklist_lists_the_repository_settings_the_checker_cannot_see(self):
        text = (REPO / "docs" / "RELEASE_CHECKLIST.md").read_text()
        m = re.search(r"(?im)^#+[^\n]*repository settings[^\n]*\n(.*?)(?=^#|\Z)", text, re.S | re.M)
        self.assertIsNotNone(m, "no heading for repository settings in RELEASE_CHECKLIST.md")
        body = m.group(1).lower()
        for needle in ("load-bearing", "environment", "release", "required reviewers",
                       "deployment branches", "branch protection", "tag ruleset", "checker"):
            self.assertIn(needle, body, f"repository settings section lacks: {needle}")
        self.assertRegex(m.group(1), r"Tag ruleset pattern: `[^`]+`")

    def _settings_section(self):
        text = (REPO / "docs" / "RELEASE_CHECKLIST.md").read_text()
        m = re.search(r"(?im)^#+[^\n]*repository settings[^\n]*\n(.*?)(?=^#|\Z)", text, re.S | re.M)
        self.assertIsNotNone(m)
        return re.sub(r"\s+", " ", m.group(1))  # markdown wraps lines; clicks must not depend on that

    def test_checklist_turns_on_immutable_releases_if_offered(self):
        body = self._settings_section()
        self.assertRegex(body, r"(?i)turn on immutable releases, if GitHub offers it for this repository")
        # DELIBERATE EVAL CHANGE (W5): GitHub's click path has no "General" step.
        self.assertIn("Settings, scroll to Releases, select Enable release immutability", body)
        self.assertNotRegex(body, r"Settings > General[^.]*Releases")

    def test_checklist_gives_exact_clicks_for_every_setting(self):
        body = self._settings_section()
        for clicks in ("Settings > Rules > Rulesets > New ruleset > New tag ruleset",
                       "Settings > Environments > New environment",
                       "Settings > Collaborators and teams"):
            self.assertIn(clicks, body, f"no exact clicks: {clicks}")
        # the environment: its two load-bearing options, named as GitHub's page names them
        self.assertIn("Required reviewers", body)
        # DELIBERATE EVAL CHANGE (W5): GitHub's label is "Deployment branches" (confirmed on docs.github.com).
        self.assertIn("Deployment branches", body)
        self.assertNotIn("Deployment branches and tags", body)
        # branch protection on main: either of GitHub's two current places
        self.assertRegex(body, r"Settings > (Branches > Add (classic )?branch protection rule|Rules > Rulesets > New ruleset > New branch ruleset)")

    def test_checklist_status_check_and_administrator_clicks_match_githubs_labels(self):  # W5
        body = self._settings_section()
        self.assertIn("Require status checks to pass before merging", body)
        # the ruleset text must use the same words, so no shorter form may remain
        self.assertNotRegex(body, r"Require status checks to pass(?! before merging)")
        self.assertIn("deselect Allow administrators to bypass configured protection rules", body)
        self.assertNotRegex(body, r"(?i)do not allow administrators to bypass")

    def test_checker_and_checklist_state_the_checkers_limits_plainly(self):  # W6
        def norm(s):
            s = s.replace("\u2019", "'")
            s = re.sub(r"(?m)^[ \t]*[#>*-]+", " ", s)
            return re.sub(r"\s+", " ", s).lower()
        header = norm("\n".join(CHECKER.read_text().splitlines()[:80]))
        checklist = norm((REPO / "docs" / "RELEASE_CHECKLIST.md").read_text())
        for where, text in (("checker header", header), ("checklist", checklist)):
            for needle in ("catches mistakes", "visible weakening of main's own workflows",
                           "can always defeat a structural check",
                           "branch protection with review", "runs nothing"):
                self.assertIn(needle, text, f"{where} lacks: {needle}")

    def test_checklist_says_who_holds_write_access_and_keeps_the_publish_statement(self):
        body = self._settings_section()
        self.assertRegex(body, r"(?i)write access stays with Taylor and the agents' GitHub account")
        self.assertRegex(body, r"(?i)pushes for the agents")
        self.assertRegex(body, r"(?i)branch protection on `?main`? and the tag ruleset are what the release relies on")
        self.assertRegex(body, r"(?i)anyone with write access\b[^.]*\bcan publish")

    def test_checklist_says_how_to_cut_a_release(self):
        text = (REPO / "docs" / "RELEASE_CHECKLIST.md").read_text().lower()
        for needle in ("push the tag", "dispatch", "main"):
            self.assertIn(needle, text)

    def test_every_real_action_is_a_full_commit_with_tag_comment(self):
        for wf in (REPO / ".github" / "workflows").glob("*.yml"):
            for line in wf.read_text().splitlines():
                m = re.match(r"\s*(?:-\s*)?uses:\s*(\S+)(.*)", line)
                if not m or m.group(1).startswith("./"):
                    continue
                self.assertRegex(m.group(1), r"@[0-9a-f]{40}$", f"{wf.name}: {line}")
                self.assertRegex(m.group(2), r"#\s*\S+", f"{wf.name}: no tag comment: {line}")

    # ---- round 6 (review H1 / M2-M4 / L5-L8) ----
    def _release(self):
        return (REPO / ".github" / "workflows" / "release.yml").read_text()

    def _checklist(self):
        return re.sub(r"\s+", " ", (REPO / "docs" / "RELEASE_CHECKLIST.md").read_text())

    def test_release_resolves_the_tag_once_and_uses_that_commit_everywhere(self):  # H1, M2
        text = self._release()
        self.assertRegex(text, r"(?m)^    outputs:\n      sha: \$\{\{ steps\.\w+\.outputs\.sha \}\}")
        self.assertIn('git rev-parse "refs/tags/$TAG^{commit}"', text)
        # DELIBERATE EVAL CHANGE (H1): the bare tag as a ref let a same-named branch shadow the tag.
        self.assertNotRegex(text, r"ref:\s*\$\{\{\s*inputs\.tag\s*\}\}")
        self.assertGreaterEqual(len(re.findall(r"ref:\s*\$\{\{\s*needs\.on-main\.outputs\.sha\s*\}\}", text)), 2)

    def test_publish_rechecks_the_tag_before_the_release_step(self):  # M2
        text = self._release()
        job = text[text.index("  publish-release:"):]
        recheck = re.search(r'git rev-parse "refs/tags/\$TAG\^\{commit\}"[^\n]*needs\.on-main\.outputs\.sha', job)
        self.assertIsNotNone(recheck, "no tag-equals-sha gate step in publish-release")
        release = job.index("softprops/action-gh-release")
        self.assertLess(recheck.start(), release)
        self.assertRegex(job[:release], r"git fetch[^\n]*--tags")

    def test_release_workflow_tag_check_is_the_exact_regex(self):  # L8
        self.assertIn('[[ "$TAG" =~ ' + TAG_REGEX + " ]]", self._release())
        self.assertNotIn("v*.*.* ]]", self._release())
        self.assertIn(TAG_REGEX, CHECKER.read_text(), "the checker does not name the tag regex")
        self.assertIn(TAG_REGEX, (REPO / "docs" / "RELEASE_CHECKLIST.md").read_text())

    def test_archive_leaves_out_test_fixtures(self):  # L7
        self.assertIn("test-fixtures", self._release())

    def test_release_header_does_not_say_the_environment_stops_a_modified_copy(self):  # M3
        head = "\n".join(self._release().splitlines()[:45])
        self.assertNotRegex(head, r"(?is)environment[^.]*\bstops?\b")
        self.assertRegex(re.sub(r"[#\s]+", " ", head), r"(?i)does not stop a (weakened|modified)")

    def test_checklist_requires_one_approval_and_code_owners(self):  # M4
        body = self._checklist()
        self.assertIn("Required approvals: 1", body)
        self.assertRegex(body, r"(?i)(defaults? to 0|zero approvals|0 approvals)")
        self.assertIn("CODEOWNERS", body)
        self.assertRegex(body, r"\.github/")
        self.assertRegex(body, r"scripts/")
        self.assertRegex(body, r"(?i)confirm[^.]*(owner|CODEOWNERS)|(owner|CODEOWNERS)[^.]*confirm")
        owners = (REPO / ".github" / "CODEOWNERS").read_text()
        self.assertRegex(owners, r"(?m)^/?\.github/\s+@\S+")
        self.assertRegex(owners, r"(?m)^/?scripts/\s+@\S+")

    def test_checklist_says_what_the_attestation_proves(self):  # L5
        body = self._checklist()
        self.assertRegex(body, r"(?i)proves[^.]*built by[^.]*release\.yml[^.]*on `?main")
        self.assertRegex(body, r"(?i)(binds|names|records)[^.]*(commit|sha)[^.]*(built|checked out)")

    def test_checklist_and_ci_cover_attestations_on_private_repositories(self):  # L6
        body = self._checklist()
        self.assertRegex(body, r"(?i)private[^.]*Enterprise Cloud|Enterprise Cloud[^.]*private")
        self.assertRegex(body, r"(?i)public first|repository[^.]*public[^.]*first|public before")
        self.assertRegex(body, r"(?i)Taylor\W?s call")
        self.assertRegex(body, r"(?i)attestations: read[^.]*first real run|first real run[^.]*attestations: read")
        ci = (REPO / ".github" / "workflows" / "ci.yml").read_text()
        self.assertRegex(ci, r"(?s)workflow_call:.*?secrets:\s*\n\s+GITLEAKS_LICENSE:\s*\n\s+required: false")
        self.assertIn("GITLEAKS_LICENSE", self._release())

    def test_checklist_bypass_wording_matches_what_rulesets_allow(self):  # L8
        body = self._settings_section()
        self.assertNotRegex(body, r"(?i)leave only Taylor able to bypass")
        self.assertRegex(body, r"(?i)bypass[^.]*roles, teams or apps[^.]*not individual users|roles, teams or apps[^.]*bypass[^.]*not individual users")

    def test_readme_names_the_pinned_toolchain(self):  # L8
        readme = (REPO / "README.md").read_text()
        self.assertIn("Rust " + PINNED_TOOLCHAIN, readme)
        self.assertNotIn("Rust 1.88", readme)


if __name__ == "__main__":
    unittest.main()
