#!/usr/bin/env python3
r"""check-release-graph.py: a LOCAL, STRUCTURAL check of the release workflows.

What it proves, and what it does not. It reads .github/workflows/ci.yml,
.github/workflows/release.yml, rust-toolchain.toml and docs/RELEASE_CHECKLIST.md
under <root> and checks the SHAPE of the workflow graph. It runs no workflow
(act needs docker, and GitHub's behaviour is not reproduced here), so a pass
means "the files are wired so that a release cannot skip its checks", never "a
release ran and worked". The first real release is the end-to-end test.

Its limits, plainly. It catches mistakes and visible weakening of main's own
workflows in review: a change that drops a gate or loosens a step makes it fail,
and the diff shows what changed. It runs nothing. A writer who can change main
can always defeat a structural check (by editing the checker, its tests or the
workflow that runs them), so branch protection with review is what holds that
line, not this script.

The design it checks. No workflow that a tag push (or any push) starts can
publish: a tag push reads the workflow files from the tagged commit, which
anyone with write access can choose. release.yml is a workflow_dispatch
workflow meant to run on main, taking the input `tag`. Its jobs, in order:
on-main (fails unless it runs on refs/heads/main and the tag's commit is an
ancestor of origin/main, then resolves the tag to its commit once and outputs
it as `sha`), quality (main's ci.yml, called with that sha as its `ref`, so
main's gate tests the tagged commit), build-release (from that sha, with a
provenance attestation), verify-artifacts, publish-release (in the environment
"release", after re-checking that the tag still names the sha). Every job needs
on-main, directly or through others. The bare tag name is never a `ref`: the
pinned actions/checkout prefers a branch of that name, and a writer can push one.

Rules (the id is printed with each violation):

  no-quality-gate            Every job in release.yml other than the gate itself
                             and on-main must, directly or through other jobs,
                             need the gate: release.yml calling ci.yml as a
                             reusable workflow (same run), or (fallback)
                             carrying the same jobs inline. Jobs that run after
                             a skipped or failed gate (if: always() and the
                             like) do not count.
  quality-job-uncovered      Every job of ci.yml must be covered by that gate:
                             ci.yml must have workflow_call, its jobs must not
                             be skippable (if:) or allowed to fail
                             (continue-on-error), it must contain fmt, clippy
                             with -D warnings, tests, the secret scan and the
                             licence check (as whole commands, see below), and
                             it must test on every operating system the release
                             builds on.
  quality-not-on-tag         Judged when ci.yml is reusable: main's gate must run
                             on the tag. ci.yml's workflow_call declares an
                             input `ref`, every checkout in ci.yml has
                             `ref: ${{ inputs.ref }}`, and each call of ci.yml
                             in release.yml passes
                             `ref: ${{ needs.on-main.outputs.sha }}`.
  not-tagged-commit          The release is of the input tag and nothing else:
                             release.yml has a workflow_dispatch input `tag`; a
                             checkout in release.yml that names a ref names
                             `${{ inputs.tag }}`; the checkout of a building job
                             names it; no checkout of another repository, no git
                             checkout or switch, no artifact from another run;
                             the release step's tag_name is `${{ inputs.tag }}`;
                             a checkout that names a ref names the sha output.
  tag-ref-shadowable         A `ref:` in release.yml (a checkout, or the one
                             passed to ci.yml) is the bare `${{ inputs.tag }}`:
                             a branch pushed with the tag's name would win over
                             the tag, so the gate would pass for one commit and
                             the build would use another.
  on-main-no-sha-output      on-main lacks the job output `sha`, or the step
                             that makes it is not exactly
                             echo "sha=$(git rev-parse "refs/tags/$TAG^{commit}")" >> "$GITHUB_OUTPUT"
                             after the ancestor test ($GITHUB_SHA is main's head,
                             not the tag's commit).
  needs-output-not-direct    A job reads needs.<job>.outputs.* without listing <job> in
                             its own needs. GitHub's needs context holds direct
                             dependencies only, so it gets an empty string, and a
                             checkout with an empty ref builds main's head.
  build-checkout-unasserted  The step after a building job's checkout in release.yml
                             is not the gate step test "$(git rev-parse HEAD)" =
                             "${{ needs.on-main.outputs.sha }}" (a checkout that fell
                             back to another commit would be built and attested).
  ci-checkout-unasserted     The step after a checkout in ci.yml is not
                             `if: inputs.ref != ''` with test "$(git rev-parse HEAD)" =
                             "${{ inputs.ref }}".
  sha-shape-unasserted       No gate step after on-main's resolve step requires its
                             sha output to match ^[0-9a-f]{40}$ (echo succeeds even
                             when git rev-parse fails).
  target-commitish-not-sha   The release step's target_commitish is not
                             ${{ needs.on-main.outputs.sha }}.
  publish-no-tag-recheck     publish-release lacks, as gate steps, `git fetch
                             --force --tags origin` and then a test that
                             git rev-parse "refs/tags/$TAG^{commit}" equals
                             ${{ needs.on-main.outputs.sha }}: a tag moved or
                             deleted during the approval wait would publish
                             something else.
                             (Judged only when on-main's sha output is sound: a
                             recheck against another sha is the same defect.)
  release-before-tag-recheck The recheck exists but the release step comes first.
  archive-includes-test-fixtures
                             The Package step copies scripts/ and does not
                             remove scripts/test-fixtures (rm -rf, or tar
                             --exclude), so deliberately broken workflows ship.
  tag-check-loose            The on-main tag-name check is not exactly
                             [[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?$ ]]
                             (when it agrees with the checklist; a difference
                             between the two is tag-pattern-mismatch).
  publish-reachable-from-push
                             A workflow with any trigger other than
                             workflow_dispatch and workflow_call (a push, of a
                             branch or a tag, a pull request, ...) contains a
                             publishing job (a release action, `gh release
                             create`, or `environment: release`). Every
                             workflow file in .github/workflows is looked at;
                             one this reader cannot read counts as a violation.
  on-main-shallow            The on-main job's checkout lacks `fetch-depth: 0`.
  no-main-ref-check          The on-main job lacks a gate step whose one command
                             compares $GITHUB_REF (or ${{ github.ref }}) with
                             refs/heads/main and fails otherwise (`test`, `[ ]`
                             or `[[ ]]`); an echo of it, or another ref, is a miss.
  no-on-main-gate            There is no job `on-main`, or it can be skipped, or
                             it lacks the gate step `git fetch origin main ...`
                             followed by the gate step `git merge-base
                             --is-ancestor <the tag's commit> origin/main`
                             (refs/tags/$TAG^{commit}), or TAG is not set from
                             `${{ inputs.tag }}` (an environment variable, so the
                             input is never pasted into a script).
  tag-pattern-mismatch       The pattern in the on-main step `[[ "$TAG" =~ <regex> ]]`
                             differs from the one on the `Tag name check:` line
                             of docs/RELEASE_CHECKLIST.md (or either is
                             missing). (The ruleset's own pattern, a glob on the
                             `Tag ruleset pattern:` line, is broader.)
  job-skips-on-main-gate     A job other than on-main (the quality gate included)
                             does not need the on-main job.
  gate-step-shape            See GATE STEPS below.
  gate-step-shell            A gate step sets a `shell:` other than bash, or the
                             workflow or a job holding gate steps sets
                             `defaults.run.shell` to anything but bash (a
                             custom shell such as `echo {0}` empties the step).
  gate-continue-on-error     A gate step, a job holding gate steps, a job of the
                             quality gate, or publish-release (job or release
                             step) has `continue-on-error` that is not the
                             literal false; an expression such as
                             `${{ true }}` is refused.
  gate-env-override          An allowlist. A gate step, a job of ci.yml or release.yml
                             (they are all gate jobs) and either workflow may set
                             no env except GH_TOKEN (as ${{ github.token }}) and,
                             in release.yml at workflow level only, TAG (as
                             ${{ inputs.tag }}). Also a `working-directory` or
                             `defaults.run.working-directory` on a gate step, job
                             or workflow: they change what the command is or
                             where it looks.
  gate-writes-env-file       A run script of any job in either workflow mentions
                             GITHUB_ENV or GITHUB_PATH: a step that writes them
                             changes the environment of every later step.
  gate-job-environment       A job has `container:` or `services:`, a `runs-on`
                             that is not a GitHub-hosted label (ubuntu-*, macos-*,
                             windows-*, or ${{ matrix.os }} whose values are all
                             such), or a `timeout-minutes` that is not a positive
                             number. (A job that calls a workflow has no runner.)
  chain-job-continue-on-error
                             Any job of the publish chain (on-main, quality, ci.yml's
                             jobs, build-release, verify-artifacts, publish-release)
                             has `continue-on-error` that is not absent or the
                             literal false. Reported once: a job an older rule
                             already refuses for it is not reported again.
  release-graph-command-inexact
                             In ci.yml's release-graph job, a step mentioning the
                             checker is not exactly
                             `python3 scripts/check-release-graph.py .`, or one
                             mentioning its tests is not exactly
                             `python3 -m unittest scripts/test_check_release_graph.py`
                             (no -k, no other path or argument).
  ci-no-pull-request-trigger ci.yml lacks its pull_request trigger, so the
                             checker would not run on a proposed change.
  release-graph-job-incomplete
                             ci.yml lacks the job `release-graph`, or it can be
                             skipped, or it does not run this checker and its
                             tests as gate steps, so dropping the check from CI
                             would go unnoticed.
  unpinned-action            Every third-party action (and reusable workflow)
                             is pinned to a full 40-character commit with the
                             tag in a trailing comment; docker images to a
                             sha256 digest.
  toolchain-not-exact        rust-toolchain.toml names an exact x.y.z version,
                             and every toolchain step in the workflows names
                             that same version (no stable/beta/nightly).
  no-artifact-verification   Before publishing, the packaged artifact's sha256
                             (recorded at build) is re-checked after download,
                             the archive is unpacked, its programs run
                             --version, and scripts/check-binary-clean.sh passes
                             on them, in a job the publishing job needs or in
                             the publishing job before its release step.
  verification-after-publish The verification exists but cannot stop a
                             publish: it is in a job the publishing job does
                             not need, or after the release step.
  publish-no-release-environment
                             the job that publishes does not run in
                             `environment: release`, where required reviewers
                             (a repository setting) hold it for a human.
  no-build-provenance        a job that builds has no
                             actions/attest-build-provenance step. The sha256
                             sidecar travels in the same artifact as the
                             archive, so re-checking it proves only
                             self-consistency; the attestation is signed by
                             GitHub, outside the artifact.
  attest-subject-not-archive The attest step's subject-path is not the path the
                             building job's `tar -czf` writes.
  provenance-not-verified    the publishing job, and every job that re-checks
                             the sha256, lacks `gh attestation verify <archive>
                             --repo ${{ github.repository }}` as a whole command
                             before the release step.
  attestation-verify-unscoped
                             a `gh attestation verify` lacks
                             `--signer-workflow ${{ github.repository }}/.github/workflows/release.yml`
                             or `--source-ref refs/heads/main`, so an archive
                             attested by another workflow or branch would pass,
                             or it carries any flag besides --repo,
                             --signer-workflow and --source-ref (--bundle,
                             --cert-oidc-issuer, ...). Its target must be the
                             archive (*.tar.gz), not the .sha256 file.
  attestation-permissions-misplaced
                             `id-token: write` or `attestations: write` (or
                             write-all) at workflow level, on any job that does
                             not build, or missing from the building job that
                             attests.
  prerelease-not-from-tag    the release step's `prerelease:` is not
                             `${{ contains(inputs.tag, '-') }}` (v1.0.0-rc1 must
                             not publish as a full release).

GATE STEPS. A gate step is a step whose failure is what stops the release: in
ci.yml every step whose run mentions `cargo fmt`, `cargo clippy` or `cargo
test`, or runs this checker or its tests; in release.yml every step of the on-main job except its checkout. The
run script of a gate step is exactly ONE command on ONE line, optionally after a
first line that is only `set -euo pipefail`. A second command, a here-doc, `&&`,
`||`, `;`, a pipe, a background `&`, a command substitution (but for the one exact
line that resolves the tag's commit), `if`/`for`/`exit`
and the like, a comment line or a line continuation all fail gate-step-shape.
That is stricter than reading the script as shell would, on purpose: a reader
that tries to understand shell can be fooled (a here-doc body that looks like a
command, `false && cmd`, `exit 0` before or after, `cmd; true`); a rule that
admits one line and nothing else cannot. A step that fails gate-step-shape is
reported only under that rule and still counts as carrying its command for the
other rules, so one defect gives one finding.

Whole commands. Every other rule that looks for a command (the sha256 re-check,
gh attestation verify, ...) reads the run script as shell would: a command is
what starts a statement (a line, or after `;` or `&&`), outside quotes and
comments. `echo cargo test`, `printf '%s' "cargo test"`, `# cargo test` and
`msg="cargo test"` are not commands, and a command followed by `|| ...` or piped
onward does not count either, since its failure would not stop the job.

What this cannot see: repository settings. They are load-bearing: a workflow
runs from the file on the branch it is dispatched from, so anyone with write
access can dispatch a weakened copy from another branch, and only the settings
stop that (the environment "release" with required reviewers AND deployment
branches limited to main; branch protection on main; a tag ruleset on v*.*.*).
docs/RELEASE_CHECKLIST.md lists them under "Repository settings"; the checker
says so every time it runs.

Usage: python3 scripts/check-release-graph.py <root>
Exit status: 0 every rule holds; 1 at least one violation (one line each on
stdout); 2 the root or a file is missing (a missing file is never a pass).

The workflow files are read with a small built-in reader for the subset of YAML
these files use (block mappings and lists, inline lists, block scalars), so the
check needs nothing but Python 3 and runs the same on a developer machine and in
CI. Action commits are checked for form only, not for existence; looking them up
is a separate, networked step.

Tests: python3 -m unittest scripts/test_check_release_graph.py
"""
import json
import re
import shlex
import sys
from pathlib import Path

CI_PATH = ".github/workflows/ci.yml"
RELEASE_PATH = ".github/workflows/release.yml"
TOOLCHAIN_PATH = "rust-toolchain.toml"
CHECKLIST_PATH = "docs/RELEASE_CHECKLIST.md"
ON_MAIN = "on-main"
EXACT_VERSION = re.compile(r"^\d+\.\d+\.\d+$")
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
TAG_REF = "${{inputs.tag}}"      # expressions are compared with the spaces inside ${{ }} removed
CI_REF = "${{inputs.ref}}"
# The commit every later job uses: on-main resolves the tag ONCE and outputs it. The bare tag
# name as a ref is the bug (actions/checkout prefers a branch of that name over the tag).
SHA_REF = "${{needs.on-main.outputs.sha}}"
# The tag-name check in on-main, exactly (also the "Tag name check:" line of the checklist).
TAG_REGEX = r"^v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?$"
TAG_CHECK = re.compile(r'''^\[\[\s+"?\$TAG"?\s+(==?|=~)\s+(.+?)\s+\]\]$''')
# The one gate-step line that may hold a command substitution: it resolves the tag's commit
# and writes it to the job output. Matched as a whole line, character for character.
RESOLVE_LINE = 'echo "sha=$(git rev-parse "refs/tags/$TAG^{commit}")" >> "$GITHUB_OUTPUT"'
# publish-release's recheck, as a whole line: the tag still names the commit that was built.
TAG_RECHECK = re.compile(
    r'''^(?:test|\[\[?)\s+(?:"\$\(git rev-parse "refs/tags/\$TAG\^\{commit\}"\)"\s+==?\s+"\$\{\{needs\.on-main\.outputs\.sha\}\}"'''
    r'''|"\$\{\{needs\.on-main\.outputs\.sha\}\}"\s+==?\s+"\$\(git rev-parse "refs/tags/\$TAG\^\{commit\}"\)")(?:\s+\]\]?)?$''')
# The tag's commit as the ancestor test must name it (quotes and spaces removed): $TAG is
# the environment variable set from the input, never the input pasted into the script, and
# the full form refs/tags/$TAG^{commit}, so a branch or a bare name cannot stand in for the tag.
TAG_COMMIT = re.compile(r"^refs/tags/(?:\$TAG|\$\{TAG\})\^\{commit\}$")
# `git fetch --dry-run` (or -n, alone or in a cluster of short flags) fetches nothing.
DRY_RUN = re.compile(r"(?<!\S)(?:--dry-run|-[A-Za-z]*n[A-Za-z]*)(?!\S)")
# A gate step also runs the checker and its tests in ci.yml's release-graph job.
GATE_CHECKER = re.compile(r"check-release-graph\.py|test_check_release_graph")
RELEASE_GRAPH_JOB = "release-graph"
CHECKER_CMD = r"(?:python3?\s+)?(?:\./)?scripts/check-release-graph\.py\b"
CHECKER_TESTS_CMD = r"(?:python3?\s+)?-m\s+unittest\b.*\btest_check_release_graph\b"
# The env allowlist (gate-env-override): nothing but GH_TOKEN from the workflow's own token
# (the gh CLI needs it) and, at the top of release.yml only, TAG from the dispatch input.
ENV_GH_TOKEN = "${{github.token}}"
# Any mention of the files a step writes to change the environment of the steps after it.
ENV_FILE_WRITE = re.compile(r"GITHUB_(?:ENV|PATH)")
# GitHub-hosted runner labels; anything else (self-hosted, a group, a custom label) is not.
HOSTED_RUNNER = re.compile(r"^(?:ubuntu|macos|windows)-[A-Za-z0-9._-]+$")
EXACT_CHECKER = "python3 scripts/check-release-graph.py ."
EXACT_TESTS = "python3 -m unittest scripts/test_check_release_graph.py"
# The only flags `gh attestation verify` may carry: they scope it to this repository,
# this workflow and main. Anything else (--bundle, --cert-oidc-issuer, ...) changes what is trusted.
VERIFY_FLAGS = {"--repo", "--signer-workflow", "--source-ref"}
MAIN_REF_TEST = re.compile(r"^(?:test|\[\[?)\s+(?:\$GITHUB_REF|\$\{GITHUB_REF\}|\$\{\{github\.ref\}\})"
                           r"\s+==?\s+refs/heads/main(?:\s+\]\]?)?$")
SIGNER_WORKFLOW = "${{github.repository}}/.github/workflows/release.yml"
SOURCE_REF = "refs/heads/main"
PRERELEASE_FROM_TAG = re.compile(r"^\$\{\{\s*contains\(\s*inputs\.tag\s*,\s*'-'\s*\)\s*\}\}$")
TAR_OUTPUT = re.compile(r"\btar\s+-?[A-Za-z]*c[A-Za-z]*f\s+(\S+)")
GATE_CARGO = re.compile(r"\bcargo\s+(fmt|clippy|test)\b")
SET_LINE = "set -euo pipefail"
# S1: the checkout is asserted to be the commit that was meant (a missing `ref` or an empty
# output makes actions/checkout fall back to the dispatching ref). S2: the resolved sha has the
# shape of a commit hash. Matched as whole lines on norm_expr()ed text.
NEEDS_OUTPUT = re.compile(r"\bneeds\.([A-Za-z0-9_-]+)\.outputs\b")
BUILD_HEAD_ASSERT = re.compile(r'^(?:test|\[\[?)\s+"\$\(git rev-parse HEAD\)"\s+==?\s+"\$\{\{needs\.on-main\.outputs\.sha\}\}"(?:\s+\]\]?)?$')
CI_HEAD_ASSERT = re.compile(r'^(?:test|\[\[?)\s+"\$\(git rev-parse HEAD\)"\s+==?\s+"\$\{\{inputs\.ref\}\}"(?:\s+\]\]?)?$')
SHA_SHAPE_ASSERT = r'^\[\[\s+"\$\{\{steps\.%s\.outputs\.sha\}\}"\s+=~\s+\^\[0-9a-f\]\{40\}\$\s+\]\]$'
CI_REF_SET = {"inputs.ref!=''", "${{inputs.ref!=''}}"}
NOT_CHECKED_NOTE = ("note: repository settings are not visible to this check: who has write access (anyone with it "
                    "can publish a release), branch protection on main, the tag ruleset for v*.*.*, and the environment "
                    "\"release\" (it gates the honest publish on approval; a weakened copy can leave it out); "
                    "see docs/RELEASE_CHECKLIST.md (Repository settings, Checking a download).")


# ---------------------------------------------------------------- YAML subset

class YamlError(Exception):
    pass


_KEY = re.compile(r"""^(?:"([^"]*)"|'([^']*)'|([^\s'"\[{#][^:]*?))\s*:(?:\s+(.*))?$""")


def _indent(line):
    return len(line) - len(line.lstrip(" "))


def _scalar(v):
    v = v.strip()
    if v[:1] in ("'", '"'):
        end = v.find(v[0], 1)
        return v[1:end] if end > 0 else v[1:]
    v = re.sub(r"\s+#.*$", "", v)
    if v.startswith("["):
        inner = v.strip()[1:v.rfind("]")]
        return [_scalar(p) for p in re.findall(r"""\s*("[^"]*"|'[^']*'|[^,]+)\s*(?:,|$)""", inner)]
    return None if v in ("", "~", "null") else v


class _Parser:
    def __init__(self, text):
        self.lines = text.replace("\t", "  ").split("\n")
        self.i = 0

    def skip(self):
        while self.i < len(self.lines):
            s = self.lines[self.i].strip()
            if s == "" or s.startswith("#") or s == "---":
                self.i += 1
            else:
                return

    def parse(self):
        self.skip()
        if self.i >= len(self.lines):
            return None
        return self.block(_indent(self.lines[self.i]))

    def block(self, indent):
        text = self.lines[self.i].strip()
        return self.seq(indent) if text.startswith("- ") or text == "-" else self.mapping(indent)

    def child(self, indent):
        """The value under a `key:` line whose own indent is `indent`."""
        self.skip()
        if self.i >= len(self.lines):
            return None
        ind = _indent(self.lines[self.i])
        text = self.lines[self.i].strip()
        if ind > indent:
            return self.block(ind)
        if ind == indent and (text.startswith("- ") or text == "-"):
            return self.seq(indent)
        return None

    def mapping(self, indent):
        out = {}
        while True:
            self.skip()
            if self.i >= len(self.lines):
                break
            line = self.lines[self.i]
            ind, text = _indent(line), line.strip()
            if ind < indent or (ind == indent and (text.startswith("- ") or text == "-")):
                break
            if ind > indent:
                raise YamlError(f"line {self.i + 1}: unexpected indent")
            m = _KEY.match(text)
            if not m:
                raise YamlError(f"line {self.i + 1}: not a mapping line: {text[:60]}")
            key = m.group(1) if m.group(1) is not None else m.group(2) if m.group(2) is not None else m.group(3).strip()
            val = m.group(4)
            self.i += 1
            if val is not None and re.sub(r"\s+#.*$", "", val).strip() == "":
                val = None
            if val is None:
                out[key] = self.child(indent)
            elif val[0] in "|>":
                out[key] = self.block_scalar(indent)
            else:
                out[key] = _scalar(val)
        return out

    def block_scalar(self, indent):
        body = []
        while self.i < len(self.lines):
            line = self.lines[self.i]
            if line.strip() == "" or _indent(line) > indent:
                body.append(line)
                self.i += 1
            else:
                break
        pad = min((_indent(b) for b in body if b.strip()), default=0)
        return "\n".join(b[pad:] for b in body).rstrip("\n") + "\n"

    def seq(self, indent):
        out = []
        while True:
            self.skip()
            if self.i >= len(self.lines):
                break
            line = self.lines[self.i]
            ind, text = _indent(line), line.strip()
            if ind != indent or not (text.startswith("- ") or text == "-"):
                break
            rest = text[1:].lstrip(" ")
            col = ind + (len(text) - len(rest))
            if rest == "" or rest.startswith("#"):
                self.i += 1
                out.append(self.child(indent))
            elif _KEY.match(rest) and rest[0] not in "[{":
                self.lines[self.i] = " " * col + rest
                out.append(self.mapping(col))
            else:
                self.i += 1
                out.append(_scalar(rest))
        return out


def load_yaml(path):
    try:
        doc = _Parser(Path(path).read_text()).parse()
    except YamlError as e:
        raise SystemExit(f"{path}: cannot read this workflow: {e}") from None
    if not isinstance(doc, dict) or not isinstance(doc.get("jobs"), dict):
        raise SystemExit(f"{path}: no jobs: mapping found")
    return doc


# --------------------------------------------------------------------- helpers

def triggers(doc):
    on = doc.get("on")
    if isinstance(on, str):
        return {on: None}
    if isinstance(on, list):
        return {t: None for t in on}
    return on if isinstance(on, dict) else {}


def needs_of(job):
    n = job.get("needs")
    return [] if n is None else [n] if isinstance(n, str) else list(n)


def reach(jobs, jid):
    """Every job that `jid` waits for, directly or through others."""
    seen, todo = set(), list(needs_of(jobs[jid]))
    while todo:
        j = todo.pop()
        if j in seen or j not in jobs:
            continue
        seen.add(j)
        todo.extend(needs_of(jobs[j]))
    return seen


def steps_of(job):
    return [s for s in (job.get("steps") or []) if isinstance(s, dict)]


def run_text(step):
    r = step.get("run")
    return r if isinstance(r, str) else ""


def uses_of(step):
    u = step.get("uses")
    return u if isinstance(u, str) else ""


def with_of(step):
    w = step.get("with")
    return w if isinstance(w, dict) else {}


def is_true(v):
    return str(v).strip().lower() == "true"


def all_steps(doc):
    for jid, job in doc["jobs"].items():
        for idx, s in enumerate(steps_of(job)):
            yield jid, idx, s


# ---- whole commands: a run script read as shell reads it

_QUOTED = re.compile(r"""\"(?:\\.|[^\"\\])*\"|'[^']*'""")


def commands(script, loose=False):
    """The statements of a shell script, as shell would read them.

    Splits on newlines, `;` and `&&` outside quotes, drops comments and
    backslash line continuations, and strips what comes before the command word
    (`do`, `then`, `(`, `{`, `!`, VAR=value). A statement that is only a quoted
    string, an assignment, an echo or a printf therefore never looks like the
    command it mentions. `loose` also splits on pipes and a lone `&`: it is how
    a gate step that already failed gate-step-shape is still read for the
    command it carries, so that one defect gives one finding.
    """
    segs, cur, q, i, n = [], [], None, 0, len(script)

    def flush():
        seg = "".join(cur).strip()
        cur.clear()
        if seg:
            segs.append(_clean(seg))

    while i < n:
        c = script[i]
        if q:
            cur.append(c)
            if c == "\\" and q == '"' and i + 1 < n:
                cur.append(script[i + 1])
                i += 2
                continue
            if c == q:
                q = None
        elif c == "\\" and i + 1 < n:
            if script[i + 1] != "\n":
                cur.extend((c, script[i + 1]))
            i += 2
            continue
        elif c in "'\"":
            q = c
            cur.append(c)
        elif c == "#" and (not cur or cur[-1] in " \t"):
            while i < n and script[i] != "\n":
                i += 1
            continue
        elif c in "\n;":
            flush()
        elif c == "&" and script[i + 1:i + 2] == "&":
            flush()
            i += 1
        elif loose and c in "|&":
            flush()
        else:
            cur.append(c)
        i += 1
    flush()
    return [s for s in segs if s]


def _clean(seg):
    s = seg.strip()
    while True:
        t = re.sub(r"^(?:[({!]\s*|(?:do|then|else)\b\s*)", "", s)
        if t == s:
            break
        s = t
    s = re.sub(r"""^(?:[A-Za-z_]\w*=(?:"(?:\\.|[^"\\])*"|'[^']*'|\S*)\s+)+""", "", s)
    return s.strip()


def unquoted(seg):
    return _QUOTED.sub('""', seg)


def swallowed(seg):
    """A pipe or `||` after the command: its failure would not fail the step."""
    return "|" in unquoted(seg)


def has_cmd(cmds, pattern):
    """Is there a whole command matching `pattern` at its start, not swallowed?"""
    return any(re.match(pattern, c) and not swallowed(c) for c in cmds)


def job_cmds(job, upto=None, loose=frozenset()):
    """Whole commands of a job's steps (before step index `upto`), leaving out
    steps that can be skipped or may fail without failing the job. A step whose
    id() is in `loose` (a gate step already reported under gate-step-shape) is
    read loosely."""
    out = []
    for idx, s in enumerate(steps_of(job)):
        if upto is not None and idx >= upto:
            break
        if "if" in s or is_true(s.get("continue-on-error")):
            continue
        out.extend(commands(run_text(s), loose=id(s) in loose))
    return out


def norm_expr(s):
    """Spaces inside ${{ }} removed, so expressions compare equal however spaced."""
    return re.sub(r"\$\{\{\s*(.*?)\s*\}\}", r"${{\1}}", s)


def plain_line(step, allowed=()):
    """The one command line of a step that has no if / continue-on-error / env / shell /
    working-directory (but for the keys in `allowed`), spaces in ${{ }} removed; else None."""
    if not isinstance(step, dict) or set(step) & ({"if", "continue-on-error", "env", "shell", "working-directory"} - set(allowed)):
        return None
    lines = [l.strip() for l in run_text(step).strip("\n").split("\n") if l.strip()]
    if lines and lines[0] == SET_LINE:
        lines = lines[1:]
    return norm_expr(lines[0]) if len(lines) == 1 else None


def gate_shape_problem(script):
    """Why a gate step's run script is not exactly one command (None when it is)."""
    lines = script.strip("\n").split("\n")
    if lines and lines[0].strip() == SET_LINE:
        lines = lines[1:]
    if len(lines) != 1 or not lines[0].strip():
        return "its run script is not exactly one command on one line (after an optional `set -euo pipefail` line)"
    line = lines[0].strip()
    if line == RESOLVE_LINE:
        return None
    if line.startswith("#"):
        return "its run script is a comment"
    u = unquoted(line)
    if "<<" in u:
        return "its run script has a here-doc"
    if re.search(r"&&|\|\||;|\||(?<![>&])&(?![>&])", u):
        return "its run line chains or pipes (&&, ||, ;, |, &), so something after or before the command can hide its failure"
    if u.endswith("\\"):
        return "its run line continues on the next line"
    if "$(" in re.sub(r"'[^']*'", "''", line) or "`" in re.sub(r"'[^']*'", "''", line):
        return "its run line runs a command substitution"
    if re.match(r"[({!]", u) or re.match(r"(?:if|then|else|elif|fi|for|while|until|do|done|case|esac|exit|return|trap|function)\b", u):
        return "its run line is shell control flow (if, for, exit, a group, ...), not a command"
    return None

def verifies_archive(cmd, cmds):
    """Does this `gh attestation verify` name the archive (*.tar.gz), not its .sha256 or another file?

    The target is a literal path, or a loop variable set by a `for VAR in <paths>` command
    among `cmds`; every path the loop lists must end in .tar.gz."""
    try:
        toks = shlex.split(cmd)
    except ValueError:
        return False
    if len(toks) < 4 or toks[3].startswith("-"):
        return False
    target = toks[3]
    m = re.fullmatch(r"\$(\w+)|\$\{(\w+)\}", target)
    if not m:
        return target.endswith(".tar.gz")
    var = m.group(1) or m.group(2)
    for c in cmds:
        f = re.match(r"for\s+(\w+)\s+in\s+(.*)$", c)
        if f and f.group(1) == var:
            try:
                items = shlex.split(f.group(2))
            except ValueError:
                return False
            return bool(items) and all(i.endswith(".tar.gz") for i in items)
    return False


def verify_flag_problem(cmd):
    """Why a `gh attestation verify` carries more or other than exactly --repo, --signer-workflow
    and --source-ref (None when it carries exactly those)."""
    try:
        toks = shlex.split(cmd)[4:]      # after `gh attestation verify <archive>`
    except ValueError:
        return "cannot be read as a command"
    seen, i, extra = [], 0, []
    while i < len(toks):
        t = toks[i]
        if t.startswith("-"):
            name, eq, _ = t.partition("=")
            seen.append(name)
            if name not in VERIFY_FLAGS:
                extra.append(name)
            i += 1 if eq else 2
        else:
            extra.append(t)
            i += 1
    if extra:
        return f"carries {', '.join(extra)} besides the archive; only {', '.join(sorted(VERIFY_FLAGS))} are allowed, since any other flag changes what is trusted"
    if sorted(seen) != sorted(VERIFY_FLAGS):
        return f"must carry exactly {', '.join(sorted(VERIFY_FLAGS))}, once each"
    return None


def perm_writes(perms):
    """The attestation permissions a `permissions:` value grants as write."""
    if isinstance(perms, str):
        return {"id-token", "attestations"} if perms.strip() == "write-all" else set()
    if isinstance(perms, dict):
        return {k for k in ("id-token", "attestations") if str(perms.get(k)).strip() == "write"}
    return set()


def runner_names(job):
    """Operating systems a job runs on, resolving ${{ matrix.os }}."""
    ro = job.get("runs-on")
    if not isinstance(ro, str):
        return set()
    if "matrix.os" not in ro:
        return {ro}
    m = (job.get("strategy") or {}).get("matrix") or {}
    names = set(m.get("os") or []) if isinstance(m.get("os"), list) else set()
    for inc in m.get("include") or []:
        if isinstance(inc, dict) and inc.get("os"):
            names.add(inc["os"])
    return names


CARGO_TEST = r"cargo\s+test\b"
CARGO_BUILD = r"cargo\s+build\b"
ATTEST_VERIFY = r"gh\s+attestation\s+verify\s+\S+.*--repo\s+\$\{\{github\.repository\}\}"   # on norm_expr()ed text


# ----------------------------------------------------------------------- rules

class Checker:
    def __init__(self, root):
        self.root = Path(root)
        self.violations = []

    def bad(self, rule, msg):
        self.violations.append(f"{rule}: {msg}")

    def run(self):
        paths = {k: self.root / p for k, p in
                 (("ci", CI_PATH), ("release", RELEASE_PATH), ("toolchain", TOOLCHAIN_PATH),
                  ("checklist", CHECKLIST_PATH))}
        for p in paths.values():
            if not p.is_file():
                print(f"error: {p} is missing", file=sys.stderr)
                raise SystemExit(2)
        self.ci, self.rel = load_yaml(paths["ci"]), load_yaml(paths["release"])
        self.raw = {CI_PATH: paths["ci"].read_text(), RELEASE_PATH: paths["release"].read_text()}
        self.toolchain_text = paths["toolchain"].read_text()
        self.checklist_text = paths["checklist"].read_text()
        self.gate_shape()
        self.gate_hygiene()
        self.env_hygiene()
        self.env_file_writes()
        self.job_environment()
        self.chain_job_continue_on_error()
        self.release_graph_job()
        self.quality_gate()
        self.quality_on_tag()
        self.on_main_gate()
        # A recheck against a sha that is not the tag's commit is meaningless, and the defect
        # is the sha: when on-main-no-sha-output fires, the recheck is not judged on top of it.
        if self.on_main_sha_output():
            self.publish_tag_recheck()
        self.archive_test_fixtures()
        self.push_reachable()
        self.tagged_commit()
        self.needs_outputs_direct()
        self.head_asserts()
        self.sha_shape_assert()
        self.target_commitish()
        self.pinned_actions()
        self.exact_toolchain()
        self.artifact_verification()
        self.provenance()
        self.prerelease()
        return self.violations

    def gate_jobs(self):
        rel_jobs, ci_jobs = self.rel["jobs"], self.ci["jobs"]
        calls = [j for j, v in rel_jobs.items()
                 if str(v.get("uses", "")).removeprefix("./") == CI_PATH]
        return set(calls) if calls else {j for j in rel_jobs if j in ci_jobs}

    def build_jobs(self):
        """Jobs of release.yml (outside the quality gate) that compile the release."""
        gate = self.gate_jobs()
        return [j for j, v in self.rel["jobs"].items()
                if j not in gate and has_cmd(job_cmds(v), CARGO_BUILD)]

    # (1) quality gate -------------------------------------------------------

    def quality_gate(self):
        ci_jobs, rel_jobs = self.ci["jobs"], self.rel["jobs"]
        reusable = "workflow_call" in triggers(self.ci)
        calls = [j for j, v in rel_jobs.items()
                 if str(v.get("uses", "")).removeprefix("./") == CI_PATH]
        gate = self.gate_jobs()

        if calls and not reusable:
            self.bad("quality-job-uncovered",
                     f"release.yml calls {CI_PATH} but it has no workflow_call trigger, so its jobs are not part of the release run")
        for j in sorted(gate):
            if "if" in rel_jobs[j] or is_true(rel_jobs[j].get("continue-on-error")):
                self.bad("quality-job-uncovered", f"release.yml job {j} (part of the gate) can be skipped or may fail without stopping the release")
        for j, v in ci_jobs.items():
            if "if" in v or is_true(v.get("continue-on-error")):
                self.bad("quality-job-uncovered", f"ci.yml job {j} can be skipped or may fail without failing the gate (if: / continue-on-error)")

        for j, v in rel_jobs.items():
            if j in gate or j == ON_MAIN:
                continue
            cond = str(v.get("if", ""))
            if re.search(r"\b(always|failure|cancelled)\s*\(", cond):
                self.bad("no-quality-gate", f"release.yml job {j} runs even when jobs it needs fail (if: {cond.strip()})")
            r = reach(rel_jobs, j)
            if not gate:
                self.bad("no-quality-gate", f"release.yml job {j}: release.yml neither calls {CI_PATH} nor carries its jobs, so nothing gates it")
            elif not (r & gate):
                self.bad("no-quality-gate", f"release.yml job {j} does not need the quality gate ({', '.join(sorted(gate))}), directly or through another job")
            elif not calls:
                for c in ci_jobs:
                    if c not in r:
                        self.bad("quality-job-uncovered", f"ci.yml job {c} is not needed by release.yml job {j}")
            elif not gate <= r:
                self.bad("quality-job-uncovered", f"release.yml job {j} does not need every call of {CI_PATH}")
        if not calls:
            for c in ci_jobs:
                if c not in rel_jobs:
                    self.bad("quality-job-uncovered", f"ci.yml job {c} has no counterpart in release.yml, which does not call {CI_PATH}")

        # ci.yml must hold the checks the release relies on, as whole commands.
        ci_cmds = [c for v in ci_jobs.values() for c in job_cmds(v, loose=self.loose)]
        ci_uses = " ".join(uses_of(s) for _, _, s in all_steps(self.ci))
        needed = [
            ("cargo fmt --check", r"cargo\s+fmt\b.*--check"),
            ("cargo clippy with -D warnings", r"cargo\s+clippy\b[^\n]*-D\s+warnings"),
            ("cargo test", CARGO_TEST),
        ]
        for label, pat in needed:
            if not has_cmd(ci_cmds, pat):
                self.bad("quality-job-uncovered", f"ci.yml has no step running {label} as a command")
        if "gitleaks" not in ci_uses and not has_cmd(ci_cmds, r"gitleaks\b"):
            self.bad("quality-job-uncovered", "ci.yml has no secret scan (gitleaks)")
        if "cargo-deny" not in ci_uses and not has_cmd(ci_cmds, r"cargo\s+deny\b"):
            self.bad("quality-job-uncovered", "ci.yml has no licence check (cargo deny)")
        test_os = set()
        for v in ci_jobs.values():
            if has_cmd(job_cmds(v, loose=self.loose), CARGO_TEST):
                test_os |= runner_names(v)
        for j in self.build_jobs():
            for os_name in sorted(runner_names(rel_jobs[j]) - test_os):
                self.bad("quality-job-uncovered", f"release.yml job {j} builds on {os_name}, where ci.yml runs no tests")

    # (0) gate steps ---------------------------------------------------------

    def gate_steps(self):
        """(file, job id, step index, step) of every gate step; see GATE STEPS."""
        for jid, job in self.ci["jobs"].items():
            for idx, s in enumerate(steps_of(job)):
                if GATE_CARGO.search(run_text(s)) or GATE_CHECKER.search(run_text(s)):
                    yield CI_PATH, jid, idx, s
        for idx, s in enumerate(steps_of(self.rel["jobs"].get(ON_MAIN) or {})):
            if not uses_of(s).startswith("actions/checkout"):
                yield RELEASE_PATH, ON_MAIN, idx, s

    def gate_shape(self):
        self.loose = set()
        for name, jid, idx, s in self.gate_steps():
            why = gate_shape_problem(run_text(s)) if run_text(s) else "it has no run script (a gate step is one command)"
            if why:
                self.loose.add(id(s))
                self.bad("gate-step-shape", f"{name} job {jid} step {idx + 1} ({s.get('name', 'unnamed')}): {why}")

    # (0b) a gate step runs as written ---------------------------------------

    @staticmethod
    def not_false(d):
        """continue-on-error is present and is not the literal false (an expression is not accepted)."""
        return "continue-on-error" in d and str(d["continue-on-error"]).strip().lower() != "false"

    @staticmethod
    def env_problem(env, release_top=False):
        """The env names (or the shape) in an `env:` outside the allowlist; None when fine."""
        if env is None:
            return None
        if not isinstance(env, dict):
            return "an env that is not a plain mapping of names to values"
        bad = []
        for k, v in env.items():
            k, v = str(k), norm_expr(str(v))
            if k == "GH_TOKEN" and v == ENV_GH_TOKEN:
                continue
            if k == "TAG" and release_top and v == TAG_REF:
                continue
            bad.append(k)
        return ", ".join(sorted(bad)) or None

    @staticmethod
    def defaults_run(d):
        """(shell, working-directory, readable) from a workflow's or job's defaults.run."""
        df = d.get("defaults")
        if df is None:
            return None, None, True
        run = df.get("run") if isinstance(df, dict) else None
        if run is None and isinstance(df, dict):
            return None, None, True
        if not isinstance(run, dict):
            return None, None, False
        return run.get("shell"), run.get("working-directory"), True

    def scope_problems(self, where, d, workflow):
        """Shell, env and directory settings of a workflow or of a job holding gate steps."""
        shell, wd, readable = self.defaults_run(d)
        if not readable:
            self.bad("gate-step-shell", f"{where}: defaults.run cannot be read, so the shell its gate steps use is unknown")
        if shell is not None and str(shell).strip() != "bash":
            self.bad("gate-step-shell", f"{where} sets defaults.run.shell to {shell!r}; a gate step must run under bash")
        if wd is not None:
            self.bad("gate-env-override", f"{where} sets defaults.run.working-directory, which moves where gate steps run")
        if not workflow and self.not_false(d):
            self.bad("gate-continue-on-error", f"{where} has continue-on-error that is not the literal false")

    def gate_hygiene(self):
        """Gate steps, their jobs and their workflows must not change how a gate step runs: no other
        shell, no continue-on-error but the literal false, no env or working-directory override."""
        held = {}
        for name, jid, idx, s in self.gate_steps():
            held.setdefault(name, set()).add(jid)
            where = f"{name} job {jid} step {idx + 1} ({s.get('name', 'unnamed')})"
            if "shell" in s and str(s["shell"]).strip() != "bash":
                self.bad("gate-step-shell", f"{where} sets shell {s['shell']!r}; a gate step must run under bash (or the default)")
            if self.not_false(s):
                self.bad("gate-continue-on-error", f"{where} has continue-on-error that is not the literal false")
            if "working-directory" in s:
                self.bad("gate-env-override", f"{where} sets working-directory, which changes where the command runs")
        self.held = held
        for name, jids in held.items():
            doc = self.ci if name == CI_PATH else self.rel
            self.scope_problems(f"{name} (workflow level)", doc, workflow=True)
            for jid in sorted(jids):
                self.scope_problems(f"{name} job {jid}", doc["jobs"][jid], workflow=False)
        for j in sorted(self.gate_jobs()):
            if j in self.rel["jobs"] and self.not_false(self.rel["jobs"][j]):
                self.bad("gate-continue-on-error", f"release.yml job {j} (part of the quality gate) has continue-on-error that is not the literal false")
        for j, pidx in self.publishers().items():
            job = self.rel["jobs"][j]
            if self.not_false(job):
                self.bad("gate-continue-on-error", f"release.yml job {j} (publishes) has continue-on-error that is not the literal false")
            if self.not_false(steps_of(job)[pidx]):
                self.bad("gate-continue-on-error", f"release.yml job {j}: the release step has continue-on-error that is not the literal false")

    # (0b2) the environment a gate job runs in ---------------------------------

    def both(self):
        return ((CI_PATH, self.ci), (RELEASE_PATH, self.rel))

    def env_hygiene(self):
        """The env allowlist: the workflow, every job and every gate step set nothing but GH_TOKEN
        (and TAG at the top of release.yml). Every job of both files is a gate job."""
        for name, doc in self.both():
            why = self.env_problem(doc.get("env"), release_top=(name == RELEASE_PATH))
            if why:
                self.bad("gate-env-override", f"{name} (workflow level) sets env {why}, outside the allowlist (GH_TOKEN from github.token; TAG from inputs.tag in release.yml)")
            for jid, job in doc["jobs"].items():
                why = self.env_problem(job.get("env"))
                if why:
                    self.bad("gate-env-override", f"{name} job {jid} sets env {why}, outside the allowlist (GH_TOKEN from github.token only)")
        for name, jid, idx, s in self.gate_steps():
            why = self.env_problem(s.get("env"))
            if why:
                self.bad("gate-env-override", f"{name} job {jid} step {idx + 1} ({s.get('name', 'unnamed')}) sets env {why}, outside the allowlist (GH_TOKEN from github.token only)")

    def env_file_writes(self):
        for name, doc in self.both():
            for jid, idx, s in all_steps(doc):
                if ENV_FILE_WRITE.search(run_text(s)):
                    self.bad("gate-writes-env-file", f"{name} job {jid} step {idx + 1} ({s.get('name', 'unnamed')}) mentions GITHUB_ENV or GITHUB_PATH, which change the environment of every later step")

    @staticmethod
    def runner_problem(job):
        """Why a job's runs-on is not a GitHub-hosted label (None when it is)."""
        ro = job.get("runs-on")
        if not isinstance(ro, str):
            return "its runs-on is not a single label (a list or a group is not accepted)"
        ro = ro.strip()
        if norm_expr(ro) == "${{matrix.os}}":
            st = job.get("strategy")
            m = st.get("matrix") if isinstance(st, dict) else None
            names = []
            if isinstance(m, dict):
                os_ = m.get("os")
                names += os_ if isinstance(os_, list) else ([os_] if os_ is not None else [])
                names += [i["os"] for i in (m.get("include") or []) if isinstance(i, dict) and "os" in i]
            if not names:
                return "its runs-on is ${{ matrix.os }} but the matrix values cannot be read"
            bad = [str(n) for n in names if not (isinstance(n, str) and HOSTED_RUNNER.match(n))]
            return f"its matrix runs on {', '.join(bad)}, not a GitHub-hosted label" if bad else None
        if not HOSTED_RUNNER.match(ro):
            return f"it runs on {ro!r}, not a GitHub-hosted label (ubuntu-*, macos-*, windows-*)"
        return None

    def job_environment(self):
        """No container, no services, a hosted runner and a positive timeout, on every job."""
        for name, doc in self.both():
            for jid, job in doc["jobs"].items():
                where = f"{name} job {jid}"
                for key in ("container", "services"):
                    if key in job:
                        self.bad("gate-job-environment", f"{where} sets {key}:, which changes what its steps run in or against")
                if "uses" not in job:
                    why = self.runner_problem(job)
                    if why:
                        self.bad("gate-job-environment", f"{where}: {why}")
                if "timeout-minutes" in job:
                    t = str(job["timeout-minutes"]).strip()
                    if not (re.fullmatch(r"\d+(?:\.\d+)?", t) and float(t) > 0):
                        self.bad("gate-job-environment", f"{where} has timeout-minutes {t!r}, not a positive number")

    def coe_covered(self, name, jid):
        """A job an older rule already refuses for continue-on-error (one defect, one finding)."""
        job = (self.ci if name == CI_PATH else self.rel)["jobs"][jid]
        if jid in self.held.get(name, set()):
            return True
        if name == CI_PATH:
            return is_true(job.get("continue-on-error"))
        return (jid in self.gate_jobs() or jid in self.publishers()
                or (jid == ON_MAIN and is_true(job.get("continue-on-error"))))

    def chain_job_continue_on_error(self):
        for name, doc in self.both():
            for jid, job in doc["jobs"].items():
                if self.not_false(job) and not self.coe_covered(name, jid):
                    self.bad("chain-job-continue-on-error", f"{name} job {jid} has continue-on-error that is not absent or the literal false, so the job may fail without stopping the release")

    # (0c) ci.yml keeps running this checker ---------------------------------

    def release_graph_job(self):
        """ci.yml's release-graph job must run the checker and its tests, as gate steps (one command each,
        unskippable), so removing the check from CI is itself caught."""
        if "pull_request" not in triggers(self.ci):
            self.bad("ci-no-pull-request-trigger", f"{CI_PATH} has no pull_request trigger, so the checker would not run on a proposed change")
        job = self.ci["jobs"].get(RELEASE_GRAPH_JOB)
        if job is None:
            self.bad("release-graph-job-incomplete", f"{CI_PATH} has no job {RELEASE_GRAPH_JOB}, so nothing re-runs this check on every push")
            return
        if "if" in job:
            self.bad("release-graph-job-incomplete", f"{CI_PATH} job {RELEASE_GRAPH_JOB} can be skipped (if:)")
        cmds = job_cmds(job, loose=self.loose)
        if not has_cmd(cmds, CHECKER_CMD):
            self.bad("release-graph-job-incomplete", f"{CI_PATH} job {RELEASE_GRAPH_JOB} does not run scripts/check-release-graph.py as a gate step")
        if not has_cmd(cmds, CHECKER_TESTS_CMD):
            self.bad("release-graph-job-incomplete", f"{CI_PATH} job {RELEASE_GRAPH_JOB} does not run the checker's own tests (python3 -m unittest scripts/test_check_release_graph.py) as a gate step")
        for idx, s in enumerate(steps_of(job)):
            lines = [ln.strip() for ln in run_text(s).strip().splitlines()]
            if lines and lines[0] == SET_LINE:
                lines = lines[1:]
            cmd = lines[0] if len(lines) == 1 else None
            text = run_text(s)
            for mention, exact in (("check-release-graph.py", EXACT_CHECKER), ("test_check_release_graph", EXACT_TESTS)):
                if mention in text and cmd != exact:
                    self.bad("release-graph-command-inexact", f"{CI_PATH} job {RELEASE_GRAPH_JOB} step {idx + 1} must run exactly `{exact}`")
                    break

    # (1a) main's gate runs on the tag ---------------------------------------

    def quality_on_tag(self):
        wc_present = "workflow_call" in triggers(self.ci)
        if not wc_present:
            return
        wc = triggers(self.ci)["workflow_call"]
        inputs = wc.get("inputs") if isinstance(wc, dict) else None
        if not (isinstance(inputs, dict) and "ref" in inputs):
            self.bad("quality-not-on-tag", f"{CI_PATH} workflow_call declares no input `ref`, so main's gate cannot be told which commit to test")
        for jid, idx, s in all_steps(self.ci):
            if uses_of(s).startswith("actions/checkout") and norm_expr(str(with_of(s).get("ref", ""))) != CI_REF:
                self.bad("quality-not-on-tag", f"{CI_PATH} job {jid} step {idx + 1}: a checkout without `ref: ${{{{ inputs.ref }}}}` tests whatever the workflow was started on, not the tag")
        for j, v in self.rel["jobs"].items():
            if str(v.get("uses", "")).removeprefix("./") == CI_PATH:
                w = v.get("with") if isinstance(v.get("with"), dict) else {}
                ref = norm_expr(str(w.get("ref", "")))
                if ref == TAG_REF:
                    self.bad("tag-ref-shadowable", f"release.yml job {j} calls {CI_PATH} with `ref: ${{{{ inputs.tag }}}}`; a branch named like the tag would win over the tag. Use `ref: ${{{{ needs.{ON_MAIN}.outputs.sha }}}}`")
                elif ref != SHA_REF:
                    self.bad("quality-not-on-tag", f"release.yml job {j} calls {CI_PATH} without `ref: ${{{{ needs.{ON_MAIN}.outputs.sha }}}}`, so main's gate would not test the tagged commit")

    # (1b) the tagged commit is on main --------------------------------------

    def on_main_gate(self):
        rel_jobs = self.rel["jobs"]
        job = rel_jobs.get(ON_MAIN)
        if job is None:
            self.bad("no-on-main-gate", f"release.yml has no job named {ON_MAIN}, which must fail unless this run is on main and the tag's commit is an ancestor of origin/main")
            return
        if "if" in job or is_true(job.get("continue-on-error")):
            self.bad("no-on-main-gate", f"release.yml job {ON_MAIN} can be skipped or may fail without stopping the release (if: / continue-on-error)")
        steps = steps_of(job)
        if not any(uses_of(s).startswith("actions/checkout") and str(with_of(s).get("fetch-depth")).strip() == "0"
                   and "if" not in s for s in steps):
            self.bad("on-main-shallow", f"release.yml job {ON_MAIN} has no checkout with fetch-depth: 0, so origin/main and the tag's history are not all there")
        cmds = job_cmds(job, loose=self.loose)
        if not any(MAIN_REF_TEST.match(re.sub(r"""["']""", "", norm_expr(c))) for c in cmds):
            self.bad("no-main-ref-check",
                     f"release.yml job {ON_MAIN} has no gate step that fails unless $GITHUB_REF is {SOURCE_REF} "
                     "(test \"$GITHUB_REF\" = refs/heads/main)")
        fetch = [i for i, c in enumerate(cmds)
                 if re.match(r"git\s+fetch\b", c) and re.search(r"(?<!\S)origin(?!\S)", c)
                 and re.search(r"(?<![\w/-])main(?![\w/-])", c) and not swallowed(c)
                 and not DRY_RUN.search(c)]
        test = []
        for i, c in enumerate(cmds):
            m = re.match(r"git\s+merge-base\s+--is-ancestor\s+(\S+)\s+origin/main\s*$", c)
            if m and not swallowed(c) and TAG_COMMIT.match(re.sub(r"""[\s"']""", "", m.group(1))):
                test.append(i)
        if not (fetch and test and min(fetch) < max(test)):
            self.bad("no-on-main-gate",
                     f"release.yml job {ON_MAIN} lacks the gate steps `git fetch origin main` and then "
                     "`git merge-base --is-ancestor \"refs/tags/$TAG^{commit}\" origin/main` (the whole ref, not a bare name; not --dry-run)")
        tag_envs = [e["TAG"] for e in [self.rel.get("env"), job.get("env")] + [s.get("env") for s in steps]
                    if isinstance(e, dict) and "TAG" in e]
        if not tag_envs or any(norm_expr(str(v)) != TAG_REF for v in tag_envs):
            self.bad("no-on-main-gate", "release.yml does not set TAG from `${{ inputs.tag }}` (as an environment variable) for the on-main steps")
        checks = []
        for s in steps:
            lines = [l.strip() for l in run_text(s).strip("\n").split("\n") if l.strip()]
            if lines and lines[0] == SET_LINE:
                lines = lines[1:]
            m = TAG_CHECK.match(lines[0]) if len(lines) == 1 else None
            if m:
                checks.append((m.group(1), m.group(2)))
        listed = re.search(r"Tag name check: `([^`]+)`", self.checklist_text)
        if not checks or not listed or any(p != listed.group(1) for _, p in checks):
            self.bad("tag-pattern-mismatch",
                     f"the tag pattern checked in release.yml ({checks[0][1] if checks else 'none'}) and the `Tag name check:` "
                     f"line of {CHECKLIST_PATH} ({listed.group(1) if listed else 'none'}) are not the same")
        elif any(op != "=~" or p != TAG_REGEX for op, p in checks):
            self.bad("tag-check-loose",
                     f"release.yml job {ON_MAIN} checks the tag name with something other than "
                     f'[[ "$TAG" =~ {TAG_REGEX} ]]')
        for j in rel_jobs:
            if j != ON_MAIN and ON_MAIN not in reach(rel_jobs, j):
                self.bad("job-skips-on-main-gate",
                         f"release.yml job {j} does not need the {ON_MAIN} job, directly or through another job")

    def push_reachable(self):
        """Nothing a push (or a pull request, ...) starts may publish."""
        docs = [(CI_PATH, self.ci), (RELEASE_PATH, self.rel)]
        for p in sorted((self.root / ".github" / "workflows").glob("*.y*ml")):
            name = p.relative_to(self.root).as_posix()
            if name in (CI_PATH, RELEASE_PATH):
                continue
            try:
                docs.append((name, load_yaml(p)))
            except SystemExit as e:
                self.bad("publish-reachable-from-push", f"{name} cannot be read, so it cannot be shown not to publish: {e}")
        for name, doc in docs:
            extra = sorted(set(triggers(doc)) - {"workflow_dispatch", "workflow_call"})
            if not extra:
                continue
            for j, v in doc["jobs"].items():
                env = v.get("environment")
                env = env.get("name") if isinstance(env, dict) else env
                if any(self.is_publish(s) for s in steps_of(v)) or str(env).strip() == "release":
                    self.bad("publish-reachable-from-push",
                             f"{name} job {j} publishes, and {name} is started by {', '.join(extra)}; only a workflow_dispatch run may publish")

    def on_main_sha_output(self):
        """on-main resolves the tag's commit once and outputs it as `sha` (H1)."""
        job = self.rel["jobs"].get(ON_MAIN)
        if job is None:
            return True     # no-on-main-gate reports a missing job
        steps = steps_of(job)
        outs = job.get("outputs") if isinstance(job.get("outputs"), dict) else {}
        m = re.match(r"^\$\{\{steps\.([A-Za-z0-9_-]+)\.outputs\.sha\}\}$", norm_expr(str(outs.get("sha", ""))))
        why = None
        idx = next((i for i, s in enumerate(steps) if m and str(s.get("id", "")) == m.group(1)), None)
        if idx is None:
            why = "it has no output `sha` taken from a step's `sha` output"
        else:
            s = steps[idx]
            lines = [l.strip() for l in run_text(s).strip("\n").split("\n") if l.strip()]
            if lines and lines[0] == SET_LINE:
                lines = lines[1:]
            if lines != [RESOLVE_LINE]:
                why = f"the step that makes it must run exactly {RESOLVE_LINE} (not main's head, not $GITHUB_SHA)"
            elif "if" in s or "continue-on-error" in s or "env" in s:
                why = "the step that makes it has if/continue-on-error/env"
        if why:
            self.bad("on-main-no-sha-output", f"release.yml job {ON_MAIN}: {why}, so later jobs cannot use the tag's commit")
        return why is None

    def publish_tag_recheck(self):
        """publish-release re-fetches the tags and checks the tag still names the built commit, before releasing (M2)."""
        jobs = self.rel["jobs"]

        def one_line(s):
            if any(k in s for k in ("if", "continue-on-error", "env", "shell", "working-directory")):
                return None
            lines = [l.strip() for l in run_text(s).strip("\n").split("\n") if l.strip()]
            if lines and lines[0] == SET_LINE:
                lines = lines[1:]
            return lines[0] if len(lines) == 1 else None

        for pj, pidx in self.publishers().items():
            steps = steps_of(jobs[pj])
            fetches, compares = [], []
            for i, s in enumerate(steps):
                line = one_line(s)
                if not line:
                    continue
                if (re.match(r"git\s+fetch\b", line) and not re.search(r"[;&|<>$`()]", line)
                        and re.search(r"(?<!\S)--tags(?!\S)", line) and re.search(r"(?<!\S)origin(?!\S)", line)
                        and not DRY_RUN.search(line)):
                    fetches.append(i)
                if TAG_RECHECK.match(norm_expr(line)):
                    compares.append(i)
            good = [c for c in compares if any(f < c for f in fetches)]
            if not good:
                self.bad("publish-no-tag-recheck",
                         f"release.yml job {pj} publishes without two gate steps before it: `git fetch --force --tags origin`, then "
                         f'test "$(git rev-parse "refs/tags/$TAG^{{commit}}")" = "${{{{ needs.{ON_MAIN}.outputs.sha }}}}"; a tag moved or deleted '
                         "during the approval wait would publish something else")
            elif pidx < min(good):
                self.bad("release-before-tag-recheck", f"release.yml job {pj}: the release step comes before the tag recheck")

    def archive_test_fixtures(self):
        """The Package step, when it copies scripts/, leaves scripts/test-fixtures out (L7)."""
        for j, v in self.rel["jobs"].items():
            for idx, s in enumerate(steps_of(v)):
                lines = [l.strip() for l in run_text(s).split("\n")]
                cps = [i for i, l in enumerate(lines)
                       if re.match(r"cp\s+(?:-\S+\s+)*(?:\./)?scripts(?:/\*?)?(?:\s|$)", l)]
                if not cps:
                    continue
                dropped = any(re.match(r"rm\s+(?:-\S+\s+)+.*scripts/test-fixtures\S*\s*$", l) for l in lines[cps[0]:]) \
                    or re.search(r"--exclude[= ]\S*test-fixtures", run_text(s))
                if not dropped:
                    self.bad("archive-includes-test-fixtures",
                             f"release.yml job {j} step {idx + 1} copies scripts/ into the archive without removing scripts/test-fixtures "
                             "(rm -rf, or tar --exclude), so the deliberately broken workflows ship to users")

    # (1c) the tagged commit -------------------------------------------------

    def tagged_commit(self):
        trig = triggers(self.rel)
        d = trig.get("workflow_dispatch")
        inputs = d.get("inputs") if isinstance(d, dict) else None
        if not (isinstance(inputs, dict) and "tag" in inputs):
            self.bad("not-tagged-commit", "release.yml has no workflow_dispatch input `tag`, so there is no tag to release")
        builders = set(self.build_jobs())
        for name, doc in (("ci.yml", self.ci), ("release.yml", self.rel)):
            for jid, idx, s in all_steps(doc):
                w = with_of(s)
                if uses_of(s).startswith("actions/checkout"):
                    if "repository" in w:
                        self.bad("not-tagged-commit", f"{name} job {jid} checks out another repository")
                    if name == "release.yml":
                        if "ref" in w and norm_expr(str(w["ref"])) == TAG_REF:
                            self.bad("tag-ref-shadowable", f"release.yml job {jid} checks out `ref: ${{{{ inputs.tag }}}}`; a branch named like the tag would win over the tag. Use `ref: ${{{{ needs.{ON_MAIN}.outputs.sha }}}}`")
                        elif "ref" in w and norm_expr(str(w["ref"])) != SHA_REF:
                            self.bad("not-tagged-commit", f"release.yml job {jid} checks out ref {w['ref']}, not ${{{{ needs.{ON_MAIN}.outputs.sha }}}}")
                        if "ref" not in w and jid in builders:
                            self.bad("not-tagged-commit", f"release.yml job {jid} builds but its checkout has no ref, so it would build the dispatching branch, not the tag")
                if uses_of(s).startswith("actions/download-artifact") and ("run-id" in w or "repository" in w):
                    self.bad("not-tagged-commit", f"{name} job {jid} downloads an artifact from another run")
                if re.search(r"\bgit\s+(checkout|switch)\b", run_text(s)):
                    self.bad("not-tagged-commit", f"{name} job {jid} step {idx + 1} switches the checked-out commit")
                if name == "release.yml" and uses_of(s).startswith("softprops/action-gh-release") \
                        and norm_expr(str(w.get("tag_name", ""))) != TAG_REF:
                    self.bad("not-tagged-commit", f"release.yml job {jid}: the release step must set tag_name: ${{{{ inputs.tag }}}}, or a dispatched run releases against the branch")

    # (1d) the checkout is the commit that was meant -------------------------

    def needs_outputs_direct(self):
        """S1: GitHub's `needs` context holds a job's direct dependencies only, so a job that
        reads needs.X.outputs.* without listing X gets an empty string."""
        for name, doc in (("ci.yml", self.ci), ("release.yml", self.rel)):
            for jid, job in doc["jobs"].items():
                body = json.dumps({k: v for k, v in job.items() if k != "needs"}, default=str)
                for x in sorted(set(NEEDS_OUTPUT.findall(body)) - set(needs_of(job))):
                    if x == ON_MAIN and name == "release.yml" and ON_MAIN not in reach(doc["jobs"], jid):
                        continue    # not waiting for on-main at all: job-skips-on-main-gate reports that, once
                    self.bad("needs-output-not-direct",
                             f"{name} job {jid} reads needs.{x}.outputs but does not list {x} in its own needs (only direct dependencies are in the context; "
                             "it gets an empty string, and a checkout with an empty ref builds main's head)")

    def head_asserts(self):
        """S1: the step after each checkout fails unless HEAD is the commit that was meant."""
        rel_jobs = self.rel["jobs"]
        for jid in self.build_jobs():
            steps = steps_of(rel_jobs[jid])
            cos = [i for i, s in enumerate(steps) if uses_of(s).startswith("actions/checkout")]
            if not cos:
                self.bad("build-checkout-unasserted", f"release.yml job {jid} builds without a checkout")
            for i in cos:
                line = plain_line(steps[i + 1]) if i + 1 < len(steps) else None
                if not (line and BUILD_HEAD_ASSERT.match(line)):
                    self.bad("build-checkout-unasserted",
                             f"release.yml job {jid}: the step after the checkout (step {i + 1}) is not the gate step "
                             f'test "$(git rev-parse HEAD)" = "${{{{ needs.{ON_MAIN}.outputs.sha }}}}", so a checkout that fell back to another commit would be built and attested')
        for jid, job in self.ci["jobs"].items():
            steps = steps_of(job)
            for i, s in enumerate(steps):
                if not uses_of(s).startswith("actions/checkout"):
                    continue
                nxt = steps[i + 1] if i + 1 < len(steps) else None
                line = plain_line(nxt, allowed=("if",)) if nxt else None
                cond = re.sub(r"\s", "", norm_expr(str(nxt.get("if", "")))) if nxt else ""
                if not (line and CI_HEAD_ASSERT.match(line) and cond in CI_REF_SET):
                    self.bad("ci-checkout-unasserted",
                             f"ci.yml job {jid}: the step after the checkout (step {i + 1}) is not `if: inputs.ref != ''` with "
                             'test "$(git rev-parse HEAD)" = "${{ inputs.ref }}", so a gate that tested another commit would pass')

    def sha_shape_assert(self):
        """S2: after the resolve step, a gate step requires the sha output to be 40 hex digits."""
        job = self.rel["jobs"].get(ON_MAIN)
        if job is None:
            return
        steps = steps_of(job)
        outs = job.get("outputs") if isinstance(job.get("outputs"), dict) else {}
        m = re.match(r"^\$\{\{steps\.([A-Za-z0-9_-]+)\.outputs\.sha\}\}$", norm_expr(str(outs.get("sha", ""))))
        idx = next((i for i, s in enumerate(steps) if m and str(s.get("id", "")) == m.group(1)), None)
        if idx is None:
            return      # on-main-no-sha-output reports it
        shape = re.compile(SHA_SHAPE_ASSERT % re.escape(m.group(1)))
        if not any((l := plain_line(s)) and shape.match(l) for s in steps[idx + 1:]):
            self.bad("sha-shape-unasserted",
                     f"release.yml job {ON_MAIN}: no gate step after the resolve step requires the sha to match ^[0-9a-f]{{40}}$ "
                     "(echo succeeds even when git rev-parse fails, so an empty or garbage sha would go on)")

    def target_commitish(self):
        """S3: the release step creates nothing at main's head: target_commitish is the sha output."""
        for jid, idx, s in all_steps(self.rel):
            if uses_of(s).startswith("softprops/action-gh-release") \
                    and norm_expr(str(with_of(s).get("target_commitish", ""))) != SHA_REF:
                self.bad("target-commitish-not-sha",
                         f"release.yml job {jid} step {idx + 1}: the release step must set target_commitish: ${{{{ needs.{ON_MAIN}.outputs.sha }}}} (not main, not absent)")

    # (3) pinned actions -----------------------------------------------------

    def pinned_actions(self):
        pat = re.compile(r"^\s*(?:-\s*)?uses:\s*(\S+)(.*)$")
        for name, text in self.raw.items():
            for n, line in enumerate(text.split("\n"), 1):
                m = pat.match(line)
                if not m:
                    continue
                target, rest = m.group(1).strip("'\""), m.group(2)
                if target.startswith("./"):
                    continue
                if target.startswith("docker://"):
                    ok = re.search(r"@sha256:[0-9a-f]{64}$", target) is not None
                else:
                    ok = "@" in target and FULL_SHA.match(target.rsplit("@", 1)[1]) is not None
                if not ok:
                    self.bad("unpinned-action", f"{name}:{n} {target} is not pinned to a full 40-character commit")
                elif not re.match(r"\s*#\s*\S+", rest):
                    self.bad("unpinned-action", f"{name}:{n} {target} has no tag comment after the commit")

    # (4) exact toolchain ----------------------------------------------------

    def exact_toolchain(self):
        m = re.search(r'^\s*channel\s*=\s*"([^"]*)"', self.toolchain_text, re.M)
        channel = m.group(1) if m else None
        if channel is None or not EXACT_VERSION.match(channel):
            self.bad("toolchain-not-exact", f"{TOOLCHAIN_PATH} channel is {channel!r}, not an exact x.y.z version")
        for name, doc in (("ci.yml", self.ci), ("release.yml", self.rel)):
            for jid, idx, s in all_steps(doc):
                u = uses_of(s)
                if "rust-toolchain" in u or u.startswith("actions-rs/toolchain"):
                    tc = str(with_of(s).get("toolchain", ""))
                    if not EXACT_VERSION.match(tc):
                        self.bad("toolchain-not-exact", f"{name} job {jid} installs Rust toolchain {tc or '(none named)'}, not an exact version")
                    elif channel and tc != channel:
                        self.bad("toolchain-not-exact", f"{name} job {jid} installs Rust {tc} but {TOOLCHAIN_PATH} says {channel}")
                if re.search(r"\brustup\s+(default|update|toolchain\s+install|override\s+set)\s+(stable|beta|nightly)\b", run_text(s)):
                    self.bad("toolchain-not-exact", f"{name} job {jid} selects a Rust channel by name")

    # (2) verification before publishing -------------------------------------

    SHA_RECHECK = r"(sha256sum|shasum\s+-a\s+256)\s+(-c|--check)\b"
    EVIDENCE = [
        ("sha256 re-check after download", SHA_RECHECK),
        ("unpacking the archive", r"tar\s+(-?[a-zA-Z]*x[a-zA-Z]*|--extract)\b|unzip\b"),
        ("running the programs with --version", r"(?!echo\b|printf\b)\S.*(?<![\w-])--version\b"),
        ("scripts/check-binary-clean.sh", r"(?:(?:ba)?sh\s+)?\S*check-binary-clean\.sh\b"),
    ]

    @staticmethod
    def is_publish(step):
        u = uses_of(step)
        if re.match(r"(softprops/action-gh-release|ncipollo/release-action|actions/create-release|actions/upload-release-asset)\b", u):
            return True
        return re.search(r"\bgh\s+release\s+(create|upload)\b|\bgh\s+api\b[^\n]*releases", run_text(step)) is not None

    def evidence(self, job, upto=None):
        """The verification steps found in a job, before step index `upto`."""
        cmds = job_cmds(job, upto)
        found = set()
        for label, pat in self.EVIDENCE:
            if label == "running the programs with --version":
                hit = any(re.match(pat, unquoted(c)) or (re.match(r"(?!echo\b|printf\b)\S", c) and re.search(r"(?<![\w-])--version\b", unquoted(c))) for c in cmds)
            else:
                hit = any(re.match(pat, c) for c in cmds)
            if hit:
                found.add(label)
        return found

    def publishers(self):
        jobs = self.rel["jobs"]
        return {j: next(i for i, s in enumerate(steps_of(v)) if self.is_publish(s))
                for j, v in jobs.items() if any(self.is_publish(s) for s in steps_of(v))}

    def artifact_verification(self):
        jobs = self.rel["jobs"]
        publishers = self.publishers()
        if not publishers:
            self.bad("no-artifact-verification", "release.yml has no publishing step to verify before")
            return
        every = {label for label, _ in self.EVIDENCE}
        anywhere = set()
        for v in jobs.values():
            anywhere |= self.evidence(v)
        for pj, pidx in publishers.items():
            before = set()
            for j in reach(jobs, pj):
                before |= self.evidence(jobs[j])
            before |= self.evidence(jobs[pj], upto=pidx)
            missing = every - before
            if not missing:
                continue
            if not (missing & anywhere):
                self.bad("no-artifact-verification",
                         f"release.yml job {pj} publishes without: {', '.join(sorted(missing))}")
            else:
                self.bad("verification-after-publish",
                         f"release.yml job {pj} publishes before, or without waiting for: {', '.join(sorted(missing & anywhere))}")
            # a part that exists nowhere at all is a missing verification too
            nowhere = missing - anywhere
            if nowhere and (missing & anywhere):
                self.bad("no-artifact-verification", f"release.yml verifies nothing for: {', '.join(sorted(nowhere))}")

    # (5) provenance, environment, permissions -------------------------------

    def provenance(self):
        jobs = self.rel["jobs"]
        publishers = self.publishers()
        builders = self.build_jobs()

        # the publishing job runs in the protected environment "release"
        for pj in publishers:
            env = jobs[pj].get("environment")
            name = env.get("name") if isinstance(env, dict) else env
            if str(name).strip() != "release":
                self.bad("publish-no-release-environment",
                         f"release.yml job {pj} publishes but does not run in environment: release (found {name!r})")

        # every building job attests each archive
        attesting = set()
        if not builders:
            self.bad("no-build-provenance", "release.yml has no job that builds the release, so nothing is attested")
        for j in builders:
            if any(uses_of(s).startswith("actions/attest-build-provenance@") and "if" not in s
                   and not is_true(s.get("continue-on-error")) for s in steps_of(jobs[j])):
                attesting.add(j)
            else:
                self.bad("no-build-provenance", f"release.yml job {j} builds the archives but has no actions/attest-build-provenance step")

        # the attestation permissions sit on the building job and nowhere else
        for name, doc in (("ci.yml", self.ci), ("release.yml", self.rel)):
            if perm_writes(doc.get("permissions")):
                self.bad("attestation-permissions-misplaced", f"{name} grants id-token/attestations write at workflow level; it belongs on the building job only")
            for j, v in doc["jobs"].items():
                if perm_writes(v.get("permissions")) and not (doc is self.rel and j in builders):
                    self.bad("attestation-permissions-misplaced", f"{name} job {j} has id-token/attestations write but does not build; only the building job may")
        for j in attesting:
            if perm_writes(jobs[j].get("permissions")) != {"id-token", "attestations"}:
                self.bad("attestation-permissions-misplaced", f"release.yml job {j} attests but lacks id-token: write and attestations: write in its own permissions")

        # the attestation covers the archive the build made
        for j in attesting:
            steps = steps_of(jobs[j])
            made = next((m.group(1).strip("\"'") for s in steps
                         for m in [TAR_OUTPUT.search(norm_expr(run_text(s)))] if m), None)
            subjects = [norm_expr(str(with_of(s).get("subject-path", ""))).strip("\"'") for s in steps
                        if uses_of(s).startswith("actions/attest-build-provenance@")]
            if made is None or not subjects or any(sp != made for sp in subjects):
                self.bad("attest-subject-not-archive",
                         f"release.yml job {j}: the attested subject-path ({', '.join(subjects) or 'none'}) is not the archive "
                         f"its tar -czf writes ({made or 'no tar -czf found'})")

        # whoever re-checks the sha256, and whoever publishes, verifies the attestation first,
        # and only an attestation made by this workflow on main counts
        for j, v in jobs.items():
            rechecks = has_cmd(job_cmds(v), self.SHA_RECHECK)
            if j in publishers:
                cmds, where = job_cmds(v, publishers[j]), "before its release step"
            elif rechecks:
                cmds, where = job_cmds(v), "in the job"
            else:
                continue
            verifies = [norm_expr(c) for c in cmds if re.match(ATTEST_VERIFY, norm_expr(c)) and not swallowed(c)
                        and verifies_archive(norm_expr(c), cmds)]
            if not verifies:
                self.bad("provenance-not-verified",
                         f"release.yml job {j} has no `gh attestation verify <archive> --repo ${{{{ github.repository }}}}` command {where}")
                continue
            for c in verifies:
                extra = verify_flag_problem(c)
                if extra:
                    self.bad("attestation-verify-unscoped", f"release.yml job {j}: `gh attestation verify` {extra}")
                    break
                signer = re.search(r"--signer-workflow[ =](\S+)", c)
                source = re.search(r"--source-ref[ =](\S+)", c)
                if not (signer and signer.group(1).strip("\"'") == SIGNER_WORKFLOW
                        and source and source.group(1).strip("\"'") == SOURCE_REF):
                    self.bad("attestation-verify-unscoped",
                             f"release.yml job {j}: `gh attestation verify` needs --signer-workflow ${{{{ github.repository }}}}/.github/workflows/release.yml "
                             f"and --source-ref {SOURCE_REF}, or an archive attested by another workflow or branch would pass")
                    break

    def prerelease(self):
        for j, v in self.rel["jobs"].items():
            for s in steps_of(v):
                if not self.is_publish(s):
                    continue
                value = with_of(s).get("prerelease")
                if not uses_of(s) or not isinstance(value, str) or not PRERELEASE_FROM_TAG.match(value.strip()):
                    self.bad("prerelease-not-from-tag",
                             f"release.yml job {j}: the release step's prerelease must be ${{{{ contains(inputs.tag, '-') }}}} (found {value!r}), so v1.0.0-rc1 is not published as a full release")

def main(argv):
    if len(argv) != 2:
        print("usage: check-release-graph.py <root holding .github/workflows and rust-toolchain.toml>", file=sys.stderr)
        return 2
    if not Path(argv[1]).is_dir():
        print(f"error: {argv[1]} is not a directory", file=sys.stderr)
        return 2
    violations = Checker(argv[1]).run()
    for v in violations:
        print(v)
    if violations:
        print(f"{len(violations)} violation(s). This is a local structural check; no workflow was run.")
        print(NOT_CHECKED_NOTE)
        return 1
    print("ok: the release graph holds (local structural check; no workflow was run)")
    print(NOT_CHECKED_NOTE)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
