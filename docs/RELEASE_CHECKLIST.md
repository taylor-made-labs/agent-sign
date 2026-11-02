# Release checklist

agent-sign 0.1.0 is ready for users when every check below passes. It
covers both halves of "ready": the tool works (F), and someone who finds it
can install it and trust what it says (R). Each check says how it's run, so
anyone can rerun it; the status column records the latest run.

Status: **Pass**, **Fail**, **Open** (not run yet), **Limit** (it doesn't
hold, and the README says so), **Person** (only the maintainer can do it), or
**Superseded** (a later change made the check's expectation wrong; see below).

## Superseded by per-agent identities and the identity review (28 Oct 2026)

Each agent now signs, authors and commits as its own identity, under a
certificate from the agents' authority, and the identity review fixed nine
findings in that change (see [ADVERSARIAL_REVIEW.md](ADVERSARIAL_REVIEW.md)).
These parts of the checks below no longer describe the aim, and are marked
**Superseded** where they appear:

- **F1's manual check** that an agent commit shows **Verified** on GitHub:
  agent commits show as Unverified by design (GitHub doesn't check SSH
  certificate signatures, and they aren't the person's). The automated half
  stands, now checked under the agents' trust line.
- **F3's editor-button Limit** ("it looks like an agent"): a commit with no
  terminal and no agent mark is now left to git, unsigned, under git's own
  names, never attributed to an agent.
- **F7's "signed with the agent key"**: now "signed as the agent's own
  identity". Its coverage rows for merge, cherry-pick, rebase, revert, pull
  and shell aliases ("would have signed with the person's key") were fixed on
  26 Oct (never the person's key) and 28 Oct (signed as the agent, only in
  the repository and on the branch the run started from).
- **F10 (commits name the agent)'s "a configured name is kept"**: an
  identified agent's signed commit is its identity's, whatever the config.
- **R3's open item** "agent commits show as Verified for the person":
  resolved; they're the agent's.
- **P3's "key kept"**: on upgrade the installer deletes the shared agent
  key's private half (stored unprotected, so exposed), keeping its public
  half; no private key is kept across upgrades, since the agents' authority
  lives only in the service's memory.

## F: the tool works

| # | Check | How it's run | Status |
|---|---|---|---|
| F1 | Agent commits are signed and verify | Automated: `tests/test_e2e_git_commit.rs` and `tests/test_signature_equivalence.rs` check `git log --show-signature` and `ssh-keygen -Y verify`. Manual, once: an agent commit pushed to GitHub shows **Verified**. | **Pass** (automated, 7 Oct 2026; under the agents' trust line since 28 Oct); GitHub **Superseded** (Unverified by design) |
| F2 | One approval, then no more asking | Automated: one approval, then 20 agent commits in the same scope, counting approval requests (must be exactly 1). `tests/test_approval_scope.rs`. | **Pass** (7 Oct 2026) |
| F3 | Your own commits never use the agent key | Automated: a commit from a terminal goes to your normal git and signing (`tests/test_human_isolation.rs`). Manual: an editor's commit button and GitHub Desktop. | Terminal **Pass**; editor buttons **Superseded** (28 Oct 2026: unmarked commits with no terminal are left to git, unsigned, never an agent's) |
| F4 | Fails closed | Automated: with no lease, a revoked lease, an expired lease, a forged or replayed token, or the service stopped, an agent commit is refused with a message saying why, and is never signed with another key. | **Pass** (7 Oct 2026): `tests/test_edge_cases.rs` (denied, revoked, ended, forged and reused tokens, service stopped: each refused, and no commit exists afterwards) |
| F5 | The rules refuse with a reason | Automated: commits on `main`/`master`, touching CI workflows or key files, over a diff-size limit the person set, or over the rate limit are refused, each with its own message. | **Pass** (7 Oct 2026): `tests/test_edge_cases.rs` (protected branch without asking, CI workflow and key files, diff size, rate limit) |
| F10 | Commits name the agent | Automated: with each known agent mark, or `AGENT_SIGN_AGENT_NAME`, the commit's author is that agent; a configured name is kept (`tests/test_agent_name.rs`). | **Pass** (7 Oct 2026); "a configured name is kept" **Superseded** (28 Oct 2026: an identified agent's name always) |
| F11 | The identity review's findings stay fixed | Automated: `tests/test_identity_review_fixes.rs`, one regression test per finding (repository files only tighten; unsigned agent commits; tokens bound to repository and branch; strict config; unmarked commits left to git; well-formed principals; run rate limits, session-key cap and canonical paths; leaked tokens; branch case), each recorded failing before its fix. Manual: the installer's step that retires the shared key, run on its own in a throwaway folder (28 Oct 2026: key moved, 0600 in a 0700 folder, `.pub` and `allowed_signers` untouched, commands printed); the whole installer on macOS is **Person**. | **Pass** (28 Oct 2026) |
| F6 | Terms never grow after approval | Automated: `tests/test_lease_terms.rs` (config can only narrow; an unreadable ceiling stops the service). | **Pass** (7 Oct 2026) |
| F7 | Real agents actually go through it | Manual, recorded: Claude Code, Codex and Cursor, each started the normal way, on macOS and on Linux, make a commit; the commit is signed with the agent key, or `agent-sign doctor` says plainly that this agent bypasses the wrapper. | See "F7: coverage" below. |
| F8 | Edge cases, repeated | Automated: two agents committing at once (same repository and different ones), the service restarted mid-work, hundreds of commits in a row, repository paths with spaces and non-ASCII characters, symlinked repositories, worktrees, detached HEAD, `--amend`, and each approval scope's boundaries (a folder lease saved earlier doesn't cover a sibling whose name starts the same). Each case runs enough times to rule out flakes. | Mostly **Pass** (7 Oct 2026): `tests/test_edge_cases.rs` covers paths with spaces and accents, a symlinked repository (one lease), a worktree, detached HEAD, `--amend`, 200 commits in a row, two agents committing at once in two repositories, and a restart between commits; `tests/test_service_restart.rs` covers a commit during a restart; the full suite (117 tests) passed 2 runs in 2. **Limit**: a home folder long enough to push the socket path past 104 bytes (macOS) stops the service. Not yet: two agents committing in the same repository at once (git itself locks the index). |
| F9 | An approval covers the narrowest thing by default | Automated: the approval covers this branch of this repository and nothing else (another branch, another repository in the same folder, and the same branch name elsewhere each ask again); with `allow_branch_switching = true` it covers the repository's other unprotected branches, still only that repository; folder and everywhere leases saved earlier still work and revoke (`tests/test_approval_scope.rs`, with a stand-in owner). Changed 19 Oct 2026 on purpose, with the one-prompt change: the check used to be that the person chooses the scope in a dialog (this repository, a folder, or everywhere). That choice was removed, so the check now asks for the narrowest default instead. | Automated **Pass** (19 Oct 2026). The earlier real-dialog pass (9 Oct) no longer applies. |
| F10 | A click alone can't approve a lease | Automated: `tests/test_device_owner_approval.rs`: failed, cancelled, timed-out or unavailable authentication approves nothing; success approves this repository; `agent-sign deny` wins over a late yes; the source has no dialog of its own (no AppleScript, no button), no Linux dialog, no terminal prompt; one prompt at a time; the hold-back after a refusal; at most 4 requests waiting; a nonexistent repository or a path or branch with control or invisible characters is refused unasked; the reason text says the branch, the repository's name and path and how long, in at most 200 characters keeping the branch and name; a branch that could pose as prompt text ("typo fix in scratch (~/tmp/scratch)", U+3164, right-to-left letters) or that isn't the one checked out is refused unasked; a linked worktree is shown as its repository. A program that can be installed must not contain the test stand-in: `cargo test --release` fails to compile (tested), the installer refuses a program that contains it (tested), and `strings target/release/agent-signd \| grep AGENT_SIGN_TEST_` finds nothing. Manual, once per install on a Mac: one real approval, by Touch ID (or the login password), in one prompt that names "agent-sign" (not "agent-signd") and reads "let an agent sign commits on branch ... in ... (...)"; and one cancelled prompt that refuses. | Automated **Pass** (19 Oct 2026). Real Touch ID **Open**: needs the maintainer's finger after installing this build. The prompt's name ("agent-sign", from the app bundle) and wording are **Open** until seen. Linux: no authenticator, no prompt (stated limit). |

## R: the release is usable

| # | Check | How it's run | Status |
|---|---|---|---|
| R1 | No secrets in the history | `python3 scripts/release/scan-history-secrets.py . --all`, and gitleaks in CI once the CI patch is applied. | **Pass** (8 Oct 2026): gitleaks and the history scan in CI, and locally (0 findings over 269 file versions) |
| R2 | License: MIT OR Apache-2.0 | `LICENSE-MIT`, `LICENSE-APACHE`, and `license = "MIT OR Apache-2.0"` in `Cargo.toml`. A dependency license check (`cargo deny`) in CI. | **Pass** (7 Oct 2026): files, and `cargo deny check` on the Pi: advisories, bans, licenses, sources all ok |
| R3 | Fresh readers trust it | Two new readers given only `README.md` and `docs/INSTALL.md` say what it does, what it doesn't protect against, and every reason they'd hesitate to use it. Each reason gets fixed or is a stated limit. A held-out reader checks only at the end. | First round done (7 Oct 2026): two readers (a developer, an engineering lead). Fixed from their reports: the opening overclaimed agent identity; GitHub key added without asking; agents in terminal panes skipped the tool; no security policy; the installer's reach shown only in INSTALL.md (it now lists its changes and asks). Left for the maintainer: agent commits show as Verified for the person (a direction, not a wording fix). Held-out reader **Open**, after the remaining fixes. |
| R4 | Every claim is backed | Each claim in the README points to an F check that passes, or is stated as a limit. | **Open** |
| R5 | Clean install from a release | On a clean Mac and a clean Linux machine, following only the README with a downloaded release (no Rust), the install ends in a verified agent commit. Repeatable on Linux: `scripts/release/install-test.sh` (fresh install to a verified commit, upgrade from agent-sign's layout keeping key and lease, a state folder linked elsewhere, uninstall; 31 checks, in throwaway homes with a stand-in systemd). | Linux from source **Pass** on the Pi (ARM64), 7 Oct 2026: 31 of 31, and it catches planted flaws (2 of 2). From a release **Open** (no release yet). macOS **Person**: the installer replaces the live LaunchAgent, so it's run on the Mac by its owner. |
| R6 | CI on every push | macOS, Linux x86_64 and Linux ARM64: fmt, clippy, tests, secret scan. | **Pass** (8 Oct 2026): applied by the maintainer; all 7 jobs pass (tests on macOS, Linux x86_64 and ARM64; secret scan; cargo deny; install test on both Linux architectures) |
| R7 | Release downloads and Homebrew | A tag builds archives for macOS arm64 and x86_64 and Linux x86_64 and ARM64, with `SHA256SUMS.txt`; the formula installs from them. The formula's setup step is `install.sh --from-homebrew <prefix>`. | **Open** |
| R8 | Nothing is published unless it was checked | No tag push starts anything that publishes. `release.yml` is dispatched by hand on `main` with the tag as its input; its first job fails unless the run is on `main`, the tag name has the release form and the tag's commit is an ancestor of `origin/main`, and then resolves the tag to its commit once (the `sha` output); every later job needs it, and `main`'s own `ci.yml` (called with that sha as its `ref`) must pass on the tagged commit, in that same run, before anything is built from that same sha (never from the bare tag name, which a branch of the same name would shadow); each archive's sha256 is recorded at build and re-checked after download, in `verify-artifacts` and again in `publish-release`, and each archive's build provenance is attested at build and verified with `gh attestation verify` (requiring this workflow, run on `main`) in both of those jobs, before anything is published; publishing runs in the `release` environment, first re-fetches the tags and fails unless the tag still names the sha that was built, and a tag with a `-` in it publishes as a prerelease; each archive is unpacked on its own platform, its programs run `--version`, and `scripts/check-binary-clean.sh` passes; every third-party action is pinned to a full commit with its tag in a comment; and the Rust toolchain is pinned to an exact version in `rust-toolchain.toml`. Automated, **locally and structurally only**: `python3 scripts/check-release-graph.py .` checks the shape of the two workflow files and `python3 -m unittest scripts/test_check_release_graph.py` checks the checker against good and bad examples (one per rule and per way round it found so far). It runs no workflow, so it cannot show that GitHub runs them as written; the first tagged release is that test. It also cannot see the repository settings the gate relies on (the `release` environment's required reviewers and deployment branches, branch protection on `main`, the tag ruleset; load-bearing, see below): those are listed under [Repository settings](#repository-settings-the-checker-cannot-see). | Structural check **Pass** (1 Nov 2026), also run by `ci.yml`'s `release-graph` job. Repository settings **Open** (Taylor sets them; see below). A real tagged run **Open** (no release yet). |

## F7: coverage

Run with `scripts/release/coverage-probe.sh` (11 Oct 2026, the maintainer's
Mac, build da05c38). Each row has an agent, or a way of running git, make one
commit in a throwaway repository on `main`: agent-sign refuses it as
protected (CAUGHT), or the real git runs it (MISSED; the person's real
signer is never called, a stand-in records that it would have been). The
probe was calibrated first: plain `git` from an agent's shell is CAUGHT,
`/usr/bin/git` is MISSED.

| Where an agent commits | Result |
|---|---|
| Claude Code, desktop app | CAUGHT |
| Claude Code, command line started from a terminal | CAUGHT |
| Claude Code (or any agent) run as a background job: launchd, cron, a scheduled task, with the system's default PATH | **MISSED**: would have signed with the person's key |
| Merge, cherry-pick, rebase, revert, pull | **MISSED**: would have signed with the person's key (stated limit) |
| A commit inside one of the person's git shell aliases | **MISSED**: would have signed with the person's key (stated limit) |
| hetzner and the Pi | **MISSED**: agent-sign isn't installed there |
| Gemini CLI | not run: its sign-in failed (account tier error) |
| Codex | not run: account at its usage limit until 21 Oct |
| OpenCode | not run: its config file is invalid |
| Cursor's agent | not run: needs the person (a desktop app) |

Every MISSED row on the Mac has the same cause: agent-sign catches commits
at the `git` on PATH, and these run git without it.

## Security reviews

Two independent reviews (10 Oct 2026) of the changes since the build then
installed. The first found that commits read as "signing off" could be
signed with the person's own key (a regression, never installed); it and
the other findings are fixed with tests (8e85354, 300ebf4). The second
confirmed those fixes and found older gaps (aliases of aliases, `--amend`,
quoted and renamed paths, `diff.relative`, first-commit size), fixed in
da05c38. Open, and stated in the README: a commit inside one of the
person's git shell aliases, like merges and rebases, runs git's own copy
of itself and so goes to the person's own signing.

Installed on the maintainer's Mac on 10 Oct (da05c38): 12 of 12 install
checks, doctor clean, 17 approvals kept. cas's git tests (`live`,
`git-env`), which left about ten approval dialogs per run before, ran with
none, and all 10 passed.

## Only the maintainer

| # | What | Why only them |
|---|---|---|
| P1 | ~~Apply `docs/release/ci-workflows.patch` and push.~~ Done 8 Oct. | Agents can't change `.github/workflows/`. |
| P2 | Turn on private vulnerability reporting (Settings, Code security), which `SECURITY.md` points to. | A repository setting. |
| P3 | ~~Click the real approval dialog once on macOS (F9), and run the installer on the Mac (R5).~~ Done 9 Oct: installed over the live service (key kept, doctor clean), dialog answered. | It replaces the live service on the maintainer's machine. |
| P4 | Merge `release/v0.1` into `main`, and tag `v0.1.0`. | Agents don't commit to `main`. |

## Last: onboarding and polish

Not needed for 0.1.0, but on the roadmap: `agent-sign upgrade` with
automatic rollback, an install with no terminal steps, and a first-run page.

## Rerunning the checks

```sh
cargo fmt --check && cargo clippy --all-targets --locked -- -D warnings && cargo test --locked
python3 scripts/release/scan-history-secrets.py . --all
git apply --check docs/release/ci-workflows.patch
python3 scripts/check-release-graph.py . && python3 -m unittest scripts/test_check_release_graph.py
```

### Cutting a release

Pushing a tag starts nothing, and no workflow that a push starts can publish.
To release:

1. Merge the change to `main` through a pull request, with its checks passing.
2. Push the tag (`vX.Y.Z`, for example `v1.2.3`, or `v1.2.3-rc1` for a
   prerelease; the exact form is the "Tag name check" below) on the commit on `main` to release. Only the maintainer can
   create it (the tag ruleset below).
3. Dispatch the Release workflow from `main` with the tag as its input
   (Actions, Release, Run workflow, "Use workflow from: main", Tag: the tag;
   or `gh workflow run release.yml --ref main -f tag=vX.Y.Z`). This file,
   dispatched from any other branch, stops at its first job. A weakened copy
   on another branch could leave that check out: see
   [Repository settings](#repository-settings-the-checker-cannot-see) for what
   stops that and what doesn't.
4. Approve the publish when `publish-release` pauses for the environment's
   required reviewers.

The quality gate runs `main`'s `ci.yml` on the tagged commit, including the
checker and its tests, `rust-toolchain.toml` and `scripts/release/install-test.sh`
as the tag has them. A tag on a commit from before those existed fails the
gate: tag a newer commit on `main`.

### How a release is gated (R8)

`release.yml` runs only when dispatched (`workflow_dispatch`, input `tag`) and
is meant to run on `main`. Its stages each need the one before: `on-main`
(fails unless `$GITHUB_REF` is `refs/heads/main`, the tag name matches
the Tag name check below, and the tag's commit is an ancestor of `origin/main`;
then it resolves `refs/tags/<tag>^{commit}` once, outputs it as `sha` and fails unless it is 40 hex digits),
`quality` (`main`'s `ci.yml`, called with `ref: ${{ needs.on-main.outputs.sha }}`,
so the gate that runs is main's and what it tests is the tagged commit; each checkout in `ci.yml` is followed by a step that fails unless `HEAD` is that `ref`),
`build-release` (checks out that sha and fails unless `HEAD` is that sha; one archive per platform, with its sha256 and an attestation of its
build provenance for exactly that archive), `verify-artifacts` (on each
platform: re-check the sha256, run `gh attestation verify` requiring this
workflow and `refs/heads/main`, unpack, run `--version`, run
`scripts/check-binary-clean.sh`), `publish-release` (re-check the sha256 and the
attestation of what was downloaded, re-fetch the tags and fail unless the tag
still names the sha, then publish the tag). The sha256 file
travels in the same artifact as the archive, so re-checking it shows only that
the two agree; the attestation is what ties the archive to this workflow run.

Why the sha and not the tag name: the gate tests `refs/tags/<tag>^{commit}`, but
`actions/checkout` given the bare name `v1.2.3` prefers a branch of that name
over the tag. A writer could push a branch `v1.2.3` with other code beside the
tag, dispatch from `main`, and the gate would pass for the tag while quality
and the build used the branch. So the tag is resolved once, in `on-main`, and
every later use is that full commit sha (a job that reads `needs.on-main.outputs.sha` must list `on-main` in its own `needs`, or it gets an empty string, and the release step's `target_commitish` is the sha too). The approval wait can be long; the
tag is checked against the sha again right before the release step, so a tag
moved or deleted meanwhile stops the publish instead of publishing something
else (or having the release step create the tag at `main`'s head).

What the attestation proves: the archive was built by `release.yml` run on
`main`. Since the build checks out the sha, it also binds the commit: the
archive is of the commit that `on-main` resolved from the tag and the gate
tested (it does not prove the code is good, only what was built and by what).
Only `publish-release` can write to the repository, it runs in the `release`
environment, and a tag with a `-` in it (such as `v1.0.0-rc1`) publishes as a
prerelease. `id-token: write` and `attestations: write` are on `build-release`
only.

Why not a tag-push workflow: a workflow started by a tag push is read from the
tagged commit, and so are the `ci.yml` it calls and the checker it runs. Anyone
with write access could tag a commit whose `release.yml` drops the gate, and
it would publish. Here nothing a push starts can publish (the checker fails a
workflow that has a push, tag or pull request trigger and a publishing job).

Each `on-main` step, and each `cargo fmt`, `clippy` and `test` step in
`ci.yml`, is a gate step: its `run` is exactly one command on one line (a
leading `set -euo pipefail` line is allowed), nothing else. The checker refuses
any other shape, because a script that mixes commands can hide a failure (a
here-doc, `false && cmd`, `exit 0`, `cmd; true`) in ways a reader of shell
cannot reliably see. Keep them that way when you edit them.

The checker also refuses, in both workflow files: any `env` but `GH_TOKEN` (as
`${{ github.token }}`) and, at the top of `release.yml`, `TAG` (as
`${{ inputs.tag }}`); any run script that mentions `GITHUB_ENV` or
`GITHUB_PATH`; a job with `container:` or `services:`, a runner that is not
GitHub-hosted (`ubuntu-*`, `macos-*`, `windows-*`) or a `timeout-minutes` that
is not a positive number; `continue-on-error` on any job unless it is the
literal `false`; a `release-graph` job that runs anything but exactly
`python3 scripts/check-release-graph.py .` and `python3 -m unittest
scripts/test_check_release_graph.py`; and a `ci.yml` without its
`pull_request` trigger.

When you change a workflow:

- **Add an action** pinned to a full commit, never a tag: look the commit up
  with `git ls-remote https://github.com/<owner>/<repo> refs/tags/<tag>` (for
  an annotated tag, use the `^{}` line), and write the tag after it as a
  comment, `uses: owner/repo@<40 hex> # v1.2.3`. Moving a pin is its own
  change, with the new tag in the commit message.
- **Move the Rust toolchain** by changing `channel` in `rust-toolchain.toml`
  and every `toolchain:` line in `.github/workflows/` together. It is an exact
  version (now 1.98.1, what the Hetzner server and the Raspberry Pi run); the
  checker fails if any of them says `stable` or disagrees.
- **Add a CI job** and it is part of the release gate automatically, since
  `release.yml` calls the whole of `ci.yml`; give its checkout
  `ref: ${{ inputs.ref }}`.
- **Change the tag form** in `release.yml`'s `on-main` step and on the "Tag
  name check" line below together (and widen or narrow the tag ruleset's own
  pattern if needed); the checker fails if the first two differ, and if the
  workflow's check is not the regex below.
- Run the two commands above. They are a local, structural check; they run
  no workflow and look up no commit, so a mistyped commit is caught only by
  the first real run.

### Repository settings the checker cannot see

The checker (`scripts/check-release-graph.py`) reads only the workflow files,
and says so each time it runs. These settings are made on GitHub by Taylor,
in the repository's Settings tab, using the clicks written out below (GitHub's
interface as of 1 Nov 2026; if a label has moved, GitHub's own documentation
for rulesets, environments and immutable releases is the reference).

What the checker can and can't do, plainly: it catches mistakes and visible
weakening of main's own workflows in review (a change that drops a gate, loosens
a step, adds an env override, a container or a self-hosted runner makes it fail,
and the diff shows what changed). It runs nothing. A writer who can change main
can always defeat a structural check, by editing the checker, its tests or the
workflow that runs them; branch protection with review is what holds that line.

What these settings can and can't do, plainly (an independent check, 1 Nov 2026):
anyone with write access to the repository can publish a release, either
directly or through any workflow they push that asks for `contents: write`,
and nothing in these files or in GitHub's settings can stop that. A weakened
copy of `release.yml` can simply leave the `release` environment out. So the
real barriers against a dishonest writer are:

- **who has write access**: write access stays with Taylor and the agents'
  GitHub account, which pushes for the agents. Nobody else is added, and
  Taylor looks at Settings > Collaborators and teams whenever anything about
  access changes;
- **the tag ruleset** below: a rogue release can't take or move a `v*.*.*`
  version tag;
- **branch protection on `main`**: the gate that runs can't be weakened
  without review. Branch protection on main and the tag ruleset are what the
  release relies on;
- **provenance anyone can check**: every archive this workflow publishes has
  a signed build attestation from `release.yml` run on `main`; a release
  built any other way has none, and the check under
  [Checking a download](#checking-a-download) fails for it.

The files' own checks make the honest path safe and auditable; these
settings and that check are what expose the dishonest one.

- [ ] **Immutable releases.** Turn on immutable releases, if GitHub offers it
  for this repository: Settings, scroll to Releases, select Enable release immutability. Once a release is published, its tag and its
  files can no longer be changed or deleted. If the option is not there, skip
  this step and say so when ticking off the list.
- [ ] **Who has write access** (load-bearing): Settings > Collaborators and
  teams. Check the list: Taylor and the agents' GitHub account, and nobody
  else with Write, Maintain or Admin. Write access stays with Taylor and the
  agents' GitHub account, which pushes for the agents.
- [ ] **Branch protection on `main`**, load-bearing. Either place works:
  Settings > Rules > Rulesets > New ruleset > New branch ruleset (name it, set
  Enforcement status to Active, add the target branch `main` under Target
  branches, tick Restrict deletions, Require a pull request before merging,
  Require status checks to pass before merging, and Block force pushes), or Settings >
  Branches > Add (classic) branch protection rule (branch name pattern `main`,
  tick Require a pull request before merging, Require status checks to pass
  before merging, and Do not allow bypassing the above settings). `main` holds
  the `release.yml` and `ci.yml` that run, and a tag's commit must be on it,
  so whoever can push to it without review can rewrite the gate.
- [ ] **Required approvals and code owners on `main`**, load-bearing, in the
  same ruleset or rule: set `Required approvals: 1` and tick Require review
  from Code Owners (classic rule: Require approvals, with Required number of
  approvals before merging set to 1, and Require review from Code Owners).
  Why: a ruleset's required approvals defaults to 0, so "Require a pull request
  before merging" alone lets a writer merge their own change to `release.yml`,
  the checker or its tests without anyone else looking, which is the one
  change the other settings assume somebody reviews. `.github/CODEOWNERS`
  names an owner for `.github/` and `scripts/`; it is a placeholder
  (`@taylor-made-labs`, assumed from the repository's address): Taylor, confirm
  the owner is the right GitHub account with write access. GitHub does not let
  an author approve their own pull request, so the owner must not be the
  account that opens the agents' pull requests.
- [ ] **Tag ruleset**, load-bearing for what is released: Settings > Rules >
  Rulesets > New ruleset > New tag ruleset. Name it, set Enforcement status to
  Active, add a target under Target tags with the pattern below, and tick
  Restrict creations, Restrict updates and Restrict deletions. Under Bypass
  list, add the Repository admin role (a ruleset's bypass list takes roles,
  teams or apps, not individual users, so "only Taylor" cannot be written:
  keep the admin role to Taylor). Without that bypass nobody could create a
  release tag, and step 2 of "Cutting a release" needs one. Then
  save. A tag that could be moved after the `on-main` check could point the
  build at a different commit.
  - Tag ruleset pattern: `v*.*.*` (a glob, so broader than the check below)
  - Tag name check: `^v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?$` (what `on-main` enforces; the checker compares it with the workflow)
- [ ] **Environment `release`**: Settings > Environments > New environment,
  name it `release`, then Configure environment. Tick Required reviewers and
  add Taylor (tick Prevent self-review if anyone else has write access). Under
  Deployment branches, choose Selected branches and tags, add the branch
  `main`, and deselect Allow administrators to bypass configured protection
  rules.
  `publish-release` runs in this environment, so every honest publish waits for
  Taylor's approval. It does not stop a weakened copy, which can leave the
  environment out (above).
- [ ] **Make the repository public before the first release** (publishing it
  is Taylor's call, and stays so). Build attestations on a private repository
  need GitHub Enterprise Cloud; on a free plan the attestation step fails, so
  the repository has to be public first, and the history scan (R1) has to have
  passed before that. If the repository ends up in an organization, gitleaks
  may ask for a licence: set a `GITLEAKS_LICENSE` secret; `ci.yml` accepts it
  as an optional secret of `workflow_call` and `release.yml` passes it on.
  Whether the attestation steps need `attestations: read` on the verifying
  jobs is settled by the first real run (the permission is not added before a
  run shows it is needed).
- [ ] Tick these off here with the date once set. A real dispatched release is
  the end-to-end test that they work: the run should stop at the first job when
  dispatched from another branch, and the publish should pause for approval.

## Checking a download

Anyone can check that an archive was built by this repository's
`release.yml`, run on `main`, from the GitHub CLI:

```sh
gh attestation verify agent-sign-<target>.tar.gz --repo taylor-made-labs/agent-sign \
  --signer-workflow taylor-made-labs/agent-sign/.github/workflows/release.yml \
  --source-ref refs/heads/main
```

A release made any other way (by hand, or by another workflow) has no such
attestation, and the check fails for it. The attestation proves the archive was
built by `release.yml` run on `main`, and it names the commit that run checked
out (the tag's commit, resolved once); it does not prove the code is free of bugs.

## Publishing from the private hub

The hub (the maintainer's own copy of the repository) keeps its private history under `refs/private/*`
(`refs/private/pre-public-2026-11-02` holds the history before the public copy was squashed, because it held
private deployment records) and never pushes those refs. The public `main` on GitHub is only ever advanced by a
fast-forward from the hub's `main`. `scripts/release/scan-private-details.py`, run by
`tests/test_no_private_details.rs` in every test run, fails when the tree holds a real tailnet name, a tailnet
address beyond the documentation examples, a real home folder, or a file under `docs/signing-step0/` or a
machine settings file other than `machine-example.env`; run it on a commit before pushing it.
