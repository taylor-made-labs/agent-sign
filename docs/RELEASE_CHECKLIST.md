# Release checklist

agent-sign 0.1.0 is ready for users when every check below passes. It
covers both halves of "ready": the tool works (F), and someone who finds it
can install it and trust what it says (R). Each check says how it's run, so
anyone can rerun it; the status column records the latest run.

Status: **Pass**, **Fail**, **Open** (not run yet), **Limit** (it doesn't
hold, and the README says so), or **Person** (only the maintainer can do it).

## F: the tool works

| # | Check | How it's run | Status |
|---|---|---|---|
| F1 | Agent commits are signed and verify | Automated: `tests/test_e2e_git_commit.rs` and `tests/test_signature_equivalence.rs` check `git log --show-signature` and `ssh-keygen -Y verify`. Manual, once: an agent commit pushed to GitHub shows **Verified**. | **Pass** (automated, 7 Oct 2026); GitHub **Open** |
| F2 | One approval, then no more asking | Automated: one approval, then 20 agent commits in the same scope, counting approval requests (must be exactly 1). `tests/test_approval_scope.rs`. | **Pass** (7 Oct 2026) |
| F3 | Your own commits never use the agent key | Automated: a commit from a terminal goes to your normal git and signing (`tests/test_human_isolation.rs`). Manual: an editor's commit button and GitHub Desktop. | Terminal **Pass**; editor buttons **Limit** (if the editor's git is the wrapper, it looks like an agent) |
| F4 | Fails closed | Automated: with no lease, a revoked lease, an expired lease, a forged or replayed token, or the service stopped, an agent commit is refused with a message saying why, and is never signed with another key. | **Pass** (7 Oct 2026): `tests/test_edge_cases.rs` (denied, revoked, ended, forged and reused tokens, service stopped: each refused, and no commit exists afterwards) |
| F5 | The rules refuse with a reason | Automated: commits on `main`/`master`, touching CI workflows or key files, over a diff-size limit the person set, or over the rate limit are refused, each with its own message. | **Pass** (7 Oct 2026): `tests/test_edge_cases.rs` (protected branch without asking, CI workflow and key files, diff size, rate limit) |
| F10 | Commits name the agent | Automated: with each known agent mark, or `AGENT_SIGN_AGENT_NAME`, the commit's author is that agent; a configured name is kept (`tests/test_agent_name.rs`). | **Pass** (7 Oct 2026) |
| F6 | Terms never grow after approval | Automated: `tests/test_lease_terms.rs` (config can only narrow; an unreadable ceiling stops the service). | **Pass** (7 Oct 2026) |
| F7 | Real agents actually go through it | Manual, recorded: Claude Code, Codex and Cursor, each started the normal way, on macOS and on Linux, make a commit; the commit is signed with the agent key, or `agent-sign doctor` says plainly that this agent bypasses the wrapper. | Claude Code (desktop app) on macOS **Pass**: every commit of this release went through the wrapper and verifies (`%G?` = `G`), 7 Oct 2026. Codex **Open** (its account here is at its usage limit until 21 Oct). Cursor, and Linux, **Open**. |
| F8 | Edge cases, repeated | Automated: two agents committing at once (same repository and different ones), the service restarted mid-work, hundreds of commits in a row, repository paths with spaces and non-ASCII characters, symlinked repositories, worktrees, detached HEAD, `--amend`, and each approval scope's boundaries (a folder doesn't cover a sibling whose name starts the same). Each case runs enough times to rule out flakes. | Mostly **Pass** (7 Oct 2026): `tests/test_edge_cases.rs` covers paths with spaces and accents, a symlinked repository (one lease), a worktree, detached HEAD, `--amend`, 200 commits in a row, two agents committing at once in two repositories, and a restart between commits; `tests/test_service_restart.rs` covers a commit during a restart; the full suite (117 tests) passed 2 runs in 2. **Limit**: a home folder long enough to push the socket path past 104 bytes (macOS) stops the service. Not yet: two agents committing in the same repository at once (git itself locks the index). |
| F9 | The approval scope is the person's choice | Automated: the dialog offers this repository, this folder and everything under it, or everywhere, and the lease covers exactly the scope chosen (`tests/test_approval_scope.rs`, with stand-in dialogs). Manual, once each: the real macOS and Linux dialogs show the three choices and return the one picked. | Automated **Pass** (7 Oct 2026); real dialogs **Person** (one click on the Mac) |

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

## Only the maintainer

| # | What | Why only them |
|---|---|---|
| P1 | ~~Apply `docs/release/ci-workflows.patch` and push.~~ Done 8 Oct. | Agents can't change `.github/workflows/`. |
| P2 | Turn on private vulnerability reporting (Settings, Code security), which `SECURITY.md` points to. | A repository setting. |
| P3 | Click the real approval dialog once on macOS (F9), and run the installer on the Mac (R5). | It replaces the live service on the maintainer's machine. |
| P4 | Merge `release/v0.1` into `main`, and tag `v0.1.0`. | Agents don't commit to `main`. |

## Last: onboarding and polish

Not needed for 0.1.0, but on the roadmap: `agent-sign upgrade` with
automatic rollback, an install with no terminal steps, and a first-run page.

## Rerunning the checks

```sh
cargo fmt --check && cargo clippy --all-targets --locked -- -D warnings && cargo test --locked
python3 scripts/release/scan-history-secrets.py . --all
git apply --check docs/release/ci-workflows.patch
```
