# Release checklist

agent-commits 0.1.0 is ready for users when every check below passes. It
covers both halves of "ready": the tool works (F), and someone who finds it
can install it and trust what it says (R). Each check says how it's run, so
anyone can rerun it; the status column records the latest run.

Status: **Pass**, **Fail**, **Open** (not run yet), **Limit** (it doesn't
hold, and the README says so), or **Person** (only the maintainer can do it).

## F: the tool works

| # | Check | How it's run | Status |
|---|---|---|---|
| F1 | Agent commits are signed and verify | Automated: `tests/test_e2e_git_commit.rs` and `tests/test_signature_equivalence.rs` check `git log --show-signature` and `ssh-keygen -Y verify`. Manual, once: an agent commit pushed to GitHub shows **Verified**. | **Pass** (automated, 7 Oct 2026); GitHub **Open** |
| F2 | One approval, then no more asking | Automated: one approval, then 20 agent commits in the same scope, counting approval requests (must be exactly 1). | **Open** |
| F3 | Your own commits never use the agent key | Automated: a commit from a terminal goes to your normal git and signing (`tests/test_human_isolation.rs`). Manual: an editor's commit button and GitHub Desktop. | Terminal **Pass**; editor buttons **Limit** (if the editor's git is the wrapper, it looks like an agent) |
| F4 | Fails closed | Automated: with no lease, a revoked lease, an expired lease, a forged or replayed token, or the service stopped, an agent commit is refused with a message saying why, and is never signed with another key. | **Open** (partly covered by `tests/test_refusals_and_revoke.rs` and `tests/test_lease_engine.rs`) |
| F5 | The rules refuse with a reason | Automated: commits on `main`/`master`, touching CI workflows or key files, over the diff-size limit, or over the rate limit are refused, each with its own message. | **Open** (partly covered by `tests/test_interceptor.rs`) |
| F6 | Terms never grow after approval | Automated: `tests/test_lease_terms.rs` (config can only narrow; an unreadable ceiling stops the service). | **Pass** (7 Oct 2026) |
| F7 | Real agents actually go through it | Manual, recorded: Claude Code, Codex and Cursor, each started the normal way, on macOS and on Linux, make a commit; the commit is signed with the agent key, or `agent-commits doctor` says plainly that this agent bypasses the wrapper. | **Open** |
| F8 | Edge cases, repeated | Automated: two agents committing at once (same repository and different ones), the service restarted mid-work, hundreds of commits in a row, repository paths with spaces and non-ASCII characters, symlinked repositories, worktrees, detached HEAD, `--amend`, and each approval scope's boundaries (a folder doesn't cover a sibling whose name starts the same). Each case runs enough times to rule out flakes. | **Open** |
| F9 | The approval scope is the person's choice | Automated: the dialog offers this repository, this folder and everything under it, or everywhere, and the lease covers exactly the scope chosen. | **Open** |

## R: the release is usable

| # | Check | How it's run | Status |
|---|---|---|---|
| R1 | No secrets in the history | `python3 scripts/release/scan-history-secrets.py . --all`, and gitleaks in CI once the CI patch is applied. | **Pass** locally (0 findings, 7 Oct 2026) |
| R2 | License: MIT OR Apache-2.0 | `LICENSE-MIT`, `LICENSE-APACHE`, and `license = "MIT OR Apache-2.0"` in `Cargo.toml`. A dependency license check (`cargo deny`) in CI. | Files **Pass**; `cargo deny` **Open** |
| R3 | Fresh readers trust it | Two new readers given only `README.md` and `docs/INSTALL.md` say what it does, what it doesn't protect against, and every reason they'd hesitate to use it. Each reason gets fixed or is a stated limit. A held-out reader checks only at the end. | **Open** |
| R4 | Every claim is backed | Each claim in the README points to an F check that passes, or is stated as a limit. | **Open** |
| R5 | Clean install from a release | On a clean Mac and a clean Linux machine, following only the README with a downloaded release (no Rust), the install ends in a verified agent commit. | **Open** |
| R6 | CI on every push | macOS, Linux x86_64 and Linux ARM64: fmt, clippy, tests, secret scan. | **Person**: apply `docs/release/ci-workflows.patch` (agents can't change `.github/workflows/`) |
| R7 | Release downloads and Homebrew | A tag builds archives for macOS arm64 and x86_64 and Linux x86_64 and ARM64, with `SHA256SUMS.txt`; the formula installs from them. The formula's setup step (`install.sh --from-homebrew`) still has to be written. | **Open** |

## Last: onboarding and polish

Not needed for 0.1.0, but on the roadmap: `agent-commits upgrade` with
automatic rollback, an install with no terminal steps, and a first-run page.

## Rerunning the checks

```sh
cargo fmt --check && cargo clippy --all-targets --locked -- -D warnings && cargo test --locked
python3 scripts/release/scan-history-secrets.py . --all
git apply --check docs/release/ci-workflows.patch
```
