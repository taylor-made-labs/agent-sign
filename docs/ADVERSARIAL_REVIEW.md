# Adversarial & Critical Codebase Review: Agent-Sign

- **Review Date**: 2026-09-25
- **Reviewer**: Autonomous Systems & Security Reviewer
- **Target Repository**: `agent-sign` (`v0.1.0`)
- **Review Scope**: Cryptographic soundness, runtime architecture, security invariants, usability, setup experience, and alignment between documentation/specifications and real implementation.

> **A historical record.** This review is of agent-sign as it was on
> 25 Sept 2026, before it became agent-sign; the file names and quotes are
> agent-sign's. It's kept because it explains many of the changes since.
> Where each finding stands in agent-sign (checked 30 Sept 2026):
>
> | Finding | Now |
> |---|---|
> | 1. Branch-switching deadlock | Fixed: leases can cover every unprotected branch, and revocation works. |
> | 2. "Touch ID" is an AppleScript dialog | The docs no longer claim Touch ID. Fixed on macOS on 19 Oct 2026: the dialog only picks the coverage (nothing preselected, Continue or Deny), and the lease is granted only after Touch ID or the login password through LocalAuthentication. No Approve default remains. Linux has no dialog and no authenticator (release checklist F10). |
> | 3. `trailers` mode never applied | Fixed for messages given with `-m` or `--message`; `-F` and editor messages are left as they are. |
> | 4. Repository config never loaded | Fixed for the wrapper's rules, merged over the person's config. Since the identity review (28 Oct 2026, below) a repository's file can only tighten them, and can't change attribution. The service deliberately reads only the person's own config. |
> | 5. Service blocks during dialogs | Fixed: a thread per connection, and the lock isn't held during a dialog. |
> | 6. Repositories keyed by folder name | Fixed: keyed by canonical path. |
> | 7. Hard-coded `/usr/bin/git` and `ssh-keygen` | Fixed: git is found on `PATH`; `fallback_program` is used. |
> | 8. Tokens never expire; revocation a no-op | Fixed: tokens expire after 60 seconds; `agent-sign revoke` works (and since 30 Sept, reports when nothing matched). |
> | Usability 1. Terminal commits treated as the agent's | Fixed: commits with a terminal on standard input and output are the person's. An editor's commit button is still treated as an agent's. |
> | Usability 2. No service management | Fixed: launchd and systemd user services. |
> | Usability 3. `status` says little | Fixed: it lists leases. |
> | Usability 4. Merge, rebase, cherry-pick not intercepted | Fixed 26 Oct 2026: an agent's merges, rebases, cherry-picks, reverts, pulls and aliases make unsigned commits, never signed with the person's key. Signing them with the agent key waits for per-agent identities. |
> | Usability 5. `alias` mode shows Unverified | Still true with the default `.internal` email; documented in SPEC.md. |
>
> The review's praise of a "zero blast radius" key needs a correction: the key
> can't log in or push, but it's unencrypted and readable by the person's user,
> and commits signed with it show as Verified for the person.


## Identity review, 28 Oct 2026

Two independent reviewers read the per-agent identity change (every agent
signing as itself, under certificates from an agents' authority) before it
merged, and confirmed these findings with isolated reproductions. The fixes
were decided before any code was written; each finding (1 to 9) got a
regression test in `tests/test_identity_review_fixes.rs` first, run against
the code before the fix, where it **failed**, then passed after it. The run
before the fixes: 23 of 25 failed for the reason under test; the other two
(`f2_a_fixture_with_its_own_user_keeps_its_names`,
`f4_a_config_any_installer_wrote_still_starts_the_service`) are guards that
must hold before and after.

| # | Finding | Regression test (failed before the fix) | Fix |
|---|---|---|---|
| 1 | HIGH. A repository's `.agent-sign.toml` overlaid every table, so a cloned repository could set `[attribution]`, `[human]` and `[agent]` and put anyone's name on commits with a Good agent signature, or replace `forbidden_paths`. | `f1_a_repository_file_cant_put_another_name_on_agent_commits`, `f1_every_attribution_mode_commits_as_the_agent`, `f1_a_repository_file_adds_forbidden_paths_but_cant_remove_them`, `f1_a_repository_file_cant_raise_max_diff_lines`, `f1_a_repository_file_can_block_more_branches` | A repository's file can only add `forbidden_paths` and `block_branches` and lower `max_commits_per_minute` and `max_diff_lines`; everything else is ignored with one warning line (`config::tighten_with_repo_file`). An identified agent's signed commit is authored (new commits) and committed by its identity in every mode (`AttributionEngine::compute_env_vars`). The wrapper refuses branches the repository's file adds. |
| 2 | HIGH. An identified agent's commit that declined signing carried the person's global name and email. | `f2_an_identified_agents_unsigned_commit_is_attributed_to_it` | On that path the wrapper sets author and committer to the identity when `user.email` comes only from global or system config (a fixture's own user, and variables already set, are kept). Unsigned commits on `main` stay allowed, and are documented: protection covers agent-signed commits, and a signed-merge rule guards `main`. |
| 3 | MEDIUM. Run tokens were checked against the starting branch but signed anything for 10 minutes: `git rebase feature main` and `rebase --exec 'cd /other && git commit'` made agent-signed commits on `main` and in other repositories. | `f3_rebasing_main_from_another_branch_makes_no_agent_commit_on_main`, `f3_a_run_token_signs_nothing_in_another_repository`, `f3_a_commit_token_signs_only_for_its_repository_and_branch` | The signing program sends the canonical repository top and the branch being written (`git_place::repo_and_branch`: `branch --show-current`, or the rebase's `head-name`, or `HEAD`); the service refuses a signature unless both are the token's and the branch isn't protected. The wrapper uses the same rule. Commit tokens too. |
| 4 | MEDIUM, fail open. A `config.toml` that existed but couldn't be read became the defaults (now `approval = "none"`), and a misspelt or misplaced key was ignored. | `f4_an_unreadable_config_stops_the_service`, `f4_a_config_that_is_a_directory_or_a_dangling_link_stops_the_service`, `f4_an_unknown_or_misplaced_key_stops_the_service`, `f4_the_service_logs_its_approval_mode_at_start` (guard: `f4_a_config_any_installer_wrote_still_starts_the_service`, every key from `git log -p -- scripts/install.sh`) | Only "not found" means no config; any other read error, unknown table or key stops the service naming file and key (`Config::check_file`). `auto_revoke_on_branch_delete`, written by installers before 30 Sept, is accepted and ignored. The service logs its approval mode at start. |
| 5 | MEDIUM. Commits with no terminal and no agent mark (the person's editor, or an unmarked agent) were signed as "Agent <agent.unidentified@agents.local>", attributing the person's commits to an agent. | `f5_an_unmarked_commit_needs_no_service_and_is_gits_own`, and the four tests of `test_per_agent_identity.rs` rewritten to the new behaviour (a deliberate eval change, listed in the change's report) | Such commits go to git unsigned (`commit.gpgsign=false`, every signing program failing), under git's own names, with nothing asked and no service needed. The old `IssueToken` request is refused. |
| 6 | LOW. The authority signed any principal `check()` let through, such as `codex.admin@agents.local` or `---.a@agents.local`. | `f6_check_refuses_principals_that_dont_look_like_sessions`, `f6_an_explicit_name_gets_a_slug_check_accepts` | The session part must be 8 lowercase hex digits or `nosession`, the slug must match `^[a-z0-9]+(-[a-z0-9]+)*$`; `slug_of` joins words with single `-` so every name passes. |
| 7 | LOW. Run tokens skipped `max_commits_per_minute`; session keys were never evicted; a repository named by a link had its own lease and rate window. | `f7_a_run_tokens_signatures_count_against_the_rate_limit`, `f7_session_keys_are_capped_least_recently_used_first`, `f7_a_repository_named_by_a_link_shares_its_lease_and_rate_window` (unit: `an_idle_session_key_is_evicted_after_twelve_hours`, `at_most_max_signers_are_kept`, which use the new time-injected API and so could not run before) | Every run-token signature counts against the repository's window (`LeaseEngine::record_signature`); signers idle 12 hours are evicted and at most 1024 kept, least recently used first; the service canonicalizes repository paths for leases, tokens, the limiter, status and revocation. |
| 8 | LOW. A leaked `AGENT_EVENT_TOKEN` made the person's terminal commit sign as the agent. | `f8_a_leaked_token_doesnt_sign_the_persons_terminal_commit`, `f8_the_signing_program_ignores_a_token_without_the_wrappers_mark` | The person's git runs without `AGENT_EVENT_TOKEN`; the signing program ignores a token unless the wrapper's `AGENT_SIGN_AGENT_RUN` is set. |
| 9 | LOW, older than the change. On a case-insensitive disk a branch named `MAIN` slipped past main protection. | `f9_protected_branches_are_compared_without_case`, `f9_an_agent_commit_on_upper_case_main_is_refused` | `block_branches` are compared without ASCII case everywhere (`lease::branch_matches_blocked`). |
| 10 | LOW. After an upgrade the old shared key stayed live, and its `allowed_signers` line still trusted it under the person's email. | Checked by hand: the installer's retirement step run alone in a throwaway folder. | The installer moves `keys/agent_ed25519` to `keys/retired/agent_ed25519.<date>` (0600, folder 0700), keeps the `.pub`, and prints the exact commands to remove its `allowed_signers` line and GitHub signing key; it runs neither. |

Left open, and stated in the README: an agent that names another author on
purpose (`--author`, or `--amend` of someone else's commit). (A repository's
lower `max_commits_per_minute`, accepted but not enforced after this round,
is ignored since the follow-up round below.)

### Follow-up round (28 Oct 2026)

Two new requirements of Taylor's (A: the certificate authority key is never
stored unprotected, "never create keys unprotected, they must be protected
from the start"; B: the installer routes the user's own signing through
agent-sign) and five findings of the independent check after the fix round
(C to G). Each test in `tests/test_identity_followup.rs` was written first
and run against the code before its change: **all 14 failed**, each for the
reason under test (the assertion that fails is named below), and all 14
pass after.

| Item | Test (failed before) | How it failed before | Change |
|---|---|---|---|
| A | `a_no_file_under_the_state_dir_holds_private_key_material_after_start` | `keys/agents_ca_ed25519` is a raw 32-byte seed | The authority is made in memory at each start (`AgentsCa::generate`) behind the `CertificateIssuer` port; nothing private is written. |
| A | `a_a_commit_certified_before_a_restart_still_verifies_after_it` | The same authority after a restart (it was loaded from the file). The verification half held before too, since the key was reused. | Each start appends its public key, dated, to `keys/agents_cas.pub`; `trust-line` prints one line per authority; both commits verify under its output. |
| A | `a_the_service_rewrites_only_the_managed_trust_block` | The block still held the stale line | The service rewrites only the lines between the markers (`update_allowed_signers`), byte for byte outside them; a file without markers is untouched. |
| A | `a_a_ca_private_key_left_by_an_earlier_build_stops_the_service` | The service started with it | `refuse_unprotected_key` stops the service, naming the file. |
| A | `a_the_installer_deletes_the_authority_key_and_writes_the_managed_block` | The key file was still there after install | The installer deletes it after its question, moves a bare trust line into the block, and the service fills the block at start. |
| B | `b_the_installer_routes_the_users_signing_and_uninstall_restores_it`, `b_with_no_program_set_uninstall_leaves_it_unset_again` | `gpg.ssh.program` unchanged by the installer | The installer sets it to `agent-ssh-sign`, keeping the old value (or `ssh-keygen`) as `fallback_program`; `uninstall.sh` puts it back (unset for `ssh-keygen`). |
| B | `b_doctor_reports_when_the_users_signing_isnt_routed` | `doctor` didn't mention it | `doctor` reports whether the routing is in place. |
| B, G | `b_g_the_summary_names_the_routing_and_the_deletion_before_asking` | The summary didn't mention `gpg.ssh.program` | The summary lists the routing (with the current signer) and each private key it will delete; answering no changes nothing. |
| C | `c_an_unmarked_commit_that_asks_to_sign_is_made_unsigned` | `commit -S` exited 128 (git called the failing signing program) | `exec_unmarked_commit` strips `-S`/`--gpg-sign[=key]` (before `--`) and `-c commit.gpgsign=...`, adds `--no-gpg-sign`, and prints one line. |
| D | `d_a_repository_file_cant_lower_max_commits_per_minute` | The repository's 1 replaced the 10 | The key is ignored, with the usual warning, whose text no longer promises it. |
| E | `e_the_config_template_and_spec_say_every_mode_commits_as_the_agent` | The template said "Committer: you" | The template and SPEC say every mode commits as the agent. |
| F | `f_the_github_notice_is_printed_only_while_the_old_key_is_trusted` | The notice was printed with the old key's line already gone | The notice is inside the "still trusted" branch. |
| G | `g_the_installer_deletes_the_old_keys_private_half_and_keeps_its_public_half` | The private half was moved to `keys/retired/` | Deleted (with copies an earlier build moved aside), `.pub` kept. |

The installer tests run the real `scripts/install.sh` and `uninstall.sh`
(non-interactive: `--yes` with no terminal, the installer's existing mode;
the summary test answers "n" in a pseudo-terminal) from a copy of
`scripts/` whose programs are the test builds, in a throwaway home with a
throwaway global git config, and with stand-ins first on `PATH` for
`launchctl`, `systemctl`, `loginctl`, `codesign`, `pkill`, `pgrep`, `curl`
and `cargo`, so no real service, process or network is touched. The copy's
`check-binary-clean.sh` passes, since test builds carry the test
authenticator it rightly refuses.

Existing assertions changed by design: none in the integration tests. The
unit test `the_authority_is_created_private_once_and_reused`
(`src/agents_ca.rs`) asserted the behaviour item A removes (a 0600 key file
reused across starts); it is replaced by
`each_generated_authority_is_new_and_nothing_is_written` and
`the_history_is_appended_and_an_earlier_authority_carried_over`.
`scripts/release/install-test.sh` (Linux CI) checked "same agents'
authority" across a reinstall and a key file in a moved state folder; it now
checks that the earlier authority is still recorded and that a commit from
before the reinstall still verifies.

---

## 1. Executive Summary & Verdict

`agent-sign` sets out to solve one of the most frustrating friction points in modern agentic engineering: **biometric Touch ID interrupts and master credential exposure caused by autonomous AI coding agents committing to Git**. The proposed vision—pairing an ephemeral, scoped Ed25519 signing sub-key with a local session lease daemon and a transparent Git multiplexer—is conceptually brilliant and addresses an urgent developer need.

However, an adversarial audit of the codebase reveals a sharp dichotomy between the **clean cryptographic core** and the **underdeveloped runtime integration layer**. Several major features promised in `README.md`, `SPEC.md`, and `VALUE_PROP.md` are either **stubs, dead code, architectural illusions, or harboring critical deadlock bugs**.

### Scorecard

| Dimension | Rating | Summary |
| :--- | :---: | :--- |
| **Core Cryptography** | **A** | Pure-Rust OpenSSH SSHSIG generator is clean, robust, and correctly validated by `ssh-keygen -Y verify`. |
| **Threat Model & Security Design** | **B+** | Sound concept (sub-key restricted strictly to signing Git buffers, zero push/auth blast radius), but keys sit unencrypted on disk. |
| **System Invariant Adherence** | **D** | [INV-1] leaks under recommended Cursor PATH setup; [INV-4] uses fake AppleScript instead of Touch ID; [INV-5] trailers mode is completely unimplemented in execution. |
| **Runtime Architecture & Reliability** | **D+** | Single-threaded daemon blocks listener while holding mutex for UI dialogs; switching branches causes permanent 2-hour signing deadlocks. |
| **User Experience & Setup** | **C** | Manual background process management required; zero `launchd`/`systemd` automation; hardcoded macOS `/usr/bin` paths break Linux and Homebrew setups. |

---

## 2. What's Good: Architectural & Technical Strengths

1. **Native OpenSSH SSHSIG Generation in Pure Rust**:
   Instead of clumsily spawning `/usr/bin/ssh-keygen` to sign buffers, `src/crypto.rs` implements RFC 4251 SSH wire encoding, SHA-512 pre-image hashing, Ed25519 signing via `ed25519-dalek`, and armored PEM serialization (`-----BEGIN SSH SIGNATURE-----`). This avoids external process spawning for agent signatures and achieves sub-millisecond execution. It passes system `ssh-keygen -Y verify` in automated E2E tests.

2. **Zero Blast-Radius Key Scoping**:
   Generating a dedicated Ed25519 sub-key that is uploaded to GitHub strictly as a **Signing Key** (not an Authentication Key) is fundamentally sound. Even if an adversarial prompt injection exfiltrates `agent_ed25519`, the key cannot be used to clone private repos, push commits, or authenticate via SSH to remote servers.

3. **High-Speed IPC with Minimal Dependencies**:
   The protocol layer (`src/protocol.rs`) uses lightweight newline-delimited JSON over local Unix Domain Sockets (`AF_UNIX`). This satisfies the sub-millisecond latency budget without pulling in bloated dependencies like HTTP/gRPC or asynchronous runtime frameworks.

4. **Genuine End-to-End Testing**:
   The test suite in `tests/test_e2e_git_commit.rs` does not rely on mocks. It spawns the real compiled binaries, initializes ephemeral Git repositories, generates commits, and executes `git log -1 --show-signature` to verify that Git itself reports `Good "git" signature`.

5. **Thoughtful Product Framing & Documentation**:
   The repository features clear documentation: `SPEC.md` outlines formal invariants, `VALUE_PROP.md` articulates clear developer personas (1Password, YubiKey, Enterprise, Containers), and `BEST_PRACTICES.md` establishes architectural guidelines.

---

## 3. Critical Findings: Technical Perspective

### 🔴 Finding 1: The Branch-Switching Deadlock (Critical Bug)

**Severity**: High / Functional Blocker  
**Affected Files**: `src/bin/agent_signd.rs`, `src/lease.rs`

#### The Flaw:
In `agent_signd.rs`:
```rust
// agent_signd.rs:263
if !st.lease_engine.has_active_lease(&repo) {
    // prompts user and grants lease for (repo, branch)
} else {
    Response::LeaseGranted {
        lease_id: "active".to_string(),
        expires_at_secs: 7200,
    }
}
```
`has_active_lease(&repo)` **only** checks if a lease exists for the repository name—it ignores the branch. If an agent starts on `feat/step-1`, a lease is granted. If the agent subsequently checks out `feat/step-2` and attempts a commit:
1. `agent-git` calls `RequestLease { repo, branch: "feat/step-2" }`.
2. `agent_signd` sees an active lease for `repo` (from `feat/step-1`) and returns `Response::LeaseGranted`.
3. `agent-git` then calls `IssueToken { repo, branch: "feat/step-2" }`.
4. `issue_commit_token` in `lease.rs` checks:
   ```rust
   if lease.branch != branch {
       return Err(format!("Lease was granted for branch '{}', not '{}'", lease.branch, branch));
   }
   ```
5. `IssueToken` fails. `agent-git` exits with code 1.
6. Because `Request::RevokeLease` is an empty no-op in `agent_signd.rs:329`, **the agent is permanently locked out of committing on any new branch until the original 2-hour lease expires or the daemon process is killed**.

---

### 🔴 Finding 2: "Touch ID" is Fictitious (AppleScript Dialogue Deception)

**Severity**: High / Misleading Claim & Security Vulnerability  
**Affected File**: `src/bin/agent_signd.rs`

#### The Flaw:
The README, SPEC, and integration docs claim:
> *"When an agent first commits, you are prompted once via Touch ID."*  
> *"invokes macOS biometric authorization (via native LocalAuthentication framework / Secure Enclave prompt) once."*

In reality, the code executes a plain AppleScript modal dialog via `osascript`:
```rust
let script = format!(
    "display dialog \"{}\" with title \"Agent-Sign Security Lease\" buttons {{\"Deny\", \"Approve\"}} default button \"Approve\" with icon caution",
    prompt_text.replace('"', "\\\"")
);
let output = Command::new("osascript").arg("-e").arg(&script).output();
```
- **Zero biometrics**: No Touch ID, no Secure Enclave, no PAM, no `LocalAuthentication.framework`.
- **Insecure Default**: The dialog sets `default button "Approve"`. If a developer happens to be typing and hits the Return key, the lease is approved invisibly.
- **Total Linux & DevContainer Breakdown**: Running on Linux, Docker, or headless SSH will immediately fail because `osascript` does not exist. Since `auto_approve` defaults to `false`, `agent-signd` unconditionally denies approval on non-macOS platforms.

---

### 🔴 Finding 3: Commit Message Transformation (`mode = "trailers"`) is Dead Code

**Severity**: High / Broken Enterprise Feature  
**Affected Files**: `src/attribution.rs`, `src/bin/agent_git.rs`

#### The Flaw:
`AttributionEngine::transform_commit_message` is designed to append `Co-Authored-By: Agent`, `X-Agent-Signer`, and `X-Agent-Lease`. It has a passing unit test in `tests/test_interceptor.rs`.

However, in `src/bin/agent_git.rs`, **`transform_commit_message` is never called**:
```rust
// agent_git.rs:165
git_args.extend_from_slice(original_args);
// ...
exec_system_git(&git_args, &env_pairs)
```
`agent_git` passes `original_args` straight through to `git`. If a team configures `attribution.mode = "trailers"`, Author and Committer are set to the human's credentials, the commit message is left completely untouched, and the commit is signed with the agent sub-key. The promised `Co-Authored-By` trailer is never added.

---

### 🔴 Finding 4: Repository-Level `.agent-sign.toml` is Never Loaded

**Severity**: Medium / Broken Configuration Hierarchy  
**Affected Files**: `src/config.rs`, `src/bin/agent_git.rs`, `src/bin/agent_signd.rs`

#### The Flaw:
Both `agent_git` and `agent_signd` call:
```rust
let config = Config::load(None);
```
Even though `agent_git.rs` determines the repository top-level directory via `rev-parse --show-toplevel`, it explicitly passes `None` to `Config::load`. 
Consequently:
- `.agent-sign.toml` files in repositories are **completely ignored**.
- Repo-specific settings (such as `allow_main_branch = true` or `block_branches`) can never take effect.
- Furthermore, `Config::load` completely overwrites `config = loaded;` rather than merging tables, meaning any repo config would wipe out global user settings if loaded.

---

### 🔴 Finding 5: Single-Threaded Daemon Blocks Listener During UI Prompts

**Severity**: Medium / Denial of Service & Architecture Smell  
**Affected File**: `src/bin/agent_signd.rs`

#### The Flaw:
The incoming connection loop in `agent_signd.rs` is synchronous:
```rust
for stream in listener.incoming() {
    match stream {
        Ok(mut s) => {
            let state_clone = Arc::clone(&state);
            handle_client(&mut s, state_clone);
        }
    }
}
```
Inside `handle_client`:
```rust
let mut st = state.lock().unwrap();
// ...
let approved = request_human_approval(&repo, &branch, &intent);
```
1. `handle_client` runs on the main listener thread.
2. The `state` mutex is locked **before** calling `request_human_approval`.
3. `request_human_approval` blocks on the desktop user dismissing the AppleScript dialog.
While the dialog is displayed, the daemon listener is blocked from accepting any connections, and all other threads/processes querying `agent-signd status` or pinging the socket hang until the dialog is closed.

---

### 🔴 Finding 6: Repository Collision by Directory Base Name

**Severity**: Medium / Multi-Repo Collision  
**Affected File**: `src/bin/agent_git.rs`

#### The Flaw:
In `get_repo_and_branch()`:
```rust
Path::new(&path_str)
    .file_name()
    .map(|f| f.to_string_lossy().to_string())
    .unwrap_or_else(|| "default-repo".to_string())
```
The repository identifier used for leases and rate limits is only the directory basename (e.g., `"frontend"` or `"app"`). If a developer works across multiple repositories sharing common folder names (e.g. `~/work/api` and `~/personal/api`), leases, rate limits, and branch constraints collide directly in the daemon.

---

### 🔴 Finding 7: Hardcoded System Binaries & Linux Portability Failure

**Severity**: Medium / Portability & Custom Setup Failure  
**Affected Files**: `src/bin/agent_git.rs`, `src/bin/agent_sign.rs`

#### The Flaw:
- `agent-git` hardcodes `/usr/bin/git`. On macOS, this calls the Apple Xcode Command Line Tools wrapper, bypassing user-installed modern Git from Homebrew (`/opt/homebrew/bin/git`) or MacPorts. On NixOS or systems without `/usr/bin/git`, this fails completely.
- `agent-sign` hardcodes `/usr/bin/ssh-keygen`. If a user uses 1Password commit signing (`op-ssh-sign`), delegating human commits to `/usr/bin/ssh-keygen` fails to trigger the 1Password agent. Although `fallback_program` exists in `Config`, `agent_sign.rs:29` does not even read it.

---

### 🔴 Finding 8: Token Leak & Unimplemented Revocation

**Severity**: Low / Resource Leak & Incomplete Implementation  
**Affected Files**: `src/bin/agent_signd.rs`, `src/lease.rs`

#### The Flaw:
- Tokens are stored in a `HashSet<String>`. If an agent issues a token but aborts before committing (e.g. hook failure or linter failure), the token remains in `valid_tokens` forever. The 60-second automatic token expiration promised in `BEST_PRACTICES.md` is not implemented.
- `Request::RevokeLease` returns `Response::Success` without modifying state. `LeaseEngine` does not have a `revoke_lease` method.

---

## 4. Usability & User Experience Perspective

### 1. The Human Isolation Catch-22 (Cursor / Terminal PATH Pollution)
In `docs/integrations/cursor.md`, the setup instruction tells users to modify their Cursor terminal settings:
```json
{
  "terminal.integrated.env.osx": {
    "PATH": "${env:HOME}/.agent-sign/bin:${env:PATH}"
  }
}
```
If a human developer opens an integrated terminal in Cursor and runs `git commit`, `git` resolves to `~/.agent-sign/bin/git`. 
Because `agent-git` does **not** check whether `stdin` is an interactive TTY (`std::io::stdin().is_terminal()`), it immediately treats the human's manual terminal commit as an autonomous agent commit! It issues an event token, overrides author/committer, and signs with the agent key—directly violating Non-Negotiable Invariant `[INV-1]`.

### 2. Lack of Daemon Service Management
The installation script (`scripts/install.sh`) simply prints:
```bash
$INSTALL_DIR/agent-signd &
```
There is no `launchd` plist for macOS or `systemd` user service unit for Linux. If the user reboots or closes the terminal session, the background job dies. Subsequent agent commits immediately fail with:
```
[agent-git] Unable to connect to agent-signd at ~/.agent-sign/daemon.sock: Connection refused
```

### 3. Misleading `agent-signd status`
Running `agent-signd status` only sends a `Ping` request and prints `Daemon is active and healthy`. It does not report:
- Active repositories or active leases.
- Lease expiration timestamps.
- Remaining rate-limit capacity.
- Configured attribution mode or branch restrictions.

### 4. Git Merge / Rebase / Cherry-Pick Ignored
In real agent workflows, autonomous agents frequently run `git merge`, `git cherry-pick`, or `git rebase`. All of these Git commands can create signed commits. 
However, `CommandInterceptor` in `src/interceptor.rs` strictly checks for `arg == "commit"`. If an agent runs `git merge feature-branch`, `agent-git` passes it through to `/usr/bin/git` without the signing shim or event token, leading to unexpected signing prompt failures.

### 5. GitHub "Verified" Badge Pitfall with `.internal` Emails
In `alias` mode, `AttributionEngine` sets Author and Committer email to `agent@local.internal`. GitHub requires that the committer email matches an email address registered and verified on the user's GitHub account. Because top-level domains like `.internal` cannot receive verification emails, commits signed in `alias` mode will show up on GitHub as **Unverified**!

---

## 5. Prioritized Remediation Roadmap

### Priority 0: Functional Correctness & Bug Fixes
- [ ] **Fix Branch Switching**: In `agent_signd.rs`, check both `repo` and `branch` in `has_active_lease`. If the branch changes within the same repo, trigger a new approval or update the lease rather than returning `LeaseGranted` on an invalid branch.
- [ ] **Implement Trailer Injection**: In `agent_git.rs`, inspect arguments for `-m` / `-F` or write a commit-msg hook filter to call `AttributionEngine::transform_commit_message` so that `mode = "trailers"` actually outputs trailers.
- [ ] **Fix Repo-Level Config**: Pass the repository path from `get_repo_and_branch()` into `Config::load(Some(&repo_path))`. Implement proper config struct merging (instead of full overwrite).
- [ ] **Implement `RevokeLease`**: Add `revoke_lease(&mut self, repo: &str)` to `LeaseEngine` and hook it up in `agent_signd.rs`.

### Priority 1: Security & Architecture
- [ ] **Replace Synchronous Daemon Lock**: Move `request_human_approval` outside of the `state` mutex lock, and spawn client handlers into worker threads (`std::thread::spawn`).
- [ ] **Replace AppleScript with True Touch ID / PAM**: Use native macOS `LocalAuthentication` bindings (via `security-framework` or `pam`) so that Touch ID / biometric verification is genuinely enforced.
- [ ] **Human Terminal TTY Guard**: In `agent-git`, check `std::io::stdin().is_terminal()`. If the user is in an interactive shell, bypass agent signing and delegate directly to system git to protect [INV-1].
- [ ] **Repo Key by Canonical Path**: Key leases in `LeaseEngine` using canonical repository absolute paths (or remote URLs) rather than `file_name()`.

### Priority 2: Usability & Portability
- [ ] **Dynamic Git & Fallback Path Resolution**: Search `PATH` for `git` (skipping `~/.agent-sign/bin`) instead of hardcoding `/usr/bin/git`. Read `config.ssh.fallback_program` in `agent-sign.rs` instead of hardcoding `/usr/bin/ssh-keygen`.
- [ ] **Interception of Merge / Rebase**: Expand `CommandInterceptor` to detect `merge`, `cherry-pick`, and `revert` commands that generate commits.
- [ ] **Daemon Lifecycle Scripts**: Provide `scripts/agent-signd.plist` (macOS launchd) and `systemd/agent-signd.service` for persistent background operation.
- [ ] **Token Expiration GC**: Add timestamps to `valid_tokens` and periodically evict unconsumed tokens older than 60 seconds.

---

## 6. Conclusion

`agent-sign` contains a strong, elegant cryptographic foundation. Generating valid OpenSSH signatures in pure Rust and isolating agent signing to a scoped sub-key is the right solution to a real problem. However, the runtime orchestration currently suffers from significant bugs (branch switching deadlocks, inactive trailers, unread configs) and exaggerated claims ("Touch ID" via AppleScript). Addressing the P0 and P1 issues in the remediation roadmap will transform this project from a promising proof-of-concept into a dependable, production-grade developer tool.
