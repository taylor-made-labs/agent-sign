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
> | 2. "Touch ID" is an AppleScript dialog | The docs no longer claim Touch ID. The dialog is still a confirmation with Approve as its default button (open; release checklist M9). |
> | 3. `trailers` mode never applied | Fixed for messages given with `-m` or `--message`; `-F` and editor messages are left as they are. |
> | 4. Repository config never loaded | Fixed for the wrapper's rules and attribution, merged over the person's config. The service deliberately reads only the person's own config. |
> | 5. Service blocks during dialogs | Fixed: a thread per connection, and the lock isn't held during a dialog. |
> | 6. Repositories keyed by folder name | Fixed: keyed by canonical path. |
> | 7. Hard-coded `/usr/bin/git` and `ssh-keygen` | Fixed: git is found on `PATH`; `fallback_program` is used. |
> | 8. Tokens never expire; revocation a no-op | Fixed: tokens expire after 60 seconds; `agent-sign revoke` works (and since 30 Sept, reports when nothing matched). |
> | Usability 1. Terminal commits treated as the agent's | Fixed: commits with a terminal on standard input and output are the person's. An editor's commit button is still treated as an agent's. |
> | Usability 2. No service management | Fixed: launchd and systemd user services. |
> | Usability 3. `status` says little | Fixed: it lists leases. |
> | Usability 4. Merge, rebase, cherry-pick not intercepted | Open (release checklist M2). |
> | Usability 5. `alias` mode shows Unverified | Still true with the default `.internal` email; documented in SPEC.md. |
>
> The review's praise of a "zero blast radius" key needs a correction: the key
> can't log in or push, but it's unencrypted and readable by the person's user,
> and commits signed with it show as Verified for the person.

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
