# SPECIFICATION: Agent-Sign (Deterministic AI Agent Git Commit Signing & Identity)

- **Status**: Draft / RFC
- **Date**: 2026-09-25
- **Methodology**: Spec-Driven Development (SDD) & Test-Driven Development (TDD)

---

## 1. Executive Summary & Problem Statement

Modern software development increasingly uses autonomous and semi-autonomous AI coding agents (Antigravity, Claude Code, Cursor, Codex, Devin, Aider). When these agents commit code to Git repositories:
1. **Biometric Fatigue**: If the human developer uses hardware-backed commit signing (e.g., 1Password SSH Agent with Touch ID), every agent commit triggers a modal interrupt, halting automation.
2. **Insecurity via Conflation**: Disabling prompts or sharing the human's primary key allows the agent to impersonate the human across all repositories with unmitigated access.
3. **No Provenance**: Disabling signing produces unverified commits that fail repository branch-protection rules and eliminate cryptographic audit trails.
4. **Flawed Attribution**: Existing tools rely on cosmetic trailers (`Co-Authored-By: Claude`) without cryptographic proof, or risk misattributing manual human commits made in IDE interfaces.

`Agent-Sign` provides a **deterministic, scoped signing multiplexer and session lease daemon** that allows agents to headlessly sign commits with a dedicated GitHub-verifiable Agent Sub-Key, while ensuring 100% of human commits continue through the human's standard 1Password Touch ID flow.

---

## 2. Fundamental System Invariants (Non-Negotiable)

The following invariants MUST be verified by automated tests and MUST NEVER be violated:

* **[INV-1] Human Isolation**: Any `git commit` initiated by a human (whether via interactive terminal shell or IDE graphical Source Control buttons) MUST bypass agent signing and delegate directly to the standard human signing agent (e.g., 1Password / `/usr/bin/ssh-keygen`), preserving biometric prompts.
* **[INV-2] Deterministic Interception**: Any `git commit` initiated by an AI agent within an agent session MUST be deterministically intercepted without requiring the LLM to remember flags, special commands, or custom CLI syntax.
* **[INV-3] Gated Session Lease**: Headless signing MUST NOT occur without a valid, unexpired session lease.
* **[INV-4] Single-Touch Approval**: If no valid lease exists when an agent initiates a task or commit, the system MUST pause execution and request human biometric/confirmation approval ONCE. Subsequent commits within the lease TTL MUST proceed autonomously.
* **[INV-5] Configurable Attribution**: The system MUST support multiple attribution modes (`split`, `trailers`, `alias`) via configuration without altering core signing mechanics.
* **[INV-6] Cryptographic Validity**: Signatures MUST conform to standard Git SSH signature format (`gpg.format = ssh`), verifiable locally via `ssh-keygen -Y verify` and remotely via GitHub/GitLab "Verified" status.
* **[INV-7] Fail-Closed Security**: If lease validation fails, daemon is unreachable, or signature generation errors occur, the system MUST fail closed (refusing to sign) rather than silently falling back to signing with unprotected keys.

---

## 3. Architecture & Data Flow

```
+-------------------------------------------------------------------------+
|                              USER MACHINE                               |
|                                                                         |
|  +---------------------------+       +-------------------------------+  |
|  |     Human Environment     |       |    Agent Tool Environment     |  |
|  |  (Terminal / IDE GUI UI)  |       | (Antigravity / Claude / etc.) |  |
|  +-------------+-------------+       +---------------+---------------+  |
|                |                                     |                  |
|                | git commit                          | git commit       |
|                | (Standard PATH)                     | (Injected PATH)  |
|                v                                     v                  |
|        /usr/bin/git                     ~/.agent-sign/bin/git           |
|                |                        (Deterministic Shim)            |
|                |                                     |                  |
|                |                                     v                  |
|                |                             Attach Event Token         |
|                |                                     |                  |
|                +------------------+------------------+                  |
|                                   |                                     |
|                                   v                                     |
|                         agent-sign multiplexer                          |
|                         (as gpg.ssh.program)                            |
|                                   |                                     |
|                   Has valid AGENT_EVENT_TOKEN?                          |
|                          /                 \                            |
|                        NO                  YES                          |
|                        /                     \                          |
|                       v                       v                         |
|             Forward to standard         Check Daemon Lease              |
|             1Password / ssh-keygen            |                         |
|                       |                [Valid Lease?]                   |
|                       v                    /     \                      |
|                Touch ID Prompt            YES     NO                    |
|                       |                   /         \                   |
|                       v                  v           v                  |
|                 Human Signature    Sign Buffer   Trigger Touch ID       |
|                                    with Agent    Once for Lease         |
|                                      Sub-Key            |               |
|                                         |               v               |
|                                         |        Approved / Denied      |
|                                         v                               |
|                                  Agent Signature                        |
+-----------------------------------------+-------------------------------+
                                          |
                                          v
                                   GitHub / GitLab
                         (Verified via User's Agent Sub-Key)
```

---

## 4. Component Specifications

### 4.1. Component A: Deterministic Environment Interceptor (`agent-git`)
- **Path**: `~/.agent-sign/bin/git`
- **Role**: Sits first in `PATH` only inside the agent's tool execution context.
- **Behavior**:
  1. Inspects arguments. If command is not `commit`, directly execs real `/usr/bin/git` with original args and env.
  2. If command is `commit`:
     - Queries local daemon at `~/.agent-sign/daemon.sock` to obtain an ephemeral single-use `AGENT_EVENT_TOKEN`.
     - Appends or injects `AGENT_EVENT_TOKEN=<token>` into the environment for this specific execution.
     - Injects custom git configuration overrides (`-c gpg.ssh.program=~/.agent-sign/bin/agent-sign`).
     - Execs real `git commit` with the modified environment.

### 4.2. Component B: Signing Multiplexer (`agent-sign`)
- **Path**: `~/.agent-sign/bin/agent-sign`
- **Role**: Registered as `gpg.ssh.program` in Git.
- **Contract**: Conforms strictly to OpenSSH `ssh-keygen -Y sign -n git -f <key_path> <buffer_path>`.
- **Behavior**:
  1. Checks for presence of `AGENT_EVENT_TOKEN` in environment.
  2. **If token is absent or invalid**:
     - Immediately delegates to system default `ssh-keygen` (forwarding to 1Password agent socket).
     - Standard human Touch ID runs.
  3. **If token is valid**:
     - Connects to local daemon.
     - Validates active lease (and triggers human auth prompt if lease is uninitialized).
     - Applies attribution transformation per configuration (`split`, `trailers`, `alias`).
     - Signs commit buffer using the local agent SSH private key.
     - Outputs valid SSH signature buffer to stdout / file as required by Git.

### 4.3. Component C: Local Daemon & Lease Engine (`agent-signd`)
- **Socket**: `~/.agent-sign/daemon.sock`
- **Role**: Manages in-memory active lease, rate limits, audit logs, and Touch ID / prompt authorization.
- **Data Structures**:
  ```yaml
  Lease:
    id: UUID
    granted_at: Timestamp
    expires_at: Timestamp
    repo_root: Path
    branch: String
    max_commits: Integer
    commits_issued: Integer
    allowed_models: List[String]
  ```
- **Operations**:
  - `request_lease(repo, duration, intent)`: If valid lease exists for repo, returns existing lease ID. If not, invokes macOS biometric authorization (via native `LocalAuthentication` framework / Secure Enclave prompt) once.
  - `issue_token()`: Returns a single-use cryptographically random token tied to current lease.
  - `verify_and_sign(token, buffer)`: Verifies token, decrements remaining allowance, signs buffer, logs audit event.
  - `revoke_lease(id)`: Immediately invalidates the active lease.

### 4.4. Component D: Attribution Engine
Configured via `~/.agent-sign/config.toml` and optional `.agent-sign.toml`:

```toml
[attribution]
mode = "split" # "split" | "trailers" | "alias"

[agent]
name = "Antigravity Agent"
email = "agent@local.internal"

[human]
name = "Human Developer"
email = "developer@example.com"
github_username = "developer"

[security]
default_lease_duration = "2h"
block_branches = ["main", "master", "release/*"]
max_commits_per_minute = 10
```

#### Attribution Mode Behaviors:
- **`split`**: Sets `GIT_AUTHOR_NAME` to agent name/email, sets `GIT_COMMITTER_NAME` to human name/email. Signature made with Agent Sub-Key. Result on GitHub: *"Agent authored and Human committed (Verified)"*.
- **`trailers`**: Leaves Author and Committer as human. Injects `Co-Authored-By: Agent <email>` and `X-Agent-Signer: agent-sign/v0.1` into the commit message. Result on GitHub: *"Human committed (Verified) with Agent co-author"*.
- **`alias`**: Sets Committer and Author to `Human (Agent) <developer+agent@example.com>`.

---

## 5. Security Threat Model

| Threat | Mitigation |
| :--- | :--- |
| **Agent compromises master SSH key** | Agent never touches or sees the human's 1Password key. Agent key is a distinct, scoped SSH key registered in GitHub solely as a "Signing Key", incapable of authentication or pushing. |
| **Runaway agent loops (1000s of commits)** | Daemon enforces hard rate limits (`max_commits_per_minute`) and lease-based total commit caps. |
| **Accidental commit to production branch** | Daemon and wrapper reject signing if active branch matches `block_branches` policy (e.g. `main`). |
| **Malicious process steals Agent Sub-Key** | Private key can be encrypted at rest with a key held in macOS Keychain, unlocked only during an active lease. |
| **Prompt Injection attacks** | Agent cannot escalate permissions beyond signing code on the authorized branch; cannot bypass lease expiration without human re-authentication. |

---

## 6. Test-Driven Development (TDD) Test Matrix

The following test suites MUST be implemented and passing:

### Suite 1: Human Isolation & Default Fallback (`test_human_isolation`)
- [ ] `test_human_terminal_commit_invokes_standard_ssh_agent`: Ensure standard `git commit` without token invokes standard `ssh-keygen` and passes through to 1Password.
- [ ] `test_ide_gui_commit_not_intercepted`: Verify that calls lacking `AGENT_EVENT_TOKEN` never trigger agent signing or agent attribution.
- [ ] `test_corrupt_or_expired_token_fails_closed`: Invalid tokens must not sign with agent key.

### Suite 2: Deterministic Interception & Attribution (`test_interceptor`)
- [ ] `test_agent_git_injects_event_token_on_commit`: Verify wrapper detects `commit` command and attaches valid event token.
- [ ] `test_agent_git_passes_non_commit_commands_untouched`: Commands like `git status`, `git diff`, `git push` pass through without modification.
- [ ] `test_attribution_split_mode`: Verify author and committer headers match specification.
- [ ] `test_attribution_trailers_mode`: Verify trailers are correctly formatted in commit message.

### Suite 3: Lease Lifecycle & Guardrails (`test_lease_engine`)
- [ ] `test_lease_granted_after_single_auth`: Approving prompt grants lease for configured duration.
- [ ] `test_subsequent_commits_within_ttl_require_zero_prompts`: Multiple commits within lease succeed headlessly.
- [ ] `test_expired_lease_triggers_new_prompt`: Commits after TTL trigger re-authorization.
- [ ] `test_branch_protection_blocks_main`: Commits targeting protected branches are blocked with descriptive error.
- [ ] `test_rate_limiter_throttles_rapid_commits`: Exceeding threshold blocks commit and notifies developer.

### Suite 4: Cryptographic Verification (`test_crypto_verification`)
- [ ] `test_generated_signature_validates_with_ssh_keygen`: Output signature passes `ssh-keygen -Y verify -f allowed_signers`.
- [ ] `test_signature_format_matches_git_ssh_specification`: Headers and format strictly adhere to OpenSSH signature format (`-----BEGIN SSH SIGNATURE-----`).
