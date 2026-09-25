# Agent-Sign 🔏🤖

**Deterministic AI Coding Agent Commit Signing & Identity Multiplexer**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/tests-15%20passed-brightgreen.svg)]()

> Stop tapping Touch ID on every commit your agent makes. Give your coding agents their own verified GitHub SSH sub-key with one-touch session leasing—without ever compromising your master 1Password/hardware credentials.

---

## The Problem

When working with autonomous coding agents (Antigravity, Claude Code, Cursor, Codex, Devin, Aider):
1. **Biometric Interrupts**: If you use 1Password or Touch ID commit signing, every commit the agent makes triggers a modal interrupt waiting for your fingerprint. Incremental commits grind automation to a halt.
2. **The Insecure "Fix"**: Developers often turn off `commit.gpgsign`, causing commits to show as unverified and violating repository branch protection rules.
3. **Cosmetic Attribution**: Agents rely on `Co-Authored-By: Claude` text trailers that carry zero cryptographic proof.
4. **False Attribution**: Blunter scripts accidentally attribute human commits made in IDE GUI buttons to the agent.

---

## The Solution: How `agent-sign` Works

`agent-sign` is a lightweight Rust toolchain that solves this with three coordinated components:

```
+--------------------------------------------------------------------------+
|                              USER MACHINE                                |
|                                                                          |
|  Human (Terminal / IDE GUI)                 Agent (Antigravity / Claude) |
|         |                                                |               |
|         v                                                v               |
|    /usr/bin/git                                ~/.agent-sign/bin/git     |
|   (Standard PATH)                              (Deterministic Shim)      |
|         |                                                |               |
|         | (No token)                     (Injects single-use event token)|
|         +-----------------------+------------------------+               |
|                                 |                                        |
|                                 v                                        |
|                       agent-sign multiplexer                             |
|                       (as gpg.ssh.program)                               |
|                                 |                                        |
|                  Has valid AGENT_EVENT_TOKEN?                            |
|                         /               \                                |
|                       NO                YES                              |
|                       /                   \                              |
|                      v                     v                             |
|             Forward to standard      Check Daemon Lease                  |
|             1Password / ssh-keygen         |                             |
|                      |               [Valid Lease?]                      |
|                      v                  /        \                       |
|               Touch ID Prompt         YES         NO                     |
|                      |                /             \                    |
|                      v               v               v                   |
|                Human Commit     Sign Buffer    Trigger Touch ID          |
|                                 Headlessly     Once for 2hr Lease        |
|                                 with Sub-Key                             |
+--------------------------------------------------------------------------+
```

1. **`agent-signd` (Session Lease Daemon)**: Holds a dedicated Ed25519 Agent Signing Key in memory and manages a 2-hour session lease. When an agent first commits, you are prompted **once** via Touch ID. All subsequent commits within the lease sign autonomously.
2. **`agent-sign` (`gpg.ssh.program` Multiplexer)**: Registered in Git. If a commit lacks an agent event token, it delegates to `/usr/bin/ssh-keygen` (forwarding straight to 1Password). If a token is present, it validates the lease and signs with the agent's key.
3. **`agent-git` (Environment Interceptor)**: Placed in the agent's tool `PATH` as `git`. The LLM doesn't have to remember any flags—it runs normal `git commit` and the wrapper deterministically coordinates with the daemon.

---

## Key Invariants & Features

* **100% Human Isolation**: Clicking "Commit" in the IDE Source Control GUI or running `git commit` in your personal shell *never* triggers agent signing. It always prompts your personal 1Password Touch ID.
* **Green "Verified" Badge on GitHub**: The dedicated Agent Sub-Key is added to your existing GitHub account as a **Signing Key**. Every commit signed by the agent gets the official green "Verified" badge.
* **Zero Blast Radius**: An SSH signing key can **only** sign text buffers. It cannot authenticate to servers, push commits, or clone private repositories.
* **Branch Protection Guardrails**: Automatically blocks agent commits directly to `main` or `master`.
* **Sliding Rate Limiting**: Throttles runaway loops (e.g. max 10 commits/minute).
* **Flexible Attribution**:
  * `split`: Author = Agent, Committer = You (Open-source transparency).
  * `trailers`: Author = You, Committer = You + `Co-Authored-By: Agent` (Enterprise LDAP compliant).
  * `alias`: Author & Committer = `You (Agent) <you+agent@domain.com>`.

---

## Quickstart

### 1. Build & Run Tests
```bash
cargo test
cargo build --release
```

### 2. Setup Agent Keypair
```bash
target/release/agent-signd setup
```
This generates your dedicated Agent Signing Key (`~/.agent-sign/keys/agent_ed25519`) and outputs the public key string:
```text
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... agent@local.internal
```

### 3. Add to GitHub
1. Go to **GitHub Settings -> SSH and GPG keys -> New SSH key**.
2. Key type: select **Signing Key**.
3. Paste the public key string and save.

### 4. Start the Daemon
```bash
target/release/agent-signd
```

### 5. Configure Your Agent's Environment
Point the agent's tool execution `PATH` to include `~/.agent-sign/bin`:
```bash
mkdir -p ~/.agent-sign/bin
cp target/release/agent-git ~/.agent-sign/bin/git
cp target/release/agent-sign ~/.agent-sign/bin/agent-sign
```

---

## Documentation & Integration Guides

* **Integration Guides**:
  * [Claude Code Setup](docs/integrations/claude-code.md)
  * [Cursor Agent Setup](docs/integrations/cursor.md)
  * [Google Antigravity & Gemini CLI Setup](docs/integrations/antigravity.md)
  * [Aider Setup](docs/integrations/aider.md)
* **Specifications & Principles**:
  * [SPEC.md](SPEC.md): Formal System Specification, non-negotiable invariants, and state machines.
  * [VALUE_PROP.md](VALUE_PROP.md): Concrete commitments across 5 workflows (1Password, YubiKey, GPG, Enterprise, DevContainers).
  * [docs/BEST_PRACTICES.md](docs/BEST_PRACTICES.md): Architectural patterns, security guidelines, and performance standards.
  * [CONTRIBUTING.md](CONTRIBUTING.md): Contribution guidelines and TDD workflows.

---

## License
MIT
