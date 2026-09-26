# Agent-Sign 🔏🤖

**Deterministic AI Coding Agent Commit Signing & Identity Multiplexer for Any Toolchain**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/tests-23%20passed-brightgreen.svg)]()
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20WSL2-lightgrey.svg)]()
[![Security: Zero Blast Radius](https://img.shields.io/badge/security-zero%20blast%20radius-success.svg)]()

> **Stop repetitive biometric/hardware prompts (1Password, Touch ID, YubiKey, or GPG smartcards) on every micro-commit your AI agent makes.** Give your coding agents their own verified GitHub/GitLab SSH sub-key with one-touch session leasing—without ever compromising your master hardware keys, personal credentials, or human commit attribution.

---

## The Problem

When pairing with autonomous AI coding agents (**Claude Code**, **Cursor**, **Google Antigravity**, **Aider**, **Windsurf**, **Devin**, or custom subagents):

1. **Prompt Fatigue**: If you sign commits with hardware-backed keys, 1Password, Touch ID, or GPG, your agent makes 20 incremental commits and halts on *every single one* waiting for your fingerprint or PIN.
2. **The Dangerous "Fix"**: Developers disable `commit.gpgsign`, causing commits to appear as **Unverified** on GitHub and violating organizational branch-protection rules.
3. **Master Key Exposure**: Giving an agent access to your primary private key or SSH agent socket creates severe host blast-radius risk—an agent with your primary key can impersonate you, push to repositories, or authenticate to remote servers.
4. **Cosmetic Plaintext Trailers**: `Co-Authored-By: Claude` trailers in commit messages carry zero cryptographic proof—anyone can write any text in a commit message.
5. **False Attribution**: Crude wrapper scripts accidentally intercept human commits in IDE GUI buttons or interactive terminals, attributing human work to the agent.

---

## Comparison: The Commit Signing Matrix

| Feature | Without Agent-Sign | Turn Off GPG/SSH | Export Personal Key | 🔏 **With Agent-Sign** |
| :--- | :---: | :---: | :---: | :---: |
| **GitHub "Verified" Badge** | ✅ Yes | ❌ No (Unverified) | ✅ Yes | ✅ **Yes (Dedicated Agent Key)** |
| **Hardware / Biometric Prompts** | ❌ On *every* commit | ✅ None | ✅ None | ✅ **Once per 2h lease session** |
| **Personal Key Security** | ✅ Protected | ✅ Protected | ❌ Catastrophic Risk | ✅ **100% Isolated & Untouched** |
| **Human Commit Protection** | ✅ Yes | ❌ No | ❌ Agent identity mixup | ✅ **100% Isolated (TTY & GUI)** |
| **Branch Protection Rules** | ❌ Fails / Blocked | ❌ Fails / Blocked | ❌ Overwrites human rules | ✅ **Protected (`main` guarded)** |
| **Runaway Loop Throttling** | ❌ None | ❌ None | ❌ None | ✅ **Sliding Rate Limiter** |

---

## Universal Agent Compatibility

`agent-sign` provides zero-friction, zero-alias support across all major AI agent toolchains:

| Agent / Tool | Vendor | Integration Method | Configuration Needed |
| :--- | :--- | :--- | :--- |
| **[Claude Code](docs/integrations/claude-code.md)** | Anthropic | Shell PATH (`~/.zshrc` / `~/.zprofile`) | **Zero-config** (installer auto-configures) |
| **[Cursor](docs/integrations/cursor.md)** | Anysphere | Terminal environment (`settings.json`) | **Zero-config** (installer auto-configures) |
| **[Google Antigravity & Gemini CLI](docs/integrations/antigravity.md)** | Google | Shell PATH + Agent Rules | **Zero-config** (installer auto-configures) |
| **[Aider](docs/integrations/aider.md)** | Open Source | Shell PATH | **Zero-config** (installer auto-configures) |
| **VS Code / GitHub Copilot** | Microsoft | Terminal environment (`settings.json`) | **Zero-config** (installer auto-configures) |
| **Windsurf** | Codeium | Terminal environment (`settings.json`) | **Zero-config** (installer auto-configures) |
| **Devin / Codex / Custom Agents** | Any | Universal `$INSTALL_DIR/git` shim | **Zero-config** via PATH |
| **CI / Docker / DevContainers** | Any | `--auto-approve` / Environment variable | Set `AGENT_SIGN_AUTO_APPROVE=1` |

---

## Quickstart (Up & Running in 60 Seconds)

### 1. Install (One-Liner or Clone)

**One-line install (Recommended):**
```bash
curl -fsSL https://raw.githubusercontent.com/taylor-made-labs/agent-sign/main/scripts/install.sh | bash
```

*Or install from source:*
```bash
git clone https://github.com/taylor-made-labs/agent-sign.git
cd agent-sign
./scripts/install.sh
```

The installer automatically:
- Builds optimized release binaries with [Cargo](https://rustup.rs).
- Generates a dedicated Ed25519 agent signing keypair in `~/.agent-sign/keys/`.
- Auto-detects your existing signing toolchain (1Password `op-ssh-sign`, YubiKey, GPG, OpenSSH `ssh-keygen`).
- Generates `~/.agent-sign/config.toml` with the correct fallback configuration.
- Registers the agent key in your Git `allowed_signers` file for local verification.
- Installs and activates `agent-signd` as a background user service (launchd on macOS, systemd on Linux).
- **Auto-configures your environment**:
  - Injects PATH into your shell profiles (`~/.zshrc`, `~/.zprofile`, `~/.bashrc`, `~/.bash_profile`).
  - Injects terminal environment into IDE settings (Cursor, VS Code, Windsurf).
  - Creates Antigravity agent rules in `~/.gemini/config/rules/`.
- Runs an 11-point health check to verify everything is operational.
- **Zero-Friction Key Registration**: If you have the GitHub CLI (`gh`) installed, `install.sh` automatically registers your agent signing key to your GitHub account! If not, it copies the public key to your clipboard and opens the GitHub settings page directly in your browser.

### 2. Signing Key on GitHub / GitLab
If you don't use `gh` or use GitLab, register the public key manually:
1. Go to **[GitHub → Settings → SSH and GPG keys → New SSH Key](https://github.com/settings/ssh/new)**
2. Key type: Select **Signing Key** (NOT Authentication Key)
3. Title: e.g. `Agent-Sign Sub-Key`
4. Key: Paste the public key (already copied to your clipboard by the installer)
5. Click **Add SSH Key**

### 3. Start Coding With Your Agent!
Reload your shell (or open a new terminal window):
```bash
source ~/.zshrc
```

Now run your agent normally—**no aliases, no wrappers, no custom flags required**:
```bash
claude        # Claude Code
cursor .      # Cursor
agy           # Google Antigravity
aider         # Aider
```

On the agent's first commit, you will see a single native prompt (macOS dialog, Linux desktop GUI, or terminal prompt):
> *"AI Agent requesting commit signing lease for 2 hours."*

Click **Approve**. All subsequent commits for the next 2 hours sign silently in milliseconds.

---

## How It Works: Architecture & Routing

```
+-----------------------------------------------------------------------------------+
|                                   USER MACHINE                                    |
|                                                                                   |
|   Human (Interactive Terminal / IDE GUI)             AI Agent (Claude / Cursor)   |
|                 |                                                 |               |
|                 v                                                 v               |
|            system git                                   ~/.agent-sign/bin/git     |
|         (Standard PATH)                                 (Deterministic Shim)      |
|                 |                                                 |               |
|                 | (No token)                      (Injects single-use event token)|
|                 +-----------------------+-------------------------+               |
|                                         |                                         |
|                                         v                                         |
|                               agent-sign multiplexer                              |
|                                (as gpg.ssh.program)                               |
|                                         |                                         |
|                          Has valid AGENT_EVENT_TOKEN?                             |
|                                 /               \                                 |
|                               NO                YES                               |
|                               /                   \                               |
|                              v                     v                              |
|                     Forward to standard       Check Daemon Lease                  |
|                     human signing program          |                              |
|                  (1Password / YubiKey / GPG)       |                              |
|                              |               [Valid Lease?]                       |
|                              v                  /        \                        |
|                       Personal Prompt         YES         NO                      |
|                      (Touch ID / PIN)         /             \                     |
|                              |               v               v                    |
|                              v          Sign Buffer     Trigger Prompt            |
|                        Human Commit     Headlessly      Once for 2hr Lease        |
|                                         with Sub-Key    (GUI / TTY / Auto)        |
+-----------------------------------------------------------------------------------+
```

### The Three Components

1. **`agent-signd` (Session Lease Daemon)**:
   A lightweight background daemon running via launchd (macOS) or systemd (Linux). It holds the dedicated Ed25519 agent private key, enforces time-limited session leases (default 2h), guards protected branches (`main`/`master`), and applies sliding-window rate limiting.
2. **`agent-sign` (`gpg.ssh.program` Multiplexer)**:
   Registered in Git as your SSH signing program. If a commit lacks an agent event token, it delegates directly to your configured personal signing program (e.g. 1Password `op-ssh-sign`, YubiKey, or `/usr/bin/ssh-keygen`). If an agent token is present, it validates the lease and signs with the agent sub-key.
3. **`agent-git` (Environment Interceptor & Attribution Engine)**:
   Installed in the agent's tool PATH as `git`. When an agent executes `git commit`, `agent-git` requests a single-use token from `agent-signd`, injects attribution metadata, and invokes real git.

### The 100% Human Isolation Invariant
`agent-sign` strictly guarantees that your manual human commits are never signed as an agent:
* **Interactive Terminal**: `agent-git` checks `is_terminal()` on stdin/stdout. If both are active TTYs, it detects human interactive usage and immediately passes through to system git without agent signing.
* **IDE GUI Sidebar**: Clicking "Commit" in VS Code or Cursor's Source Control GUI bypasses `agent-git` entirely or invokes git without an agent event token, routing directly to your personal signing program.

---

## Key Features & Security Guarantees

* **Zero Blast Radius**: An SSH signing key can **only** sign Git buffers. It cannot authenticate SSH sessions, clone private repositories, or push to remotes.
* **Pure Rust OpenSSH SSHSIG Generation**: Uses `ed25519-dalek` to produce RFC 4251 compliant SSH signatures directly in-process—no slow child processes, passing system `ssh-keygen -Y verify` in sub-milliseconds.
* **Fail-Closed Security**: If the daemon is unreachable, the token is invalid, or lease verification fails, the toolchain halts immediately with an informative error rather than silently signing with unverified keys.
* **Branch Protection**: Commits directly to `main` and `master` are blocked by default, protecting production branches from accidental autonomous agent commits.
* **Seamless Branch Switching**: Work across multiple feature branches within an authorized session without repetitive prompts or deadlocks.
* **Sliding Rate Limiter**: Guards against runaway recursive agent loops (default: max 10 commits/minute).
* **Flexible Attribution Modes**:
  * `split` (Recommended for OSS): Author = Agent, Committer = You.
  * `trailers` (Enterprise LDAP compliant): Author = You, Committer = You + `Co-Authored-By: Agent` + `X-Agent-Signer`.
  * `alias`: Author & Committer = `You (Agent) <you+agent@domain.com>`.

---

## Configuration Reference

Configuration is managed in `~/.agent-sign/config.toml` (or at repo root in `.agent-sign.toml`):

```toml
# Agent-Sign Configuration
# Documentation: https://github.com/taylor-made-labs/agent-sign

[security]
# Session lease duration before re-approval is needed (e.g. "30m", "2h", "1d")
default_lease_duration = "2h"

# Protect production branches (agent commits to these branches are blocked)
allow_main_branch = false
block_branches = ["main", "master", "release/*"]

# Guard against runaway commit loops (max commits per 60-second window)
max_commits_per_minute = 10

# Auto-approve leases without desktop prompt (useful for CI, containers, headless)
auto_approve = false

[attribution]
# "split"    -> Author: Agent, Committer: You (Recommended for OSS)
# "trailers" -> Author: You + Co-Authored-By trailers (Enterprise LDAP compliant)
# "alias"    -> Author & Committer: You (Agent) <you+agent@domain.com>
mode = "split"

[agent]
name = "AI Agent"
email = "agent@local.internal"

[human]
# Auto-detected from git config (user.name and user.email). Override here if needed:
# name = "Your Name"
# email = "you@example.com"

[ssh]
# Your personal signing program — human commits are forwarded here.
# Auto-detected during installation (1Password, ssh-keygen, GPG, etc.)
fallback_program = "/Applications/1Password.app/Contents/MacOS/op-ssh-sign"
```

---

## CLI Cheatsheet & Day-to-Day Commands

```bash
# Run full system diagnostics and health audit
~/.agent-sign/bin/agent-sign doctor

# Run an ephemeral 2-minute sandbox demo
./scripts/demo-sandbox.sh

# Check daemon health & active leases
~/.agent-sign/bin/agent-signd status

# Manually generate or verify keypairs
~/.agent-sign/bin/agent-signd setup

# Stop the daemon
pkill -f agent-signd

# Verify a commit signature locally using Git
git verify-commit HEAD
git log -1 --show-signature

# Cleanly uninstall agent-sign and revert all configs
./scripts/uninstall.sh
```

---

## Frequently Asked Questions (FAQ)

### Is it safe to leave the agent private key on my machine?
Yes. The agent private key is restricted by file permissions (`0600`) and directory permissions (`0700`). Crucially, an SSH key registered as a **Signing Key** on GitHub/GitLab has zero permissions to clone, read, or push to repositories, and cannot authenticate to any SSH server. Its blast radius is strictly confined to signing Git commit buffers locally.

### Will my normal interactive Git commits be signed by the agent?
**No.** `agent-sign` enforces strict human isolation. When you type `git commit` in your interactive terminal, `agent-git` detects an active TTY on both stdin and stdout and immediately executes your system git. When you click "Commit" in an IDE GUI (VS Code / Cursor), the GUI does not pass an agent event token, routing directly to your personal signing program (e.g. 1Password Touch ID).

### What if I want to commit to `main` branch with an agent?
By default, commits to `main` and `master` are blocked to prevent automated mistakes in production. You can enable main branch commits by setting `allow_main_branch = true` in `~/.agent-sign/config.toml` or running with `AGENT_SIGN_ALLOW_MAIN=1`.

### Can I use Agent-Sign in CI/CD, DevContainers, or Docker?
Yes! In headless environments where desktop GUI prompts are unavailable, set:
```bash
export AGENT_SIGN_AUTO_APPROVE=1
```
Or start the daemon with `--auto-approve`. The daemon will automatically grant session leases without prompting.

### How do I cleanly uninstall?
Run the included uninstaller:
```bash
./scripts/uninstall.sh
```
This cleanly removes daemon services (launchd/systemd), reverts your shell profile PATH entries (`~/.zshrc`, `~/.zprofile`, `~/.bashrc`), reverts IDE settings (Cursor, VS Code, Windsurf), removes the agent key from `allowed_signers`, and deletes `~/.agent-sign/`.

---

## Documentation & Deep Dives

* **Integration Guides**:
  * [Claude Code Setup](docs/integrations/claude-code.md)
  * [Cursor Agent Setup](docs/integrations/cursor.md)
  * [Google Antigravity & Gemini CLI Setup](docs/integrations/antigravity.md)
  * [Aider Setup](docs/integrations/aider.md)
* **Specifications & Architecture**:
  * [SPEC.md](SPEC.md): Formal System Specification, non-negotiable invariants, and state machines.
  * [VALUE_PROP.md](VALUE_PROP.md): Concrete commitments across 5 workflows (1Password, YubiKey, GPG, Enterprise, DevContainers).
  * [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md): Step-by-step solutions for 1Password, YubiKey, Linux desktop, and containers.
  * [docs/BEST_PRACTICES.md](docs/BEST_PRACTICES.md): Architectural patterns, security guidelines, and performance standards.
  * [docs/ADVERSARIAL_REVIEW.md](docs/ADVERSARIAL_REVIEW.md): Independent adversarial audit and architectural scorecard.
  * [CONTRIBUTING.md](CONTRIBUTING.md): Contribution guidelines and TDD workflows.

---

## License

This project is licensed under the [MIT License](LICENSE).
