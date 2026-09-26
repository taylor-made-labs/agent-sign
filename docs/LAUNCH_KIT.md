# Agent-Sign Launch Kit & Community Outlines

This document contains publication-ready technical copy, pitches, and discussion threads for introducing `agent-sign` to the developer ecosystem.

---

## 1. Show HN: Agent-Sign – Deterministic commit signing & identity multiplexer for AI coding agents

**Target**: [news.ycombinator.com](https://news.ycombinator.com)  
**Title**: Show HN: Agent-Sign – Stop biometric/GPG interrupts on AI agent git commits

### Post Body:

> Hey HN,
>
> Over the past few months, my team shifted heavily towards using autonomous coding agents (Claude Code, Cursor, Aider, Antigravity) for iterative development loops.
>
> If you follow modern security hygiene, you likely have `commit.gpgsign = true` with a hardware-backed key: Touch ID via 1Password / macOS Secure Enclave, a YubiKey, or GPG.
>
> That creates an immediate collision:
> 1. **Prompt Fatigue**: The agent makes 10 incremental atomic commits during a refactor. Every single commit triggers a 1Password modal, macOS Touch ID prompt, or YubiKey touch. If you step away from your desk, execution blocks on step 1.
> 2. **The Terminal UI Freeze**: In Claude Code and TUI agents, `gpg` attempts to launch `pinentry-curses` or `pinentry-tty` on the active terminal. The agent hangs in an infinite lock or crashes with "No passphrase given".
> 3. **The Dangerous "Workaround"**: Many developers respond by disabling commit signing (`--no-gpg-sign`), stripping their commits of verification and violating company branch protection rules (SOC2 / ISO 27001).
>
> We built **agent-sign** (open source in Rust) to solve this without weakening human security:
>
> - **Architecture**: It registers as your `gpg.ssh.program` in Git and runs a lightweight local session daemon (`agent-signd`).
> - **One-Touch Session Leasing**: When an agent initiates a task, you are prompted **once** (macOS dialog, Linux desktop GUI, or terminal prompt) to approve a scoped session lease (e.g. 2 hours). All subsequent agent commits sign headlessly in < 10ms with a dedicated Ed25519 sub-key.
> - **100% Human Isolation**: Any commit initiated by you in an interactive terminal or via IDE GUI buttons (Cursor / VS Code) bypasses the agent lease and routes directly to your personal signing program (1Password Touch ID / YubiKey / GPG).
> - **Zero Blast Radius**: The agent's dedicated sub-key is added to GitHub/GitLab strictly as an SSH *Signing Key*. It has zero permission to clone repositories, push remotes, or SSH into servers.
>
> It installs in one command:
> `curl -fsSL https://raw.githubusercontent.com/taylor-made-labs/agent-sign/main/scripts/install.sh | bash`
>
> Code & Architecture: https://github.com/taylor-made-labs/agent-sign  
>
> Would love your feedback on the daemon protocol, token multiplexing, and attribution modes!

---

## 2. Cursor Forum / Community Post

**Target**: [forum.cursor.com](https://forum.cursor.com) (Category: Showcase / Tips & Tricks)  
**Title**: Solving 1Password Touch ID fatigue & DevContainer GPG errors when Cursor Agent commits

### Post Body:

> If you use Cursor Agent with Git commit signing enabled (especially with 1Password Touch ID, YubiKeys, or inside DevContainers), you've probably hit one of two walls:
> 1. Cursor Agent prompts you for Touch ID / 1Password on every incremental step, completely halting autonomous flow.
> 2. Inside DevContainers, GPG keys and SSH agents don't forward cleanly, resulting in `gpg failed to sign the data` errors.
>
> We built an open-source Rust tool called **agent-sign** (https://github.com/taylor-made-labs/agent-sign).
>
> It intercepts agent Git commands via a deterministic shim, prompts you **once** for a 2-hour session lease, and signs all agent commits in milliseconds with a scoped SSH signing key that displays the green "Verified" badge on GitHub.
>
> If you make a commit yourself by clicking "Commit" in Cursor's Source Control sidebar or typing `git commit` in your own terminal, it routes right back to your personal 1Password Touch ID or hardware key.
>
> Works out of the box with Cursor: `install.sh` automatically configures Cursor's `terminal.integrated.env` settings.
>
> Repo: https://github.com/taylor-made-labs/agent-sign

---

## 3. Anthropic Claude Code Discussion Reference

**Target**: `anthropics/claude-code` GitHub Issues (e.g. issues tagged with `git`, `gpg`, or `signing`)

### Response Template:

> If you are running into `pinentry` terminal freezes, TUI flickering, or repeated 1Password biometric modal interrupts when Claude Code runs `git commit`, we built a local multiplexer specifically for this:
>
> **agent-sign**: https://github.com/taylor-made-labs/agent-sign
>
> Instead of disabling signing (`--no-gpg-sign`), it grants Claude a scoped session lease (1 prompt per 2 hours) and headlessly signs commits with an isolated SSH sub-key while preserving your personal signing key for human terminal work. It installs via:
> ```bash
> curl -fsSL https://raw.githubusercontent.com/taylor-made-labs/agent-sign/main/scripts/install.sh | bash
> ```
