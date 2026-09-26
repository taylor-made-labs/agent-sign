# Integrating Agent-Sign with Google Antigravity & Gemini CLI

Antigravity executes commands via its agentic `run_command` tool runner.

---

## 1. Automated Setup

`agent-sign` provides zero-friction compatibility with Google Antigravity & Gemini CLI.

When you run `./scripts/install.sh`, it automatically:
1. Adds `~/.agent-sign/bin` to your shell profile (`~/.zshrc` / `~/.zprofile`), which Antigravity's `run_command` tool runner uses.
2. Creates an agent rule in `~/.gemini/config/rules/agent-sign.md` that informs the agent that git commits are autonomously signed and attributed.

**Zero wrappers or aliases required.** Launch Antigravity normally:
```bash
agy
```

---

## 2. Behavior Under Antigravity

* When the agent runs `run_command` with `git commit`:
  1. `~/.agent-sign/bin/git` intercepts the call.
  2. If the session lease has not been granted, you are prompted to approve the lease once.
  3. Once approved, Antigravity executes all subsequent commits headlessly throughout the session.
  4. Commits are signed with the dedicated Agent Sub-Key, earning green "Verified" badges on GitHub/GitLab.
