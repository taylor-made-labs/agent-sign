# Integrating Agent-Sign with Google Antigravity & Gemini CLI

Antigravity executes commands via its agentic `run_command` tool runner.

---

## 1. Setup

`agent-sign` provides zero-friction compatibility with Antigravity:

Prepend `~/.agent-sign/bin` to your environment path before starting an Antigravity agent session, or set it in your workspace configuration:

```bash
PATH="$HOME/.agent-sign/bin:$PATH" agy
```

---

## 2. Behavior Under Antigravity

* When the agent runs `run_command` with `git commit`:
  1. `~/.agent-sign/bin/git` intercepts the call.
  2. If the 2-hour session lease has not been granted, macOS prompts for Touch ID approval once.
  3. Once approved, Antigravity executes all subsequent commits headlessly throughout the session.
  4. Commits are signed with the dedicated Agent Sub-Key, earning green "Verified" badges on GitHub.
