# Integrating Agent-Sign with Claude Code

[Claude Code](https://docs.anthropic.com/en/docs/agents-and-tools/claude-code) executes shell commands and git commits via its built-in tool execution runtime.

---

## 1. Zero-Config Setup

When you run `./scripts/install.sh`, `agent-sign` is automatically added to your shell profile (`~/.zshrc`, `~/.zprofile`, `~/.bashrc`).

Because Claude Code is launched from your shell terminal, it inherits `PATH` automatically:

```bash
claude
```

**Zero wrappers, zero aliases, zero environment variables required.**

Whenever Claude Code invokes `git commit`, `~/.agent-sign/bin/git` intercepts the call and coordinates with `agent-signd`.

---

## 2. What Happens During Execution

1. When Claude decides to commit (`git commit -m "feat: implement auth"`):
   - Claude's tool runner calls `git`, which resolves to `~/.agent-sign/bin/git`.
   - `agent-git` inspects the command and contacts `agent-signd`.
2. **First Commit of Session**:
   - A single confirmation prompt appears (macOS dialog, Linux desktop GUI, or interactive terminal prompt): *"AI Agent requesting commit signing lease for 2 hours."*
   - You approve the session lease once.
3. **Subsequent Commits**:
   - Claude makes 10, 20, or 50 incremental commits headlessly.
   - Zero interruptions, zero prompts.
   - Every commit is signed with the dedicated Agent Sub-Key and displays the green "Verified" badge on GitHub/GitLab.
4. **Your Terminal**:
   - Running `git commit` in your normal interactive terminal uses your personal signing key (1Password, YubiKey, GPG, or OpenSSH) as normal.
