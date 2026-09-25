# Integrating Agent-Sign with Claude Code

[Claude Code](https://docs.anthropic.com/en/docs/agents-and-tools/claude-code) executes shell commands and git commits via its built-in tool execution runtime.

---

## 1. Quick Setup

Once `agent-sign` is installed on your machine (`~/.agent-sign/bin/`):

### Option A: Per-Session Wrapper (Recommended)
Launch Claude Code with `~/.agent-sign/bin` prepended to its PATH:

```bash
PATH="$HOME/.agent-sign/bin:$PATH" claude
```

You can create a convenient shell alias in `~/.zshrc` or `~/.bashrc`:

```bash
alias claude-agent="PATH=\"$HOME/.agent-sign/bin:\$PATH\" claude"
```

### Option B: Tool Environment Injection
If using Claude Code configuration, you can configure your environment to inject `~/.agent-sign/bin` into child tool processes.

---

## 2. What Happens During Execution

1. When Claude decides to commit (`git commit -m "feat: implement auth"`):
   - Claude's tool runner calls `git`, which resolves to `~/.agent-sign/bin/git`.
   - `agent-git` inspects the command and contacts `agent-signd`.
2. **First Commit of Session**:
   - A single Touch ID / macOS prompt appears: *"AI Agent requesting commit signing lease for 2 hours."*
   - You tap Touch ID once.
3. **Subsequent Commits**:
   - Claude makes 10, 20, or 50 incremental commits headlessly.
   - Zero interruptions, zero prompts.
   - Every commit is signed with the dedicated Agent Sub-Key and displays the green "Verified" badge on GitHub.
4. **Your Terminal**:
   - Running `git commit` in your normal terminal uses your normal 1Password key with standard Touch ID.
