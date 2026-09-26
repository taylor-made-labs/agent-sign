# Integrating Agent-Sign with Cursor

Cursor's Agent Mode executes terminal tools and git operations within workspace sessions.

---

## 1. Automated Setup

When you run `./scripts/install.sh`, the installer detects your Cursor installation and automatically adds the environment path configuration to `settings.json`.

**No manual edits required.**

### Reference Configuration (Applied Automatically)
For reference, the installer adds this to `settings.json`:
```json
{
  "terminal.integrated.env.osx": {
    "PATH": "${env:HOME}/.agent-sign/bin:${env:PATH}"
  },
  "terminal.integrated.env.linux": {
    "PATH": "${env:HOME}/.agent-sign/bin:${env:PATH}"
  }
}
```

---

## 2. The Critical Invariant: 100% Human Isolation

One of the foundational innovations of `Agent-Sign` is protecting human commits whether in the GUI or terminal:

* **When Cursor's Agent commits**: Cursor's tool execution environment runs `git commit` non-interactively via piped stdio. The command hits `~/.agent-sign/bin/git`, requests an event token from `agent-signd`, and signs headlessly with the Agent Sub-Key.
* **When YOU commit in Cursor's Source Control sidebar**: The VS Code / Cursor GUI button invokes the internal Git extension. Because it does not run through the agent event ticket workflow, `agent-sign` delegates directly to your personal signing agent (1Password, YubiKey, GPG, or standard ssh-keygen).
* **When YOU type `git commit` in Cursor's integrated terminal**: Because an interactive terminal has an active TTY attached (`is_terminal()`), `agent-git` detects human interactive usage and passes directly to your standard Git toolchain. Your manual commits are never falsely attributed to the AI.
