# Integrating Agent-Sign with Cursor

Cursor's Agent Mode executes terminal tools and git operations within workspace sessions.

---

## 1. Setup in Cursor

### Terminal Settings Configuration
To ensure Cursor's terminal agent inherits the `agent-sign` binaries, add `~/.agent-sign/bin` to Cursor's integrated terminal environment settings:

In Cursor `settings.json`:
```json
{
  "terminal.integrated.env.osx": {
    "PATH": "${env:HOME}/.agent-sign/bin:${env:PATH}"
  }
}
```

---

## 2. The Critical Invariant: Human IDE GUI Isolation

One of the foundational innovations of `Agent-Sign` is protecting human GUI commits:

* **When Cursor's Agent commits**: The agent runs `git commit` in its terminal environment. The command hits `~/.agent-sign/bin/git`, requests an event token from `agent-signd`, and signs headlessly with the Agent Sub-Key.
* **When YOU commit in Cursor's Source Control sidebar**: The VS Code / Cursor GUI button invokes the internal Git extension. Because it does not run through the agent event ticket workflow, `agent-sign` multiplexes the signature directly to your 1Password Touch ID agent. Your personal commits are never falsely attributed to the AI.
