# Integrating Agent-Sign with Aider

[Aider](https://aider.chat) automatically creates Git commits after editing files.

---

## 1. Setup

Launch Aider with `~/.agent-sign/bin` prepended to PATH:

```bash
PATH="$HOME/.agent-sign/bin:$PATH" aider
```

Or configure an alias in your shell:
```bash
alias aider-sign='PATH="$HOME/.agent-sign/bin:$PATH" aider'
```

---

## 2. Benefits for Aider Users

* Aider commits rapidly after every file edit. Under normal 1Password configurations, this means a Touch ID popup every 30 seconds.
* With `agent-sign`, you approve Touch ID **once** when Aider starts, and all subsequent incremental commits during that 2-hour window sign silently with green verified badges on GitHub.
