# Integrating Agent-Sign with Aider

[Aider](https://aider.chat) automatically creates Git commits after editing files.

---

## 1. Zero-Config Setup

When you run `./scripts/install.sh`, `agent-sign` is automatically added to your shell profile (`~/.zshrc`, `~/.zprofile`, `~/.bashrc`).

Because Aider is launched from your shell terminal, it inherits `PATH` automatically:

```bash
aider
```

**Zero wrappers, zero aliases required.**

---

## 2. Benefits for Aider Users

* **No More Prompt Hell**: Aider commits rapidly after every file edit. Under hardware-backed keys or 1Password, this would normally mean an interrupt every 30 seconds.
* **One-Touch Session Leasing**: You approve the session lease **once** (desktop dialog or terminal prompt) when Aider makes its first commit, and all subsequent incremental commits during that window (default 2 hours) sign headlessly in milliseconds.
* **100% Cryptographic Verification**: Commits are signed with your dedicated Agent Sub-Key and earn the green "Verified" badge on GitHub/GitLab.
* **Protected Personal Key**: Aider never accesses your personal private key, hardware token, or 1Password vault.
