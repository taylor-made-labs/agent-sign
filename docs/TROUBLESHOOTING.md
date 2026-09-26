# Agent-Sign: Troubleshooting & Environmental Edge Cases

This guide provides tested, step-by-step solutions for common edge cases across different operating systems, security hardware, secret managers, and container runtimes.

---

## 1. Quick Diagnostics (`agent-sign doctor`)

Whenever you experience unexpected signing behavior, run the built-in diagnostic tool first:
```bash
~/.agent-sign/bin/agent-sign doctor
```
This tests:
- Git configuration (`gpg.format == ssh`, `gpg.ssh.program`)
- Fallback signer binary path (1Password, ssh-keygen, GPG)
- Agent cryptographic keypair permissions
- Local `allowed_signers` registration
- Daemon socket communication (`~/.agent-sign/daemon.sock`)
- GitHub CLI key status (`gh ssh-key list`)

---

## 2. 1Password & Touch ID (macOS & Windows/WSL)

### Issue: "1Password prompt appears on every agent commit"
- **Cause**: The agent is executing `git` directly from the system `PATH` instead of through `~/.agent-sign/bin/git`.
- **Solution**:
  Verify that `~/.agent-sign/bin` is at the beginning of your shell `PATH`:
  ```bash
  which git
  # Expected: ~/.agent-sign/bin/git
  ```
  If not, run `source ~/.zshrc` or restart your terminal.

### Issue: "op-ssh-sign: could not connect to 1Password agent"
- **Cause**: 1Password SSH Agent is not enabled in 1Password app settings.
- **Solution**:
  1. Open **1Password → Settings → Developer**.
  2. Ensure **"Use the SSH agent"** is checked.
  3. Ensure **"Integrate with 1Password CLI"** is enabled.

---

## 3. Physical Hardware Security Keys (YubiKey / FIDO2)

### Issue: "YubiKey requires touch for every agent commit"
- **Cause**: Your personal signing key has FIDO2 `touch-policy=always` or GPG `Signature PIN = forced`.
- **Solution**:
  `agent-sign` provides dedicated sub-key delegation specifically to resolve this:
  1. The YubiKey is only touched when you initiate personal commits from your terminal or IDE GUI.
  2. The agent uses its dedicated `agent_ed25519` sub-key during its authorized 2-hour session lease, requiring zero physical touches on incremental agent commits.
  3. Ensure your human fallback in `~/.agent-sign/config.toml` points to your standard key or GPG:
     ```toml
     [ssh]
     fallback_program = "/usr/bin/ssh-keygen"
     ```

---

## 4. Linux Desktop & Window Managers (Wayland / i3 / Sway)

### Issue: "No prompt appears when the agent requests a lease"
- **Cause**: Neither `zenity` nor `kdialog` is installed in headless or minimal window manager environments.
- **Solution**:
  - Install `zenity`:
    - Ubuntu/Debian: `sudo apt-get install zenity`
    - Arch Linux: `sudo pacman -S zenity`
    - Fedora: `sudo dnf install zenity`
  - Or run the agent in an interactive terminal where standard TTY prompt `[y/N]` is supported automatically.

---

## 5. DevContainers, Docker & Headless CI

### Issue: "GUI dialog cannot open inside container"
- **Solution**:
  In headless environments or automated CI pipelines, activate headless auto-approval:
  ```bash
  export AGENT_SIGN_AUTO_APPROVE=1
  ```
  Or set it in your container's `.agent-sign.toml`:
  ```toml
  [security]
  auto_approve = true
  ```

---

## 6. Enterprise Guardrail Violations

### Issue: "Agent commit touches forbidden path matching rule"
- **Cause**: The agent attempted to commit changes to a protected security path (e.g. `.github/workflows/`, `terraform/`, `*.pem`, `*.key`).
- **Solution**:
  - If the commit was intentional, commit it yourself from your interactive terminal shell (bypassing agent interception).
  - To adjust the forbidden paths for your repository, add an exception in `.agent-sign.toml`:
    ```toml
    [security]
    forbidden_paths = ["*.pem", "*.key"]  # Allow workflows in this repository
    ```

### Issue: "Agent commit diff exceeds safety circuit breaker"
- **Cause**: The agent changed more than `max_diff_lines` (default 2,000 lines) in a single atomic commit.
- **Solution**:
  - Run with `AGENT_SIGN_ALLOW_LARGE_DIFF=1 git commit ...`
  - Or increase the threshold in `~/.agent-sign/config.toml`:
    ```toml
    [security]
    max_diff_lines = 5000
    ```
