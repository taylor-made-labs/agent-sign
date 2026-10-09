# Upgrading, and what changed since the first agent-sign

## How to upgrade

Run the installer from the new version, as for a new install (see
[INSTALL.md](INSTALL.md)). It installs over the existing one: the same
`~/.agent-sign` directory, the same service (`com.agentsign.agent-signd` on
macOS, `agent-signd.service` on Linux), and the same `# >>> agent-sign >>>`
`PATH` block. Your agent key and config are kept, so GitHub's registered
signing key and your `allowed_signers` line stay valid. Leases you've
approved are kept too.

Open a new terminal afterwards, and run `agent-sign doctor`.

## What changed since the first agent-sign (September 2026)

- **A separate signing program.** git now calls `agent-ssh-sign` (named like
  1Password's `op-ssh-sign`) to sign. `agent-sign` still accepts git's
  signing arguments, so a `gpg.ssh.program` that names it keeps working, and
  signatures are the same byte for byte (`tests/test_signature_equivalence.rs`).
- **Leases are saved and their terms fixed.** Approvals survive a restart,
  crash or sleep. What a lease covers and when it ends are shown before you
  approve, and never grow; config changes can only narrow them.
- **You choose what one approval covers:** this repository, every repository
  under its folder, or every repository.
- **Commits name the agent** that made them, when it marks its commands
  (Claude Code, Gemini CLI, Codex) or is started with
  `AGENT_SIGN_AGENT_NAME`. An agent that marks its commands is treated as an
  agent even in a terminal.
- **Clearer refusals:** "couldn't ask you" is no longer reported as a denial,
  `revoke` reports when nothing matched, and a commit during a service
  restart waits for it briefly instead of failing.
- **The installer asks first:** it lists every change before making any, and
  adds the agent key to your GitHub account only if you say yes.
- **The license** is MIT OR Apache-2.0 (it was MIT).

## If something goes wrong

`agent-sign doctor` checks every piece and says how to fix what's wrong.
[TROUBLESHOOTING.md](TROUBLESHOOTING.md) lists each refusal message with
its cause.
