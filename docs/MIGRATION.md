# Upgrading, and what changed since the first agent-sign

## How to upgrade

Run the installer from the new version, as for a new install (see
[INSTALL.md](INSTALL.md)). It installs over the existing one: the same
`~/.agent-sign` directory, the same service (`com.agentsign.agent-signd` on
macOS, `agent-signd.service` on Linux), and the same `# >>> agent-sign >>>`
`PATH` block. Your config and leases are kept.

Open a new terminal afterwards, and run `agent-sign doctor`.

## What changed since the first agent-sign (September 2026)

- **No private key is stored, and your own signing goes through
  agent-sign** (follow-up round, 28 Oct 2026). Taylor's standing rule: keys
  are never stored unprotected; they live in OpenBao, a hardware or OS
  keystore, or only in a running program's memory. So:
  - The agents' certificate authority is made in the service's memory each
    time it starts and never written anywhere. Each start adds its public
    key, with the date, to `~/.agent-sign/keys/agents_cas.pub`, and
    `agent-sign trust-line` prints one line per authority there, so commits
    certified before a restart still verify.
  - The installer keeps those lines in a marked block of your
    allowed-signers file (between `# agent-sign: agents' certificate
    authorities, managed; do not edit` and its end line), and the service
    rewrites that block, and nothing else, each time it starts. The bare
    trust line an earlier build added moves into the block.
  - Private keys earlier versions stored in plain files are deleted by the
    installer, after its usual question: the authority key an earlier build
    of this change kept (`keys/agents_ca_ed25519`; the service refuses to
    start while it's there), and the old shared agent key's private half
    (`keys/agent_ed25519`, and any copy moved to `keys/retired/`). Their
    public halves stay, so what they signed still verifies.
  - The installer sets your global `gpg.ssh.program` to
    `~/.agent-sign/bin/agent-ssh-sign` and keeps what it was (or
    `ssh-keygen`, git's default) as `fallback_program`, so a signing request
    from an agent's process is refused even outside the wrapper.
    `uninstall.sh` puts it back. `agent-sign doctor` says whether it's in
    place. It covers SSH signing only.
  - An unmarked commit with no terminal that asks to be signed (`-S`, your
    `commit.gpgsign = true`) is made unsigned, with one line saying why,
    instead of failing.
  - A repository's `.agent-sign.toml` can no longer lower
    `max_commits_per_minute`: the service counts the rate and reads only
    your config, so it's ignored with the same warning as other keys.

- **Every agent signs as itself** (28 Oct 2026). Agents no longer share one
  key listed under your email: the service creates an agents' certificate
  authority, gives each agent session its own key (in memory only) with a
  certificate for its principal (`claude-code.1a2b3c4d@agents.local`), and
  makes the agent both author and committer in every attribution mode
  (`[attribution] mode = "agent"` is the new default; the installer
  switches a config still on the old `"split"` default). Agent commits need
  no approval by default (`approval = "device-owner"` brings the Touch ID
  prompt back). The installer adds `agent-sign trust-line`'s lines to your
  allowed-signers file;
  remove the old agent key's line (under your email) and the key on your
  GitHub account yourself, since they made agent commits verify as yours.
- **The identity review's fixes** (28 Oct 2026). The installer took the old
  shared agent key's private half out of use (the follow-up round deletes
  it) and prints the commands to remove its trust (it runs neither). A commit with no terminal and no
  agent mark is left to git, unsigned, instead of being signed as an
  "unidentified agent": name an unmarked agent with `AGENT_SIGN_AGENT_NAME`.
  A repository's `.agent-sign.toml` can only tighten the rules. Agent
  commits are the agent's in every attribution mode. The service refuses
  to start on a `config.toml` it can't read or with a key it doesn't know
  (every key an earlier installer wrote is accepted). Tokens sign only in
  their own repository and branch, every signature counts against the rate
  limit, and `MAIN` is as protected as `main`.

- **A separate signing program.** git now calls `agent-ssh-sign` (named like
  1Password's `op-ssh-sign`) to sign. `agent-sign` still accepts git's
  signing arguments, so a `gpg.ssh.program` that names it keeps working, and
  signatures are the same byte for byte (`tests/test_signature_equivalence.rs`).
- **Leases are saved and their terms fixed.** Approvals survive a restart,
  crash or sleep. What a lease covers and when it ends never grow; config
  changes can only narrow them.
- **One approval covers one branch of one repository** (19 Oct 2026). Earlier
  builds had you pick, in a dialog, this repository, every repository under
  its folder, or every repository, and covered all of a repository's branches
  by default. Now the approval is one Touch ID prompt that says the branch and
  repository, the lease covers just that (`allow_branch_switching` is off by
  default; turn it on to cover the repository's other unprotected branches),
  and leases of the wider kinds approved earlier still work and can be
  revoked.
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
