# Installing agent-sign

agent-sign runs on macOS (as a launchd user agent) and on Linux (as a systemd user
service). There are no prebuilt releases yet, so you build it from source.

## What you need

- macOS, or Linux with systemd (x86_64 or ARM64, such as a Raspberry Pi 5)
- Rust 1.88 or newer (install from https://rustup.rs). agent-sign is checked with
  1.93 and 1.98.
- git 2.34 or newer (SSH commit signing), and `ssh-keygen` (git uses it to
  verify SSH signatures). On macOS both come with the Xcode command line
  tools (`xcode-select --install`), as does `python3`.
- `python3` (the installer uses it to update editor settings)
- Only if you turn on `approval = "device-owner"` (agent commits need no
  approval by default): on macOS a desktop session, and Touch ID or a login
  password; Linux has no way to approve a lease yet (see
  [Headless machines](#headless-machines-servers-containers-ci)).

## Install

```sh
git clone https://github.com/taylor-made-labs/agent-sign.git
cd agent-sign
cargo build --release --locked
./scripts/install.sh
```

Build first: the installer uses `target/release/` when it's there. If you
skip the build, the installer still works: it tries to download a release
(there isn't one yet; it says so and moves on) and then builds with Cargo
itself.

Where things go: everything is in `~/.agent-sign` (the programs, the
agents' certificate authority, the config, leases and the service's socket).
Installing over an existing install keeps its keys and leases; see
[Upgrading](#upgrading).

Then open a new terminal (the installer changes your shell's `PATH`) and run:

```sh
agent-sign doctor
```

It checks every piece and says how to fix anything that's wrong.

To see it work end to end, run `./scripts/demo-sandbox.sh` from the `agent-sign`
directory. It makes two signed agent commits in a throwaway repository
(with `approval = "device-owner"` you'll see the Touch ID or password prompt once), shows one refused by a local rule, then
deletes the repository and revokes its lease.

When you try it in your own repository, have the agent work on a branch
other than `main` or `master`: agents never commit on those, so an agent
can't make the first commit of a brand-new repository on `main`.

## What the installer changes

Read this before you run it; at a terminal, the installer lists these
changes and asks before making any (`--yes`, or no terminal, goes ahead).
`./scripts/uninstall.sh` undoes each change, except the global
`gpg.ssh.allowedSignersFile` setting, as noted below.

| Where | What |
|---|---|
| `~/.agent-sign/bin` | The programs: `agent-signd`, `agent-sign`, `agent-ssh-sign`, `agent-git`, and a copy of `agent-git` named `git`. |
| `~/.agent-sign/agent-sign.app` | macOS only. A tiny app bundle holding a copy of `agent-signd` and an `Info.plist` that names it "agent-sign". The service runs from here, so the Touch ID prompt says "agent-sign is trying to ..." instead of "agent-signd is trying to ...". It is signed ad hoc (no developer account), and rebuilt each time you run the installer, so after `brew upgrade` run the installer again to refresh it. |
| `~/.agent-sign/keys` | Public keys only. The agents' certificate authority is made in the service's memory each time it starts and never written anywhere; each start adds its public key, with the date, to `agents_cas.pub`. Private keys earlier versions stored here unprotected (`agents_ca_ed25519`, the old shared `agent_ed25519`, and copies in `retired/`) are deleted; their public halves stay. |
| `~/.agent-sign/config.toml` | Settings. Only written if missing; on an install over an existing one, only `fallback_program` (below) and an old `"split"` default are changed. |
| Your global `gpg.ssh.program` | Set to `~/.agent-sign/bin/agent-ssh-sign`, so your own SSH signing goes through agent-sign: your signatures go on to your signer, and a request from an agent's process is refused. What it was (or `ssh-keygen`, git's default, if unset) becomes `fallback_program` in `config.toml`; the uninstaller puts it back. If it already is `agent-ssh-sign`, the existing `fallback_program` is kept. |
| git's `allowed_signers` file (the list of SSH keys git trusts when it checks signatures) | A marked block, between `# agent-sign: agents' certificate authorities, managed; do not edit` and its end line, holding `agent-sign trust-line`'s lines: they trust the agents' certificate authorities for `*@agents.local` principals and git signatures only. The service rewrites the block, and nothing outside it, each time it starts. An earlier version's bare trust line moves into the block. (And `gpg.ssh.allowedSignersFile` is set globally, to `~/.config/git/allowed_signers`, if it wasn't set; the uninstaller leaves that setting.) This is what makes `git log --show-signature` report each agent commit as good **for that agent**, never for you. |
| launchd or systemd | A user service that runs `agent-signd` and restarts it if it stops (on macOS the copy in `agent-sign.app`; `~/Library/LaunchAgents/com.agentsign.agent-signd.plist`, or `~/.config/systemd/user/agent-signd.service`). Before installing it, the installer stops a service installed earlier, and any `agent-signd` or `agent-signd` process of yours started by hand. |
| `~/.zshrc`, `~/.zprofile`, `~/.bashrc`, `~/.bash_profile` | A marked block putting `~/.agent-sign/bin` first on `PATH` (once), in each of these files that exists, so every program started from your shell, agents included, gets the wrapper as `git`. |
| Cursor, VS Code and Windsurf `settings.json` | The same `PATH` for their built-in terminals, if those editors are installed. |
| `~/.gemini/config/rules/agent-sign.md` | A rule for Google Antigravity, if it's installed. |

Two consequences worth knowing:

- Each agent signs, authors and commits as its own identity (such as
  `Claude Code <claude-code.1a2b3c4d@agents.local>`), never as you. GitHub
  doesn't check signatures made with SSH certificates, so agent commits show
  there as Unverified. The identities are claims made by programs running
  as your user: attribution, not a security boundary.
- Editors that read your login shell's `PATH` (VS Code on macOS does) may
  run the wrapper for their own commit button. With no terminal attached and
  no agent mark, the wrapper leaves that commit to git: unsigned, under your
  git name, never attributed to an agent (point the editor's `git.path` at
  your real git to have it signed with your own key).
- On an upgrade, the installer deletes the old shared agent key's private
  half (it was stored unprotected) and, while its line is still in your
  allowed-signers file, prints the commands to remove that line and its
  GitHub signing key; it runs neither.

## Headless machines (servers, containers, CI)

With no screen, `agent-signd` can't ask you (it runs in the background, so a
terminal you're logged in to over SSH doesn't help), so it refuses new
leases (failing closed), and the agent sees "agent-sign couldn't ask you to
approve a lease". **Linux machines are in the same position**: Linux has no platform
authenticator in agent-sign yet, and the two ways it could ask anyway both let
an agent approve for itself (a dialog any program can click, and a terminal
prompt an agent can drive through its own pseudo-terminal or by typing into
yours). So the service refuses every new lease there. (Earlier builds showed a
`zenity` or `kdialog` dialog or a terminal prompt; both were removed for this
reason.) To use agent-sign anyway, turn on auto-approval, which grants every
lease without asking. Use it only where every process that can reach the
service is trusted.

1. In `~/.agent-sign/config.toml`, under `[security]`, set `auto_approve = true`. A repository's `.agent-sign.toml`
   can't turn it on.
2. Restart the service, which reads its config only when it starts:
   `systemctl --user restart agent-signd` on Linux, or
   `launchctl kickstart -k gui/$(id -u)/com.agentsign.agent-signd` on macOS.

Alternatively, set `AGENT_SIGN_AUTO_APPROVE=1` in the service's environment
(`systemctl --user edit agent-signd`), or run `agent-signd --auto-approve` yourself.

On Linux, a user service stops when you log out unless lingering is on:
`loginctl enable-linger "$USER"` (some systems allow this only for an
administrator). Approving from another device, such as a passkey on your
phone, is planned (it belongs to the agentic-credentials work), not built.

## Checking an agent commit

```sh
git log -1 --format='%an <%ae> | %cn <%ce> | %G?'
git verify-commit HEAD
```

`%G?` prints `G` for a good signature.

## Uninstall

```sh
./scripts/uninstall.sh
```

This stops and removes the service, removes the `PATH` blocks and editor
settings, removes agent-sign's lines from `allowed_signers` (the agents'
trust line, and an earlier version's agent key), and deletes
`~/.agent-sign`, including the agents' certificate authority and all leases
(if it's a link to a folder kept elsewhere, only the link is removed).
It leaves git's global `gpg.ssh.allowedSignersFile` setting (unset it with
`git config --global --unset gpg.ssh.allowedSignersFile` if nothing else uses
it). If an earlier version added the shared agent key to your GitHub account,
remove it there (Settings, SSH and GPG keys) yourself.

## Not ready yet

- **Prebuilt releases.** `.github/workflows/release.yml` packages only three of the
  four programs and has no Linux ARM64 build; the fix,
  `docs/release/ci-workflows.patch`, is waiting to be applied (see
  [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md)). Until then, build from
  source as above.
- **Homebrew.** `Formula/agent-sign.rb` installs from those releases, so
  it can't be used until the first one is published, and it isn't in a tap
  yet. After `brew install`, its caveats give the one command that finishes
  setup (`install.sh --from-homebrew`).

## Upgrading

Run the installer again from the new version. The key, leases and config
carry over, with no new approval. [MIGRATION.md](MIGRATION.md) lists what
changed since the first agent-sign.

## Source and release selection after the October 29 review

From a source checkout the installer rebuilds that source with Cargo, even when
old release programs exist. A missing toolchain or failed build stops it; there
is no automatic release download. To install a reviewed archive, run a separately
reviewed installer with `--archive FILE --sha256 DIGEST`. Obtain DIGEST through
your independent review/trusted channel before running it: this option checks
bytes, not the trustworthiness of whoever supplied the digest. It checks the
archive before extraction. An already unpacked binary folder is not accepted as
source. An explicitly selected Homebrew prefix retains package-manager trust.
See the [repair record](security-review-2026-10-29.md) for the isolated Linux
validation, exact source hashes and remaining host assumptions.
