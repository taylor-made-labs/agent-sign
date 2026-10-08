# Installing agent-commits

agent-commits runs on macOS (as a launchd user agent) and on Linux (as a systemd user
service). There are no prebuilt releases yet, so you build it from source.

## What you need

- macOS, or Linux with systemd (x86_64 or ARM64, such as a Raspberry Pi 5)
- Rust 1.88 or newer (install from https://rustup.rs). agent-commits is checked with
  1.93 and 1.98.
- git 2.34 or newer (SSH commit signing), and `ssh-keygen` (git uses it to
  verify SSH signatures). On macOS both come with the Xcode command line
  tools (`xcode-select --install`), as does `python3`.
- `python3` (the installer uses it to update editor settings)
- On Linux, for the approval dialog: a desktop session and `zenity` or
  `kdialog`. Without them, see [Headless machines](#headless-machines-servers-containers-ci).
- Optional: the GitHub CLI (`gh`), logged in, so the installer can register
  the agent's signing key on your account

## Install

```sh
git clone https://github.com/taylor-made-labs/agent-commits.git
cd agent-commits
cargo build --release --locked
./scripts/install.sh
```

Build first: the installer uses `target/release/` when it's there. If you
skip the build, the installer still works: it tries to download a release
(there isn't one yet; it says so and moves on) and then builds with Cargo
itself.

Where things go: everything is in `~/.agent-commits` (the programs, the
agent key, the config, leases and the service's socket). An agent-sign
install is moved there first, keeping its key and leases; see
[Upgrading from agent-sign](#upgrading-from-agent-sign).

Then open a new terminal (the installer changes your shell's `PATH`) and run:

```sh
agent-commits doctor
```

It checks every piece and says how to fix anything that's wrong.

To see it work end to end, run `./scripts/demo-sandbox.sh` from the `agent-commits`
directory. It makes two signed agent commits in a throwaway repository
(you'll see the lease dialog once), shows one refused by a local rule, then
deletes the repository and revokes its lease.

When you try it in your own repository, have the agent work on a branch
other than `main` or `master`: agents never commit on those, so an agent
can't make the first commit of a brand-new repository on `main`.

## What the installer changes

Read this before you run it. `./scripts/uninstall.sh` undoes each change,
except the global `gpg.ssh.allowedSignersFile` setting and your GitHub
account's key, as noted below.

| Where | What |
|---|---|
| `~/.agent-commits/bin` | The programs: `agent-commitsd`, `agent-commits`, `agent-commits-ssh-sign`, `agent-commits-git`, a copy of `agent-commits-git` named `git`, and agent-sign's old names as links. |
| `~/.agent-commits/keys` | A new ed25519 key for the agent, readable only by your user (and so by any agent running as you). It is not encrypted. |
| `~/.agent-commits/config.toml` | Settings, with your existing SSH signing program detected (git's `gpg.ssh.program`, 1Password's `op-ssh-sign`, or `ssh-keygen`). Only written if missing. |
| git's `allowed_signers` file (the list of SSH keys git trusts when it checks signatures) | One line with the agent's public key, **under your git email** (and `gpg.ssh.allowedSignersFile` set globally, to `~/.config/git/allowed_signers`, if it wasn't set; the uninstaller leaves that setting). This is what makes `git log --show-signature` report agent commits as good, and it attributes them to you. |
| launchd or systemd | A user service that runs `agent-commitsd` and restarts it if it stops (`~/Library/LaunchAgents/com.agentcommits.agent-commitsd.plist`, or `~/.config/systemd/user/agent-commitsd.service`). Before installing it, the installer stops a service installed earlier (removing agent-sign's, if it's there), and any `agent-signd` or `agent-commitsd` process of yours started by hand. |
| `~/.zshrc`, `~/.zprofile`, `~/.bashrc`, `~/.bash_profile` | A marked block putting `~/.agent-commits/bin` first on `PATH` (replacing agent-sign's block, if there is one), in each of these files that exists, so every program started from your shell, agents included, gets the wrapper as `git`. |
| Cursor, VS Code and Windsurf `settings.json` | The same `PATH` for their built-in terminals, if those editors are installed. |
| `~/.gemini/config/rules/agent-commits.md` | A rule for Google Antigravity, if it's installed. |
| Your GitHub account | Only if you say yes: with `gh` logged in and you at the terminal, the installer asks whether to add the agent's public key to your account as a **signing key** (it can't be used to log in or push). Otherwise, or if you say no, the public key is printed (and copied to your clipboard, on a desktop) and GitHub's settings page is opened when there's a browser, for you to add it yourself. |

Two consequences worth knowing:

- Because the agent key is registered under your email and on your GitHub
  account, and you're the committer in the default `split` attribution mode
  (the agent is the author, you're the committer), GitHub shows agent commits
  as Verified for you. agent-commits' aim is attribution
  to the agent's own identity; that isn't built yet.
- Editors that read your login shell's `PATH` (VS Code on macOS does) may
  run the wrapper for their own commit button. With no terminal attached,
  the wrapper treats that commit as an agent's, and asks for a lease.

## Headless machines (servers, containers, CI)

With no screen, `agent-commitsd` can't ask you (it runs in the background, so a
terminal you're logged in to over SSH doesn't help), so it refuses new
leases (failing closed), and the agent sees "agent-commits couldn't ask you to
approve a lease". To use agent-commits anyway, turn on auto-approval, which grants
every lease without asking. Use it only where every process that can reach
the service is trusted.

1. In `~/.agent-commits/config.toml`, under `[security]`, set `auto_approve = true`. A repository's `.agent-commits.toml`
   can't turn it on.
2. Restart the service, which reads its config only when it starts:
   `systemctl --user restart agent-commitsd` on Linux, or
   `launchctl kickstart -k gui/$(id -u)/com.agentcommits.agent-commitsd` on macOS.

Alternatively, set `AGENT_COMMITS_AUTO_APPROVE=1` in the service's environment
(`systemctl --user edit agent-commitsd`), or run `agent-commitsd --auto-approve` yourself.

On Linux, a user service stops when you log out unless lingering is on:
`loginctl enable-linger "$USER"` (some systems allow this only for an
administrator). Approving from another device is planned, not built.

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
settings, removes the agent key's line from `allowed_signers`, and deletes
`~/.agent-commits` and `~/.agent-sign`, including the agent key and all leases.
It leaves git's global `gpg.ssh.allowedSignersFile` setting (unset it with
`git config --global --unset gpg.ssh.allowedSignersFile` if nothing else uses
it). Remove the key from GitHub (Settings, SSH and GPG keys) yourself.

## Not ready yet

- **Prebuilt releases.** `.github/workflows/release.yml` still packages
  agent-sign's program names and has no Linux ARM64 build; the fix,
  `docs/release/ci-workflows.patch`, is waiting to be applied (see
  [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md)). Until then, build from
  source as above.
- **Homebrew.** `Formula/agent-commits.rb` installs from those releases, so
  it can't be used until the first one is published, and it isn't in a tap
  yet. After `brew install`, its caveats give the one command that finishes
  setup (`install.sh --from-homebrew`).

## Upgrading from agent-sign

See [MIGRATION.md](MIGRATION.md). Nothing needs to be done by hand: the key,
leases and config carry over, and the old names keep working.
