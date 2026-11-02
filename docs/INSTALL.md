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

### Installer options

| Option | What it does |
|---|---|
| `--yes` | Don't stop to ask before changing things. Without a terminal (over a non-interactive `ssh`, say) the installer goes ahead anyway. |
| `--machine <name>` | Names this machine: writes `machine = "<name>"` under `[identity]` in `~/.agent-sign/config.toml` **before** the service first starts, so no agent commit is ever signed under the plain `@agents.local` domain. A name is 1 to 63 lowercase letters and digits, in words joined by single `-` (`build-1`, `pi-4`). Anything else, or a missing or empty name, is refused with a message naming it, before anything is installed or changed. An existing `config.toml` keeps every other setting, `[identity] allowed_agents` included, and installing again with the same name leaves the file as it is. A different name replaces the old one, with a warning. Why you'd name machines, and what changes if you name one later: [Naming the machine](../README.md#naming-the-machine). |
| `--person <name>` | A person's name, such as `--person Taylor` or `--person "Dana Example"` (repeat the option for more): adds it to `people = [...]` under `[identity]` in `~/.agent-sign/config.toml` before the service starts, and the service then never certifies an agent under that name or any word of it, whatever `allowed_agents` says. For anyone whose name agent-sign can't know otherwise; the people with accounts on the machine are refused without it. A name has 1 to 64 characters, at least one letter a-z or digit, and no quotes, backslashes or control characters; anything else is refused before anything changes. A name already listed is left as it is, so installing again changes nothing. See [Allowed agent names](../README.md#allowed-agent-names). |
| `--launcher-unit <unit>` | Linux only (refused on macOS). For a systemd user service that starts agents (repeat the option for each one; `foo` means `foo.service`), writes a drop-in that puts `~/.agent-sign/bin` first on that unit's `PATH`. It needs no machine name. A missing or invalid unit name is refused before anything changes. The installer never restarts the unit: see [Agents started by background services](#agents-started-by-background-services). |

To see it work end to end, run `./scripts/demo-sandbox.sh` from the `agent-sign`
directory. It starts a short-lived service of its own, with its own settings
in a throwaway folder (your installed service, settings and leases aren't
touched, and nothing asks you anything), makes two signed agent commits in a
throwaway repository and checks their signatures, shows one refused by a
local rule, then stops that service and deletes the folder.

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
| `~/.agent-sign/keys` | Public keys only. The agents' certificate authority is made in the service's memory each time it starts and never written anywhere; `agent-sign trust install` (which the installer runs once the service is up) adds the running service's public key, with the date, to `agents_cas.pub`; a start alone writes only `agents_ca_ed25519.pub`, the live key, which isn't trusted by itself. Private keys earlier versions stored here unprotected (`agents_ca_ed25519`, the old shared `agent_ed25519`, and copies in `retired/`) are deleted; their public halves stay. |
| `~/.agent-sign/config.toml` | Settings. Only written if missing; on an install over an existing one, only `fallback_program` (below), an old `"split"` default, and, with `--machine`, `[identity] machine` are changed. |
| Your global `gpg.ssh.program` | Set to `~/.agent-sign/bin/agent-ssh-sign`, so your own SSH signing goes through agent-sign: your signatures go on to your signer, and a request from an agent's process is refused. What it was (or `ssh-keygen`, git's default, if unset) becomes `fallback_program` in `config.toml`; the uninstaller puts it back. If it already is `agent-ssh-sign`, the existing `fallback_program` is kept. |
| git's `allowed_signers` file (the list of SSH keys git trusts when it checks signatures) | A marked block, between `# agent-sign: agents' certificate authorities, managed; do not edit` and its end line, holding `agent-sign trust-line`'s lines: they trust the agents' certificate authorities for `*@agents.local` principals (or `*@<machine>.agents.local` on a named machine) and git signatures only. `agent-sign trust install` rewrites the block, and nothing outside it: the installer runs it once the service is up, and after a restart of the service you run it again (`agent-sign doctor` says when). A start never writes it. An earlier version's bare trust line moves into the block. (And `gpg.ssh.allowedSignersFile` is set globally, to `~/.config/git/allowed_signers`, if it wasn't set; the uninstaller leaves that setting.) This is what makes `git log --show-signature` report each agent commit as good **for that agent**, never for you. |
| launchd or systemd | A user service that runs `agent-signd` and restarts it if it stops (on macOS the copy in `agent-sign.app`; `~/Library/LaunchAgents/com.agentsign.agent-signd.plist`, or `~/.config/systemd/user/agent-signd.service`). Before installing it, the installer stops a service installed earlier, and any `agent-signd` process of yours started by hand. On macOS the LaunchAgent also sets `AGENT_SIGN_REAL_GIT` to your real git (the first `git` on your `PATH` outside `~/.agent-sign`, or the one `xcrun --find git` names), because under launchd `git` is Apple's `/usr/bin/git` stand-in, which looks the real one up again on every run and made agent commits slow. |
| `~/.zshrc`, `~/.zprofile`, `~/.bashrc`, `~/.bash_profile` | A marked block putting `~/.agent-sign/bin` first on `PATH` (once), in each of these files that exists, so every program started from your shell, agents included, gets the wrapper as `git`. |
| `~/.config/systemd/user/<unit>.d/agent-sign.conf` | Linux, only with `--launcher-unit <unit>`. A drop-in holding `[Service]` and `Environment=PATH=<your home>/.agent-sign/bin:<your service manager's PATH>` (as it was at install time), so agents that unit starts get the wrapper as `git`. Your own drop-ins for the unit are left alone. |
| Cursor, VS Code and Windsurf `settings.json` | The same `PATH` for their built-in terminals, if those editors are installed. |
| `~/.gemini/config/rules/agent-sign.md` | A rule for Google Antigravity, if it's installed. |

Consequences worth knowing:

- Each agent signs, authors and commits as its own identity (such as
  `Claude Code <claude-code.1a2b3c4d@agents.local>`), never as you. GitHub
  doesn't check signatures made with SSH certificates, so agent commits show
  there as Unverified. Only [allowed agent names](../README.md#allowed-agent-names)
  get signed, and the identities are claims made by programs running in
  the same account as agent-sign: see
  [What a signature proves](../README.md#what-a-signature-proves).
- Editors that read your login shell's `PATH` (VS Code on macOS does) may
  run the wrapper for their own commit button. With no terminal attached and
  no agent mark, the wrapper leaves that commit to git: unsigned, under your
  git name, never attributed to an agent (point the editor's `git.path` at
  your real git to have it signed with your own key).
- On an upgrade, the installer deletes the old shared agent key's private
  half (it was stored unprotected) and, while its line is still in your
  allowed-signers file, prints the commands to remove that line and its
  GitHub signing key; it runs neither.

## Servers and non-interactive installs

On a Linux server, install agent-sign in the account the agents run in.
agent-sign never needs root, and its service runs as that account.

**Over a non-interactive `ssh` command.** You can run the installer
without a terminal:

```sh
ssh build-1 'cd agent-sign && ./scripts/install.sh --yes --machine build-1'
```

(`build-1` stands for your server's `ssh` name.) `systemctl --user`, which
the installer uses to install and start the service, finds your service
manager through `XDG_RUNTIME_DIR`, and some systems don't set it for a
command run over `ssh`. When it's missing, the installer and the uninstaller
set it to `/run/user/<your user id>` themselves, if that folder exists. The
folder exists only while your service manager runs: while you're logged in,
or always once lingering is on (below). If `systemctl --user` still can't
connect, turn on lingering and run the installer again.

**Keep it running after you log out.** A user service stops when your last
session ends, unless lingering is on: `loginctl enable-linger "$USER"`
(some systems allow this only for an administrator:
`sudo loginctl enable-linger <user>`). With lingering, your user services,
agent-sign's included, also start at boot.

**Name the machine at install time** with `--machine <name>` if you run
agent-sign on more than one machine, so the name is in place before the
service's first start ([why](../README.md#naming-the-machine)).

### Agents started by background services

Agents started from your shell get the wrapper from your shell profile. An
agent started by a background service, such as a systemd user unit that
runs agent sessions, doesn't read your profile, so it runs the real `git`
and its commits go unsigned. For each such unit:

```sh
./scripts/install.sh --launcher-unit my-agent-runner.service
```

(`my-agent-runner` alone means `my-agent-runner.service`.) The installer
asks your service manager for its `PATH`
(`systemctl --user show-environment`) and writes
`~/.config/systemd/user/my-agent-runner.service.d/agent-sign.conf`, marked
as agent-sign's in its first line:

```ini
[Service]
Environment=PATH=/home/you/.agent-sign/bin:<the manager's PATH>
```

Repeat the option for each unit. Installing again with the same units
leaves one identical drop-in each. This works for your own user units only,
not system-wide ones, and only on Linux: on macOS the option is refused.

The installer doesn't write a drop-in, and says so (its final check of the
drop-ins fails too), when it can't read the service manager's `PATH`, or when that
unit's folder already holds an `agent-sign.conf` that isn't marked as
agent-sign's. If the unit sets a `PATH` of its own, the installer warns that
the drop-in replaces it: check that before you restart the unit.

**Restarting the unit is yours to do.** The installer never restarts, stops
or starts a launcher unit, because a restart stops the agents it is
running; it prints the command for each unit instead (it has already
reloaded systemd's settings). The drop-in takes effect only when the unit
next starts, so restart it yourself when no agent it started is in the
middle of work:

```sh
systemctl --user restart my-agent-runner.service
```

Restart it again only after the drop-in changes (a new install that names
the unit for the first time, or a change to your service manager's
`PATH`). The installer does restart agent-sign's own service; agents keep
running through that, and a commit made at that moment waits up to 2
seconds for the service to answer again.

`./scripts/uninstall.sh` removes the drop-ins marked as agent-sign's, leaves
your own drop-ins for the same units alone, and doesn't restart the units
either: they keep agent-sign's `PATH` until you restart them, and it prints
the commands.

## Servers: system mode

The install above puts agent-sign in one account, which is right for a laptop.
On a shared server, where the agents' own account must not be able to change
agent-sign, use **system mode**: agent-sign runs in accounts of its own, and
each launched session runs in an account of its own too. Nothing changes on a
machine with no `/etc/agent-sign/system.toml`.

What system mode puts on the machine:

- **The service**, `agent-signd`, as the system service `agent-signd.service`
  in the account `agent-sign`. The agents' account can't restart or read it.
- **The launcher**, `agent-launchd`, as `agent-launchd.service` in the account
  `agent-launch`. It starts and ends sessions and does nothing else (it never
  runs git).
- **Slots**: accounts `agent-slot-1` to `agent-slot-N` (8 by default), each with
  a folder under `/var/lib/agent-slots/N`. A session runs in one slot; when it
  ends its folder moves to that slot's `trash/` (it is never deleted).
- **The OpenBao issuer**: agents' certificates come from an SSH certificate
  authority in OpenBao, which never leaves OpenBao. The service logs in with
  a login stored encrypted for this machine in `/etc/credstore.encrypted/`.
  Needs OpenBao 2.7.2 or later.
- **Root's trust file**, `/etc/agent-sign/allowed_signers`, holds exactly the
  OpenBao authority, and `/etc/gitconfig` points git at it.
- **The settings file**, `/etc/agent-sign/system.toml`, written by the sitting.
  Don't edit it by hand: run the sitting again.

You install it with the sitting script, `scripts/sitting/agent-sign-sitting.sh`,
as the administrator (not root, not the agents account), with sudo:

```sh
git archive --format=tar -o /tmp/source.tar <commit>
scripts/sitting/agent-sign-sitting.sh --machine hetzner --commit <commit> --source /tmp/source.tar --dry-run
scripts/sitting/agent-sign-sitting.sh --machine hetzner --commit <commit> --source /tmp/source.tar
```

The dry run prints what it would change and changes nothing. A real run
is safe to repeat: each step says `kept:` when nothing is left to do. It stops at
the first failure and says why, and it ends with PASS, FAIL or SKIP for each
check. `--undo` puts the machine back and never deletes data. The details are in
`scripts/sitting/README.md` and the design in [system-mode.md](system-mode.md).

**Starting an agent.** In system mode an agent runs only as a launched session:

```sh
agent-sign launch --agent codex -- <program> [args...]
```

Only the administrator's account may launch (the accounts in
`[launcher] people_accounts`), until a signing key for launch approvals is set.
The command stays up while the session runs and shows its output. If you start
it in a git repository, that repository goes into the session as a bundle, and
the session's commits come back as branches named
`session/<principal>/<branch>`. Sessions have no terminal and no login of their
own yet. If you lose the connection, `agent-sign launch --collect <session>`
fetches the bundles later.

**Checking.** `agent-sign doctor` should print `ping: ok` and
`authority: OpenBao CA matches the trust file`.

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
`loginctl enable-linger "$USER"` (see
[Servers and non-interactive installs](#servers-and-non-interactive-installs)).
Approving from another device, such as a passkey on your
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
settings and the drop-ins written for `--launcher-unit`, removes agent-sign's lines from `allowed_signers` (the agents'
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
