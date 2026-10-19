# agent-sign

Improve your workflow with agent commits.

If you sign your git commits with a hardware key, 1Password, or a passkey,
an AI agent making twenty small commits stops twenty times for your
fingerprint. The usual workarounds are worse: turning signing off, or
handing the agent your own key. agent-sign gives agents a separate
signing key, held by a small background service, and asks you once instead:
for one repository, every repository in a folder, or all of them, as you
choose. After that, agent commits are signed without interrupting you, and
your own key is never handed to an agent.

What it is, plainly: it removes the interruption, and adds local guardrails
for agents that cooperate (no agent commits on `main`, no changes to CI
workflows or key files, a rate limit). It is **not** a separate
identity for agents on GitHub: the agent key is registered on your account,
so agent commits show as Verified for you, with the agent's name as author.
See [what it protects against, and what it doesn't](#what-it-protects-against-and-what-it-doesnt).

The approval is a **lease**, and you see its terms before you approve: what
it covers, which branches, and when it ends. No lease lasts forever: it ends
when the branch it was approved for is merged or deleted, after a week with
no agent commits, or when you turn it off, whichever comes first. The terms
are fixed when you approve and never grow on their own. Commits you
make yourself in a terminal go through your normal signing.

**Status: pre-release (0.1.0).** Its author uses it daily on macOS for every
agent commit. Linux builds and passes its tests, but has had little daily
use, and cannot approve leases interactively (see [Linux](#linux)). There are
no downloadable releases yet: you build it from source.

## How it works

1. The installer puts a `git` wrapper (`agent-git`) first on your shell's
   `PATH`. Agents started from that shell run `git` as usual. (An agent
   started some other way, such as an app launched from the Dock, may not
   get that `PATH`: check with `command -v git` from the agent.)
2. When an agent runs `git commit`, the wrapper checks the local rules: no
   changes to CI workflows (`.github/workflows/`, `.circleci/`) or key files
   (`*.pem`, `*.key`, `id_rsa*`, `id_ed25519*`). There's no limit on a
   commit's size unless you set one (`max_diff_lines`). Then it asks the
   service (`agent-signd`) for a lease covering this repository.
3. If there's no lease, you get one dialog showing the repository, the
   branch, which branches the lease would cover, and when it ends. You pick
   what the approval covers and press Continue (or Deny), and then the Mac
   asks you to prove it's you: Touch ID, or your login password. Only then
   is the lease granted. A click alone approves nothing, so a program that
   can click the dialog (a computer-use agent, a System Events script)
   can't approve a lease for itself. Commits that ask while it's open
   (retries, or several agents at once) wait for the same answer instead of
   opening more dialogs, and the request closes by itself if every commit
   waiting on it has gone (a test that timed out, say). Only one approval
   prompt is shown at a time, and after one is refused (Deny, or a Touch ID
   that is cancelled, fails or times out) no new one opens for a while, 60
   seconds at first and doubling with each refusal in a row (the agent is
   told how long). At most 4 requests wait at once. A request is only asked
   about if its repository is a real, existing git working tree and its path
   and branch have no control or invisible characters in them.
   A commit that turns signing off (`--no-gpg-sign`, or `commit.gpgsign`
   set to false for that command or that repository, as test suites do for
   throwaway commits) never asks: it goes to plain git, unsigned.
4. With a lease, and if the branch isn't protected and the commit rate is
   under its limit, the commit is signed with the agent's key through git's
   own SSH signing (`agent-ssh-sign`). By default (`split` attribution) the
   agent is the author and you're the committer.
5. Leases are saved, so a crash, a restart, or your laptop sleeping doesn't
   ask again. `agent-sign leases` lists them; `agent-sign revoke` ends them.

The wrapper tells you from an agent this way: if both its input and output
are a terminal, and no agent has marked the command as its own (Claude Code,
Gemini CLI and Codex do), it's you, and it steps aside and runs your normal
git with your normal signing. Anything else is treated as an agent.

## What it protects against, and what it doesn't

agent-sign catches mistakes by an agent that cooperates. It is **not** a security
boundary against an agent that tries to get around it, when the agent runs
as your own user account, which is how agents run on a laptop today.

It does:

- keep your own signing key away from agents (they never talk to it)
- refuse agent commits on protected branches (`main` and `master` by
  default), checked on every commit
- ask you before the first signed commit that no lease covers, showing the
  lease's terms and letting you choose how far it reaches, and (on macOS)
  require Touch ID or your login password to approve it. Cancel, a failed
  or timed-out check, or no way to run the check all deny
- stop runaway commit loops (and oversized diffs, if you set a size limit), and block edits to CI
  workflows and key files
- fail closed: for a commit through the wrapper, if the service is down,
  there's no lease, or you can't be asked, the commit is refused, never
  signed some other way

It does not, yet:

- stop an agent running as your user from reading the agent key, editing
  agent-sign's config, starting its own service, or calling the real git directly.
  The key isn't encrypted, so anything that copies it can make commits that
  GitHub shows as Verified for you
- apply its rules to a commit that turns signing off (`--no-gpg-sign`, or
  `commit.gpgsign = false` for that command or repository): it goes to
  plain git unsigned, as calling the real git directly would
- intercept `merge`, `rebase`, `cherry-pick`, `revert` or `pull`, or a
  commit run from inside one of your git shell aliases (`alias.x = "!git
  commit ..."`): git runs its own copy of itself there, not the wrapper, so
  those go to your normal signing. If that's set up to sign, you'll see your
  own signer's prompt (Touch ID, for example)
- tell agents apart for security: there is one agent key per machine, and a
  lease belongs to the machine, not to a particular agent. Commits do name
  the agent when it can be told (Claude Code, Gemini CLI and Codex mark the
  commands they run; others can be started with `AGENT_SIGN_AGENT_NAME`),
  but that's a label: any program can set those variables
- stop an agent running as your user from approving its own lease by other
  means than the dialog: it can edit the config (`auto_approve`), start its
  own service, or, if it knows your login password, type it into the
  system's prompt. The dialog and Touch ID close the screen-clicking route,
  not those
- approve anything on Linux: it has no platform authenticator yet, so every
  request there is refused (see [Linux](#linux))
- keep agent work apart from yours on GitHub: the agent key goes on your
  GitHub account (the installer offers to add it, and does only if you say
  yes) and in `allowed_signers` under your email,
  and in the default attribution mode you're the committer, so agent commits
  show as Verified for you
- recognise an agent running in a real terminal (a terminal pane) unless
  it marks its commands, as Claude Code, Gemini CLI and Codex do (an
  unmarked one looks like you), or an editor's commit button whose git is
  the wrapper (it looks like an agent)

These are the next steps; see [docs/RELEASE_CHECKLIST.md](docs/RELEASE_CHECKLIST.md).

## Install

Full instructions, including exactly what the installer changes on your
machine: [docs/INSTALL.md](docs/INSTALL.md). In short, on macOS or Linux,
with Rust 1.88 or newer:

```sh
git clone https://github.com/taylor-made-labs/agent-sign.git
cd agent-sign
cargo build --release --locked
./scripts/install.sh
```

Then open a new terminal and check the setup:

```sh
agent-sign doctor
```

## Your first agent commit

Start your agent from a new terminal, so the wrapper is on its `PATH`, and
let it commit on a branch other than `main` or `master` (agents never commit
on those). You'll see one dialog, titled "agent-sign":

```
An AI agent asks to sign git commits as the agent without asking you again.

Repository: /Users/you/code/project
Branch now: feat/parser
Branches: every branch except protected ones (main, master)
Ends: when the work on branch 'feat/parser' is merged or the branch is deleted,
  after 7 days with no agent commits, or when you turn it off (agent-sign revoke)

Choose what this approval covers, then Continue. You will then be asked to
confirm that it is you (Touch ID or your password); nothing is approved until
you do. These terms are fixed when you approve. They never grow.

    This repository only
    Every repository under /Users/you/code
    Every repository on this computer

                                         [Deny]  [Continue]
```

Nothing is selected to begin with, and Continue stays greyed out until you
pick one; Deny (or Escape) refuses. After Continue, the system's own prompt
asks for Touch ID or your login password, and waits up to five minutes; if
you cancel, get it wrong, or it times out, the lease is refused and the agent
sees that agent-sign could not confirm it was you. Choose a wider scope if
you start new repositories often and don't want to be asked for each. Agent
commits in what you chose are signed from then on without asking. Check one
with `git log -1 --show-signature`. (With `allow_branch_switching = false`,
only "This repository only" is offered: a wider lease can't be held to one
branch.)

In a brand-new repository, make the first commit yourself (agents can't
commit on `main`), then have the agent work on a branch.

On a machine with no screen (a server, a container, or over SSH: the service
runs in the background, so your SSH terminal doesn't count), agent-sign can't
ask you, so it refuses: see
[Headless machines](docs/INSTALL.md#headless-machines-servers-containers-ci).
When a commit is refused, the agent sees why; the messages are listed in
[docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md).

## Linux

Linux can't approve leases yet, so the service refuses every request there
(unless `auto_approve` is on). agent-sign has no platform authenticator for
Linux, and the two ways it could have asked anyway both let an agent approve
for itself: a dialog any program can click, and a terminal prompt, which an
agent can drive through a pseudo-terminal of its own or by typing into yours.
So there is neither. The refusal says why. For an unattended machine you
trust, turn on `auto_approve`, which grants every lease without asking (only
where every process that can reach the service is trusted). Approving from
another device, such as a passkey on your phone, is the planned next step and
belongs to the agentic-credentials work; it isn't built.

## Leases

| Setting in `~/.agent-sign/config.toml`, under `[security]` | Default | What it does |
|---|---|---|
| `lease_mode` | `"identity"` | `identity`: until its work is finished (see below). `timed`: also no later than `default_lease_duration` after approval. |
| `end_after_idle` | `"7d"` | A lease ends after this long with no agent commit under it, so one whose branch is never merged or deleted still ends. `"none"` turns this off. A value agent-sign can't read stops the service rather than being ignored. |
| `max_lease_ceiling` | `"none"` | Longest life of an `identity` lease, such as `"7d"`. It also shortens leases already granted. A value agent-sign can't read stops the service rather than being ignored. |
| `default_lease_duration` | `"2h"` | Life of a `timed` lease. |
| `allow_branch_switching` | `true` | With `lease_scope = "branch"` (the default), `true` makes a lease cover every unprotected branch of the repository, following the agent between them; `false` limits it to the branch it was approved on. `lease_scope = "repo"` always covers every unprotected branch. |
| `block_branches` | `["main", "master"]` | Branches no lease covers (a name, or a prefix ending in `*`). |
| `allow_main_branch` | `false` | `true` turns that protection off. |
| `max_commits_per_minute` | `10` | Commit rate limit per repository. |
| `refusal_backoff` | `"60s"` | After an approval prompt is refused, no new one opens for this long, doubling with each refusal in a row (up to an hour); an approval resets it. `"none"` turns it off. A value agent-sign can't read stops the service. |

Every lease also ends with its work: when the branch it was approved for is
merged into `main` or `master` (counting only commits made since the
approval, and a merge on GitHub once you've fetched it) or deleted. Detached
HEAD has no branch to follow, so there only the other endings apply.

Changing these only ever narrows leases already granted: a shorter ceiling
ends older leases sooner, and a longer one doesn't extend them. The service
reads the file when it starts, so restart it after a change
([how](docs/TROUBLESHOOTING.md#the-service)). The whole config, with
attribution modes, is in [SPEC.md](SPEC.md).

```sh
agent-sign leases            # the leases in force, and when each ends
agent-sign revoke <repo>     # end a repository's lease (its path, or . inside it)
agent-sign revoke <folder>   # end a lease covering every repository under a folder
agent-sign revoke everywhere # end a lease covering every repository
agent-sign revoke --all      # end every lease
agent-sign pending           # approval requests waiting for your answer
agent-sign deny --all        # answer no to all of them and close their dialogs
agent-sign status            # is the service running
agent-sign doctor            # check the whole setup, with fixes
```

## Uninstall

```sh
./scripts/uninstall.sh
```

It removes the service, the `PATH` and editor changes, and the agent key's
`allowed_signers` line, and deletes `~/.agent-sign`, the agent
key included. It leaves git's `gpg.ssh.allowedSignersFile` setting, if the
installer set it. Remove the agent key from your GitHub account's signing
keys yourself.

## Upgrading

Run the installer again from the new version. Your key, leases and config
carry over, with no new approval. What changed since the first agent-sign:
[docs/MIGRATION.md](docs/MIGRATION.md).

## More

- [docs/INSTALL.md](docs/INSTALL.md): installing, what changes, headless machines
- [SPEC.md](SPEC.md): the components, invariants and config
- [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md): when a commit is refused
- [docs/integrations/](docs/integrations/): notes for Claude Code, Cursor, Aider and Antigravity
- [CONTRIBUTING.md](CONTRIBUTING.md): building, testing, and sending changes

## License

agent-sign is licensed under either of

- the [Apache License, Version 2.0](LICENSE-APACHE), or
- the [MIT License](LICENSE-MIT),

at your option. This is the same pair most Rust projects use: pick whichever
your organization already accepts.
