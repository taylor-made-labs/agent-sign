# agent-commits

agent-commits gives AI coding agents their own key for signing git commits, so an
agent's commits are signed, name the agent as their author, and don't stop
for your fingerprint: you're asked once, for the scope you choose (one
repository, a folder of them, or all of them), instead of on every commit. (On GitHub they still count as yours; see the limits below.)

You approve a **lease**: permission for agents to sign, with terms you see
before you approve: what it covers (this repository only, every repository
under the folder that holds it, or every repository on the computer; you
pick), which branches, and when it ends (by default, when you revoke it). Those terms are fixed when you approve
and never grow on their own. Your own signing key is never used for agents'
commits, and commits you make yourself go through your normal signing.

agent-commits was called agent-sign before (see [Upgrading from agent-sign](#upgrading-from-agent-sign)).

**Status: pre-release (0.1.0).** Its author uses it daily on macOS for every
agent commit. Linux builds and passes its tests, but has had little daily
use. There are no downloadable releases yet: you build it from source.

## Why

If you sign your commits with a hardware key, 1Password, or a passkey, an
agent making twenty small commits stops twenty times for your fingerprint.
The usual workarounds are worse: turning signing off, or handing the agent
your own key. agent-commits gives the agent a separate signing key, held by a small
background service, and asks you once.

## How it works

1. The installer puts a `git` wrapper (`agent-commits-git`) first on your shell's
   `PATH`. Agents started from that shell run `git` as usual. (An agent
   started some other way, such as an app launched from the Dock, may not
   get that `PATH`: check with `command -v git` from the agent.)
2. When an agent runs `git commit`, the wrapper checks the local rules (no
   changes to CI workflows or key files, a diff-size limit), then asks the
   service (`agent-commitsd`) for a lease on this repository.
3. If there's no lease, you get one dialog showing the repository, the
   branch, which branches the lease would cover, when it ends, and the reason
   the agent gave. You approve or deny.
4. With a lease, and if the branch isn't protected and the commit rate is
   under its limit, the commit is signed with the agent's key through git's
   own SSH signing (`agent-commits-ssh-sign`). By default (`split` attribution) the
   agent is the author and you're the committer.
5. Leases are saved, so a crash, a restart, or your laptop sleeping doesn't
   ask again. `agent-commits leases` lists them; `agent-commits revoke` ends them.

The wrapper tells you from an agent by one test: if both its input and
output are a terminal, it's you, and it steps aside and runs your normal git
with your normal signing. Anything else is treated as an agent.

## What it protects against, and what it doesn't

agent-commits catches mistakes by an agent that cooperates. It is **not** a security
boundary against an agent that tries to get around it, when the agent runs
as your own user account, which is how agents run on a laptop today.

It does:

- keep your own signing key away from agents (they never talk to it)
- refuse agent commits on protected branches (`main` and `master` by
  default), checked on every commit
- ask you before the first signed commit that no lease covers, showing the
  lease's terms and letting you choose how far it reaches
- stop runaway commit loops and oversized diffs, and block edits to CI
  workflows and key files
- fail closed: for a commit through the wrapper, if the service is down,
  there's no lease, or you can't be asked, the commit is refused, never
  signed some other way

It does not, yet:

- stop an agent running as your user from reading the agent key, editing
  agent-commits' config, starting its own service, or calling the real git directly.
  The key isn't encrypted, so anything that copies it can make commits that
  GitHub shows as Verified for you
- intercept `merge`, `rebase`, `cherry-pick`, `revert` or `pull`: those go to
  your normal signing
- tell agents apart: there is one agent key per machine, and a lease belongs
  to the machine, not to a particular agent
- make the dialog a biometric check: it's a confirmation dialog, and its
  default button is Approve
- keep agent work apart from yours on GitHub: the installer registers the
  agent key on your GitHub account and in `allowed_signers` under your email,
  and in the default attribution mode you're the committer, so agent commits
  show as Verified for you
- recognise an agent running in a terminal pane (it looks like you), or an
  editor's commit button whose git is the wrapper (it looks like an agent)

These are the next steps; see [docs/RELEASE_CHECKLIST.md](docs/RELEASE_CHECKLIST.md).

## Install

Full instructions, including exactly what the installer changes on your
machine: [docs/INSTALL.md](docs/INSTALL.md). In short, on macOS or Linux,
with Rust 1.88 or newer:

```sh
git clone https://github.com/taylor-made-labs/agent-commits.git
cd agent-commits
cargo build --release --locked
./scripts/install.sh
```

Then open a new terminal and check the setup:

```sh
agent-commits doctor
```

## Your first agent commit

Start your agent from a new terminal, so the wrapper is on its `PATH`, and
let it commit on a branch other than `main` or `master` (agents never commit
on those). You'll see one dialog, titled "agent-commits":

```
An AI agent asks to sign git commits as the agent without asking you again.

Repository: /Users/you/code/project
Branch now: feat/parser
Branches: every branch except protected ones (main, master)
Ends: when you revoke it (agent-commits revoke)
Reason given by the agent: Autonomous coding agent commit

Choose what this approval covers. These terms are fixed when you approve.
They never grow.

  > This repository only
    Every repository under /Users/you/code
    Every repository on this computer

                                         [Deny]  [Approve]
```

"This repository only" is selected, so Approve alone keeps it to one
repository. Choose a wider scope if you start new repositories often and
don't want to be asked for each. Agent commits in what you chose are signed
from then on without asking. Check one with `git log -1 --show-signature`.
(With `allow_branch_switching = false`, only "This repository only" is
offered: a wider lease can't be held to one branch.)

In a brand-new repository, make the first commit yourself (agents can't
commit on `main`), then have the agent work on a branch.

On a machine with no screen (a server, a container, or over SSH: the service
runs in the background, so your SSH terminal doesn't count), agent-commits can't show
the dialog, so it refuses: see
[Headless machines](docs/INSTALL.md#headless-machines-servers-containers-ci).
When a commit is refused, the agent sees why; the messages are listed in
[docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md).

## Leases

| Setting in `~/.agent-commits/config.toml`, under `[security]` | Default | What it does |
|---|---|---|
| `lease_mode` | `"identity"` | `identity` (named for an agent identity's lifetime): until you revoke it, or `max_lease_ceiling`. `timed`: `default_lease_duration` after approval. |
| `max_lease_ceiling` | `"none"` | Longest life of an `identity` lease, such as `"7d"`. It also shortens leases already granted. A value agent-commits can't read stops the service rather than being ignored. |
| `default_lease_duration` | `"2h"` | Life of a `timed` lease. |
| `allow_branch_switching` | `true` | With `lease_scope = "branch"` (the default), `true` makes a lease cover every unprotected branch of the repository, following the agent between them; `false` limits it to the branch it was approved on. `lease_scope = "repo"` always covers every unprotected branch. |
| `block_branches` | `["main", "master"]` | Branches no lease covers (a name, or a prefix ending in `*`). |
| `allow_main_branch` | `false` | `true` turns that protection off. |
| `max_commits_per_minute` | `10` | Commit rate limit per repository. |

Changing these only ever narrows leases already granted: a shorter ceiling
ends older leases sooner, and a longer one doesn't extend them. The service
reads the file when it starts, so restart it after a change
([how](docs/TROUBLESHOOTING.md#the-service)). The whole config, with
attribution modes, is in [SPEC.md](SPEC.md).

```sh
agent-commits leases            # the leases in force, and when each ends
agent-commits revoke <repo>     # end a repository's lease (its path, or . inside it)
agent-commits revoke <folder>   # end a lease covering every repository under a folder
agent-commits revoke everywhere # end a lease covering every repository
agent-commits revoke --all      # end every lease
agent-commits status            # is the service running
agent-commits doctor            # check the whole setup, with fixes
```

## Uninstall

```sh
./scripts/uninstall.sh
```

It removes the service, the `PATH` and editor changes, and the agent key's
`allowed_signers` line, and deletes `~/.agent-commits` and `~/.agent-sign`, the agent
key included. It leaves git's `gpg.ssh.allowedSignersFile` setting, if the
installer set it. Remove the agent key from your GitHub account's signing
keys yourself.

## Upgrading from agent-sign

The old program names, `AGENT_SIGN_*` variables and `.agent-sign.toml` all
still work, and `agent-commitsd` moves `~/.agent-sign` to `~/.agent-commits` on its first
start, leaving a link. Your key and leases carry over without a new
approval. Step by step: [docs/MIGRATION.md](docs/MIGRATION.md).

## More

- [docs/INSTALL.md](docs/INSTALL.md): installing, what changes, headless machines
- [SPEC.md](SPEC.md): the components, invariants and config
- [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md): when a commit is refused
- [docs/integrations/](docs/integrations/): notes for Claude Code, Cursor, Aider and Antigravity
- [CONTRIBUTING.md](CONTRIBUTING.md): building, testing, and sending changes

## License

agent-commits is licensed under either of

- the [Apache License, Version 2.0](LICENSE-APACHE), or
- the [MIT License](LICENSE-MIT),

at your option. This is the same pair most Rust projects use: pick whichever
your organization already accepts.
