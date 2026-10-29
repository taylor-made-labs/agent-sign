# agent-sign

**Each AI agent signs and commits as itself, never as you.** An agent's
commit is authored, committed and signed by that agent's own identity, such
as `Claude Code <claude-code.1a2b3c4d@agents.local>`, so `git log` tells
agent work from yours, and nothing an agent makes is signed with your key.

- **No approval by default.** Agent commits don't stop for your fingerprint;
  the service logs which agent committed where. If you want to approve
  each repository's agent work yourself, `approval = "device-owner"` brings
  back one Touch ID prompt per **lease** (one branch of one repository,
  until it's merged; see [Leases](#leases)).
- **One block of trust.** A marked block in your allowed-signers file trusts
  agents' signatures for `*@agents.local` names only, never your email; the
  installer adds it and the service keeps it current. Then
  `git log --show-signature` shows a Good signature for the agent that made
  each commit.
- **No private key on disk.** Each agent session's signing key, and the
  certificate authority that vouches for it, live only in the service's
  memory, never in a file.
- **Your own signing is routed.** The installer points git's
  `gpg.ssh.program` at agent-sign's signing program, which passes your own
  signatures on to your signer (1Password, a hardware key, `ssh-keygen`)
  as before, and refuses any signing request from an agent's process.
  Commits you make in a terminal are signed as you, as before.
- **Limits.** These identities are attribution, not a security boundary:
  agents run as your user, and one agent could claim to be another. agent-sign
  catches mistakes by agents that cooperate; it doesn't stop one set on getting
  around it. See
  [what it protects against, and what it doesn't](#what-it-protects-against-and-what-it-doesnt).

Why: if you sign your git commits with a hardware key, 1Password, or a
passkey, an agent making twenty small commits stops twenty times for your
fingerprint, and the usual workarounds (turning signing off, or handing the
agent your key) are worse. agent-sign also adds local guardrails for agents
that cooperate: no agent commits on `main`, no changes to CI workflows or
key files, a rate limit.

**Status: pre-release (0.1.0).** Its author uses it daily on macOS for every
agent commit. Linux builds and passes its tests, but has had little daily
use (see [Linux](#linux)). There are no downloadable releases yet: you build
it from source.

## How it works

1. The installer puts a `git` wrapper (`agent-git`) first on your shell's
   `PATH`. Agents started from that shell run `git` as usual. (An agent
   started some other way, such as an app launched from the Dock, may not
   get that `PATH`: check with `command -v git` from the agent.)
2. When an agent runs `git commit`, the wrapper checks the local rules: no
   changes to CI workflows (`.github/workflows/`, `.circleci/`) or key files
   (`*.pem`, `*.key`, `id_rsa*`, `id_ed25519*`). There's no limit on a
   commit's size unless you set one (`max_diff_lines`). Then it asks the
   service (`agent-signd`) for a lease covering this repository and branch.
3. The service grants a lease for that repository and branch without
   asking anyone (`approval = "none"`, the default), and writes in its log
   which agent got it, for which repository and branch: the record of who
   committed where. With `approval = "device-owner"` it asks you instead,
   once per lease, in the Mac's own Touch ID (or login password) prompt,
   with the reason spelled out, such as "let an agent sign commits on branch
   “feat/parser” in project (~/code/project), until merged" (details in
   [Approving leases yourself](#approving-leases-yourself)).
   A commit that turns signing off (`--no-gpg-sign`, or `commit.gpgsign`
   set to false for that command or that repository, as test suites do for
   throwaway commits) goes to plain git, unsigned. An agent's still carries
   the agent's name and principal, unless the repository sets its own
   `user.email` (a test fixture's names are kept). Branch protection covers
   signed agent commits only, so such unsigned commits can land on `main`:
   a rule that every commit on `main` is signed (your own signed merges)
   keeps them out.
4. If the branch isn't protected and the commit rate is under its limit,
   the commit is signed through git's own SSH signing (`agent-ssh-sign`) as
   the agent's own identity: the service gives each agent session a signing
   key that lives only in its memory, with a 12-hour OpenSSH certificate
   from the agents' certificate authority naming the agent's principal. The
   authority is made in the service's memory each time it starts, and its
   private key is never written anywhere. In every attribution mode the
   agent is both author and committer.
5. Commands that make commits by themselves (`merge`, `pull`, `rebase`,
   `cherry-pick`, `revert`, `am`, aliases for those, and shell aliases) are
   signed the same way for an agent that says who it is: the wrapper gets a
   token for that one git run, so every commit it makes is signed as the
   agent and committed by it (new commits, such as a merge or a revert, are
   also authored by it; replayed ones keep their author). A token signs only
   in the repository and on the branch it was issued for: the signing
   program tells the service where each commit is going, and a run that
   moves elsewhere (`git rebase feature main` from `feature`, or a `cd` into
   another repository) gets nothing signed there. Every signature counts
   against the rate limit.
6. Leases are saved, so a crash, a restart, or your laptop sleeping changes
   nothing. `agent-sign leases` lists them; `agent-sign revoke` ends them.

### Which agent is it

An agent's identity comes only from what the agent itself sets in its
environment (a config file can't change it, so a cloned repository can't
make agent work look like someone else's):

| Agent | Mark | Session |
|---|---|---|
| Claude Code | `CLAUDECODE` (not empty or `0`) | `CLAUDE_CODE_SESSION_ID` |
| Codex | `CODEX_SESSION_ID` or `CODEX_THREAD_ID` | the first of those |
| Gemini CLI | `GEMINI_CLI` | none of its own |
| any other | `AGENT_SIGN_AGENT_NAME="Cursor"` (overrides the above) | `AGENT_SIGN_SESSION_ID` (overrides the above) |

The identity's email, its **principal**, is `<tool>.<session>@agents.local`,
where `<session>` is the first 8 hex characters of the SHA-256 of the
session id (`nosession` when the agent gives none): `claude-code.1a2b3c4d@agents.local`.
Two sessions get two principals, and two tools never share one. A name in
`AGENT_SIGN_AGENT_NAME` becomes the tool part in lowercase letters and
digits joined by single `-` ("My Bot (beta)" is `my-bot-beta`), and the
service certifies nothing else: no principal it signs for has any other
shape.

A commit with no terminal and no mark at all (your editor's commit button,
a GUI, or an agent that doesn't say it's one) is left to git: unsigned,
under git's own names, with nothing asked. agent-sign can't tell it from
your own, so it never puts an agent's name on it. If it asked to be signed
(`-S`, or your `commit.gpgsign = true`), it's still made unsigned rather
than failing, and one line says why: commit in a terminal to sign it as
yourself.

### Trusting agents' signatures

git checks SSH signatures against the file `gpg.ssh.allowedSignersFile`
names. The installer adds a marked block there that trusts every agent's
signature, for its own principal only:

```
# agent-sign: agents' certificate authorities, managed; do not edit
*@agents.local cert-authority,namespaces="git" ssh-ed25519 AAAA...
# agent-sign: end of agents' certificate authorities
```

The service makes a new certificate authority, in memory, each time it
starts, and adds its public key to `~/.agent-sign/keys/agents_cas.pub`
(with the date; earlier ones stay). At each start it rewrites the lines
between those two markers with one line per authority (what
`agent-sign trust-line` prints), so commits certified before a restart
still verify, and a new authority is trusted with no step of yours. It
never changes anything outside the markers, and does nothing if they
aren't there.

Then `git log --show-signature` shows
`Good "git" signature for claude-code.1a2b3c4d@agents.local`. Each line
trusts an agents' authority for `@agents.local` principals and git
signatures only: it can't vouch for your email or anyone else's. GitHub
doesn't check signatures made with SSH certificates, so agents' commits show
there as Unverified, which is accurate: they aren't yours.

The wrapper tells you from an agent this way: if both its input and output
are a terminal, and no agent has marked the command as its own (Claude Code,
Gemini CLI and Codex do), it's you, and it steps aside and runs your normal
git with your normal signing. Anything an agent marks (or names with
`AGENT_SIGN_AGENT_NAME`) is that agent's, signed as it. Anything else with no
terminal (which may be your own editor) is left as git makes it, unsigned,
under git's own names.

## What it protects against, and what it doesn't

agent-sign catches mistakes by an agent that cooperates. It is **not** a security
boundary against an agent that tries to get around it, when the agent runs
as your own user account, which is how agents run on a laptop today.

It does:

- keep your own signing key away from agents (they never talk to it), and
  ignore an agent's token that leaks into your own terminal
- sign each agent's commits as that agent, never as you: its own name and
  `@agents.local` principal as author and committer whatever the config
  says, and a signature that git reports as Good for that principal only
  under the trust lines
- let a repository's `.agent-sign.toml` only tighten the rules (add
  forbidden paths and protected branches, lower `max_diff_lines`); anything
  else in it is ignored, with a warning, so a cloned repository can't loosen
  them or put your name on agent commits
- keep every private key off disk: each session's signing key and the
  agents' certificate authority exist only in the service's memory (a new
  authority at each start), and are never written anywhere. A private key
  an earlier version stored in a file stops the service until it's gone;
  the installer deletes it, after asking
- keep sessions apart: each session has its own key, with a 12-hour
  certificate for its own principal
- refuse agent commits on protected branches (`main` and `master` by
  default, compared without case, so `MAIN` too), checked on every commit,
  every git run that makes commits, and every signature (an agent's merge
  on `main` makes no commit)
- stop runaway commit loops (and oversized diffs, if you set a size limit), and block edits to CI
  workflows and key files
- fail closed: for a commit through the wrapper, if the service is down or
  there's no lease, the commit is refused, never signed some other way;
  for an agent's merge, rebase and the like, a commit it needs to make
  fails. A `config.toml` the service can't read, or with a key it doesn't
  know (a misspelt `approval`), stops it with a message naming the file and
  key, instead of falling back to the defaults
- with `approval = "device-owner"`, ask you before the first signed commit
  that no lease covers, with Touch ID or your login password on macOS

It does not, yet:

- prove which agent made a commit. Identities are claims made by processes
  running as your own user: any program can set `CLAUDECODE` or
  `AGENT_SIGN_AGENT_NAME`, so one agent can sign as another. That's
  attribution, not a security boundary, until agents run under their own
  OS accounts
- stop an agent running as your user from reading the service's memory
  (with a debugger), asking the service over its socket for a certificate
  for another agent's principal, editing agent-sign's config, starting its
  own service, or calling the real git directly. None of these reaches your
  email: the trust lines only cover `@agents.local`
- apply its rules to a commit that turns signing off (`--no-gpg-sign`, or
  `commit.gpgsign = false` for that command or repository): it goes to
  plain git unsigned, as calling the real git directly would, and may land
  on `main` (protected branches cover signed agent commits)
- stop an agent from naming another author on purpose (`--author`, or
  amending someone else's commit, which keeps its author)
- sign the commits git makes for an unmarked command with no terminal (an
  editor's merge button, a script): agent-sign can't tell it from an
  agent's, so those are unsigned, with git's own names, and never reach your
  signer. An explicit request to sign a tag (`tag -s`) or a lone
  `commit-tree -S` from an agent fails. Agents can still check SSH and
  OpenPGP signatures (X.509 ones read as unchecked)
- catch git that runs without the wrapper's settings: an agent calling the
  real git directly, a tool that clears the environment (`env -i`), or a
  hook in a repository on the same machine that the agent pushes to (git
  clears the settings at that boundary). The installer closes most of that
  by routing your own signing: your `gpg.ssh.program` becomes
  `~/.agent-sign/bin/agent-ssh-sign`, with your signer as `fallback_program`
  in `config.toml` (`agent-sign doctor` says whether it's in place). Your
  commits still go to your signer, and a signing request from a process an
  agent marked (`CLAUDECODE`, `GEMINI_CLI`, `CODEX_THREAD_ID`,
  `CODEX_SESSION_ID`, or the wrapper's own `AGENT_SIGN_AGENT_RUN`) is
  refused. An unmarked program that clears its environment still reaches
  your signer. This covers SSH signing (`gpg.format = ssh`) only: if you
  sign with OpenPGP, a hook in a local repository an agent pushes to can
  still reach your `gpg`
- show agents' commits as Verified on GitHub, which doesn't check SSH
  certificate signatures
- recognise an agent running in a real terminal (a terminal pane) unless
  it marks its commands, as Claude Code, Gemini CLI and Codex do (an
  unmarked one looks like you), or an agent with no terminal that doesn't
  say it's one (its commits are left to git, unsigned)
- with `approval = "device-owner"`: stop an agent running as your user from
  approving its own lease by other means than the prompt (editing the
  config, starting its own service, typing your login password), or approve
  anything on Linux, which has no platform authenticator yet

These are the next steps; see [docs/RELEASE_CHECKLIST.md](docs/RELEASE_CHECKLIST.md).

## Where it's going

This is planned, not built.

- **Agents off your own computer.** agent-sign is meant for agents that run
  on servers and in cloud sessions, each under its own account, not as you.
  That turns its identities from labels into a boundary: an agent then
  can't reach your keys or claim to be you.
- **The authority in a vault.** Certificates are made through a small
  interface (`CertificateIssuer`). Today its only implementation keeps the
  authority in the service's memory. The next is OpenBao's SSH engine, so
  that no machine holds the authority, and cloud sessions with no
  long-running service can get certificates too.
- **Signing only what you committed to.** Before signing, agent-sign will
  ask a decision service whether this commit, by this agent session,
  follows from what you approved (your plan, its scope). It refuses
  anything that doesn't. The decision comes from a verified logic (the
  NMMS sequent calculus in [lean-nmms](https://github.com/taylor-made-labs/lean-nmms)),
  with a model trained on your own feedback only where judgment is needed.
  An agent identity comes first because every such check needs to know who
  acted.
- **Verified on GitHub too.** Agents push and sign through their own GitHub
  account rather than yours.

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
on those). Nothing asks you anything. Check the commit:

```sh
git log -1 --format='%an <%ae> | %cn <%ce>'
git log -1 --show-signature
```

The first shows the agent as author and committer; the second shows a Good
signature for its principal, through the block the installer put in your
allowed-signers file (see [Trusting agents' signatures](#trusting-agents-signatures)).

In a brand-new repository, make the first commit yourself (agents can't
commit on `main`), then have the agent work on a branch. When a commit is
refused, the agent sees why; the messages are listed in
[docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md).

## Approving leases yourself

With `approval = "device-owner"` under `[security]` in
`~/.agent-sign/config.toml` (restart the service after setting it), the
first agent commit that no lease covers asks you, in a prompt from the Mac
itself that names the program "agent-sign" and says what you're approving
(the layout is the system's):

```
agent-sign is trying to let an agent sign commits on branch “feat/parser” in
project (~/code/project), until merged.

Touch ID or enter your password to allow this.
```

Touch ID, or your login password, approves it; cancelling refuses, as does
a timeout (five minutes). agent-sign shows no dialog of its own, because a
program that can click one (a computer-use agent, a System Events script)
could approve a lease for itself, and none can answer Touch ID. Commits that
ask while it's open wait for the same answer; only one prompt is shown at a
time; after a refusal no new one opens for a while (60 seconds at first,
doubling with each refusal in a row); at most 4 requests wait at once. A
request is only asked about if its repository is a real git working tree,
its path and branch have no control or invisible characters, and the branch
is the one checked out and a plain name (letters, digits and `/ - _ .`), since
an agent picks what goes into the prompt's sentence. Approving doesn't change
whose identity signs: the commits are still the agent's.

The installer runs the service from a small app bundle
(`~/.agent-sign/agent-sign.app`) named "agent-sign" so that the prompt says
that; started bare, macOS names the prompt after the program, `agent-signd`.

## Linux

With the default `approval = "none"`, agent commits work on Linux as on
macOS. Linux can't approve leases interactively yet, so with
`approval = "device-owner"` the service refuses every request there (unless
`auto_approve` is on): agent-sign has no platform authenticator for Linux,
and the two ways it could have asked anyway both let an agent approve for
itself: a dialog any program can click, and a terminal prompt, which an
agent can drive through a pseudo-terminal of its own or by typing into
yours. Approving from another device, such as a passkey on your phone, is
the planned next step and belongs to the agentic-credentials work; it isn't
built.

## Leases

| Setting in `~/.agent-sign/config.toml`, under `[security]` | Default | What it does |
|---|---|---|
| `approval` | `"none"` | `none`: leases are granted without asking, and the service's log records each grant and which agent used it. `device-owner`: you approve each lease with Touch ID or your login password ([how](#approving-leases-yourself)). A value agent-sign can't read stops the service rather than being ignored, as does any key or table it doesn't know, or a `config.toml` it can't read; the service logs the mode it's using when it starts. |
| `lease_mode` | `"identity"` | `identity`: until its work is finished (see below). `timed`: also no later than `default_lease_duration` after approval. |
| `end_after_idle` | `"7d"` | A lease ends after this long with no agent commit under it, so one whose branch is never merged or deleted still ends. `"none"` turns this off. A value agent-sign can't read stops the service rather than being ignored. |
| `max_lease_ceiling` | `"none"` | Longest life of an `identity` lease, such as `"7d"`. It also shortens leases already granted. A value agent-sign can't read stops the service rather than being ignored. |
| `default_lease_duration` | `"2h"` | Life of a `timed` lease. |
| `allow_branch_switching` | `false` | With `lease_scope = "branch"` (the default), `false` limits a lease to the branch it was approved on, in the repository it was asked from: the narrowest approval, and the default for safety. `true` makes it cover every unprotected branch of the repository, following the agent between them, and the prompt then says "any unprotected branch". `lease_scope = "repo"` always covers every unprotected branch. |
| `block_branches` | `["main", "master"]` | Branches no lease covers (a name, or a prefix ending in `*`), compared without case. A repository's `.agent-sign.toml` can add to them. |
| `allow_main_branch` | `false` | `true` turns that protection off. |
| `max_commits_per_minute` | `10` | Agent signatures per repository per minute, counting every commit an agent's merge, rebase and the like makes. |
| `refusal_backoff` | `"60s"` | After an approval prompt is refused, no new one opens for this long, doubling with each refusal in a row (up to an hour); an approval resets it. `"none"` turns it off. A value agent-sign can't read stops the service. |

Every lease also ends with its work: when the branch it was approved for is
merged into `main` or `master` (counting only commits made since the
approval, and a merge on GitHub once you've fetched it) or deleted. Detached
HEAD has no branch to follow, so there only the other endings apply.

With `approval = "device-owner"`, there is no prompt choice to widen a lease further: earlier versions offered
"every repository under a folder" and "every repository on this computer" in
a dialog, and those are no longer offered: the approval is one prompt with
nothing to choose. A lease of either kind approved earlier still works
(while `allow_branch_switching` is on, which they need to cover every branch)
and can be revoked; `agent-sign leases` and `agent-sign doctor` point them out. To avoid a prompt for each new repository on a machine
you trust, `auto_approve` grants every lease without asking (see
[Headless machines](docs/INSTALL.md#headless-machines-servers-containers-ci)).

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
agent-sign deny --all        # answer no to all of them and close their prompts
agent-sign status            # is the service running
agent-sign doctor            # check the whole setup, with fixes
```

## Uninstall

```sh
./scripts/uninstall.sh
```

It removes the service, the `PATH` and editor changes, and agent-sign's
block (and an earlier version's agent key line) from `allowed_signers`; puts
your own signer back as git's `gpg.ssh.program` (from `fallback_program`, or
unset if that was git's default, `ssh-keygen`); and deletes `~/.agent-sign`.
It leaves git's `gpg.ssh.allowedSignersFile` setting, if the installer set
it.
If an earlier version added the shared agent key to your GitHub account,
remove it from your signing keys yourself.

## Upgrading

Run the installer again from the new version. Your leases and config carry
over. Changes to know about:

- **Per-agent identities.** Agents no longer sign with the shared agent key
  (`~/.agent-sign/keys/agent_ed25519`): each signs as itself, through an
  agents' certificate authority the service makes in memory at each start.
  The installer adds the trust block to your allowed-signers file, and
  deletes the old key's private half (stored unprotected, so it counts as
  exposed), after its usual question; its public half stays, so commits it
  already signed still verify while its line is in your allowed-signers
  file. While that line is there, the installer prints the exact commands
  to remove it, under your email, and the key from your GitHub account (it
  made agent commits look like yours); it runs neither.
- **No private key on disk.** An agents' authority key an earlier build of
  this change kept in `keys/agents_ca_ed25519` is deleted by the installer
  (after asking); the service won't start while it's there. Its public key
  isn't trusted either: a key that was ever stored unprotected counts as
  exposed.
- **Your own signing is routed through agent-sign.** The installer sets
  your global `gpg.ssh.program` to `~/.agent-sign/bin/agent-ssh-sign` and
  keeps what it was as `fallback_program`; `uninstall.sh` puts it back.
- **Unmarked commits are git's own.** A commit with no terminal and no agent
  mark (your editor's button, or an agent that doesn't say it's one) is no
  longer signed as an "unidentified agent": it's unsigned, under git's own
  names, even when it asks to be signed (it says so in one line). Start an
  unmarked agent with `AGENT_SIGN_AGENT_NAME` to have its
  commits signed as it.
- **A repository's `.agent-sign.toml` only tightens.** It can add
  `forbidden_paths` and `block_branches` and lower `max_diff_lines`;
  anything else in it, `max_commits_per_minute` included (the service
  counts the rate and reads only your own config), is ignored, with a
  warning.
- **`config.toml` is read strictly.** A key or table agent-sign doesn't know,
  or a file it can't read, stops the service with a message naming it. Every
  key an earlier installer wrote is still accepted.
- **No approval by default.** Set `approval = "device-owner"` to keep being
  asked.
- **Agent commits are always the agent's.** An agent's signed commits are
  authored and committed by the agent in every attribution mode: `split`
  and `alias` no longer change the names (they still load), and `trailers`
  only adds its trailers.
- `allow_branch_switching` defaults to `false`, so a lease that followed the
  agent between branches (approved under the old default) covers only its
  own branch, until you set `allow_branch_switching = true` in `config.toml`
  and restart the service.

What changed since the first agent-sign: [docs/MIGRATION.md](docs/MIGRATION.md).

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
