# agent-sign

**AI agents commit and sign as themselves, never as you.** Each agent
session gets its own short-lived certificate (12 hours), so its commits are
authored, committed and signed by that agent's own identity, such as
`Claude Code <claude-code.1a2b3c4d@agents.local>`. `git log` tells agent work
from yours, nothing an agent makes is signed with your key, and nothing asks
you anything. It runs on macOS and Linux, laptops and servers alike.

- **No prompts for you.** Agent commits don't stop for your fingerprint;
  the service logs which agent committed where. If you want to approve
  each repository's agent work yourself, `approval = "device-owner"` brings
  back one Touch ID prompt per **lease** (one branch of one repository,
  until it's merged; see [Leases](#leases)). That option is macOS only.
- **One block of trust.** A marked block in your allowed-signers file trusts
  agents' signatures for agents' names only (`*@agents.local`, or
  `*@<machine>.agents.local` once you [name the machine](#naming-the-machine)),
  never your email; the installer adds it and runs `agent-sign trust install`,
  the only thing that writes it (run it again after the service restarts).
  Then `git log --show-signature` shows a Good signature for the agent that
  made each commit.
- **Only names you allow.** Well-known agents are allowed out of the box;
  any other agent name has to be listed first, and your own name never can
  be ([Allowed agent names](#allowed-agent-names)).
- **No private key on disk.** Each agent session's signing key, and the
  certificate authority that vouches for it, live only in the service's
  memory, never in a file. On Linux, other programs of your account can't
  read that memory either.
- **Your own signing is routed.** The installer points git's
  `gpg.ssh.program` at agent-sign's signing program, which passes your own
  signatures on to your signer (1Password, a hardware key, `ssh-keygen`)
  as before, and refuses any signing request from an agent's process.
  Commits you make in a terminal are signed as you, as before.
- **Limits.** While agents run in the same OS account as agent-sign (the
  usual setup today), a signature names the agent that agent-sign was told
  about, which a misbehaving agent can lie about. See
  [What a signature proves](#what-a-signature-proves).

Why: if you sign your git commits with a hardware key, 1Password, or a
passkey, an agent making twenty small commits stops twenty times for your
fingerprint, and the usual workarounds (turning signing off, or handing the
agent your key) are worse. agent-sign also adds local guardrails for agents
that cooperate: no agent commits on `main`, no changes to CI workflows or
key files, a rate limit.

**Status: pre-release (0.1.0).** Its author uses it daily on macOS for every
agent commit, and Mac support stays first-class. On Linux it builds and
passes its tests, runs as a systemd user service, and is now being put to
real use on servers (see [Linux](#linux)). There are no downloadable
releases yet: you build it from source. When there are, each archive carries
signed build provenance; [docs/RELEASE_CHECKLIST.md](docs/RELEASE_CHECKLIST.md#checking-a-download)
shows how to check it.

## How it works

1. The installer puts a `git` wrapper (`agent-git`) first on your shell's
   `PATH`. Agents started from that shell run `git` as usual. (An agent
   started some other way, such as an app launched from the Dock or a
   background service on a server, may not get that `PATH`: check with
   `command -v git` from the agent, and see
   [Agents started by background services](#agents-started-by-background-services).)
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
4. If the branch isn't protected, the agent's name is allowed, and the
   commit rate is under its limit, the commit is signed through git's own
   SSH signing (`agent-ssh-sign`) as the agent's own identity: the service
   gives each agent session a signing key that lives only in its memory,
   with a 12-hour OpenSSH certificate from the agents' certificate authority
   naming the agent's principal. The authority is made in the service's
   memory each time it starts. A commit whose committer date falls outside
   that certificate's validity (from 5 minutes before it was issued to 12
   hours after) isn't signed at all: git checks a certificate at the
   commit's own date, so a backdated or postdated commit must not carry a
   signature. The service disables ordinary core dumps before it makes any
   private key, and, on Linux, makes its memory unreadable by other programs
   of the same account; it never writes a private key anywhere. Swap, and
   the administrator (root), remain outside its control. In every
   attribution mode the agent is both author and committer.
5. Commands that make commits by themselves (`merge`, `pull`, `rebase`,
   `cherry-pick`, `revert`, `am`, aliases for those, and shell aliases) are
   signed the same way for an agent that says who it is: the wrapper gets a
   token for that one git run, so every commit it makes is signed as the
   agent and committed by it (new commits, such as a merge or a revert, are
   also authored by it; replayed ones keep their author). A token signs only
   in the repository and on the branch it was issued for: the signing
   program tells the service where each commit is going, and a run that
   moves elsewhere (`git rebase feature main` from `feature`, or a `cd` into
   another repository) gets nothing signed there. The service also checks
   the actual candidate tree and message against local rules before every
   signature. Each direct commit or Git run counts once against the rate limit.
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
| any other | `AGENT_SIGN_AGENT_NAME="Aider"` (overrides the above) | `AGENT_SIGN_SESSION_ID` (overrides the above) |

The identity's email, its **principal**, is `<tool>.<session>@agents.local`,
where `<session>` is the first 8 hex characters of the SHA-256 of the
session id (`nosession` when the agent gives none): `claude-code.1a2b3c4d@agents.local`.
On a [named machine](#naming-the-machine) it is
`<tool>.<session>@<machine>.agents.local`. Two sessions get two principals,
and two tools never share one. A name in `AGENT_SIGN_AGENT_NAME` becomes the
tool part, its **slug**: lowercase letters and digits joined by single `-`
("My Bot (beta)" is `my-bot-beta`). The service certifies nothing else: no
principal it signs for has any other shape, and the slug must be an
[allowed agent name](#allowed-agent-names).

The name itself becomes the author name on the agent's commits, so it must
be **printable ASCII**: letters A-Z and a-z, digits, spaces and punctuation
("My Bot (beta) #2" is fine). Any other character is refused, and the
agent's commits get no signature ("agent identity refused: the display name
... has characters that aren't printable ASCII"). Letters from another
alphabet can look exactly like a person's name in `git log`: "Taylor" with
its "a" swapped for the Cyrillic letter a (U+0430) reads as Taylor, and
Unicode normalisation can't tell them apart. Name the agent in plain ASCII instead.

A commit with no terminal and no mark at all (your editor's commit button,
a GUI, or an agent that doesn't say it's one) is left to git: unsigned,
under git's own names, with nothing asked. agent-sign can't tell it from
your own, so it never puts an agent's name on it. If it asked to be signed
(`-S`, or your `commit.gpgsign = true`), it's still made unsigned rather
than failing, and one line says why: commit in a terminal to sign it as
yourself.

### Allowed agent names

The service gives a certificate only to agent names it allows:

- **Built in**, recognised by their own marks: `claude-code`, `codex`,
  `gemini-cli`.
- **Widely used agents**, which have no mark of their own, so you name them
  with `AGENT_SIGN_AGENT_NAME`: `aider`, `antigravity`, `cline`, `copilot`,
  `cursor`, `opencode`, `windsurf`. They need no setting.
- **Any other name**: list its slug under `[identity]` in
  `~/.agent-sign/config.toml`, then restart the service:

  ```toml
  [identity]
  allowed_agents = ["my-bot-2"]   # for AGENT_SIGN_AGENT_NAME="My Bot 2"
  ```

  An entry must be a slug (lowercase letters and digits in words joined by
  single `-`), or the service won't start. Until a name is listed, its
  commits are refused with "agent identity refused: `my-bot-2` is not an
  allowed agent name".

**A person's name is never allowed.** Without this rule an agent could
name itself after you and get a Good signature under your name, which is
what per-agent identities exist to prevent. These names are refused, as a
whole or any word of them (as a slug), whatever `allowed_agents` says:

- `root`, `admin` and `administrator`, with nothing configured;
- your name and the part of your email before the `@`, from `[human]` in
  `config.toml` (or git's `user.name` and `user.email` when `[human]`
  doesn't set them; on a server whose agents set `user.name` themselves,
  git names no person, so agent-sign never relies on it);
- the people you list in `config.toml`, for anyone whose name agent-sign
  can't know otherwise:

  ```toml
  [identity]
  people = ["Taylor", "Dana Example"]
  ```

  `./scripts/install.sh --person Taylor` adds one (repeat it for more);
  installing again with the same name leaves the file as it is;
- the people's accounts on the machine: the login name and the words of
  the full name of every account with a login shell and a person's user id
  (1000 and up on Linux, 501 and up on macOS), except the account agent-sign
  runs as. The service reads them once, when it starts, from the system's
  account database. If it can't read them, it doesn't start.

Names are compared without regard to case and after Unicode NFKC
normalisation, on both sides: "Taylor", "TAYLOR" and fullwidth "Ｔａｙｌｏｒ"
are the same name, wherever they are written.

If `allowed_agents` lists one of the first three, the service refuses to
start and says which entry to remove. The service also refuses each
certificate for any of them it knows without git (everything above but
git's names), accounts included ("agent identity refused:
`taylor` is the login name of the account taylor on this machine ...").
The built-in and widely used agents' names are the tools' own, and are
never refused for matching a word of someone's name.

`[identity]` is read only from your own `config.toml`: a repository's
`.agent-sign.toml` can't set it.

### Naming the machine

If you run agent-sign on more than one machine, give each one a name:

```toml
[identity]
machine = "build-1"
```

A machine name is 1 to 63 lowercase letters and digits, in words joined by
single `-` (`build-1`, `pi-4`, `my-laptop`): no dots, capitals or spaces.
agent-sign never takes it from the computer's own host name, which often
breaks these rules and can change.

With a name set:

- agents' principals say where the agent ran:
  `claude-code.1a2b3c4d@build-1.agents.local`;
- the machine's trust lines cover only its own agents
  (`*@build-1.agents.local cert-authority,...`), and its service certifies
  only names in that domain. So if you gather several machines' trust lines
  into one allowed-signers file, to check commits made on all of them, no
  machine can vouch for another machine's agents. Without names, every
  machine's authority is trusted for every `@agents.local` name.

Leave it out and everything stays `@agents.local`, as before.

**Set it before the service first starts.** The installer does that for
you: `./scripts/install.sh --machine build-1` writes it into `config.toml`
before it starts the service (see [docs/INSTALL.md](docs/INSTALL.md)). If you
set it later, by hand, restart the service at once: the git wrapper reads the
setting at every commit, the service only when it starts, and until both
agree agent commits are refused ("not in this machine's agents' domain").
Setting, changing or removing the name later also re-scopes every earlier
authority's trust line to the new domain, so **agent commits already signed
under the old domain (such as `@agents.local`) stop verifying** under the
machine's lines.

### Trusting agents' signatures

git checks SSH signatures against the file `gpg.ssh.allowedSignersFile`
names. The installer adds a marked block there that trusts every agent's
signature, for its own principal only:

```
# agent-sign: agents' certificate authorities, managed; do not edit
*@agents.local cert-authority,namespaces="git" ssh-ed25519 AAAA...
# agent-sign: end of agents' certificate authorities
```

(On a named machine the lines start `*@<machine>.agents.local`.)

The service makes a new certificate authority, in memory, each time it
starts, and keeps it for as long as it runs. **A start never changes what
verifiers trust**: only `agent-sign trust install` does. It adds the
running service's authority to `~/.agent-sign/keys/agents_cas.pub` (with
the date; earlier ones stay) and rewrites the lines between those two
markers with one line per recorded authority (what `agent-sign trust-line`
prints), so commits certified before a restart still verify. It never
changes anything outside the markers. The installer runs it once the
service is up, so a fresh install needs nothing more; after the service
restarts (a reboot, an upgrade), run `agent-sign trust install` again, and
`agent-sign doctor` says when it's needed. Only one service runs per state
folder: a second `agent-signd` for the same `~/.agent-sign` stops at once,
without touching it.

Then `git log --show-signature` shows
`Good "git" signature for claude-code.1a2b3c4d@agents.local`. Each line
trusts an agents' authority for agents' principals and git signatures
only: it can't vouch for your email or anyone else's. GitHub doesn't check
signatures made with SSH certificates, so agents' commits show there as
Unverified, which is accurate: they aren't yours.

The wrapper tells you from an agent this way: if both its input and output
are a terminal, and no agent has marked the command as its own (Claude Code,
Gemini CLI and Codex do), it's you, and it steps aside and runs your normal
git with your normal signing. Anything an agent marks (or names with
`AGENT_SIGN_AGENT_NAME`) is that agent's, signed as it. Anything else with no
terminal (which may be your own editor) is left as git makes it, unsigned,
under git's own names.

## What a signature proves

**Today, on servers and Macs alike, an agent's name is claimed by a process
in a shared account, not proven.** Every agent and agent-sign run in one OS
account, so any process in it can claim to be any agent. Each certificate
says so in its key id ("`<agent's name>` on `<host>`, claimed by a process in
a shared account"), and so does `agent-sign doctor`. This is not an accepted
gap: making the name proven, with the identity coming from the trusted
program that started the agent or from your approval, and agent-sign running
in an OS account of its own, is agent-sign's top-priority work in progress.

A Good signature for `claude-code.1a2b3c4d@build-1.agents.local` proves
that **agent-sign on that machine, or something running in the same OS
account as agent-sign, signed that commit for that agent name**, with a
committer date inside the certificate's 12 hours. It never proves anything
about you: agents' trust lines can't vouch for your email.

It doesn't prove which program really made the commit. If agents run in
the same OS account as agent-sign, which is how agents run on a laptop
today and how most servers are set up, a misbehaving agent could:

- **claim another agent's name**: set `CLAUDECODE` or
  `AGENT_SIGN_AGENT_NAME` itself, or ask the service's socket for a
  certificate under any allowed name;
- **make the machine trust a key of its own**: add a key to agent-sign's
  list of authorities (`~/.agent-sign/keys/agents_cas.pub`), edit your
  allowed-signers file, or replace agent-sign's programs or settings, so
  that signatures it made itself verify on that machine.

Agents' names are labels the agents give themselves. `cursor`, `aider` or
`my-bot-2` in a signature means a process asked for that name, not that
Cursor, Aider or your bot made the commit: the widely used names are
allowed by default only so their users need no setting.

On Linux, other programs of the same account can't read agent-sign's
memory, so an agent can't copy the authority or a session's key out of the
running service. (The administrator, root, still can.) On macOS, what
another program of your account can read is up to macOS: agent-sign adds no
protection of its own there, and its service doesn't use the hardened
runtime yet, so a debugger that macOS lets attach can read it.

**In progress, top priority:** running agent-sign in an OS account of its
own, which agents can't touch, on macOS and Linux alike, as an option beside
today's zero-setup default, with each agent's identity taken from the
trusted program that started it or from your approval. A signature would
then prove that agent-sign itself signed it, for an agent it can tell
apart, under the rules you set. Until each agent is also isolated from the
others, agents sharing one account could still claim each other's names.

**Anything that decides must use `agent-sign verify --format json --allowed-signers <file>` and never git's own verdict** (`%G?`, `git log --show-signature`, `git verify-commit`): a merge gate, a server-side check, a hook, a release script. git checks an SSH certificate by handing `ssh-keygen` the commit's date as local time with no zone (`-Overify-time=YYYYMMDDHHMMSS`), and OpenSSH 10.0p2 (Debian 13, the Raspberry Pi) misreads that whenever the clock zone isn't UTC: it takes the local time as UTC, so the certificate's window is shifted by the zone's offset, and git can call a signature unverified that is good, or the other way round. OpenSSH 10.2p1 reads it correctly. `agent-sign verify` gives `ssh-keygen` the date as UTC with a `Z` and is unaffected, and it also refuses a certificate from an authority the trust file doesn't hold and a commit dated outside its certificate's window whatever git says. A gate reads `verify --format json` (exit 0 only when verified and attested, 1 for any other verdict, 2 when it can't run) and passes the trust file itself with `--allowed-signers <file>` (an absolute path outside the checkout being verified; a relative one is read from the current folder, which is that checkout, and a global `includeIf "gitdir:"` is not followed because the verifier reads git's global config from outside any repository): the verifier never takes the trust file from the repository's own git config, which the session being checked can write, and it ignores `refs/replace/*`, so a pushed replace ref can't make one commit read as another, and it never lets git fetch a missing object lazily, so a repository's own config can't make it run a command. `agent-sign doctor` warns when git on a machine is affected; running git with `TZ=UTC`, or a newer OpenSSH, makes git's own check read right too.

## What it protects against, and what it doesn't

agent-sign catches mistakes by an agent that cooperates. It is **not** a security
boundary against an agent that tries to get around it, while the agent runs
in the same OS account as agent-sign (see [What a signature proves](#what-a-signature-proves)).

It does:

- keep your own signing key away from agents (they never talk to it), and
  ignore an agent's token that leaks into your own terminal
- sign each agent's commits as that agent, never as you: its own name and
  principal as author and committer whatever the config says, and a
  signature that git reports as Good for that principal only under the
  trust lines
- certify only [allowed agent names](#allowed-agent-names), never one
  matching a person's name (reserved names, `[human]`, `[identity] people`,
  and the people's accounts on the machine), and on a
  [named machine](#naming-the-machine) only that machine's agents
- refuse to sign a commit whose committer date lies outside its signing
  certificate's validity
- let a repository's `.agent-sign.toml` only tighten the rules (add
  forbidden paths and protected branches, lower `max_diff_lines`); anything
  else in it is ignored, with a warning, so a cloned repository can't loosen
  them or put your name on agent commits
- keep every private key off disk: each session's signing key and the
  agents' certificate authority exist only in the service's memory (a new
  authority at each start), and are never written anywhere. A private key
  an earlier version stored in a file stops the service until it's gone;
  the installer deletes it, after asking
- on Linux, keep other programs of the same account from reading the
  service's memory
- keep sessions apart: each session has its own key, with a 12-hour
  certificate for its own principal
- refuse agent commits on protected branches (`main` and `master` by
  default, compared without case, so `MAIN` too), checked on every commit,
  every git run that makes commits, and every signature (an agent's merge
  on `main` makes no commit). With that protection off (`allow_main_branch`
  or `agent-signd --allow-main`; off by default), a lease for `main` or
  `master` itself ends only once its new commits reach `origin/main` as
  last fetched (or another of `main`, `master` and `origin/master`), or by
  the idle backstop or a revoke
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

- prove which agent made a commit, or stop an agent in agent-sign's own OS
  account from getting around it: claiming another agent's name, asking the
  service over its socket for a certificate under any allowed name, making
  the machine trust a key of its own, editing agent-sign's config, starting
  its own service, or calling the real git directly (see
  [What a signature proves](#what-a-signature-proves)). None of these
  reaches your email: the trust lines only cover agents' names
- on macOS, stop another program of your account from reading the service's
  memory with a debugger, where macOS allows it (no hardened runtime yet)
- tell whether an agent's name, such as `cursor`, is true: names are labels
  the agents give themselves
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

- **agent-sign in its own account (top priority, in progress).** An option
  to run agent-sign as an OS account of its own that agents can't touch, on
  macOS and Linux, with each agent's identity from the trusted program that
  started it or from your approval, so an agent's name is proven rather than
  claimed (see [What a signature proves](#what-a-signature-proves)). The
  zero-setup default stays as it is.
- **The authority in a vault.** Certificates are made through a small
  interface (`CertificateIssuer`). Today its only implementation keeps the
  authority in the service's memory. The next is OpenBao's SSH engine, as
  an option, so that the authority lasts across restarts, each machine can
  check the others' agents, and cloud sessions with no long-running service
  can get certificates too.
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
with Rust 1.98.1 (rustup picks that exact version, the one the project pins in
`rust-toolchain.toml`):

```sh
git clone https://github.com/taylor-made-labs/agent-sign.git
cd agent-sign
cargo build --release --locked
./scripts/install.sh                  # or: ./scripts/install.sh --machine build-1
```

Then open a new terminal and check the setup:

```sh
agent-sign doctor
```

## Servers: system mode

On a shared server, agent-sign can run in accounts of its own, so that the
agents' account can't change it: its service and launcher run as `agent-sign` and
`agent-launch`, each launched session runs in an account of its own, agents'
certificates come from an authority kept in OpenBao, and the only trust file
that counts is root's. A one-time script, `scripts/sitting/agent-sign-sitting.sh`,
sets it up; without `/etc/agent-sign/system.toml`, nothing changes. It is built
and tested but not yet installed on a real machine. See
[docs/INSTALL.md](docs/INSTALL.md#servers-system-mode) and
[docs/system-mode.md](docs/system-mode.md).

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

agent-sign works on Linux as on macOS, with the default `approval = "none"`:
each agent session gets its own certificate and signs as itself, with no
prompts. This section is about running it on a server, where agents are
often started by background services rather than from your shell.

### The service

The installer installs `agent-signd` as a **systemd user service**
(`~/.config/systemd/user/agent-signd.service`), enables it and starts it.
A user service runs in your account, never as root, and only while your
user's service manager is running: normally while you're logged in. On a
server you log out of, turn on **lingering**, so your services start at boot
and keep running with nobody logged in:

```sh
loginctl enable-linger "$USER"
```

Some systems let only an administrator do this
(`sudo loginctl enable-linger <user>`). Restart the service with
`systemctl --user restart agent-signd`; its log is
`journalctl --user -u agent-signd`.

You can install over a non-interactive `ssh` command
(`ssh build-1 'cd agent-sign && ./scripts/install.sh --yes'`). Such sessions
don't always set `XDG_RUNTIME_DIR`, which `systemctl --user` needs; the
installer then sets it to `/run/user/<your user id>` itself. See
[docs/INSTALL.md](docs/INSTALL.md#servers-and-non-interactive-installs).

### Several machines

Give each machine its own name when you install, so agents' names say
where they ran and each machine vouches only for its own agents:

```sh
./scripts/install.sh --machine build-1
```

See [Naming the machine](#naming-the-machine) for why to set it before the
first start.

### Agents started by background services

The installer puts the wrapper first on `PATH` in your shell profiles. An
agent started by a background service (a systemd user unit that runs agents
or agent sessions) never reads those profiles, so it would run the real
`git`, and its commits wouldn't be signed. Name each such unit:

```sh
./scripts/install.sh --launcher-unit my-agent-runner.service --launcher-unit other.service
```

(The option is for Linux only; macOS has no such units.)

For each one, the installer writes a small systemd **drop-in** (an extra
settings file for that unit,
`~/.config/systemd/user/<unit>.d/agent-sign.conf`) that puts
`~/.agent-sign/bin` first on the `PATH` it starts with. It never restarts the
unit itself, since that would stop the agents it is running: it prints the
command instead. Restart each unit when no agent it started is mid-task:

```sh
systemctl --user restart my-agent-runner.service
```

A unit that sets its own `PATH` gets a warning first, since the drop-in
replaces it. A unit that sets `PATH` in an environment file
(`EnvironmentFile=`) gets a stronger one: systemd lets such a file override
the drop-in, so its agents wouldn't get the wrapper at all until you put
`~/.agent-sign/bin` first on `PATH` in that file (or take `PATH` out of it).

This covers your own user units, not system-wide ones.
`./scripts/uninstall.sh` removes the drop-ins agent-sign wrote and leaves
any of your own beside them.

### Approval on Linux

Linux can't approve leases interactively yet, so with
`approval = "device-owner"` the service refuses every request there (unless
`auto_approve` is on): agent-sign has no platform authenticator for Linux,
and the two ways it could have asked anyway both let an agent approve for
itself: a dialog any program can click, and a terminal prompt, which an
agent can drive through a pseudo-terminal of its own or by typing into
yours. Approving from another device, such as a passkey on your phone, is
planned, not built.

### Memory

On Linux the service makes itself unreadable by other programs of the same
account before it makes any private key: they can't read its memory or
attach a debugger to it, not even the program that started it. Only the
administrator (root) can. If the service can't turn this protection on, it
doesn't start, rather than make keys other programs could read.

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
agent-sign notices finished work at that lease's next agent commit, when
the leases are listed (`agent-sign leases`), or within about a minute,
whichever comes first. An agent commit checks only its own lease, so
commits stay fast however many leases are open.

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
agent-sign trust-line        # the allowed-signers lines for this machine's agents
agent-sign trust install     # trust the running service's authority (after a restart)
agent-sign verify [--format json] [--allowed-signers <file>] <rev>  # check a commit's signature, then say how the agent's name was established
```

`agent-sign verify` checks the signature against a trust file the verifier
chooses, with the system's `ssh-keygen` by absolute path (never one found on
`PATH`, never git's signing program), and only when it verifies prints
`attestation: ...`: "approval" for a commit signed on a commit approval, and
"claimed by a process in a shared account" for a certificate that records
nothing (see `docs/caller-identity.md`). Otherwise it prints
`not verified: <why>`. It exits 0 only for a commit that is verified and
attested (a launcher or an approval), 1 for every other verdict (a claimed or
unattested commit prints its `verified:` lines and the merge note, and still
exits 1), and 2 when the check cannot run. What the commit controls (the
committer's email, a certified name) is printed with control characters
written out, never raw.

The trust file, in this order, and never the repository's own config (a
session can write `.git/config`, a worktree's config or an `includeIf`, and
with it name an authority it made itself):

1. `--allowed-signers <file>`, which a gate should pass.
2. In system mode (`/etc/agent-sign/system.toml` exists), always
   `/etc/agent-sign/allowed_signers`, whatever any git config says.
3. Otherwise `gpg.ssh.allowedSignersFile` from git's **global** config, else
   its **system** config (read from outside any repository, with
   `GIT_CONFIG_COUNT`, `GIT_CONFIG_PARAMETERS` and the like removed). It must
   be an absolute path to a readable file.

### Merge gates (`--format json`)

A merge step, a hook or a script calls `agent-sign verify --format json <rev>`
and reads exactly one JSON object from stdout:

```json
{"verified": true, "attested": true, "attestation": "launcher", "signer": "name@host.agents.local", "reason": "ok", "detail": "...", "trust_file": "/etc/agent-sign/allowed_signers", "author": "name@host.agents.local", "author_matches_signer": true}
```

- `verified`: the signature checked out against the allowed-signers file.
- `attested`: verified, and a launcher or an approval established the name.
- `attestation`: `launcher`, `approval`, `unattested`, `claimed` or `none`.
- `signer`: the committer's principal when verified, else `null`.
- `reason`: `ok`, `unsigned`, `unattested`, `claimed`, `untrusted_authority`,
  `outside_window`, `bad_signature`, `no_trust_file` or `error`.
- `detail`: the sentence the human output would say.
- `trust_file`: the file the verdict was checked against (`null` when there
  was none). Added later than the other six; read the six as before.
- `author`: the email of the commit's author line, exactly as the commit has
  it (`null` when the commit has no single author with an email). Reported
  for any commit that could be read, verified or not. It is information, never
  part of the verdict: the exit code doesn't depend on it.
- `author_matches_signer`: `true` only when the commit is verified and
  `author` equals `signer` exactly (byte for byte, no case folding). A gate
  that needs the author to be the agent must require this to be `true`: the
  signature and the certificate vouch for the committer, and an author line
  is the commit's to write. (`author` and `author_matches_signer` were added
  after `trust_file`; the human form prints an `author:` line.)

The exit code is 0 only when the commit is verified and attested, 1 for every
other verdict, and 2 when the check cannot run (for example, the revision
does not exist; the object still prints, with `reason` `error`). The human
form exits the same way and comes from the same function, so the two always
agree. One `error` exits 1: a commit object whose bytes don't hash to its
name (a planted object; the detail says so), which is a verdict on the commit,
not a check that could not run. `verify` ignores replace refs
(`refs/replace/*`), so a pushed replace ref can't make an unsigned commit
read as an attested one.

`--allowed-signers <file>` must be an absolute path to a file outside the
checkout being verified; a relative path is refused (exit 2), because it would
be read from the current folder, which the session under check can write.
`verify` also never fetches: it sets `GIT_NO_LAZY_FETCH=1` (git 2.44 and
later, so a missing object in a shallow or partial clone is reported, not
fetched) and `GIT_ALLOW_PROTOCOL` to the empty string (git 2.12 and later, no
transport at all, so an older git can't run a command the repository's config
names). In the human form, bidi, zero-width and byte-order-mark characters in
text a commit controls are written out as `\u{..}`, like control characters.

An agent that nobody launched gets its `merge`, `rebase`, `cherry-pick`,
`revert`, `am` and `pull` commits made **unsigned**, with a one-line note,
not refused (decision D1). A merge gate that runs `agent-sign verify` is what
keeps such commits off `main`: it exits non-zero for them.

A commit approval binds the whole commit: it carries `commit_sha256`, the
SHA-256 of the exact unsigned commit object (message, author, committer and
dates included), and agent-sign signs only that object, once. A captured
approval presented with any other message, name or date is refused.

## Uninstall

```sh
./scripts/uninstall.sh
```

It removes the service, the `PATH` and editor changes, the drop-ins it wrote
for background services, and agent-sign's block (and an earlier version's
agent key line) from `allowed_signers`; puts your own signer back as git's
`gpg.ssh.program` (from `fallback_program`, or unset if that was git's
default, `ssh-keygen`); and deletes `~/.agent-sign`. It leaves git's
`gpg.ssh.allowedSignersFile` setting, if the installer set it.
If an earlier version added the shared agent key to your GitHub account,
remove it from your signing keys yourself.

## Upgrading

Run the installer again from the new version. Your leases and config carry
over. Changes to know about:

- **Only allowed agent names are signed.** Before, any well-formed
  `AGENT_SIGN_AGENT_NAME` got a certificate. Now only the built-in and
  widely used names do, plus those in `[identity] allowed_agents`
  ([Allowed agent names](#allowed-agent-names)); add any other name you use
  there and restart the service.
- **People's names, without git.** `root`, `admin` and `administrator`,
  the names in the new `[identity] people` (`install.sh --person`), and the
  people's accounts on the machine are never agents' names, whatever
  `allowed_agents` says ([Allowed agent names](#allowed-agent-names)). A
  config whose `allowed_agents` lists one of the configured names no longer
  starts the service.
- **Certificates say the name was claimed.** Their key id is now
  "`<name>` on `<host>`, claimed by a process in a shared account".
- **An optional machine name.** `[identity] machine` scopes agents' names
  and trust lines to one machine. Nothing changes without it; read
  [Naming the machine](#naming-the-machine) before setting it on a machine
  whose agents have already committed.
- **Commits dated outside their certificate aren't signed.** A commit whose
  committer date lies outside its signing certificate's validity is now
  refused rather than signed (such a commit never verified anyway).
- **Faster agent commits.** An agent commit no longer checks every open
  lease's branch for finished work, which made each one wait several
  seconds on a Mac with many leases open.
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

- [docs/INSTALL.md](docs/INSTALL.md): installing, what changes, servers and headless machines
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

## October 29 security repair scope

The [security repair record](docs/security-review-2026-10-29.md) describes exact
candidate checks, lease-generation binding, explicit persistence failures,
trusted release inputs and remaining host assumptions. Isolated Linux validation
passed 330 tests and 35 installer checks; the record identifies the exact source,
commands and untested platforms, separately from independent source review.
