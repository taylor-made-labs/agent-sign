# agent-sign: specification

- **Status:** pre-release (0.1.0). This page describes what the code does
  today, checked against it on 28 Oct 2026 (after the identity review's
  fixes). Where agent-sign falls short of what it
  aims for, the gap is stated next to the aim.

## 1. The problem

When an AI coding agent commits in a repository where the person signs their
commits with a hardware key, 1Password, or a passkey, every agent commit
stops for the person's fingerprint or touch. The common workarounds are
worse: turning signing off (unsigned commits, which fail "require signed
commits" rules), or giving the agent the person's own key (the agent can then
sign anything as the person, anywhere).

agent-sign gives every agent its own identity (28 Oct 2026). A small
service holds an agents' certificate authority and gives each agent session
its own signing key, in memory only, with a short-lived OpenSSH certificate
for the agent's principal (`claude-code.1a2b3c4d@agents.local`). Agent
commits are signed, authored and committed as the agent, never as the
person, and need no approval by default. Each commit is still made under a
**lease** for its repository and branch, which the service records; with
`approval = "device-owner"` the person approves each lease once, in one
Touch ID prompt that says which branch of which repository it is for. By
default a lease covers that one branch of that one repository; the config can
let it follow the agent across the repository's other unprotected branches.

Before 28 Oct 2026 every agent signed with one shared key, whose trust entry
was the person's own email, so agent commits looked like the person's, and
the first commit on each branch asked for the person's Touch ID.

## 2. Invariants

Each invariant says whether it holds today, and how that's checked.

- **INV-1, the person's commits are left alone.** A `git commit` the person
  types in an interactive terminal (standard input and output both
  terminals) goes to the real git unchanged, with the person's own signing,
  unless an agent has marked the command as its own (`CLAUDECODE`,
  `GEMINI_CLI`, `CODEX_THREAD_ID`, `CODEX_SESSION_ID`). An agent token in
  that environment is removed first, and the signing program ignores a
  token without the wrapper's mark, so a token that leaked into the
  person's terminal never signs their commit as an agent (identity review,
  28 Oct 2026). A commit with no terminal and no agent mark (an editor's
  commit button whose `git` is the wrapper, a GUI) is left to git:
  unsigned, under git's own names, nothing asked; it is never attributed to
  an agent. If it asked to be signed (`-S`, `--gpg-sign[=<key>]`, `-c
  commit.gpgsign=true`, or the user's own `commit.gpgsign = true`), the
  request is taken out (only before `--`), the commit is made unsigned, and
  one line on stderr says why ("agent-sign: no terminal and no agent mark,
  so this commit was made unsigned ..."); before the follow-up round (28 Oct
  2026) such a commit failed. *Holds for terminals and unmarked commits.* An agent driving a
  terminal pane without marking its commands looks like the person. Checked
  in a real terminal (`script`) by `tests/test_edge_cases.rs` and
  `tests/test_identity_review_fixes.rs`.
- **INV-2, interception doesn't depend on the agent.** An agent that runs
  `git commit` through the wrapper is handled without remembering flags or
  commands. *Holds for `commit`.* Every other command from an agent runs
  with signing off for tags and pushes, agent-sign's signing program as
  `gpg.ssh.program`, `gpg.program` and `gpg.openpgp.program`, X.509's set to
  fail, and `AGENT_SIGN_AGENT_RUN=1` in its environment. For an identified
  agent (INV-9), a command that makes commits (`merge`, `pull`, `rebase`,
  `cherry-pick`, `revert`, `am`, an alias for one of those, or a shell
  alias) runs with commit signing on
  and a run token, so the commits git makes are signed as the agent, with
  the agent as committer (and as author of new commits); if the token is
  refused (a protected branch) or the service can't be reached, signing
  stays on without a token, so those commits fail. Any other command, and
  every command from an unmarked caller, runs with commit signing off:
  those commits are unsigned with git's own names, never signed with the
  person's key (26 Oct 2026). The signing program refuses a signing request
  without a token when that mark or an agent's own mark is set, and checks
  signatures with plain `ssh-keygen` or `gpg`. The wrapper reads config and
  asks the service only for an identified agent's commit-making commands,
  finds the real git without `PATH` (`paths::real_git`), and stops at 8
  nested wrappers (`AGENT_SIGN_DEPTH`) rather than call itself without end. An
  agent can still bypass the wrapper by calling the real git by path, and
  git clears the `-c` settings for hooks of a repository on the same
  machine. The installer routes the user's own SSH signing through
  agent-sign (their global `gpg.ssh.program` becomes `agent-ssh-sign`, and
  what it was becomes `fallback_program`), so a signing request from a
  marked process is refused there too; `uninstall.sh` puts the old program
  back. Checked by `tests/test_agent_ops_never_persons_key.rs` and
  `tests/test_identity_followup.rs`.
- **INV-3, no agent signature without a lease, and only where it was
  issued.** The service signs only with a token issued under a lease that is
  in force and covers the repository and branch: a single-use one for a
  commit (60 seconds), or a run token for one git run of an identified agent
  (10 minutes, several signatures, and only while its lease is still in
  force). Every signature request names the repository and branch the git
  run is writing (`git_place::repo_and_branch`, asked again by the signing
  program from inside the run), and the service refuses it unless both are
  the token's and the branch isn't protected: before the identity review a
  run token signed anything for ten minutes, so `git rebase feature main`
  and `rebase --exec 'cd /other && git commit'` made agent-signed commits on
  `main` and in other repositories. *Holds* (tests: `test_lease_engine.rs`,
  `test_human_isolation.rs`, `test_e2e_git_commit.rs`,
  `test_per_agent_identity.rs`, `test_identity_review_fixes.rs`).
- **INV-4, approve once, on fixed terms (opt-in).** With `approval =
  "none"` (the default) leases are granted without asking, and the
  service's log records each grant and each identity that signs under it.
  With `approval = "device-owner"`: if no lease covers a commit, the
  person is asked once, in a single prompt that says what is being approved:
  the branch (or, when the config lets leases follow the agent, that every
  unprotected branch), the repository's name and path, and how long ("until
  merged", with a ceiling or idle limit if the config sets one). Every ending
  is listed in the README and shown by `agent-sign leases`, and the service's
  log records the terms in full with each approval. A lease's terms
  are fixed at approval and never grow: using, moving, saving or reloading it
  never extends it, and a later config change can only narrow it. Leases are
  saved, so a crash, restart or sleep doesn't ask again. *Holds* (tests:
  `test_lease_terms.rs`, `test_persistent_identity_leases.rs`).
  The approval is one prompt, from the system and not from agent-sign, so a
  click can't supply it: the device's owner authenticates through the system
  (macOS: LocalAuthentication, policy `deviceOwnerAuthentication`, so Touch ID
  or the login password), and the prompt's reason text says what is being
  approved. There is no dialog of agent-sign's own, no choice to make, and no
  Approve button anywhere. Cancel, failure, a timeout (five minutes) or no
  authenticator denies. *Holds on macOS* (tests:
  `test_device_owner_approval.rs`; the real sensor, and the system's wording
  around the reason, are a manual check, F10). Linux has no platform
  authenticator, so there is no prompt and no terminal fallback either (an
  agent can drive its own pseudo-terminal or type into the person's): every
  request is refused unless `auto_approve` is on (see 4.3).
  Around that: one prompt at a time; after a refused prompt, new requests are
  held back (`refusal_backoff`, doubling); at most 4 requests wait at once; a
  request is asked about only if its repository is an existing git working
  tree and neither it nor the branch has control, invisible or
  direction-changing characters; and the prompt shows the verified path (the
  real one, not the spelling the agent used) and branch.
- **INV-5, an agent's signed commit is always the agent's.** Its author
  (for new commits) and committer are the agent's identity in every
  attribution mode, and no config, the person's or a repository's, changes
  that (identity review, 28 Oct 2026: `split`, `trailers` and `alias` used
  to put the person's or a configured name there, and a repository's file
  could choose them). `trailers` adds trailers to a message given with `-m`
  or `--message`; `split` and `alias` are accepted and change nothing. An
  identified agent's commit that declines signing carries its identity too,
  unless the repository (or the command) sets its own `user.email`. *Holds*,
  except for an agent that names another author on purpose (`--author`, or
  `--amend` of someone else's commit).
- **INV-6, standard signatures.** Signatures are git's SSH signature format
  (`gpg.format = ssh`): SSHSIG, namespace "git", sha512, with the agent
  session's OpenSSH certificate as the public key, as `ssh-keygen -Y sign`
  makes with a certificate. `ssh-keygen -Y verify` and git accept them under
  the trust line; GitHub doesn't check certificate signatures, so it shows
  them as Unverified. *Holds* (tests: `test_crypto_verification.rs`,
  `test_signature_equivalence.rs`, `test_per_agent_identity.rs`).
- **INV-7, fail closed.** If the service is down, there's no lease, the token
  is bad, or the person can't be asked, the commit is refused; it's never
  signed some other way. *Holds* (tests: `test_human_isolation.rs`,
  `test_refusals_and_revoke.rs`).
- **INV-8, protected branches.** No lease covers a protected branch
  (`block_branches`, default `main` and `master`, compared without ASCII
  case, so `MAIN` is protected too), checked when a lease is asked for, on
  every token, run tokens included, and on every signature, so an identified
  agent's merge on `main` makes no commit. *Holds* for signed agent commits,
  except that a detached HEAD (reported as `HEAD`) is never protected. A
  commit that declines signing is not an agent signature and can land on a
  protected branch (test fixtures commit on `main`); a rule that every
  commit on `main` is signed, as the person's own signed merges are, keeps
  those out.
- **INV-9, every agent signs as itself (28 Oct 2026).** An agent's identity
  comes only from the environment it sets (positive evidence; a config file
  can't change it): `CLAUDECODE` (not empty or `0`) is Claude Code, session
  `CLAUDE_CODE_SESSION_ID`; `CODEX_SESSION_ID` or `CODEX_THREAD_ID` is
  Codex, session the first of those; `GEMINI_CLI` is Gemini CLI, with no
  session of its own; `AGENT_SIGN_AGENT_NAME` (display name; its slug is the
  name lowercased with every other character `-`) and
  `AGENT_SIGN_SESSION_ID` override those. The principal is
  `<slug>.<session8>@agents.local`, `session8` being the first 8 hex
  characters of the SHA-256 of the session id, or `nosession`. A commit
  through the wrapper with no terminal and no mark is no agent's (INV-1);
  it was `Agent <agent.unidentified@agents.local>` before the identity
  review. Each commit is signed with a
  certificate for that principal, from the agents' certificate authority,
  and (in every attribution mode) authored and committed as it. The same
  session keeps one principal; different sessions, and different tools,
  get different ones. The service checks every identity it is sent
  (`AgentIdentity::check`: a slug matching `^[a-z0-9]+(-[a-z0-9]+)*$`, a
  session part of exactly 8 lowercase hex digits or `nosession`, a display
  name without control characters, `<` or `>`) before issuing a
  certificate, so it never certifies a principal no session can have, such
  as `codex.admin@agents.local`. `AGENT_SIGN_AGENT_NAME`'s slug joins its
  words of letters and digits with single `-`, so every name passes.
  *Holds* (tests: `test_per_agent_identity.rs`,
  `test_identity_review_fixes.rs`, and unit tests in `src/attribution.rs`
  and `src/agents_ca.rs`). These identities
  are claims made by processes running as the same user as the person: they
  are attribution, not a security boundary, until agents run under their own
  OS accounts.

## 3. How a commit flows

```
  agent runs `git commit`                     person types `git commit`
            |                                          |
            v                                          v
  ~/.agent-sign/bin/git  (agent-git, the wrapper)   same wrapper: stdin and stdout
            |                                 are terminals -> real git,
            | not a terminal (or AGENT_SIGN_FORCE)  unchanged (person's own signing)
            v
  no agent mark? --> real git, unsigned, git's own names, nothing asked
            |
            v
  local rules: the repository's added protected branches, forbidden paths,
  (optional) diff size and message format
            |
            v
  agent-signd: lease for this branch?     --no--> approval = "none": grant, log it
            |                                  "device-owner": one Touch ID prompt
            | yes (and branch not protected, rate under limit)
            v
  single-use token (60 s), bound to the agent's identity (from its
  environment), the repository and the branch
            |
            v
  real git commit -c gpg.format=ssh -c gpg.ssh.program=agent-ssh-sign
            |                     with AGENT_EVENT_TOKEN, the agent as author and committer
            v
  agent-ssh-sign: token and the wrapper's mark? --no--> the person's own signer
            | yes          (fallback_program; refused instead when an agent is behind the call)
            v
  sends the token, the buffer, and the repository and branch git is writing
            |
            v
  agent-signd checks and burns the token (same repository and branch, branch
  not protected), signs with the agent session's key, carrying its
  certificate for <slug>.<session8>@agents.local -> <file>.sig
```

## 4. Components

### 4.1 The wrapper, `agent-git` (installed as `git`)

- Installed in `~/.agent-sign/bin`, which the installer puts first on `PATH`
  in shell profiles.
- Every command except `commit` (the first non-option argument, so
  `git -C dir commit` counts) runs the real git with the settings of INV-2:
  signing as the agent, through a run token, for an identified agent's
  commit-making commands; signing off for the rest.
- A commit is recognised after any of git's global options, including
  those that take a value (`-C`, `-c`, `--git-dir`, `--work-tree`,
  `--namespace`, `--config-env`, `--attr-source`, `--super-prefix`), and
  through an alias whose expansion starts with `commit`. The repository,
  branch and the rules' view of the changes all come from git run with the
  commit's own global options.
- The rules check everything the commit could contain compared with HEAD,
  unstaged tracked changes included (`commit -a` and commits naming paths
  include them). If git can't list the changes, the commit is refused.
- The real git: `AGENT_SIGN_REAL_GIT` if set, else the first `git` on `PATH` that
  isn't in a agent-sign directory and isn't the wrapper, else `/opt/homebrew/bin`,
  `/usr/local/bin`, `/usr/bin`, `/bin`.
- A commit with standard input and output both terminals, neither
  `AGENT_SIGN_FORCE` nor `AGENT_SIGN_SESSION` set, and no agent mark
  (see INV-1) is the person's: it runs the real git unchanged.
- A commit that turns signing off goes to the real git unsigned, with no
  lease asked for and no rules applied, and with every signing program set
  to one that always fails, so it can't be signed with the person's key
  however its options are read: `--no-gpg-sign` (unless a
  later `-S` turns it back on), or `commit.gpgsign = false` at command,
  repository or worktree scope (`git config --show-scope`). A global or
  system `false` doesn't count, so agent commits are signed whatever the
  person's own default. For an identified agent with no terminal, author
  and committer are set to its identity, unless `user.email` is set at a
  scope other than global or system (a test fixture's own user is kept,
  since other projects' test suites depend on it), and unless the caller
  already set those variables.
- A commit with no terminal and no agent mark (`identify_agent` finds none)
  is no agent's (INV-1): the real git runs it with `commit.gpgsign=false`
  and every signing program set to one that always fails, under git's own
  names, with no lease, no rules and no service needed, so it never fails
  for want of one.
- Otherwise it's an identified agent's. The repository is the canonical
  path of `git rev-parse --show-toplevel`; the branch is
  `git branch --show-current`, or during a rebase the branch named in
  `rebase-merge/head-name` or `rebase-apply/head-name`, or `HEAD` when
  detached (`src/git_place.rs`, the rule the signing program uses too). It
  then:
  1. checks the local rules: a branch the repository's file added to
     `block_branches` (the service checks the person's list), then against
     the staged changes `forbidden_paths`,
     `max_diff_lines` (skipped when `AGENT_SIGN_ALLOW_LARGE_DIFF` is set), and, if
     `enforce_conventional_commits` is on, the `-m` message's format;
  2. asks the service for a lease (the reason sent is always "Autonomous
     coding agent commit"; any duration it sends is ignored);
  3. asks for a single-use token for the agent's identity
     (`IssueIdentifiedToken`);
  4. runs the real git with `commit.gpgsign=true`, `gpg.format=ssh`,
     `gpg.ssh.program` set to `agent-ssh-sign` next to the wrapper,
     `user.signingkey` set to an existing public key file (the agents'
     certificate authority's; the signing program ignores it), the token in
     `AGENT_EVENT_TOKEN` beside the wrapper's mark `AGENT_SIGN_AGENT_RUN`,
     and the agent's identity as author and committer.
- The person's own commands run with `AGENT_SIGN_AGENT_RUN` and
  `AGENT_EVENT_TOKEN` removed.

### 4.2 The signing program, `agent-ssh-sign`

Git runs it as `gpg.ssh.program` with ssh-keygen's arguments. A token counts
only beside the wrapper's mark (`AGENT_SIGN_AGENT_RUN`); without both it runs
`fallback_program` (the user's own signer: what their `gpg.ssh.program` was
before the installer routed it here, or `ssh-keygen`, git's default) with
the same arguments, unless an agent marked the process, when a signing
request is refused. With a token it asks the real git, from git's own folder
and environment, which repository and branch the run is writing
(`src/git_place.rs`), sends those with the buffer to the service, and writes
the signature it gets back to `<file>.sig`. It never reads a key.
`agent-sign` accepts the same arguments, as `agent-sign` did.

### 4.3 The service, `agent-signd`

- One per user, run by launchd (`com.agentsign.agent-signd`) or a systemd
  user service (`agent-signd.service`). It listens on
  `~/.agent-sign/daemon.sock` (0600, in a 0700 directory), one thread per
  connection; the lock isn't held while a prompt is open.
- Holds the agents' certificate authority **in memory only**: a new
  ed25519 key made at each start, whose private half is never written
  anywhere (Taylor's standing rule, 28 Oct 2026: keys are never stored
  unprotected; they live in OpenBao, a hardware or OS keystore, or only in a
  running process's memory). Issuing goes through the `CertificateIssuer`
  port (`src/agents_ca.rs`); the in-memory authority is its one adapter, and
  OpenBao's SSH secrets engine is the intended second, which would keep one
  authority across restarts.
- At each start it appends the new authority's public key, with the time,
  to `keys/agents_cas.pub` (append-only, oldest first), and writes it to
  `keys/agents_ca_ed25519.pub` as the current one. An authority an earlier
  development build left in `agents_ca_ed25519.pub` is never carried into
  the trust: its private key sat in a plain file, so it counts as exposed.
  `agent-sign trust-line` prints one allowed-signers line
  `*@agents.local cert-authority,namespaces="git" <key>` per authority in
  that history, so a commit certified before a restart still verifies.
- The user's allowed-signers file (git's global
  `gpg.ssh.allowedSignersFile`) can hold a managed block between the lines
  `# agent-sign: agents' certificate authorities, managed; do not edit` and
  `# agent-sign: end of agents' certificate authorities`; the installer
  writes it. At each start the service rewrites the lines between the
  markers with `trust-line`'s lines, and nothing else: every byte outside
  them is kept, a link is followed, and the file keeps its permissions. A
  file without the markers is left alone.
- A private key file `keys/agents_ca_ed25519` left by an earlier
  development build stops the service at start, with a message naming it;
  the service doesn't delete it (the installer does, after its usual
  question).
- Holds each agent session's signing key in memory only, never on disk,
  one per principal, each with an OpenSSH user certificate from the
  authority: principal the agent's principal, key id "<principal> on
  <hostname>", valid from 5 minutes ago to 12 hours ahead, no critical
  options or extensions, random serial and nonce; replaced shortly before
  it ends. A restart gives each session a new key and certificate, which
  verify the same way. A session key unused for 12 hours is dropped, and at
  most 1024 are kept (the least recently used goes first), since anyone who
  can reach the socket picks the principals. Encoded with RustCrypto's
  `ssh-key` (`src/agents_ca.rs`).
- The shared agent key of earlier versions (`agent_ed25519`) is no longer
  created or used. Its private half was stored unprotected, so it counts as
  exposed: the installer deletes it (and any copy an earlier build moved to
  `keys/retired/`), after its usual question, and keeps the `.pub` for
  checking commits it signed. While its line is still in the
  allowed-signers file, the installer prints the exact commands to remove
  that line and the key's GitHub entry, and runs neither: those are the
  user's choice. `agent-sign doctor` points out a private half still in
  `keys/`.
- Reads the config once, when it starts: a change needs a restart. Only a
  missing `config.toml` means the defaults: one it can't read (its
  permissions, a link to nothing, a directory), any table or key it doesn't
  know (a misspelt `approvl`, or `approval` outside `[security]`), a value
  it can't read, or a `max_lease_ceiling` it can't read stops it, with a
  message naming the file and key (`Config::check_file`). Keys only older
  installers wrote (`auto_revoke_on_branch_delete`) are accepted and
  ignored. It logs the approval mode in effect when it starts. Environment
  variables in the service's own environment (`AGENT_SIGN_AUTO_APPROVE`,
  `AGENT_SIGN_LEASE_MODE`, ...) override the file.
- Names every repository by its canonical path (leases, tokens, the rate
  window, revocation), so a link to a repository is the same repository.
- With `approval = "none"` (the default) it grants a lease without asking,
  for that repository only, and logs it; every token it issues is logged
  with the identity it signs as, the repository and the branch.
- With `approval = "device-owner"`, asks the person with one prompt from the platform's own authentication
  (`src/device_owner.rs`; on macOS LocalAuthentication, so Touch ID or the
  login password), giving up as a denial after five minutes. The prompt's
  reason text (`auth_reason` in `src/approval.rs`) reads "let an agent sign
  commits on branch “<branch>” in <repo name> (<path>), <how long>", where
  how long is "until merged", with ", at most <ceiling>" or " or <idle limit>
  idle" when the config sets one (`LeasePolicy::end_phrase`); it says "on any
  unprotected branch" when the config lets leases follow the agent. For a
  linked worktree the name and path are those of the repository the commits go
  into, and the parentheses add `worktree “<name>”`. The names and paths are
  the agent's to choose, so unsafe characters are removed, the brackets and
  quotes of the sentence itself and right-to-left letters are shown as `?`. macOS builds the
  prompt as "<name> is trying to <reason>." (that sentence is in the system's
  own string tables), so the reason starts lowercase and has no full stop.
  The reason is at most 200 characters: macOS documents no limit on it, but
  the Touch Bar form has to fit on one line, so the branch and the repository
  name come first and are shortened only past 32 and 20 characters (cut in
  the middle, so both ends show), and the path comes after, with the home
  folder as `~`, shortened past 32.
  Before asking, the service checks the branch (`src/repo_info.rs`, without
  running git): a valid git branch name by `check-ref-format`'s rules, made
  only of ASCII letters, digits and `/ - _ .`, and the branch the repository
  has checked out, read from its `HEAD` (`HEAD` when detached, as the wrapper
  reports it). Otherwise it refuses and nobody is asked. Without this an agent
  could send the branch "typo fix in scratch (~/tmp/scratch)" and have the
  prompt read as if for another place.
  If no authenticator can be used (no password set, no desktop session) it
  refuses and says it couldn't ask; the service's log says why. There is no
  terminal prompt and no Linux prompt, by design: a dialog any program can
  click, or a terminal an agent can drive, would let an agent approve its own
  lease; on Linux every request is refused. With `auto_approve`, every lease
  is granted without asking. One prompt is shown at a time across the
  service; a cancelled or failed authentication, or timeout holds new
  requests back for `refusal_backoff` (default 60 seconds, doubling with each
  refusal in a row up to an hour, reset by an approval; `agent-sign deny`
  doesn't count); at most 4 requests may wait. Before asking, `RequestLease`
  refuses a repository that isn't an existing git working tree (a `.git`
  inside the path), and a repository or branch containing control, invisible
  or direction-changing characters. The decision itself (`src/approval.rs`:
  an approval counts only if the `Authenticator` succeeds) sits behind a small
  trait so tests can inject one. Test builds only (cargo feature
  `test-authenticator`, which `cargo test` turns on and `cargo build` never
  does, and which refuses to compile without debug assertions, so `cargo test
  --release` fails instead of producing an installable program with it) have a
  stand-in for the owner (`AGENT_SIGN_TEST_AUTH` and the variables beside it).
  The installer also refuses programs that contain it
  (`scripts/check-binary-clean.sh`).
- **The name in the prompt.** The system names the program that asked, so a
  bare `agent-signd` would show as "agent-signd" (the "d" means daemon, which
  means nothing to most people). On macOS the installer builds a small app
  bundle, `~/.agent-sign/agent-sign.app`, holding a copy of `agent-signd` and
  an `Info.plist` (`scripts/agent-sign.Info.plist`) whose `CFBundleName` and
  `CFBundleDisplayName` are "agent-sign", signs it ad hoc, and points the
  LaunchAgent at the copy inside it. That the prompt then says "agent-sign"
  has not been seen by the author of this change: it is the standard way a
  program gets a name in system prompts, but only seeing the prompt confirms
  it (check F10).
- Approving a lease from another device (a passkey on the phone) is the next
  step and belongs to agentic-credentials; it is not built.
- Commit tokens are single-use and expire after 60 seconds; run tokens last
  10 minutes and sign as many buffers as the run needs, while their lease is
  in force and the rate limit allows (each signature counts). Either signs
  only for its own repository and branch (INV-3). A token authorises
  signatures of whatever buffer is sent with it; the service doesn't check
  the buffer is a commit.

### 4.4 Leases

Saved in `~/.agent-sign/leases.json` (0600, written to a temporary file, synced,
and renamed). A file that can't be read is left untouched, and one that can't
be parsed is set aside; either way the service starts with no leases.

```yaml
Lease:
  id: UUID
  repo: String                  # canonical path of the repository's top level
  branch: String                # the branch it was approved on, or moved to
  intent: String                # the reason the agent gave
  mode: identity | timed | process
  scope: branch | repo
  granted_at_secs: u64
  last_used_at_secs: u64        # usage record only
  expires_at_secs: u64 or none  # fixed at approval; none = until revoked
  commit_count: u64             # usage record only
  follows_branches: bool        # fixed at approval; absent on older leases
  coverage: repository | folder <path> | everywhere   # absent = repository
```

- The service now approves only `repository` coverage: the repository asked
  from, and its one branch unless the config lets leases follow the agent
  (below). Earlier versions let the person pick, in a dialog, every
  repository under a folder (compared by whole path components, so `/w/dev`
  never covers `/w/dev2`) or every repository. Those leases still load, work
  and can be revoked, and a commit uses the most specific lease that covers
  its repository and branch, but nothing grants new ones. (They also need
  `allow_branch_switching = true` or `lease_scope = "repo"` to keep covering
  every branch.) `agent-sign leases`, `agent-sign doctor` and the service's
  log point them out. Unattended approval (`auto_approve`) grants this repository
  only.
- Each lease is in force until the first of:
  - its effective end: the end recorded at approval, brought forward if the
    current config's cap for its mode is shorter (`max_lease_ceiling` for
    `identity`, `default_lease_duration` for `timed`), never pushed back
  - its work is finished: the branch it was approved on (recorded with its
    tip at approval, as `work`) is deleted, or has commits since approval
    that are now in `main` or `master` (local, or `origin`'s as last
    fetched). Checked by the service on every request (`src/work.rs`).
    Detached HEAD never counts as finished.
  - `end_after_idle` (default 7 days) passes with no agent commit under it
  - the person revokes it
  No lease lasts forever unless the person sets both `end_after_idle` and
  `max_lease_ceiling` to "none" and never merges or deletes the branch.
- `process` mode isn't tied to a process: it works as `timed`, and the
  service's log says so.
- By default (`scope = "branch"`, `allow_branch_switching = false`) a lease
  covers only the branch it was approved on, in the repository it was asked
  from: the narrowest approval, chosen for safety, so an agent that moves to
  another branch needs a new approval. With `allow_branch_switching = true`,
  or `scope = "repo"`, it covers every unprotected branch of the repository
  and follows the agent between them; the prompt says so ("any unprotected
  branch"). Changing the setting only affects leases approved afterwards, and
  can only narrow older ones.
- Commits are limited per repository to `max_commits_per_minute` in a
  sliding 60-second window: a single-use token counts when issued, and each
  signature a run token makes counts as it's made (issuing a run token only
  checks the window isn't full). There's no cap on a lease's total commits.
- Leases belong to the machine's user, not to a particular agent: every
  agent on the machine shares them.

### 4.5 Operations (the socket protocol)

Newline-delimited JSON, unchanged from agent-sign.

| Request | What the service does |
|---|---|
| `RequestLease {repo, branch, intent, duration_secs}` | Refuses a protected branch without asking. Returns the lease if one covers the branch (moving a branch-following lease to it); otherwise grants it (`approval = "none"`, or `auto_approve`), or asks the person and grants on approval (`"device-owner"`). `duration_secs` is ignored. While a request for the same repository and branch is open, a new one waits for its answer instead of opening another prompt; when every commit waiting on a prompt has disconnected, the prompt is closed and the request withdrawn. |
| `IssueToken {repo, branch}` | Sent by wrappers older than per-agent identities. Refused since the identity review: it names no agent, and nobody's commit is signed as an "unidentified agent". |
| `IssueIdentifiedToken {repo, branch, identity}` | Checks the identity (`slug`, `name`, `principal`), branch rules, that the lease is in force and covers the branch, and the rate limit; counts the commit; returns a single-use token that signs as the identity in that repository on that branch. |
| `IssueRunToken {repo, branch, identity}` | The same checks, without counting; returns a token for one git run (10 minutes, several signatures), bound to the identity, repository and branch. |
| `SignCommit {token, buffer_b64, repo, branch}` | Burns a single-use token, or checks a run token is fresh, its lease still in force and the rate window not full (counting the signature); refuses unless `repo` (canonicalized) and `branch` are the token's and the branch isn't protected (a request without them, from an older signing program, is refused); returns the signature made with the identity's session key and certificate. |
| `ListLeases` | The leases, with commit counts and when each ends. |
| `ListPending` | The approval requests waiting for the person: one per repository and branch, how long each has waited, and how many commits wait on it. |
| `DenyPending {id, all}` | Answers the request with that id (or all of them) as denied, and closes its prompt. |
| `RevokeLease {repo, branch, all}` | Ends the lease filed under `repo`: a repository's path, a folder's path, or `everywhere` (an error if none matches); or all of them; and saves. `branch` is ignored. |
| `GetStatus {repo}`, `Ping` | Status and health. |

### 4.6 Configuration

Built-in defaults, then `~/.agent-sign/config.toml`, then the repository's
`.agent-sign.toml` (which can only tighten, below), then `AGENT_SIGN_*`
environment variables. Which program reads what matters:

- **The service** reads only `~/.agent-sign/config.toml` and its own environment:
  every lease, branch, rate and approval setting comes from there.
  Repository files can't change them.
- **The wrapper** also reads the repository's file and the environment it
  runs in, both of which an agent can change. The repository's file can
  only tighten (`config::tighten_with_repo_file`, identity review, 28 Oct
  2026): its `forbidden_paths` and `block_branches` entries are added to
  the person's, and its `max_diff_lines` applies only when lower (any limit
  is lower than the default 0, no limit). Every other table and key in it
  (`[attribution]`, `[agent]`, `[human]`, `[ssh]`, `approval`,
  `allow_main_branch`, `max_commits_per_minute`,
  `enforce_conventional_commits`, ...) is ignored, and
  the wrapper prints one warning line naming them. Before, a cloned
  repository's file overlaid every table, so it could loosen the rules or
  name the person as the committer of agent-signed commits. The
  environment can still change the local rules, so they catch mistakes, not
  an agent set on getting past them.

```toml
[security]                        # read by the service
approval = "none"                 # "none" (grant leases unasked, logged) | "device-owner" (Touch ID / login password); unreadable = service won't start
lease_mode = "identity"           # "identity" | "timed" | "process" (works as timed)
lease_scope = "branch"            # "branch" | "repo"
allow_branch_switching = false    # with branch scope: true lets a lease follow the agent between branches
default_lease_duration = "2h"     # life of a timed lease
max_lease_ceiling = "none"        # longest life of an identity lease, e.g. "7d"; unreadable = service won't start
end_after_idle = "7d"             # a lease ends after this long with no agent commit; "none" turns it off; unreadable = service won't start
block_branches = ["main", "master"]   # exact names, or a prefix ending in "*", e.g. "release/*"
allow_main_branch = false         # true turns branch protection off entirely
max_commits_per_minute = 10
refusal_backoff = "60s"           # after a refused prompt, no new one for this long, doubling; "none" turns it off; unreadable = service won't start
auto_approve = false              # with "device-owner": true grants every lease without asking

[security]                        # read by the wrapper (repository files and environment apply)
forbidden_paths = [".github/workflows/*", ".circleci/*", "*.pem", "*.key", "id_rsa*", "id_ed25519*"]
max_diff_lines = 0                # 0 = no limit (the default); set a number to refuse bigger agent commits
enforce_conventional_commits = false

[attribution]
mode = "agent"                    # "agent" | "split" | "trailers" | "alias"

[agent]                           # only the Co-Authored-By trailer in "trailers" mode; never who authors or commits
name = "Agent"                    # the default; replaced by the detected agent (below)
email = "agent@local.internal"

[human]                           # defaults to git's user.name and user.email
# name = "..."
# email = "..."

[ssh]
fallback_program = "ssh-keygen"   # your own signer: what gpg.ssh.program was before the installer routed it (ssh-keygen if unset)
# agent_key_path = "~/.agent-sign/keys/agent_ed25519"   # the legacy shared key; no longer signs
```

In every mode, author and committer of an agent's signed commit are the
agent's identity (INV-5, INV-9), and no setting changes them. In
`trailers` mode the `Co-Authored-By` trailer names the agent that made the
commit, when that can be told and `[agent] name` is still the default
("Agent", or agent-sign's "Antigravity Agent"): `AGENT_SIGN_AGENT_NAME` if
the agent was started with it, otherwise the first mark set among
`CLAUDECODE` (Claude Code), `GEMINI_CLI` (Gemini CLI) and `CODEX_THREAD_ID`
(Codex). This is attribution, not identity: any program can set those
variables.

(The two `[security]` blocks are one table in a real file; they're split here
to show who reads which keys.)

Attribution modes:

- **`agent`** (default): author and committer are the agent's display name
  and principal, for commits and for the commits an identified agent's
  merge, revert, pull and the like make (replayed commits keep their author).
- **`trailers`**: as `agent`, and a message given with `-m` or `--message`
  gets `Co-Authored-By: <agent>`, `X-Agent-Signer: agent-sign/v0.1` and
  `X-Agent-Lease: <lease id>` trailers. A message from `-F` or an editor is
  left as it is. (Before the identity review the author and committer were
  the person.)
- **`split`** and **`alias`**: accepted, so configs that name them still
  load, and the same as `agent`. (Before the identity review, `split` made
  the person the committer and `alias` named "`<person's name> (Agent)`".)

In every mode the signature is the agent's own: its session key, with a
certificate for its principal. Locally, git shows it as Good for that
principal under the trust line. GitHub doesn't check SSH certificate
signatures, so agent commits show there as Unverified; before 28 Oct 2026
the installer registered the shared agent key on the person's account, which
made agent commits show as Verified for the person.

## 5. Threat model

agent-sign's current protections assume an agent that cooperates: it runs `git`
from its `PATH` and doesn't set out to get around agent-sign. Agents today run as
the person's own user account, and agent-sign doesn't change that.

| Threat | What agent-sign does today | Gap |
|---|---|---|
| An agent signs as the person with the person's key | Agents sign with their own session keys; agents never talk to the person's signer through agent-sign. | An agent can still call the real git (or the person's signer) directly. |
| Agent work passes as the person's | Agent commits carry the agent's name and `@agents.local` principal as author and committer in every mode, and their certificates are trusted for `*@agents.local` only; a repository's file can't change names; an agent's token that leaks into the person's terminal is ignored. | An agent can still name another author on purpose (`--author`, or amending someone else's commit). |
| A cloned repository changes the rules | Its `.agent-sign.toml` can only add forbidden paths and protected branches, or lower `max_diff_lines`; everything else in it, `max_commits_per_minute` included (the service counts the rate and reads only your config), is ignored, with a warning. | |
| An agent signs somewhere other than it was allowed | Every signature names the repository and branch git is writing; the service refuses one that isn't the token's, or is on a protected branch. | An agent that calls the real git directly, or clears the environment, isn't seen at all. |
| One agent passes as another | Each session gets its own principal and key. | Identities are claims by processes running as the person's user: any of them can set another agent's marks. Attribution, not a security boundary, until agents run under their own OS accounts. |
| The agents' certificate authority key is copied | It's never stored: made in the service's memory at each start, so there's no file to copy, and it can only vouch for `@agents.local` principals under the trust lines, never your email. A private key file an earlier build left stops the service. | A process running as the same user can still read the service's memory (a debugger) or ask the service for a certificate for any well-formed agent principal over its socket. Each restart adds an authority to the trusted list, which only grows. |
| An agent approves its own lease (`approval = "device-owner"`) | The only approval is the system's own Touch ID or login-password prompt, which a program that controls the screen can't answer; agent-sign shows no dialog of its own to click. | An agent running as the person can still edit the config (`auto_approve`), start its own service, or, if it knows the login password, type it into the system's prompt. On Linux nothing can be approved interactively: every request is refused unless `auto_approve` is on. A prompt can still be repeated by an agent with a screen: the service shows one at a time and holds requests back after a refusal, but one reflexive touch for the wrong request is still a grant, and the prompt's text says the branch and repository so it can be read. |
| Runaway commit loops | `max_commits_per_minute` per repository, counting every signature, run tokens' included; a bounded set of session keys. | No total cap per lease. |
| Commits on protected branches | Refused on every token and signature, compared without case. | Detached HEAD isn't protected; `allow_main_branch` turns protection off; a commit that declines signing isn't an agent signature and can land there. |
| Changes to CI workflows or key files | `forbidden_paths` and `max_diff_lines` in the wrapper; a repository's file can only add to them. | An environment variable, writable by the agent, can loosen them. |
| A config that doesn't say what the person thinks | The service refuses to start on a `config.toml` it can't read or with a key it doesn't know, naming it, and logs its approval mode at start. | |
| Approving by accident | One prompt states the branch and the repository's name and path; it covers the narrowest thing by default; there is no default button that approves, and cancelling refuses. | Touch ID is a reflex: the prompt can't stop someone who touches without reading. The prompt says "until merged"; the other ways a lease ends (deleted branch, idle limit, revoke) only shorten it and are in the README. |
| Mixing agents' work | Each agent session signs with its own key and principal. | Leases still belong to the machine's user, shared by every agent. |

The release checklist (`docs/RELEASE_CHECKLIST.md`) tracks the work on these
gaps: a separate service user (so agents can't read the key or approve their
own leases) and attribution to a separate GitHub machine account.

## 6. Tests

`cargo test --locked` runs them all; the end-to-end ones start their own
service in a temporary home with its own socket, so they never touch an
installed agent-sign.

| File | What it shows |
|---|---|
| `test_human_isolation.rs` | Without a token, signing goes to the person's signer; a bad token is refused. |
| `test_interceptor.rs` | Only `commit` is intercepted; `split` and `trailers` attribution. |
| `test_lease_engine.rs` | Granting, commits under a lease, protected branches, rate limit, branch switching, revocation. |
| `test_device_owner_approval.rs` | Without successful owner authentication nothing is approved (failure, cancel, timeout, unavailable); success approves this repository; `agent-sign deny` wins over a late yes; one prompt at a time; the hold-back after a refusal; the cap on waiting requests; a repository that doesn't exist, or a path or branch with control or invisible characters, is refused unasked; the reason text says branch, repository, path and how long, stays within 200 characters keeping the branch and name, and can't be reshaped by the agent; a branch that could pose as prompt text, or that isn't the one checked out, is refused unasked; a linked worktree is shown as its repository; an optimized build can't include the test stand-in; the installer refuses a program that does; no dialog, Linux dialog or terminal prompt in the source. |
| `test_lease_terms.rs` | Terms fixed at approval; config narrows, never widens; the terms in plain words; the unreadable ceiling. |
| `test_persistent_identity_leases.rs` | Leases survive restarts; revocation persists; ceiling; scope. |
| `test_crypto_verification.rs` | Keys and signatures in OpenSSH format, verified by `ssh-keygen`. |
| `test_signature_equivalence.rs` | The library signer makes byte-identical signatures to the first agent-sign's; every program name signs through the service as the agent, verified under the trust line. |
| `test_per_agent_identity.rs` | The change's eval, written before it: identities from each agent's marks, no approval by default and the opt-in, Good signatures for each principal under the trust line, the legacy key unused, the agent as author and committer, sessions kept apart, merges, reverts, pulls, aliases, rebases, cherry-picks and `am` signed as the agent, unmarked commits and runs left to git, the branch and path rules, the person's own commits in a terminal. |
| `test_identity_followup.rs` | The follow-up round (28 Oct 2026), each test failing before its change: no file under `~/.agent-sign` holds private key material after start; a commit certified before a restart verifies after it under `trust-line`'s lines; only the managed block of the allowed-signers file changes; a leftover authority key stops the service; an unmarked commit asking to sign is made unsigned; a repository can't lower `max_commits_per_minute`; the template and SPEC describe attribution as it is; and, running the real installer and uninstaller in a throwaway home with stand-ins for the service manager, process tools and network, the routing of your own signing and its undoing, the summary before asking, the deleted authority key and old shared key, the managed block, and the GitHub notice only while the old key is trusted. |
| `test_identity_review_fixes.rs` | One regression test per finding of the identity review (28 Oct 2026), each failing before its fix: a repository's file only tightens and every mode commits as the agent; unsigned agent commits carry the identity unless a fixture names its user; tokens sign only for their repository and branch; an unreadable or misspelt config stops the service, every installer's keys still start it, and the approval mode is logged; an unmarked commit needs no service; only well-formed principals; a git run counts once against the rate limit however many commits it signs, session keys are capped, and links share one lease; a leaked token never signs the person's commit; `MAIN` is protected. |
| `test_e2e_git_commit.rs` | Real git commits through the wrapper, signing program and service, verified by git; old and new names. |
| `test_approval_scope.rs` | What an approval covers: one branch of one repository by default, the repository's other branches with `allow_branch_switching`; folder and everywhere leases saved earlier still work and revoke. |
| `test_pending.rs` | One prompt per repository and branch; a prompt withdrawn when nobody waits on it; `agent-sign pending` and `deny`. |
| `test_refusals_and_revoke.rs` | "Couldn't ask" versus "denied"; revoking a repository with no lease is an error; `agent-sign revoke .`; the doctor's advice. |

Not covered by an automated test yet: the real Touch ID prompt, the name and
wording the system puts around the reason (a program can't press a finger on
the sensor or read the prompt; see check F10 in
`docs/RELEASE_CHECKLIST.md`). The installer and
uninstaller are covered on Linux by `scripts/release/install-test.sh`, and in
part (with stand-ins for the service manager) by `test_identity_followup.rs`.

## October 29 signature-boundary contract amendment

The [security repair record](docs/security-review-2026-10-29.md) specifies the
source repair: exact UTF-8 candidate bytes and first-parent object delta checked
before every signature; strict selected guardrail loading; both token types bound
to an unchanged lease ID with validity rechecked after blocking reads; durable
explicit revocation acknowledged only after file and directory synchronization.
No wire format changes. Startup lease-policy semantics, cooperative caller/host
trust and replayed authors are retained. The record binds isolated Linux runtime
validation (330 tests and 35 installer checks) to exact source hashes and states
remaining assumptions and untested platforms.
