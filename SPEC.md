# agent-sign: specification

- **Status:** pre-release (0.1.0). This page describes what the code does
  today, checked against it on 30 Sept 2026. Where agent-sign falls short of what it
  aims for, the gap is stated next to the aim.

## 1. The problem

When an AI coding agent commits in a repository where the person signs their
commits with a hardware key, 1Password, or a passkey, every agent commit
stops for the person's fingerprint or touch. The common workarounds are
worse: turning signing off (unsigned commits, which fail "require signed
commits" rules), or giving the agent the person's own key (the agent can then
sign anything as the person, anywhere).

agent-sign gives agents a separate signing key, held by a small service, and asks
the person once for a **lease**: permission for agents to sign, in one
Touch ID prompt that says which branch of which repository it is for. By
default a lease covers that one branch of that one repository; the config can
let it follow the agent across the repository's other unprotected branches.

## 2. Invariants

Each invariant says whether it holds today, and how that's checked.

- **INV-1, the person's commits are left alone.** A `git commit` the person
  types in an interactive terminal (standard input and output both
  terminals) goes to the real git unchanged, with the person's own signing,
  unless an agent has marked the command as its own (`CLAUDECODE`,
  `GEMINI_CLI`, `CODEX_THREAD_ID`). *Holds for terminals.* It does **not**
  hold for an editor's commit button whose `git` is the wrapper (there's no
  terminal, so the wrapper treats it as an agent's), and an agent driving a
  terminal pane without marking its commands looks like the person. Checked
  in a real terminal (`script`) by `tests/test_edge_cases.rs`.
- **INV-2, interception doesn't depend on the agent.** An agent that runs
  `git commit` through the wrapper is handled without remembering flags or
  commands. *Holds for `commit`.* Every other command from an agent (`merge`,
  `rebase`, `cherry-pick`, `revert`, `pull`, `am`, shell aliases) runs with
  signing off for commits, tags and pushes, agent-sign's signing program as
  `gpg.ssh.program`, `gpg.program` and `gpg.openpgp.program`, X.509's set to
  fail, and `AGENT_SIGN_AGENT_RUN=1` in its environment: the commits git
  makes are unsigned, never signed with the person's key (26 Oct 2026). The
  signing program refuses a signing request without a token when that mark
  or an agent's own mark is set, and checks signatures with plain
  `ssh-keygen` or `gpg`. The wrapper reads no config on this path, finds the
  real git without `PATH` (`paths::real_git`), and stops at 8 nested
  wrappers (`AGENT_SIGN_DEPTH`) rather than call itself without end. An
  agent can still bypass the wrapper by calling the real git by path, and
  git clears the `-c` settings for hooks of a repository on the same
  machine; with the person's `gpg.ssh.program` set to `agent-ssh-sign`, a
  marked one is refused there too. Checked by
  `tests/test_agent_ops_never_persons_key.rs`.
- **INV-3, no agent signature without a lease.** The service signs only with
  a single-use token, issued only under a lease that is in force and covers
  the repository and branch. *Holds* (tests: `test_lease_engine.rs`,
  `test_human_isolation.rs`, `test_e2e_git_commit.rs`).
- **INV-4, approve once, on fixed terms.** If no lease covers a commit, the
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
- **INV-5, configurable attribution.** `split`, `trailers` and `alias` modes
  change author, committer and message, not the signing. *Holds*, except that
  `trailers` only rewrites a message given with `-m` or `--message`.
- **INV-6, standard signatures.** Signatures are git's SSH signature format
  (`gpg.format = ssh`), verifiable with `ssh-keygen -Y verify` and by GitHub
  or GitLab. *Holds* (tests: `test_crypto_verification.rs`,
  `test_signature_equivalence.rs`).
- **INV-7, fail closed.** If the service is down, there's no lease, the token
  is bad, or the person can't be asked, the commit is refused; it's never
  signed some other way. *Holds* (tests: `test_human_isolation.rs`,
  `test_refusals_and_revoke.rs`).
- **INV-8, protected branches.** No lease covers a protected branch
  (`block_branches`, default `main` and `master`), checked when a lease is
  asked for and on every token. *Holds*, except that a detached HEAD
  (reported as `HEAD`) is never protected.

## 3. How a commit flows

```
  agent runs `git commit`                     person types `git commit`
            |                                          |
            v                                          v
  ~/.agent-sign/bin/git  (agent-git, the wrapper)   same wrapper: stdin and stdout
            |                                 are terminals -> real git,
            | not a terminal (or AGENT_SIGN_FORCE)  unchanged (person's own signing)
            v
  local rules: forbidden paths, (optional) diff size and message format
            |
            v
  agent-signd: lease for this branch?     --no--> ask the person once (one Touch ID prompt)
            |                                  approve -> lease saved
            | yes (and branch not protected, rate under limit)
            v
  single-use token (60 s)
            |
            v
  real git commit -c gpg.format=ssh -c gpg.ssh.program=agent-ssh-sign
            |                     with AGENT_EVENT_TOKEN and agent attribution
            v
  agent-ssh-sign: token? --no--> the person's own signer (fallback_program)
            | yes
            v
  agent-signd checks and burns the token, signs with the agent key -> <file>.sig
```

## 4. Components

### 4.1 The wrapper, `agent-git` (installed as `git`)

- Installed in `~/.agent-sign/bin`, which the installer puts first on `PATH`
  in shell profiles.
- Every command except `commit` (the first non-option argument, so
  `git -C dir commit` counts) runs the real git unchanged.
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
  person's own default.
- Otherwise it's an agent's. The repository is the canonical path of
  `git rev-parse --show-toplevel`; the branch is `git branch --show-current`,
  or `HEAD` when detached. It then:
  1. checks the local rules against the staged changes: `forbidden_paths`,
     `max_diff_lines` (skipped when `AGENT_SIGN_ALLOW_LARGE_DIFF` is set), and, if
     `enforce_conventional_commits` is on, the `-m` message's format;
  2. asks the service for a lease (the reason sent is always "Autonomous
     coding agent commit"; any duration it sends is ignored);
  3. asks for a token;
  4. runs the real git with `commit.gpgsign=true`, `gpg.format=ssh`,
     `gpg.ssh.program` set to `agent-ssh-sign` next to the wrapper,
     `user.signingkey` set to the agent's public key, the token in
     `AGENT_EVENT_TOKEN`, and author and committer set by the attribution
     mode.

### 4.2 The signing program, `agent-ssh-sign`

Git runs it as `gpg.ssh.program` with ssh-keygen's arguments. Without a
token it runs `fallback_program` (the person's own signer, detected by the
installer) with the same arguments. With a token it sends the buffer to the
service and writes the signature it gets back to `<file>.sig`. It never reads
the agent key. `agent-sign` accepts the same arguments, as `agent-sign` did.

### 4.3 The service, `agent-signd`

- One per user, run by launchd (`com.agentsign.agent-signd`) or a systemd
  user service (`agent-signd.service`). It listens on
  `~/.agent-sign/daemon.sock` (0600, in a 0700 directory), one thread per
  connection; the lock isn't held while a prompt is open.
- Holds the agent key: an ed25519 seed in `~/.agent-sign/keys/agent_ed25519`, 0600,
  **not encrypted**, generated on first start if missing.
- Reads the config once, when it starts: a change needs a restart. A
  `max_lease_ceiling` it can't read stops it. Environment variables in the
  service's own environment (`AGENT_SIGN_AUTO_APPROVE`, `AGENT_SIGN_LEASE_MODE`, ...)
  override the file.
- Asks the person with one prompt from the platform's own authentication
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
- Tokens are single-use and expire after 60 seconds. A token authorises one
  signature of whatever buffer is sent with it; the service doesn't check the
  buffer is a commit.

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
  sliding 60-second window. There's no cap on a lease's total commits.
- Leases belong to the machine's user, not to a particular agent: every
  agent on the machine shares them.

### 4.5 Operations (the socket protocol)

Newline-delimited JSON, unchanged from agent-sign.

| Request | What the service does |
|---|---|
| `RequestLease {repo, branch, intent, duration_secs}` | Refuses a protected branch without asking. Returns the lease if one covers the branch (moving a branch-following lease to it); otherwise asks the person and grants on approval. `duration_secs` is ignored. While a request for the same repository and branch is open, a new one waits for its answer instead of opening another prompt; when every commit waiting on a prompt has disconnected, the prompt is closed and the request withdrawn. |
| `IssueToken {repo, branch}` | Checks branch rules, that the lease is in force and covers the branch, and the rate limit; counts the commit; returns a token. |
| `SignCommit {token, buffer_b64}` | Burns the token and returns the signature. |
| `ListLeases` | The leases, with commit counts and when each ends. |
| `ListPending` | The approval requests waiting for the person: one per repository and branch, how long each has waited, and how many commits wait on it. |
| `DenyPending {id, all}` | Answers the request with that id (or all of them) as denied, and closes its prompt. |
| `RevokeLease {repo, branch, all}` | Ends the lease filed under `repo`: a repository's path, a folder's path, or `everywhere` (an error if none matches); or all of them; and saves. `branch` is ignored. |
| `GetStatus {repo}`, `Ping` | Status and health. |

### 4.6 Configuration

Built-in defaults, then `~/.agent-sign/config.toml`, then the repository's
`.agent-sign.toml`, then `AGENT_SIGN_*` environment variables. Which program reads what matters:

- **The service** reads only `~/.agent-sign/config.toml` and its own environment:
  every lease, branch, rate and approval setting comes from there.
  Repository files can't change them.
- **The wrapper** also reads the repository's files and the environment it
  runs in, both of which an agent can change: the local rules
  (`forbidden_paths`, `max_diff_lines`, `enforce_conventional_commits`) and
  attribution. So those rules catch mistakes, not an agent set on getting
  past them.

```toml
[security]                        # read by the service
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
auto_approve = false              # true grants every lease without asking

[security]                        # read by the wrapper (repository files and environment apply)
forbidden_paths = [".github/workflows/*", ".circleci/*", "*.pem", "*.key", "id_rsa*", "id_ed25519*"]
max_diff_lines = 0                # 0 = no limit (the default); set a number to refuse bigger agent commits
enforce_conventional_commits = false

[attribution]
mode = "split"                    # "split" | "trailers" | "alias"

[agent]
name = "Agent"                    # the default; replaced by the detected agent (below)
email = "agent@local.internal"

[human]                           # defaults to git's user.name and user.email
# name = "..."
# email = "..."

[ssh]
fallback_program = "/usr/bin/ssh-keygen"   # the person's own signer, detected by the installer
# agent_key_path = "~/.agent-sign/keys/agent_ed25519"
```

The author name of an agent commit is the agent that made it, when that can
be told and `[agent] name` is still the default ("Agent", or agent-sign's
"Antigravity Agent"): `AGENT_SIGN_AGENT_NAME` if the agent was started
with it, otherwise the first mark set among `CLAUDECODE` (Claude Code),
`GEMINI_CLI` (Gemini CLI) and `CODEX_THREAD_ID` (Codex). A name the person
configured is kept. This is attribution, not identity: any program can set
those variables.

(The two `[security]` blocks are one table in a real file; they're split here
to show who reads which keys.)

Attribution modes:

- **`split`** (default): author is the agent, committer is the person.
- **`trailers`**: author and committer are the person; a message given with
  `-m` or `--message` gets `Co-Authored-By: <agent>`, `X-Agent-Signer:
  agent-sign/v0.1` and `X-Agent-Lease: <lease id>` trailers. A message from `-F` or
  an editor is left as it is.
- **`alias`**: author and committer are "`<person's name> (Agent)`" with the
  agent's email.

In every mode the signature is the agent key's. GitHub shows a commit as
Verified when the signing key is registered on the account whose email is
the committer's; since the installer registers the agent key on the person's
account and `split` makes the person the committer, agent commits show as
Verified for the person. With `alias` and the default `agent@local.internal`
they show as Unverified.

## 5. Threat model

agent-sign's current protections assume an agent that cooperates: it runs `git`
from its `PATH` and doesn't set out to get around agent-sign. Agents today run as
the person's own user account, and agent-sign doesn't change that.

| Threat | What agent-sign does today | Gap |
|---|---|---|
| An agent signs as the person with the person's key | The agent key is separate; agents never talk to the person's signer through agent-sign. | An agent can still call the real git (or the person's signer) directly. |
| The agent key is copied | It's registered on GitHub as a signing key only, so it can't log in, clone or push. | It's unencrypted and readable by the person's user, so any process running as them can copy it, and commits signed with it show as Verified for the person. |
| An agent approves its own lease | The only approval is the system's own Touch ID or login-password prompt, which a program that controls the screen can't answer; agent-sign shows no dialog of its own to click. | An agent running as the person can still edit the config (`auto_approve`), start its own service, or, if it knows the login password, type it into the system's prompt. On Linux nothing can be approved interactively: every request is refused unless `auto_approve` is on. A prompt can still be repeated by an agent with a screen: the service shows one at a time and holds requests back after a refusal, but one reflexive touch for the wrong request is still a grant, and the prompt's text says the branch and repository so it can be read. |
| Runaway commit loops | `max_commits_per_minute` per repository. | No total cap per lease. |
| Commits on protected branches | Refused on every token. | Detached HEAD isn't protected; `allow_main_branch` turns protection off. |
| Changes to CI workflows or key files | `forbidden_paths` and `max_diff_lines` in the wrapper. | A repository's `.agent-sign.toml` or an environment variable, both writable by the agent, can loosen them. |
| Approving by accident | One prompt states the branch and the repository's name and path; it covers the narrowest thing by default; there is no default button that approves, and cancelling refuses. | Touch ID is a reflex: the prompt can't stop someone who touches without reading. The prompt says "until merged"; the other ways a lease ends (deleted branch, idle limit, revoke) only shorten it and are in the README. |
| Mixing agents' work | None. | One key and one set of leases per machine user; agents aren't told apart. |

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
| `test_signature_equivalence.rs` | Every program name makes byte-identical signatures to agent-sign's. |
| `test_e2e_git_commit.rs` | Real git commits through the wrapper, signing program and service, verified by git; old and new names. |
| `test_approval_scope.rs` | What an approval covers: one branch of one repository by default, the repository's other branches with `allow_branch_switching`; folder and everywhere leases saved earlier still work and revoke. |
| `test_pending.rs` | One prompt per repository and branch; a prompt withdrawn when nobody waits on it; `agent-sign pending` and `deny`. |
| `test_refusals_and_revoke.rs` | "Couldn't ask" versus "denied"; revoking a repository with no lease is an error; `agent-sign revoke .`; the doctor's advice. |

Not covered by an automated test yet: the real Touch ID prompt, the name and
wording the system puts around the reason (a program can't press a finger on
the sensor or read the prompt; see check F10 in
`docs/RELEASE_CHECKLIST.md`). The installer and
uninstaller are covered on Linux by `scripts/release/install-test.sh`.
