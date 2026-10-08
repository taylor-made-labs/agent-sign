# agent-commits: specification

- **Status:** pre-release (0.1.0). This page describes what the code does
  today, checked against it on 30 Sept 2026. Where agent-commits falls short of what it
  aims for, the gap is stated next to the aim.
- **Formerly:** agent-sign. `agent-signd` is now `agent-commitsd`, `agent-sign` is
  `agent-commits-ssh-sign` (signing) and `agent-commits` (command line), `agent-git` is
  `agent-commits-git`, and `~/.agent-sign` is `~/.agent-commits`. The old names and path remain
  as links; see [docs/MIGRATION.md](docs/MIGRATION.md).

## 1. The problem

When an AI coding agent commits in a repository where the person signs their
commits with a hardware key, 1Password, or a passkey, every agent commit
stops for the person's fingerprint or touch. The common workarounds are
worse: turning signing off (unsigned commits, which fail "require signed
commits" rules), or giving the agent the person's own key (the agent can then
sign anything as the person, anywhere).

agent-commits gives agents a separate signing key, held by a small service, and asks
the person once for a **lease**: permission for agents to sign, on terms the
person sees before approving, in the scope the person chooses (one
repository, every repository under a folder, or every repository).

## 2. Invariants

Each invariant says whether it holds today, and how that's checked.

- **INV-1, the person's commits are left alone.** A `git commit` the person
  types in an interactive terminal (standard input and output both
  terminals) goes to the real git unchanged, with the person's own signing.
  *Holds for terminals.* It does **not** hold for an editor's commit button
  whose `git` is the wrapper (there's no terminal, so the wrapper treats it as
  an agent's), and an agent driving a terminal pane looks like the person.
  Checked by hand in the install test (`docs/RELEASE_CHECKLIST.md`, R5); the
  terminal check itself has no automated test yet.
- **INV-2, interception doesn't depend on the agent.** An agent that runs
  `git commit` through the wrapper is handled without remembering flags or
  commands. *Holds for `commit` only*; `merge`, `rebase`, `cherry-pick`,
  `revert`, `pull` and `am` pass through to the real git and the person's own
  signing. An agent can also bypass the wrapper by calling the real git by
  path.
- **INV-3, no agent signature without a lease.** The service signs only with
  a single-use token, issued only under a lease that is in force and covers
  the repository and branch. *Holds* (tests: `test_lease_engine.rs`,
  `test_human_isolation.rs`, `test_e2e_git_commit.rs`).
- **INV-4, approve once, on fixed terms.** If no lease covers a commit, the
  person is asked once, and shown which branches the lease covers and when it
  ends. A lease's terms are fixed at approval and never grow: using, moving,
  saving or reloading it never extends it, and a later config change can only
  narrow it. Leases are saved, so a crash, restart or sleep doesn't ask again.
  *Holds* (tests: `test_lease_terms.rs`, `test_persistent_identity_leases.rs`).
  The approval is a confirmation dialog, not a biometric check, and its
  default button is Approve.
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
  ~/.agent-commits/bin/git  (agent-commits-git, the wrapper)   same wrapper: stdin and stdout
            |                                 are terminals -> real git,
            | not a terminal (or AGENT_COMMITS_FORCE)  unchanged (person's own signing)
            v
  local rules: forbidden paths, diff size, (optional) message format
            |
            v
  agent-commitsd: lease for this repository? --no--> ask the person once (dialog)
            |                                  approve -> lease saved
            | yes (and branch not protected, rate under limit)
            v
  single-use token (60 s)
            |
            v
  real git commit -c gpg.format=ssh -c gpg.ssh.program=agent-commits-ssh-sign
            |                     with AGENT_EVENT_TOKEN and agent attribution
            v
  agent-commits-ssh-sign: token? --no--> the person's own signer (fallback_program)
            | yes
            v
  agent-commitsd checks and burns the token, signs with the agent key -> <file>.sig
```

## 4. Components

### 4.1 The wrapper, `agent-commits-git` (installed as `git`)

- Installed in `~/.agent-commits/bin`, which the installer puts first on `PATH`
  in shell profiles.
- Every command except `commit` (the first non-option argument, so
  `git -C dir commit` counts) runs the real git unchanged.
- The real git: `AGENT_COMMITS_REAL_GIT` if set, else the first `git` on `PATH` that
  isn't in a agent-commits directory and isn't the wrapper, else `/opt/homebrew/bin`,
  `/usr/local/bin`, `/usr/bin`, `/bin`.
- A commit with standard input and output both terminals, and neither
  `AGENT_COMMITS_FORCE` nor `AGENT_COMMITS_SESSION` set, is the person's: it runs the real git
  unchanged.
- Otherwise it's an agent's. The repository is the canonical path of
  `git rev-parse --show-toplevel`; the branch is `git branch --show-current`,
  or `HEAD` when detached. It then:
  1. checks the local rules against the staged changes: `forbidden_paths`,
     `max_diff_lines` (skipped when `AGENT_COMMITS_ALLOW_LARGE_DIFF` is set), and, if
     `enforce_conventional_commits` is on, the `-m` message's format;
  2. asks the service for a lease (the reason sent is always "Autonomous
     coding agent commit"; any duration it sends is ignored);
  3. asks for a token;
  4. runs the real git with `commit.gpgsign=true`, `gpg.format=ssh`,
     `gpg.ssh.program` set to `agent-commits-ssh-sign` next to the wrapper,
     `user.signingkey` set to the agent's public key, the token in
     `AGENT_EVENT_TOKEN`, and author and committer set by the attribution
     mode.

### 4.2 The signing program, `agent-commits-ssh-sign`

Git runs it as `gpg.ssh.program` with ssh-keygen's arguments. Without a
token it runs `fallback_program` (the person's own signer, detected by the
installer) with the same arguments. With a token it sends the buffer to the
service and writes the signature it gets back to `<file>.sig`. It never reads
the agent key. `agent-commits` accepts the same arguments, as `agent-sign` did.

### 4.3 The service, `agent-commitsd`

- One per user, run by launchd (`com.agentcommits.agent-commitsd`) or a systemd
  user service (`agent-commitsd.service`). It listens on
  `~/.agent-commits/daemon.sock` (0600, in a 0700 directory), one thread per
  connection; the lock isn't held while a dialog is open.
- Holds the agent key: an ed25519 seed in `~/.agent-commits/keys/agent_ed25519`, 0600,
  **not encrypted**, generated on first start if missing.
- Reads the config once, when it starts: a change needs a restart. A
  `max_lease_ceiling` it can't read stops it. Environment variables in the
  service's own environment (`AGENT_COMMITS_AUTO_APPROVE`, `AGENT_COMMITS_LEASE_MODE`, ...)
  override the file.
- Asks the person, in order: on macOS an AppleScript dialog; on Linux with
  `DISPLAY` or `WAYLAND_DISPLAY`, `zenity` or `kdialog`; otherwise a prompt
  on its own terminal, which it has only when started by hand. With none of
  these it refuses the lease and says it couldn't ask. With `auto_approve`,
  every lease is granted without asking.
- Tokens are single-use and expire after 60 seconds. A token authorises one
  signature of whatever buffer is sent with it; the service doesn't check the
  buffer is a commit.

### 4.4 Leases

Saved in `~/.agent-commits/leases.json` (0600, written to a temporary file, synced,
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
  coverage: repository | folder <path> | everywhere   # chosen at approval; absent = repository
```

- A lease covers what the person chose in the dialog: the repository asked
  from, every repository under the folder that holds it (compared by whole
  path components, so `/w/dev` never covers `/w/dev2`), or every
  repository. A folder or everywhere lease covers every unprotected branch,
  and is only offered when the config lets leases follow branches. A commit
  uses the most specific lease that covers its repository and branch.
  Unattended approval (`auto_approve`) grants this repository only.
- Each lease is in force until its effective end: the end
  recorded at approval, brought forward if the current config's cap for its
  mode is shorter (`max_lease_ceiling` for `identity`,
  `default_lease_duration` for `timed`), never pushed back.
- `process` mode isn't tied to a process: it works as `timed`, and the
  dialog and the service's log say so.
- With `scope = "branch"` and `allow_branch_switching = true` (the defaults)
  a lease covers every unprotected branch of its repository and follows the
  agent between them; the dialog says so. Otherwise it covers only its
  branch, and another branch needs a new approval.
- Commits are limited per repository to `max_commits_per_minute` in a
  sliding 60-second window. There's no cap on a lease's total commits.
- Leases belong to the machine's user, not to a particular agent: every
  agent on the machine shares them.

### 4.5 Operations (the socket protocol)

Newline-delimited JSON, unchanged from agent-sign.

| Request | What the service does |
|---|---|
| `RequestLease {repo, branch, intent, duration_secs}` | Refuses a protected branch without asking. Returns the lease if one covers the branch (moving a branch-following lease to it); otherwise asks the person and grants on approval. `duration_secs` is ignored. |
| `IssueToken {repo, branch}` | Checks branch rules, that the lease is in force and covers the branch, and the rate limit; counts the commit; returns a token. |
| `SignCommit {token, buffer_b64}` | Burns the token and returns the signature. |
| `ListLeases` | The leases, with commit counts and when each ends. |
| `RevokeLease {repo, branch, all}` | Ends the lease filed under `repo`: a repository's path, a folder's path, or `everywhere` (an error if none matches); or all of them; and saves. `branch` is ignored. |
| `GetStatus {repo}`, `Ping` | Status and health. |

### 4.6 Configuration

Built-in defaults, then `~/.agent-commits/config.toml`, then the repository's
`.agent-sign.toml` and `.agent-commits.toml`, then `AGENT_COMMITS_*` (or `AGENT_SIGN_*`)
environment variables. Which program reads what matters:

- **The service** reads only `~/.agent-commits/config.toml` and its own environment:
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
allow_branch_switching = true     # with branch scope: follow the agent between branches
default_lease_duration = "2h"     # life of a timed lease
max_lease_ceiling = "none"        # longest life of an identity lease, e.g. "7d"; unreadable = service won't start
block_branches = ["main", "master"]   # exact names, or a prefix ending in "*", e.g. "release/*"
allow_main_branch = false         # true turns branch protection off entirely
max_commits_per_minute = 10
auto_approve = false              # true grants every lease without asking

[security]                        # read by the wrapper (repository files and environment apply)
forbidden_paths = [".github/workflows/*", ".circleci/*", "*.pem", "*.key", "id_rsa*", "id_ed25519*"]
max_diff_lines = 2000
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
# agent_key_path = "~/.agent-commits/keys/agent_ed25519"
```

The author name of an agent commit is the agent that made it, when that can
be told and `[agent] name` is still the default ("Agent", or agent-sign's
"Antigravity Agent"): `AGENT_COMMITS_AGENT_NAME` if the agent was started
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
  agent-commits/v0.1` and `X-Agent-Lease: <lease id>` trailers. A message from `-F` or
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

agent-commits' current protections assume an agent that cooperates: it runs `git`
from its `PATH` and doesn't set out to get around agent-commits. Agents today run as
the person's own user account, and agent-commits doesn't change that.

| Threat | What agent-commits does today | Gap |
|---|---|---|
| An agent signs as the person with the person's key | The agent key is separate; agents never talk to the person's signer through agent-commits. | An agent can still call the real git (or the person's signer) directly. |
| The agent key is copied | It's registered on GitHub as a signing key only, so it can't log in, clone or push. | It's unencrypted and readable by the person's user, so any process running as them can copy it, and commits signed with it show as Verified for the person. |
| An agent approves its own lease | The dialog comes from the service, not the agent. | An agent running as the person can edit the config (`auto_approve`), start its own service, or answer a terminal prompt. |
| Runaway commit loops | `max_commits_per_minute` per repository. | No total cap per lease. |
| Commits on protected branches | Refused on every token. | Detached HEAD isn't protected; `allow_main_branch` turns protection off. |
| Changes to CI workflows or key files | `forbidden_paths` and `max_diff_lines` in the wrapper. | A repository's `.agent-commits.toml` or an environment variable, both writable by the agent, can loosen them. |
| Approving by accident | The dialog states the repository, branch, coverage, end, and the agent's reason. | Its default button is Approve, and the dialog text is built into an AppleScript string. |
| Mixing agents' work | None. | One key and one set of leases per machine user; agents aren't told apart. |

The release checklist (`docs/RELEASE_CHECKLIST.md`) tracks the work on these
gaps: a separate service user (so agents can't read the key or approve their
own leases), attribution to a separate GitHub machine account, and a dialog
with no default Approve.

## 6. Tests

`cargo test --locked` runs them all; the end-to-end ones start their own
service in a temporary home with its own socket, so they never touch an
installed agent-commits.

| File | What it shows |
|---|---|
| `test_human_isolation.rs` | Without a token, signing goes to the person's signer; a bad token is refused. |
| `test_interceptor.rs` | Only `commit` is intercepted; `split` and `trailers` attribution. |
| `test_lease_engine.rs` | Granting, commits under a lease, protected branches, rate limit, branch switching, revocation. |
| `test_lease_terms.rs` | Terms fixed at approval; config narrows, never widens; the dialog's terms; the unreadable ceiling. |
| `test_persistent_identity_leases.rs` | Leases survive restarts; revocation persists; ceiling; scope. |
| `test_crypto_verification.rs` | Keys and signatures in OpenSSH format, verified by `ssh-keygen`. |
| `test_signature_equivalence.rs` | Every program name makes byte-identical signatures to agent-sign's. |
| `test_e2e_git_commit.rs` | Real git commits through the wrapper, signing program and service, verified by git; old and new names. |
| `test_switch_over.rs` | An agent-sign install switched to agent-commits keeps signing without a new approval. |
| `test_migration.rs` | Moving `~/.agent-sign` to `~/.agent-commits`. |
| `test_refusals_and_revoke.rs` | "Couldn't ask" versus "denied"; revoking a repository with no lease is an error; `agent-commits revoke .`; the doctor's advice. |

Not covered by an automated test yet: the wrapper's terminal check (INV-1),
the real dialogs, and the installer and uninstaller (covered by the install
test in the checklist).
