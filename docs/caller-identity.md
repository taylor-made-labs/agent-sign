# Caller identity: who is asking for a signature

Status: being built. Written 31 Oct 2026, after the independent security
review of `feat/servers` at f3c9278. It's done when every test in
`tests/test_caller_identity.rs` and `tests/test_caller_identity_extra.rs`
passes here, and every test in `tests/test_caller_identity_sitting.rs`
passes on the server after the sitting.

Built so far (build plan steps S1 to S8, and the suite PM's decisions D1 to
D4, 31 Oct 2026 and 1 Nov 2026):

- **The approval path** (path 1 below): `[approvals] commitments_key` in
  agent-sign's own config, and the `SignApproved` request
  (`src/commit_approval.rs`, the handler in `src/bin/agent_signd.rs`). The
  approval binds the whole commit (D3): its `commit_sha256` must be the
  SHA-256 of exactly the unsigned commit object presented. It
  also requires the commit's author to be the approved principal, checks
  and records the nonce in one step under the service's lock, synced to
  disk before signing, and neither needs nor leaves a lease. Its rate
  limit is the approvals themselves: one signature per approval, each
  needing the commitments key; `max_commits_per_minute` doesn't apply. An
  approved principal is refused to the plain path from then on, and the
  approval path refuses a principal the plain path is signing as in this
  run. (The launcher, when built, must also never draw a session whose
  principal an approval has named: `~/.agent-sign/approvals/principals`.)
- **Attestations** (`src/attestation.rs`): approved commits' certificates
  carry `attestation@agent-sign` = `approval sha256=<hash of the approval
  text>`. Certificates from today's plain path carry none, and keep the key
  id that says the name was claimed.
- **The committer check**: a token's signature is refused unless the
  commit's one committer is the token's principal (P2).
  A launched session's token also refuses a commit whose one author is
  another session running now, a person's name the service knows, or a
  person's email address it knows (review finding F7; the address, re-check
  R3: the `[human]` email and any `[identity] people` entry written as an
  address, compared whole, case-insensitively after NFKC, so an address whose
  local part has no ASCII letter or digit is caught too); any other author is
  kept, so replayed commits (an earlier session's too) keep theirs.
- **`agent-sign verify <rev>`** (`src/verify.rs`): checks the signature
  with the system's `ssh-keygen` (absolute path) against a trust file the
  verifier chooses (`--allowed-signers <file>`; in system mode always
  `/etc/agent-sign/allowed_signers`; else git's global, then system, config,
  never the repository's own, which a session can write), at the committer's
  date, on the commit's own bytes (replace refs ignored, and the bytes must
  hash to the commit's name), and only then prints the attestation;
  otherwise `not verified: <why>`. Exit 0 only when verified and attested,
  in both the human and the JSON form; 1 for any other verdict, 2 when it
  can't run. The signature vouches for the committer, and the author line is
  the commit's to write, so the JSON also gives `author` (the author's email
  as the commit has it) and `author_matches_signer` (`true` only when the
  commit is verified and the author is exactly the signer): **a gate that
  needs the author to be the agent requires `author_matches_signer` to be
  `true`.** The author never changes the verdict or the exit code; the human
  form prints it as an `author:` line, filtered like the committer.
- **The authority without OpenBao** (D2, P3; `src/state_lock.rs`): the
  service takes an exclusive `flock` on `~/.agent-sign/agent-signd.lock`
  before it writes anything in the state folder (a stale socket's removal
  included), so a second service for the same state stops with a message.
  The authority lives in the service's memory for its lifetime. A start
  writes only the live public key (`keys/agents_ca_ed25519.pub`, and the
  lock file), never `agents_cas.pub` or the managed block. **`agent-sign
  trust install` is the only writer of trust**: it records the live
  authority in `agents_cas.pub` and rewrites the managed block; the
  installer runs it once the service is up. `agent-sign trust-line` prints
  the recorded authorities, plus the live one only while a service holds
  the lock and wrote it this run. `agent-sign doctor` says when the live
  authority isn't trusted yet. Known gap, by design until a keystore-backed
  authority (backlog): after a restart, new commits aren't trusted until
  `agent-sign trust install` runs again. In one account this guards
  against accidents and a second service, not against the account itself,
  which can edit its own allowed-signers file; the boundary is system mode.

- **The launcher and sessions, in one account** (build step S6, decision
  D4; `src/launch.rs`, `src/session.rs`, the session code in
  `src/bin/agent_signd.rs`): `agent-sign launch --agent <name> --
  <program> [args...]`, Linux only. The service makes the session's id
  (128 random bits) and principal, after the same name rules as any token,
  so a reserved or person's name, or one not allowed, gets no session and
  the program never runs; it never draws a principal a session, an
  approval or the plain path has had (`~/.agent-sign/sessions.log`, synced,
  read at start). Only a caller running as the service's own account may
  launch, and not once a system config exists (`/etc/agent-sign/system.toml`;
  checked at every launch, by the launcher and the service). The session's
  channel is one end of a `SOCK_SEQPACKET` pair, inherited as the
  descriptor `AGENT_SIGN_CHANNEL_FD` names; a client counts it only if it
  is such a socket whose peer runs as the service's account, and opens a
  private stream over it for each request (`SCM_RIGHTS`). Tokens issued on
  a session's channel are bound to the session's id: they sign only on
  that channel, while the session lasts, and the plain path never gets a
  token for a launched session's principal. When the launcher's
  registration closes, the session ends: its channel is shut and refused,
  its tokens and key dropped, its id never used again. The launcher strips
  every identity claim from the environment (keeping `AGENT_SIGN_SOCKET`,
  `_REAL_GIT`, `_BIN` and `_CONNECT_WAIT_MS`), makes itself non-dumpable,
  closes its copy of the channel once the program has it, and runs the
  program under bwrap: its own PID and IPC namespaces, `/` read-only, only
  its own working copy (the git work tree it starts in, and that
  repository's git folders) and a private `/tmp` (`TMPDIR`) writable,
  `~/.agent-sign` and agent-sign's programs read-only even inside a
  working copy, a private `/dev`, and an empty `/run/user/<uid>` so it
  can't reach this account's user services. A working copy that holds the
  home folder or agent-sign's state is refused. Certificates of launched
  sessions carry `launcher session=<id> uid=<n> isolation=pid-namespace`,
  and `agent-sign verify` says "launcher, same account: isolated from
  other launched sessions, not from other processes of this account".
  A session's channel takes only its own commit requests (ping, who it
  is, a lease, a token, a signature): not another session's launch (a
  request on the service's socket from a process in a PID namespace below
  the service's is refused too, read from `NSpid` in `/proc/<pid>/status`,
  because the launcher is non-dumpable and its `ns/pid` link can't be
  read), and not an approval. Known gap, recorded by an ignored test
  (`d4_a_plain_process_of_the_account_cant_take_a_sessions_channel`): a
  plain process of the same account can take a session's channel with
  `pidfd_getfd`; only a uid per session (system mode) closes it. Two
  smaller limits of one account: sessions started in linked worktrees of
  one repository share that repository's common git folder (hooks and
  config included), so they are kept apart from each other only when each
  has a repository of its own; and what a session writes into its own
  working copy (a hook, say) is there for whoever runs git in it next,
  outside the sandbox. On macOS, `launch` says there is no attested
  session there and runs nothing (the code builds for macOS; it was
  checked with `cargo check --target aarch64-apple-darwin` on hetzner, not
  run). In a session, `agent-git` takes its identity from the service
  (`SessionIdentity`), never from marks or `AGENT_SIGN_AGENT_NAME`.
  Because tokens are bound to their session and the plain path refuses a
  launched session's name, two tests the plan gave to the switch (S8),
  `p1_a_socket_message_naming_a_session_gets_no_signature_as_it` and
  `p5_a_token_captured_from_a_sessions_git_run_signs_nothing_else`, passed
  from that step on; the switch itself (P7) is the next item.

- **The switch and the plain path** (build steps S7 and S8, decision D1,
  1 Nov 2026; `src/bin/agent_git.rs`, `src/bin/agent_signd.rs`): a caller
  that is not a launched session (no valid channel) gets no identity token
  and no signature, whatever it claims. The service answers a token request
  from the plain socket with the name rules first (allowed agents, a
  person's name, the machine's domain, a name an approval or a session
  holds), so those refusals keep their words, and only then with "no token:
  agent-sign signs an agent's commit only for a session a launcher
  started". An agent run by a process with agent marks and no launcher (the
  **plain path**) **commits unsigned**, under the agent's own names, with
  exactly one line on stderr that says it is unsigned because no launcher
  started it. Unsigned claims nothing. The wrapper first makes the same
  refusals as before: protected branch, forbidden paths, the diff limit
  (its own checks), then asks the service the policy-only question
  `CheckPlainCommit` (the name rules, the protected branches, the rate limit,
  which counts the commit in the repository's window), and makes no lease,
  token or signature. Commits that merge, rebase, cherry-pick, revert, am or
  pull make likewise go unsigned for such an agent. Where the service can't
  be reached, the plain path refuses, as it always did (the rules couldn't be
  checked). `agent-sign verify` on an unsigned commit, or on one whose
  signature isn't attested (an `unattested` or a pre-switch certificate),
  adds that it can live on a branch, but merging to main will require an
  attested signature (launcher or approval). The merge gate that enforces
  that is a backlog thread; it is not built.
  `agent-sign doctor` says the same in its health check, and no longer says
  every name is "claimed".
  What the plain path does *not* catch, said plainly: the checks that the
  service makes on a *finished* signed commit don't exist for an unsigned
  one. A pre-commit hook that stages a forbidden file after the wrapper's
  look, a cherry-pick or merge that brings one in, and a `rebase <upstream>
  <protected branch>` (the run is checked for the branch it starts on) go
  through on the plain path; for a launched session the service refuses all of
  them at signature time. An unsigned commit is allowed on a branch whatever
  it holds; what matters for it is the merge gate.
- **Tests moved onto the launcher** (S7): every existing test that expected
  a plain process with an agent's marks to get a Good signature now starts
  the agent with `agent-sign launch` (or plays the launcher in-process,
  `tests/support/launch.rs`), each marked "DELIBERATE EVAL CHANGE (P7/D1,
  1 Nov 2026): agents sign only when launched". The plain path's refusals
  keep one test each, the `d1_*` tests in `tests/test_launcher_policy.rs`.

Not built yet: `agent-git` saying when the live authority isn't trusted yet,
and the merge gate.

- **System mode** (build steps 1 to 5 of `docs/system-mode.md`): built and
  tested here; not yet installed anywhere. It adds the `agent-sign` account,
  the launcher `agent-launchd` in its own account, one account per session
  (a slot), the OpenBao certificate authority, and root's trust file. The
  sitting script installs it.

### Status of the properties

| Property | Where it is guarded | State |
|---|---|---|
| P1, P2, P5, P8 | `tests/test_caller_identity.rs`, `_extra.rs` | built; passing (full suite on hetzner, 1 Nov 2026: 598 passed, 0 failed) |
| P3 (one account) | `tests/test_caller_identity.rs` | built; passing (full suite on hetzner, 1 Nov 2026: 598 passed, 0 failed) |
| P3 (service in its own account) | system mode, sitting tests | passes only after the sitting |
| P4 (session against session) | one account: not closed; system mode: a uid per session | passes only after the sitting |
| P6, P7 | `tests/test_caller_identity.rs`; P7 also the sitting | P6 built; P7 on the server after the sitting |
| Launcher, caller identification, issuer, sitting script | `test_launcher_daemon.rs`, `test_caller_registration.rs`, `test_session_end_check.rs`, `test_issuer_openbao.rs`, `test_sitting_script.rs` | built; passing (full suite on hetzner, 1 Nov 2026: 598 passed, 0 failed) |

### The sitting tests that pass only after the sitting

The six tests in `tests/test_caller_identity_sitting.rs` are ignored in a
plain `cargo test`, and fail with "NEEDS THE SERVER SITTING" until the
accounts exist. Run them as the agents account, with one launched session
running (the sitting script leaves one):

- `sitting_p3_the_agents_account_cant_read_or_change_agent_signs_state`
- `sitting_p3_the_agents_account_cant_reach_the_service_process`
- `sitting_p3_a_service_the_agents_account_starts_is_trusted_by_no_verifier`
- `sitting_p1_p7_a_plain_agents_process_gets_no_attested_signature_from_the_service`
- `sitting_p4_the_agents_account_cant_reach_a_launched_session`
- `sitting_p1_the_agents_account_cant_launch_a_session_itself`

The thread is done when these six pass on hetzner, the sitting script's own
end checks print no FAIL, and the full `cargo test` passes.

## The problem

agent-sign exists so that a commit signed as an agent was really made by
that agent. Today it can't promise that. Every agent on a server runs as one
Unix account (`agents`), and on the Mac several Claude Code sessions share
Taylor's account. The service never checks who is calling. It believes what
the caller says: a session id (in the environment, and readable by any
process of the account in `/proc/<pid>/environ`) and an agent name
(`AGENT_SIGN_AGENT_NAME`, or a principal in a socket message). So any
process in the account can:

- sign as any other session, or under any agent name the config allows;
- edit `config.toml` and restart the service, widening `allowed_agents` or
  `allow_main_branch`;
- start its own `agent-signd`. Each start made a new authority and added it
  to `agents_cas.pub` and to the managed block in the allowed-signers file.
  So the new service's signatures verified as Good for any
  `*@<machine>.agents.local`, and they skipped the allowlist, the date
  window and the main-branch rule. (Fixed for a second service on the same
  state by the state lock and `trust install`, D2; the account itself can
  still edit its trust files, until system mode.)

Moving agent-sign into its own account fixes the last two, not the first.
The service would still see every caller as the one `agents` uid, and would
still have to believe what it's told.

## The rule

**Identity comes from whoever started or approved the work, never from the
caller's claim.** A signature names an agent only when something the caller
can't forge says which agent it is: a signed approval, or the kernel's
answer to "which process is on the other end of this socket".

There are two ways to get there. The suite uses the first. Agents run
outside the suite (Claude Code, Codex, Cursor with agent-sign on its own)
use the second.

### Path 1: the suite's model layer, signed approvals

Agents never call agent-sign. A model's tool call is approved and signed by
the commitments check, and machine-mesh's job runner runs it in its sandbox.
To commit, the runner presents agent-sign with a **commit approval** signed
by the commitments approval key. agent-sign checks the signature itself and
signs as the agent the approval names. The agent's own code has no route to
agent-sign at all.

An approval must bind everything a replay could change (P5). The tests use
this shape, which should become the commitments format's commit kind:

| Field | What agent-sign checks |
|---|---|
| `principal` | in this machine's domain, an allowed and unreserved name, and the commit's committer |
| `machine` | this machine |
| `repo`, `branch` | the request's working copy and branch, and the branch isn't protected |
| `tree`, `parents` | the commit's own `tree` and `parent` lines, so no other content |
| `commit_sha256` | the lowercase hex SHA-256 of exactly the unsigned commit object presented (the bytes git hands its signing program, without `gpgsig`), so no other message, author or committer name, or date (D3). Required: an approval without it is refused |
| `nonce` | never seen before; checked and recorded in one step under the service's lock, synced to disk before signing; kept in agent-sign's own state |
| `expires_at` | in the future |

The runner builds the unsigned commit object first, with fixed author and
committer dates, hashes it, gets the approval for that hash, and presents
both. The commit's author and committer emails must also be the
principal. The path needs no lease.

The signature is an SSHSIG over the exact approval text, in the namespace
`agent-sign-commit-approval`. Any other key, namespace or text is refused
(P6). The key is set as `[approvals] commitments_key` in agent-sign's own
config, which agents can't change (P3).

Two things to settle with the suite:

- machine-mesh's tool-call runner says it runs "never a commit". So a
  commit approval is a kind of its own, and nobody has defined it yet. The
  field names above are the tests'. When the commitments format is written,
  align them in one change to the test file.
- Who presents the approval doesn't matter, because the approval is what's
  trusted. A stolen approval is useless, because it signs one exact commit
  object (`commit_sha256`), once. Presented first by a thief, it gets that
  same commit signed, which is what was approved.

### Path 2: outside agents, a trusted launcher

Each agent is started by a launcher, `agent-sign launch --agent <slug> --
<program>`. The launcher, not the program, picks the identity: the slug it
was given, a session it makes, and this machine's domain. The service learns
the caller from the kernel (`SO_PEERCRED` uid and pid, and a pidfd for
liveness), or from which per-session channel the request came in on. It
never learns it from a field in the request.

What is achievable, measured on hetzner (31 Oct): `bwrap` makes user and PID
namespaces without root, because AppArmor allows bwrap. Plain `unshare -U`
is refused, because `kernel.apparmor_restrict_unprivileged_userns = 1`. Yama
`ptrace_scope = 1`.

| | A. Same uid, bwrap sandbox, per-session socket fd | B. A uid per session (systemd DynamicUser) |
|---|---|---|
| Root needed | No | Once, at the sitting: the unit template, and a polkit rule that lets the launcher's account start only `agent-session@*.service` |
| How the service knows the caller | The connection is the session: the launcher makes a socketpair per session and hands one end in as an inherited fd | `SO_PEERCRED` uid, mapped to a session by the launcher's registration; the per-session fd too |
| Session against session (P4) | Yes: separate PID namespaces hide each other's `/proc`, and the fd can't be taken (`pidfd_getfd` needs ptrace rights) | Yes, enforced by the kernel's uid checks |
| Forged claims (P1) | Yes, for sandboxed callers | Yes |
| **A plain process of the same uid outside any sandbox** | **No.** It sees sandboxed processes in `/proc`, reads their environment (Yama doesn't cover `environ`), can connect to any socket the uid can, and can replace the launcher's files. The kernel shows the service the same uid, so it can't tell them apart | Yes: it has another uid |
| Fits agents run as they are today (Claude Code in a terminal in the `agents` account) | No: that is exactly the unsandboxed same-uid process | Yes: they become per-session uids, and the old `agents` account gets nothing attested (P7) |
| Costs | bwrap's bind list must give the agent its working copy and tools | Working copies need group write, or are owned by the session uid. DynamicUser uids are reused, so a registration is (uid, pidfd, session) and is dropped when the unit stops |

**Recommendation: B, with A's per-session fd as the channel.** A alone moves
the gap rather than closing it. As long as anything runs unsandboxed in the
agents account, and today everything does, that thing can see into the
sandboxes and talk to the service as the same uid. B makes the kernel tell
callers apart. The fd still helps, because then the service needs no socket
path that other uids can reach. B costs one root step, at the sitting.

**On the Mac** there is neither DynamicUser nor rootless namespaces. Peer
credentials (`LOCAL_PEERCRED`, `LOCAL_PEERPID`) give only Taylor's uid,
shared by every session. So outside agents on the Mac can't be attested.
Their commits are refused, or at most signed as "unattested" (P7). On the
Mac, attestation comes through path 1.

### agent-sign in its own account (needed, not sufficient)

- The account (`agent-sign`) holds the state: config, leases, the approval
  nonces, the authority history. The service runs as that account under a
  system unit that the agents account can't restart (P3).
- **The authority is stable, not made at each start.** Making it at start,
  and trusting whatever starts, is P3's hole whatever the accounts are. The
  certificate authority lives in OpenBao's SSH secrets engine. agent-sign's
  account has its own AppRole, which may only sign with its role, and the
  key never leaves OpenBao. The trust line is installed once, at the
  sitting, into `/etc/agent-sign/allowed_signers` (root-owned,
  world-readable), and git's system config names it. **A service never
  writes trust at start.** That's checked here by
  `p3_starting_another_service_never_changes_what_verifiers_trust`.
- Session keys stay in the service's memory. The process is already
  non-dumpable (`hardening.rs`; checked by `test_memory_guard.rs`).

### What verification says (P8)

Each certificate carries how its identity was established, as an OpenSSH
certificate *extension* (`attestation@agent-sign`). Verifiers that don't
know an extension ignore it, so ordinary `git log --show-signature` keeps
working. The values: `launcher` (with the kernel-checked uid), `approval`
(with the approval's hash), and `unattested`. A certificate without the
extension is from before the fix, and `agent-sign verify` reports it as
"claimed by a process in a shared account", never as proven.

An unattested signature, if one is allowed at all, must not be Good under
the machine's trust for the attested domain. Use its own domain
(`*@unattested.<machine>.agents.local`), or don't sign. The default should
be not signing.

**Anything that decides must use `agent-sign verify --format json --allowed-signers <file>` and never git's own verdict** (`%G?`, `git log --show-signature`, `git verify-commit`): a merge gate, a server-side check, a hook, a release script. git checks an SSH certificate by handing `ssh-keygen` the commit's date as local time with no zone (`-Overify-time=YYYYMMDDHHMMSS`), and OpenSSH 10.0p2 (Debian 13, the Raspberry Pi) misreads that whenever the clock zone isn't UTC: it takes the local time as UTC, so the certificate's window is shifted by the zone's offset, and git can call a signature unverified that is good, or the other way round. OpenSSH 10.2p1 reads it correctly. `agent-sign verify` gives `ssh-keygen` the date as UTC with a `Z` and is unaffected, and it also refuses a certificate from an authority the trust file doesn't hold and a commit dated outside its certificate's window whatever git says. A gate reads `verify --format json` (exit 0 only when verified and attested, 1 for any other verdict, 2 when it can't run) and passes the trust file itself with `--allowed-signers <file>`: the verifier never takes the trust file from the repository's own git config, which the session being checked can write, and it ignores `refs/replace/*`, so a pushed replace ref can't make one commit read as another. `agent-sign doctor` warns when git on a machine is affected; running git with `TZ=UTC`, or a newer OpenSSH, makes git's own check read right too.

## The trust that remains, and where it lives

| Trusted | Where | What its compromise allows |
|---|---|---|
| The commitments approval key | OpenBao transit (non-exportable), usable only by the commitments check's own account | Approving any commit, for any agent, on any machine whose agent-sign names this key, within each machine's domain and name rules |
| The launcher | Its own account (`agent-launch`); it registers sessions with agent-sign on a launcher-only socket, checked by peer uid; any signing key it needs is in OpenBao | Starting sessions under any allowed name. So who may ask the launcher matters: Taylor (signed by Taylor's device) or an approved job, never the agents account (sitting test) |
| agent-sign's account and its OpenBao role | `agent-sign` account; the CA in OpenBao's SSH engine | Certifying any principal in the machine's domain |
| root and the kernel | the machine | Everything |

What none of this covers:

- What an agent does inside its own session. That is the agent.
- Whether the content of a launcher-path commit was approved. The launcher
  binds the identity, not the content. Path 1 binds both.
- The Mac's outside agents, as above.

## Where I push back on the direction

The direction is right. The changes I'd make:

1. **bwrap alone isn't enough** while unsandboxed agents share the uid (see
   the table). Servers need a uid per session.
2. **The approval must bind content and committer** (tree, parents,
   committer, nonce), not only the agent. Otherwise one approval signs
   anything.
3. **Launching is itself a privilege.** If the agents account can run the
   launcher with any `--agent`, it picks its own name, and P1 fails again.
   Launch requests need Taylor's signature or an approval.
4. **The per-start authority has to go**, whatever the accounts. Trust that
   grows each time a service starts is P3's hole.
5. **Existing tests will conflict.** Many existing tests expect a plain
   process with Claude Code's marks to get a Good signature (for example,
   `test_per_agent_identity.rs` and `test_machine_names.rs`). Under P7 it
   mustn't. The fix moves those tests to the launcher, which runs as the
   same uid in tests, as a deliberate change to them, said as such.

## The tests

`tests/test_caller_identity.rs` runs as one account, with no root. Every
test fails today, each for its own stated reason:

| Property | Test | Fails today because |
|---|---|---|
| P1 | `p1_a_process_with_a_copy_of_a_sessions_environment_cant_sign_as_it` (Linux) | a copy of the environment signs as the session |
| P1 | `p1_a_socket_message_naming_a_session_gets_no_signature_as_it` | the service believes the principal in the message |
| P1 | `p1_identity_variables_set_inside_a_session_dont_change_who_signs` | the variables are the identity |
| P1 | `p1_an_ended_sessions_id_is_never_signed_again` | the same session id makes the same principal |
| P2 | `p2_reserved_names_are_never_certified_whatever_the_config_says` | a listed `taylor`, `root` or `admin` is certified |
| P2 | `p2_a_commit_naming_the_person_as_committer_is_never_signed` | any committer line is signed |
| P2 | `p2_an_approval_never_names_another_machine_or_a_reserved_name` | no approval path (control) |
| P3 | `p3_starting_another_service_never_changes_what_verifiers_trust` | each start rewrites the trusted block |
| P4 | `p4_one_session_cant_read_anothers_environment_files_memory_or_channel` (Linux) | one session reads another's environment |
| P5 | `p5_a_token_captured_from_a_sessions_git_run_signs_nothing_else` | `AGENT_EVENT_TOKEN` signs whatever comes with it |
| P5 | `p5_an_approval_signs_only_what_it_names_once_and_in_time` | no approval path (control) |
| P6 | `p6_only_the_commitments_approval_key_can_approve` | no approval path (control) |
| P7 | `p7_a_process_no_launcher_started_gets_no_attested_signature` | it is Good in the attested domain |
| P8 | `p8_a_self_asserted_signature_is_reported_as_claimed_never_as_proven` | no `agent-sign verify` |
| P8 | `p8_a_launched_sessions_signature_says_how_its_identity_was_established` | no launcher |
| P8 | `p8_an_approved_commits_signature_says_it_came_from_an_approval` | no approval path (control) |

Until the launcher exists, a test's "session" is a plain process that claims
its identity the way agents do today. That makes every attack easier, never
harder, so it can't make a test pass.

`tests/test_caller_identity_sitting.rs` holds what needs separate accounts:
P3 (state, process, a rogue service, the trust file), P4 (a launched session
under its own uid), and P1 and P7 (the real service and the launcher seen
from the agents account). Every test there is `#[ignore = "needs the server
sitting: ..."]`. Run them as the agents account with `cargo test --test
test_caller_identity_sitting -- --ignored`. They fail with "NEEDS THE SERVER
SITTING" until the accounts exist, and never pass for lack of something to
check.

Already guarded by existing tests, so not repeated here:

- the service's memory is non-dumpable (`test_memory_guard.rs`);
- the person's own name, from `[human]` or git, is refused in
  `allowed_agents` (`test_allowed_agents.rs`);
- raw token requests in another machine's domain are refused
  (`test_machine_names.rs`).
