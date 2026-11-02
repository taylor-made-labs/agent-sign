# System mode: agent-sign in its own accounts on a server

Status, 1 Nov 2026: built through step 5 of the build order below, not yet
run on a real machine. This is the last part of the caller-identity work
(docs/caller-identity.md, build plan steps S10 and S11). The suite PM's
decisions D1 to D6 (31 Oct and 1 Nov 2026) bind it; where this note and the
build plan differ, this note follows the decisions.

**Built (steps 1 to 5), each passing its own tests:**

- Step 1: `/etc/agent-sign/system.toml` and the mode switch (`src/system_config.rs`).
  Its existence means system mode; unknown keys are refused.
- Step 2: who is asking, by uid, cgroup and pidfd, with the launcher-only
  socket and session registration; the OpenBao issuer is wired into the
  service's start (`src/issuer_openbao.rs`, `src/kernel_facts.rs`).
- Step 3: the launcher `agent-launchd`, `agent-sign launch`,
  `agent-sign session-exec` and `session-end`, the slots' folders and Trash
  (`src/launcher.rs`, `src/session_runner.rs`).
- Step 4: the OpenBao issuer, with the dev-server tests marked `--ignored`.
- Step 5: the sitting script and its files, `scripts/sitting/`, tested against
  stand-ins (`tests/test_sitting_script.rs`). On a real machine its final
  checks also start real sessions (a signed commit comes back; one slot can't
  see another; the next session in a slot finds nothing left over).

**Remains:**

- Step 6 and 7 (other repositories): the SSH engine in agentic-credentials,
  and the suite's slot that ships this script.
- Step 9: the independent review of the sitting script (D5) and the security
  review.
- Step 10: the sitting itself on hetzner, run by Taylor with sudo, then an
  agent running the six sitting tests as the agents account. The Pi is a
  second sitting, started only once hetzner passes.

How to run agent-sign on a server, in plain steps, is in
[INSTALL.md](INSTALL.md#servers-system-mode); what goes wrong is in
[TROUBLESHOOTING.md](TROUBLESHOOTING.md#servers-in-system-mode).

## What it is for, and how we will know it works

Today every agent on hetzner and the Pi runs in one account, `agents`, and
so does agent-sign's service. Anything in that account can change
agent-sign's config, start its own service, and write the trust file git
uses. System mode moves agent-sign out of reach:

- the service runs in its own account, `agent-sign`, under a system unit the
  agents account can't restart;
- the certificate authority lives in OpenBao and never on the machine;
- the only trust file that counts is root's, `/etc/agent-sign/allowed_signers`;
- each launched agent session runs in an account of its own (a "slot"), so
  the kernel, not a claim, says which session is asking;
- the agents account itself can no longer start a session.

On a laptop nothing changes: with no `/etc/agent-sign/system.toml`, agent-sign
stays in one-account mode, with no setup (D4).

**The eval (definition of done for this thread).** All of these, and nothing
widens the scope without the PM choosing to:

1. The six tests in `tests/test_caller_identity_sitting.rs` pass on hetzner,
   run as `agents` with `--ignored` after the sitting, with one launched
   session running. (P4's test first gets the deliberate eval change in
   build step 0.)
2. The sitting script's own end checks print 0 FAIL on hetzner, including the
   D5 trust checks and the D6 slot checks listed under "The checks at the end".
3. Every new test named in "Build order" passes, and the full `cargo test`
   passes on hetzner.
4. The sitting script's stub tests pass (dry run changes nothing, a second
   run changes nothing, every sudo prompt is named, no secret is printed,
   undo restores).
5. Merged to main after the independent review of the sitting script (D5)
   and the security review.

Effort limit: each review gets at most two rounds of fixes; a third round of
findings goes back to the PM rather than looping. The Pi is a second sitting
with the same tests (see "The Pi"), started only once hetzner passes.

## Facts this design rests on (checked read-only on 1 Nov 2026)

- hetzner: kernel 7.0, systemd 259, polkit 127 (rules written in JavaScript
  in `/etc/polkit-1/rules.d`), bubblewrap installed, Yama ptrace scope 1.
- The Pi: kernel 6.18 (aarch64), systemd 257, polkit 126, bubblewrap
  installed, no Yama module, OpenSSH 10.0p2, no `bao` program, no
  `/etc/suite`.
- Both kernels give `SO_PEERPIDFD` (6.5 and later); both systemd versions
  have the unit settings used below.
- No `agent-sign`, `agent-launch` or `agent-slot-*` account exists on either
  machine. `agents` is uid 1001 on hetzner (1003 on the Pi); its home is
  `drwxr-x---`.
- No account for the commitments check exists on hetzner: `getent passwd`
  finds no `suite-commitments`, `commitments`, `ntaild` or `suite-ntaild`.
  The commitments checker (ntaild) runs inside unharness's services as
  `suite-unharness` (`UNHARNESS_NTAILD_PROJECT` in `/etc/suite/hetzner.env`).
  `suite-mig` exists for mig, which ntaild is replacing.
- The user-level `agent-signd.service` is active in the agents account on
  both machines. On both, the agents' global git config sets
  `gpg.ssh.allowedSignersFile=/home/agents/.config/git/allowed_signers`.
  hetzner's agents also set `gpg.ssh.program` to
  `~/.agent-sign/bin/agent-ssh-sign`. `~/.agent-sign/bin` holds plain copies
  of the programs, and `~/.bashrc` puts it first on `PATH`.
- `/etc/gitconfig` doesn't exist on hetzner.
- OpenBao on hetzner answers at `https://hetzner.example.ts.net:8200`
  (CA `/usr/local/share/openbao/ca.pem`, address 100.64.0.10), unsealed.
  It reports **version 2.7.1**; agentic-credentials pins 2.7.2 as a security
  update (GHSA-736f-82w7-hj22). The `bao` program on `PATH` is also 2.7.1.
- No SSH secrets engine is mounted yet: `GET /v1/ssh-agents-hetzner/public_key`
  answers 403.
- agentic-credentials' logins sitting can today make only KV read and
  exact-path write grants (`src/sitting/declaration.ts`). It has no way to
  mount an SSH engine, make a CA or grant `sign`.
- The suite's slot (`step_agent_sign` in `scripts/sitting/hetzner/sitting.sh`,
  suite main 49b257b) runs one file, `$BUNDLE/agent-sign/<script name>`, and
  passes only `SITTING_SUDO_PROMPT_PREFIX` and `--dry-run`.
- The Rust toolchain on hetzner is in the agents' home (`~/.cargo`), which
  the agents account can change. Ubuntu's archive has rustc 1.93; Debian 13
  (the Pi) has 1.85, older than this crate needs (it uses `let` chains,
  stable since 1.88).
- In `src/bin/agent_signd.rs` the service runs git in the caller's
  repository in several places: the content guardrails
  (`guardrails::validate_candidate`), the finished-work sweep (`work.rs`) and
  the branch check for plain commits (`check_asked_branch`).
- The session channel client (`Channel::check`) accepts a channel whose peer
  is "this account, or the owner of the service's socket".
- hetzner has `/usr/bin/crontab` and `/usr/bin/at`, an `/etc/at.deny`, and no
  `/etc/cron.deny`.

## 1. Accounts and files on a server

### Accounts

All are system accounts (uid below 1000), with `/usr/sbin/nologin` as their
shell and no password, so nobody can log in as them and agent-sign's rule
for people's accounts (uid 1000 and up with a login shell) never counts them
as people.

| Account | What runs as it | Home |
|---|---|---|
| `agent-sign` | the service, `agent-signd.service` | `/var/lib/agent-sign` |
| `agent-launch` | the launcher service, `agent-launchd.service` | `/var/lib/agent-launch` |
| `agent-slot-1` to `agent-slot-N` | one launched session at a time each | none at rest (see below) |

N is the setting `[slots] count` in `/etc/agent-sign/system.toml`, default 8
(D6). The sitting takes `--slots N` and writes it there. Raising it later is
a rerun of the sitting with a larger N; lowering it never deletes an account
or its Trash.

Each slot account has its own group of the same name. `agent-launch` is a
member of every slot group, so it can read what a session's end step leaves
for it (and nothing a session keeps private, because sessions run with
`UMask=0077`). Each slot account is added to `/etc/at.deny`, and to
`/etc/cron.deny` (which the sitting creates on hetzner, containing only the
slot accounts, so nobody else is affected). The session unit's
`NoNewPrivileges=yes` already stops `crontab` and `at` from working inside a
session, since both rely on setuid; the deny lists are a second wall.

### Files

| Path | Owner, mode | What it is |
|---|---|---|
| `/etc/agent-sign/system.toml` | root:root 0644 | the machine's settings. Its existence means system mode. No secrets |
| `/etc/agent-sign/allowed_signers` | root:root 0644 | exactly one line: `*@<machine>.agents.local cert-authority,namespaces="git" <OpenBao CA public key>` |
| `/etc/gitconfig` | root:root 0644 | `gpg.ssh.allowedSignersFile = /etc/agent-sign/allowed_signers`, nothing else that agent-sign sets |
| `/opt/agent-sign/<commit>/bin/` | root:root 0755 | `agent-sign`, `agent-signd`, `agent-launchd`, `agent-git`, `agent-ssh-sign` |
| `/opt/agent-sign/<commit>/wrap/git` | root:root, a link to `../bin/agent-git` | the git wrapper, put first on a session's `PATH` |
| `/opt/agent-sign/current` | root:root, a link to `<commit>` | switched in one rename; the previous release stays for undo |
| `/opt/agent-sign/toolchain/` | root:root 0755 | the pinned Rust toolchain the build used (see "Building the programs") |
| `/etc/credstore.encrypted/agent-sign.role-id`, `.secret-id` | root 0600 (systemd-creds) | agent-sign's OpenBao login, readable only by its unit |
| `/var/lib/agent-sign/` | agent-sign 0700 (`StateDirectory=`) | the account's home |
| `/var/lib/agent-sign/.agent-sign/` | agent-sign 0700 | the service's state: lock, leases, approval nonces, `sessions.log`. It is `state_dir_in(home)`, as today, so no code or test needs a special case |
| `/var/lib/agent-launch/` | agent-launch 0700 | the launcher's state: `sessions.log`, launch-approval nonces, returned bundles. Nothing in it is ever opened by systemd |
| `/var/lib/agent-launch-io/`, `specs/`, `logs/` | root:agent-launch 0750, all three | the launcher's I/O folder: the only place systemd, as root, opens a slot unit's spec and output. No account but root can make, rename or remove an entry in it (see "The I/O folder") |
| `/var/lib/agent-launch-io/specs/<n>.json`, `logs/<n>.out` | agent-launch:agent-launch 0600, regular files, made by the sitting for every slot | slot n's session spec, and its output. The launcher opens these and writes into them; it makes nothing there |
| `/var/lib/agent-slots/` | root:root 0755 | the slots' folders |
| `/var/lib/agent-slots/<n>/` | agent-launch:agent-slot-<n> 0750 | slot n's folder. Other slots can't enter it |
| `/var/lib/agent-slots/<n>/current/` | agent-launch:agent-slot-<n> 0770 | the running session's folder, made fresh for each session |
| `/var/lib/agent-slots/<n>/trash/` | agent-launch 0700 | slot n's Trash. No slot can enter it, its own included |
| `/run/agent-sign/daemon.sock` | agent-sign, 0666, made by `agent-signd.socket` | the service's socket for everyone; the service decides by the caller's uid |
| `/run/agent-sign/launcher.sock` | agent-sign:agent-launch 0660, made by `agent-signd-launcher.socket` | the launcher-only socket |
| `/run/agent-launch/launch.sock` | agent-launch, 0666, made by `agent-launchd.socket` | where launch requests arrive |

Why the two public sockets are 0666 and not group-gated: every request on
them is decided by the uid (and for sessions, the unit) that the kernel
reports for the caller, and an account outside `[service] client_accounts`
gets a refusal. A group would add nothing to that, and it would break every
agent process already running when the sitting happens, because a process
only gets a new group at its next login: their commits would stop reaching
the service.

Because any account may connect to the service's 0666 sockets, what a
connection can make the service hold is bounded (review finding L6). Each
connection gets its own thread and its request line is read with `take(limit)`
and a total deadline (`read_request_line` in `agent_signd.rs`): at most 1 MiB
on the main socket (`MAX_REQUEST_BYTES`), 64 KiB on the launcher-only socket,
and `REQUEST_READ_DEADLINE` (10 s) for the whole line counted from the first
read, so a client that sends one byte at a time gets no longer than one that
sends nothing. A line over the limit or past the deadline is dropped without
an answer. If the thread for a connection cannot be started (the account's
thread limit or memory), `spawn_connection` answers that connection with an
error and closes it, and the service carries on; it no longer panics.

The number of connections open at once is capped too (G-signd-2), because a
crowd of them is a crowd of threads that can each hold up to 1 MiB for 10 s.
On the main socket at most `MAX_CONNECTIONS` (256) are served at once, about
270 MiB at worst, and at most `MAX_CONNECTIONS_PER_UID` (64) from any one
account as the kernel reports it, so one account that floods the socket
cannot use up the places the slot accounts need. The launcher-only socket
takes 64 and each session's channel (one-account mode) 64. A connection past
a cap is answered with an error line and closed, not held, and its place is
given back when it ends. A request waiting on an approval prompt holds its
place the whole time, and so does a registration on the launcher-only socket
(the launcher keeps one per live session); real use is a few of each. In
one-account mode a `LaunchSession` connection gives its place back once it
has become the session's registration (it then holds a thread, not a
request, and only the service's own account can open one), so the sessions
open at once are not capped by it.

Two more bounds on what an account that can reach the socket can make the
service keep (F5). The plain path's unsigned checks are counted in a rate
window of their own per repository, apart from the window signing uses, so
a plain caller can never use up a session's window (nor the reverse). Each
kind of window is kept for at most `MAX_RATE_WINDOWS` (4,096) repositories,
dropping idle ones first and then the oldest-used eighth, and a repository
path over 4,096 bytes (Linux's `PATH_MAX`) is refused: in system mode the
service cannot tell whether a path exists (it cannot see `/home`, and a path
it cannot read is not one that is missing), so entries for paths that do not
exist are bounded by the cap and the length limit, not skipped.

### The settings file

```toml
# /etc/agent-sign/system.toml: written by agent-sign's sitting, root-owned.
# Its existence means system mode: one-account launch is refused (D4), and
# clients use the sockets named here.
machine = "hetzner"

[service]
account = "agent-sign"
socket = "/run/agent-sign/daemon.sock"
launcher_socket = "/run/agent-sign/launcher.sock"
trust_file = "/etc/agent-sign/allowed_signers"
# Accounts whose plain-path questions the service answers (they never get a
# signature). Slot accounts and the launcher are added from the settings below.
client_accounts = ["agents", "taylor"]

[launcher]
account = "agent-launch"
socket = "/run/agent-launch/launch.sock"
# Accounts that may launch a session by asking, with no signed request:
# Taylor's own, reached over SSH with Taylor's device key.
people_accounts = ["taylor"]
# Public keys that may sign a launch request (kind "launch"). Empty until the
# commitments approval key exists.
approvers = []
# The most launches one caller account may make in any hour. 48 = 8 slots x 6
# launches an hour each (a session worth a launch runs about ten minutes at
# least); real use is far lower since sessions may run up to max_duration.
launches_per_hour = 48

[slots]
count = 8
account_prefix = "agent-slot-"
root = "/var/lib/agent-slots"
# The longest a session may run before the launcher stops it. Matches the
# certificate lifetime, so a session never outlives its certificate.
max_duration = "12h"

[identity]
people = ["Taylor"]

[authority]
issuer = "openbao"
address = "https://hetzner.example.ts.net:8200"
ca_cert = "/usr/local/share/openbao/ca.pem"
resolve = "100.64.0.10"
mount = "ssh-agents-hetzner"
role = "agent-sign-hetzner"

# [approvals]
# commitments_key = "ssh-ed25519 ..."   # unset until the commitments key exists

[security]
# as in today's config.toml
```

In system mode the service reads only this file. A `config.toml` in its state
folder is ignored with a warning, so there is one place to look. Unknown keys
are refused, as in today's config.

## 2. How a session runs in a slot, with no root at run time

### The choice: a template unit started by the launcher, allowed by one polkit rule

Root is needed once, at the sitting, to install two unit templates and one
polkit rule. After that, starting a session needs no root:

- `agent-session@.service`: runs a session as `agent-slot-%i`.
- `agent-session-end@.service`: runs the end-of-session check, also as
  `agent-slot-%i`, after the session's unit has fully stopped.
- `/etc/polkit-1/rules.d/50-agent-launch.rules`: lets `agent-launch`, and
  only it, start and stop exactly `agent-session@1.service` to
  `agent-session@N.service` and the matching `agent-session-end@` units.
  polkit is the system's permission service: systemd asks it whether a
  given account may start or stop a given unit.

The rule is generated by the sitting for the slot count, so it lists exact
names:

```js
// agent-sign: only the launcher account may start or stop a slot's session
// units, and nothing else. Made by agent-sign's sitting for 8 slots.
polkit.addRule(function (action, subject) {
  if (action.id.indexOf("org.freedesktop.systemd1.") !== 0) return polkit.Result.NOT_HANDLED;
  if (subject.user !== "agent-launch") return polkit.Result.NOT_HANDLED;
  var unit = action.lookup("unit"), verb = action.lookup("verb");
  if (action.id === "org.freedesktop.systemd1.manage-units" &&
      typeof unit === "string" && typeof verb === "string" &&
      /^agent-session(-end)?@([1-8])\.service$/.test(unit) &&
      (verb === "start" || verb === "stop")) {
    return polkit.Result.YES;
  }
  return polkit.Result.NO;
});
```

Everything else `agent-launch` might ask systemd for is refused, including
restarting `agent-signd`, editing unit files and making transient units. A
transient unit (one made on the fly with its own settings) would let the
launcher pick `User=root`, so it must never be allowed. systemd also refuses
to make a transient unit under a name a template already provides; the end
checks probe both.

**Alternatives considered.**

- *A transient unit per session* (`systemd-run`): polkit sees only the
  unit's name and the verb, not its settings, so it can't stop `User=root`.
  Rejected.
- *Socket activation per slot* (a socket owned by `agent-launch` whose
  connection starts the slot's unit, with the connection as the session's
  standard input and output): no polkit at all, and it carries input and
  output naturally. Rejected for now because the launcher then has no way to
  force a stuck session to stop. D6 needs the slot to be empty before the
  next session, so a forced stop is required. Worth revisiting for
  interactive sessions later.
- *DynamicUser* (a fresh account per run): rejected by D6. Its uids are
  reused, so files and leftovers could pass from one session to the next.

### The session unit

```ini
# /etc/systemd/system/agent-session@.service (installed by agent-sign's sitting;
# the installed file also carries comments, and is scripts/sitting/files/agent-session@.service)
[Unit]
Description=agent-sign launched session in slot %i

[Service]
Type=exec
User=agent-slot-%i
Group=agent-slot-%i
# Opened by systemd as root: only under /var/lib/agent-launch-io (A-2). Nothing
# under /var/lib/agent-launch is ever opened by systemd.
LoadCredential=spec:/var/lib/agent-launch-io/specs/%i.json
Environment=HOME=/var/lib/agent-slots/%i/current/home
WorkingDirectory=/var/lib/agent-slots/%i/current
ExecStart=/opt/agent-sign/current/bin/agent-sign session-exec
StandardInput=null
StandardOutput=append:/var/lib/agent-launch-io/logs/%i.out
StandardError=append:/var/lib/agent-launch-io/logs/%i.out
KillMode=control-group
RuntimeMaxSec=12h
UMask=0077
# What the session can see and change: its own folder, and nothing else that lasts.
ProtectSystem=strict
TemporaryFileSystem=/var/lib/agent-slots:ro
BindPaths=/var/lib/agent-slots/%i/current
ProtectHome=yes
InaccessiblePaths=-/var/lib/agent-sign -/var/lib/agent-launch -/var/lib/agent-launch-io
PrivateTmp=yes
PrivateDevices=yes
PrivateIPC=yes
# A fresh /dev/shm per session (PrivateDevices shows the host's; review M2).
TemporaryFileSystem=/dev/shm:mode=1777
ProtectProc=invisible
NoNewPrivileges=yes
RestrictSUIDSGID=yes
CapabilityBoundingSet=
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
LockPersonality=yes
RestrictRealtime=yes
LimitCORE=0
# Review round 2 (M2, L5): a deny-list of system calls, no keyring, limits.
SystemCallArchitectures=native
SystemCallFilter=~@clock @cpu-emulation @module @raw-io @reboot @swap @obsolete add_key keyctl request_key
SystemCallErrorNumber=EPERM
MemoryMax=50%
TasksMax=15%
```

`systemd` (running as root) reads the session's spec through
`LoadCredential=` and opens the output file before it drops to the slot
account, so neither the spec folder nor the log folder needs to be open to
the slot. The output file is opened for appending only; the session can't
read earlier sessions' output through it, and can't reopen it, because it
belongs to `agent-launch` with mode 0600.

`agent-session-end@.service` is the same shape (it runs `session-end`, adds
`PrivateNetwork=yes` and `RuntimeMaxSec=30min`, and has no spec).

**Between sessions in a slot (review round 2, M2).** `PrivateDevices=yes`
bind-mounts the host's `/dev/shm`, and `PrivateTmp=` and `PrivateIPC=` don't
cover it, so a file left in `/dev/shm` would reach the next session in the
same slot (breaking D6). Both slot units therefore mount a fresh tmpfs on
`/dev/shm` (`TemporaryFileSystem=/dev/shm:mode=1777`, writable, so programs
that use shared memory still work). The per-uid user keyring (`@u`) also
outlives a session, so the `SystemCallFilter=` below denies `add_key`,
`keyctl` and `request_key` (EPERM): nothing can be put in it. The sitting's D6
end check leaves a file in `/dev/shm` and tries to add a key to `@u` in the
first session, and the second session must find neither (it reads
`/proc/keys` too, since `keyctl` is itself denied in the slot; if `keyctl`
isn't installed the check says so).

**Limits (L5).** Both slot units set `SystemCallArchitectures=native` and a
`SystemCallFilter=` that is a deny-list (`~@clock @cpu-emulation @module
@raw-io @reboot @swap @obsolete` plus the three keyring calls) with
`SystemCallErrorNumber=EPERM`. `RestrictNamespaces=` is left out on purpose:
agents' own sandboxes need user namespaces (Claude Code's sandbox on Linux uses
bubblewrap), and `unshare`, `clone`, `mount` and `setns` stay allowed.
`MemoryMax=50%` (half the machine's memory) and `TasksMax=15%` (systemd's own
default share of the kernel's pid limit, made explicit) are the sitting's
defaults; `--slot-memory-max` and `--slot-tasks-max` (a percentage, or a size /
a whole number) rewrite them in both units. They are starting points, not
measured on hetzner yet: the sitting's real-machine checks should confirm that
a normal launch isn't killed. `agent-launchd.service` has `MemoryMax=6G`: its
largest request is 512 MiB, a bulk read peaks at about three times that (the
growing buffer plus a copy), and it reads up to 3 at once (3 x 512 MiB x 3 =
4.5 GiB; see "Memory bound" below), plus 256 KiB of small reads and 1 GiB of
headroom: a floor of 5.5 GiB + 256 KiB, which a test keeps the cap above.

#### The bind of `current/` (review finding L2)

`BindPaths=/var/lib/agent-slots/%i/current` is also set up by systemd as
root, from a folder the launcher owns (it must: it renames `current/` into
`trash/`). A compromised launcher could replace `current/` with a link, and
root would bind the link's target into the session's namespace: bind mounts
skip the permission checks on the target's ancestors. `man systemd.exec`
(v259) describes `BindPaths=` as taking a source and destination path and
says nothing about links in the source, so nothing is assumed. The fix is in
the session's own programs: `session-exec` and `session-end`, in `this_slot`
before anything else, read `/proc/self/mountinfo` (`check_own_mount`) and
refuse unless the mount at the slot's `current/` is exactly that slot's own
`current/` (`session_runner::check_current_mount`, a pure function over the
mountinfo text). It must be on the same device as the filesystem that holds
the slots folder, and its root (the directory's path inside its filesystem)
must be that filesystem's root plus the path of `current/` below its mount
point. A followed link to `/etc`, to another slot, to a lookalike path such
as `/var/lib/agent-launch/agent-slots/<n>/current`, to the same path on
another device, and a missing mount are all refused. Limits: a dedicated
filesystem mounted at the slots folder itself, or a link above the slots
folder, is refused rather than guessed at; the sitting makes neither. A
real bind of a followed link can't be tried without root, so the tests use
mountinfo fixtures (`session_runner::tests::l2_*`,
`tests/test_session_mount_check.rs`).

#### The I/O folder (review finding A-2)

systemd v259 opens `LoadCredential=` and `StandardOutput=append:` paths as
root, before it drops privilege, and without `O_NOFOLLOW`. If those paths
sat in a folder the launcher controls (it runs as an ordinary account and
its socket is 0666), a compromised launcher could plant `logs/N.out ->
/etc/cron.d/x` (the slot's output would then be appended there as root) or
`specs/N.json -> /var/lib/systemd/credential.secret` (a root-only file
would be handed to the slot as its spec). So root now opens only paths whose
every folder is root's: `/var/lib/agent-launch-io/` and its `specs/` and
`logs/` are root:agent-launch 0750. The launcher is in that group, so it can
enter and list them, but no account except root can make, rename or remove
an entry. Nothing under `/var/lib/agent-launch` (the launcher's own folder)
is opened by systemd.

The sitting pre-creates `specs/<n>.json` and `logs/<n>.out` for every slot n
as regular files owned by `agent-launch`, mode 0600, exclusively: an existing
entry that isn't exactly that stops the sitting. The launcher's side:

- it opens those existing files only: `O_NOFOLLOW`, never `O_CREAT`, then
  `fstat` on the open descriptor: a regular file, owned by its own uid, with
  one name (a second hard link would let a write land in another file). The
  folders are checked too: owned by root, no write for group or others;
- it truncates and writes a spec in place before the unit starts, truncates
  the log before a session starts (so a session's output never starts with
  an earlier boot's bytes), and reads the log to stream it. The caller sees
  only what this session wrote;
- it never creates, renames, links or removes an entry in the I/O folder, and
  has no fallback: nothing is written under its state folder in place of a
  missing or wrong entry;
- a slot whose folders or files aren't exactly right is skipped, with the
  reason in the launcher's log (`slot 1 stays out of use: specs/1.json is
  missing ...`) and, when no slot is left, in the refusal the caller gets.
  The other slots work; the slot returns to use when the sitting has fixed
  its files (the check is made at every launch, so no restart is needed),
  and no launch approval's nonce is spent on a slot that was skipped.

In debug test builds only, the folder's place comes from
`AGENT_SIGN_TEST_LAUNCH_IO` (compiled in with the `test-authenticator`
feature, as `AGENT_SIGN_TEST_LAUNCH_STATE` and `AGENT_SIGN_TEST_SYSTEMD`
are; an installed program has the path `/var/lib/agent-launch-io` and
ignores the variable). Under the test stand-in for the kernel only, the
folders and files are the test's own account's instead of root's and
`agent-launch`'s, because a test can't chown. What is not covered by a test
here: a file owned by another account (a test can't make one), and root's
and systemd's own behaviour, which is the sitting's folder modes and unit
files.

The spec (written by the launcher, read by `session-exec`) holds: the
session id, the agent's name, the program and its arguments, the
environment, and the repositories to set up. **The environment is an
allow-list (M1, review of 1 Nov 2026):** only `LANG` and `TERM`, each at most
once, each value 1 to 64 bytes of `A-Za-z0-9._@+-`, from every caller
(`launcher::check_env`). Any other name, a bad value or a name sent twice
refuses the whole request in plain words naming the variable (never its
value): nothing is started, no spec is written and an approval's nonce is not
used up. This replaces the old filter that dropped identity claims and kept
everything else, because a launch approval signs the agent, the program and
the repositories but not the environment: a relayer could add
`ANTHROPIC_BASE_URL`, `GIT_CONFIG_COUNT`/`KEY_0`/`VALUE_0` (git runs a
command named `core.fsmonitor`) or `LD_PRELOAD` to a genuine approval, and
the code would have run inside an attested session. Identity claims
(`AGENT_SIGN_*`, `CLAUDE_CODE_SESSION_ID`, agents' marks) are now refused
like any other name, not silently stripped. `session-exec` applies the same
rule to the spec it is handed, as defence in depth. Widening the list would
be a root-owned `system.toml` setting; it is not built, and the caller can't
widen it.

`agent-sign session-exec` (running as the slot account, inside the unit):

1. Refuses to run unless its uid is a slot account's and its own cgroup is
   `agent-session@<that slot>.service`.
2. Makes `home/`, `work/` and `tmp/` in `current/`.
3. For each repository in the spec, takes from the input bundle the launcher
   left in `current/in/` into `work/<name>` only the approved base commit
   (L4; a git bundle is git's single-file package of commits; fetching from
   one runs nothing from it). The bundle's branches are fetched into a
   holding namespace, the base is checked to be there, and the holding refs
   are deleted, so a branch the approval never named, or a commit past the
   base, is on no ref in the working copy and can't be bundled back to the
   caller in `Ended`. The base is checked out (on the bundle's branch that
   was at exactly the base, if any, else detached) and recorded as
   `refs/agent-sign/base`. The unreachable objects may remain in the
   object store; nothing sends them anywhere.
4. Asks the service who it is (`SessionIdentity`) and writes the session's
   own git settings to `home/.gitconfig`: name and email from the service,
   `gpg.format=ssh`, `gpg.ssh.program=/opt/agent-sign/current/bin/agent-ssh-sign`,
   `commit.gpgsign=true`.
5. Sets `PATH` with `/opt/agent-sign/current/wrap` first, then runs the
   program in `work/<first repository>` and waits for it.

### D6: the next session in a slot never sees the previous one's leftovers

When a session ends (its program exits, the caller disconnects, the
launcher is asked to stop it, or `RuntimeMaxSec` is reached):

1. The launcher closes the session's registration with the service (see
   section 4). From then on nothing in that slot can get a signature.
2. systemd stops the unit and kills every process left in it
   (`KillMode=control-group`). The launcher waits until the unit is
   inactive.
3. The launcher starts `agent-session-end@<n>.service`. It runs as the slot
   account in its own unit (so it is never taken for the session, see
   section 4), with no network, with write access to `current/` only. For
   each working copy it checks that everything is committed: no changed or
   staged tracked file, no untracked file that isn't ignored, no stash, no
   merge or rebase in progress. It writes the commits made in the session
   (every branch that moved past its base) to `current/out/<name>.bundle`,
   and a status file `current/out/status.json` saying for each working copy
   "clean" or what was left. It removes nothing, not even a clean working
   copy whose commits are all in its bundle (the suite PM, 1 Nov 2026):
   everything stays in place for the Trash.
4. The launcher reads `status.json` and the bundles, opening each with
   `openat2` set to refuse links and anything outside `current/out`, and
   only if the file is a regular file owned by that slot account. So a
   session can't point the launcher at one of the launcher's own files.
5. The launcher renames `current/` to `trash/<date>-<session8>/`, always,
   and logs it in `/var/lib/agent-launch/sessions.log` with the status. A
   rename is not a deletion: nothing is ever deleted by agent-sign. What
   reaches the Trash is whatever wasn't saved, plus the session's home
   folder (agents' own records, such as transcripts, live there).
6. The next session in that slot gets a new, empty `current/` and fresh
   clones.

Why the next session can't see any of it: the Trash belongs to
`agent-launch` with mode 0700, so the slot account can't even enter it,
although it owns the files inside. A file can only be reached through a
folder the account may enter, and the session's own processes, the only
holders of open handles, are all dead. While a session runs, its unit also
hides `/var/lib/agent-slots` behind an empty folder and shows only its own
`current/`.

Why the end check runs as the slot account and is trusted only for one
thing: running git in a session's repository reads that repository's
config, and the session controls it. Run as `agent-launch`, it could make
the launcher run the session's code. Run as the slot account, the worst a
hostile session can do is make the check report "clean" while leaving
files, and then lose its own files. A session can always delete its own
work, so this gives it no new power. The check exists so that agent-sign
never destroys work by accident, not to defend against a hostile session.

**Who empties the Trash.** Nothing does yet. `agent-sign doctor` shows
each slot's Trash size. The planned cleanup (backlog, not built) is a
sweep that permanently deletes only Trash folders it can prove are
regenerable: a clean working copy whose HEAD is in a bundle that was
delivered, or upstream. It logs each deletion, and runs as the slot
account in a unit like the end step, because only that account can delete
files it owns inside a folder it can't enter. Anything else stays until a
person empties it. The kept bundles (the `out/` bundles written for each
session) are never emptied either, so until the sweep exists the disk can
fill: a full disk stops new sessions. The sweep will cover kept bundles too
(a bundle whose commits were delivered or are upstream is regenerable).

### How working copies are shared: bundles in, bundles out, never shared folders

No folder is writable by both a session and another account, and no
account ever runs git in a repository another account controls. Shared,
group-writable repositories would let one account's repository config or
hooks run as the other account the next time it runs git there. That is the
same reason git itself refuses to work in a repository owned by someone else.

- **In.** The caller (Taylor's `agent-sign launch`, or a job runner relaying
  a signed launch request) names the repositories and the base commit for
  each. The `agent-sign launch` command makes a bundle of each base from the
  caller's own repository (`git bundle create`, run by the caller, in the
  caller's account) and sends it over the launch socket with the request.
  The launcher writes it to `current/in/` (owned by `agent-launch`, mode
  0640, group the slot). The approval, when there is one, names the base
  commit, so the content is checked by its hash. A caller that isn't a
  person's sends the head first and the bundles on a second line (see "The
  request's limits" below), so no bundle byte is read before its approval has
  been verified.
- **Out.** At the end, the launcher sends the session's bundles back over
  the same connection, and the caller's `agent-sign launch` fetches them
  into its own repository as `session/<principal>/<branch>`. Fetching from a
  bundle runs nothing from it. If the caller has gone, the bundles stay in
  `/var/lib/agent-launch/out/<session>/` and `agent-sign launch --collect
  <session>` fetches them later, for the account that started the session
  only.
- **While a session runs**, nobody else sees its working copy. Seeing it
  live is not needed for the first uses (non-interactive jobs and the
  sitting's own checks).

### What the service itself no longer does in system mode: run git in callers' repositories

Today the service runs git in the caller's repository to check content
(forbidden paths, diff size), to see whether a lease's work has been merged,
and to read the branch for a plain commit. In system mode the caller's
repository belongs to a slot or to `agents`, so running git there as
`agent-sign` would let that repository's config act as the account that
holds the OpenBao signing login. In system mode, therefore:

- the service's unit hides `/home` and `/var/lib/agent-slots`
  (`ProtectHome=yes`, `InaccessiblePaths=`), so it can't reach any caller's
  repository, even by mistake;
- the service keeps every check that needs only the commit it is asked to
  sign: the one committer is the session's principal, and the one author is
  not another session running now or a person's name (F7): an author who is
  another live session's principal, or whose name is a person's this machine
  knows, is refused, while any other author is kept, so a session can
  replay (cherry-pick, rebase, amend, `am`) commits written by someone else,
  or by its own agent's earlier session, which keep their author and name
  the session as committer. The display name is
  free, the email is the rule. The dates are in the
  certificate's window, the name rules, and the protected branch names, read
  from the request;
- the content rules (forbidden paths, diff limit) run in the session's git
  wrapper, as they do on the plain path today, and at the merge gate
  (backlog, D1);
- a session's lease ends with its session (F4): every lease the service
  grants because a session asked, whether the person approved it or the
  settings grant it unasked, is recorded against that session's id, and
  when the registration closes the service revokes each of them (saved to
  `leases.json`, so a restart doesn't bring it back). The next session on the
  same repository and branch, in the same slot or another, starts with no
  lease and needs its own approval, which costs its own prompt under
  `approval = "device-owner"`. A lease a plain caller already held, handed to
  a session as the covering lease, isn't the session's and stays. Two live
  sessions sharing a lease both hold it, and it ends with the last. Which
  lease belongs to which session is kept in memory only, and no session
  outlives the service, so the service ends every lease it finds in
  `leases.json` when it starts in system mode (a plain caller asks again),
  and a crash or restart leaves none for the next session to inherit. If a
  plain caller shared the prompt that granted it, the lease is the session's,
  and the plain caller asks again after the session ends. So the
  finished-work sweep has nothing to check;
- `CheckPlainCommit` (the plain path's policy question) takes the branch the
  wrapper reports and doesn't open the repository. A plain commit gets no
  signature, so believing its branch costs nothing. Without this change,
  every plain commit by the agents account would be refused once the service
  can't read `/home`.

This is a change of behaviour for launched sessions, so it is also
question 3 below.

## 3. Who may ask the launcher to start a session

The agents account must not be able to start one (sitting test P1).

**Recommendation: two ways, both checked by the launcher before anything runs.**

1. **Taylor's account, by asking.** A request on the launch socket from a uid
   in `[launcher] people_accounts` (default: `taylor`) is accepted with no
   signature. Taylor reaches that account over SSH with the key kept on
   Taylor's device, and the account can already become root, so trusting
   its uid trusts nobody new. A separate signature from Taylor's device for
   each launch would add a prompt per session and no protection.
2. **A signed launch request from anyone else.** The text is a launch
   approval, signed with SSHSIG in the namespace
   `agent-sign-launch-approval` by a key listed in `[launcher] approvers`:
   the commitments approval key, which signs a kind "launch" approval when
   the commitments graph approves the work. Its fields: `kind` ("launch"),
   `machine`, `agent` (the agent's name), `repos` (name and base commit of
   each), `program` (the SHA-256 of the exact program and arguments),
   `expires_at` and `nonce`. The launcher checks the signature, the fields,
   that the nonce has never been used (recorded and synced to disk under
   its lock before the session starts) and that the request matches the
   approval exactly. The code is the commit approval's verifier
   (`commit_approval.rs`) with another namespace and kind. Who relays the
   request doesn't matter: the agents account, or a job runner in it, may
   present it, as with commit approvals.

Why the commitments key rather than Taylor's device key for the second way:
launches are made by job runners, not by Taylor; an approval from the
commitments graph is scoped to the approved work and expires with it, which
is the suite's rule for approvals; and it needs no new key format, because
it is the same verifier as commit approvals.

Until the commitments key exists, `approvers` is empty, so only Taylor's
account can launch. The agents account gets a refusal saying why, which is
exactly what sitting test P1 checks. What that means for daily work is
question 1.

## 4. How the service knows who is asking

- **The launcher registers each session** on `/run/agent-sign/launcher.sock`.
  The service accepts a connection there only if the kernel reports the
  caller's uid (`SO_PEERCRED`, the kernel's answer to "which account and
  process is on the other end of this socket") as `[launcher] account`. The
  registration says: slot n, its account's uid, its unit name
  (`agent-session@n.service`) and the agent's name. The service checks that
  the uid really is `agent-slot-<n>` (looked up by name, within the
  configured count) and that no live session holds that slot, applies the
  name rules, makes the session id and principal as today, records them in
  `sessions.log`, and answers with the principal. The launcher keeps that
  connection open for the session's life, and starts the unit only after
  the answer. When the connection closes, the session ends, exactly as the
  one-account registration does today.
- **Requests from the session** arrive on the ordinary socket. When a
  connection is accepted, the service reads the caller's uid and a pidfd
  (`SO_PEERPIDFD`: a handle on the caller's process that can't be confused
  with a later process given the same number). It reads the process's
  cgroup (the kernel's record of which unit a process belongs to) from
  `/proc/<pid>/cgroup`, then checks through the pidfd that the process is
  still the same one. The caller is the session only if the uid is a slot
  account with a live registration **and** the cgroup is exactly that
  slot's `agent-session@n.service`. Anything else is a plain caller: the
  agents account, Taylor, and a process of a slot account outside its
  session unit (say one left by `cron`, if that ever got through). A plain
  caller gets the plain-path answers and never a signature (D1).
- Because the uid decides, a session in system mode needs no inherited
  channel descriptor. The channel stays as it is for one-account mode. In
  system mode `agent-git` asks the service `SessionIdentity` first, and the
  answer says whether it is a session.
- Tokens are bound to the session id, as today. A process of the same
  session can use one; nothing else can, because nothing else is that
  session.
- The certificate's attestation becomes
  `launcher session=<id> uid=<slot uid> isolation=slot-account`, and
  `agent-sign verify` says "launcher, own account: the session ran in an
  account of its own (agent-slot-3), so no other account could reach it".
  `isolation=dynamic-user` is replaced, since D6 replaced DynamicUser and
  nothing has shipped with it.
- The builder checks whether systemd 257 and 259 put a readable invocation id
  on the cgroup. If they do, the service also compares it with the one the
  launcher registered. It isn't needed for correctness: the launcher
  registers a new session only after the previous unit is inactive, so
  every process of the previous run is already dead.

**One-account mode stays the zero-config default.** Without
`/etc/agent-sign/system.toml` nothing above applies: the launcher uses
bubblewrap, the channel descriptor identifies the session, and the local
in-memory authority signs, as today.

**In system mode the service refuses to start as any account but
`[service] account`.** A copy of `agent-signd` started by the agents account
(sitting test P3) stops at once, before it makes anything.

**Clients find the system socket by themselves.** The order is
`AGENT_SIGN_SOCKET` if set, then the socket `system.toml` names, then
today's default. The sitting checks that the agents' login files don't set
`AGENT_SIGN_SOCKET`.

**`agent-launchd`** is a new program, `src/bin/agent_launchd.rs`, running as
`agent-launch`. It owns the slots: it picks the lowest free one, makes
`current/`, writes the spec, registers with the service, starts and stops
the units through systemd's D-Bus interface, streams the output log to the
caller, runs the end step and the Trash move. When it starts, it stops every
`agent-session@` unit still running (the service has already ended those
sessions, because their registrations closed) and moves their folders to
the Trash. It never runs git. Its unit is hardened like the service's (own
account, no capabilities, `ProtectHome=yes`, read-write only
`/var/lib/agent-launch` and `/var/lib/agent-slots`, Unix sockets only).

**As built (step 2, 1 Nov 2026).** The kernel's facts sit behind a port,
`src/kernel_facts.rs` (`KernelFacts`: an account's uid by name, and a
connection's peer as uid, cgroup line and whether its process is still the
one that connected). Its module comment has the reasoning; in short:

- **The order of the reads closes the pid-reuse race.** The pidfd comes
  first (`SO_PEERPIDFD`, pinning the process the kernel recorded at
  `connect`), then `/proc/<pid>/cgroup` through the number, then the pidfd is
  asked whether its process still exists (`pidfd_send_signal` with signal 0;
  `EPERM` means it exists under another account). A number isn't reused until
  its process is reaped, so a process still there after the read means the
  cgroup read was its own. A process already gone is refused outright, with
  no answer to its request.
- **Fallback:** a kernel without `SO_PEERPIDFD` (before Linux 6.5) never has
  a session; every caller is plain, said once in the log. Nothing trusts a
  bare pid. hetzner runs 7.0.
- **The unit's cgroup** is accepted at exactly two places, both root's:
  `/system.slice/agent-session@<n>.service`, and
  `/system.slice/system-agent\x2dsession.slice/agent-session@<n>.service`,
  where systemd puts a template's instances by default (the session unit has
  no `Slice=`). A sub-cgroup or any other unit is plain.
- **Registration** (`RegisterSession {slot, uid, unit, agent}` on the
  launcher-only socket) is checked by the peer's uid against
  `[launcher] account` looked up by name; the slot must be 1 to
  `[slots] count`, `<account_prefix><n>` must have exactly that uid, the unit
  must be exactly `agent-session@<n>.service`, and the uid must not be root,
  the service's, the launcher's or a person's account. The slot (and its
  uid) must have no live session, checked under the lock that records the new
  one. It is refused on the ordinary socket. The answer is `SessionStarted`
  with no descriptor.
- **Socket activation:** systemd's sockets are taken by name (`daemon`,
  `launcher`); anything else passed is a refusal to start. Without them the
  service makes both itself (`daemon.sock` 0666, the launcher-only socket
  0600, since it can't give it the launcher's group).
- **The issuer** is the OpenBao adapter whenever `$CREDENTIALS_DIRECTORY` is
  set and the settings are usable; otherwise the closed stand-in. The first
  check against OpenBao runs in the background, so a down OpenBao never
  delays the start.
- **Doctor** prints `ping: ok` when the service answers, and in system mode
  `authority: OpenBao CA matches the trust file` only after OpenBao's public
  key equals the trust file's one line (the issuer's own comparison, which
  needs no login); otherwise `authority:` and what is wrong.
- **The invocation id:** systemd 259 writes it on a unit's cgroup as the
  `user.invocation_id` attribute, readable by anyone. It is not used: the
  launcher registers before it starts the unit, so there is none to register
  yet, and the launcher's ordering already makes it unnecessary.
- **Known limit:** a session's first signature in each 12 hours asks OpenBao
  while the service's state lock is held, so a slow OpenBao (10 s deadline)
  holds up other requests meanwhile.

**As built (step 3, 1 Nov 2026).** The launcher is `src/bin/agent_launchd.rs`;
its shared pieces are in `src/launcher.rs` (the launch socket's protocol, the
spec, the folder names), `src/launch_approval.rs`, `src/systemd_port.rs`,
`src/slot_fs.rs`, `src/session_runner.rs` (`session-exec`, `session-end`) and
`src/launch_client.rs` (`agent-sign launch` in system mode, and `--collect`).
Each module's header has the reasoning; in short:

- **The launch socket** takes one JSON line, `Launch {agent, command, env,
  repos:[{name, base, bundle_b64}], approval, bundles_follow}` or `Collect
  {session}`, and, when `bundles_follow` is true, a second line
  `{"bundles_b64":[...]}` (one entry per repository, in order; the
  repositories' own `bundle_b64` are then empty). See "The request's limits"
  below. The launcher answers `Launched {session, slot, principal}` once the unit has
  started, `Output {data_b64}` with what the session writes, and `Ended
  {status, bundles}` once the folder is in the Trash; any refusal is `Error
  {message}`. While the session runs and writes nothing, the launcher says
  nothing.
- **Who may launch:** the kernel's uid for the connection, at accept. A
  `[launcher] people_accounts` uid launches by asking. Anyone else needs a
  launch approval (`kind` "launch", `machine`, `agent`, `repos`, `program`,
  `expires_at`, `nonce`), where `program` is the lowercase hex SHA-256 of the
  compact JSON text of the command array. Its signature is checked by the
  commit approval's verifier (`CommitmentsKey::verify_in`) in the namespace
  `agent-sign-launch-approval`, before its text is read. The nonce is
  recorded and synced in `<state>/approvals/launch-nonces` under the slot
  lock, after every other check and after a free slot is found, so a refused
  approval is never used up. The approval does not cover the environment;
  the launcher's own allow-list does (see the spec above). A request from an
  account that isn't a person's is read only up to 64 KiB until its approval
  is verified, whether or not `approvers` is empty.
- **The request's limits (L1, L2, L3, L4 of the review of 1 Nov 2026).**
  - *One line, one total deadline.* A line has a size limit and a deadline
    counted from its first read, not restarted by each byte (the old
    per-read timeout let a client sending one byte a minute hold a place
    for ever). A caller that isn't a person's has `HEAD_DEADLINE`, 10 s, for
    64 KiB (at a stated minimum of 8 KiB per second it needs 8 s); a line that
    may carry bundles has `BULK_DEADLINE`, 600 s, for 512 MiB (at a minimum of
    1 MiB per second it needs 512 s). Past the deadline the connection is
    closed, saying why. The constants and their arithmetic are in
    `src/bin/agent_launchd.rs`.
  - *Verify, then read bundles.* A person's account (the kernel's uid) may
    send up to 512 MiB in its line, inline or as `bundles_follow`. Anyone else
    gets 64 KiB, enough for the head: the approval is verified (signature,
    fields, expiry, and that its nonce isn't already used, without recording
    it), and only then is the second line read, up to 512 MiB, under the
    same total deadline. At most four first reads from non-people at once
    (`MAX_OTHERS_READING`, a person is never counted), and of those one
    account holds at most one (`MAX_OTHERS_PER_UID`, re-check R1 and Q1:
    without it one local account could keep all four busy by reconnecting) and
    one place is never given to any such account
    (`MAX_PEOPLE_SMALL_RESERVED`, Q1: headroom, never lent out), so other
    accounts together hold at most three, one each, and two accounts can't fill
    the pool between them. A person's own first read never uses these places:
    it is read in the people's bulk place below, which nobody else can take.
    Several accounts can still hold the three, one each, and then relayers are
    told the launcher is busy until the head deadline. Lines that may carry bundles are read in
    places of their own: two for verified relayers
    (`MAX_RELAYED_BULK_READING`) and one for the people's accounts together
    (`MAX_PEOPLE_BULK_READING`), which no relayer can take, so a relayer can
    never keep a person out (re-check R2); three in all (`MAX_BULK_READING`).
    A person whose own place is taken may use a relayers' place that is
    free, so a person is no worse placed than when all three were shared; a
    relayer never takes the person's. A request that is refused gives back
    its place, and its nonce's reservation, *before* the refusal is written,
    so a caller that reconnects the moment it reads the refusal never finds
    its own earlier request still holding them (a refusal that cannot be
    written, to a caller that doesn't read, holds nothing while it waits).
  - *An approval's nonce is reserved when it verifies (re-check R2).* The
    record of a used nonce is made at the slot's claim, after the bundles are
    read, and a relayer may take up to 600 s over them, so one valid approval
    could otherwise be presented again and again, each presentation holding a
    place until its deadline. The nonce is now reserved, in memory, the moment
    its approval verifies and before any bundle byte is read; a second
    presentation of a nonce that is reserved or used is refused at once and
    takes no bulk place. Any launch that ends before a slot is claimed (a
    timeout, a wrong bundle count, a bad bundle, a hit hourly limit, no free
    slot) gives the reservation back, so a refusal still doesn't use the
    approval up; a recorded nonce is spent for good. Someone holding a copy of
    an approval can delay its real user by presenting it first, for at most
    the request deadline each time; it is not lost.
  - *Memory bound.* One such line is text up to 512 MiB, then parsed (a copy,
    1 GiB at the peak), then decoded (up to 384 MiB), and held until written
    to the slot; about 1.5 GiB each, so about 4.5 GiB for the three at once,
    plus the rest of the launcher (small). The sitting's check counts the
    same peak, 3 x 512 MiB x 3 = 4.5 GiB, plus 256 KiB of small reads plus
    1 GiB of headroom, and `agent-launchd.service`'s `MemoryMax=` is derived
    from it (the sitting's unit file, see the sitting's section): 6G. Giving
    the people's accounts a place of their own added one to the count, and
    counting a read at three times its size rather than two raised the cap
    from 4G.
  - *Write timeout.* Every send to a caller makes progress or the caller is
    counted as gone: a write that takes not one byte for 30 s
    (`SEND_PATIENCE`), or a whole message that takes longer than that plus its
    size at 1 MiB per second, fails. Failing is the path the loop already has
    for a caller that hung up: the unit is stopped, the end step runs, the
    folder goes to the Trash, and the returned bundles are kept for
    `launch --collect`. Before, a caller that stayed connected but stopped
    reading blocked the thread in a write for ever: the unit never stopped
    and the slot was lost until the launcher restarted.
  - *Only the base comes in (L4)*, see `session-exec` below.
  - *Launches per caller (F7, round 2).* `[launcher] launches_per_hour`
    (default 48, `DEFAULT_LAUNCHES_PER_HOUR` in `src/system_config.rs`) is
    the most launches one caller account (by the kernel's uid; a person's
    account too) may make in any hour. The default is derived from the slots
    and the session length: 8 slots by default, a session worth a launch runs
    at least about ten minutes, so a slot turns over at most six times an
    hour and the slots can serve at most 8 x 6 = 48 launches an hour; sessions
    may run up to `[slots] max_duration` (12 h), so real use is far lower.
    An approval presented with `bundles_follow` is charged one launch
    when it takes a relayers' bulk place, whether or not it ends in a launch
    (re-check Q2: otherwise a holder of several valid approvals could keep both
    relayer places busy by presenting them in a loop); the launch it leads to
    is not counted again. A caller over the limit is refused in plain words ("launching too often",
    with when to try again) before any bundle byte is read, with nothing
    started and no approval used up. One caller's launches do not count
    against another's. The count is in memory (`launcher::LaunchRate`):
    a caller keeps at most `launches_per_hour` timestamps, each leaves an
    hour after it was made, and the launcher's restart forgets the hour (the
    audit log keeps every launch). `0` refuses every launch. The launcher's
    other in-memory records are bounded too: the used nonces leave memory
    once they are a day past their approval's expiry (they are pruned when the
    next nonce is recorded, and the file at the launcher's start), and the
    slots' claims are a fixed list of one entry per slot.
  - *How big `sessions.log` grows.* `sessions.log` is the audit log and is
    never trimmed or rotated by the launcher. Each launch adds one line when
    its session ends (and a line more for a leftover folder or a session not
    started, which are rare): about 330 bytes per launch with no end-step
    status, and a few hundred bytes more for each repository in the session's
    status, so budget 1 KiB per launch. At the default limit one caller adds at
    most 48 KiB an hour; a million launches would be about a gibibyte. The
    launcher only appends to it and never reads it back, so moving it aside
    is safe; that is the sitting's choice, not the launcher's.
  - Test seams, debug test builds only (`test-authenticator`):
    `AGENT_SIGN_TEST_REQUEST_DEADLINE_MS` replaces both request deadlines
    (and the bundle line's) with that many milliseconds, and
    `AGENT_SIGN_TEST_SEND_TIMEOUT_MS` replaces the 30 s without progress.
    Neither exists in a release build.
- **The slot choice** is one step under one lock: the lowest slot that no
  session of this launcher holds and whose session and end units are both
  inactive (an error from systemd counts as active). The slot is held until
  its folder is in the Trash; the Trash move and the release are one step
  under the same lock.
- **The folders.** `current/` is made with `mkdirat` (so nothing already
  there is reused), private (0700) while the bundles are written to `in/`
  (`O_CREAT|O_EXCL|O_NOFOLLOW`, 0640), and only then given the slot's group
  (taken from the slot folder the sitting made) and 0770. The slot's folder
  must be the launcher's with no group write and nothing for others, or
  nothing is made in it. The Trash is made 0700 if absent. A `current/`
  found before a new session (a crash) goes to the Trash first, logged
  `leftover`.
- **The end.** The registration is closed first; the unit is asked to stop
  (again every 30 s) if the caller went or `max_duration` passed; the
  launcher waits until it is inactive, starts the end unit and waits until
  that is inactive too. It reads `out/status.json` and `out/<repo>.bundle`
  (only the repositories the request named) with `openat2`
  (`RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS |
  RESOLVE_NO_XDEV`, falling back to a component-by-component `O_NOFOLLOW`
  walk), `O_NONBLOCK`, and only a regular file with one link, owned by the
  slot's account, within a size limit. It renames `current/` to
  `trash/<UTC time>-<session8>` with `RENAME_NOREPLACE`, after checking that
  `current` is still the folder it made, and logs a line in `sessions.log`
  (session, principal, agent, launcher's uid, why it ended, the status, the
  Trash name, any file it refused to read). If the rename fails, the slot
  stays out of use until the launcher restarts and sweeps it.
- **Returned bundles** go to the caller in `Ended`. If the caller has gone,
  they are kept in `<state>/out/<session>/` with the launching uid, and
  `Collect` gives them only to that uid.
- **systemd** is reached through `systemctl` at its root-owned path, with an
  empty environment and `--no-ask-password`; `stop` doesn't wait
  (`--no-block`). The adapter refuses any unit but
  `agent-session(-end)@<1..N>.service`, on top of the polkit rule. Tests
  replace it with a folder (`AGENT_SIGN_TEST_SYSTEMD`) and the state folder
  with `AGENT_SIGN_TEST_LAUNCH_STATE` and the I/O folder with
  `AGENT_SIGN_TEST_LAUNCH_IO`, in debug test builds only.
  `scripts/check-binary-clean.sh` now checks `agent-launchd` too.
- **At start** the launcher holds every slot with an active unit or a
  leftover `current/`, stops its session unit, waits for both units to be
  inactive, and moves the folder to the Trash (`swept`) before giving the
  slot out. It refuses to run as root, as any account but `[launcher]
  account`, or beside another launcher on the same state folder (a lock).
- **session-exec** checks its uid is a slot account's and its cgroup is that
  slot's session unit, reads the spec from `$CREDENTIALS_DIRECTORY/spec`,
  refuses it unless its environment passes `launcher::check_env`, makes
  `home/`, `work/` and `tmp/`, takes each bundle's approved base into a fresh
  `work/<name>` (`session_runner::fetch_base`: `git init`, `git fetch` of the
  bundle's branches into a holding namespace, the base checked to be there,
  the holding refs deleted, so nothing but the base is reachable), records
  the base as `refs/agent-sign/base`, checks out the
  branch at the base (or the base, detached), asks the service
  `SessionIdentity`, writes `home/.gitconfig`, and `exec`s the program with
  `/opt/agent-sign/current/wrap` first on `PATH`. It refuses to run if the
  wrapper isn't there.
- **session-end** checks it is in the slot's end unit, and for each
  `work/<name>` reports "clean" or what was left (changes or untracked
  files, a stash, a merge, rebase, cherry-pick, revert or bisect in
  progress), bundles every branch past `refs/agent-sign/base` into
  `out/<name>.bundle`, removes nothing, and opens `out/` to the slot's
  group (0750, files 0640).
- **`agent-sign launch`**, once `system.toml` exists, sends the request to
  the launcher instead of refusing: the working copy it runs in goes as a
  bundle of its current branch (inline in the head, `bundles_follow` false,
  as a person's account may), only `LANG` and `TERM` go as environment (and
  one whose value the launcher wouldn't accept is left out, with a note, not
  sent), and returned bundles are fetched as `session/<principal>/<branch>`.
  The fetch runs with `transfer.fsckObjects` and `fetch.fsckObjects` set to
  true on the command line (F6, round 2 of the review of 1 Nov 2026): the
  bundle came from a session's code, and git checks the objects it takes in
  only when asked. A malformed object (a commit with no author, a bad tree)
  refuses the fetch, nothing is stored under a ref, and the command says the
  bundle couldn't be fetched. The command-line setting wins over the caller's
  own repository config, so a repository that turns these checks off does not
  weaken it.
- **Not covered by the step-3 eval** (`tests/test_launcher_daemon.rs`, 12
  tests): `session-exec`, `session-end` and `launch` in system mode run only
  with real slot accounts and units, so they are checked by the sitting's
  probe session, not by `cargo test`; their pure parts have unit tests.

## 5. The OpenBao issuer: a second `CertificateIssuer`

New module `src/issuer_openbao.rs`, the second adapter of the existing port
in `agents_ca.rs`. In system mode it is the only issuer: the in-memory
authority is never used there, so a failure never falls back to a local key.

**In OpenBao (made by agentic-credentials' logins sitting, see below):**

- One SSH secrets engine per machine, mounted at `ssh-agents-<machine>`. Its
  CA key is made inside OpenBao (`config/ca` with `generate_signing_key`,
  `key_type` ed25519) and can't be read out.
- One role, `agent-sign-<machine>`: user certificates only; principals
  matching `*@<machine>.agents.local` only; the key id set by the caller;
  the one extension `attestation@agent-sign` allowed, none by default; no
  critical options; only ed25519 keys to certify; `ttl` and `max_ttl` 12 h;
  `not_before_duration` 5 m. These are the same 12 h and 5 min as the
  in-memory authority's constants (`CERT_LIFETIME_SECS`,
  `CERT_BACKDATE_SECS`).
- One AppRole login, `agent-sign-<machine>`, with agentic-credentials'
  standard settings (tokens of 15 minutes, 1 hour at most, usable only from
  the machine's own tailnet address). Its policy grants exactly `update` on
  `ssh-agents-<machine>/sign/agent-sign-<machine>` and the token's own
  revocation. The CA's public key is read from the engine's public
  `public_key` endpoint and needs no grant.

**How the login reaches the service** (the agentic-credentials pattern,
reused as is): the logins sitting delivers the secret ID, wrapped and
single-use, to Taylor's account on the machine, where it goes straight into
`systemd-creds --user encrypt`. agent-sign's sitting then moves it in one
pipe, as the suite's sitting moves the unharness login:
`systemd-creds --user decrypt ... - | sudo systemd-creds encrypt
--name=secret-id - /etc/credstore.encrypted/agent-sign.secret-id`, and the
role ID (the login's name) the same way. Taylor's copy is then deleted. The
unit loads both with `LoadCredentialEncrypted=`. Nothing is printed and
nothing is written in plain text.

**What the adapter does:**

- Logs in when it first needs to (`auth/approle/login`), keeps the token
  only in memory (zeroed when dropped), and logs in again when the token
  expires or is refused. It rereads the secret ID from
  `$CREDENTIALS_DIRECTORY` each time rather than holding it.
- Signs with `POST /v1/<mount>/sign/<role>`: the session key, exactly one
  principal, `cert_type` user, the key id `<principal> on <host>`, the
  attestation extension, `ttl` 12 h.
- Checks every certificate it gets back before using it: signed by the CA
  key it read at start, exactly the one principal asked for, user type, no
  critical options, exactly the asked extension with the asked value, and a
  validity window within a minute of the expected one. Anything else is
  refused.
- **Fails closed.** If OpenBao can't be reached, answers an error, or
  returns anything unexpected, the signature is refused with a plain
  message, and the commit fails. The service still starts and still answers
  plain-path questions; `agent-sign doctor` says what is wrong.
- **Never writes trust.** At start it reads the CA's public key from OpenBao
  and compares it with the one line in `[service] trust_file`. If they
  differ, it signs nothing and says so: trust is root's, set at the sitting.
- Uses TLS 1.3 only, trusting only the CA file named in `[authority]
  ca_cert`, reaching the address given in `resolve`. The service runs no
  other program (an existing guard test), so this needs an HTTP client in
  Rust: `ureq` with `rustls`, pinned, both checked by `cargo deny`. Their
  TLS libraries (`ring`, `rustls-webpki`) are licensed partly under ISC,
  which `deny.toml` doesn't list yet (question 5).

**As built (step 4, 1 Nov 2026).** `src/issuer_openbao.rs` follows the list
above, with these choices made while building it:

- The HTTP client is `ureq` 3.5.0 over `rustls` 0.23.46 with the `ring`
  provider, both pinned in `Cargo.toml`. ureq 3 can't be told "TLS 1.3
  only" directly, so the crypto provider handed to it holds only the three
  TLS 1.3 cipher suites: a server that offers only TLS 1.2 has nothing to
  negotiate. No web roots are compiled in, no proxy from the environment is
  used, no redirect is followed, no connection is kept, and every call has a
  10 second deadline.
- The CA comparison with the trust file is repeated at each request until it
  has succeeded once, so a service that started before OpenBao was up (or
  before trust was installed) recovers without a restart. Nothing is ever
  signed before it succeeds, and the trust file is only read.
- The principal is checked before any request: `<name>@<machine>.agents.local`
  with a name of lowercase letters, digits, `.` and `-`. OpenBao 2.7.1's role
  can't be relied on for this (see the two role tests, which fail on 2.7.1
  and belong to step 6: `allowed_users` is matched exactly, and an empty
  `allowed_critical_options` allows any). OpenBao therefore doesn't limit the
  principal domain: the real limits are the per-machine authority (one CA per
  machine) and the single trust line, so this authority must never be added to
  sshd's `TrustedUserCAKeys`.
- OpenBao 2.7.2 still matches `allowed_users` exactly
  (`internal/builtin/logical/ssh/path_issue_sign.go` at v2.7.2: L88
  `slices.Contains` for user certificates; L250-251 the literal `*` is the only
  wildcard; L254-257 an exact element match; L167-211 templates substitute
  identity values only, then the same exact match; `allowed_domains` applies to
  host certificates only). Confirmed on a dev server on 1 Nov 2026:
  `*@hetzner.agents.local` refuses every principal, valid ones included, and
  only one exact principal per role works. So the role keeps `allowed_users`
  `*`, and the domain stays held by the per-machine authority, the exact trust
  line, agent-sign's own checks, and its account alone holding the login.
- `deny.toml` allows ISC: it is MIT-equivalent, and `ring` and `rustls-webpki`
  carry it.

**Its tests run against a throwaway `bao server -dev`, on loopback, in the
agents account. That is sound, with these conditions:**

- The dev server keeps everything in memory, including the CA key it
  generates, so no key is ever written to disk. It must be started with
  `-dev-no-store-token`, so it doesn't write its root token to
  `~/.vault-token`, and with a random root token the test makes, passed in
  its environment.
- It must not use `-dev-tls`: that writes a TLS private key and certificate
  to a folder on disk. The tests instead put a TLS 1.3 proxy in front of the
  dev server, inside the test process, with a key made in memory (`rcgen`, a
  test-only dependency). So the adapter's real TLS path, with a pinned CA,
  is what gets tested.
- It listens on `127.0.0.1` on a free port. The dev server also opens a
  cluster port at its port plus one, and hetzner's real OpenBao already uses
  127.0.0.1:8201, so the test picks a port whose next port is free too.
- The tests are `#[ignore = "needs bao"]` and are run with `--ignored` on
  hetzner in their build step, so they never pass for lack of a server. CI
  installs the pinned OpenBao release, checked against its SHA-256, the way
  agentic-credentials pins it.
- On hetzner the `bao` on `PATH` is 2.7.1 and the pin is 2.7.2. The tests
  print the version they ran against (question 4).
- The dev server's authority is trusted by nothing, and everything in it is
  thrown away when the test ends. Other processes of the agents account
  could talk to it while it runs; they would gain nothing from that.

## 6. D5: removing the old trust the agents can write

After the new service is up and checked, the sitting, acting as `agents`
(through `sudo -u agents`, with `/usr/bin/git` and a clean environment,
never the agents' own `PATH`):

1. saves copies of the agents' global git config, their allowed-signers
   file and `~/.agent-sign/bin` to `/var/lib/agent-sign-sitting/before/`
   (root-owned, for undo; the agents' own `~/.config/systemd/user/agent-signd.service`
   is saved there too, at step 5, when it is a real file);
2. removes `gpg.ssh.allowedSignersFile` from the agents' global git config;
3. removes agent-sign's managed block, from
   `# agent-sign: agents' certificate authorities, managed; do not edit` to
   `# agent-sign: end of agents' certificate authorities`, from
   `~/.config/git/allowed_signers`, leaving any other lines;
4. points `gpg.ssh.program` at `/opt/agent-sign/current/bin/agent-ssh-sign`;
5. stops and disables the user-level `agent-signd.service`, then, as the agents
   account, saves its unit file for undo (a copy in root's folder and a
   `user-unit` line in the manifest), checks the copy is byte for byte the file,
   removes the file, and masks the unit. Both steps are needed: `systemctl
   --user mask` refuses to mask a unit that has a real file in its own folder
   ("File ... already exists"; reproduced on systemd 259), as the old install
   left it. On a rerun a copy already saved is kept and a manifest saved before
   this change gets its line added. If that path is a link instead, `mask` fails
   over it too, unless it points at `/dev/null` (a mask already in place, left
   alone). Any other link is handled like the bin links: as the agents account,
   its target is saved as data in root's folder (a `user-unit` line of kind
   `link` in the manifest; a target with a newline, a `|` or a control
   character is refused before anything changes), the link is removed, and the
   unit is masked. Root never follows the link;
6. replaces the plain copies in `~/.agent-sign/bin` with links to
   `/opt/agent-sign/current/bin` and `.../wrap/git`, so the agents' git
   wrapper is the reviewed build, reads `system.toml` and reaches the system
   service. The old `agent-signd` copy is not linked back.

Then it checks, as `agents`: `git config --show-origin --get
gpg.ssh.allowedSignersFile` answers `/etc/agent-sign/allowed_signers` from
`file:/etc/gitconfig`; that file has exactly one line that isn't blank or a
comment; that line is a `cert-authority` line; and its key is the one
OpenBao's `public_key` gives.

The agents account could put its own setting back afterwards. That changes
only what the agents account sees; the boundary is the root-owned file, the
OpenBao authority and the service in its own account. Whatever decides (the
merge gate, Taylor's machines) uses `agent-sign verify --format json` against
the `/etc` file, not the agents' view. In system mode `verify` reads the trust
file from `/etc/agent-sign/allowed_signers` always, whatever any git config
says (a gate outside system mode passes `--allowed-signers <file>`), and the
JSON names the file it used in `trust_file`. Old commits certified by the agents' earlier
authorities no longer verify under the `/etc` file, and `agent-sign verify`
says "not verified" for them, which is accurate. The agents' old history file
is left where it is, trusted by nothing.

## 7. The commitments approval key

The plan puts it in OpenBao transit (not exportable), usable only by the
commitments check's own account. **No such account exists on hetzner**
(checked with `getent`; see the facts). ntaild runs inside unharness's
services as `suite-unharness`.

What the sitting can do now: everything in this design except the two things
that need that key. It leaves `[approvals] commitments_key` unset (so
`SignApproved` is refused, as today when it isn't configured) and
`[launcher] approvers` empty (so only Taylor's account can launch). Both
are lines in `system.toml`; turning them on later is a rerun of the sitting
with the published public key line.

What it can't do now: make the transit key, publish its public line, or let
any job launch a session. Which account should hold that key is question 2.

## 8. The sitting script

`scripts/sitting/agent-sign-sitting.sh` in the agent-sign repo, with its
files beside it: `scripts/sitting/lib.sh` (the same helpers as the suite's
`hetzner/lib.sh`: `say`, `section`, `die`, `change`, `keep`, `as_root`,
`as_user`, `install_file`, `check`, `wait_for`), `scripts/sitting/files/`
(the unit files, the polkit rule template, the `system.toml` template) and
`scripts/sitting/pins.env` (the Rust toolchain's version and its SHA-256 for
each architecture). Bash, `set -euo pipefail`, `umask 077`.

```
agent-sign-sitting.sh --machine hetzner|pi --commit SHA --source BUNDLE
                      [--slots N] [--dry-run [--login-pending]] [--undo]
```

`--source` is a git bundle (`git bundle create FILE refs/heads/main`, made in
agent-sign's repository, whose `main` contains `--commit`); a tar is refused.
`--slots` is 2 or more (the probe session holds one slot for an hour, and the
end checks need a second, so one slot could never pass them; it is refused
before any change). `--login-pending` is accepted only with `--dry-run`: the
steps that need the OpenBao login and SSH engine, which agentic-credentials'
logins sitting delivers, are listed as "after the login is delivered" instead
of stopping the dry run. `AGENT_SIGN_SITTING_ROOT` and `_GIT`, which aim the
script at a test root, are honoured only with `AGENT_SIGN_SITTING_TEST=1`.

### It meets the slot contract

- **Runs as Taylor with sudo.** It refuses uid 0 and the agents account.
  Every root command goes through `as_root WHY ...` and every other account
  through `as_user ACCOUNT WHY ...`. The prompt is
  `"${SITTING_SUDO_PROMPT_PREFIX:-<machine> sudo (<account>)}: "` (default
  `"hetzner sudo (taylor): "` when run on its own on hetzner), with `%` doubled
  as the suite's does; the `$WHY` is one short line on stderr just before the
  prompt, and no product name is ever in a sudo prompt (Taylor's prompt rule,
  1 Nov 2026). There is no other `sudo`.
- **`--dry-run`** prints every `would:` line and every file diff, and changes
  nothing. It may use sudo to read root-only state.
- **Idempotent**: every step checks first and prints `kept:` when there is
  nothing to do. A second run changes nothing.
- **Stops at the first failure**, through `change` and `die`. Every
  multi-command function ends each command with `|| return 1` or `&&`,
  because bash ignores `set -e` inside a function called from `||`.
- **Prints no secret**: the secret ID moves only by pipe; no `set -x`; the
  check of the stored login prints only whether it has the right shape.
- **Ends by checking its results**, printing PASS or FAIL for each.
- **Root never runs anything from a place another account can write.**
  Nothing under `/home` is run by root. The build runs in a throwaway
  account (below), and root only copies its output and records its hash.
  The files systemd opens as root for the session units live under
  `/var/lib/agent-launch-io`, every folder of which is root's: systemd follows
  links when it opens them, so a folder the launcher could write in would let a
  compromised launcher aim root's open at `/etc/cron.d` (review finding A-2).
- **No program from the source or from `/opt/agent-sign` runs while sudo's
  ticket is cached** (review finding A-3). `forget_sudo` (`sudo -k`, through
  the script's own `sudo` wrapper) comes before the first run of the installed
  `agent-sign` (the check that it starts, the health check, the probe launch and
  the end checks' launches); the next root step asks for the password again
  with its own named prompt. `check-binary-clean.sh` is the sitting's own
  reviewed copy, `scripts/sitting/files/check-binary-clean.sh` (a test keeps it
  identical to `scripts/check-binary-clean.sh`), never a script from the source.
- **Text the agents control is filtered before it is printed** (A-8): their
  settings' values, file names and git's origin go through `plain_text`, so an
  escape sequence can't retitle or clear Taylor's terminal. Besides control
  characters, `plain_text` writes out the invisible format characters that
  reorder or hide text: the bidi marks and isolates, zero-width characters,
  and (re-check Q3) U+061C, U+180E, U+2028, U+2029, U+2061-U+2064 and the tag
  characters U+E0000-U+E007F.

### What the suite's slot must change (suite repo, small)

- `server-sitting.sh` also puts a git bundle of agent-sign's `main`
  (`git bundle create <file> refs/heads/main`; `main` contains
  `$AGENT_SIGN_COMMIT`) into the bundle, as `agent-sign/source.bundle`, beside
  the script. It comes from the Mac's own clone, like everything else in the
  bundle. (Before review finding A-6 it was `git archive` as `source.tar`; the
  tar's header proves only that the tar says so, not that the content is the
  commit, and a tar is now refused.)
- `step_agent_sign` passes `--machine "$SUITE_MACHINE" --commit
  "$AGENT_SIGN_COMMIT" --source "$BUNDLE/agent-sign/source.bundle"`, and on its
  `--dry-run` call, while agent-sign's login is not yet in
  `/etc/suite/installed-logins`, also `--login-pending` (never on the real call).
- The logins sitting it already runs for unharness also makes the
  `agent-sign-<machine>` login, once agentic-credentials supports SSH
  engines (build step 6), and it runs before agent-sign's slot.

### Before any change (read-only)

1. `--machine` matches this machine (its tailnet name), and the account
   running the script is the admin account, not root and not `agents`.
2. systemd 257 or later; kernel 6.5 or later; polkit with JavaScript rules;
   `git`, `ssh-keygen` and `systemd-creds` present.
3. The source is a git bundle that holds `--commit` (review finding A-6). In a
   fresh empty repository with git's config isolated (`GIT_CONFIG_GLOBAL=
   /dev/null`, `GIT_CONFIG_NOSYSTEM=1`, no template, no hooks, an empty
   environment), the script runs `git bundle verify`, fetches the bundle's refs,
   requires `git cat-file -e <commit>^{commit}`, and makes the tree to build with
   `git archive <commit>`. git recomputes every object's hash and a commit id
   names its tree by hash, so that tree is exactly what the commit id names. A
   tar, a bundle of other history, one that stops before the commit, an
   incremental one and a damaged one are refused, all with the word "bundle".
   Nothing from the source is run except the build, inside the sandbox.
4. OpenBao is unsealed; `ssh-agents-<machine>/public_key` answers with one
   ed25519 key; the `agent-sign-<machine>` login is in Taylor's credential
   store, or already in the system store. (With `--dry-run --login-pending`, a
   missing login or SSH engine is listed as "after the login is delivered"
   rather than stopping; sealed and older-than-2.7.2 still stop.)
5. If `/etc/agent-sign/system.toml` exists, it parses and names the same
   machine and accounts. Any other layout stops the run.
6. The account names are free, or are already system accounts with the
   expected home and shell.
7. Lists what runs today: the agents' user `agent-signd`, the agents' global
   `allowedSignersFile` and `gpg.ssh.program`, and any `AGENT_SIGN_SOCKET`
   in the agents' login files (which stops the run). A link in the agents' bin
   folder whose target holds a newline, a `|` or a control character stops the
   run too, before anything changes: undo copies saved links back, and the
   reviewer's exploit (A-1) was a target made to look like a manifest line.
8. Says plainly that approvals and signed launches stay off, because the
   commitments key doesn't exist yet.

### The changes, in order, and which sitting test each one serves

The six sitting tests are: P3-state (`..._cant_read_or_change_agent_signs_state`),
P3-process (`..._cant_reach_the_service_process`), P3-rogue
(`..._a_service_the_agents_account_starts_is_trusted_by_no_verifier`),
P1/P7-plain (`..._a_plain_agents_process_gets_no_attested_signature_from_the_service`),
P4 (`..._cant_reach_a_launched_session`), P1-launch
(`..._the_agents_account_cant_launch_a_session_itself`).

| # | Change (each named, with why) | Serves |
|---|---|---|
| 1 | **Build** the pinned commit in a throwaway sandbox (see below) and install the programs into `/opt/agent-sign/<commit>/`, root-owned, after `scripts/check-binary-clean.sh` confirms no test hooks are in them; switch `/opt/agent-sign/current` | all |
| 2 | **Accounts**: `agent-sign`, `agent-launch`, `agent-slot-1..N` with their groups; `agent-launch` into each slot group; slot accounts into `/etc/at.deny` and `/etc/cron.deny` | P3-state, P3-process, P4, P1-launch |
| 3 | **Folders**: `/var/lib/agent-slots/<n>/` and `trash/` with the owners and modes in section 1; `/var/lib/agent-launch/out`; and the launcher's I/O folder `/var/lib/agent-launch-io/{specs,logs}` (root:agent-launch 0750), with one pre-made plain file per slot in each (`specs/<n>.json`, `logs/<n>.out`, agent-launch:agent-launch 0600). An existing entry that is not exactly that stops the run and is not followed or changed | P4, D6 |
| 4 | **The login**: move the `agent-sign-<machine>` secret ID and role ID into `/etc/credstore.encrypted/` by pipe, as a pair (the earlier files are kept as spares until both new ones are in place and check out; any failure puts the earlier pair back whole); check the stored value's shape; delete Taylor's copy; add the name to `/etc/suite/installed-logins` where that file exists | (the service can sign) |
| 5 | **Trust**: `/etc/agent-sign/allowed_signers` with the one CA line from OpenBao; `git config --system gpg.ssh.allowedSignersFile /etc/agent-sign/allowed_signers` | P3-rogue, D5 |
| 6 | **Units**: `agent-signd.socket`, `agent-signd-launcher.socket`, `agent-signd.service`, `agent-launchd.socket`, `agent-launchd.service`, `agent-session@.service`, `agent-session-end@.service`; `daemon-reload` | P3-process, P4 |
| 7 | **polkit rule** `50-agent-launch.rules`, generated for N slots | P4, P1-launch |
| 8 | **`system.toml`**, from the template with this machine's values. From here on, one-account launch is refused on this machine. It is placed only after the installed `agent-sign` has been seen to start (`agent-sign --version`, with no sudo ticket), and a start that then fails puts it back (see below) | P1-launch, P1/P7-plain |
| 9 | **Start**: enable and start the sockets and both services; wait until the service answers `Ping` and reports that OpenBao's CA matches the trust file | P3-process, P1/P7-plain |
| 10 | **Retire the old trust** (D5, section 6) | D5 |
| 11 | **A probe session** for P4: as Taylor, `agent-sign launch --agent sitting-probe -- sleep 3600`, left running in the background for an hour, so an agent can run the six tests | P4 |

**Building the programs.** Root must not install a program built with a
toolchain the agents account can change, and building runs third-party code
(dependencies' build scripts), which must not run as Taylor while sudo is
cached. So:

- the build is two throwaway accounts, one per `systemd-run --wait --pipe -p
  DynamicUser=yes` call, each with `ProtectHome=yes`, no capabilities and its
  own state folder (review finding A-4: one call cannot give the fetch a
  network and the compile none, and the compile is where third-party build
  scripts and proc-macros run);
- **fetch**: the toolchain is the official Rust standalone archive for the
  machine's architecture, downloaded in the sandbox and checked against the
  SHA-256 in `scripts/sitting/pins.env`; dependencies are fetched with `cargo
  fetch --locked`, which checks each crate against `Cargo.lock`. This phase has
  the network, but `IPAddressDeny=` covers a list of address ranges:
  `0.0.0.0/8`, loopback (`127.0.0.0/8`,
  `::1`), Tailscale (`100.64.0.0/10`, `fd7a:115c:a1e0::/48`), RFC 1918,
  link-local and the cloud metadata address (`169.254.0.0/16`, `fe80::/10`),
  unique-local (`fc00::/7`) and multicast, plus this machine's own global
  addresses (read with `ip` at sitting time), so build-time code can't reach
  NATS, the inbox, OpenBao or a tailnet node. `IPAddressAllow=` names the
  machine's DNS servers, read from `/etc/resolv.conf`, as single addresses (it
  wins over the deny): hetzner's is systemd-resolved's stub `127.0.0.53` (a link
  into `/run/systemd/resolve`), the Pi's is Tailscale's `100.100.100.100` and
  `fd7a:115c:a1e0::53`. `TemporaryFileSystem=/run` hides every socket in `/run`,
  and `BindReadOnlyPaths=-/run/systemd/resolve` brings the resolver's back.
  Not covered: abstract unix sockets belong to the host's network namespace,
  which an IP filter can't see. **Known limit:** the allowance is by address,
  not port, so the fetch phase reaches the DNS servers on every port (DNS is
  enough for small data leaks; on the Pi it reaches Tailscale's
  `100.100.100.100` service on any port; a loopback service bound to all
  addresses answers on `127.0.0.53` on any port). Nothing in systemd narrows
  it to port 53 cheaply (`SocketBindAllow=` restricts only `bind(2)`); the
  next step, kept in the sitting's README as a backlog idea, is to resolve
  the hosts first and give the fetch an `/etc/hosts` and no resolver. Its
  output (the toolchain archive and the crate files with the registry index)
  goes to the next phase through Taylor's script, which looks at none of it;
- **compile**: `PrivateNetwork=yes`, no network at all, and `/run` hidden too
  (`TemporaryFileSystem=/run`: the system D-Bus and every unix-socket service).
  Both phases also hide, with `InaccessiblePaths=-...`, the host's own state a
  build never needs: `/etc/credstore.encrypted`, `/etc/credstore`,
  `/etc/agent-sign`, `/var/lib/agent-sign`, `/var/lib/agent-launch`,
  `/var/lib/agent-launch-io`, `/var/lib/agent-slots`,
  `/var/lib/agent-sign-sitting` and `/var/lib/tailscale`. The compile phase
  takes from the fetch phase only the toolchain archive, the `.crate` files and
  the index, never the extracted `registry/src` or a cargo config, so cargo
  extracts every crate itself from a `.crate` that was checked. It checks the
  toolchain archive against the pinned hash again and every `.crate` file against the
  checksum in `Cargo.lock` (cargo checks a crate's hash only when it downloads
  it), installs the toolchain (its install script runs as the throwaway
  account, never as root) and builds with `--frozen`;
- root copies the four programs out, records their SHA-256 in
  `/opt/agent-sign/<commit>/SHA256SUMS`, and keeps the toolchain under
  `/opt/agent-sign/toolchain/` so a rerun reuses it.

The same steps work on the Pi, where Debian's rustc is too old. Using
Ubuntu's rustc 1.93 on hetzner would save the download there but not on the
Pi, so one method for both is simpler to review.

### The checks at the end (PASS/FAIL)

| Check | How | For |
|---|---|---|
| The service runs as `agent-sign`, active, not restarted | `systemctl show` MainPID, user, NRestarts | P3-process |
| The agents account can't restart either service | `as_user agents ... systemctl --no-ask-password restart agent-signd.service` (and `agent-launchd`) fail | P3-process |
| The agents account can't read the state or write the trust file | `as_user agents` `stat` of the state folder fails; `test -w` on the trust file fails | P3-state |
| Exactly one trust line, OpenBao's | compare the file with `public_key` | P3-rogue, D5 |
| The agents' git sees only the `/etc` file | `--show-origin` as `agents` | D5 |
| The old user service is off | `systemctl --user -M agents@ is-enabled/is-active` | D5 |
| The agents account can't launch | as `agents`, `agent-sign launch --agent codex -- /bin/sh -c 'echo probe'` fails, doesn't print the probe, and its output carries the launcher's refusal (the account isn't a person's, no signed approval came) | P1-launch |
| The agents account gets no token | as `agents`, `agent-sign` asks for an identified token: refused | P1/P7-plain |
| The launcher can do only what the rule says | as `agent-launch`, with `pkcheck`'s own exit status (0 yes, 1 no, 2 would ask): starting `agent-session@1.service` and stopping `agent-session-end@1.service` are allowed (the positive controls: a polkit that refused everything would pass the refusals alone); restart `agent-signd` refused; start `agent-session@<N+1>.service` refused; `systemd-run --unit=agent-session@1.service -p User=root true` and a transient unit under any other name refused, each by output that carries polkit's or systemd's refusal text, so a command that fails for another reason does not count | polkit scope |
| The launcher can't make, rename or remove an entry in its I/O folders | as `agent-launch`, `test -w` on `/var/lib/agent-launch-io` and its `specs/` and `logs/` is false, and on its own `specs/1.json` and `logs/1.out` true. Also, on every run: the installed session units open (as root) only paths under `/var/lib/agent-launch-io/` | A-2 |
| A launched session signs Good | as Taylor, a session that makes a repository, commits and exits; its bundle comes back; `agent-sign verify` on the fetched commit says "launcher, own account" under the `/etc` file | end to end |
| D6: slots can't see each other | a session in slot 1 holds an uncommitted file; a session in slot 2 tries to read slot 1's `current/`: refused | D6 test 1 |
| D6: no leftovers | slot 1's session ends with the uncommitted file; the next session in slot 1 can't read `trash/` or the old path; the file is in the Trash, owned by `agent-slot-1`, and logged | D6 test 2 |
| The probe session runs | `systemctl is-active agent-session@<n>.service` | P4 |

Then it prints: "An agent now runs the six sitting tests as agents on this
machine. The probe session stays up for an hour." Running the tests is an
agent's step, not Taylor's: `AGENT_SIGN_SITTING_SOCKET=/run/agent-sign/daemon.sock
cargo test --test test_caller_identity_sitting -- --ignored`, as `agents`,
in a fresh login (so the account's view is current).

### How a failed run is undone

- **Stopped part-way.** Each step checks before it changes, so the usual fix
  is to correct the cause and run the same command again; it carries on from
  where it stopped. The changes are ordered so that the agents' commits keep
  working at every point: the old user service is stopped only in step 10,
  after the new one has passed its health check.
- **The service doesn't come up healthy.** `system.toml` is what makes the
  service start in system mode, and `agent-sign doctor` reports the CA match
  only in system mode, so `system.toml` can't be placed after a health check
  that needs it (review finding A-10). Instead the installed `agent-sign` is
  first seen to start, then `system.toml` is placed, and if anything from there
  to the health check fails, the run rolls it back (the earlier `system.toml`
  restored, or the new one moved aside when there was none) and stops the
  system units, so a service that never came up doesn't leave the machine
  refusing one-account launches. On a rerun this also stops (and disables) the
  system units of an earlier healthy deployment: the rollback restores the
  earlier `system.toml` but does not restart anything, so that deployment is
  down until the sitting is run again successfully. The agents' own service is
  not touched until step 10.
- **`--undo`** (also with `--dry-run`) reverses steps 11 to 5 in reverse
  order: stops the probe session; restores the agents' saved git config,
  allowed-signers block, `bin` copies and own user-level unit file or link (a file put back
  byte for byte with its mode, a link put back with the same target, over the mask link), unmasks, enables and starts
  their user service. The manifest is read on its own file descriptor, so a
  `sudo` that reads its standard input can't eat its lines; afterwards undo
  reads every restored entry back as the agents account and compares it with
  its saved copy, says so ("every restored file matches its saved copy"), or
  stops naming the entries that do not match; stops and disables the system units and removes the unit
  files and the polkit rule; moves `system.toml` aside to
  `/etc/agent-sign/undone/system.toml.<date>` (anything at the original path
  would keep one-account launch refused); removes the `/etc/gitconfig` key.
  It never deletes data: the accounts (left with no shell and no password),
  `/var/lib/agent-sign`, `/var/lib/agent-launch`, `/var/lib/agent-launch-io`,
  `/var/lib/agent-slots` with every Trash, `/opt/agent-sign` and the stored
  login all stay. The
  OpenBao mount, CA and login are undone, if ever, in agentic-credentials.
  The CA is never destroyed, so commits it certified stay verifiable.
- Undo restores from the copies made at the FIRST run, and says so (A-11): it
  does not look for what the agents changed in those files since, so those later
  changes are overwritten, and a saved copy or link replaces whatever stands at
  the path now. The saved copies are root's, under fixed names: the manifest
  holds only the five bin labels, `gitconfig`, `allowed_signers` and (only when the
  agents had their own unit file) `user-unit`, a mode of 3
  or 4 octal digits and the fixed name of each copy. Undo reads the whole manifest
  first and changes nothing unless every line is exactly what the sitting writes
  (a link's target is saved as data in a file of its own, never in the
  manifest). Manifests made before this change are refused by undo.
- The stub tests check that run-then-undo leaves every file outside the
  kept data byte-identical to before.

## 9. The Pi

The same script, with `--machine pi`. What differs:

- aarch64: the toolchain pin for that architecture.
- OpenBao is on hetzner, reached over the tailnet (`[authority] address`
  stays hetzner's, `resolve` is hetzner's tailnet address). Its own mount
  `ssh-agents-pi`, role `agent-sign-pi` (principals `*@pi.agents.local`) and
  login `agent-sign-pi`, bound to the Pi's tailnet address. If hetzner or
  the tailnet is down, the Pi's launched sessions can't sign (fail closed);
  plain commits are unaffected.
- No Yama module. That doesn't weaken the slot boundary: reading another
  account's process needs `CAP_SYS_PTRACE` whatever Yama says.
- OpenSSH 10.0p2 misreads the verify time git hands it
  (docs/caller-identity.md); `agent-sign verify` already avoids that path.
- No `/etc/suite`: the step that records the login's name skips it.
- The suite's server sitting drives only hetzner. A Pi leg (the same bundle,
  over `ssh` to the Pi) is suite work (question 6).

## 10. Build order

Each step starts with its tests, written by an agent other than its builder,
failing for the stated reason, then built until they pass. `cargo test` runs
on hetzner only, never on the Mac. Model: Sonnet unless marked.

0. **Evals first** (Sonnet).
   - Deliberate eval change, its own labelled commit ("DELIBERATE EVAL
     CHANGE (D6, 1 Nov 2026): sessions run in static slot accounts, not
     DynamicUser"): P4 in `tests/test_caller_identity_sitting.rs` finds
     sessions by slot account (prefix `agent-slot-`, setting
     `AGENT_SIGN_SITTING_SLOT_PREFIX`) instead of the DynamicUser uid range,
     and fails with "NEEDS THE SERVER SITTING" unless at least one process
     runs in a slot account. Without this, P4 would pass by checking only
     the launcher's own process, with no session checked. The module
     comment is updated to match.
   - The failing tests listed under steps 1 to 5.
1. **The settings file and the mode switch** (Sonnet). `system.toml`
   parsing with unknown keys refused; socket resolution; the service refuses
   to start in system mode as another account; system mode never opens a
   caller's repository; the in-memory issuer is never used in system mode.
   Tests: `system_toml_parses_and_refuses_unknown_keys`,
   `clients_use_the_system_socket_when_system_toml_exists`,
   `the_service_refuses_system_mode_as_another_account`,
   `system_mode_never_runs_git_in_a_callers_repository`,
   `a_plain_commit_check_in_system_mode_takes_the_reported_branch`,
   `system_mode_has_no_local_authority`.
2. **Who is asking: uid, unit and registration** (Opus: the security core,
   with subtle process-identity races). The launcher-only socket,
   registration, `Caller::Session` from slot uid plus cgroup plus pidfd,
   `isolation=slot-account`, socket activation (`LISTEN_FDS` with names).
   The kernel facts sit behind a small port (uid, cgroup, still alive), so
   the tests run without root. Tests:
   `a_slot_process_in_its_session_unit_is_that_session`,
   `a_slot_process_outside_its_unit_is_plain`,
   `a_slot_without_a_live_registration_is_plain`,
   `a_caller_whose_process_is_gone_is_refused`,
   `only_the_launcher_account_registers`,
   `a_registration_for_an_account_outside_the_slots_is_refused`,
   `a_closed_registration_ends_the_session_and_its_tokens`,
   `verify_says_launcher_own_account_for_a_slot_session`.
3. **The launcher, the session runner and the end step** (Opus: the
   filesystem moves must hold against a hostile session). `agent-launchd`,
   `agent-sign session-exec`, `agent-sign session-end`,
   `agent-sign launch --collect`, launch approvals. The systemd calls sit
   behind a port with a test stand-in. Tests:
   `taylors_account_may_launch_and_the_agents_account_may_not`,
   `any_other_account_needs_a_signed_launch_approval_used_once`,
   `each_session_gets_a_fresh_folder_and_fresh_clones`,
   `a_finished_session_folder_always_goes_to_the_slots_trash_and_is_logged`,
   `session_end_removes_nothing_a_clean_bundled_copy_stays_for_the_trash`,
   `the_launcher_never_follows_a_link_out_of_a_slot_folder`,
   `a_slot_is_reused_only_after_its_unit_is_inactive`,
   `a_launcher_restart_stops_every_session_and_trashes_its_folder`,
   `the_launcher_never_runs_git`.
4. **The OpenBao issuer** (Sonnet). Tests (against the dev server, run with
   `--ignored` on hetzner): `issues_through_openbao_and_verifies_under_its_ca`,
   `openbao_itself_refuses_a_principal_outside_the_machine_domain` (this one
   also shows whether this OpenBao version matches patterns in its role's
   allowed principals; if not, the role is fixed in step 6 before the
   sitting), `a_certificate_unlike_the_request_is_refused`,
   `fails_closed_when_openbao_is_down`,
   `fails_closed_when_the_ca_differs_from_the_trust_file`,
   `never_writes_trust_at_start`, `logs_in_again_when_the_token_expires`,
   `only_tls_1_3_with_the_pinned_ca`,
   `the_secret_id_is_never_in_a_message_or_log`.
5. **The sitting script and its files** (Sonnet), with stub tests modelled
   on the suite's `scripts/sitting/test`: a throwaway root with stand-ins for
   `sudo`, `systemctl`, `useradd`, `systemd-creds`, `curl`, `git`. Tests: the
   dry run changes no file (hashes before and after); a second run changes
   nothing; every sudo prompt starts with the prefix and names why; the
   first failure stops the run; a planted secret never appears in the
   output; run-then-undo restores; the generated polkit rule allows exactly
   start and stop of slots 1 to N and the end units; no private key is
   written (`check-no-unprotected-keys.sh`).
6. **agentic-credentials: SSH engines in the logins sitting** (its own
   thread in that repo, Sonnet, plus a reviewer sized to it, because it
   changes who can do what). A declaration kind for an SSH CA mount and role,
   and a `sign` grant shape. The root token's short-lived work token gets
   exactly the mount, `config/ca` and role paths for the declared machines.
   The CA is generated only if `public_key` doesn't answer, never replaced.
   Then the `agent-sign-hetzner` login, delivered to Taylor's account.
7. **The suite's slot** (suite repo, Sonnet): ship `source.bundle` (a git bundle
   of main), pass the three flags, `--login-pending` on the dry run while the
   login is not yet installed, order the logins sitting first.
8. **Docs** (Sonnet): this note's status; `docs/caller-identity.md`'s
   status and its table (DynamicUser becomes slot accounts); INSTALL and
   TROUBLESHOOTING for servers; how to launch an agent on a server.
9. **Reviews** (Opus): the independent review of the sitting script that D5
   asks for (dispatched by the PM, against the suite's REVIEW.md checklist),
   and the security review of the branch. Then merge.
10. **Taylor's sitting on hetzner**, then an agent runs the six tests as
    `agents`. Then the Pi, as its own thread.

Order: 0 first; 1, 4, 5 and 6 can run in parallel (no shared files: 4 adds
a new module plus `Cargo.toml`, `Cargo.lock` and `deny.toml`); 2 after 1; 3
after 2; 7 after 5; 8 and 9 last. Wiring the OpenBao issuer into the start
path is part of step 2's owner's work, after 4 merges, because both touch
`agent_signd.rs`.

## Not in this design (to the backlog)

- **Interactive sessions in slots.** v1 sessions have no terminal (standard
  input is empty, and output is streamed back from a log). Claude Code run
  by hand in the agents account stays a plain process, and its commits stay
  unsigned (D1).
- **Agents' own logins inside slots.** A slot has no model or GitHub login,
  so Claude Code or Codex can't yet run as a launched session for real work.
  Either per-slot logins from OpenBao (agentic-credentials) or model calls
  through unharness's model-call service would solve it.
- **Emptying the Trash**: the sweep that deletes only provably regenerable
  Trash folders (a clean working copy whose HEAD is in a delivered bundle
  or upstream), each deletion logged, run as the slot account. Everything
  else is a person's to empty.
- **The merge gate** (D1), which also makes the content rules binding for
  launched sessions in system mode.
- **Taylor's Mac's view**: its allowed-signers line for
  `*@hetzner.agents.local` must become the OpenBao CA's.
- **Socket activation per slot**, if interactive sessions need it.

## QUESTIONS for the suite PM

Each is a judgment call; everything else above is decided.

1. **Until the commitments key exists, only Taylor's account can launch a
   session on hetzner. Is that acceptable?** Effect: no job can start an
   attested session yet. Every agent working in the agents account (Claude
   Code included) keeps committing unsigned under its own names (D1), as
   after S8 today. Attested commits on the server come only from sessions
   Taylor starts, until signed launches exist (and, for real agent work,
   until slots have model logins). Alternative: hold the whole sitting
   until the commitments key exists. **Recommendation: go ahead.** The
   boundary (agent-sign in its own account, root's trust file, OpenBao's
   authority) is worth having now, and nothing that works today stops
   working.

2. **Which account holds the commitments approval key** (and so signs commit
   and launch approvals)? (a) A new account for the commitments check alone,
   for example `suite-commitments`, with its own OpenBao login and the
   transit key usable only by it. (b) `suite-unharness`, where ntaild runs
   today. Effect of (b): anything that compromises unharness's turn control
   or model-call service could approve any agent commit or launch.
   **Recommendation: (a)**, with ntaild's signing moved behind that account
   when the key is made.

3. **Content rules for launched sessions in system mode.** The service can
   no longer run git in a session's repository without letting that
   repository act as the account that holds the signing login. Proposed:
   the service keeps the identity, date and branch-name checks; the
   forbidden-path and diff-size rules run in the session's git wrapper and
   at the merge gate. Effect: until the merge gate exists, a session that
   bypasses its wrapper can get a signed commit that breaks a content rule.
   It would carry the session's true name, and it would be refused at merge
   once the gate exists. Alternative: the service runs git on a read-only
   copy inside a bubblewrap sandbox as its own account (more code; the
   repository's config still runs in a sandbox of the signing account).
   **Recommendation: the proposal**, with the merge gate as the place
   content is enforced.

4. **OpenBao on hetzner is 2.7.1; agentic-credentials pins 2.7.2 as a
   security update (GHSA-736f-82w7-hj22).** Upgrade before this sitting,
   through agentic-credentials' own process? **Recommendation: yes, before
   the sitting.** This sitting adds a signing role to that server.

5. **Allow the ISC licence in agent-sign's `deny.toml`?** The TLS libraries
   the OpenBao client needs (`ring`, `rustls-webpki`) are under ISC, a
   permissive licence equivalent to MIT. `deny.toml` today allows only MIT,
   Apache-2.0, BSD-3-Clause and Unicode-3.0, "so ... nothing new for an
   organization to review". Effect of no: the OpenBao client needs another
   TLS stack, and all of the maintained Rust ones include ISC code.
   **Recommendation: allow ISC.**

6. **The Pi's sitting.** The suite's server sitting drives only hetzner.
   **Recommendation:** hetzner first; once its six tests pass, the suite
   adds a Pi leg (the same bundle, over SSH to the Pi) and the same script
   runs with `--machine pi`.
