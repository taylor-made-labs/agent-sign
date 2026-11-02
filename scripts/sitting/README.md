# agent-sign's server sitting

`agent-sign-sitting.sh` puts agent-sign into system mode on a server: its own
accounts, a system service that the agents account can't restart, the
certificate authority in OpenBao, root's trust file, and one account per launched
session. The design is `docs/system-mode.md` (section 8 and build step 5); the
suite PM's decisions D5 and D6 bind it. Its eval is `tests/test_sitting_script.rs`,
which runs this script as an ordinary account against a throwaway root with
stand-ins for `sudo`, `systemctl`, `useradd` and the rest.

```
agent-sign-sitting.sh --machine hetzner --commit SHA --source BUNDLE [--slots N] [--slot-memory-max SIZE] [--slot-tasks-max N] [--dry-run [--login-pending]] [--undo]
```

`--source` is a git bundle (`git bundle create FILE refs/heads/main` in agent-sign's
repository, whose `main` contains the commit); a tar is refused. `--slots` is 2
or more (one slot could never pass the end checks: the probe holds it). `--slot-memory-max`
(a percentage of the machine's memory, 1% to 100%, or a size with a unit suffix K, M, G or T, such as `2G`; a bare number like `10` is refused because it would mean 10 bytes; default `50%`) and
`--slot-tasks-max` (a percentage, or a whole number of tasks; default `15%`) are written as
`MemoryMax=` and `TasksMax=` into both slot units; a bad value is refused before any change. `--login-pending`
works only with `--dry-run`: steps that need agentic-credentials' login and SSH engine
are listed as "after the login is delivered" instead of stopping. The test overrides
`AGENT_SIGN_SITTING_ROOT` and `AGENT_SIGN_SITTING_GIT` are honoured only with
`AGENT_SIGN_SITTING_TEST=1`.

## The contract (the suite's `REVIEW.md`, "The agent-sign slot")

- Runs as Taylor with sudo; refuses uid 0 and the agents account.
- `--dry-run` prints a `would:` line for every change and a diff for every file,
  and changes nothing (it may use sudo to read root-only state).
- Idempotent: each step checks first and prints `kept:` when nothing is left to do.
- Stops at the first failure with a `Stopped:` line in plain words.
- Every sudo prompt is `${SITTING_SUDO_PROMPT_PREFIX:-<machine> sudo (<account>)}: `
  (for example `hetzner sudo (taylor): `), with the why on one short line just
  before it and no product name in it. There is no other
  use of sudo (`lib.sh`: `as_root`, `as_user`).
- Prints no secret. The OpenBao secret ID moves only by pipe, from
  `systemd-creds --user decrypt` into `sudo systemd-creds encrypt`.
- Ends by checking its results (`PASS`, `FAIL` or `SKIP` per line). Exit status
  is non-zero if any check failed.
- `--undo` reverses the changes and never deletes data.
- Preflight needs OpenBao 2.7.2 or later (GHSA-736f-82w7-hj22).

## Folder

| File | What it is |
|---|---|
| `agent-sign-sitting.sh` | the script |
| `lib.sh` | the helpers: `change`, `keep`, `as_root`, `as_user`, `check`, `install_file` |
| `pins.env` | the Rust toolchain version and its SHA-256 for each architecture |
| `files/machine-<name>.env` | one machine's public settings (OpenBao address, mount, role, login name). The repository holds only `machine-example.env`, with made-up values; copy it to `machine-<name>.env` (git ignores that name) and fill in the real machine's values, which are never committed. |
| `files/*.service`, `files/*.socket` | the units, installed as they are |
| `files/50-agent-launch.rules.in` | the polkit rule, filled in for N slots |
| `files/system.toml.in` | `/etc/agent-sign/system.toml`, filled in for this machine |
| `files/build-in-sandbox.sh` | the build, run in a throwaway account in two phases (`fetch`, then `compile`) |
| `files/check-binary-clean.sh` | the sitting's own reviewed copy of `scripts/check-binary-clean.sh` (a test keeps them identical); the one the sitting runs, never the source's |

The script reads its other files from the folder it sits in. The suite's slot
today copies only the one script file into its bundle, so its build step 7 must
ship this whole folder (for example as a tar beside `source.tar`) and run the
script from there.

## What it changes, in order

1. Builds the pinned commit in two throwaway accounts (`systemd-run --wait --pipe
   -p DynamicUser=yes`, twice): a fetch phase with the network but with
   `IPAddressDeny=` for loopback, Tailscale, RFC 1918, link-local, unique-local and
   multicast, `IPAddressAllow=` for the machine's DNS servers only, and `/run`
   hidden except `/run/systemd/resolve`; then a compile phase with
   `PrivateNetwork=yes`. The source is the commit's tree, made by git from a
   verified bundle. Both phases set `ProtectProc=invisible` (other processes are hidden in `/proc`; no `ProcSubset=`, as build tools read `/proc/cpuinfo`). If the health check fails, the run rolls back (units stopped and disabled, `system.toml` restored or moved aside) and says so instead of claiming nothing changed. It refuses a build that the sitting's own
   `files/check-binary-clean.sh` finds a test hook in, and installs the five
   programs root-owned under `/opt/agent-sign/<commit>/` with a `SHA256SUMS`;
   `current` is switched in one rename and the previous release stays.
2. Accounts `agent-sign`, `agent-launch`, `agent-slot-1..N` (N is `--slots`,
   else what `system.toml` says, else 8); `agent-launch` joins each slot's group;
   the slots go into `/etc/at.deny` and `/etc/cron.deny`.
3. The slots' and the launcher's folders, and the launcher's I/O folder
   `/var/lib/agent-launch-io/{specs,logs}` (root:agent-launch 0750) with one plain
   file per slot in each (`specs/N.json`, `logs/N.out`, agent-launch 0600). systemd
   opens exactly those paths as root for the session units; every folder on the
   way is root's, so nothing can be planted. An existing entry that isn't exactly
   that stops the run; nothing is followed, replaced or removed.
4. The OpenBao login: moved from the administrator's credential store into
   `/etc/credstore.encrypted/agent-sign.{secret-id,role-id}`; the delivered copy
   is removed once the stored one checks out.
   An end check says so: the installed credential is present and the
   administrator's delivered copy is gone, naming both paths.
5. `/etc/agent-sign/allowed_signers` (exactly one line, OpenBao's CA, scoped to
   `*@<machine>.agents.local`) and `gpg.ssh.allowedSignersFile` in `/etc/gitconfig`.
6. The units, then `daemon-reload`.
7. The polkit rule `50-agent-launch.rules`: the launcher account may start and
   stop `agent-session@1..N` and `agent-session-end@1..N`, and is refused
   everything else systemd offers it.
8. `/etc/agent-sign/system.toml`, placed after the installed `agent-sign` has been
   seen to start (`agent-sign --version`, with no sudo ticket).
9. Starts the sockets and services, and waits for the installed `agent-sign` to
   report a ping and a CA match. If that fails, `system.toml` is put back as it
   was (or moved aside) and the units are stopped, so a service that never came
   up doesn't leave one-account launch refused. On a rerun this also stops
   (and disables) the units of an earlier healthy deployment: the earlier
   `system.toml` comes back, but nothing is restarted, so that deployment is
   down until the sitting succeeds again. (`system.toml` can't be placed
   after the health check: the service needs it to start in system mode.)
10. D5: only after step 9, as the agents account: removes its own
    `gpg.ssh.allowedSignersFile`, removes agent-sign's managed block from its
    `allowed_signers`, points `gpg.ssh.program` at the reviewed build, replaces
    its plain program copies with links, then stops and disables its
    user-level `agent-signd`, saves and removes its own unit file or link (a real file
    or a link to anything but `/dev/null` blocks `mask`), and masks it. Root's copies of everything it touches are kept in
    `/var/lib/agent-sign-sitting/before/` first. Then it checks, as the agents
    account, that git trusts only the `/etc` file.
11. A probe session (`agent-sign launch --agent codex -- sleep 3600`, started
    from `/`), for the six sitting tests.

Raising `--slots` on a rerun adds accounts, folders and rule entries; lowering it
never deletes an account, a folder or a Trash.

## Interfaces it depends on in the programs

These are built (build steps 2 and 3). If one changes, the script changes with it.

- `agent-sign doctor`, in system mode, prints the lines `ping: ok` and
  `authority: OpenBao CA matches the trust file` when the service answers and
  OpenBao's CA is the one in `[service] trust_file`. The sitting waits up to 30
  seconds for both. Its exit status is not used, because `doctor` also warns
  about things unrelated to the service.
- The launcher is `agent-launchd` (no flags). It takes its socket from systemd
  (a socket named `launch`, from `agent-launchd.socket`), and reads everything
  else from `/etc/agent-sign/system.toml`. It refuses to run as root or as any
  account but `[launcher] account`.
- `agent-sign session-exec` and `agent-sign session-end` take no arguments (they
  work out the slot from their own uid and cgroup), as the unit files call them.
- `agent-sign launch --agent NAME -- COMMAND...` starts a session and stays up
  until it ends. `NAME` must be a built-in agent name (`claude-code`, `codex`,
  `gemini-cli`) or listed in `[identity] allowed_agents`; the probe and the end
  checks use `codex`. Run inside a git working copy it sends that repository
  as a bundle and fetches the session's commits back as
  `session/<principal>/<branch>`; the script runs its launches from `/` or from a
  throwaway repository.
- Sockets: the service's `/run/agent-sign/daemon.sock` (everyone, mode 0666),
  the service's launcher-only `/run/agent-sign/launcher.sock` (group
  `agent-launch`, mode 0660), and the launcher's `/run/agent-launch/launch.sock`
  (mode 0666; the launcher decides by uid). Their names are `system.toml`'s
  `[service] socket`, `[service] launcher_socket` and `[launcher] socket`.
- The launcher's state folder is `/var/lib/agent-launch` (`out/`, `sessions.log`,
  `launcher.lock`, all private to `agent-launch`). The files systemd opens as root
  are in `/var/lib/agent-launch-io` (`specs/N.json`, `logs/N.out`, made by the
  sitting; the launcher opens those existing files without following links and
  never creates, renames or removes an entry there; the session units' paths and
  `ReadWritePaths=` in the launcher's unit follow this). Each
  slot's folder under `/var/lib/agent-slots/N` is `agent-launch:agent-slot-N`
  mode 0750 with a private `trash/`.
- `system.toml` keys are exactly those `src/system_config.rs` accepts
  (unknown keys are refused): `machine`, and the tables `[service]`,
  `[launcher]`, `[slots]`, `[identity]`, `[authority]`, `[approvals]`.
- The OpenBao role must accept any principal on 2.7.1 and later (`allowed_users`
  is matched exactly, with no patterns). What limits principals to this machine's
  agents is the machine's own CA and the one trust line this script writes.

## What the end checks cannot do here

Under a non-empty `AGENT_SIGN_SITTING_ROOT` (the tests) the checks that need a
real kernel, accounts, polkit or sessions print `SKIP`. That includes the three
that launch sessions: a launched session signs Good and its commit comes back
(verified against the trust file), a session can't see another slot's folder
while the probe runs, and the next session in a slot finds no leftovers (the old
folder is in the Trash and `sessions.log` names the slot). On a real machine
they run, as the administrator, and each starts one or two short sessions.

## For the reviewer (D5 asks for an independent review)

Worth a look first:

- `agents_git`, `agents_cat` and every `as_user agents`: absolute paths, `env -i`,
  and the git the sitting was given; nothing from the agents' own bin folder.
- `save_agents_state` and `restore_agents_state`: root's copies are read as the
  agents account, so a link the agents plant can't make root read something else.
- `build-in-sandbox.sh`: the fetch phase has the network for the toolchain and
  `cargo fetch --locked`, minus the private address ranges and this machine's
  own global addresses; the compile phase has no network and no `/run`; both
  hide the credential stores and agent-sign's and the launcher's state; the
  compile re-checks the toolchain hash and every crate against `Cargo.lock` and
  extracts the crates itself (it takes no extracted source from the fetch).
  Its limits are in the file's header. Nothing could test here
  that systemd enforces `IPAddressDeny`, `IPAddressAllow` or
  `TemporaryFileSystem`, or that DNS works through the bound-back
  `/run/systemd/resolve`: that needs root and systemd, so the first real run is
  the check.
- `forget_sudo` (lib.sh) and every place that runs an installed program: `sudo -k`
  comes first, with no sudo use between (a test reads the script for it).
- `verify_source`: the bundle is checked by git in an empty repository with its
  config isolated; nothing from the source runs outside the sandbox.
- `check-binary-clean.sh` is the sitting's own copy, run as Taylor (it only
  greps), never a script from the source.
- `save_agents_state` / `restore_agents_state`: nothing the agents write is a
  name, path or mode in the manifest; undo reads the whole manifest first and
  changes nothing unless every line is exactly what the sitting writes. Undo also
  says it overwrites the agents' later changes. The manifest is read on file
  descriptor 3 (a `sudo` that reads its standard input can't eat it), and after
  restoring, `verify_restored_state` compares every entry with its saved copy.
  The agents' real `agent-signd.service` file is the `user-unit` label
  (`save_and_remove_agents_unit_file`, M1). When that path is a link instead
  (systemd's mask fails over any link that doesn't point at `/dev/null`), the
  label has kind `link`: the target is read as the agents account and saved as
  data like a bin link's (refused if it holds a newline, a `|` or a control
  character, at the start and again before the service is stopped), the link is
  removed, then the unit is masked; undo puts the link back. A link to
  `/dev/null` is a mask already in place and is left alone. Root never follows
  the link.
- The two Rust hashes in `pins.env` came from `static.rust-lang.org`'s own
  `.sha256` files on 1 Nov 2026; compare them with the signed channel manifest.

## Known limits and backlog

- **The fetch phase may reach the DNS servers on every port of their addresses**
  (known limit, accepted for now, the suite PM's note). `IPAddressAllow=` is by
  address, so allowing the resolver (`127.0.0.53` on hetzner; Tailscale's
  `100.100.100.100` on the Pi) allows every port of it. DNS is enough for small
  data leaks; on the Pi it reaches Tailscale's service on any port; and a
  loopback service listening on all addresses answers on `127.0.0.53` on any
  port. Nothing in systemd narrows this to port 53 cheaply: `SocketBindAllow=`
  and `SocketBindDeny=` restrict only `bind(2)`, `RestrictNetworkInterfaces=` is
  by interface (`lo` also holds every other local service), and a port-level
  rule would be a hand-written BPF program (`IPEgressFilterPath=`). It is also
  said in `find_resolvers`' comments and in REVIEW.md.
- **Backlog idea, not built: no resolver in the fetch phase at all.** Before the
  fetch, resolve the hosts it needs (`static.rust-lang.org`, `index.crates.io`,
  `static.crates.io`) in the sitting itself; give the fetch an `/etc/hosts` with
  those answers and no resolver, and drop the `IPAddressAllow=` for DNS. That
  closes the limit above, at the cost of pinning addresses that a CDN may move
  between the lookup and the fetch (a rerun fixes it).
