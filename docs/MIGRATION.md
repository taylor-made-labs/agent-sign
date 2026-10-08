# Migrating from agent-sign to agent-commits

agent-sign is now agent-commits. Upgrading keeps your agent key, your leases
and your settings: it signs, attributes, and asks for approval as agent-sign
did, with the fixes listed in the README (lease terms fixed at approval,
clearer refusals, and a revoke that reports what it ended).

## What changes for an existing agent-sign user

Nothing needs to be done by hand. After the new binaries are installed, the
service moves its directory on its first start and everything that names the
old programs or paths keeps working.

| Thing | agent-sign | agent-commits | What keeps the old setup working |
|---|---|---|---|
| Service | `agent-signd` | `agent-commitsd` | `agent-signd` is a link to `agent-commitsd`, so the LaunchAgent (`com.agentsign.agent-signd`, which runs `~/.agent-sign/bin/agent-signd`) is unchanged. |
| Git wrapper | `agent-git`, installed as `git` | `agent-commits-git`, installed as `git` | `agent-git` is a link; `~/.agent-sign/bin` on `PATH` still finds `git`. |
| Signing program git calls | `agent-sign` | `agent-commits-ssh-sign` | `agent-sign` is a link to `agent-commits`, which signs with the same code. The wrapper now hands git `agent-commits-ssh-sign` (next to itself), falling back to `agent-sign` if that is all that is installed. Any `gpg.ssh.program` pointing at `agent-sign` keeps working. |
| Command line | `agent-sign leases`, `status`, `revoke`, `doctor` | `agent-commits leases`, `status`, `revoke`, `doctor` | `agent-sign ...` runs `agent-commits ...`. |
| State directory | `~/.agent-sign` | `~/.agent-commits` | On first start, `agent-commitsd` renames `~/.agent-sign` to `~/.agent-commits` in one step and leaves `~/.agent-sign` as a link to it. Nothing inside is rewritten. |
| Key | `~/.agent-sign/keys/agent_ed25519` | `~/.agent-commits/keys/agent_ed25519` | Same file, same bytes, same permissions. GitHub's registered signing key and the `allowed_signers` line stay valid. |
| Leases | `~/.agent-sign/leases.json` | `~/.agent-commits/leases.json` | Same file: same lease IDs, branches, and commit counts, honoured without a new approval. |
| Config | `~/.agent-sign/config.toml` | `~/.agent-commits/config.toml` | Same file and format. An absolute `~/.agent-sign/...` path in it still resolves (through the link, and also if the link is later removed). |
| Socket | `~/.agent-sign/daemon.sock` | `~/.agent-commits/daemon.sock` | Same socket through the link. The protocol is unchanged, so an old wrapper can talk to the new service and the reverse. |
| Environment variables | `AGENT_SIGN_*` | `AGENT_COMMITS_*` | Every `AGENT_SIGN_*` name is still read. If both are set, `AGENT_COMMITS_*` wins. `AGENT_EVENT_TOKEN` (wrapper to signing program) keeps its name. |
| Repository file | `.agent-sign.toml` | `.agent-commits.toml` | `.agent-sign.toml` is still read; `.agent-commits.toml` is read after it and wins where both set a value. |

### Every intentional difference

All are names or paths:

- Program names, as above, and what `--version` prints: `agent-commits 0.1.0` and
  `agent-commitsd 0.1.0`, also when run by an old name.
- Log and error prefixes (`[agent-commitsd]`, `[agent-commits-git]`, `[agent-commits-ssh-sign]`,
  `[agent-commits]`), help text, and the approval dialog's title ("agent-commits Security
  Lease"). The dialog's text, buttons, and default are unchanged.
- In `trailers` attribution mode only, the trailer reads
  `X-Agent-Signer: agent-commits/v0.1` instead of `agent-sign/v0.1`. (The Mac uses
  `split` mode, which adds no trailers.)
- New, and inert unless used: `AGENT_COMMITS_*` variable names, `.agent-commits.toml`, and
  `agent-commitsd migrate` (the move on its own, reporting what it did).
- `agent-commitsd` will not start if both `~/.agent-sign` and `~/.agent-commits` hold state
  (neither is a link to the other, and `~/.agent-commits` is not empty). It says so in
  its log. Choosing one silently could mean signing with a key GitHub does
  not know. See "If agent-commitsd refuses to start" below.

Unchanged: signatures (byte for byte, with the same key), author and
committer, lease rules and branch protection, the local rules (forbidden
paths, diff size), when approval is asked for, the fallback to the person's
own signer, the LaunchAgent, the shell profiles, and IDE settings.

## Switching the Mac over

Run these in a shell where `~/.agent-sign/bin` is on `PATH` (a login zsh).
The service is down for a few seconds between steps 2 and 5. Agent commits
in that window fail with "Unable to connect to the agent-commits service" (or
agent-sign's equivalent) and are not signed any other way; they can simply
be retried.

**0. Build** (from a checkout of the reviewed commit):

```sh
cargo build --release --locked
AGENT_COMMITS_BUILD="$PWD/target/release"   # or "$CARGO_TARGET_DIR/release" if that is set
UNIT="gui/$(id -u)/com.agentsign.agent-signd"
PLIST="$HOME/Library/LaunchAgents/com.agentsign.agent-signd.plist"
```

**1. Preflight.** Each line prints nothing when all is well:

```sh
{ [ -d "$HOME/.agent-sign" ] && [ ! -L "$HOME/.agent-sign" ]; } || echo "STOP: ~/.agent-sign is not an unmigrated directory"
[ ! -e "$HOME/.agent-commits" ] || echo "STOP: ~/.agent-commits already exists"
for n in agent-commitsd agent-commits agent-commits-ssh-sign agent-commits-git; do [ -x "$AGENT_COMMITS_BUILD/$n" ] || echo "STOP: $n not built"; done
"$HOME/.agent-sign/bin/agent-sign" leases   # note the leases listed
```

**2. Stop the service** (stopping it through launchd, since `KeepAlive`
would restart a killed one with the old binary):

```sh
launchctl bootout "$UNIT"
```

**3. Back up** the whole directory, key included, permissions kept:

```sh
BACKUP="$HOME/.agent-sign-backup-$(date +%Y%m%d-%H%M%S)"
cp -Rp "$HOME/.agent-sign" "$BACKUP"   # "daemon.sock is a socket (not copied)" is expected
echo "$BACKUP"
```

**4. Install the binaries.** Each is copied to a temporary name and renamed
into place, so no running binary is overwritten in place. The old names
become links:

```sh
BIN="$HOME/.agent-sign/bin"
for n in agent-commitsd agent-commits agent-commits-ssh-sign agent-commits-git; do
  cp "$AGENT_COMMITS_BUILD/$n" "$BIN/.$n.new" && mv -f "$BIN/.$n.new" "$BIN/$n"
done
cp "$AGENT_COMMITS_BUILD/agent-commits-git" "$BIN/.git.new" && mv -f "$BIN/.git.new" "$BIN/git"
ln -s agent-commitsd    "$BIN/.agent-signd.new" && mv -f "$BIN/.agent-signd.new" "$BIN/agent-signd"
ln -s agent-commits     "$BIN/.agent-sign.new"  && mv -f "$BIN/.agent-sign.new"  "$BIN/agent-sign"
ln -s agent-commits-git "$BIN/.agent-git.new"   && mv -f "$BIN/.agent-git.new"   "$BIN/agent-git"
```

**5. Start the service** with the same LaunchAgent. It now runs `agent-commitsd`
(through the `agent-signd` link), which moves `~/.agent-sign` to `~/.agent-commits`:

```sh
launchctl bootstrap "gui/$(id -u)" "$PLIST"
```

**6. Verify:**

```sh
sleep 2
ls -ld "$HOME/.agent-sign" "$HOME/.agent-commits"   # ~/.agent-sign -> /Users/<you>/.agent-commits, and a 0700 directory
tail -n 3 /tmp/agent-signd.stderr.log      # "[agent-commitsd] moved .../.agent-sign to .../.agent-commits and left a link at the old path"
"$HOME/.agent-commits/bin/agent-commits" --version           # agent-commits 0.1.0
"$HOME/.agent-commits/bin/agent-commits" status              # "active and healthy", and the same leases as in step 1
cmp "$BACKUP/keys/agent_ed25519" "$HOME/.agent-commits/keys/agent_ed25519" && echo "key unchanged"
cmp "$BACKUP/config.toml" "$HOME/.agent-commits/config.toml" && echo "config unchanged"
python3 - "$BACKUP/leases.json" "$HOME/.agent-commits/leases.json" <<'PY'
import json, sys
a, b = (json.load(open(p)) for p in sys.argv[1:])
key = lambda d: {r: (l["id"], l["branch"], l["mode"], l["scope"]) for r, l in d.items()}
print("leases unchanged" if key(a) == key(b) else "LEASES DIFFER")
PY
"$HOME/.agent-commits/bin/agent-commits" doctor
```

(The lease check compares lease IDs, branches, modes, and scopes, not commit
counts, which agents may already have raised since the start.)

**7. End-to-end check:** a signed agent commit in a scratch repository. A
new repository has no lease, so expect **one approval dialog** ("agent-commits
Security Lease"). `AGENT_COMMITS_FORCE=1` makes the wrapper treat the commit as an
agent's even when run from a terminal; `< /dev/null` keeps it
non-interactive.

```sh
CHECK=$(mktemp -d)/agent-commits-switch-check && mkdir -p "$CHECK" && cd "$CHECK"
git init -q -b agent-commits/switch-check && echo ok > check.txt && git add check.txt
AGENT_COMMITS_FORCE=1 git commit -q -m "chore: check agent-commits signing after the switch" < /dev/null
git verify-commit HEAD && git log -1 --format='%an <%ae> | %cn <%ce> | sig %G?'
"$HOME/.agent-commits/bin/agent-commits" revoke "$(pwd -P)" && cd && rm -rf "$(dirname "$CHECK")"
```

Expect `Good "git" signature for <the principal in allowed_signers>`, then
`Agent <agent@local.internal> | <you> | sig G`. To avoid the dialog, make the
check commit in a repository and branch that already has a lease instead.

When satisfied, delete the backup: it holds a copy of the agent's private key.

## Rollback

Puts the agent-sign binaries and the `~/.agent-sign` layout back, keeping the
current key and leases (including any granted since the switch; the file
format is the same):

```sh
launchctl bootout "$UNIT"
[ -L "$HOME/.agent-sign" ] && rm "$HOME/.agent-sign" && mv "$HOME/.agent-commits" "$HOME/.agent-sign"
BIN="$HOME/.agent-sign/bin"
for n in agent-signd agent-sign agent-git git; do
  cp "$BACKUP/bin/$n" "$BIN/.$n.old" && mv -f "$BIN/.$n.old" "$BIN/$n"
done
rm -f "$BIN/agent-commitsd" "$BIN/agent-commits" "$BIN/agent-commits-ssh-sign" "$BIN/agent-commits-git"
launchctl bootstrap "gui/$(id -u)" "$PLIST"
sleep 2
"$HOME/.agent-sign/bin/agent-sign" --version   # agent-sign 0.1.0
"$HOME/.agent-sign/bin/agent-sign" status
```

(`$UNIT`, `$PLIST`, and `$BACKUP` are the values from the switch; set them
again in a new shell.) If the state itself is in doubt, restore the backup
instead of keeping the current state: after `launchctl bootout`, move the
current directory aside (`mv ~/.agent-commits ~/.agent-commits-after-switch`, and remove the
`~/.agent-sign` link), then `cp -Rp "$BACKUP" "$HOME/.agent-sign"`, restore the
binaries as above, and `launchctl bootstrap`. Leases granted after the backup
are then lost and will be asked for again.

## If agent-commitsd refuses to start

`/tmp/agent-signd.stderr.log` says "Refusing to start: both ... exist". Both
directories hold state and agent-commits will not guess which key is the right one.
Keep the directory whose `keys/agent_ed25519.pub` matches the key registered
on GitHub and in `allowed_signers`, move the other aside (not delete), and
start the service again. `agent-commitsd migrate` performs and reports the move
without starting the service.

## Later, not needed now

These finish the switch to agent-commits' own names. Each is independent, and none is
required for the above to keep working:

- LaunchAgent: `launchctl bootout "$UNIT"`, remove its plist, install
  `scripts/agent-commitsd.plist` as `~/Library/LaunchAgents/com.agentcommits.agent-commitsd.plist`, and
  `launchctl bootstrap` it (logs move to `/tmp/agent-commitsd.*.log`). On Linux,
  `scripts/agent-commitsd.service` replaces `agent-signd.service`.
- `PATH`: change the `# >>> agent-sign >>>` blocks in `~/.zshrc` and
  `~/.zprofile` (and IDE terminal settings) from `$HOME/.agent-sign/bin` to
  `$HOME/.agent-commits/bin`.
- Then, once nothing names them, remove the old-name links in `~/.agent-commits/bin`
  and the `~/.agent-sign` link.
- `.github/workflows/release.yml` still packages the old binary names. The
  wrapper's forbidden-path rule blocks agent commits to CI workflows, so the
  person makes that change: copy `agent-commitsd`, `agent-commits`, `agent-commits-ssh-sign`, and
  `agent-commits-git` (and `agent-commits-git` as `git`), and add the three old-name links.

## How this was checked

- `cargo test`: every end-to-end scenario runs with the new names and again
  through old-name links with `AGENT_SIGN_*` variables and `.agent-sign.toml`;
  `tests/test_migration.rs` moves synthetic agent-sign homes and compares key,
  leases, config, and permissions; `tests/test_signature_equivalence.rs`
  checks that `agent-commits-ssh-sign`, `agent-commits`, and `agent-sign` reproduce a signature
  made by the pre-rename binaries byte for byte; `tests/test_switch_over.rs`
  rehearses steps 4 to 6 with no auto-approve and stand-in dialogs that deny.
- A dry run of this page's commands in a temporary home: the pre-rename
  binaries installed as the installer does, a lease approved and a commit made
  with them, then steps 1 to 7, the rollback, and a second switch, with
  launchd simulated by running the plist's exact command. Every commit
  verified with the same `allowed_signers` line, and no approval was asked for
  except for new repositories.
