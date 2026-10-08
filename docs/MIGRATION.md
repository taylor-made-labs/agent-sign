# Upgrading from agent-sign

agent-sign is now agent-commits. Upgrading keeps your agent key, your leases
and your settings. It signs and asks for approval as agent-sign did, with
the changes listed in the README: lease terms fixed at approval, a choice of
what one approval covers, agent names on commits, clearer refusals, and a
`revoke` that reports what it ended.

## How to upgrade

Run the new installer, as for a new install (see [INSTALL.md](INSTALL.md)).
It finds your agent-sign install and:

1. stops agent-sign's service
2. moves `~/.agent-sign` to `~/.agent-commits` in one step, and leaves
   `~/.agent-sign` as a link to it, so anything that still names the old
   path keeps working (if `~/.agent-sign` was already a link to a folder you
   keep elsewhere, `~/.agent-commits` becomes a link to the same folder, and
   nothing is moved)
3. installs the new programs, with agent-sign's names as links
4. replaces agent-sign's service (`com.agentsign.agent-signd` on macOS,
   `agent-signd.service` on Linux) with agent-commits' own
   (`com.agentcommits.agent-commitsd`, `agent-commitsd.service`)
5. replaces the `# >>> agent-sign >>>` `PATH` block in your shell profiles,
   and the editor terminal settings, with ones naming `~/.agent-commits/bin`

Open a new terminal afterwards, and run `agent-commits doctor`.

If you only replace the programs, without the installer, that works too:
the service moves `~/.agent-sign` to `~/.agent-commits` on its first start
and leaves the link, and the old names, service and `PATH` keep working
through it.

## What carries over

| Thing | agent-sign | agent-commits | |
|---|---|---|---|
| Key | `~/.agent-sign/keys/agent_ed25519` | `~/.agent-commits/keys/agent_ed25519` | Same file, same bytes. GitHub's registered signing key and your `allowed_signers` line stay valid. |
| Leases | `~/.agent-sign/leases.json` | `~/.agent-commits/leases.json` | Same leases, honoured without a new approval. They load as "this repository only". |
| Config | `~/.agent-sign/config.toml` | `~/.agent-commits/config.toml` | Same file and format. An absolute `~/.agent-sign/...` path in it still resolves. |
| Programs | `agent-signd`, `agent-git`, `agent-sign` | `agent-commitsd`, `agent-commits-git`, `agent-commits` (and `agent-commits-ssh-sign`) | The old names are links to the new programs. `agent-sign leases` runs `agent-commits leases`, and a `gpg.ssh.program` pointing at `agent-sign` keeps working. |
| Environment variables | `AGENT_SIGN_*` | `AGENT_COMMITS_*` | Every `AGENT_SIGN_*` name is still read; if both are set, `AGENT_COMMITS_*` wins. |
| Repository file | `.agent-sign.toml` | `.agent-commits.toml` | `.agent-sign.toml` is still read; `.agent-commits.toml` is read after it and wins. |
| Socket protocol | | | Unchanged, so an old wrapper can talk to the new service and the reverse. |

Signatures are the same byte for byte with the same key
(`tests/test_signature_equivalence.rs`).

## If agent-commitsd refuses to start

Its log (`/tmp/agent-commitsd.stderr.log` on macOS, `journalctl --user -u
agent-commitsd` on Linux) says "Refusing to start: both ... exist": both
`~/.agent-sign` and `~/.agent-commits` hold state, and agent-commits won't
guess which key is the right one. The installer stops for the same reason.
Keep the directory whose `keys/agent_ed25519.pub` matches the key registered
on GitHub and in `allowed_signers`, move the other aside (don't delete it),
and run the installer or start the service again. `agent-commitsd migrate`
does the move on its own and reports what it did.

## How this is checked

- Every end-to-end scenario in `tests/test_e2e_git_commit.rs` runs twice:
  with the new names, and through old-name links with `AGENT_SIGN_*`
  variables and `.agent-sign.toml`.
- `tests/test_migration.rs` moves synthetic agent-sign homes and compares
  the key, leases, config and permissions before and after.
- `tests/test_switch_over.rs` switches an agent-sign install with an
  approved lease to the new programs, and checks that agent commits keep
  signing with the same key and no new approval.
