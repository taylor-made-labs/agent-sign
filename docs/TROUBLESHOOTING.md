# Troubleshooting

## Start with `agent-sign doctor`

```sh
agent-sign doctor
```

It checks: your own `gpg.format` (shown for information; agent commits don't
need it), your own signer (`fallback_program`), the agent key files, git's
`allowed_signers` file, that the service answers on its socket, whether the
agent key is on your GitHub account (if `gh` is installed), and the
permissions and contents of `~/.agent-sign` and `leases.json`. Each failure comes
with a hint.

## The service

agent-sign's service is `agent-signd`:

| | Restart it | Its log |
|---|---|---|
| macOS | `launchctl kickstart -k gui/$(id -u)/com.agentsign.agent-signd` | `/tmp/agent-signd.stderr.log` |
| Linux | `systemctl --user restart agent-signd` | `journalctl --user -u agent-signd` (some systems keep no user journal; then run `agent-signd` by hand in a terminal to see its messages) |

`agent-signd` reads `~/.agent-sign/config.toml` only when it starts: **restart it after
changing the config.** `agent-sign status` says whether it's running.

On a Linux machine you log out of (a server), a user service stops when you
log out, unless lingering is on: `loginctl enable-linger "$USER"`.

## An agent commit was refused

The wrapper prints why, starting `[agent-git]`.

| Message | Why | What to do |
|---|---|---|
| `Unable to connect to the agent-sign service` | `agent-signd` isn't running. | Restart it (above), then `agent-sign status`. |
| `No signing lease: Branch 'main' is protected` | Agents never commit on `main` or `master` (`block_branches`). | Have the agent work on another branch. |
| `No signing lease: the person denied the signing lease` | You pressed Deny. | Commit again to be asked again. |
| You're asked again when the agent changes branch | The lease covers only the branch it was approved on (`allow_branch_switching = false`, or leases approved that way). | Approve, or set `allow_branch_switching = true` for future leases. |
| `No signing lease: agent-sign couldn't ask you to approve a lease` | The service couldn't confirm it was you: no desktop session on macOS, or Linux (which has no approval dialog), or a server, container or SSH session with no terminal. | See "Linux has no approval dialog" and "Machines with no screen" below. |
| `No signing lease: the signing lease was not approved: agent-sign could not confirm it was you (...)` | You picked a coverage but the Touch ID / password check was cancelled, failed, or timed out (five minutes). | Commit again and authenticate. If the Mac offers no check (no password set, no desktop session), the reason says so. |
| `No signing lease: agent-sign is not asking again for N more seconds` | A recent approval prompt was refused (Deny, or Touch ID cancelled, failed or timed out), so new ones are held back, doubling with each refusal in a row. | Wait, or set `refusal_backoff` (default `"60s"`, `"none"` turns it off) and restart the service. |
| `No signing lease: agent-sign already has 4 approval requests waiting` | Four requests are already waiting for an answer. | Answer them, or `agent-sign deny --all`. |
| `No signing lease: ... isn't an existing git working tree` or `... control or invisible characters` | The repository the wrapper named doesn't exist or isn't a git working tree, or its path or the branch name has characters that could disguise the prompt. | Run git from inside a real repository; rename the branch or folder. |
| `Token issuance failed: Rate limit exceeded` | More than `max_commits_per_minute` agent commits in a minute in this repository. | Wait a minute, or raise the limit in `~/.agent-sign/config.toml` and restart the service. |
| `Security Policy Violation: ... forbidden path` | The commit changes a path in `forbidden_paths` (CI workflows, key files). | Commit that change yourself from your terminal. |
| `Agent commit changes N lines, more than the limit you set` | You set `max_diff_lines`, and the commit changes more lines than that. (There's no limit by default.) | Split the commit, or commit with `AGENT_SIGN_ALLOW_LARGE_DIFF=1`. |

## Your fingerprint (or 1Password) is asked for on every agent commit

The agent isn't running agent-sign's wrapper as `git`. In the agent's shell:

```sh
command -v git     # should end in .agent-sign/bin/git
```

If it doesn't, start the agent from a new terminal (the installer changed
your shell profiles), or run `source ~/.zshrc` / `source ~/.bashrc` first.

Merges, rebases, cherry-picks, reverts and pulls aren't intercepted, so they
use your own signing and still ask for your fingerprint.

## 1Password: `op-ssh-sign` can't connect

Your own commits go to 1Password's `op-ssh-sign`. In 1Password, Settings,
Developer, turn on "Use the SSH agent".

## Hardware keys (YubiKey, FIDO2)

Agent commits are signed with the agent's file key, so they need no touch.
Your own commits still use your key and still need a touch. Your hardware
key isn't used to approve leases: that's the dialog, then Touch ID or your
login password on the Mac.

## Linux has no approval dialog

Linux can't approve leases yet, so the service refuses every request there. agent-sign
no longer shows a `zenity` or `kdialog` dialog or a terminal prompt: Linux has
no platform authenticator in agent-sign, and a dialog any program can click, or
a terminal an agent can drive, would let an agent approve its own lease. To
grant leases anyway see the next section. Approving from another device, such
as a passkey on your phone, is planned, not built.

## Machines with no screen (servers, containers, CI)

With no screen and no terminal (or on Linux, which can't approve leases),
agent-sign can't ask you, so it refuses leases.
To grant every lease without asking, set in `~/.agent-sign/config.toml`:

```toml
[security]
auto_approve = true
```

and restart the service. (Setting it in a repository's `.agent-sign.toml` has no
effect: the service reads only your own config.) Or set `AGENT_SIGN_AUTO_APPROVE=1`
in the service's own environment (`systemctl --user edit agent-signd`, then
`Environment=AGENT_SIGN_AUTO_APPROVE=1`), or run `agent-signd --auto-approve` yourself.
Use it only where every process that can reach the service is trusted:
every agent on the machine then gets leases without you seeing them.

## Adjusting the local rules for one repository

A repository can loosen or tighten the wrapper's local rules in a
`.agent-sign.toml` at its top level:

```toml
[security]
forbidden_paths = ["*.pem", "*.key"]   # allow agent commits to CI workflows here
max_diff_lines = 5000
```

An agent can edit that file too, so these rules catch mistakes, not an agent
set on getting past them. Lease, branch and approval settings can't be
changed from a repository.

## `agent-sign revoke` says there's no lease

`agent-sign revoke` takes the repository's full path, as `agent-sign leases` shows it,
or a path inside the repository (such as `.`). `agent-sign revoke --all` ends every
lease.

## Approval dialogs keep appearing

- **Many at once, from tests:** a test suite that makes throwaway commits
  should turn signing off for them (`git config commit.gpgsign false` in the
  test repository, or `git -c commit.gpgsign=false commit ...`). Commits
  that do never ask for approval; they go to plain git, unsigned.
- **To see and close what's waiting:** `agent-sign pending` lists the open
  requests (one per repository and branch, however many commits are
  waiting on it), and `agent-sign deny --all` (or `agent-sign deny <id>`)
  answers no and closes their dialogs.
- **Left open after a program stopped:** a dialog (or the Touch ID prompt)
  closes by itself within about a second once every commit waiting on it
  has gone.
