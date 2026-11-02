# Troubleshooting

## Start with `agent-sign doctor`

```sh
agent-sign doctor
```

It checks: your own `gpg.format` (shown for information; agent commits don't
need it), your own signer (`fallback_program`), whether your own signing
goes through agent-sign (`gpg.ssh.program` set to `agent-ssh-sign`), the
agents' certificate authorities the service has recorded, git's
`allowed_signers` file and whether it trusts every one of them, whether
git on this machine reads an SSH certificate's times correctly (a warning
there has its own row in the table under "An agent commit was refused"),
that the service answers on its socket, and the permissions and contents of
`~/.agent-sign` and `leases.json`. It points out a private key an earlier
version stored unprotected (the agents' authority key, or the old shared
agent key's private half; running the installer again deletes them, after
asking). Each failure comes with a hint.

## The service won't start

The service reads `~/.agent-sign/config.toml` as a whole when it starts, and
stops rather than fall back to the defaults when it can't: a misspelt
`approval = "device_owner"` would otherwise quietly mean no approval. Its
log says which file and which key:

| Message | What to do |
|---|---|
| `... config.toml has a setting agent-sign can't read` | Fix the value it names (`approval` takes `"none"` or `"device-owner"`). |
| "... config.toml has an unknown key \`approvl\` in [security]" (or "an unknown table", or "the key \`approval\` outside any table (it belongs under [security])") | Fix the spelling, or move the key under the table it names. |
| `... config.toml exists but can't be read (...)` | Fix its permissions (`chmod 600 ~/.agent-sign/config.toml`), or move it aside to use the defaults. |
| `... config.toml is a link to a file that doesn't exist` | Point the link at your config, or remove it. |
| `... keys/agents_ca_ed25519 holds an agents' certificate authority private key, stored unprotected by an earlier development build` | Run the installer again (it deletes the file after asking), or delete it yourself. The authority now lives only in the service's memory. |
| `couldn't keep other programs from reading agent-signd's memory (PR_SET_DUMPABLE 0): ...; not starting, so no key is made` (Linux) | The service couldn't make its memory unreadable to other programs of your account, so it stopped before making any key. The text after the colon is the system's reason. On Linux agent-sign doesn't run without this protection, so fix what that reason names. |
| `[identity] machine = "Build-1" isn't a valid machine name: use 1 to 63 lowercase letters and digits, in words joined by single '-' ...` | Fix the name (`build-1`), or leave `machine` out. An empty `machine = ""` is an error too, not "no machine". Then restart the service. Read [Naming the machine](../README.md#naming-the-machine) first if this machine's agents have already committed. |
| `[identity] allowed_agents lists "My Bot", which isn't an agent name: use the name's slug ...` | List the name's slug instead: lowercase letters and digits in words joined by single `-` ("My Bot" is `my-bot`). |
| `[identity] allowed_agents lists "sam", which is the person's name (...): agent-sign never certifies an agent under a person's name. Remove it from allowed_agents` (or "which is a reserved name ...", or "which is a person's name ([identity] people lists ...)") | Remove that entry. A person's name, as a whole or any word of it (as a slug), is never an agent's: `root`, `admin` and `administrator`; your name and the part of your email before the `@` (from `[human]` in `config.toml`, or git's `user.name` and `user.email` when `[human]` doesn't set them); and every name in `[identity] people`. If an agent's name happens to match, start it under a different `AGENT_SIGN_AGENT_NAME`. See [Allowed agent names](../README.md#allowed-agent-names). |
| `[identity] people lists "...", which isn't a person's name agent-sign can use: ...` | Each entry of `people` needs 1 to 64 characters, at least one letter a-z or digit (fullwidth letters count: names are compared after Unicode NFKC normalisation), and no quotes, backslashes or control characters. Fix or remove it. |
| `[agent-signd] refusing to start: reading the machine's account database failed ...` (or "... listed ... accounts and no root account, so the list isn't whole") | The service reads the people's accounts on the machine when it starts, so that no agent is certified under a person's name, and the read failed. It won't run without them. | Check that the account database can be read (`getent passwd` on Linux; on macOS, `dscl . -list /Users`), fix what that shows (a name service that is down, say), then start the service again. |

Then restart the service. When it starts, its log says the approval mode in
effect (`approval = "none"` or `approval = "device-owner"`). Keys that only
an older installer wrote, such as `auto_revoke_on_branch_delete`, are
accepted and ignored.

## The service

agent-sign's service is `agent-signd`:

| | Restart it | Its log |
|---|---|---|
| macOS | `launchctl kickstart -k gui/$(id -u)/com.agentsign.agent-signd` | `/tmp/agent-signd.stderr.log` |
| Linux | `systemctl --user restart agent-signd` | `journalctl --user -u agent-signd` (some systems keep no user journal; then run `agent-signd` by hand in a terminal to see its messages) |

`agent-signd` reads `~/.agent-sign/config.toml` only when it starts: **restart it after
changing the config.** `agent-sign status` says whether it's running.

On a Linux machine you log out of (a server), a user service stops when you
log out, unless lingering is on: `loginctl enable-linger "$USER"`. If
`systemctl --user` says it can't connect to the bus over a non-interactive
`ssh` command, set `XDG_RUNTIME_DIR=/run/user/$(id -u)` first (see
[Servers and non-interactive installs](INSTALL.md#servers-and-non-interactive-installs)).

## An agent commit was refused

The wrapper prints why, starting `[agent-git]`.

| Message | Why | What to do |
|---|---|---|
| `Unable to connect to the agent-sign service` | `agent-signd` isn't running. | Restart it (above), then `agent-sign status`. |
| `No signing lease: Branch 'main' is protected` | Agents never commit on `main` or `master` (`block_branches`). | Have the agent work on another branch. |
| `agent-sign won't sign commits this git command makes for <principal>: ...`, then `gpg failed to sign the data` | An agent's merge, rebase, cherry-pick, revert, am, pull or alias needed to make a commit, and the service refused a token for it (a protected branch, say) or didn't answer. No commit is made. | Fix what the message names (work on another branch, or start the service). |
| ``Token issuance failed: agent identity refused: `my-bot-2` is not an allowed agent name, so agent-sign won't certify it. To allow it, add "my-bot-2" to allowed_agents under [identity] in ~/.agent-sign/config.toml (a person's own name is never allowed)`` | The agent's name (from `AGENT_SIGN_AGENT_NAME`) isn't built in, isn't one of the widely used agents, and isn't in `[identity] allowed_agents`. | Add the slug it names to `allowed_agents`, then restart the service (it reads the list only when it starts). See [Allowed agent names](../README.md#allowed-agent-names). |
| ``Token issuance failed: agent identity refused: `taylor` is the login name of the account taylor on this machine, and agent-sign never certifies an agent under a person's name, whatever allowed_agents says ...`` (or "is a person's name (the account ... on this machine is ...)", "is a reserved name", or "is a person's name ([identity] people lists ...)") | The agent's name is a person's: the login name or a word of the full name of a person's account on this machine (an account with a login shell and a user id of 1000 or more on Linux, 501 or more on macOS, other than the one agent-sign runs as), or one of the names in the previous section. The service reads the accounts when it starts. Listing the name in `allowed_agents` doesn't change this. | Start the agent under a different `AGENT_SIGN_AGENT_NAME`, and take the name out of `allowed_agents`. The service's log says, when it starts, whose accounts it read ("never an agent's name: ..."). |
| `agent identity refused: claude-code.1a2b3c4d@agents.local is not in this machine's agents' domain @build-1.agents.local (set by [identity] machine in agent-sign's config.toml); the git wrapper and the service must read the same machine setting` | The wrapper and the service disagree about the machine name: usually `[identity] machine` was set, changed or removed after the service started (the wrapper reads it at every commit, the service only when it starts). | Restart the service. |
| `agent-sign's [identity] settings (the machine name) can't be used: ...` | The wrapper couldn't read `[identity]` in `~/.agent-sign/config.toml` (an invalid machine name, say), so it refused the agent's commit rather than sign it under another machine's domain. | Fix what the message names. Your own commits in a terminal aren't affected. |
| `agent identity refused: the display name "T\u{430}ylor" has characters that aren't printable ASCII ...` | The agent's display name (from `AGENT_SIGN_AGENT_NAME`, usually) has a character that isn't printable ASCII; the message shows each one as `\u{...}`. The display name becomes the author name on the agent's commits, and a letter from another alphabet can look exactly like a person's name, so agent-sign refuses it and the commit gets no signature. | Set `AGENT_SIGN_AGENT_NAME` to a name of ASCII letters, digits, spaces and punctuation ("My Bot 2"), and list its slug in `allowed_agents` if it isn't built in. |
| `agent identity refused: ...` (other reasons) | The identity the wrapper sent isn't one agent-sign makes (a tool name other than lowercase words joined by single `-`, a session part other than 8 hex digits or `nosession`, a display name with `<` or `>`). | Check `AGENT_SIGN_AGENT_NAME`: ASCII letters, digits and spaces work. If a hand-written client sent it, use the shape the wrapper makes. |
| `Signing rejected by the agent-sign service: the commit's committer date (...) is outside its signing certificate's validity (... to ...), so it wasn't signed: commit with the current date`, then `gpg failed to sign the data` | The commit's committer date lies outside the 12-hour certificate's window (from 5 minutes before it was issued). Usually `GIT_COMMITTER_DATE` is set in the agent's environment, or a rebase used `--committer-date-is-author-date`. git checks a certificate at the commit's own date, so such a commit would never verify; agent-sign refuses to sign it at all. | Commit with the current date: unset `GIT_COMMITTER_DATE`, and don't keep old committer dates in a rebase. (`--date` changes only the author date, which is fine.) |
| `Git here misreads certificate times in this clock zone` (`agent-sign doctor` warning), or git's `%G?` / `git verify-commit` disagreeing with `agent-sign verify` about a commit made just now | git gives `ssh-keygen` the commit's date as local time with no zone, and OpenSSH 10.0p2 (Debian 13, the Raspberry Pi) reads that as UTC whenever the clock zone isn't UTC, so git's own check of a certificate is shifted by the zone's offset. `agent-sign verify` passes UTC with a `Z` and is unaffected; signing is unaffected too. | Anything that decides (a merge gate, a server-side check, a hook) must use `agent-sign verify`, never git's verdict. To make git's own check read right, run git with `TZ=UTC`, or install a newer OpenSSH (10.2p1 reads it correctly). |
| `Security Policy Violation: branch '...' is protected (block_branches)` | The repository's `.agent-sign.toml` adds that branch to `block_branches`. | Have the agent work on another branch. |
| `Signing rejected by the agent-sign service: this token signs only in ... on branch '...', but git is writing ...` | An agent's git run moved somewhere its token doesn't cover: `git rebase <other> main` from another branch, a `cd` into another repository inside an alias or `rebase --exec`, or a hook that commits elsewhere. Nothing was signed there. | Run the command from the branch and repository it writes (`git checkout main && git rebase ...` isn't for agents: they don't commit on protected branches). |
| `this git wrapper is older than the agent-sign service` or `the signing program ... is older than the service` | An agent-sign program from before the identity review is still on `PATH`, or in git's `gpg.ssh.program`. | Run the installer again, and open a new terminal. |
| `No signing lease: the person denied the signing lease` | Someone ran `agent-sign deny` while the prompt was open. | Commit again to be asked again. |
| With `approval = "device-owner"`: you're asked again when the agent changes branch | By default a lease covers only the branch it was approved on, in the repository it was asked from (`allow_branch_switching = false`). | Approve, or set `allow_branch_switching = true` (and restart the service) so future leases cover the repository's other unprotected branches. |
| `No signing lease: agent-sign couldn't ask you to approve a lease` | The service couldn't confirm it was you: no desktop session on macOS, or Linux (which has no way to approve), or a server, container or SSH session with no terminal. | See "Linux has no way to approve" and "Machines with no screen" below. |
| `No signing lease: the signing lease was not approved: agent-sign could not confirm it was you (...)` | The Touch ID / password prompt was cancelled, failed, or timed out (five minutes). | Commit again and authenticate. If the Mac offers no check (no password set, no desktop session), the reason says so. |
| `No signing lease: agent-sign is not asking again for N more seconds` | A recent approval prompt was refused (Touch ID cancelled, failed or timed out), so new ones are held back, doubling with each refusal in a row. | Wait, or set `refusal_backoff` (default `"60s"`, `"none"` turns it off) and restart the service. |
| `No signing lease: ... no approval was asked for` about a branch ("uses characters other than letters, digits and / - _ ." or "isn't the branch checked out") | The branch goes into the approval prompt, so only plain branch names (letters, digits, `/ - _ .`) that are the repository's current branch are asked about. | Rename the branch (no spaces, `#`, `@`, accents), or run the commit from the branch's own checkout. |
| `No signing lease: agent-sign already has 4 approval requests waiting` | Four requests are already waiting for an answer. | Answer them, or `agent-sign deny --all`. |
| `No signing lease: ... isn't an existing git working tree` or `... control or invisible characters` | The repository the wrapper named doesn't exist or isn't a git working tree, or its path or the branch name has characters that could disguise the prompt. | Run git from inside a real repository; rename the branch or folder. |
| `agent-sign: this commit is unsigned because no launcher started this agent (...)` | The agent that made the commit is a process with an agent's marks (or `AGENT_SIGN_AGENT_NAME`) that `agent-sign launch` did not start. Since the switch (1 Nov 2026) agent-sign signs only for an agent a launcher started, or an approval names; any other agent's commit goes through unsigned, under the agent's own names. It can live on a branch; merging to main will need an attested signature. | Start the agent with `agent-sign launch --agent <name> -- <program>` to have its commits signed as a session. |
| `no token for <principal>: agent-sign signs an agent's commit only for a session a launcher started` | A program asked the service for an identity token without being a launched session. The git wrapper no longer asks; a hand-made request or an old wrapper does. | Use the current wrapper, or launch the agent. |
| `Token issuance failed: Rate limit exceeded`, or `Signing rejected ...: Rate limit exceeded` during a merge or rebase | More than `max_commits_per_minute` agent signatures in a minute in this repository (every commit a rebase replays counts). | Wait a minute, or raise the limit in `~/.agent-sign/config.toml` and restart the service. |
| `Security Policy Violation: ... forbidden path` | The commit changes a path in `forbidden_paths` (CI workflows, key files). | Commit that change yourself from your terminal. |
| `Agent commit changes N lines, more than the limit you set` | You set `max_diff_lines`, and the commit changes more lines than that. (There's no limit by default.) | Split the commit, or commit with `AGENT_SIGN_ALLOW_LARGE_DIFF=1`. |

## Servers in system mode

These apply only where `/etc/agent-sign/system.toml` exists (see
[Servers: system mode](INSTALL.md#servers-system-mode)). Start with
`agent-sign doctor`; it prints `ping: ok` when the service answers and
`authority: OpenBao CA matches the trust file` when the certificate authority
OpenBao reports is the one in root's trust file.

| What you see | What it means and what to do |
|---|---|
| `agent-sign launch` says the launcher didn't answer | The launcher isn't running. `systemctl status agent-launchd.socket agent-launchd.service`; its log is `journalctl -u agent-launchd`. The sitting script starts both. |
| `launch` says this machine is in system mode and nothing was run | One-account launch is refused once `system.toml` exists. Use the launcher; to go back to one account, run the sitting with `--undo`. |
| `launch` is refused for your account | Only accounts in `[launcher] people_accounts` may launch by asking. The agents' account may not, on purpose. |
| `launch` says every slot is in use | All N slots hold a session, or are still ending. Wait, or run the sitting again with a larger `--slots`. |
| `launch` refuses the agent name | Use a built-in name (`claude-code`, `codex`, `gemini-cli`), or list it under `[identity] allowed_agents` in `system.toml`. A person's name is never allowed. |
| `authority:` line shows a mismatch | OpenBao's certificate authority is not the one in `/etc/agent-sign/allowed_signers`. The service signs nothing until they match. Don't edit the trust file; find out why the authority changed, then run the sitting again. |
| `ping` fails, or the service log says it can't log in to OpenBao | `journalctl -u agent-signd`. Check OpenBao is up and unsealed, the stored login is in `/etc/credstore.encrypted/`, and `[authority]` in `system.toml` is right. Plain-path questions still work with the login missing; every signature is refused. |
| A commit shows unverified on the server | The agents' git must take its trust file from `/etc/gitconfig` (`git config --show-origin gpg.ssh.allowedSignersFile`). The sitting removes the agents' own setting. |
| A session's commits didn't come back | Look in `/var/lib/agent-launch/sessions.log` (root only) and the slot's `trash/`: a finished session's folder always goes to the Trash, never deleted. `agent-sign launch --collect <session>` fetches bundles for a session whose caller had gone. |
| A session ended with work "left" | The end check wants everything committed. Uncommitted or untracked files, stashes and merges in progress stay in the Trash folder, and are not returned. |
| `agent-signd` won't start as another account | In system mode it runs only as the account named in `[service] account` (`agent-sign`). Start it with `systemctl`, not by hand. |

## Your fingerprint (or 1Password) is asked for on every agent commit

The agent isn't running agent-sign's wrapper as `git`. In the agent's shell:

```sh
command -v git     # should end in .agent-sign/bin/git
```

If it doesn't, start the agent from a new terminal (the installer changed
your shell profiles), or run `source ~/.zshrc` / `source ~/.bashrc` first.

An agent's merges, rebases, cherry-picks, reverts and pulls are signed as
the agent (when it marks its commands, as Claude Code, Codex and Gemini CLI
do), or made unsigned (when nothing marks it): agent-sign keeps your own
signer out of them, so they never ask for your fingerprint. If one does, the
agent called the real git directly; see the README's limits.

## Agent commits show as unverified, or as yours

- **`git log --show-signature` says "No principal matched" or the
  signature can't be checked:** your allowed-signers file doesn't have the
  agents' trust line yet. Add it: `agent-sign trust-line >> "$(git config
  --global gpg.ssh.allowedSignersFile)"`.
- **Unverified on GitHub:** expected. GitHub doesn't check signatures made
  with SSH certificates, and the commits aren't yours to verify.
- **An agent's commit is unsigned and carries your name:** the agent
  didn't mark its commands, so agent-sign couldn't tell it from your own
  editor and left the commit to git. Start it with `AGENT_SIGN_AGENT_NAME`
  (and, if you like, `AGENT_SIGN_SESSION_ID`) set. (Before the identity
  review these were signed as "Agent <agent.unidentified@agents.local>".)
- **An agent's unsigned commit (`--no-gpg-sign`, or a repository with
  `commit.gpgsign = false`) carries a test fixture's name:** the repository
  sets its own `user.email`, which is kept. Without one, the agent's name
  and principal are used.
- **A repository's `.agent-sign.toml` printed "ignored ...":** a
  repository's file can only tighten the rules; see "Adjusting the local
  rules for one repository" below.
- **Old agent commits show as yours:** they were signed with the shared
  agent key of earlier versions, whose line in your allowed-signers file is
  under your email. The installer deletes the key's private half (it was
  stored unprotected), keeps its public half, and, while that line is still
  there, prints the exact commands to remove it and the key from your
  GitHub account; run them to stop old commits verifying as yours.
- **Agent commits from before you set (or changed) `[identity] machine`
  show "No principal matched":** expected. Once a machine is named, every
  trust line agent-sign writes covers only that machine's agents
  (`*@<machine>.agents.local`), so commits signed earlier under another
  domain, such as plain `@agents.local`, no longer verify under them. Name
  a machine before its service first starts (`install.sh --machine`) to
  avoid this; see [Naming the machine](../README.md#naming-the-machine).
- **Agent commits show as unverified after a restart:** each start of the
  service makes a new authority, and a start never changes what verifiers
  trust. Run `agent-sign trust install`: it records the running service's
  authority and rewrites agent-sign's block in your allowed-signers file
  (`agent-sign doctor` says when this is needed). If your file has no block
  (you added `agent-sign trust-line`'s line by hand), run the installer
  again to add one, or replace the line with everything
  `agent-sign trust-line` prints now.
- **"another agent-signd is already running for ...":** only one service
  runs per state folder (`~/.agent-sign`). Use the running one
  (`agent-sign status`), or stop it before starting another.
- **"agent-sign: no terminal and no agent mark, so this commit was made
  unsigned":** a commit with no terminal (your editor's commit button, a
  script) and no agent mark asked to be signed. agent-sign can't tell it
  from an agent's, so it neither signs it as you nor fails it: it's made
  unsigned, under git's own names. Commit in a terminal to sign it as
  yourself, or start an agent with `AGENT_SIGN_AGENT_NAME` to have its
  commits signed as it.

## 1Password: `op-ssh-sign` can't connect

Your own commits go to 1Password's `op-ssh-sign`. In 1Password, Settings,
Developer, turn on "Use the SSH agent".

## Hardware keys (YubiKey, FIDO2)

Agent commits are signed with each agent session's own key, held by the
service, so they need no touch. Your own commits still use your key and
still need a touch. Your hardware key isn't used to approve leases: with
`approval = "device-owner"`, that's Touch ID or your login password on the
Mac.

## Linux has no way to approve

With the default `approval = "none"` nothing needs approving. With
`approval = "device-owner"`, Linux can't approve leases yet, so the service
refuses every request there. agent-sign
no longer shows a `zenity` or `kdialog` dialog or a terminal prompt: Linux has
no platform authenticator in agent-sign, and a dialog any program can click, or
a terminal an agent can drive, would let an agent approve its own lease. To
grant leases anyway see the next section. Approving from another device, such
as a passkey on your phone, is planned, not built.

## Machines with no screen (servers, containers, CI)

With `approval = "device-owner"` and no screen and no terminal (or on Linux,
which can't approve leases), agent-sign can't ask you, so it refuses leases.
The default, `approval = "none"`, asks nobody: nothing below is needed.
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

A repository can **tighten** the wrapper's local rules in a
`.agent-sign.toml` at its top level, and nothing else:

```toml
[security]
forbidden_paths = ["secrets/*"]   # added to yours, never replacing them
block_branches = ["release/*"]    # added to yours; agents can't commit there
max_diff_lines = 5000             # used only if lower than yours (or yours is 0, no limit)
```

Anything else in the file (`[attribution]`, `[agent]`, `[human]`, `[ssh]`,
`approval`, `allow_main_branch`, `max_commits_per_minute`, ...) is ignored
(the rate is counted by the service, which reads only your config), and the
wrapper prints one
line naming it: whoever wrote the repository isn't you, and before 28 Oct
2026 such a file could loosen your rules or put your name on agent commits.
To loosen a rule for one repository, change your own `config.toml`.

## `agent-sign revoke` says there's no lease

`agent-sign revoke` takes the repository's full path, as `agent-sign leases` shows it,
or a path inside the repository (such as `.`). `agent-sign revoke --all` ends every
lease.

## Approval prompts keep appearing

Only with `approval = "device-owner"`; the default asks nothing.

- **Many at once, from tests:** a test suite that makes throwaway commits
  should turn signing off for them (`git config commit.gpgsign false` in the
  test repository, or `git -c commit.gpgsign=false commit ...`). Commits
  that do never ask for approval; they go to plain git, unsigned (under the
  fixture's own `user.email` if it sets one, otherwise the agent's name).
- **To see and close what's waiting:** `agent-sign pending` lists the open
  requests (one per repository and branch, however many commits are
  waiting on it), and `agent-sign deny --all` (or `agent-sign deny <id>`)
  answers no and closes their prompts.
- **Left open after a program stopped:** the Touch ID prompt
  closes by itself within about a second once every commit waiting on it
  has gone.
