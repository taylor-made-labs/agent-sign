# agent-commits with Claude Code

[Claude Code](https://docs.anthropic.com/en/docs/claude-code) runs shell
commands, `git commit` included, through its own tool runner.

## Setup

After `./scripts/install.sh`, start Claude Code from a **new** terminal, so it
inherits the `PATH` with agent-commits' wrapper first:

```sh
claude
```

Check from inside a session that `git` is the wrapper: ask it to run
`command -v git`, which should print a path ending in `.agent-sign/bin/git`.

## What happens

1. Claude Code runs `git commit -m "..."`. Its tool runner has no terminal
   attached, so the wrapper treats the commit as an agent's.
2. The first time in a repository, you get one dialog (on macOS, or a Linux
   desktop with `zenity` or `kdialog`) showing the repository, the branch,
   which branches the lease covers, and when it ends: by default, when you
   revoke it with `agent-commits revoke`.
3. Approve, and later commits in that repository are signed with the agent
   key without asking, until the lease ends. Commits on `main` or `master`
   are refused.
4. Commits you type yourself in a terminal go to your normal git and signer.

## Things to know

- `merge`, `rebase`, `cherry-pick`, `revert` and `pull` aren't intercepted:
  they use your own signing, so they may ask for your fingerprint.
- Agent commits show on GitHub as Verified for you, because the agent key is
  registered on your account. See the README's limits.
- Claude Code runs as your user, so it could read the agent key or edit
  agent-commits' config if it set out to. agent-commits catches mistakes, not a determined
  agent.
