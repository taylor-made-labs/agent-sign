# agent-sign with Claude Code

[Claude Code](https://docs.anthropic.com/en/docs/claude-code) runs shell
commands, `git commit` included, through its own tool runner, and marks them
with `CLAUDECODE` and its session id.

## Setup

After `./scripts/install.sh`, start Claude Code from a **new** terminal, so it
inherits the `PATH` with agent-sign's wrapper first:

```sh
claude
```

Check from inside a session that `git` is the wrapper: ask it to run
`command -v git`, which should print a path ending in `.agent-sign/bin/git`.

## What happens

1. Claude Code runs `git commit -m "..."`. The wrapper sees its mark, so the
   commit is Claude Code's, even in a terminal pane.
2. It's signed with that session's own key, under a certificate for
   `claude-code.<8 hex characters of the session>@agents.local`, and
   authored and committed as `Claude Code <that principal>`, never as you.
   Nothing asks you anything; with `approval = "device-owner"` you approve
   each branch of each repository once, with Touch ID (macOS only).
3. Its merges, rebases, cherry-picks, reverts, pulls, `am` and aliases are
   signed as it too, but only in the repository and on the branch they
   started from: a run that moves to `main` or into another repository gets
   nothing signed there.
4. Commits on `main` or `master` are refused.
5. Commits you type yourself in a terminal go to your normal git and signer.

## Things to know

- `git log --show-signature` shows a Good signature for the session's
  principal once the agents' trust line is in your allowed-signers file (the
  installer adds it). GitHub shows these commits as Unverified: it doesn't
  check SSH certificate signatures, and they aren't yours.
- Claude Code runs as your user, so it could read the agents' certificate
  authority key, edit agent-sign's config, or call the real git directly if
  it set out to. agent-sign catches mistakes, not a determined agent; the
  identities are attribution, not a security boundary.
