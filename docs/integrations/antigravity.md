# agent-sign with Google Antigravity

Antigravity runs commands through its `run_command` tool.

## Setup

`./scripts/install.sh`:

1. puts `~/.agent-sign/bin` first on `PATH` in your shell profiles, which
   `run_command` uses when Antigravity is started from a shell, and
2. if `~/.gemini/config` exists, writes a rule to
   `~/.gemini/config/rules/agent-sign.md` telling the agent that commits are
   signed by agent-sign and not to bypass signing.

Start Antigravity from a new terminal.

## What happens

- A `git commit` from `run_command` goes to agent-sign's wrapper. The first one in
  a repository asks you once for a lease, showing its terms; later ones in
  that repository are signed with the agent key without asking.
- Commits on `main` or `master` are refused.
- If `run_command` gives the command a terminal, agent-sign can't tell it from you
  and it goes to your own signer. Check with
  `git log -1 --format='%an | %G?'` after the agent's first commit.
- The rule file is a request to the agent, not an enforcement.
