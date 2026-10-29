# agent-sign with Google Antigravity

Antigravity runs commands through its `run_command` tool.

## Setup

`./scripts/install.sh`:

1. puts `~/.agent-sign/bin` first on `PATH` in your shell profiles, which
   `run_command` uses when Antigravity is started from a shell, and
2. if `~/.gemini/config` exists, writes a rule to
   `~/.gemini/config/rules/agent-sign.md` telling the agent that commits are
   signed by agent-sign and not to bypass signing.

Start Antigravity from a new terminal, with `AGENT_SIGN_AGENT_NAME` set so
agent-sign knows its commits are an agent's:

```sh
AGENT_SIGN_AGENT_NAME=Antigravity antigravity
```

(If its shell tool sets `GEMINI_CLI`, as Gemini CLI's does, the commits are
named "Gemini CLI" without it. agent-sign hasn't seen Antigravity's marks yet.)

## What happens

- A `git commit` from `run_command` goes to agent-sign's wrapper. It is signed
  as the agent's own identity (such as
  `Antigravity <antigravity.nosession@agents.local>`), authored and committed
  by it; nothing asks you anything unless you set
  `approval = "device-owner"`.
- Without a name or mark, and without a terminal, agent-sign can't tell the
  commit from your own editor's, so it leaves it to git: unsigned, under your
  git name. Check with `git log -1 --format='%an | %G?'` after the agent's
  first commit: an agent commit through agent-sign shows the agent's name and
  `G` (once the trust line is in your allowed-signers file).
- Commits on `main` or `master` are refused.
- If `run_command` gives the command a terminal and nothing marks it,
  agent-sign can't tell it from you, and it goes to your own signer.
- The rule file is a request to the agent, not an enforcement.
