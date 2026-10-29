# agent-sign with Aider

[Aider](https://aider.chat) commits after each change it makes.

## Setup

After `./scripts/install.sh`, start Aider from a new terminal so it inherits
the `PATH` with agent-sign's wrapper first, and tell agent-sign it's Aider:

```sh
AGENT_SIGN_AGENT_NAME=Aider aider
```

Aider doesn't mark the commands it runs, so `AGENT_SIGN_AGENT_NAME` is what
makes its commits Aider's. Without it, agent-sign can't tell Aider from your
own editor, and leaves its commits to git: unsigned, under your own git name.

## What happens

- Aider's commits are signed as Aider's own identity,
  `Aider <aider.nosession@agents.local>` (set `AGENT_SIGN_SESSION_ID` too to
  tell sessions apart), and authored and committed by it, never by you.
  Nothing asks you anything, unless you set `approval = "device-owner"`.
- `git log --show-signature` shows a Good signature for Aider's principal
  once the agents' trust line is in your allowed-signers file (the installer
  adds it). GitHub shows these commits as Unverified: it doesn't check SSH
  certificate signatures, and they aren't yours.
- Commits on `main` or `master` are refused, so run Aider on another branch.
- Aider commits often: the default limit is 10 agent commits a minute per
  repository (`max_commits_per_minute`).
- Your own commits from a terminal keep your normal signing.
