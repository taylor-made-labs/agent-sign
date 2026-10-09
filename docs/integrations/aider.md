# agent-sign with Aider

[Aider](https://aider.chat) commits after each change it makes.

## Setup

After `./scripts/install.sh`, start Aider from a new terminal so it inherits
the `PATH` with agent-sign's wrapper first:

```sh
AGENT_SIGN_AGENT_NAME=Aider aider
```

(`AGENT_SIGN_AGENT_NAME` makes Aider's commits say "Aider" as their
author; without it they say "Agent".)

## What happens

- Aider's commits have no terminal attached, so agent-sign treats them as the
  agent's. The first one in a repository asks you once for a lease (showing
  which branches it covers and when it ends); after that, Aider's commits in
  that repository are signed with the agent key without asking.
- Commits on `main` or `master` are refused, so run Aider on another branch.
- Aider commits often: the default limit is 10 agent commits a minute per
  repository (`max_commits_per_minute`).
- Your own commits from a terminal keep your normal signing.
- Agent commits show on GitHub as Verified for you, because the agent key is
  registered on your account.
