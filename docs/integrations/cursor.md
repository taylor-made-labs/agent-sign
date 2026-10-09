# agent-sign with Cursor

## Setup

If Cursor is installed, `./scripts/install.sh` adds agent-sign's directory to the
`PATH` of Cursor's integrated terminal, in Cursor's `settings.json`:

```json
{
  "terminal.integrated.env.osx": {
    "PATH": "${env:HOME}/.agent-sign/bin:${env:PATH}"
  },
  "terminal.integrated.env.linux": {
    "PATH": "${env:HOME}/.agent-sign/bin:${env:PATH}"
  }
}
```

`./scripts/uninstall.sh` removes it. Restart Cursor after installing.

Cursor doesn't mark the commands its agent runs, so its commits are
authored by "Agent". To have them say "Cursor", add
`"AGENT_SIGN_AGENT_NAME": "Cursor"` next to `PATH` in those two blocks.

## Who agent-sign thinks is committing

The wrapper decides by one test: are standard input and output both
terminals? If so, it's you; otherwise, an agent.

- **You, typing `git commit` in the integrated terminal:** a terminal, so
  your normal git and signer. Nothing changes for you.
- **Cursor's agent running `git commit`:** if Cursor runs the command without
  a terminal, agent-sign treats it as the agent's: one lease dialog per scope you approve,
  then signed with the agent key. If Cursor runs it in a terminal, agent-sign
  can't tell it from you, and it goes to your own signer. Check which by
  letting the agent commit once and running
  `git log -1 --format='%an | %G?'`: an agent commit through agent-sign shows the
  agent's name as author.
- **The Source Control commit button:** it runs git without a terminal. If
  that git resolves to agent-sign's wrapper (on macOS, Cursor may take `PATH` from
  your login shell), agent-sign treats your click as an agent commit and asks for a
  lease. If you'd rather it didn't, point Cursor's `git.path` setting at your
  real git (for example `/usr/bin/git`).

## Things to know

- Agent commits show on GitHub as Verified for you, since the agent key is
  registered on your account.
- Merges and rebases use your own signing.
