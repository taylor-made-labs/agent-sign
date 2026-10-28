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

Cursor doesn't mark the commands its agent runs. Add
`"AGENT_SIGN_AGENT_NAME": "Cursor"` next to `PATH` in those two blocks, so
agent-sign knows commits from Cursor's agent are an agent's: they're then
signed as `Cursor <cursor.nosession@agents.local>` and authored and committed
by it. Without it, agent-sign can't tell them from your own and leaves them to
git (unsigned, under your git name, when there's no terminal).

## Who agent-sign thinks is committing

- **You, typing `git commit` in the integrated terminal:** a terminal and no
  agent mark, so your normal git and signer. (`AGENT_SIGN_AGENT_NAME` alone
  doesn't count as a mark, so setting it in the terminal's environment
  doesn't change this.) Nothing changes for you.
- **Cursor's agent running `git commit`:** without a terminal, and with
  `AGENT_SIGN_AGENT_NAME` set, it's Cursor's: signed as Cursor, nothing asked
  (unless `approval = "device-owner"`). If Cursor runs it in a terminal,
  agent-sign can't tell it from you, and it goes to your own signer. Check
  which by letting the agent commit once and running
  `git log -1 --format='%an | %G?'`: an agent commit through agent-sign shows
  the agent's name and `G` (once the agents' trust line is in your
  allowed-signers file).
- **The Source Control commit button:** it runs git without a terminal and
  without a mark. agent-sign leaves it to git: unsigned, under your git name,
  never attributed to an agent. To have the button sign with your own key,
  point Cursor's `git.path` setting at your real git (for example
  `/usr/bin/git`).

## Things to know

- Agent commits show on GitHub as Unverified: GitHub doesn't check SSH
  certificate signatures, and the commits aren't yours.
- The agent's merges and rebases are signed as Cursor when it's named, in the
  repository and on the branch they started from.
