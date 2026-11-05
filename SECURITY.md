# Security

## Reporting a vulnerability

Please report it privately, through GitHub: on this repository's
**Security** tab, choose **Report a vulnerability**. Don't open a public
issue for it.

Say what you found, how to reproduce it, and what it lets someone do. A fix
is released as soon as it's ready, and credits you unless you'd rather it
didn't.

## What agent-sign does and doesn't defend against

agent-sign is a guardrail for AI agents that cooperate, not a security
boundary against one that tries to get around it: an agent running as your
user account can read the agent key, change agent-sign's config, or call
the real git. The README's section
[What it protects against, and what it doesn't](README.md#what-it-protects-against-and-what-it-doesnt)
lists each limit. A way around one of those stated limits is known, and not
a vulnerability; a way to make agent-sign do what it says it won't is
one. For example:

- a commit signed with the agent key when no lease covered it
- a lease that covers more than the person approved, or lasts longer
- your own signing key used for an agent's commit
- an agent commit on a protected branch, or past a local rule, through the
  wrapper
- a refusal that leaves a commit signed some other way
- a launched session that reaches an ssh-agent, or makes `agent-sign act sign` sign as a person
  (README, "Signed acts": the session has no agent variable, no Unix-socket creation, hidden agent folders and no
  inherited descriptors, and the refusal rests on the process, not the environment)
- an act signed from a symbolic-linked or group- or world-writable trust or payload file, or a revoked launcher key
  that still verifies

## Supported versions

Only the latest release gets fixes while agent-sign is before 1.0.
