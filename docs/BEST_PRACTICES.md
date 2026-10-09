# Engineering practices

How agent-sign's code is meant to be written, and where it stands against each
practice today (checked 30 Sept 2026). [CONTRIBUTING.md](../CONTRIBUTING.md)
has the rules every change must keep; this page is the longer list of aims.
Where the code doesn't meet an aim yet, it says so, so a contributor can
tell an aim from a guarantee.

## 1. Structure

- **Keep decisions in the library, and the programs thin.** `src/lease.rs`
  (lease terms), `src/attribution.rs`, `src/crypto.rs`, `src/multiplexer.rs`
  and `src/interceptor.rs` hold the decisions; `src/bin/` parses arguments,
  talks to the socket and runs processes.
  *Today:* mostly. `lease.rs` also saves `leases.json`, `config.rs` runs
  `git config` for defaults, and the wrapper's local rules live in
  `src/bin/agent_git.rs`.
- **One protocol, unchanged since the first agent-sign.** Newline-delimited
  JSON over a Unix socket (`src/protocol.rs`), so old and new programs
  interoperate during an upgrade.
  *Today:* yes.

## 2. Failing closed

- Any failure in lease checks, tokens, the socket or signing ends with a
  non-zero exit and a message on standard error, and nothing is signed.
  *Today:* yes (`test_human_isolation.rs`, `test_refusals_and_revoke.rs`).
- Never fall back to another key. *Today:* yes. Without a token, signing goes
  to the person's own `fallback_program`, which is the person's normal
  signing, not a fallback for an agent.
- Never print private keys or tokens. *Today:* keys are never printed;
  single-use tokens appear only in the environment of the git process they're
  for.
- A setting that can't be read must not quietly widen access.
  *Today:* an unreadable `max_lease_ceiling` stops the service. A config file
  that isn't valid TOML is still ignored as a whole (defaults apply), which
  is a gap.

## 3. Files and permissions

- State lives in `~/.agent-sign` (or the directory it links to),
  mode 0700; the key and `leases.json` are 0600; the socket is 0600.
  *Today:* yes. The key is **not encrypted** at rest.
- Write state files atomically: a temporary file created 0600, synced, then
  renamed. Never overwrite a file that couldn't be read. *Today:* yes for
  `leases.json`.
- Tokens are single-use, random (UUID v4), and expire after 60 seconds.
  *Today:* yes.

## 4. Robustness

- No panics on paths an agent or a malformed request can reach.
  *Today:* requests are parsed without panicking, but the service still
  unwraps its state lock (a panic in one connection would poison it for the
  rest) and has a few `expect`s on checked invariants.
- The service handles each connection on its own thread and never holds its
  lock while a dialog is open. *Today:* yes.
- Stop cleanly on SIGTERM. *Today:* not handled; the service relies on the
  socket being removed and recreated on the next start.

## 5. Speed

- The wrapper and signing program run on every commit, so keep them small:
  no async runtime, a Unix socket, a short-lived process.
  *Today:* the overhead hasn't been benchmarked. A whole agent commit under
  an existing lease took about 16 ms on a Raspberry Pi 5 in the demo script
  (one run).

## 6. Tests

- Unit tests for lease terms, attribution and signatures in memory;
  integration tests over a real socket; end-to-end tests with real git,
  verified by `ssh-keygen` and `git log --show-signature`. The end-to-end
  tests start their own service in a temporary home with its own socket and
  stand-in dialogs, so they never touch an installed agent-sign or show a real
  dialog.
- Every fix comes with a test that fails without it.
- *Today:* 72 tests. Not covered automatically: the wrapper's terminal check,
  the real dialogs, and the installer (see the install test in
  [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md)).
