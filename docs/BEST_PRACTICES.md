# Engineering practices

How agent-sign's code is meant to be written, and where it stands against each
practice today (checked 30 Sept 2026; failing closed, keys and tests
updated 28 Oct 2026). [CONTRIBUTING.md](../CONTRIBUTING.md)
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
  *Today:* the service stops, with a message naming the file and key, on a
  `config.toml` it can't read (its permissions, a link to nothing, a
  directory), that isn't valid TOML, that has a table or key it doesn't
  know, or that has a value it can't read (`max_lease_ceiling`,
  `approval`, ...); only a missing file means the defaults, and it logs the
  approval mode in effect when it starts. The wrapper and signing program
  still fall back to the defaults on a bad file, which is safe only because
  the service then won't start.
- What isn't the person's can't change the person's rules.
  *Today:* a repository's `.agent-sign.toml` can only tighten them (see
  `config::tighten_with_repo_file`); what else it sets is ignored, with a
  warning.

## 3. Files and permissions

- State lives in `~/.agent-sign` (or the directory it links to),
  mode 0700; `leases.json` is 0600; the socket is 0600. No private key is
  ever stored there (Taylor, 28 Oct 2026: keys are never stored
  unprotected; they live in OpenBao, a hardware or OS keystore, or only in a
  running process's memory). The agents' certificate authority and agent
  sessions' keys live only in the service's memory (sessions: at most 1024,
  each dropped after 12 hours unused); only public keys are on disk.
  *Today:* yes. Private keys earlier versions stored (the shared agent key,
  an earlier build's authority key) are deleted by the installer, and the
  service refuses to start while the authority key file is there.
- Write state files atomically: a temporary file created 0600, synced, then
  renamed. Never overwrite a file that couldn't be read. *Today:* yes for
  `leases.json`.
- Tokens are random (UUID v4) and bound to one identity, repository and
  branch: a commit's is single-use and expires after 60 seconds, a git run's
  after 10 minutes. A token is used only beside the wrapper's own mark.
  *Today:* yes.

## 4. Robustness

- No panics on paths an agent or a malformed request can reach.
  *Today:* requests are parsed without panicking, but the service still
  unwraps its state lock (a panic in one connection would poison it for the
  rest) and has a few `expect`s on checked invariants.
- The service handles each connection on its own thread and never holds its
  lock while a prompt is open. *Today:* yes.
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
  a stand-in owner (`AGENT_SIGN_TEST_AUTH`, test builds only), so they never touch an installed agent-sign or show a real
  prompt.
- Every fix comes with a test that fails without it.
- *Today:* 305 tests, 304 run and 1 ignored (28 Oct 2026). Each finding of the identity review has a
  regression test in `tests/test_identity_review_fixes.rs` that failed before
  its fix. Not covered automatically: the real Touch ID prompt, and the
  installer on macOS (see the install test in
  [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md)).
