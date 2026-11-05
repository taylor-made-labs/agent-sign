# Evals for agent-sign: signed acts v0

author: agent-sign test writer (Claude Code, sonnet) / session: evals for signed acts v0 (role-commitments' real signatures) / created: 4 Nov 2026 / updated: 4 Nov 2026

Why: role-commitments decides "may X do E" and lists empty seats from signed acts, but nothing can really sign one:
agent-sign today signs git commits, not arbitrary acts. Until it can, no real role assignment exists, every seat is empty
and the team of teams cannot run. This thread adds **signing and verifying an act** to agent-sign, and nothing else.

These tests were written before the build, by someone other than the builder. The builder builds until they pass.
**Nobody changes an eval to make work pass.** A wrong eval is fixed as its own commit, "Deliberate change to the evals: ...".

## Scope

In: `agent-sign act sign` (as an agent, as Taylor, as the launcher), `act verify`, `act credential`, `act verify-credential`,
`act trust-lines`, `launch --identity`, the `[acts]` config table, the acts trust file format.
Out: role names or any role-commitments logic (a lower layer never names an upper one), the event log, replay protection
by log position, git commit signing (unchanged), delegation, expiry of assignments. Widening the scope is a new thread
that Taylor chooses to start.

## The interface (the contract the tests pin)

Written in full in the header of `tests/support/act_harness.rs`. In short:

- **Agent signs**: inside a session launched with `agent-sign launch --agent <slug> --identity agent:<name> -- ...`,
  `agent-sign act sign [--payload-file ABS]` signs the exact bytes (1 to 65536) in the SSH-signature namespace
  `agent-sign/act/1` with the session's in-memory key and prints one JSON object `{schema, signature, certificate}`.
  The identity is the launcher-given one; nothing in the session can choose or change it.
- **Assigners sign**: `act sign --assigner person:taylor --trust-file ABS` through Taylor's own ssh-agent (his key never
  reaches agent-sign); `act sign --assigner harness:launcher` through the service, whose key is `memory` (short-lived
  services, tests) or `openbao` (system mode). Never from inside a session.
- **Trust file** `agent-sign/acts-trust/1`: `authority`, `assigner` and `revoked` lines; one file, one digest.
- **Verify**: `act verify --format json --trust-file ABS [--now UNIX]` with `{payload_b64, signature}` on stdin prints
  `{verified, signer, kind, reason, detail, trust_sha256}`; exit 0 / 1 / 2. The signer comes from the trust file and the
  certificate, never from text in the signature.
- **Credential**: `act credential` / `act verify-credential`: a fresh (300 s) signature in namespace
  `agent-sign/credential/1`, how a session shows who it is to a consumer's `identify`.
- Keys exist only in memory, in the user's agent, or in OpenBao; never in a file.

## Definition of done

All five, for this scope only, with a limit of two rounds of fixes.

1. **All 31 public tests pass** (`cargo test --test test_act_signing`: 30 criteria tests and 1 harness test) on hetzner as
   the agents account, without root, on the exact commit to be merged; and the rest of `cargo test` still passes as before.
2. **All 6 held-out cases pass** (`evals/signed-acts-v0-heldout`, file `tests/test_act_signing_heldout.rs`). Run once,
   after (1), on the same commit; the builder does not read that branch. A failure goes back as a finding; the cases are
   not tuned against.
3. **0 of the 12 probes succeed** (the `probe_*` tests are the adversarial ones; this is the same as them passing).
4. **An independent security review** finds nothing of medium severity or worse. This changes who may sign as whom (signing,
   credentials, who can do what), so the review is required. An unresolved finding of medium or worse after the second
   round goes to the PM and blocks the merge.
5. **Merged to main** by fast-forward after 1 to 4, and pushed.

The 3 `system_*` tests are `#[ignore]`d: they need the root setup of `docs/system-mode.md` and the OpenBao issuer. They are
not part of this merge gate. They must pass at the sitting that turns on `launcher_assigner = "openbao"`, and until then
that value must not be used for anything real (`cargo test --test test_act_signing -- --ignored`, on the machine, as the
agents account).

## What the public tests pin (31)

| group | count | pin |
|---|---|---|
| `harness_*` | 1 | A launched session runs and its output and files reach the test. **Passes on main**, so no failure below is the harness's. |
| `sign_*` | 8 | An agent's signature verifies as its launcher-given identity; binds the exact bytes (5 changes refused); two sessions, two identities, and no variable or mark in the session changes it; no identity means no signing; reserved or malformed `--identity` values (10) are refused before anything runs; output is one object with exactly three keys and echoes nothing; payload limits (0, 1, 65536, 65537, 1 MiB bytes); no option picks an identity or an assigner (6 refused forms). |
| `assign_*` | 5 | Taylor signs through his own agent; needs his listed key in a reachable agent (3 refused forms); the launcher signs outside a session; a session cannot sign as the launcher or through Taylor's agent even when handed its socket; kinds (`agent`, `assigner`) are not interchangeable. |
| `keys_*` | 3 | No private key file anywhere after every signing path; the launcher key can only be `memory` or `openbao` (a key file setting stops the service); acts are off unless enabled. |
| `probe_*` | 12 | Forged signature and 5 malformed forms; a claimed identity inside the signature member or envelope; an agent's signature over an assigner act stays the agent's; 7 other domains (git, `role-commitments-act`, credential, near misses) are `wrong_namespace`; act signature as credential and the reverse; revoked agent and revoked assigner; 9 trust-file mistakes are exit 2; the validity window at a given time; mixed certificates; an authority the trust file does not name; a restarted service is a new authority; 9 hostile inputs (huge, duplicate keys, bad base64) never hang or succeed. |
| `cred_*` | 2 | A credential identifies its agent, is good for 300 s and not 301, is refused 61 s in the future, and cannot be back-dated; only identified agents have one. |

Every negative test has a positive control in the same test, so a refusal is never just "the command does not exist".

## Held-out (6, on `evals/signed-acts-v0-heldout`)

All 256 byte values in a payload; one identity with two keys and revocation of both; the canonical base64 only; two sessions
signing at once; an assigner line missing from the trust file; a session cannot launch another with an identity of its choice.

## Running

On hetzner, as `agents`, never sudo: `GIT_CONFIG_GLOBAL=/dev/null cargo test --test test_act_signing` (and `--test
test_act_signing_heldout` once). Each test starts its own service on a socket in a private temporary folder, dies with the
test, and leaves no private key (`support/no_plain_keys.rs` checks).

## Failing on main (measured 4 Nov 2026 at 02ed1f3 plus these tests)

30 of 31 fail; `harness_a_launched_session_runs_and_its_output_reaches_the_caller` passes. Most fail at once because the
service rejects the `[acts]` config table ("unknown table"), which is the feature missing; the 6 held-out cases all fail the
same way. `keys_03` fails on its control (acts enabled).
