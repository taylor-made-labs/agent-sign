# agent-commits: what it promises, and what it delivers today

- **Status:** pre-release (0.1.0), checked against the code on 30 Sept 2026.
- **Purpose:** the promises agent-commits makes to the people who use it, each with
  where it stands and how that's known. A promise that isn't kept yet says
  so.

## The problem

AI coding agents commit often. If you sign your commits with a hardware key,
1Password or a passkey, each of those commits stops for your fingerprint or a
touch, and the agent waits. The usual ways out are worse: turning signing
off, or handing the agent your own key.

## What agent-commits does

It gives agents their own signing key, held by a small service on your
machine, and asks you once per repository whether agents may sign there.
That permission is a **lease**, and you see its terms (which branches, when it
ends) before you approve. The terms are fixed when you approve and never grow.

## Promises

| # | Promise | Today | How it's known |
|---|---|---|---|
| 1 | You're asked once per repository, not once per commit. | **Kept.** Leases are saved, so restarts and sleep don't ask again. | Tests in `test_lease_engine.rs` and `test_persistent_identity_leases.rs`; daily use on the author's Mac. |
| 2 | A lease's terms never grow on their own. | **Kept.** Config changes can only narrow a lease already granted. | `test_lease_terms.rs`, including tests that fail under deliberate mutations. |
| 3 | Your own key stays out of agents' commits. | **Kept for commits through the wrapper.** Agents sign with a separate key; your terminal commits go to your own signer untouched. An agent can still call the real git or your signer directly. | `test_human_isolation.rs`, `test_signature_equivalence.rs`; the install test. |
| 4 | Agent commits are signed in git's standard format and verify on GitHub. | **Kept.** They show as Verified because the agent key is registered on *your* account and you're the committer, so they're attributed to you. | `test_crypto_verification.rs`, `test_e2e_git_commit.rs`. |
| 5 | Agent commits never land on protected branches. | **Kept** for `main` and `master` by default, checked on every commit; not for a detached HEAD. | `test_lease_engine.rs`, `test_lease_terms.rs`. |
| 6 | If anything is wrong, the commit is refused, never signed some other way. | **Kept.** | `test_human_isolation.rs`, `test_refusals_and_revoke.rs`. |
| 7 | Agent work is attributed to the agent, not to you. | **Not yet.** The key is registered under your email and account. A separate machine account is the planned fix. | Release checklist, M5 and N4. |
| 8 | An agent can't approve its own lease or take the key. | **Not yet.** Agents run as your user, so they can read the key and edit the config. A separate service user is the planned fix. | Release checklist, N1 and N2. |
| 9 | Merges, rebases and cherry-picks are agent-signed too. | **Not yet.** They use your own signing. | Release checklist, M2. |
| 10 | The approval can't be given by accident. | **Not yet.** It's a confirmation dialog, not a biometric check, and Approve is its default button. | Release checklist, M9. |

## Who it's for today

- **1Password, Secure Enclave or passkey signers on macOS:** the case agent-commits is
  used for daily. Your own commits still go through your signer; the agent's
  go through agent-commits.
- **Hardware keys (YubiKey, FIDO2):** the same; the agent key is an ordinary
  file key, so the agent's commits need no touch. Your key isn't involved in
  approving leases.
- **GPG users:** your own commits keep using GPG. Agent commits use SSH
  signatures, so verifying them needs an `allowed_signers` file (the
  installer sets one up) and, on GitHub, the agent key as a signing key.
- **Linux desktops:** builds and passes its tests on x86_64 and ARM64; little
  daily use yet. The approval dialog needs `zenity` or `kdialog`.
- **Servers and containers:** with no screen, agent-commits can't ask you. You can
  turn on `auto_approve`, which grants every lease without asking; that's
  only safe where every process that can reach the service is trusted.

## Not yet measured

- **Overhead per commit.** No benchmark exists. On a Raspberry Pi 5, a whole
  agent commit under an existing lease took about 16 ms in the demo script
  (one run, not a benchmark).

## Things agent-commits won't do

1. Weaken your own signing: it never changes how your own commits are
   signed, and never asks for your key.
2. Rely on the agent remembering anything: interception is in the `git` on
   its `PATH`, not in a prompt.
3. Lock you in: keys, signatures and config are OpenSSH, git and TOML.
4. Let a lease grow: new access always needs a new approval.
