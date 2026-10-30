# Security repairs from the October 29 review

These changes address source-derived findings against agent-sign revision
`68d6220958fbd17f2a5689c1279ef09a2f6d9871`. No credential theft or covert
upload was observed in that review. This is a cooperative same-user signing
guardrail, not isolation from a malicious process running as the person.

## Candidate signing boundary

The service checks the exact UTF-8 commit buffer it will sign, its existing tree
and parent objects, changed paths, configured size limit and actual message.
The original wrapper preflight remains an early diagnostic. The service check
also covers commits created by merge, rebase, cherry-pick, am, aliases and hooks;
the current index or an earlier message is not substituted for the candidate.
Git validates commit object structure without writing that candidate object.
External diff/text conversion and submodule ignore settings cannot suppress the
named candidate-path check. Unsupported encoding, malformed input, unreadable
selected policy or unavailable objects refuse signing.

Changed paths and line counts mean the delta against the candidate's **first
parent**, or the empty tree for a root commit. This lets an ordinary merge be
checked against the branch state it extends; other parents must also be existing
commit objects. These are supplied commit headers, not an authenticated branch
update. A hostile same-user client can choose its request and parents, change
objects/configuration or bypass the wrapper. The certificate does not prove
that the supplied committer name is an authenticated human or process identity.

Global/repository path, size and message rules are loaded for each candidate,
with errors distinguished from a missing file. Repository configuration still
only tightens supported rules. Recognized tightening fields with invalid types
refuse instead of being ignored. The service's branch, lease-duration, ceiling,
idle and approval policy remains the policy selected at startup, including
explicit command-line overrides; change those settings by restarting. Loading
current guardrail files does not silently change that lease-policy contract.
The host, trusted Git executable/object store, filesystem consistency and local
configuration remain assumptions; this is not a sandbox or full proof of the
eventual Git ref update.

## Token validity and revocation

Both one-use commit tokens and run tokens bind the exact lease ID, repository,
branch and agent claim. After potentially blocking candidate/work checks, the
service rechecks token age, the same still-active lease and branch protection
before signing. Revocation, expiration, a completed work item or revocation
followed by a new lease cannot revive an old token. A one-use token is consumed
even if its candidate is rejected. Existing per-run rate accounting is retained.

Explicit revocation changes memory immediately and only acknowledges persistent
success after writing/syncing the lease file, renaming it and syncing its parent
directory. A selected store that was unreadable is not treated as intentionally
memory-only. Persistence errors explicitly report that durable revocation was
not confirmed. If the filesystem cannot record a revocation, old disk grants can
still return after restart: repair the store and successfully revoke all leases
before restarting. The program cannot guarantee a durable write to a failing
filesystem. Automatic work-ended cleanup still has the existing warning-only
save behavior; dispatch independently rechecks work completion, and no durable
automatic-cleanup claim is made.

## Installation and private material

The installer always rebuilds an explicitly selected source checkout with Cargo,
even if old `target/release` programs exist. Missing Cargo or a failed build
refuses installation without downloading a fallback release. For a release,
invoke a reviewed installer separately with `--archive FILE --sha256 DIGEST`.
The digest must come from the caller's independently trusted review or channel;
the archive is checked before extraction. A mutable digest downloaded beside a
mutable archive does not supply independent authenticity. An unpacked binary
folder alone is no longer admitted. `--from-homebrew PREFIX` explicitly selects
the caller's package-manager installation and retains that external trust.

Before generating its CA or session private keys, the daemon sets ordinary core
dump limits to zero and refuses on failure. The supplied user-service definitions
also disable ordinary core dumps. The application does not explicitly persist
private keys. Swap, privileged debuggers, compromised runtime/toolchain and host
dump mechanisms that ignore the process limit remain outside this protection.

## Evidence status

The implementation owner executed the selected source and synthetic tests on
October 30 in an unprivileged Linux x86-64 environment with separate process and
network namespaces, an empty environment and disposable homes. Host private
homes, credentials, signing sockets and real user services were unavailable.
The Rust 1.98.1 toolchain and copied registry cache were selected explicitly;
Cargo ran offline. This execution evidence is separate from independent source
review and does not establish whole-system security.

The [source checksum manifest](security-review-source-2026-10-30.json) identifies
all 56 Cargo, source, test and script files used in the final run. The labeled
JSON manifest's SHA-256 is
`661a86f560e61b671230523cab595b855df105e2c35a8b7dfd11b15fc50ed9cd`.
It preserves every path/digest pair from the raw runtime manifest, whose SHA-256
is `913a1db904be48dd3697f2443fc77dbb45ca2cb2c01694aa4da92cc535fce220`.
The labels distinguish actual file digests from possible credentials under the
existing scanner rule; no scanner configuration changed.
Both before and after execution, the remote source hashes matched the reviewed
local files. The final commands and observations were:

- `cargo fmt --all --check`: passed.
- `cargo clippy --all-targets --locked --offline -- -D warnings`: passed.
- `cargo test --locked --offline --no-fail-fast -- --test-threads=4`: 330 passed,
  including 12 security-boundary regressions, with exit status zero.
- `cargo build --release --locked --offline`: passed.
- `env -u GIT_CONFIG_GLOBAL bash scripts/release/install-test.sh`: all 35 checks
  passed, using synthetic identities, disposable homes and a stand-in service
  manager.
- `git diff --check`, shell syntax checks and the service property-list syntax
  check: passed as static checks.

The real-object tests include both token types, actual candidate paths/message/
line count, a hook that stages a forbidden path, forbidden cherry-pick content,
normal merges and replayed authors, lease revocation/regrant/expiry, completed
work, malformed selected policy, declared encoding, pristine root commits,
submodule-ignore settings, failed persistence and recovery, ordinary Linux core
limits, required source builds and pre-extraction digest refusal. The existing
raw-crypto golden expectation is unchanged.

Earlier observations remain recorded separately: an initial compiler attempt
failed because the isolated environment lacked the compiler's alternatives link;
strict lint then found two style warnings, which were repaired. The first release
installer fixture run had five failures because the runner's `GIT_CONFIG_GLOBAL`
override redirected synthetic identity writes to `/dev/null`. Removing that
runner-only override let each disposable home create its own configuration;
the fixture source did not change for this correction. A separate unsigned Git
probe refused `commit --include` for a previously untracked file, so that earlier
hypothesis is not reported as a demonstrated exploit for the tested Git.

macOS compilation, Touch ID, actual host service installation and real personal
signing were not exercised. The dependency lock and selected build scripts were
inspected; the entire dependency implementation and the host/toolchain were not
independently audited. No host service deployment, personal credential operation
or installed configuration change is part of this repair.
