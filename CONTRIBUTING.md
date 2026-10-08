# Contributing to agent-commits

Thank you for your interest in agent-commits (formerly agent-sign).

## Rules the code keeps

1. **The invariants in [SPEC.md](SPEC.md) hold.** Every change respects them,
   and a change to one is its own, explained change.
2. **A person's own commits are never touched.** Commits from your own
   terminal go straight to git.
3. **Fail closed.** On any error, refuse to sign; never fall back to another
   key.
4. **Lease terms never grow on their own.** A lease's terms are fixed when
   the person approves it; nothing may extend them, and config changes may
   only narrow them..
5. **Every fix or feature comes with a test** in `tests/`, one that fails
   without the change.

## Checks

```sh
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
```

The end-to-end tests start their own service in a temporary home with its
own socket and stand-in dialogs, so they never touch an installed agent-commits.

## Sending changes

- Keep each pull request to one concern, and each commit small.
- Sign off every commit (`git commit -s`), certifying the
  [Developer Certificate of Origin](https://developercertificate.org/).
  There's no contributor agreement.
- Update [SPEC.md](SPEC.md) when a component's contract or data changes.

Unless you say otherwise, any contribution you send for inclusion is
licensed as the rest of agent-commits is: under either the
[Apache License 2.0](LICENSE-APACHE) or the [MIT License](LICENSE-MIT), at
the user's choice, with no other terms.
