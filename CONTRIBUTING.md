# Contributing to Agent-Sign

Thank you for your interest in contributing to `agent-sign`!

## Philosophy & Core Rules
This project strictly follows **Spec-Driven Development (SDD)** and **Test-Driven Development (TDD)**:
1. **Never violate the 7 Invariants**: Every pull request must respect all invariants in [SPEC.md](SPEC.md).
2. **Never break human isolation**: Human commits (terminal or IDE GUI) must never be intercepted or falsely attributed.
3. **Fail-Closed Security**: In the presence of errors, the system must fail closed (refusing to sign) rather than falling back to unverified keys.
4. **All PRs must include tests**: Any new feature or bug fix must include automated tests in `tests/`.

## Development Workflow
```bash
# 1. Run all test suites (unit, integration & E2E)
cargo test

# 2. Check code formatting
cargo fmt --check

# 3. Run Clippy linter
cargo clippy -- -D warnings
```

## Submitting Pull Requests
- Keep PRs focused on a single concern.
- Ensure all CI checks pass.
- Update `SPEC.md` if any component contracts or data schemas change.
