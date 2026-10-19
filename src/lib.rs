//! agent-sign: signed, attributed git commits for AI agents, with leases the
//! person approves once.
//!
//! The programs are `agent-signd` (the service), `agent-git` (the git wrapper
//! agents run as `git`), `agent-ssh-sign` (the signing program git calls), and
//! `agent-sign` (the command line). Their state lives in `~/.agent-sign` (see
//! [`paths`]).

// The stand-in for the device owner (`AGENT_SIGN_TEST_AUTH`) must never be in
// a binary that can be installed. Optimized builds are the ones installed, so
// the feature that adds it refuses to compile without debug assertions: even
// `cargo test --release`, which would otherwise unify it into
// target/release/agent-signd, stops here instead of producing such a binary.
#[cfg(all(feature = "test-authenticator", not(debug_assertions)))]
compile_error!(
    "the `test-authenticator` feature is for debug test builds only: run `cargo test` without --release"
);

pub mod approval;
pub mod attribution;
pub mod config;
pub mod crypto;
#[cfg(target_os = "macos")]
pub mod device_owner;
pub mod interceptor;
pub mod lease;
pub mod multiplexer;
pub mod paths;
pub mod protocol;
pub mod repo_info;
pub mod ssh_sign;
pub mod work;
