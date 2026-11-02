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

pub mod accounts;
pub mod agents_ca;
pub mod approval;
pub mod attestation;
pub mod attribution;
pub mod cert_times;
pub mod commit_approval;
pub mod config;
pub mod crypto;
#[cfg(target_os = "macos")]
pub mod device_owner;
pub mod git_place;
pub mod guardrails;
pub mod hardening;
pub mod interceptor;
pub mod issuer_openbao;
pub mod kernel_facts;
pub mod launch;
pub mod launch_approval;
#[cfg(target_os = "linux")]
pub mod launch_client;
#[cfg(target_os = "linux")]
pub mod launcher;
pub mod lease;
pub mod multiplexer;
pub mod paths;
pub mod protocol;
pub mod repo_info;
pub mod session;
#[cfg(target_os = "linux")]
pub mod session_runner;
#[cfg(target_os = "linux")]
pub mod slot_fs;
pub mod ssh_sign;
pub mod state_lock;
pub mod system_config;
pub mod systemd_port;
pub mod verify;
pub mod work;
