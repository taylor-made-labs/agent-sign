//! agent-commits (formerly agent-sign): signed, attributed git commits for AI agents,
//! with leases the person approves once.
//!
//! The programs are `agent-commitsd` (the service), `agent-commits-git` (the git wrapper agents
//! run as `git`), `agent-commits-ssh-sign` (the signing program git calls), and `agent-commits`
//! (the command line). The old names `agent-signd`, `agent-git`, and
//! `agent-sign` keep working as links, and an existing `~/.agent-sign` is moved
//! to `~/.agent-commits` by the service on first start (see [`migrate`] and [`paths`]).

pub mod attribution;
pub mod config;
pub mod crypto;
pub mod interceptor;
pub mod lease;
pub mod migrate;
pub mod multiplexer;
pub mod paths;
pub mod protocol;
pub mod ssh_sign;
