//! agent-sign: signed, attributed git commits for AI agents, with leases the
//! person approves once.
//!
//! The programs are `agent-signd` (the service), `agent-git` (the git wrapper
//! agents run as `git`), `agent-ssh-sign` (the signing program git calls), and
//! `agent-sign` (the command line). Their state lives in `~/.agent-sign` (see
//! [`paths`]).

pub mod attribution;
pub mod config;
pub mod crypto;
pub mod interceptor;
pub mod lease;
pub mod multiplexer;
pub mod paths;
pub mod protocol;
pub mod ssh_sign;
pub mod work;
