//! `agent-ssh-sign`: the program git calls to sign (its `gpg.ssh.program`),
//! named like 1Password's `op-ssh-sign`.
//!
//! It only signs; the management commands live in `agent-sign`. The logic is in
//! `agent_sign::ssh_sign`, shared with `agent-sign`, which also accepts git's
//! signing arguments, so both sign identically.

use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    agent_sign::ssh_sign::run(&args[1..])
}
