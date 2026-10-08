//! `agent-commits-ssh-sign`: the program git calls to sign (its `gpg.ssh.program`),
//! named like 1Password's `op-ssh-sign`.
//!
//! It only signs; the management commands live in `agent-commits`. The logic is in
//! `agent_commits::ssh_sign`, shared with `agent-commits` so that the old `agent-sign` name,
//! which now points to `agent-commits`, signs identically.

use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    agent_commits::ssh_sign::run(&args[1..])
}
