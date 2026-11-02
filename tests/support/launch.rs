//! Test support: run something as a launched session.
//!
//! Since the switch (S8, P7 and decision D1, 1 Nov 2026) the service signs
//! only for a session a launcher started: an agent's process that merely
//! carries agent marks gets an UNSIGNED commit. Tests about what a signing
//! agent gets (a lease, a token, a Good signature, the rules on a signed
//! commit) therefore start the agent's program with `agent-sign launch
//! --agent <slug> -- <program>`, or, for a test that talks to the service
//! directly, play the launcher in-process with [`start_session`]. Each
//! moved test says so: "DELIBERATE EVAL CHANGE (P7/D1, 1 Nov 2026): agents
//! sign only when launched".
//!
//! Included by each test file that needs it, with
//! `#[path = "support/launch.rs"] mod launch;`. Launched sessions exist only
//! on Linux (PID namespaces), so on macOS these helpers compile and a
//! session can't be started: the macOS decision is build step S9's.
#![allow(dead_code)]

use std::ffi::OsStr;
use std::io::Write;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::Command;

use agent_sign::attribution::AgentIdentity;
use agent_sign::protocol::{Request, Response};
use agent_sign::session::{Channel, read_line_with_fd};

/// `agent-sign launch --agent <slug> -- <program>`, ready for arguments, a
/// working directory (the session's working copy is the git work tree it
/// starts in), environment and stdio. The caller adds `.args(...)` for the
/// program as for the program itself. The launcher strips every identity
/// claim from the environment and keeps `AGENT_SIGN_SOCKET`, `_REAL_GIT`,
/// `_BIN` and `_CONNECT_WAIT_MS`.
pub fn launch_command(slug: &str, program: impl AsRef<OsStr>) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_agent-sign"));
    cmd.args(["launch", "--agent", slug, "--"]).arg(program);
    cmd
}

/// A session the test started itself, playing the launcher (no sandbox):
/// the principal the service made, the session's channel, and the
/// registration whose closing ends the session. For tests that send the
/// service requests directly, which a launched session's program would.
pub struct Session {
    /// The session's principal, `<agent>.<8 hex>@<domain>`.
    pub principal: String,
    /// The identity the service gave the session.
    pub identity: AgentIdentity,
    channel: Channel,
    _fd: OwnedFd,
    /// Closing it ends the session.
    pub registration: UnixStream,
}

impl Session {
    /// One request and its answer, on a new stream over the session's
    /// channel: the service sees the session, whatever the request names.
    pub fn ask(&self, req: &Request) -> Response {
        self.channel
            .ask(req)
            .unwrap_or_else(|e| panic!("CONTROL: the session's channel failed: {e}"))
    }

    /// The channel itself, for a test that checks what happens after the
    /// session ends.
    pub fn channel(&self) -> Channel {
        self.channel
    }

    /// Makes the program `cmd` starts inherit the session's channel and
    /// know it (`AGENT_SIGN_CHANNEL_FD`), as a program the launcher starts
    /// does: for a test that runs the signing program itself, whose
    /// signature request must come over the session's own channel to be
    /// answered.
    pub fn pass_channel_to(&self, cmd: &mut Command) {
        use std::os::unix::process::CommandExt;
        let fd = self.channel.fd();
        cmd.env(agent_sign::session::channel_fd_var(), fd.to_string());
        // SAFETY: the closure only clears close-on-exec on a descriptor
        // this process owns (an async-signal-safe fcntl), between fork and
        // exec.
        unsafe {
            cmd.pre_exec(move || agent_sign::session::clear_cloexec(fd));
        }
    }
}

/// Starts a launched session of `agent` (a slug or display name) on the
/// service listening at `socket`, the way `agent-sign launch` does, and
/// returns it. Panics, saying so, when no session was started.
pub fn start_session(socket: &Path, agent: &str) -> Session {
    let mut registration = UnixStream::connect(socket).unwrap();
    let req = serde_json::to_string(&Request::LaunchSession {
        agent: agent.into(),
    })
    .unwrap();
    registration
        .write_all(format!("{req}\n").as_bytes())
        .unwrap();
    let (line, fd) = read_line_with_fd(&registration).unwrap();
    let principal = match serde_json::from_str::<Response>(&line) {
        Ok(Response::SessionStarted { principal, .. }) => principal,
        other => panic!("CONTROL: no session was started for {agent}: {other:?}\n{line}"),
    };
    let fd = fd.expect("the answer came with the session's channel");
    let channel = Channel::check(fd.as_raw_fd()).expect("CONTROL: a session channel checks out");
    let identity = match channel.ask(&Request::SessionIdentity).unwrap() {
        Response::SessionIdentity { identity } => identity,
        other => panic!("CONTROL: no session identity: {other:?}"),
    };
    assert_eq!(identity.principal, principal);
    Session {
        principal,
        identity,
        channel,
        _fd: fd,
        registration,
    }
}
