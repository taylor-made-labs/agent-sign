//! The newline-delimited JSON protocol between agent-sign's programs and its service,
//! unchanged from agent-sign so old and new programs can talk to each other.

use crate::attribution::AgentIdentity;
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseInfo {
    pub lease_id: String,
    pub repo: String,
    pub branch: String,
    pub mode: String,
    pub granted_at_epoch: u64,
    pub last_used_epoch: u64,
    pub commit_count: u64,
    pub expires_in_secs: Option<u64>,
    /// What the lease covers, in plain words ("this repository", "every
    /// repository under /w/dev"). Empty from services older than scopes.
    #[serde(default)]
    pub covers: String,
    /// What else ends the lease, besides `expires_in_secs`, in plain words
    /// ("when branch 'feat/a' is merged or deleted, after 7 days with no agent
    /// commits, or when you turn it off"). Empty from older services.
    #[serde(default)]
    pub ends: String,
}

impl LeaseInfo {
    /// Whether the lease covers more than one repository (a folder or
    /// everywhere). This version no longer grants those: ones approved in an
    /// earlier version still work, so they are pointed out.
    pub fn is_wide(&self) -> bool {
        self.covers.starts_with("every repository")
    }
}

/// A plain-words note about leases that cover more than one repository, or
/// `None` when there are none. Shown by `agent-sign leases` and `doctor`, and
/// logged by the service at start.
pub fn wide_leases_note(leases: &[LeaseInfo]) -> Option<String> {
    let wide: Vec<&LeaseInfo> = leases.iter().filter(|l| l.is_wide()).collect();
    if wide.is_empty() {
        return None;
    }
    let names: Vec<String> = wide
        .iter()
        .map(|l| format!("{} ({})", l.repo, l.covers))
        .collect();
    Some(format!(
        "{} lease(s) from an earlier version cover more than one repository: {}. This version no longer grants those; they keep working until they end, and only follow the agent across branches if allow_branch_switching = true. End one with `agent-sign revoke <that folder, or everywhere>`.",
        wide.len(),
        names.join("; ")
    ))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum Request {
    Ping,
    RequestLease {
        repo: String,
        branch: String,
        intent: String,
        duration_secs: Option<u64>,
    },
    /// A single-use token for one commit, from a wrapper older than
    /// per-agent identities, which sends no identity. Refused since the
    /// identity review (28 Oct 2026): a commit nobody identifies is no longer
    /// signed as an "unidentified agent".
    IssueToken {
        repo: String,
        branch: String,
    },
    /// A single-use token for one commit, signed as `identity`.
    IssueIdentifiedToken {
        repo: String,
        branch: String,
        identity: AgentIdentity,
    },
    /// A token for one git run of an identified agent (merge, rebase,
    /// cherry-pick, revert, am, pull, a shell alias): bound to the identity, the
    /// repository and the branch, usable for every commit that run makes,
    /// for [`RUN_TOKEN_LIFETIME`].
    IssueRunToken {
        repo: String,
        branch: String,
        identity: AgentIdentity,
    },
    /// The plain path's policy-only question (D1, 1 Nov 2026): may an agent
    /// nobody launched make an UNSIGNED commit in `repo` on `branch`? The
    /// service checks the name rules (allowed agents, a person's name, the
    /// machine's domain), that no approval or launched session holds the
    /// name, the protected branches and the rate limit, and counts the commit
    /// in the repository's rate window. Answered [`Response::Success`] or
    /// [`Response::Error`]; it never makes a token, a lease or a signature,
    /// and a launched session's channel refuses it. The plain path has no
    /// attested identity, so its commits carry no signature at all.
    CheckPlainCommit {
        repo: String,
        branch: String,
        identity: AgentIdentity,
    },
    /// A signature over `buffer_b64` with `token`. `repo` and `branch` are
    /// where the git run asking is writing, as the signing program finds
    /// them (see [`crate::git_place`]): the service refuses when they aren't
    /// the token's, or when the branch is protected. A signing program older
    /// than the identity review sends neither, and is refused.
    SignCommit {
        token: String,
        buffer_b64: String,
        #[serde(default)]
        repo: Option<String>,
        #[serde(default)]
        branch: Option<String>,
    },
    /// A signature over `buffer_b64` as the agent a commit approval names
    /// (docs/caller-identity.md, path 1). `approval` is the approval's exact
    /// JSON text ([`crate::commit_approval::CommitApproval`]),
    /// `approval_signature` an armored SSHSIG over it by the commitments
    /// approval key in [`crate::commit_approval::APPROVAL_NAMESPACE`], and
    /// `repo` and `branch` where the commit is made. Answered
    /// [`Response::Signed`] only when every check passes; needs no lease.
    SignApproved {
        approval: String,
        approval_signature: String,
        buffer_b64: String,
        repo: String,
        branch: String,
    },
    /// Starts a launched session for `agent` (a display name or a slug, as
    /// `AGENT_SIGN_AGENT_NAME` takes them): sent by `agent-sign launch`
    /// only. The service makes the session's id and principal, and answers
    /// [`Response::SessionStarted`] with the session's channel attached
    /// (`SCM_RIGHTS`; see [`crate::session`]). The connection it came on is
    /// the session's registration: the session ends when it closes.
    LaunchSession {
        agent: String,
    },
    /// System mode: the launcher registers a session in `slot`, whose
    /// account is `uid` and whose systemd unit is `unit`
    /// (`agent-session@<slot>.service`), for `agent` (docs/system-mode.md,
    /// section 4). Accepted only on the launcher-only socket and only from
    /// the `[launcher] account`'s uid as the kernel reports it; answered
    /// [`Response::SessionStarted`] with no descriptor attached. The
    /// connection is the registration: the session ends when it closes. The
    /// service then counts a caller as this session only by its uid, its
    /// unit and its live process (`crate::kernel_facts`), never by anything
    /// it says.
    RegisterSession {
        slot: u32,
        uid: u32,
        unit: String,
        agent: String,
    },
    /// Who this launched session is: answered [`Response::SessionIdentity`]
    /// only to a launched session (a stream over its channel in one-account
    /// mode; a process of its slot account in its unit in system mode).
    SessionIdentity,
    GetStatus {
        repo: String,
    },
    ListLeases,
    RevokeLease {
        repo: String,
        #[serde(default)]
        branch: Option<String>,
        #[serde(default)]
        all: bool,
    },
    /// The approval requests waiting for the person's answer.
    ListPending,
    /// Answers waiting requests with a denial and closes their dialogs:
    /// the one with this `id`, or all of them.
    DenyPending {
        #[serde(default)]
        id: Option<String>,
        #[serde(default)]
        all: bool,
    },
}

/// One approval request waiting for the person, as `agent-sign pending`
/// lists it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingInfo {
    pub id: String,
    pub repo: String,
    pub branch: String,
    /// How long the dialog has been open.
    pub waiting_secs: u64,
    /// How many commits are waiting on this one answer.
    pub waiters: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum Response {
    Pong,
    LeaseGranted {
        lease_id: String,
        expires_at_secs: u64,
    },
    TokenIssued {
        token: String,
    },
    Signed {
        signature_pem: String,
    },
    Status {
        active: bool,
        lease_id: Option<String>,
        branch: Option<String>,
        expires_in_secs: Option<u64>,
    },
    LeaseList {
        leases: Vec<LeaseInfo>,
    },
    PendingList {
        pending: Vec<PendingInfo>,
    },
    /// A launched session started: its principal and the id the service
    /// made for it. Its channel comes attached to this answer.
    SessionStarted {
        principal: String,
        session: String,
    },
    /// The identity of the launched session whose channel the request came
    /// in on.
    SessionIdentity {
        identity: AgentIdentity,
    },
    Success,
    Error {
        message: String,
    },
}

/// How long a run token ([`Request::IssueRunToken`]) can be used: long
/// enough for a big rebase, short enough that a leaked one soon stops working.
pub const RUN_TOKEN_LIFETIME: Duration = Duration::from_secs(10 * 60);

/// The service's socket when none is given: `daemon.sock` in the state
/// directory (`~/.agent-sign`).
pub fn default_socket_path() -> PathBuf {
    crate::paths::state_dir().join("daemon.sock")
}

/// The socket a client (CLI, git wrapper, signing program) connects to, in
/// this order (docs/system-mode.md, section 4): `AGENT_SIGN_SOCKET` if set;
/// else the `[service] socket` of `/etc/agent-sign/system.toml`, if that
/// file exists ([`crate::system_config::client_socket`]); else
/// [`default_socket_path`], which is what a laptop uses.
/// The service itself ignores the variable and uses `--socket`, then the
/// same file, then the default.
pub fn client_socket_path() -> PathBuf {
    crate::paths::env_var("SOCKET")
        .map(PathBuf::from)
        .or_else(crate::system_config::client_socket)
        .unwrap_or_else(default_socket_path)
}

/// How long a client waits for the service to start answering, by default:
/// about twenty times the ~85 ms it takes to start on an Intel Mac (Core i9, 2019), so a
/// restart (an upgrade, launchd or systemd bringing it back) doesn't fail a
/// commit an agent makes at that moment. `AGENT_SIGN_CONNECT_WAIT_MS`
/// changes it; 0 turns the wait off.
pub const DEFAULT_CONNECT_WAIT: Duration = Duration::from_secs(2);

/// The wait from `AGENT_SIGN_CONNECT_WAIT_MS`, or [`DEFAULT_CONNECT_WAIT`].
pub fn connect_wait() -> Duration {
    crate::paths::env_var("CONNECT_WAIT_MS")
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map_or(DEFAULT_CONNECT_WAIT, Duration::from_millis)
}

/// Sends one request and reads the answer, waiting up to [`connect_wait`]
/// for a service that's starting or restarting.
pub fn send_request(
    socket_path: &Path,
    req: &Request,
) -> Result<Response, Box<dyn std::error::Error>> {
    send_request_waiting(socket_path, req, connect_wait())
}

/// Connects, retrying while the socket is missing or has nothing listening
/// yet (the moments a restart leaves), for up to `wait`. Any other error, or
/// one that outlasts the wait, is returned as is: a service that doesn't come
/// back still fails the commit.
pub fn connect_waiting(socket_path: &Path, wait: Duration) -> std::io::Result<UnixStream> {
    let start = Instant::now();
    loop {
        match UnixStream::connect(socket_path) {
            Ok(stream) => return Ok(stream),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                ) && start.elapsed() < wait =>
            {
                std::thread::sleep(Duration::from_millis(20).min(wait));
            }
            Err(e) => return Err(e),
        }
    }
}

/// [`send_request`] with an explicit wait for the service to answer.
pub fn send_request_waiting(
    socket_path: &Path,
    req: &Request,
    wait: Duration,
) -> Result<Response, Box<dyn std::error::Error>> {
    let stream = connect_waiting(socket_path, wait)?;
    request_on(stream, req)
}

/// Sends one request on an open `stream` and reads the answer: the
/// service's socket, or a launched session's private stream
/// ([`crate::session::Channel::open_stream`]).
pub fn request_on(
    mut stream: UnixStream,
    req: &Request,
) -> Result<Response, Box<dyn std::error::Error>> {
    let mut serialized = serde_json::to_string(req)?;
    serialized.push('\n');
    stream.write_all(serialized.as_bytes())?;
    stream.flush()?;

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;

    if line.is_empty() {
        return Err("Daemon closed connection without response".into());
    }

    let resp: Response = serde_json::from_str(&line)?;
    Ok(resp)
}

/// Asks the service: over this process's launched session's channel when it
/// has one ([`crate::session::Channel::from_env`]), so the service knows the
/// session from the channel, never from the request; otherwise on the
/// service's socket ([`client_socket_path`]).
pub fn ask_service(req: &Request) -> Result<Response, Box<dyn std::error::Error>> {
    match crate::session::Channel::from_env() {
        Some(channel) => channel.ask(req),
        None => send_request(&client_socket_path(), req),
    }
}

/// Where [`ask_service`] asks, for messages: the session's channel, or the
/// socket's path.
pub fn service_place() -> String {
    match crate::session::Channel::from_env() {
        Some(channel) => format!("this session's channel (descriptor {})", channel.fd()),
        None => client_socket_path().display().to_string(),
    }
}

pub fn send_response(
    stream: &mut UnixStream,
    resp: &Response,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut serialized = serde_json::to_string(resp)?;
    serialized.push('\n');
    stream.write_all(serialized.as_bytes())?;
    stream.flush()?;
    Ok(())
}
