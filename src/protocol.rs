//! The newline-delimited JSON protocol between agent-commits' programs and its service,
//! unchanged from agent-sign so old and new programs can talk to each other.

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
    IssueToken {
        repo: String,
        branch: String,
    },
    SignCommit {
        token: String,
        buffer_b64: String,
    },
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
    Success,
    Error {
        message: String,
    },
}

/// The service's socket when none is given: `daemon.sock` in the state
/// directory (`~/.agent-commits`, or `~/.agent-sign` before migration). After migration
/// `~/.agent-sign` is a link to `~/.agent-commits`, so older clients using the old path
/// reach the same socket.
pub fn default_socket_path() -> PathBuf {
    crate::paths::state_dir().join("daemon.sock")
}

/// The socket a client (CLI, git wrapper, signing program) connects to:
/// `AGENT_COMMITS_SOCKET`, else `AGENT_SIGN_SOCKET`, else [`default_socket_path`].
/// The service itself ignores these variables and uses `--socket` or the default.
pub fn client_socket_path() -> PathBuf {
    crate::paths::env_var("SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(default_socket_path)
}

/// How long a client waits for the service to start answering, by default:
/// about twenty times the ~85 ms it takes to start on an Intel Mac (Core i9, 2019), so a
/// restart (an upgrade, launchd or systemd bringing it back) doesn't fail a
/// commit an agent makes at that moment. `AGENT_COMMITS_CONNECT_WAIT_MS`
/// changes it; 0 turns the wait off.
pub const DEFAULT_CONNECT_WAIT: Duration = Duration::from_secs(2);

/// The wait from `AGENT_COMMITS_CONNECT_WAIT_MS` (or the old
/// `AGENT_SIGN_CONNECT_WAIT_MS`), or [`DEFAULT_CONNECT_WAIT`].
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
fn connect_waiting(socket_path: &Path, wait: Duration) -> std::io::Result<UnixStream> {
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
    let mut stream = connect_waiting(socket_path, wait)?;
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
