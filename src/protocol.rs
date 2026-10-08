//! The newline-delimited JSON protocol between agent-commits' programs and its service,
//! unchanged from agent-sign so old and new programs can talk to each other.

use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

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

pub fn send_request(
    socket_path: &Path,
    req: &Request,
) -> Result<Response, Box<dyn std::error::Error>> {
    let mut stream = UnixStream::connect(socket_path)?;
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
