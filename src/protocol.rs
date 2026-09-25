use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

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
    RevokeLease {
        repo: String,
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
    Success,
    Error {
        message: String,
    },
}

pub fn default_socket_path() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".agent-sign/daemon.sock")
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
