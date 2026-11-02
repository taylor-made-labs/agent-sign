#![allow(dead_code)]
//! A per-test ssh agent, so a test key can sign without ever being a file.
//!
//! The rule (Taylor, 28 Oct 2026; a breach found 1 Nov 2026): every private
//! key is protected from the moment it exists. A test that needs a key to sign
//! (git calling `ssh-keygen -Y sign`) makes the key in memory
//! (`support/memory_keys.rs`), starts a [`TestAgent`], and hands the key to the
//! agent over its socket. git then names the public key (`user.signingkey` as
//! `key::<public key>`) and `SSH_AUTH_SOCK` points at the agent, so
//! `ssh-keygen` asks the agent to sign; the private key is never written.
//!
//! The agent is a real `ssh-agent -D` whose socket sits in a private (0700)
//! temporary folder of its own. It is killed and waited for when the
//! [`TestAgent`] is dropped, and it also dies if the test process is killed
//! (a timeout, an agent's session ending, SIGKILL), when drop never runs:
//! on Linux by `PR_SET_PDEATHSIG`, as for the test daemons in
//! `support/die_with_parent.rs` (which the including test file must also
//! include as `mod die_with_parent;`); elsewhere (macOS has no such request)
//! by a parent-pid watchdog, a small `sh` process started beside the agent
//! that kills the agent as soon as its own parent is no longer the test
//! process ([`WATCHDOG_SCRIPT`]; pinned by `tests/test_key_agent_watchdog.rs`).
//!
//! `ssh-add -` could load a plain key from stdin, but not a certified one:
//! `ssh-add` takes a certificate only from a `-cert.pub` file beside a key
//! file. So the key is added with the agent protocol's own add-identity
//! request (`PROTOCOL.agent`), which carries the certificate with the key. That
//! is a few lines here, and it keeps the key out of every file and argument
//! list.
//!
//! Included with `#[path = "support/key_agent.rs"] mod key_agent;`.

use crate::die_with_parent::DieWithParent;
use rand::RngCore;
use rand::rngs::OsRng;
use ssh_key::Certificate;
use ssh_key::certificate::{Builder, CertType};
use ssh_key::private::PrivateKey;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::{TempDir, tempdir};
use zeroize::Zeroizing;

/// `SSH_AGENTC_ADD_IDENTITY` and `SSH_AGENT_SUCCESS` from `PROTOCOL.agent`.
const AGENTC_ADD_IDENTITY: u8 = 17;
const AGENT_SUCCESS: u8 = 6;
/// The key type name for an ed25519 certificate.
const ED25519_CERT_TYPE: &str = "ssh-ed25519-cert-v01@openssh.com";

/// "No expiry" for a certificate: the end of the year 9999. ssh-keygen's own
/// `u64::MAX` is more than ssh-key will build a certificate with.
const FOREVER: u64 = 253_402_300_799;

/// The parent-pid watchdog, a POSIX `sh` script run as `sh -c SCRIPT watchdog
/// <test pid> <agent pid>` and started by the test process itself, so the test
/// process is its parent. Once a second it asks `ps` for its own parent's pid;
/// when that is no longer the test's (the test died and the watchdog was handed
/// to another process) it kills the agent and ends. It also ends, doing
/// nothing, when the agent is gone first, so it never signals a pid the agent
/// no longer holds. An empty answer from `ps` counts as "no news", never as
/// "the parent is gone". `PR_SET_PDEATHSIG` does this on Linux; this is for
/// macOS, and works wherever `ps -o ppid= -p` does.
pub const WATCHDOG_SCRIPT: &str = r#"parent=$1; agent=$2
while kill -0 "$agent" 2>/dev/null; do
  now=$(ps -o ppid= -p $$ 2>/dev/null | tr -d ' ')
  if [ -n "$now" ] && [ "$now" != "$parent" ]; then
    kill "$agent" 2>/dev/null
    exit 0
  fi
  sleep 1
done
"#;

/// Starts the watchdog for `agent`, whose parent is the process `parent`
/// (the caller, which must be that process: the watchdog's own parent is
/// whoever starts it).
pub fn start_watchdog(parent: u32, agent: u32) -> std::io::Result<Child> {
    Command::new("sh")
        .arg("-c")
        .arg(WATCHDOG_SCRIPT)
        .arg("watchdog")
        .arg(parent.to_string())
        .arg(agent.to_string())
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
}

/// A running `ssh-agent`, alone in its own 0700 folder; killed on drop, and
/// when the test process dies (see the module header).
pub struct TestAgent {
    child: Child,
    /// The parent-pid watchdog, where the kernel cannot do that (not Linux).
    watchdog: Option<Child>,
    socket: PathBuf,
    /// Declared after `child` is killed in `drop`; removes the folder.
    _dir: TempDir,
}

impl TestAgent {
    /// Starts an agent with an empty environment and waits for its socket.
    pub fn start() -> TestAgent {
        Self::start_with(cfg!(not(target_os = "linux")))
    }

    /// Like [`TestAgent::start`] but always with the parent-pid watchdog, so a
    /// Linux run can exercise the macOS path (`tests/test_key_agent_watchdog.rs`).
    pub fn start_watched() -> TestAgent {
        Self::start_with(true)
    }

    /// The agent's process id.
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// The watchdog's process id, if there is one.
    pub fn watchdog_pid(&self) -> Option<u32> {
        self.watchdog.as_ref().map(Child::id)
    }

    fn start_with(watched: bool) -> TestAgent {
        // `tempdir` makes the folder readable by its owner only (0700).
        let dir = tempdir().unwrap();
        let socket = dir.path().join("a.sock");
        let mut cmd = Command::new("ssh-agent");
        cmd.die_with_parent();
        let child = cmd
            .arg("-D")
            .arg("-a")
            .arg(&socket)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start ssh-agent");
        let watchdog = watched.then(|| {
            start_watchdog(std::process::id(), child.id()).expect("start the agent's watchdog")
        });
        let mut agent = TestAgent {
            child,
            watchdog,
            socket,
            _dir: dir,
        };
        let start = Instant::now();
        while UnixStream::connect(&agent.socket).is_err() {
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "the test ssh-agent did not open its socket"
            );
            assert!(
                agent.child.try_wait().unwrap().is_none(),
                "the test ssh-agent exited at start"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        agent
    }

    /// The agent's socket, for `SSH_AUTH_SOCK`.
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// Loads an ed25519 `key` together with its OpenSSH `certificate`, so the
    /// agent signs as the certificate. The key goes over the socket and
    /// nowhere else.
    pub fn add_ed25519_with_certificate(&self, key: &PrivateKey, certificate: &Certificate) {
        let pair = key.key_data().ed25519().expect("an ed25519 key");
        let mut secret = Zeroizing::new(pair.to_bytes().to_vec());
        let mut body = Zeroizing::new(vec![AGENTC_ADD_IDENTITY]);
        put_string(&mut body, ED25519_CERT_TYPE.as_bytes());
        put_string(&mut body, &certificate.to_bytes().unwrap());
        put_string(&mut body, pair.public.as_ref());
        put_string(&mut body, &secret);
        put_string(&mut body, b"test key");
        secret.fill(0);

        let mut stream = UnixStream::connect(&self.socket).unwrap();
        let mut request = Zeroizing::new((body.len() as u32).to_be_bytes().to_vec());
        request.extend_from_slice(&body);
        stream.write_all(&request).unwrap();
        let mut len = [0u8; 4];
        stream.read_exact(&mut len).unwrap();
        let mut reply = vec![0u8; u32::from_be_bytes(len) as usize];
        stream.read_exact(&mut reply).unwrap();
        assert_eq!(
            reply.first().copied(),
            Some(AGENT_SUCCESS),
            "the test ssh-agent refused the key"
        );
    }
}

impl Drop for TestAgent {
    fn drop(&mut self) {
        // The watchdog first, so it never sees the agent go and the test not.
        if let Some(mut watchdog) = self.watchdog.take() {
            let _ = watchdog.kill();
            let _ = watchdog.wait();
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// An OpenSSH user certificate for `subject`'s public key, signed by `ca`, for
/// the one `principal`, valid from the epoch to [`FOREVER`]: what `ssh-keygen -s <ca> -I
/// <key_id> -n <principal> <subject>.pub` makes, with its default
/// extensions. Built in memory; the authority key is never a file.
pub fn user_certificate(
    ca: &PrivateKey,
    subject: &PrivateKey,
    key_id: &str,
    principal: &str,
) -> Certificate {
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    let mut builder = Builder::new(
        nonce.to_vec(),
        subject.public_key().key_data().clone(),
        0,
        FOREVER,
    )
    .unwrap();
    builder
        .serial(0)
        .unwrap()
        .key_id(key_id)
        .unwrap()
        .cert_type(CertType::User)
        .unwrap()
        .valid_principal(principal)
        .unwrap();
    for extension in [
        "permit-X11-forwarding",
        "permit-agent-forwarding",
        "permit-port-forwarding",
        "permit-pty",
        "permit-user-rc",
    ] {
        builder.extension(extension, "").unwrap();
    }
    builder.sign(ca).unwrap()
}
