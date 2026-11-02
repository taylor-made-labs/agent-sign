//! L6 (whole-branch security review, system-mode half): `agent-signd`'s
//! per-connection handler read a request with no size limit and no timeout
//! on a socket anyone can connect to (mode 0666 in system mode), one thread
//! per connection, and `thread::spawn` panics when threads run out.
//!
//! These tests start the real service (as test_sessions.rs does) and drive
//! its main socket. The handler is the same code in both modes, so a plain
//! start exercises it. Each test names what the fix must do:
//!
//! 1. A request line is read up to a fixed limit (as serve_launcher's
//!    MAX_REGISTRATION_BYTES does); past it the connection is dropped, so a
//!    client streaming bytes with no newline cannot grow the service.
//! 2. A client that connects and sends nothing is dropped after a read
//!    timeout, so it cannot hold a thread for ever.
//! 3. When a thread cannot be started, that connection is refused and the
//!    service lives on (std::thread::Builder::spawn, not thread::spawn).
//!
//! Test seams for the builder: none are required. The timeout constant is
//! the builder's to choose; test 2 allows it up to IDLE_LIMIT below.
//! Linux only: test 3 uses prlimit(2).

#![cfg(target_os = "linux")]

use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// The most a silent connection may be held. The builder picks the actual
/// timeout (the launcher uses seconds-scale ones); anything above this is
/// the unbounded wait the review named.
const IDLE_LIMIT: Duration = Duration::from_secs(20);

struct Service {
    dir: tempfile::TempDir,
    socket: PathBuf,
    child: Child,
}

impl Service {
    fn start() -> Service {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        fs::create_dir_all(home.join(".agent-sign")).unwrap();
        fs::write(home.join(".agent-sign/config.toml"), "").unwrap();
        let socket = home.join("s.sock");
        let log = fs::File::create(home.join("service.log")).unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_agent-signd"));
        cmd.env_clear()
            .env("HOME", &home)
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("TZ", "UTC")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("AGENT_SIGN_SOCKET", &socket)
            .env("AGENT_SIGN_TEST_AUTH", "fail")
            .env("AGENT_SIGN_REFUSAL_BACKOFF", "none")
            .arg("--socket")
            .arg(&socket)
            .arg("--auto-approve")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(log));
        if let Some(tmp) = std::env::var_os("TMPDIR") {
            cmd.env("TMPDIR", tmp);
        }
        let mut child = cmd.spawn().unwrap();
        let start = Instant::now();
        while !socket.exists() {
            if let Some(status) = child.try_wait().unwrap() {
                panic!("CONTROL: the service stopped at start ({status})");
            }
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "CONTROL: no socket"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        Service { dir, socket, child }
    }

    fn log(&self) -> String {
        fs::read_to_string(self.dir.path().join("service.log")).unwrap_or_default()
    }

    /// One Ping on a fresh connection; true if it is answered with Pong.
    fn pings(&self) -> bool {
        let Ok(mut s) = UnixStream::connect(&self.socket) else {
            return false;
        };
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        if s.write_all(b"{\"type\":\"Ping\"}\n").is_err() {
            return false;
        }
        let mut buf = String::new();
        let mut one = [0u8; 1];
        while let Ok(1) = s.read(&mut one) {
            buf.push(one[0] as char);
            if one[0] == b'\n' {
                break;
            }
        }
        buf.contains("Pong")
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn control_a_ping_is_answered() {
    let svc = Service::start();
    assert!(svc.pings(), "CONTROL: Ping not answered\n{}", svc.log());
}

/// L6, size: a client that streams bytes with no newline is cut off at a
/// limit. Today read_line buffers all of it, so every write succeeds.
#[test]
fn a_request_with_no_end_is_cut_off_at_a_limit() {
    let svc = Service::start();
    let mut s = UnixStream::connect(&svc.socket).unwrap();
    s.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    let chunk = vec![b'a'; 256 * 1024];
    let cap: usize = 32 * 1024 * 1024; // far above any sane request limit
    let mut sent = 0usize;
    let mut cut_off = false;
    while sent < cap {
        match s.write(&chunk) {
            Ok(n) => sent += n,
            Err(_) => {
                cut_off = true;
                break;
            }
        }
    }
    assert!(
        cut_off,
        "L6: the service kept reading a request line with no newline for {} MiB; it must stop \
         at a fixed limit (like serve_launcher's 64 KiB take) and drop the connection",
        sent / (1024 * 1024)
    );
    drop(s);
    assert!(
        svc.pings(),
        "CONTROL: the service must still answer after cutting a client off\n{}",
        svc.log()
    );
}

/// L6, time: a client that connects and says nothing is dropped.
/// Today the handler waits for ever (this test then runs for IDLE_LIMIT).
#[test]
fn a_silent_connection_is_dropped_after_a_timeout() {
    let svc = Service::start();
    let mut s = UnixStream::connect(&svc.socket).unwrap();
    s.set_read_timeout(Some(IDLE_LIMIT)).unwrap();
    let start = Instant::now();
    let mut buf = [0u8; 256];
    let outcome = s.read(&mut buf);
    let waited = start.elapsed();
    let dropped = match &outcome {
        Ok(_) => true,
        Err(e) => !matches!(
            e.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ),
    };
    assert!(
        dropped,
        "L6: a connection that sent nothing was still held after {waited:?}; the service must \
         time the read out (within {IDLE_LIMIT:?}) and drop it"
    );
    assert!(svc.pings(), "CONTROL: service must still answer");
}

/// L6, threads: when no thread can be started, the connection is refused
/// and the service survives. The test lowers the service's own
/// RLIMIT_NPROC to 1 (the account already has more processes, so every
/// clone fails with EAGAIN), connects, then restores the limit.
/// Today the accept loop's thread::spawn panics and the service exits.
#[test]
fn when_a_thread_cannot_start_the_connection_is_refused_not_the_service_killed() {
    let mut svc = Service::start();
    assert!(svc.pings(), "CONTROL: service up");
    let pid = svc.child.id() as libc::pid_t;
    // Returns whether the limit was set; a service that has already died
    // (the failure under test) cannot be, and that is reported below.
    let set = |soft: libc::rlim_t| -> bool {
        let mut cur = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: plain syscalls on a child of ours, with valid pointers.
        unsafe {
            if libc::prlimit(pid, libc::RLIMIT_NPROC, std::ptr::null(), &mut cur) != 0 {
                return false;
            }
            let new = libc::rlimit {
                rlim_cur: soft.min(cur.rlim_max),
                rlim_max: cur.rlim_max,
            };
            libc::prlimit(pid, libc::RLIMIT_NPROC, &new, std::ptr::null_mut()) == 0
        }
    };
    assert!(set(1), "CONTROL: could not set the service's process limit");
    // A connection while no thread can start. Whatever the client sees
    // (an error line or a plain close), it must not hang.
    if let Ok(mut s) = UnixStream::connect(&svc.socket) {
        let _ = s.set_read_timeout(Some(Duration::from_secs(3)));
        let _ = s.write_all(b"{\"type\":\"Ping\"}\n");
        let mut buf = [0u8; 256];
        let _ = s.read(&mut buf);
    }
    std::thread::sleep(Duration::from_millis(300));
    let exited = svc.child.try_wait().unwrap();
    let _ = set(libc::RLIM_INFINITY);
    assert!(
        exited.is_none(),
        "L6: the service exited ({exited:?}) when a connection thread could not start; it must \
         refuse that connection and keep running\n{}",
        svc.log()
    );
    assert!(
        svc.pings(),
        "L6: after threads are available again the service must answer\n{}",
        svc.log()
    );
}
