//! Round 2 of the whole-branch security review: two gaps the round-1
//! checkers found in the fix for L6 (a request line read with no limit, on a
//! socket anyone can reach), written before the round-2 fix as its eval by an
//! agent other than the builder. They add to `test_signd_request_limits.rs`
//! (round 1) and change none of its assertions.
//!
//! - **G-signd-1: a dripping client.** Round 1 tested a client that sends
//!   nothing. The risk the deadline exists for is the one that sends a byte
//!   at a time: a read timeout that restarts at every byte never fires.
//!   `REQUEST_READ_DEADLINE` counts from the first read. This test drips one
//!   byte a second and requires the connection to be dropped well before the
//!   20 s the silent-client test allows. It passes with round 1's fix (the
//!   report that came with this test shows it failing when the fix is
//!   undone: the deadline made a per-read timeout again).
//! - **G-signd-2: connection threads are unbounded in number.** Each
//!   connection has a thread and may hold up to 1 MiB of request for 10 s,
//!   so the memory a crowd of connections can pin is the number of
//!   connections times that. Round 2 caps the connections open at once, with
//!   a named constant whose doc comment gives the memory reasoning; past the
//!   cap a connection is refused (an error line, or closed), not held.
//!   The cap's value is the builder's. What a test can say without it is
//!   this: with `FLOOD` (2,500) silent connections open at once, some are
//!   refused promptly, and they were refused rather than left waiting; the
//!   cap is released when the crowd goes (the service answers again). Any
//!   cap below 2,500 passes; 2,500 threads each able to hold 1 MiB is
//!   already over 2.4 GiB, which is the bound the cap exists to prevent.
//!
//! Run on hetzner, never on the Mac:
//! `cargo test --locked --test test_signd_connection_limits`.

#![cfg(target_os = "linux")]

use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use agent_sign::protocol::Response;

/// The longest a connection that is still sending may be held. The silent
/// client test of round 1 allows this much; the builder's deadline is 10 s.
const IDLE_LIMIT: Duration = Duration::from_secs(20);

/// Silent connections opened at once in the cap test.
const FLOOD: usize = 2_500;

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

/// Raises this process's open-files limit (soft) to `want` or the hard
/// limit, whichever is lower, so that this test's crowd of connections, and
/// the service it starts after (which inherits the limit), are not stopped by
/// the default 1,024 descriptors instead of by a cap.
fn raise_open_files(want: u64) {
    let mut cur = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: plain syscalls on this process, with valid pointers.
    unsafe {
        assert_eq!(
            libc::getrlimit(libc::RLIMIT_NOFILE, &mut cur),
            0,
            "CONTROL: getrlimit"
        );
        let new = libc::rlimit {
            rlim_cur: (want as libc::rlim_t).min(cur.rlim_max),
            rlim_max: cur.rlim_max,
        };
        assert_eq!(
            libc::setrlimit(libc::RLIMIT_NOFILE, &new),
            0,
            "CONTROL: setrlimit"
        );
        assert!(
            new.rlim_cur >= want as libc::rlim_t,
            "CONTROL: this account's hard open-files limit is {}, too low for the test",
            cur.rlim_max
        );
    }
}

#[test]
fn control_a_ping_is_answered() {
    let svc = Service::start();
    assert!(svc.pings(), "CONTROL: Ping not answered\n{}", svc.log());
}

/// G-signd-1: a client that sends one byte a second, never a newline, is
/// dropped by the whole-request deadline (10 s in round 1's fix) even though
/// each read would have returned in time. The client writes a byte, then
/// listens for a second; the service sends nothing to a request it is still
/// reading, so an end of stream or a failed write is the drop. Not dropped
/// within `IDLE_LIMIT` is the failure. The few bytes sent are far under the
/// size limit, so only the deadline can stop it.
#[test]
fn a_client_dripping_one_byte_a_second_is_dropped_at_the_deadline() {
    let svc = Service::start();
    let mut s = UnixStream::connect(&svc.socket).unwrap();
    s.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    s.set_read_timeout(Some(Duration::from_millis(900)))
        .unwrap();
    let start = Instant::now();
    let mut sent = 0usize;
    let mut dropped_after = None;
    while start.elapsed() < IDLE_LIMIT + Duration::from_secs(5) {
        if s.write_all(b"a").is_err() {
            dropped_after = Some(start.elapsed());
            break;
        }
        sent += 1;
        let mut buf = [0u8; 64];
        match s.read(&mut buf) {
            // End of stream, or an answer: the service is done with us.
            Ok(_) => {
                dropped_after = Some(start.elapsed());
                break;
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(_) => {
                dropped_after = Some(start.elapsed());
                break;
            }
        }
    }
    let waited = dropped_after.unwrap_or_else(|| start.elapsed());
    assert!(
        dropped_after.is_some_and(|t| t < IDLE_LIMIT),
        "G-signd-1: a client that sent one byte a second ({sent} bytes) was still being held \
         after {waited:?}; the service's deadline must count from the first read, not restart \
         at every byte (it must drop the connection within {IDLE_LIMIT:?})"
    );
    assert!(
        svc.pings(),
        "CONTROL: the service must still answer after dropping the drip\n{}",
        svc.log()
    );
}

/// G-signd-2: the connections open at once are capped. `FLOOD` silent
/// connections are opened (each one a client that said nothing, which the
/// service holds until its 10 s deadline); within a few seconds some of
/// them must have been refused: an error line from the service, or the
/// connection closed, not left silent. The refusals that carry a line must
/// carry a service `Error`. Then the crowd is let go, and the service must
/// answer a Ping again (what the cap counted is given back). Fails today:
/// every one of the connections gets its own thread and is held.
#[test]
fn connections_past_a_cap_are_refused_not_held() {
    raise_open_files(20_000);
    let svc = Service::start();
    assert!(svc.pings(), "CONTROL: service up\n{}", svc.log());

    // Open the crowd in a thread of its own, so a service that stops
    // accepting (connections left waiting in the backlog) fails this test
    // with a message instead of hanging it.
    let (tx, rx) = mpsc::channel();
    let socket = svc.socket.clone();
    let opener = std::thread::spawn(move || {
        let mut crowd = Vec::with_capacity(FLOOD);
        for _ in 0..FLOOD {
            match UnixStream::connect(&socket) {
                Ok(s) => crowd.push(s),
                Err(e) => {
                    let _ = tx.send(Err(format!("connection {} failed: {e}", crowd.len())));
                    return crowd;
                }
            }
        }
        let _ = tx.send(Ok(()));
        crowd
    });
    let started = Instant::now();
    match rx.recv_timeout(Duration::from_secs(40)) {
        Ok(Ok(())) => {}
        Ok(Err(e)) => panic!("CONTROL: the crowd could not be opened: {e}\n{}", svc.log()),
        Err(_) => panic!(
            "G-signd-2: opening {FLOOD} connections did not finish in 40 s: connections past a \
             limit were left waiting to be accepted, not refused\n{}",
            svc.log()
        ),
    }
    let mut crowd = opener.join().unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(6),
        "CONTROL: opening the crowd took {:?}, too long to tell refusal from the 10 s deadline",
        started.elapsed()
    );
    std::thread::sleep(Duration::from_millis(1500));

    let (mut held, mut closed, mut answered, mut errors) = (0usize, 0usize, 0usize, 0usize);
    let mut sample = String::new();
    for s in crowd.iter_mut() {
        s.set_nonblocking(true).unwrap();
        let mut buf = [0u8; 4096];
        match s.read(&mut buf) {
            Ok(0) => closed += 1,
            Ok(n) => {
                answered += 1;
                let line = String::from_utf8_lossy(&buf[..n]).to_string();
                if matches!(
                    serde_json::from_str::<Response>(line.lines().next().unwrap_or("")),
                    Ok(Response::Error { .. })
                ) {
                    errors += 1;
                } else if sample.is_empty() {
                    sample = line;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => held += 1,
            Err(_) => closed += 1,
        }
    }
    let refused = closed + answered;
    drop(crowd);
    assert!(
        refused > 0,
        "G-signd-2: all {FLOOD} silent connections were held ({held} still waiting): the \
         service has no cap on connections open at once; each one is a thread that can hold \
         1 MiB for 10 s\n{}",
        svc.log()
    );
    assert_eq!(
        errors, answered,
        "G-signd-2: a refusal that carries a line must carry a service Error, but one carried \
         {sample:?} ({answered} answered, {errors} of them errors)"
    );

    // The crowd is gone: what the cap counted must be given back.
    let released = Instant::now();
    loop {
        if svc.pings() {
            break;
        }
        assert!(
            released.elapsed() < Duration::from_secs(20),
            "G-signd-2: 20 s after the crowd left, the service still refuses a Ping: the cap \
             is not released when connections end\n{}",
            svc.log()
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}
