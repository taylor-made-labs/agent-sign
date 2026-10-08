//! A commit made while the service is starting or restarting waits for it,
//! briefly, instead of being refused (release check F8).
//!
//! Between the service removing its old socket and listening on the new one
//! there's a moment when connecting fails: the socket file is missing, or is
//! there with nothing listening yet. Measured on an M-series Mac, the service
//! answers about 85 ms after it starts. Clients retry for a short, configurable
//! wait (`AGENT_COMMITS_CONNECT_WAIT_MS`, 2 seconds by default) rather than
//! failing a commit an agent made at that moment. A service that never comes
//! back still fails the commit, after the wait.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::time::{Duration, Instant};

use agent_commits::protocol::{Request, Response, send_request_waiting};
use tempfile::tempdir;

/// Answers one request with Pong.
fn answer_one(listener: UnixListener) {
    let (stream, _) = listener.accept().unwrap();
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let mut out = stream;
    out.write_all(b"{\"type\":\"Pong\"}\n").unwrap();
}

#[test]
fn a_socket_with_nothing_listening_yet_is_waited_for() {
    let dir = tempdir().unwrap();
    let socket = dir.path().join("s.sock");
    // A socket file with no listener: what a restart leaves for a moment.
    drop(UnixListener::bind(&socket).unwrap());

    let path = socket.clone();
    let service = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        std::fs::remove_file(&path).unwrap();
        answer_one(UnixListener::bind(&path).unwrap());
    });

    let resp = send_request_waiting(&socket, &Request::Ping, Duration::from_secs(2)).unwrap();
    assert!(matches!(resp, Response::Pong));
    service.join().unwrap();
}

#[test]
fn a_missing_socket_that_appears_is_waited_for() {
    let dir = tempdir().unwrap();
    let socket = dir.path().join("s.sock");

    let path = socket.clone();
    let service = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        answer_one(UnixListener::bind(&path).unwrap());
    });

    let resp = send_request_waiting(&socket, &Request::Ping, Duration::from_secs(2)).unwrap();
    assert!(matches!(resp, Response::Pong));
    service.join().unwrap();
}

#[test]
fn a_service_that_never_comes_back_fails_after_the_wait() {
    let dir = tempdir().unwrap();
    let socket = dir.path().join("s.sock");

    let start = Instant::now();
    let err = send_request_waiting(&socket, &Request::Ping, Duration::from_millis(300));
    let waited = start.elapsed();
    assert!(err.is_err());
    assert!(
        waited >= Duration::from_millis(300),
        "gave up early: {waited:?}"
    );
    assert!(
        waited < Duration::from_secs(2),
        "waited too long: {waited:?}"
    );
}

#[test]
fn no_wait_fails_at_once() {
    let dir = tempdir().unwrap();
    let socket = dir.path().join("s.sock");
    let start = Instant::now();
    assert!(send_request_waiting(&socket, &Request::Ping, Duration::ZERO).is_err());
    assert!(start.elapsed() < Duration::from_millis(100));
}
