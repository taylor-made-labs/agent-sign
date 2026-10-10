//! At most one approval dialog per repository and branch; dialogs withdrawn
//! when nobody is waiting on them any more; and `agent-sign pending` and
//! `agent-sign deny` to see and close them. These came from one cas test run
//! leaving about ten dialogs on the person's screen (9 Oct 2026).
//!
//! The stand-in dialog stays open until the test writes an answer, or until
//! it's killed. It records its process ID, so a test can tell whether the
//! service closed it.

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use agent_sign::protocol::{Request, Response, send_request};
use tempfile::{TempDir, tempdir};

struct Service {
    _dir: TempDir,
    home: PathBuf,
    socket: PathBuf,
    child: Child,
}

impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        // Stop any stand-in dialog still open, rather than leave it behind.
        for pid in self.dialog_pids() {
            let _ = Command::new("kill")
                .arg(pid.to_string())
                .stderr(Stdio::null())
                .status();
        }
    }
}

fn write_script(path: &Path, body: &str) {
    fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

fn start() -> Service {
    let dir = tempdir().unwrap();
    let home = dir.path().to_path_buf();
    let fakebin = home.join("fakebin");
    fs::create_dir_all(&fakebin).unwrap();
    for tool in ["git", "sleep"] {
        let real = ["/usr/bin", "/bin", "/usr/local/bin", "/opt/homebrew/bin"]
            .iter()
            .map(|d| Path::new(d).join(tool))
            .find(|p| p.exists())
            .unwrap();
        std::os::unix::fs::symlink(real, fakebin.join(tool)).unwrap();
    }
    let (pids, log, answer) = (home.join("pids"), home.join("shown"), home.join("answer"));
    // Waits for an answer to be written, then gives it, as the real dialog
    // would when the person clicks. It gives up when its home is gone or
    // `sleep` fails, so it can never outlive the test spinning.
    let body = format!(
        "echo $$ >> '{pids}'\necho shown >> '{log}'\nwhile [ ! -f '{answer}' ]; do [ -d '{home}' ] || exit 1; sleep 0.1 || exit 1; done\nread -r A < '{answer}'\n[ \"$A\" = false ] && {{ echo false; exit 1; }}\necho \"$A\"",
        pids = pids.display(),
        log = log.display(),
        answer = answer.display(),
        home = home.display(),
    );
    write_script(&fakebin.join("osascript"), &body);
    write_script(&fakebin.join("zenity"), &body);

    let socket = home.join("s.sock");
    let child = Command::new(env!("CARGO_BIN_EXE_agent-signd"))
        .arg("--socket")
        .arg(&socket)
        .env("HOME", &home)
        .env("PATH", &fakebin)
        .env("DISPLAY", ":99")
        .env_remove("AGENT_SIGN_AUTO_APPROVE")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let start = Instant::now();
    while !matches!(send_request(&socket, &Request::Ping), Ok(Response::Pong)) {
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "service didn't start"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    Service {
        _dir: dir,
        home,
        socket,
        child,
    }
}

impl Service {
    fn times_shown(&self) -> usize {
        fs::read_to_string(self.home.join("shown"))
            .map(|s| s.lines().count())
            .unwrap_or(0)
    }

    fn dialog_pids(&self) -> Vec<i32> {
        fs::read_to_string(self.home.join("pids"))
            .unwrap_or_default()
            .lines()
            .filter_map(|l| l.trim().parse().ok())
            .collect()
    }

    fn answer(&self, answer: &str) {
        fs::write(self.home.join("answer"), answer).unwrap();
    }

    fn pending(&self) -> Vec<agent_sign::protocol::PendingInfo> {
        match send_request(&self.socket, &Request::ListPending).unwrap() {
            Response::PendingList { pending } => pending,
            other => panic!("unexpected {other:?}"),
        }
    }

    fn wait_until(&self, what: &str, done: impl Fn() -> bool) {
        let start = Instant::now();
        while !done() {
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "timed out waiting: {what}"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

fn ask_lease(socket: &Path, repo: &str) -> Response {
    send_request(
        socket,
        &Request::RequestLease {
            repo: repo.to_string(),
            branch: "feat/a".to_string(),
            intent: "t".to_string(),
            duration_secs: None,
        },
    )
    .unwrap()
}

fn process_alive(pid: i32) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[test]
fn many_commits_asking_at_once_share_one_dialog() {
    let s = start();
    let handles: Vec<_> = (0..5)
        .map(|_| {
            let socket = s.socket.clone();
            std::thread::spawn(move || ask_lease(&socket, "/w/repo"))
        })
        .collect();
    s.wait_until("all five waiting on one request", || {
        s.pending().first().is_some_and(|p| p.waiters == 5)
    });
    assert_eq!(s.pending().len(), 1);
    s.answer("This repository only");
    for h in handles {
        assert!(matches!(h.join().unwrap(), Response::LeaseGranted { .. }));
    }
    assert_eq!(s.times_shown(), 1);
}

#[test]
fn a_dialog_closes_when_the_commit_that_asked_has_gone() {
    let s = start();
    let mut stream = UnixStream::connect(&s.socket).unwrap();
    let request = serde_json::to_string(&Request::RequestLease {
        repo: "/w/repo".into(),
        branch: "feat/a".into(),
        intent: "t".into(),
        duration_secs: None,
    })
    .unwrap();
    writeln!(stream, "{request}").unwrap();
    s.wait_until("the dialog to open", || s.times_shown() == 1);
    let pid = s.dialog_pids()[0];
    assert!(process_alive(pid));

    drop(stream); // the commit's program goes away (a test timed out, say)
    s.wait_until("the dialog to close", || !process_alive(pid));
    s.wait_until("no request left waiting", || s.pending().is_empty());
}

#[test]
fn one_commit_leaving_doesnt_close_a_dialog_another_is_waiting_on() {
    let s = start();
    let waiting = {
        let socket = s.socket.clone();
        std::thread::spawn(move || ask_lease(&socket, "/w/repo"))
    };
    s.wait_until("the dialog to open", || s.times_shown() == 1);
    let mut leaving = UnixStream::connect(&s.socket).unwrap();
    let request = serde_json::to_string(&Request::RequestLease {
        repo: "/w/repo".into(),
        branch: "feat/a".into(),
        intent: "t".into(),
        duration_secs: None,
    })
    .unwrap();
    writeln!(leaving, "{request}").unwrap();
    s.wait_until("two waiting", || {
        s.pending().first().is_some_and(|p| p.waiters == 2)
    });
    drop(leaving);
    s.wait_until("one waiting", || {
        s.pending().first().is_some_and(|p| p.waiters == 1)
    });
    assert!(
        process_alive(s.dialog_pids()[0]),
        "the dialog stays for the other commit"
    );
    s.answer("This repository only");
    assert!(matches!(
        waiting.join().unwrap(),
        Response::LeaseGranted { .. }
    ));
}

#[test]
fn deny_all_answers_every_waiting_request_and_closes_the_dialogs() {
    let s = start();
    let waiting: Vec<_> = ["/w/one", "/w/two"]
        .into_iter()
        .map(|repo| {
            let socket = s.socket.clone();
            std::thread::spawn(move || ask_lease(&socket, repo))
        })
        .collect();
    s.wait_until("two dialogs open", || s.times_shown() == 2);

    let cli = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_agent-sign"))
            .args(args)
            .env("HOME", &s.home)
            .env("AGENT_SIGN_SOCKET", &s.socket)
            .output()
            .unwrap()
    };
    let listed = String::from_utf8_lossy(&cli(&["pending"]).stdout).to_string();
    assert!(
        listed.contains("/w/one (feat/a)") && listed.contains("/w/two (feat/a)"),
        "{listed}"
    );

    assert!(cli(&["deny", "--all"]).status.success());
    for h in waiting {
        match h.join().unwrap() {
            Response::Error { message } => assert!(message.contains("denied"), "{message}"),
            other => panic!("expected a denial, got {other:?}"),
        }
    }
    for pid in s.dialog_pids() {
        s.wait_until("each dialog to close", || !process_alive(pid));
    }
    assert!(s.pending().is_empty());
    let none_left = String::from_utf8_lossy(&cli(&["pending"]).stdout).to_string();
    assert!(
        none_left.contains("No approval requests are waiting"),
        "{none_left}"
    );
}

#[test]
fn deny_by_id_answers_only_that_request() {
    let s = start();
    let one = {
        let socket = s.socket.clone();
        std::thread::spawn(move || ask_lease(&socket, "/w/one"))
    };
    let two = {
        let socket = s.socket.clone();
        std::thread::spawn(move || ask_lease(&socket, "/w/two"))
    };
    s.wait_until("two dialogs open", || s.times_shown() == 2);
    let id = s
        .pending()
        .into_iter()
        .find(|p| p.repo == "/w/one")
        .unwrap()
        .id;
    assert!(matches!(
        send_request(
            &s.socket,
            &Request::DenyPending {
                id: Some(id),
                all: false
            }
        )
        .unwrap(),
        Response::Success
    ));
    assert!(matches!(one.join().unwrap(), Response::Error { .. }));
    assert_eq!(s.pending().len(), 1);
    s.answer("This repository only");
    assert!(matches!(two.join().unwrap(), Response::LeaseGranted { .. }));
}
