//! At most one approval prompt per repository and branch; prompts withdrawn
//! when nobody is waiting on them any more; and `agent-sign pending` and
//! `agent-sign deny` to see and close them. These came from one cas test run
//! leaving about ten dialogs on the person's screen (9 Oct 2026).
//!
//! The stand-in for the owner (Touch ID) keeps its prompt open until the
//! test writes an answer. It logs each prompt it shows, and logs when the
//! service cancelled one that was still open, so a test can tell whether the
//! service closed it.

use std::fs;
use std::io::Write;
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
    }
}

fn start() -> Service {
    let dir = tempdir().unwrap();
    let home = dir.path().to_path_buf();
    let fakebin = home.join("fakebin");
    fs::create_dir_all(&fakebin).unwrap();
    let real = ["/usr/bin", "/bin", "/usr/local/bin", "/opt/homebrew/bin"]
        .iter()
        .map(|d| Path::new(d).join("git"))
        .find(|p| p.exists())
        .unwrap();
    std::os::unix::fs::symlink(real, fakebin.join("git")).unwrap();
    // Waiting approval requests exist only when the device owner approves
    // leases, which is opt-in since per-agent identities.
    fs::create_dir_all(home.join(".agent-sign")).unwrap();
    fs::write(
        home.join(".agent-sign/config.toml"),
        "[security]\napproval = \"device-owner\"\n",
    )
    .unwrap();

    let socket = home.join("s.sock");
    let child = Command::new(env!("CARGO_BIN_EXE_agent-signd"))
        .arg("--socket")
        .arg(&socket)
        .env("HOME", &home)
        .env("PATH", &fakebin)
        // The stand-in owner keeps each prompt open until the test writes an
        // answer, and logs each prompt and each cancellation.
        .env_remove("AGENT_SIGN_TEST_AUTH")
        .env("AGENT_SIGN_TEST_AUTH_ANSWER", home.join("answer"))
        .env("AGENT_SIGN_TEST_AUTH_LOG", home.join("shown"))
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
    /// A directory that looks like a git working tree (the service checks
    /// that before asking about a repository). Returns its path.
    fn repo(&self, name: &str) -> String {
        let repo = self.home.join("w").join(name);
        fs::create_dir_all(repo.join(".git")).unwrap();
        // The service checks that the branch asked about is the one checked out.
        fs::write(repo.join(".git/HEAD"), "ref: refs/heads/feat/a\n").unwrap();
        // The service names repositories by their canonical path (identity
        // review, 28 Oct 2026), as `agent-sign pending` then lists them.
        fs::canonicalize(&repo).unwrap().display().to_string()
    }

    fn times_shown(&self) -> usize {
        fs::read_to_string(self.home.join("shown"))
            .map(|s| s.lines().count())
            .unwrap_or(0)
    }

    /// How many prompts the service cancelled while they were open.
    fn times_withdrawn(&self) -> usize {
        fs::read_to_string(self.home.join("shown.withdrawn"))
            .map(|s| s.lines().count())
            .unwrap_or(0)
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

#[test]
fn many_commits_asking_at_once_share_one_prompt() {
    let s = start();
    let repo = s.repo("repo");
    let handles: Vec<_> = (0..5)
        .map(|_| {
            let socket = s.socket.clone();
            let repo = repo.clone();
            std::thread::spawn(move || ask_lease(&socket, &repo))
        })
        .collect();
    s.wait_until("all five waiting on one request", || {
        s.pending().first().is_some_and(|p| p.waiters == 5)
    });
    assert_eq!(s.pending().len(), 1);
    s.answer("allow");
    for h in handles {
        assert!(matches!(h.join().unwrap(), Response::LeaseGranted { .. }));
    }
    assert_eq!(s.times_shown(), 1);
}

#[test]
fn a_prompt_closes_when_the_commit_that_asked_has_gone() {
    let s = start();
    let mut stream = UnixStream::connect(&s.socket).unwrap();
    let request = serde_json::to_string(&Request::RequestLease {
        repo: s.repo("repo"),
        branch: "feat/a".into(),
        intent: "t".into(),
        duration_secs: None,
    })
    .unwrap();
    writeln!(stream, "{request}").unwrap();
    s.wait_until("the prompt to open", || s.times_shown() == 1);
    assert_eq!(s.times_withdrawn(), 0);

    drop(stream); // the commit's program goes away (a test timed out, say)
    s.wait_until("the prompt to close", || s.times_withdrawn() == 1);
    s.wait_until("no request left waiting", || s.pending().is_empty());
}

#[test]
fn one_commit_leaving_doesnt_close_a_prompt_another_is_waiting_on() {
    let s = start();
    let repo = s.repo("repo");
    let waiting = {
        let socket = s.socket.clone();
        let repo = repo.clone();
        std::thread::spawn(move || ask_lease(&socket, &repo))
    };
    s.wait_until("the prompt to open", || s.times_shown() == 1);
    let mut leaving = UnixStream::connect(&s.socket).unwrap();
    let request = serde_json::to_string(&Request::RequestLease {
        repo,
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
    assert_eq!(
        s.times_withdrawn(),
        0,
        "the prompt stays for the other commit"
    );
    s.answer("allow");
    assert!(matches!(
        waiting.join().unwrap(),
        Response::LeaseGranted { .. }
    ));
}

#[test]
fn deny_all_answers_every_waiting_request_and_closes_the_prompts() {
    let s = start();
    let (one, two) = (s.repo("one"), s.repo("two"));
    let waiting: Vec<_> = [one.clone(), two.clone()]
        .into_iter()
        .map(|repo| {
            let socket = s.socket.clone();
            std::thread::spawn(move || ask_lease(&socket, &repo))
        })
        .collect();
    // One prompt at a time: one is open, the other request waits its turn.
    s.wait_until("two requests waiting", || s.pending().len() == 2);
    s.wait_until("one prompt open", || s.times_shown() == 1);

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
        listed.contains(&format!("{one} (feat/a)")) && listed.contains(&format!("{two} (feat/a)")),
        "{listed}"
    );

    assert!(cli(&["deny", "--all"]).status.success());
    for h in waiting {
        match h.join().unwrap() {
            Response::Error { message } => assert!(message.contains("denied"), "{message}"),
            other => panic!("expected a denial, got {other:?}"),
        }
    }
    s.wait_until("the open prompt to close", || s.times_withdrawn() == 1);
    assert!(s.pending().is_empty());
    // The request that was waiting its turn never got a prompt.
    assert_eq!(s.times_shown(), 1);
    let none_left = String::from_utf8_lossy(&cli(&["pending"]).stdout).to_string();
    assert!(
        none_left.contains("No approval requests are waiting"),
        "{none_left}"
    );
}

#[test]
fn deny_by_id_answers_only_that_request() {
    let s = start();
    let (repo_one, repo_two) = (s.repo("one"), s.repo("two"));
    let one = {
        let socket = s.socket.clone();
        let repo = repo_one.clone();
        std::thread::spawn(move || ask_lease(&socket, &repo))
    };
    let two = {
        let socket = s.socket.clone();
        let repo = repo_two.clone();
        std::thread::spawn(move || ask_lease(&socket, &repo))
    };
    s.wait_until("two requests waiting", || s.pending().len() == 2);
    s.wait_until("a prompt open", || s.times_shown() >= 1);
    let id = s
        .pending()
        .into_iter()
        .find(|p| p.repo == repo_one)
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
    s.answer("allow");
    assert!(matches!(two.join().unwrap(), Response::LeaseGranted { .. }));
}
