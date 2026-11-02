//! Re-check low P1 (leftover): plus-addressing must not get round the person
//! check for a session's commit author. `dana+x@example.invalid` is signed
//! although `dana@example.invalid` is refused. The rule to build: strip a
//! "+tag" from the local part before both the whole-address comparison and the
//! name-slug check (after NFKC and case folding), for the `[human]` email and
//! the `[identity] people` emails alike. Written before the fix, as its eval,
//! by an agent other than the builder. Harness copied from
//! `test_rechecks_lows_signd.rs` (a test file cannot import another).
//!
//! Run on hetzner, never on the Mac:
//! `cargo test --locked --test test_rechecks_lows_plus`.

#![cfg(target_os = "linux")]

use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use base64::Engine;

use agent_sign::protocol::{Request, Response};
use agent_sign::session::{Channel, read_line_with_fd};
use tempfile::TempDir;

struct World {
    _dir: TempDir,
    home: PathBuf,
    socket: PathBuf,
    service: Option<Child>,
}

impl Drop for World {
    fn drop(&mut self) {
        if let Some(mut service) = self.service.take() {
            let _ = service.kill();
            let _ = service.wait();
        }
    }
}

fn cleaned_path() -> OsString {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let kept: Vec<PathBuf> = std::env::split_paths(&path)
        .filter(|p| !p.to_string_lossy().contains(".agent-sign"))
        .collect();
    std::env::join_paths(kept).unwrap()
}

fn base(program: &Path, home: &Path, socket: &Path) -> Command {
    let mut cmd = Command::new(program);
    cmd.env_clear()
        .env("HOME", home)
        .env("PATH", cleaned_path())
        .env("TZ", "UTC")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("AGENT_SIGN_SOCKET", socket)
        .env("AGENT_SIGN_CONNECT_WAIT_MS", "200")
        .stdin(Stdio::null());
    if let Some(tmp) = std::env::var_os("TMPDIR") {
        cmd.env("TMPDIR", tmp);
    }
    cmd
}

impl World {
    fn with_config(config: &str) -> World {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        fs::create_dir_all(home.join(".agent-sign")).unwrap();
        fs::write(home.join(".agent-sign/config.toml"), config).unwrap();
        let socket = home.join("s.sock");
        let log = fs::File::create(home.join("service.log")).unwrap();
        let mut service = base(Path::new(env!("CARGO_BIN_EXE_agent-signd")), &home, &socket)
            .arg("--socket")
            .arg(&socket)
            .arg("--auto-approve")
            .env("AGENT_SIGN_TEST_AUTH", "fail")
            .env("AGENT_SIGN_REFUSAL_BACKOFF", "none")
            .stdout(Stdio::null())
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap();
        let start = Instant::now();
        while !socket.exists() {
            if let Some(status) = service.try_wait().unwrap() {
                panic!("CONTROL: the service stopped at start ({status})");
            }
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "CONTROL: the service didn't open its socket"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        World {
            _dir: dir,
            home,
            socket,
            service: Some(service),
        }
    }

    fn service_log(&self) -> String {
        fs::read_to_string(self.home.join("service.log")).unwrap_or_default()
    }

    /// A repository with one (empty) commit on branch `work`; its empty
    /// tree is then an object the service's content check can find.
    fn repo(&self) -> PathBuf {
        let repo = self.home.join("repo");
        fs::create_dir_all(&repo).unwrap();
        for args in [
            &["init", "-q", "-b", "work"][..],
            &[
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-q",
                "--allow-empty",
                "-m",
                "base",
            ][..],
        ] {
            let out = base(Path::new("git"), &self.home, &self.socket)
                .args(["-c", "user.name=T", "-c", "user.email=t@example.com"])
                .args(args)
                .current_dir(&repo)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "setup git {args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        repo.canonicalize().unwrap()
    }

    /// Plays the launcher: asks for a session as `agent`; the session lasts
    /// while the returned registration is open.
    fn start_session(&self, agent: &str) -> (String, OwnedFd, UnixStream) {
        let mut registration = UnixStream::connect(&self.socket).unwrap();
        let req = serde_json::to_string(&Request::LaunchSession {
            agent: agent.into(),
        })
        .unwrap();
        registration
            .write_all(format!("{req}\n").as_bytes())
            .unwrap();
        let (line, fd) = read_line_with_fd(&registration).unwrap();
        match serde_json::from_str::<Response>(&line) {
            Ok(Response::SessionStarted { principal, .. }) => (
                principal,
                fd.expect("the answer came with the session's channel"),
                registration,
            ),
            other => panic!("CONTROL: no session was started: {other:?}\n{line}"),
        }
    }
}

fn commit_buffer(author: &str, committer: &str) -> Vec<u8> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    format!(
        "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\nauthor Agent <{author}> {now} +0000\n\
         committer Agent <{committer}> {now} +0000\n\nan agent's commit\n"
    )
    .into_bytes()
}

const CONFIG: &str = "[identity]\nmachine = \"hetzner\"\npeople = [\"Taylor\", \"王芳@people.example.org\"]\n\n\
                      [human]\nname = \"Dana Example\"\nemail = \"pat@human.example.org\"\n";

/// P1. Controls: a stranger's plain and plus-addressed authors are signed; the
/// plain forms of the person's name slug, the `[human]` email and the people
/// entry's email are refused. Then each plus-addressed form is refused with a
/// message that names the author: of the `[human]` email, of the people entry's
/// email (also upper-case and fullwidth), and of a person's name-slug address
/// (`dana+x@`, `taylor+x@`, an upper-case local part). A stranger with a plus
/// tag, including at the person's own domain, still signs.
#[test]
fn p1_plus_addressed_authors_of_a_person_are_refused_and_strangers_still_sign() {
    let w = World::with_config(CONFIG);
    let repo = w.repo();
    let repo_s = repo.to_string_lossy().into_owned();
    let (principal, fd, _registration) = w.start_session("claude-code");
    let channel = Channel::check(fd.as_raw_fd()).expect("CONTROL: a session channel checks out");
    let identity = match channel.ask(&Request::SessionIdentity).unwrap() {
        Response::SessionIdentity { identity } => identity,
        other => panic!("CONTROL: no session identity: {other:?}"),
    };
    match channel
        .ask(&Request::RequestLease {
            repo: repo_s.clone(),
            branch: "work".into(),
            intent: "test".into(),
            duration_secs: Some(600),
        })
        .unwrap()
    {
        Response::LeaseGranted { .. } => {}
        other => panic!("CONTROL: no lease on the channel: {other:?}"),
    }
    let token = match channel
        .ask(&Request::IssueRunToken {
            repo: repo_s.clone(),
            branch: "work".into(),
            identity: identity.clone(),
        })
        .unwrap()
    {
        Response::TokenIssued { token } => token,
        other => panic!("CONTROL: no run token: {other:?}"),
    };
    let sign = |email: &str| -> Response {
        let buffer = String::from_utf8(commit_buffer(email, &principal))
            .unwrap()
            .replacen("author Agent <", "author Someone Else <", 1)
            .into_bytes();
        channel
            .ask(&Request::SignCommit {
                token: token.clone(),
                buffer_b64: base64::engine::general_purpose::STANDARD.encode(buffer),
                repo: Some(repo_s.clone()),
                branch: Some("work".into()),
            })
            .unwrap()
    };

    // Controls: strangers sign; the plain person forms are refused.
    for email in [
        "original.author@example.invalid",
        "original.author+x@example.invalid",
        "other+x@human.example.org",
        "other+x@people.example.org",
    ] {
        let r = sign(email);
        assert!(
            matches!(r, Response::Signed { .. }),
            "CONTROL: a stranger's author {email} was refused: {r:?}\n{}",
            w.service_log()
        );
    }
    for email in [
        "dana@example.invalid",
        "pat@human.example.org",
        "王芳@people.example.org",
    ] {
        match sign(email) {
            Response::Error { .. } => {}
            other => panic!("CONTROL: the plain person form {email} was not refused: {other:?}"),
        }
    }

    let mut bad = Vec::new();
    for (what, email) in [
        (
            "the [human] email, plus-addressed",
            "pat+x@human.example.org",
        ),
        (
            "the [human] email, plus-addressed, upper case",
            "PAT+X@HUMAN.EXAMPLE.ORG",
        ),
        (
            "the [human] email, plus-addressed, long tag",
            "pat+a.b-c_d123@human.example.org",
        ),
        (
            "the people entry's email, plus-addressed",
            "王芳+x@people.example.org",
        ),
        (
            "the people entry's email, plus-addressed, upper case domain",
            "王芳+x@PEOPLE.EXAMPLE.ORG",
        ),
        (
            "the people entry's email, plus-addressed, fullwidth domain",
            "王芳+x@\u{FF50}\u{FF45}\u{FF4F}\u{FF50}\u{FF4C}\u{FF45}.example.org",
        ),
        (
            "the person's name slug (the [human] name), plus-addressed",
            "dana+x@example.invalid",
        ),
        (
            "the person's name slug, plus-addressed, upper case",
            "DANA+X@example.invalid",
        ),
        (
            "a people name slug, plus-addressed",
            "taylor+x@example.invalid",
        ),
    ] {
        match sign(email) {
            Response::Error { message } => {
                if !message.to_lowercase().contains("author") {
                    bad.push(format!(
                        "{what}: refused, but the message doesn't name the author: {message}"
                    ));
                }
            }
            Response::Signed { .. } => bad.push(format!(
                "{what} ({email}): a session signed a commit authored with a plus-addressed person"
            )),
            other => bad.push(format!("{what}: unexpected answer {other:?}")),
        }
    }
    assert!(bad.is_empty(), "P1:\n  {}", bad.join("\n  "));
}
