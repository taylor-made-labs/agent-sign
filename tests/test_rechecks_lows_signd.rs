//! Re-check low R3, the service half: a session's commit whose author email is
//! a person's email is refused, not only one whose local part is a person's
//! name. Written before the fix, as its eval, by an agent other than the
//! builder.
//!
//! The rule today (`check_author` in agent_signd) refuses an author when the
//! local part of its email, slugged, is one of the people the service knows,
//! or when it is another live session's principal. The narrowed rule accepted
//! by the PM extends the person check to people's email addresses: the
//! `[human]` section's email and any people emails the config knows, compared
//! case-insensitively after NFKC, as the name check is. The case that tells
//! the new rule from the old: a `[human]` email whose local part has no ASCII
//! letters or digits (here Chinese characters), so its slug is empty and the
//! name check cannot see it, written in plain, upper-case and fullwidth forms.
//! The display name on the author line is free (here "Someone Else").
//!
//! One-account mode, a real signature, as `test_signd_session_author.rs` does
//! (the harness is copied: a test file cannot import another).
//!
//! Run on hetzner, never on the Mac:
//! `cargo test --locked --test test_rechecks_lows_signd`.

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
    fn new() -> World {
        World::with_config(CONFIG)
    }

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

const CONFIG: &str = "[identity]\nmachine = \"hetzner\"\npeople = [\"Taylor\"]\n\n\
                      [human]\nname = \"Dana Example\"\nemail = \"李明@example.org\"\n";

/// R3, the service half. A session holds a run token. Controls: a commit by a
/// stranger is signed; a commit whose author is the person's *name* slug (the
/// old rule) is refused. Then a commit whose author email is the `[human]`
/// email (the display name is different) is refused, with a message that names
/// the author; so is the same email in other letter case and in fullwidth
/// forms (NFKC); and no signature comes back for any of them.
///
/// Red today: the `[human]` email is not compared as a whole, only its local
/// part as a name, which for this email is empty; all three are signed.
#[test]
fn r3_a_sessions_commit_authored_with_the_humans_email_is_refused() {
    let w = World::new();
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
    let sign = |buffer: &[u8]| -> Response {
        channel
            .ask(&Request::SignCommit {
                token: token.clone(),
                buffer_b64: base64::engine::general_purpose::STANDARD.encode(buffer),
                repo: Some(repo_s.clone()),
                branch: Some("work".into()),
            })
            .unwrap()
    };
    let named = |email: &str| -> Vec<u8> {
        String::from_utf8(commit_buffer(email, &principal))
            .unwrap()
            .replacen("author Agent <", "author Someone Else <", 1)
            .into_bytes()
    };

    // Controls.
    let stranger = sign(&named("original.author@example.invalid"));
    assert!(
        matches!(stranger, Response::Signed { .. }),
        "CONTROL: a stranger's replayed commit was refused: {stranger:?}\n{}",
        w.service_log()
    );
    match sign(&named("dana@example.invalid")) {
        Response::Error { message } => assert!(
            message.to_lowercase().contains("author"),
            "CONTROL: the person-name refusal does not name the author: {message}"
        ),
        other => panic!("CONTROL: an author whose name is the person's was not refused: {other:?}"),
    }

    let mut bad = Vec::new();
    for (what, email) in [
        ("the [human] email", "李明@example.org"),
        ("the [human] email in upper case", "李明@EXAMPLE.ORG"),
        (
            "the [human] email with a fullwidth domain",
            "李明@\u{FF45}\u{FF58}\u{FF41}\u{FF4D}\u{FF50}\u{FF4C}\u{FF45}.org",
        ),
    ] {
        match sign(&named(email)) {
            Response::Error { message } => {
                if !message.to_lowercase().contains("author") {
                    bad.push(format!(
                        "{what}: refused, but the message doesn't name the author: {message}"
                    ));
                }
            }
            Response::Signed { .. } => bad.push(format!(
                "{what} ({email}): a session signed a commit authored with the person's email"
            )),
            other => bad.push(format!("{what}: unexpected answer {other:?}")),
        }
    }
    assert!(bad.is_empty(), "R3:\n  {}", bad.join("\n  "));
}

/// The `[identity] people` half of the same rule (fix round: the checker
/// found no test that failed when `IdentityConfig::people_emails` returned
/// nothing). `people` lists a name and an email address; the `[human]` email
/// is a different one, so only the people entry can refuse the address below.
/// A commit authored with the people entry's address is refused in its plain,
/// upper-case and fullwidth forms, with a message that names the author; a
/// stranger's address is still signed (control), and so is the `[human]`
/// section's own address (which is refused by the other test, not this one:
/// here that section names someone else).
#[test]
fn r3_a_sessions_commit_authored_with_a_people_entry_email_is_refused() {
    let w = World::with_config(
        "[identity]\nmachine = \"hetzner\"\npeople = [\"Taylor\", \"王芳@people.example.org\"]\n\n\
         [human]\nname = \"Dana Example\"\nemail = \"dana@human.example.org\"\n",
    );
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

    let stranger = sign("original.author@example.invalid");
    assert!(
        matches!(stranger, Response::Signed { .. }),
        "CONTROL: a stranger's replayed commit was refused: {stranger:?}\n{}",
        w.service_log()
    );
    let mut bad = Vec::new();
    for (what, email) in [
        ("the people entry's email", "王芳@people.example.org"),
        (
            "the people entry's email in upper case",
            "王芳@PEOPLE.EXAMPLE.ORG",
        ),
        (
            "the people entry's email with a fullwidth domain",
            "王芳@\u{FF50}\u{FF45}\u{FF4F}\u{FF50}\u{FF4C}\u{FF45}.example.org",
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
                "{what} ({email}): a session signed a commit authored with a people entry's email"
            )),
            other => bad.push(format!("{what}: unexpected answer {other:?}")),
        }
    }
    assert!(bad.is_empty(), "R3 (people entry):\n  {}", bad.join("\n  "));
}
