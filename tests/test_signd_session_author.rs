//! F7, the author half, with a real signature (round 2 of the whole-branch
//! security review, second reviewer), written before the fix as its eval by
//! an agent other than the builder.
//!
//! The launcher-attested signing path (a launched session's run token) checks
//! one thing about who a commit names: its committer must be the session's
//! principal (`check_committer`). It never looks at the author, so a session
//! could sign a commit that reads as authored by the person, or by another
//! agent, under its own certificate. Interface I-F7-author: that path also
//! requires the commit's author email to equal the session's principal, as
//! approvals already do; otherwise it refuses with a plain message.
//!
//! These tests use one-account mode, where the service has its in-memory
//! authority and a signature is really made, as `test_sessions.rs` does for
//! its sessions (the harness pieces are copied: a test file cannot import
//! another). The system-mode side of the same rule, seen as a refusal
//! message before the closed stand-in authority, is
//! `a_sessions_commit_must_name_the_session_as_its_author` in
//! `test_signd_session_leases.rs`.
//!
//! Run on hetzner, never on the Mac:
//! `cargo test --locked --test test_signd_session_author`.

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

const CONFIG: &str = "[identity]\nmachine = \"hetzner\"\npeople = [\"Taylor\"]\n";

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
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        fs::create_dir_all(home.join(".agent-sign")).unwrap();
        fs::write(home.join(".agent-sign/config.toml"), CONFIG).unwrap();
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

/// F7, the author half. A session holds a run token (a lease and a token on
/// its own channel). The controls: a commit whose author and committer are
/// the session's principal is signed, and so is one that differs only in the
/// author's display name (the rule is on the email), and one replayed from a
/// stranger, and one replayed from an earlier session that has ended
/// (cherry-pick, rebase, amend and `am` keep the original author: DELIBERATE
/// EVAL CHANGE: strengthened, the rule was narrowed in round 2 to authors
/// that are a session running now or a person, so replays work); a commit with a wrong
/// committer is refused, naming the committer, as today. Then commits whose
/// committer is the principal but whose author is the person, another
/// agent, or a lookalike of the principal are each refused with a message
/// that names the author and the principal it must be, and no signature is
/// returned. Fails today: all of them are signed.
#[test]
fn a_sessions_commit_must_name_the_session_as_its_author() {
    let w = World::new();
    let repo = w.repo();
    let repo_s = repo.to_string_lossy().into_owned();
    let (principal, fd, _registration) = w.start_session("claude-code");
    let channel = Channel::check(fd.as_raw_fd()).expect("CONTROL: a session channel checks out");
    let identity = match channel.ask(&Request::SessionIdentity).unwrap() {
        Response::SessionIdentity { identity } => identity,
        other => panic!("CONTROL: no session identity: {other:?}"),
    };
    assert_eq!(identity.principal, principal, "CONTROL");
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

    let right = sign(&commit_buffer(&principal, &principal));
    assert!(
        matches!(right, Response::Signed { .. }),
        "CONTROL: a commit with the session as author and committer was not signed: {right:?}\n{}",
        w.service_log()
    );
    let other_name = String::from_utf8(commit_buffer(&principal, &principal))
        .unwrap()
        .replacen("author Agent <", "author Some Other Name <", 1)
        .into_bytes();
    let renamed = sign(&other_name);
    assert!(
        matches!(renamed, Response::Signed { .. }),
        "CONTROL: only the author's email is the rule; a different display name was refused: \
         {renamed:?}"
    );
    let replayed = sign(&commit_buffer(
        "original.author@example.invalid",
        &principal,
    ));
    assert!(
        matches!(replayed, Response::Signed { .. }),
        "CONTROL: a replayed commit by a stranger (not an agent, not a person this machine \
         knows) was refused: {replayed:?}"
    );
    // An earlier session of the same agent, ended: its principal is history.
    let (earlier, _fd, earlier_registration) = w.start_session("claude-code");
    drop(earlier_registration);
    let replay_of_earlier = {
        let mut result = None;
        // The service ends a session when it sees its registration close.
        for _ in 0..100 {
            match sign(&commit_buffer(&earlier, &principal)) {
                Response::Signed { .. } => {
                    result = Some(true);
                    break;
                }
                _ => std::thread::sleep(std::time::Duration::from_millis(50)),
            }
        }
        result.unwrap_or(false)
    };
    assert!(
        replay_of_earlier,
        "CONTROL: a commit replayed from an earlier session that ended ({earlier}) was refused"
    );
    let wrong_committer = sign(&commit_buffer(&principal, "taylor@example.com"));
    assert!(
        matches!(&wrong_committer, Response::Error { message } if message.contains("committer")),
        "CONTROL: a wrong committer is refused naming the committer: {wrong_committer:?}"
    );

    // DELIBERATE EVAL CHANGE: strengthened. A lookalike is now a case-changed
    // principal, since "<principal>x" is a stranger's address, which replays
    // must be allowed to carry; and "another agent" is a second live session,
    // since an agent that is not running is only history.
    let lookalike = principal.to_uppercase();
    let (other_session, _other_fd, _other_registration) = w.start_session("codex");
    for (what, author) in [
        ("the person", "taylor@example.com".to_string()),
        ("another session running now", other_session),
        ("a lookalike of the principal", lookalike),
    ] {
        match sign(&commit_buffer(&author, &principal)) {
            Response::Error { message } => {
                assert!(
                    message.to_lowercase().contains("author"),
                    "F7: the refusal of a commit authored as {what} does not name the author: \
                     {message}"
                );
                assert!(
                    message.contains(&principal),
                    "F7: the refusal does not name the principal the author must be \
                     ({principal}): {message}"
                );
            }
            other => panic!(
                "F7: a session signed a commit authored as {what} ({author}) under its own \
                 certificate; the answer was {}",
                if matches!(other, Response::Signed { .. }) {
                    "a signature".to_string()
                } else {
                    format!("{other:?}")
                }
            ),
        }
    }
}
