//! Sessions: what the service does with a launched session's registration,
//! channel and name, checked by a client in this process that plays the
//! launcher (no sandbox needed), and what the launcher does with a name
//! that isn't allowed.
//!
//! New in build step S6 (1 Nov 2026), from the requirements of the step and
//! the critique of the build plan (finding: "tokens are bound to the
//! session, not the stream, and an ended session's channel is refused"),
//! which the earlier tests don't check directly: a session's processes that
//! outlive the launcher keep a channel, and it must be dead.
//!
//! - `an_ended_sessions_channel_tokens_and_name_are_dead`: the registration
//!   closes, and then the channel opens nothing, a token the session held
//!   signs nothing (on the channel or on the service's socket), and the
//!   plain path won't sign as the session's name, even after a restart of
//!   the service (the name is in `sessions.log`).
//! - `a_tokens_session_is_the_only_one_that_can_use_it`: a token issued on
//!   one session's channel signs nothing on another session's channel or on
//!   the service's socket, while the first session lasts.
//! - `an_agent_name_that_isnt_allowed_gets_no_session`: `--agent made-up-bot`
//!   is refused, without running the program, until `allowed_agents` lists it.
//!
//! Linux only: launched sessions need PID namespaces (see
//! `agent_sign::launch`). Isolation as in the other tests: an empty
//! environment, a temporary HOME, no git config, a socket in the temporary
//! folder, every process stopped at the end.
#![cfg(target_os = "linux")]

use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use agent_sign::protocol::{Request, Response};
use agent_sign::session::{Channel, read_line_with_fd};
use tempfile::TempDir;

const PROBE: &str = "sessions-probe";
const CONFIG: &str = "[identity]\nmachine = \"hetzner\"\n";

struct World {
    _dir: TempDir,
    home: PathBuf,
    socket: PathBuf,
    service: Option<Child>,
}

impl Drop for World {
    fn drop(&mut self) {
        self.stop_service();
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
        // DELIBERATE EVAL CHANGE (1 Nov 2026): environment only; host clock zones must not change results.
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
    fn new(config: &str) -> World {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        fs::create_dir_all(home.join(".agent-sign")).unwrap();
        fs::write(home.join(".agent-sign/config.toml"), config).unwrap();
        let socket = home.join("s.sock");
        let mut world = World {
            _dir: dir,
            home,
            socket,
            service: None,
        };
        world.start_service();
        world
    }

    fn start_service(&mut self) {
        let _ = fs::remove_file(&self.socket);
        let log = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.home.join("service.log"))
            .unwrap();
        let mut service = base(
            Path::new(env!("CARGO_BIN_EXE_agent-signd")),
            &self.home,
            &self.socket,
        )
        .arg("--socket")
        .arg(&self.socket)
        .arg("--auto-approve")
        .env("AGENT_SIGN_TEST_AUTH", "fail")
        .env("AGENT_SIGN_REFUSAL_BACKOFF", "none")
        .stdout(Stdio::null())
        .stderr(Stdio::from(log))
        .spawn()
        .unwrap();
        let start = Instant::now();
        while !self.socket.exists() {
            if let Some(status) = service.try_wait().unwrap() {
                panic!(
                    "CONTROL: the service stopped at start ({status}):\n{}",
                    fs::read_to_string(self.home.join("service.log")).unwrap_or_default()
                );
            }
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "CONTROL: the service didn't open its socket"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        self.service = Some(service);
    }

    fn stop_service(&mut self) {
        if let Some(mut service) = self.service.take() {
            let _ = service.kill();
            let _ = service.wait();
        }
    }

    fn service_log(&self) -> String {
        fs::read_to_string(self.home.join("service.log")).unwrap_or_default()
    }

    /// A repository with one commit on branch `work`.
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
            assert!(out.status.success(), "setup git {args:?}: {}", text(&out));
        }
        repo.canonicalize().unwrap()
    }

    /// Plays the launcher: asks for a session as `agent`, and returns the
    /// principal, the channel, and the registration (the session lasts while
    /// it is open).
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

    /// One request on the service's own socket (the plain path).
    fn plain(&self, req: &Request) -> Response {
        agent_sign::protocol::send_request(&self.socket, req).unwrap()
    }

    /// One CLI launch of `/bin/sh -c 'echo PROBE'` as `agent`.
    fn launch(&self, agent: &str) -> Output {
        base(
            Path::new(env!("CARGO_BIN_EXE_agent-sign")),
            &self.home,
            &self.socket,
        )
        .args(["launch", "--agent", agent, "--", "/bin/sh", "-c"])
        .arg(format!("echo {PROBE}"))
        .current_dir(&self.home)
        .output()
        .unwrap()
    }
}

fn text(out: &Output) -> String {
    format!(
        "status: {}\nstdout: {}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// Whether `r` is a refusal: an error answer, or no answer at all.
fn refused<T: std::fmt::Debug>(r: &Result<Response, T>) -> bool {
    !matches!(
        r,
        Ok(Response::Signed { .. } | Response::TokenIssued { .. })
    ) && !matches!(r, Ok(Response::Pong | Response::SessionIdentity { .. }))
}

fn sign_request(token: &str, repo: &Path) -> Request {
    Request::SignCommit {
        token: token.into(),
        buffer_b64: "dHJlZSAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwCg==".into(),
        repo: Some(repo.to_string_lossy().into_owned()),
        branch: Some("work".into()),
    }
}

/// A lease and a run token for the session on `channel`, as itself.
fn session_token(
    channel: &Channel,
    repo: &Path,
) -> (String, agent_sign::attribution::AgentIdentity) {
    let identity = match channel.ask(&Request::SessionIdentity).unwrap() {
        Response::SessionIdentity { identity } => identity,
        other => panic!("CONTROL: no session identity: {other:?}"),
    };
    let repo_s = repo.to_string_lossy().into_owned();
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
    match channel
        .ask(&Request::IssueRunToken {
            repo: repo_s,
            branch: "work".into(),
            identity: identity.clone(),
        })
        .unwrap()
    {
        Response::TokenIssued { token } => (token, identity),
        other => panic!("CONTROL: no token on the channel: {other:?}"),
    }
}

/// When the launcher's registration closes, the session ends: its channel
/// opens nothing, its tokens sign nothing, and its name is never signed
/// again by the plain path, not even after the service restarts.
#[test]
fn an_ended_sessions_channel_tokens_and_name_are_dead() {
    let mut w = World::new(CONFIG);
    let repo = w.repo();
    let (principal, fd, registration) = w.start_session("claude-code");
    let channel = Channel::check(fd.as_raw_fd()).expect("CONTROL: a session channel checks out");
    let (token, identity) = session_token(&channel, &repo);
    assert_eq!(identity.principal, principal);
    // While the session lasts the token is the session's alone: the plain
    // path refuses it.
    let plain = w.plain(&sign_request(&token, &repo));
    assert!(
        matches!(&plain, Response::Error { message } if message.contains("launched session")),
        "the service's own socket took a launched session's token: {plain:?}"
    );

    drop(registration);
    let start = Instant::now();
    while matches!(channel.ask(&Request::Ping), Ok(Response::Pong)) {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "the session's channel still answers 5 s after its registration closed"
        );
        std::thread::sleep(Duration::from_millis(20));
    }

    assert!(
        channel.open_stream().is_err() || refused(&channel.ask(&Request::SessionIdentity)),
        "an ended session's channel still gives its identity"
    );
    let on_channel = channel.ask(&sign_request(&token, &repo));
    assert!(
        refused(&on_channel),
        "an ended session's token signed on its channel: {on_channel:?}"
    );
    let on_socket = w.plain(&sign_request(&token, &repo));
    assert!(
        refused(&Ok::<_, ()>(on_socket.clone())),
        "an ended session's token signed on the service's socket: {on_socket:?}"
    );

    // The name is spent: the plain path won't sign as it, now or after a
    // restart of the service (the log keeps it).
    let ask_plain_token = |w: &World| {
        let repo_s = repo.to_string_lossy().into_owned();
        let lease = w.plain(&Request::RequestLease {
            repo: repo_s.clone(),
            branch: "work".into(),
            intent: "test".into(),
            duration_secs: Some(600),
        });
        assert!(
            matches!(lease, Response::LeaseGranted { .. }),
            "CONTROL: {lease:?}"
        );
        w.plain(&Request::IssueRunToken {
            repo: repo_s,
            branch: "work".into(),
            identity: identity.clone(),
        })
    };
    for when in ["after the session ended", "after the service restarted"] {
        let answer = ask_plain_token(&w);
        assert!(
            matches!(&answer, Response::Error { message } if message.contains("launched session")),
            "the plain path would sign as an ended session's name {when}: {answer:?}"
        );
        w.stop_service();
        w.start_service();
    }

    let log = fs::read_to_string(w.home.join(".agent-sign/sessions.log")).unwrap_or_default();
    for event in ["start", "end"] {
        assert!(
            log.lines()
                .any(|l| l.split(' ').nth(1) == Some(event) && l.contains(&principal)),
            "sessions.log has no {event} line for {principal}:\n{log}"
        );
    }
    // A new session is never the ended one's name.
    let (second, _fd, _reg) = w.start_session("claude-code");
    assert_ne!(
        second, principal,
        "a new session got an ended session's name"
    );
}

/// A token is bound to the session it was issued to (not to the stream it
/// came on): another session's channel can't use it either.
#[test]
fn a_tokens_session_is_the_only_one_that_can_use_it() {
    let w = World::new(CONFIG);
    let repo = w.repo();
    let (_p1, fd1, _reg1) = w.start_session("claude-code");
    let (_p2, fd2, _reg2) = w.start_session("codex");
    let one = Channel::check(fd1.as_raw_fd()).unwrap();
    let two = Channel::check(fd2.as_raw_fd()).unwrap();
    let (token, _) = session_token(&one, &repo);
    let elsewhere = two.ask(&sign_request(&token, &repo));
    assert!(
        matches!(&elsewhere, Ok(Response::Error { message }) if message.contains("launched session")),
        "another session's channel could use this session's token: {elsewhere:?}\n{}",
        w.service_log()
    );
    // A session may not name another identity on its own channel.
    let other = match two.ask(&Request::SessionIdentity).unwrap() {
        Response::SessionIdentity { identity } => identity,
        other => panic!("CONTROL: {other:?}"),
    };
    let named = one.ask(&Request::IssueRunToken {
        repo: repo.to_string_lossy().into_owned(),
        branch: "work".into(),
        identity: other,
    });
    assert!(
        matches!(&named, Ok(Response::Error { message }) if message.contains("signs only as itself")),
        "a session was given a token for another session's identity: {named:?}"
    );
}

/// `--agent made-up-bot` isn't an allowed name: no session, and the program
/// never runs. The control is the same name once `allowed_agents` lists it.
#[test]
fn an_agent_name_that_isnt_allowed_gets_no_session() {
    let w = World::new(CONFIG);
    let out = w.launch("made-up-bot");
    assert!(
        !out.status.success() && !String::from_utf8_lossy(&out.stdout).contains(PROBE),
        "a launch as a name that isn't allowed ran its program:\n{}",
        text(&out)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("allowed_agents"),
        "the refusal didn't say how to allow the name:\n{}",
        text(&out)
    );
    let allowed = World::new(&format!("{CONFIG}allowed_agents = [\"made-up-bot\"]\n"));
    let out = allowed.launch("made-up-bot");
    assert!(
        out.status.success() && String::from_utf8_lossy(&out.stdout).contains(PROBE),
        "CONTROL: a launch as an allowed name didn't run its program:\n{}",
        text(&out)
    );
}

/// The installer's check refuses a program that has the system-config test
/// seam in it (one-account launch is refused when a system config exists;
/// a seam that moved that path in an installed program would turn the
/// refusal off), and accepts an ordinary one.
#[test]
fn the_installer_refuses_a_program_with_the_system_config_seam() {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/check-binary-clean.sh");
    let check = |dir: &Path| Command::new("sh").arg(script).arg(dir).output().unwrap();
    let clean = tempfile::tempdir().unwrap();
    fs::write(clean.path().join("agent-sign"), b"\x7fELF ordinary program").unwrap();
    assert!(check(clean.path()).status.success(), "CONTROL");
    let dirty = tempfile::tempdir().unwrap();
    fs::write(
        dirty.path().join("agent-sign"),
        b"\x00binary\x00AGENT_SIGN_TEST_SYSTEM_CONFIG\x00more",
    )
    .unwrap();
    let out = check(dirty.path());
    assert!(!out.status.success(), "the seam was accepted");
    assert!(String::from_utf8_lossy(&out.stderr).contains("test build"));
}
