//! The launcher never starts a session under a person's or a reserved name.
//!
//! New in build step S6 (31 Oct 2026), from the critique of the build plan
//! (its last finding): `p2_reserved_names_are_never_certified_whatever_the_config_says`
//! in `test_caller_identity.rs` returns early, because a config listing
//! root or admin stops the service, so `agent-sign launch --agent taylor`
//! with `[identity] people = ["Taylor"]` was tested nowhere. Here the
//! service runs with that config, and a launch as the person, or as a
//! reserved name, exits non-zero, says why, and never runs its program; the
//! control is a launch as an ordinary agent, which runs it.
//!
//! Linux only: launched sessions need PID namespaces (see
//! `agent_sign::launch`). Isolation as in the other tests: an empty
//! environment, a temporary HOME under `TMPDIR`, no git config, a socket in
//! the temporary folder, every process stopped at the end.
#![cfg(target_os = "linux")]

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use tempfile::TempDir;

const PROBE: &str = "launch-names-probe";

struct World {
    _dir: TempDir,
    home: PathBuf,
    socket: PathBuf,
    service: Child,
}

impl Drop for World {
    fn drop(&mut self) {
        let _ = self.service.kill();
        let _ = self.service.wait();
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
                panic!(
                    "CONTROL: the service stopped at start ({status}):\n{}",
                    fs::read_to_string(home.join("service.log")).unwrap_or_default()
                );
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
            service,
        }
    }

    fn launch(&self, agent: &str) -> Output {
        let mut cmd = base(
            Path::new(env!("CARGO_BIN_EXE_agent-sign")),
            &self.home,
            &self.socket,
        );
        cmd.args(["launch", "--agent", agent, "--", "/bin/sh", "-c"])
            .arg(format!("echo {PROBE}"))
            .current_dir(&self.home)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn().unwrap();
        let start = Instant::now();
        while child.try_wait().unwrap().is_none() {
            if start.elapsed() > Duration::from_secs(30) {
                let _ = child.kill();
                panic!("the launch as {agent} didn't finish");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        child.wait_with_output().unwrap()
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

/// `--agent taylor` with `[identity] people = ["Taylor"]`, and the reserved
/// `root` and `admin`: refused before the program runs, saying it's a
/// person's name. Control: `--agent codex` runs its program.
#[test]
fn a_launch_as_a_person_or_a_reserved_name_is_refused_without_running_its_program() {
    let w = World::new("[identity]\nmachine = \"hetzner\"\npeople = [\"Taylor\"]\n");
    let control = w.launch("codex");
    assert!(
        control.status.success() && String::from_utf8_lossy(&control.stdout).contains(PROBE),
        "CONTROL: a launch as codex didn't run its program:\n{}",
        text(&control)
    );
    for name in ["taylor", "Taylor", "root", "admin"] {
        let out = w.launch(name);
        assert!(
            !out.status.success(),
            "a launch as {name} succeeded:\n{}",
            text(&out)
        );
        assert!(
            !String::from_utf8_lossy(&out.stdout).contains(PROBE),
            "a launch as {name} ran its program:\n{}",
            text(&out)
        );
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("person's name"),
            "a launch as {name} didn't say it's a person's name:\n{}",
            text(&out)
        );
    }
}

/// A launched session can't launch another session, which would let it
/// pick itself a new name: the service refuses a `LaunchSession` from a
/// process in another PID namespace. The control is the outer launch,
/// which runs its program.
#[test]
fn a_launched_session_cant_launch_another() {
    let w = World::new("[identity]\nmachine = \"hetzner\"\n");
    let mut cmd = base(
        Path::new(env!("CARGO_BIN_EXE_agent-sign")),
        &w.home,
        &w.socket,
    );
    let inner = format!(
        "echo outer-ran; '{}' launch --agent claude-code -- /bin/sh -c 'echo {PROBE}'",
        env!("CARGO_BIN_EXE_agent-sign")
    );
    cmd.args(["launch", "--agent", "codex", "--", "/bin/sh", "-c", &inner])
        .current_dir(&w.home);
    let out = cmd.output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("outer-ran"),
        "CONTROL: the outer launch didn't run its program:\n{}",
        text(&out)
    );
    assert!(
        !stdout.contains(PROBE),
        "a launched session launched another session:\n{}",
        text(&out)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("can't launch another session"),
        "the nested launch wasn't refused for being inside a session:\n{}",
        text(&out)
    );
}
