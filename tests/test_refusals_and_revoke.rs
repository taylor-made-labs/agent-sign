//! What the person and the agent are told when a lease is refused or revoked,
//! and what `agent-sign doctor` advises. Each case came from following
//! `docs/INSTALL.md` on a clean home on a Raspberry Pi (30 Sept 2026):
//!
//! - With no screen and no terminal, `agent-signd` couldn't ask anyone, but the
//!   agent was told "Human rejected the signing lease request".
//! - `agent-sign revoke project` and `agent-sign revoke .` printed "Lease revoked" while
//!   the lease stayed in force: the service answered success whether or not
//!   anything matched, and the CLI passed the argument through unresolved.
//! - `agent-sign doctor` warned that `gpg.format` wasn't `ssh` and advised setting it
//!   globally, which would switch the person's own signing; agent commits
//!   don't need it.
//!
//! Every service here runs in a temporary home with its own socket, and the
//! dialogs are stand-ins or absent, so no real dialog can appear.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use agent_sign::protocol::{Request, Response, send_request};
use tempfile::tempdir;

struct Service {
    child: Child,
    socket: PathBuf,
}

impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Starts `agent-signd` in `home` with `path` as its whole `PATH`, no display, and
/// no terminal.
fn start_service(home: &Path, path: &str, auto_approve: bool, display: bool) -> Service {
    let socket = home.join("svc.sock");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_agent-signd"));
    cmd.arg("--socket")
        .arg(&socket)
        .env("HOME", home)
        .env("PATH", path)
        .env_remove("DISPLAY")
        .env_remove("WAYLAND_DISPLAY")
        .env_remove("AGENT_SIGN_AUTO_APPROVE")
        .env_remove("AGENT_SIGN_AUTO_APPROVE")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if auto_approve {
        cmd.arg("--auto-approve");
    }
    if display {
        cmd.env("DISPLAY", ":99");
    }
    let child = cmd.spawn().expect("Failed to start agent-signd");
    let start = Instant::now();
    while !socket.exists() {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "agent-signd did not create its socket"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    Service { child, socket }
}

/// A directory holding only a link to git, for a `PATH` on which no dialog
/// program can be found.
fn path_with_only_git(dir: &Path) -> String {
    let bin = dir.join("only-git");
    fs::create_dir_all(&bin).unwrap();
    let git = [
        "/usr/bin/git",
        "/usr/local/bin/git",
        "/opt/homebrew/bin/git",
    ]
    .into_iter()
    .find(|p| Path::new(p).exists())
    .expect("git is needed for these tests");
    std::os::unix::fs::symlink(git, bin.join("git")).unwrap();
    bin.display().to_string()
}

fn write_script(path: &Path, body: &str) {
    fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

fn ask_for_lease(socket: &Path, repo: &str) -> Response {
    send_request(
        socket,
        &Request::RequestLease {
            repo: repo.to_string(),
            branch: "feat/x".to_string(),
            intent: "test".to_string(),
            duration_secs: None,
        },
    )
    .expect("request failed")
}

fn error_message(resp: Response) -> String {
    match resp {
        Response::Error { message } => message,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn a_service_that_cannot_ask_says_so_instead_of_blaming_the_person() {
    let dir = tempdir().unwrap();
    let path = path_with_only_git(dir.path());
    let svc = start_service(dir.path(), &path, false, false);

    let message = error_message(ask_for_lease(&svc.socket, "/tmp/some-repo"));
    assert!(message.contains("couldn't ask you"), "{message}");
    assert!(message.contains("Headless machines"), "{message}");
    assert!(!message.to_lowercase().contains("rejected"), "{message}");
    assert!(!message.contains("denied"), "{message}");
}

#[test]
fn a_denial_is_reported_as_the_persons() {
    let dir = tempdir().unwrap();
    let fakebin = dir.path().join("fakebin");
    fs::create_dir_all(&fakebin).unwrap();
    // Stand-ins that answer "Deny": osascript on macOS, zenity on Linux
    // (tried because DISPLAY is set).
    write_script(&fakebin.join("osascript"), "echo 'button returned:Deny'");
    write_script(&fakebin.join("zenity"), "exit 1");
    write_script(&fakebin.join("kdialog"), "exit 1");
    let path = format!("{}:{}", fakebin.display(), path_with_only_git(dir.path()));
    let svc = start_service(dir.path(), &path, false, true);

    let message = error_message(ask_for_lease(&svc.socket, "/tmp/some-repo"));
    assert!(message.contains("the person denied"), "{message}");
}

#[test]
fn revoking_a_repository_with_no_lease_is_an_error_not_a_success() {
    let dir = tempdir().unwrap();
    let path = path_with_only_git(dir.path());
    let svc = start_service(dir.path(), &path, true, false);

    assert!(matches!(
        ask_for_lease(&svc.socket, "/work/project"),
        Response::LeaseGranted { .. }
    ));

    let revoke = |repo: &str| {
        send_request(
            &svc.socket,
            &Request::RevokeLease {
                repo: repo.to_string(),
                branch: None,
                all: false,
            },
        )
        .unwrap()
    };

    // A short name doesn't match: refused, and the lease stays.
    let message = error_message(revoke("project"));
    assert!(message.contains("no lease for 'project'"), "{message}");
    match send_request(&svc.socket, &Request::ListLeases).unwrap() {
        Response::LeaseList { leases } => assert_eq!(leases.len(), 1),
        other => panic!("{other:?}"),
    }

    // The full path revokes it.
    assert!(matches!(revoke("/work/project"), Response::Success));
    match send_request(&svc.socket, &Request::ListLeases).unwrap() {
        Response::LeaseList { leases } => assert!(leases.is_empty()),
        other => panic!("{other:?}"),
    }
}

#[test]
fn agent_sign_revoke_dot_names_the_repository_it_is_run_in() {
    let dir = tempdir().unwrap();
    let path = path_with_only_git(dir.path());
    let svc = start_service(dir.path(), &path, true, false);

    // A repository, and a lease under the key the git wrapper uses: the
    // canonical path of its top level.
    let repo = dir.path().join("project");
    let sub = repo.join("src");
    fs::create_dir_all(&sub).unwrap();
    let init = Command::new("git")
        .args(["init", "-q"])
        .current_dir(&repo)
        .env("PATH", &path)
        .status()
        .unwrap();
    assert!(init.success());
    let key = fs::canonicalize(&repo).unwrap().display().to_string();
    assert!(matches!(
        ask_for_lease(&svc.socket, &key),
        Response::LeaseGranted { .. }
    ));

    let cli = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_agent-sign"))
            .args(args)
            .current_dir(&sub)
            .env("HOME", dir.path())
            .env("PATH", &path)
            .env("AGENT_SIGN_SOCKET", &svc.socket)
            .output()
            .unwrap()
    };

    // `agent-sign leases` shows the full path, the one `agent-sign revoke` takes.
    let listed = String::from_utf8_lossy(&cli(&["leases"]).stdout).to_string();
    assert!(listed.contains(&key), "{listed}");

    // A name that isn't the repository fails, and says so.
    let wrong = cli(&["revoke", "project"]);
    assert!(!wrong.status.success());
    assert!(String::from_utf8_lossy(&wrong.stderr).contains("no lease for 'project'"));

    // "." from a subdirectory is the repository.
    let out = cli(&["revoke", "."]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let listed = String::from_utf8_lossy(&cli(&["leases"]).stdout).to_string();
    assert!(listed.contains("No active agent leases"), "{listed}");
}

#[test]
fn doctor_does_not_advise_changing_the_persons_own_signing_format() {
    let dir = tempdir().unwrap();
    let path = path_with_only_git(dir.path());
    let out = Command::new(env!("CARGO_BIN_EXE_agent-sign"))
        .arg("doctor")
        .env("HOME", dir.path())
        .env("XDG_CONFIG_HOME", dir.path().join(".config"))
        .env("PATH", &path)
        .env("AGENT_SIGN_SOCKET", dir.path().join("no-service.sock"))
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("Your own git signing format: not set"),
        "{text}"
    );
    assert!(!text.contains("gpg.format ssh"), "{text}");
}
