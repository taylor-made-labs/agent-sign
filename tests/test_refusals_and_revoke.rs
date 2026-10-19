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
//! owner (Touch ID) is a stand-in, so no real prompt can appear.

use std::fs;
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

/// Starts `agent-signd` in `home` with `path` as its whole `PATH`, no terminal,
/// and `owner` as what its stand-in owner (`AGENT_SIGN_TEST_AUTH`) does.
fn start_service(home: &Path, path: &str, auto_approve: bool, owner: &str) -> Service {
    let socket = home.join("svc.sock");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_agent-signd"));
    cmd.arg("--socket")
        .arg(&socket)
        .env("HOME", home)
        .env("PATH", path)
        .env("AGENT_SIGN_TEST_AUTH", owner)
        .env_remove("AGENT_SIGN_AUTO_APPROVE")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if auto_approve {
        cmd.arg("--auto-approve");
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

/// A directory holding only a link to git, for a `PATH` with nothing else on it.
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

/// Makes the repository's `HEAD` name `branch`, as the service checks that
/// the branch it is asked about is the one checked out.
fn set_head(repo: &str, branch: &str) {
    let git = Path::new(repo).join(".git");
    if git.is_dir() {
        let _ = fs::write(git.join("HEAD"), format!("ref: refs/heads/{branch}\n"));
    }
}

fn ask_for_lease(socket: &Path, repo: &str) -> Response {
    set_head(repo, "feat/x");
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

/// A directory that looks like a git working tree (it has a `.git`), which is
/// all the service checks before asking about a repository. Returns its path.
fn fake_repo(root: &Path, rel: &str) -> String {
    let repo = root.join(rel);
    fs::create_dir_all(repo.join(".git")).unwrap();
    repo.display().to_string()
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
    let svc = start_service(dir.path(), &path, false, "unavailable");
    let repo = fake_repo(dir.path(), "some-repo");

    let message = error_message(ask_for_lease(&svc.socket, &repo));
    assert!(message.contains("couldn't ask you"), "{message}");
    assert!(message.contains("Headless machines"), "{message}");
    assert!(!message.to_lowercase().contains("rejected"), "{message}");
    assert!(!message.contains("denied"), "{message}");
}

#[test]
fn a_failed_authentication_is_not_reported_as_the_person_saying_no() {
    let dir = tempdir().unwrap();
    let path = path_with_only_git(dir.path());
    let svc = start_service(dir.path(), &path, false, "fail");
    let repo = fake_repo(dir.path(), "some-repo");

    let message = error_message(ask_for_lease(&svc.socket, &repo));
    assert!(
        message.contains("could not confirm it was you"),
        "{message}"
    );
    assert!(!message.contains("the person denied"), "{message}");
}

#[test]
fn revoking_a_repository_with_no_lease_is_an_error_not_a_success() {
    let dir = tempdir().unwrap();
    let path = path_with_only_git(dir.path());
    let svc = start_service(dir.path(), &path, true, "allow");
    let project = fake_repo(dir.path(), "work/project");

    assert!(matches!(
        ask_for_lease(&svc.socket, &project),
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
    assert!(matches!(revoke(&project), Response::Success));
    match send_request(&svc.socket, &Request::ListLeases).unwrap() {
        Response::LeaseList { leases } => assert!(leases.is_empty()),
        other => panic!("{other:?}"),
    }
}

#[test]
fn agent_sign_revoke_dot_names_the_repository_it_is_run_in() {
    let dir = tempdir().unwrap();
    let path = path_with_only_git(dir.path());
    let svc = start_service(dir.path(), &path, true, "allow");

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
