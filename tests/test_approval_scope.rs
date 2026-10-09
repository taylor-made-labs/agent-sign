//! What one approval covers, chosen by the person in the approval dialog:
//! this repository only, every repository under the folder that holds it, or
//! every repository on this computer (release check F9). And that after one
//! approval, further commits in that scope never ask again (check F2).
//!
//! The engine tests pin down the boundaries: a folder covers the
//! repositories inside it and nothing beside it, even a sibling whose name
//! starts the same; the most specific lease applies; protected branches stay
//! protected whatever the scope. The service tests use stand-in dialogs
//! that record each time they're shown, so no real dialog can appear.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use agent_sign::lease::{Coverage, LeaseEngine, LeasePolicy};
use agent_sign::protocol::{Request, Response, send_request};
use tempfile::tempdir;

fn engine() -> LeaseEngine {
    LeaseEngine::new(LeasePolicy {
        max_commits_per_minute: 1000,
        ..LeasePolicy::default()
    })
}

// --- The engine ---------------------------------------------------------

#[test]
fn a_repository_lease_covers_only_its_repository() {
    let mut e = engine();
    e.try_grant_lease_covering("/w/dev/app", "feat/a", "t", Coverage::Repository)
        .unwrap();
    assert!(e.issue_commit_token("/w/dev/app", "feat/a").is_ok());
    assert!(e.issue_commit_token("/w/dev/other", "feat/a").is_err());
}

#[test]
fn a_folder_lease_covers_every_repository_under_the_folder() {
    let mut e = engine();
    e.try_grant_lease_covering(
        "/w/dev/app",
        "feat/a",
        "t",
        Coverage::Folder("/w/dev".to_string()),
    )
    .unwrap();
    for repo in ["/w/dev/app", "/w/dev/other", "/w/dev/nested/deeper/repo"] {
        assert!(
            e.issue_commit_token(repo, "feat/b").is_ok(),
            "{repo} should be covered"
        );
    }
}

#[test]
fn a_folder_lease_does_not_cover_a_sibling_whose_name_starts_the_same() {
    let mut e = engine();
    e.try_grant_lease_covering(
        "/w/dev/app",
        "feat/a",
        "t",
        Coverage::Folder("/w/dev".to_string()),
    )
    .unwrap();
    for repo in [
        "/w/dev2/app",
        "/w/devtools",
        "/w/de",
        "/w",
        "/other/dev/app",
    ] {
        assert!(
            e.issue_commit_token(repo, "feat/a").is_err(),
            "{repo} must not be covered"
        );
    }
}

#[test]
fn an_everywhere_lease_covers_any_repository() {
    let mut e = engine();
    e.try_grant_lease_covering("/w/dev/app", "feat/a", "t", Coverage::Everywhere)
        .unwrap();
    assert!(e.issue_commit_token("/somewhere/else", "feat/z").is_ok());
}

#[test]
fn no_scope_ever_covers_a_protected_branch() {
    let mut e = engine();
    e.try_grant_lease_covering("/w/dev/app", "feat/a", "t", Coverage::Everywhere)
        .unwrap();
    e.try_grant_lease_covering(
        "/w/dev/app",
        "feat/a",
        "t",
        Coverage::Folder("/w".to_string()),
    )
    .unwrap();
    for branch in ["main", "master"] {
        assert!(e.issue_commit_token("/w/dev/app", branch).is_err());
    }
}

#[test]
fn the_most_specific_lease_is_the_one_used() {
    let mut e = engine();
    let folder = e
        .try_grant_lease_covering(
            "/w/dev/app",
            "feat/a",
            "t",
            Coverage::Folder("/w/dev".to_string()),
        )
        .unwrap();
    let repo = e
        .try_grant_lease_covering("/w/dev/app", "feat/a", "t", Coverage::Repository)
        .unwrap();
    assert_eq!(
        e.find_lease("/w/dev/app", "feat/a").map(|l| l.id.clone()),
        Some(repo.id)
    );
    assert_eq!(
        e.find_lease("/w/dev/other", "feat/a").map(|l| l.id.clone()),
        Some(folder.id)
    );
}

#[test]
fn with_branch_following_off_wide_scopes_are_refused() {
    let mut e = LeaseEngine::new(LeasePolicy {
        allow_branch_switching: false,
        max_commits_per_minute: 1000,
        ..LeasePolicy::default()
    });
    e.try_grant_lease_covering("/w/dev/app", "feat/a", "t", Coverage::Repository)
        .unwrap();
    // With branch following off, wider scopes aren't offered or granted.
    assert!(
        e.try_grant_lease_covering("/w/dev/app", "feat/a", "t", Coverage::Everywhere)
            .is_err()
    );
    assert!(e.issue_commit_token("/w/dev/app", "feat/b").is_err());
}

#[test]
fn revoking_by_folder_path_or_everywhere_ends_those_leases() {
    let mut e = engine();
    e.try_grant_lease_covering(
        "/w/dev/app",
        "feat/a",
        "t",
        Coverage::Folder("/w/dev".to_string()),
    )
    .unwrap();
    e.try_grant_lease_covering("/w/dev/app", "feat/a", "t", Coverage::Everywhere)
        .unwrap();

    assert!(e.revoke_lease("/w/dev"));
    assert!(e.issue_commit_token("/w/dev/other", "feat/a").is_ok()); // everywhere still
    assert!(e.revoke_lease("everywhere"));
    assert!(e.issue_commit_token("/w/dev/other", "feat/a").is_err());
    assert!(!e.revoke_lease("/w/dev"), "nothing left to revoke");
}

#[test]
fn leases_saved_before_scopes_existed_load_as_repository_leases() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("leases.json");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // The shape agent-sign and earlier agent-sign builds wrote.
    let old = serde_json::json!({
        "/w/dev/app": {
            "id": "old-1", "repo": "/w/dev/app", "branch": "feat/a",
            "intent": "t", "mode": "identity", "scope": "branch",
            "granted_at_secs": now, "last_used_at_secs": now,
            "expires_at_secs": null, "commit_count": 3
        }
    });
    fs::write(&path, old.to_string()).unwrap();

    let mut e = LeaseEngine::new_with_storage(LeasePolicy::default(), Some(path));
    assert_eq!(
        e.find_lease("/w/dev/app", "feat/a")
            .map(|l| l.coverage.clone()),
        Some(Coverage::Repository)
    );
    assert!(e.issue_commit_token("/w/dev/other", "feat/a").is_err());
}

#[test]
fn the_choices_offered_name_the_folder_and_drop_wide_scopes_when_branches_dont_follow() {
    let p = LeasePolicy::default();
    let choices = p.scope_choices("/w/dev/app");
    let labels: Vec<&str> = choices.iter().map(|(_, l)| l.as_str()).collect();
    assert_eq!(
        labels,
        [
            "This repository only",
            "Every repository under /w/dev",
            "Every repository on this computer"
        ]
    );
    assert_eq!(choices[1].0, Coverage::Folder("/w/dev".to_string()));

    let narrow = LeasePolicy {
        allow_branch_switching: false,
        ..LeasePolicy::default()
    };
    assert_eq!(narrow.scope_choices("/w/dev/app").len(), 1);
}

// --- The running service, with stand-in dialogs ---------------------------

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

fn write_script(path: &Path, body: &str) {
    fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

/// Stand-in dialogs that append a line to `log` each time they're shown and
/// answer with `choice` (the label of a scope), or deny when it's `None`.
fn stand_in_dialogs(dir: &Path, log: &Path, choice: Option<&str>) -> PathBuf {
    let fakebin = dir.join("fakebin");
    fs::create_dir_all(&fakebin).unwrap();
    let log = log.display();
    let (mac, zenity, kdialog_tag) = match choice {
        Some(label) => {
            let tag = if label.starts_with("This repository") {
                "repository"
            } else if label.starts_with("Every repository under") {
                "folder"
            } else {
                "everywhere"
            };
            (
                format!("echo '{label}'"),
                format!("echo '{label}'"),
                format!("echo {tag}"),
            )
        }
        None => ("echo false".into(), "exit 1".into(), "exit 1".into()),
    };
    write_script(
        &fakebin.join("osascript"),
        &format!("echo shown >> '{log}'\n{mac}"),
    );
    write_script(
        &fakebin.join("zenity"),
        &format!("echo shown >> '{log}'\n{zenity}"),
    );
    write_script(
        &fakebin.join("kdialog"),
        &format!("echo shown >> '{log}'\n{kdialog_tag}"),
    );
    fakebin
}

fn real_git_dir() -> &'static str {
    ["/usr/bin", "/usr/local/bin", "/opt/homebrew/bin"]
        .into_iter()
        .find(|d| Path::new(d).join("git").exists())
        .expect("git is needed for these tests")
}

fn start_service(home: &Path, fakebin: &Path) -> Service {
    let state = home.join(".agent-sign");
    fs::create_dir_all(&state).unwrap();
    fs::write(
        state.join("config.toml"),
        "[security]\nmax_commits_per_minute = 1000\n",
    )
    .unwrap();
    let socket = home.join("svc.sock");
    let child = Command::new(env!("CARGO_BIN_EXE_agent-signd"))
        .arg("--socket")
        .arg(&socket)
        .env("HOME", home)
        .env("PATH", format!("{}:{}", fakebin.display(), real_git_dir()))
        .env("DISPLAY", ":99")
        .env_remove("WAYLAND_DISPLAY")
        .env_remove("AGENT_SIGN_AUTO_APPROVE")
        .env_remove("AGENT_SIGN_AUTO_APPROVE")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to start agent-signd");
    // Wait until the service answers, not just until its socket file
    // exists: there is a moment between the two when connecting is refused.
    let start = Instant::now();
    while !matches!(send_request(&socket, &Request::Ping), Ok(Response::Pong)) {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "agent-signd did not start answering"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    Service { child, socket }
}

/// What the git wrapper does for one commit: ask for a lease, then a token.
fn commit_through_service(socket: &Path, repo: &str, branch: &str) -> Result<(), String> {
    let lease = send_request(
        socket,
        &Request::RequestLease {
            repo: repo.to_string(),
            branch: branch.to_string(),
            intent: "test".to_string(),
            duration_secs: None,
        },
    )
    .map_err(|e| e.to_string())?;
    if let Response::Error { message } = lease {
        return Err(message);
    }
    match send_request(
        socket,
        &Request::IssueToken {
            repo: repo.to_string(),
            branch: branch.to_string(),
        },
    )
    .map_err(|e| e.to_string())?
    {
        Response::TokenIssued { .. } => Ok(()),
        Response::Error { message } => Err(message),
        other => Err(format!("unexpected {other:?}")),
    }
}

fn times_shown(log: &Path) -> usize {
    fs::read_to_string(log)
        .map(|s| s.lines().count())
        .unwrap_or(0)
}

#[test]
fn one_approval_then_twenty_commits_ask_nothing_more() {
    let dir = tempdir().unwrap();
    let log = dir.path().join("dialog.log");
    let fakebin = stand_in_dialogs(dir.path(), &log, Some("This repository only"));
    let svc = start_service(dir.path(), &fakebin);

    for i in 0..20 {
        commit_through_service(&svc.socket, "/w/dev/app", "feat/a")
            .unwrap_or_else(|e| panic!("commit {i} refused: {e}"));
    }
    assert_eq!(times_shown(&log), 1);
}

#[test]
fn choosing_the_folder_covers_the_next_repository_without_asking() {
    let dir = tempdir().unwrap();
    let log = dir.path().join("dialog.log");
    let fakebin = stand_in_dialogs(dir.path(), &log, Some("Every repository under /w/dev"));
    let svc = start_service(dir.path(), &fakebin);

    commit_through_service(&svc.socket, "/w/dev/app", "feat/a").unwrap();
    commit_through_service(&svc.socket, "/w/dev/other", "feat/b").unwrap();
    assert_eq!(times_shown(&log), 1);

    // A repository outside the folder asks again. (The stand-in answers with
    // /w/dev, which isn't offered there, so that answer counts as a denial.)
    let _ = commit_through_service(&svc.socket, "/w/elsewhere/repo", "feat/a");
    assert_eq!(times_shown(&log), 2);
}

#[test]
fn choosing_this_repository_asks_again_for_the_next_one() {
    let dir = tempdir().unwrap();
    let log = dir.path().join("dialog.log");
    let fakebin = stand_in_dialogs(dir.path(), &log, Some("This repository only"));
    let svc = start_service(dir.path(), &fakebin);

    commit_through_service(&svc.socket, "/w/dev/app", "feat/a").unwrap();
    commit_through_service(&svc.socket, "/w/dev/other", "feat/a").unwrap();
    assert_eq!(times_shown(&log), 2);
}

#[test]
fn denying_in_the_scope_dialog_refuses_and_grants_nothing() {
    let dir = tempdir().unwrap();
    let log = dir.path().join("dialog.log");
    let fakebin = stand_in_dialogs(dir.path(), &log, None);
    let svc = start_service(dir.path(), &fakebin);

    let err = commit_through_service(&svc.socket, "/w/dev/app", "feat/a").unwrap_err();
    assert!(err.contains("the person denied"), "{err}");
    let listed = send_request(&svc.socket, &Request::ListLeases).unwrap();
    match listed {
        Response::LeaseList { leases } => assert!(leases.is_empty()),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn a_dialog_answer_that_matches_no_choice_is_a_denial() {
    let dir = tempdir().unwrap();
    let log = dir.path().join("dialog.log");
    let fakebin = stand_in_dialogs(
        dir.path(),
        &log,
        Some("Every repository under /not/the/folder"),
    );
    let svc = start_service(dir.path(), &fakebin);

    // The stand-in's folder label doesn't match the one offered for this
    // repository, so it can't be read as approval of anything.
    let err = commit_through_service(&svc.socket, "/w/dev/app", "feat/a").unwrap_err();
    assert!(err.contains("the person denied"), "{err}");
}

#[test]
fn leases_shows_what_a_wide_lease_covers_and_revoke_takes_the_folder_or_everywhere() {
    let dir = tempdir().unwrap();
    let log = dir.path().join("dialog.log");
    let fakebin = stand_in_dialogs(dir.path(), &log, Some("Every repository under /w/dev"));
    let svc = start_service(dir.path(), &fakebin);
    commit_through_service(&svc.socket, "/w/dev/app", "feat/a").unwrap();

    let cli = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_agent-sign"))
            .args(args)
            .current_dir(dir.path())
            .env("HOME", dir.path())
            .env("PATH", real_git_dir())
            .env("AGENT_SIGN_SOCKET", &svc.socket)
            .output()
            .unwrap()
    };

    let listed = String::from_utf8_lossy(&cli(&["leases"]).stdout).to_string();
    assert!(
        listed.contains("/w/dev  (every repository under /w/dev)"),
        "{listed}"
    );

    assert!(cli(&["revoke", "/w/dev"]).status.success());
    assert!(
        commit_through_service(&svc.socket, "/w/dev/other", "feat/a").is_err()
            || times_shown(&log) == 2,
        "after revoking, the folder asks again"
    );
    assert!(!cli(&["revoke", "/w/nothing-here"]).status.success());

    // An everywhere lease, revoked by name.
    let mut e = LeaseEngine::new(LeasePolicy::default());
    e.try_grant_lease_covering("/x/y", "feat/a", "t", Coverage::Everywhere)
        .unwrap();
    assert_eq!(e.list_leases()[0].repo, "everywhere");
    assert!(e.revoke_lease("everywhere"));
}
