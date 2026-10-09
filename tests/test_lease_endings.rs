//! Every lease ends: when the work it was approved for is merged or deleted,
//! after the idle backstop, or when revoked. None lasts forever, which every
//! approval on the 30 Sept build did.
//!
//! The git checks run against real throwaway repositories, with git isolated
//! from the machine's own config.

use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use agent_sign::config::{LeaseMode, LeaseScope};
use agent_sign::lease::{Coverage, Lease, LeaseEngine, LeasePolicy, Work, current_epoch_secs};
use agent_sign::work::{WorkState, branch_tip, work_state};
use tempfile::tempdir;

/// The real git, never a wrapper earlier on PATH (on a machine with
/// agent-sign installed, `git commit` there would ask its service).
fn real_git() -> &'static str {
    [
        "/usr/bin/git",
        "/usr/local/bin/git",
        "/opt/homebrew/bin/git",
    ]
    .into_iter()
    .find(|p| Path::new(p).exists())
    .expect("git is needed for these tests")
}

fn git(repo: &Path, args: &[&str]) {
    let out = Command::new(real_git())
        .args(args)
        .current_dir(repo)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", "P")
        .env("GIT_AUTHOR_EMAIL", "p@example.com")
        .env("GIT_COMMITTER_NAME", "P")
        .env("GIT_COMMITTER_EMAIL", "p@example.com")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A repository with a first commit on main and a branch feat/a at the same
/// commit, checked out.
fn repo() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempdir().unwrap();
    let repo = dir.path().join("r");
    fs::create_dir_all(&repo).unwrap();
    git(&repo, &["init", "-q", "-b", "main"]);
    git(&repo, &["commit", "-q", "--allow-empty", "-m", "first"]);
    git(&repo, &["checkout", "-q", "-b", "feat/a"]);
    (dir, repo)
}

fn commit(repo: &Path, msg: &str) {
    git(repo, &["commit", "-q", "--allow-empty", "-m", msg]);
}

// --- Telling whether the work is finished ---------------------------------

#[test]
fn a_new_branch_on_mains_tip_is_not_finished_work() {
    let (_d, r) = repo();
    let base = branch_tip(&r, "feat/a").unwrap();
    assert_eq!(work_state(&r, "feat/a", &base), WorkState::Ongoing);
}

#[test]
fn unmerged_commits_are_ongoing_work() {
    let (_d, r) = repo();
    let base = branch_tip(&r, "feat/a").unwrap();
    commit(&r, "work");
    assert_eq!(work_state(&r, "feat/a", &base), WorkState::Ongoing);
}

#[test]
fn work_merged_into_main_is_finished() {
    let (_d, r) = repo();
    let base = branch_tip(&r, "feat/a").unwrap();
    commit(&r, "work");
    git(&r, &["checkout", "-q", "main"]);
    git(&r, &["merge", "-q", "--no-ff", "-m", "merge", "feat/a"]);
    assert_eq!(work_state(&r, "feat/a", &base), WorkState::Merged);
}

#[test]
fn work_merged_on_the_remote_counts_once_fetched() {
    let (_d, r) = repo();
    let base = branch_tip(&r, "feat/a").unwrap();
    commit(&r, "work");
    // As if GitHub merged it and the merge was fetched: origin/main now
    // contains the branch's tip.
    let tip = branch_tip(&r, "feat/a").unwrap();
    git(&r, &["update-ref", "refs/remotes/origin/main", &tip]);
    assert_eq!(work_state(&r, "feat/a", &base), WorkState::Merged);
}

#[test]
fn a_deleted_branch_is_finished() {
    let (_d, r) = repo();
    let base = branch_tip(&r, "feat/a").unwrap();
    commit(&r, "work");
    git(&r, &["checkout", "-q", "main"]);
    git(&r, &["branch", "-q", "-D", "feat/a"]);
    assert_eq!(work_state(&r, "feat/a", &base), WorkState::Deleted);
}

#[test]
fn a_deleted_repository_is_finished() {
    let (d, r) = repo();
    let base = branch_tip(&r, "feat/a").unwrap();
    fs::remove_dir_all(d.path()).unwrap();
    assert_eq!(work_state(&r, "feat/a", &base), WorkState::Deleted);
}

#[test]
fn detached_head_never_counts_as_finished() {
    let (_d, r) = repo();
    git(&r, &["checkout", "-q", "--detach"]);
    assert_eq!(branch_tip(&r, "HEAD"), None);
    assert_eq!(work_state(&r, "HEAD", "anything"), WorkState::Ongoing);
}

// --- Leases ending ----------------------------------------------------------

fn work(repo: &str) -> Work {
    Work {
        repo: repo.to_string(),
        branch: "feat/a".to_string(),
        base: "base".to_string(),
    }
}

#[test]
fn a_lease_ends_when_its_work_is_finished_and_others_stay() {
    let mut e = LeaseEngine::new(LeasePolicy::default());
    e.try_grant_for_work(
        "/w/a",
        "feat/a",
        "t",
        Coverage::Repository,
        Some(work("/w/a")),
    )
    .unwrap();
    e.try_grant_for_work(
        "/w/b",
        "feat/a",
        "t",
        Coverage::Repository,
        Some(work("/w/b")),
    )
    .unwrap();
    e.try_grant_lease("/w/c", "feat/a", "t").unwrap(); // no work recorded

    let ended = e.end_finished_work(|w| {
        if w.repo == "/w/a" {
            WorkState::Merged
        } else {
            WorkState::Ongoing
        }
    });
    assert_eq!(ended.len(), 1);
    assert_eq!(ended[0].1, WorkState::Merged);
    assert!(e.issue_commit_token("/w/a", "feat/a").is_err());
    assert!(e.issue_commit_token("/w/b", "feat/a").is_ok());
    assert!(e.issue_commit_token("/w/c", "feat/a").is_ok());
}

#[test]
fn a_folder_lease_ends_with_the_work_it_was_approved_for() {
    let mut e = LeaseEngine::new(LeasePolicy::default());
    e.try_grant_for_work(
        "/w/dev/a",
        "feat/a",
        "t",
        Coverage::Folder("/w/dev".to_string()),
        Some(work("/w/dev/a")),
    )
    .unwrap();
    assert!(e.issue_commit_token("/w/dev/b", "feat/x").is_ok());
    e.end_finished_work(|_| WorkState::Deleted);
    assert!(e.issue_commit_token("/w/dev/b", "feat/x").is_err());
}

fn lease_used_ago(secs: u64) -> Lease {
    let now = current_epoch_secs();
    Lease {
        id: "id".into(),
        repo: "/r".into(),
        branch: "feat/a".into(),
        intent: "t".into(),
        mode: LeaseMode::Identity,
        scope: LeaseScope::Branch,
        granted_at_secs: now - secs - 10,
        last_used_at_secs: now - secs,
        expires_at_secs: None,
        commit_count: 1,
        follows_branches: Some(true),
        coverage: Coverage::Repository,
        work: None,
    }
}

#[test]
fn a_lease_unused_past_the_backstop_has_ended() {
    let e = LeaseEngine::new(LeasePolicy {
        idle_limit: Some(Duration::from_secs(3600)),
        ..LeasePolicy::default()
    });
    assert!(e.is_lease_active(&lease_used_ago(60)));
    assert!(!e.is_lease_active(&lease_used_ago(2 * 3600)));
}

#[test]
fn with_the_backstop_off_only_work_and_revoking_end_a_lease() {
    let e = LeaseEngine::new(LeasePolicy::default());
    assert!(e.is_lease_active(&lease_used_ago(365 * 86400)));
}

#[test]
fn the_default_config_turns_the_backstop_on() {
    let c = agent_sign::config::Config::default();
    assert_eq!(
        c.security.idle_limit_duration().unwrap(),
        Some(Duration::from_secs(7 * 86400))
    );
}

#[test]
fn the_terms_say_when_a_lease_ends() {
    let p = LeasePolicy {
        idle_limit: Some(Duration::from_secs(7 * 86400)),
        ..LeasePolicy::default()
    };
    assert_eq!(
        p.describe_terms("feat/a").ends,
        "when the work on branch 'feat/a' is merged or the branch is deleted, \
         after 7 days with no agent commits, or when you turn it off (agent-sign revoke)"
    );
}
