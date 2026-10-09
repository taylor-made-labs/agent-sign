//! Whether the work an approval was given for is finished.
//!
//! An approval (a lease) is for a piece of work: the branch the agent was on
//! when it asked, in that repository. When that work is finished, the lease
//! ends, so access lasts as long as the work it was for and never forever:
//!
//! - **Merged:** the branch has commits made since the approval, and its tip
//!   is now part of `main` or `master` (local, or as last fetched from
//!   `origin`). A branch with no new commits isn't "merged" just because it
//!   still sits on `main`'s tip, which is where a new branch starts.
//! - **Deleted:** the branch no longer exists in the repository (or the
//!   repository is gone).
//!
//! Detached HEAD has no branch to follow, so its work never counts as
//! finished here; the idle backstop and revoking still end it. Only local
//! refs are read: a merge made on GitHub counts once it's fetched. The
//! service never fetches.

use std::path::Path;
use std::process::{Command, Stdio};

/// The state of the work a lease was approved for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkState {
    /// Still going, or can't be told: the lease stays.
    Ongoing,
    /// Merged into `main` or `master`: the lease ends.
    Merged,
    /// The branch (or the repository) is gone: the lease ends.
    Deleted,
}

/// The branches work is merged into.
const MERGE_TARGETS: [&str; 4] = [
    "refs/heads/main",
    "refs/heads/master",
    "refs/remotes/origin/main",
    "refs/remotes/origin/master",
];

fn git(repo: &Path) -> Command {
    let mut cmd = Command::new("git");
    cmd.arg("-C")
        .arg(repo)
        .stdin(Stdio::null())
        .stderr(Stdio::null());
    cmd
}

/// The commit a ref points to, if it exists.
fn resolve(repo: &Path, refname: &str) -> Option<String> {
    let out = git(repo)
        .args(["rev-parse", "--verify", "--quiet"])
        .arg(format!("{refname}^{{commit}}"))
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let sha = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!sha.is_empty()).then_some(sha)
}

/// The tip of a local branch, if the branch exists. `None` for detached
/// HEAD (`branch` is "HEAD") and for anything git can't read.
pub fn branch_tip(repo: &Path, branch: &str) -> Option<String> {
    if branch == "HEAD" || branch.is_empty() {
        return None;
    }
    resolve(repo, &format!("refs/heads/{branch}"))
}

/// Whether `commit` is part of `target`'s history.
fn is_ancestor(repo: &Path, commit: &str, target: &str) -> bool {
    git(repo)
        .args(["merge-base", "--is-ancestor", commit, target])
        .stdout(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// The state of the work on `branch` in `repo`, approved when the branch's
/// tip was `base`.
pub fn work_state(repo: &Path, branch: &str, base: &str) -> WorkState {
    if branch == "HEAD" || branch.is_empty() {
        return WorkState::Ongoing;
    }
    if !repo.is_dir() {
        return WorkState::Deleted;
    }
    let Some(tip) = branch_tip(repo, branch) else {
        // Tell "the branch is gone" from "git can't read this repository".
        return if resolve(repo, "HEAD").is_some() {
            WorkState::Deleted
        } else {
            WorkState::Ongoing
        };
    };
    if tip == base {
        return WorkState::Ongoing;
    }
    let merged = MERGE_TARGETS
        .iter()
        .filter(|target| resolve(repo, target).is_some())
        .any(|target| is_ancestor(repo, &tip, target));
    if merged {
        WorkState::Merged
    } else {
        WorkState::Ongoing
    }
}
