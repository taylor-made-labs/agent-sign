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
//!
//! **Cost.** The service runs this check on an agent commit's path (for the
//! lease in use only) and for every lease when they are listed or swept, so
//! each git run counts: on a Mac under launchd each one costs about 0.14 s.
//! The usual check is one git run, a `for-each-ref --contains` that reads the
//! branch's tip and which merge targets hold it at once; only a branch that
//! can't be read costs a second run, to tell "deleted" from "unreadable".
//! Every run goes through [`crate::paths::real_git`], never `git` by name:
//! on a machine with agent-sign installed, `git` on `PATH` can be the
//! wrapper, and on a Mac it is the slow `xcrun` shim (backlog d37fd952).

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

/// The real git (see [`crate::paths::real_git`]) in `repo`, reading nothing
/// from stdin and printing nothing to the service's log.
fn git(repo: &Path) -> Command {
    let mut cmd = Command::new(crate::paths::real_git());
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

/// The branch's tip and whether any merge target holds it, from one git
/// run: `for-each-ref --contains refs/heads/<branch>` over the branch itself
/// and the merge targets. A branch always contains its own tip, so its line
/// gives the tip; each target listed holds it. Lines are matched by exact
/// ref name, since a `for-each-ref` pattern also matches refs below it.
/// `None` when the branch doesn't resolve or git fails.
fn tip_and_merged(repo: &Path, branch: &str) -> Option<(String, bool)> {
    let branch_ref = format!("refs/heads/{branch}");
    let out = git(repo)
        .args([
            "for-each-ref",
            "--format=%(objectname) %(refname)",
            "--contains",
        ])
        .arg(&branch_ref)
        .arg(&branch_ref)
        .args(MERGE_TARGETS)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let listed = String::from_utf8_lossy(&out.stdout);
    let mut tip = None;
    let mut merged = false;
    for line in listed.lines() {
        let Some((sha, name)) = line.trim().split_once(' ') else {
            continue;
        };
        if name == branch_ref {
            tip = Some(sha.to_string());
        } else if MERGE_TARGETS.contains(&name) {
            merged = true;
        }
    }
    tip.filter(|t| !t.is_empty()).map(|t| (t, merged))
}

/// The state of the work on `branch` in `repo`, approved when the branch's
/// tip was `base`. Usually one git run (see the module's notes on cost).
pub fn work_state(repo: &Path, branch: &str, base: &str) -> WorkState {
    if branch == "HEAD" || branch.is_empty() {
        return WorkState::Ongoing;
    }
    if !repo.is_dir() {
        return WorkState::Deleted;
    }
    let Some((tip, merged)) = tip_and_merged(repo, branch) else {
        // Tell "the branch is gone" from "git can't read this repository".
        return if resolve(repo, "HEAD").is_some() {
            WorkState::Deleted
        } else {
            WorkState::Ongoing
        };
    };
    // A branch with no commits since the approval isn't "merged" just
    // because it still sits where it started, on a target's tip.
    if tip == base || !merged {
        WorkState::Ongoing
    } else {
        WorkState::Merged
    }
}
