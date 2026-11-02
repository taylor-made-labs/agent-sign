//! L4: a bundle can carry branches nobody approved; `session-exec` must take
//! from it only the approved base (docs/system-mode.md, "The session unit").
//!
//! Today `session-exec` fetches `+refs/heads/*:refs/heads/*` from the bundle,
//! so every branch in it lands in the working copy; the end step then bundles
//! every branch past the base, and the unapproved branch comes back to the
//! caller in `Ended` (the reviewer's L4). The fix, in the orchestrator's words:
//! "fetch only the approved base, or check the bundle's refs exactly". Both
//! are accepted here: after the call either the unapproved commits are NOT
//! reachable from any ref in the working copy, or the call refused the bundle (an `Err`).
//!
//! **A NEW TEST SEAM the builder must provide (named here so the tests can be
//! written before the build; `exec_inner` itself can't be run without a slot's
//! cgroup and bind mount):**
//!
//! `agent_sign::session_runner::fetch_base(dir: &Path, bundle: &Path, base: &str) -> Result<(), String>`
//!
//! `dir` is an existing, empty folder (session-exec makes it); `bundle` is the
//! git bundle the launcher left in `in/`; `base` is the approved commit. It is
//! the loop body of `exec_inner` from `git init` to the checkout: on `Ok`, `dir`
//! is a git working copy whose `HEAD` is `base`, checked out, with
//! [`BASE_REF`] set to `base`, and holding nothing of the bundle's that the
//! approval didn't name; on `Err`, a plain message. `exec_inner` calls it. If
//! the builder wants another name or shape, they say so and change only the
//! `use` line and the calls to `fetch_base` below, never an assertion.
//!
//! Red today: `fetch_base` doesn't exist, so this file doesn't compile. (The
//! finding is real on the current code: its loop fetches every head.) What
//! only a real machine can show: that `session-exec` calls it, and the
//! bundle the launcher actually left in `in/`.
//!
//! Runs git, so it is a test program of its own (like
//! `test_session_end_check.rs`). Run on hetzner:
//! `cargo test --locked --test test_session_exec_bundle_refs`.

#![cfg(target_os = "linux")]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use agent_sign::session_runner::{BASE_REF, check_working_copy, fetch_base};

fn git_out(dir: &Path, args: &[&str]) -> Result<String, String> {
    let s = Command::new("git")
        .args([
            "-c",
            "user.name=T",
            "-c",
            "user.email=t@example.com",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap();
    if s.status.success() {
        Ok(String::from_utf8_lossy(&s.stdout).trim().to_string())
    } else {
        Err(String::from_utf8_lossy(&s.stderr).trim().to_string())
    }
}

fn git(dir: &Path, args: &[&str]) -> String {
    git_out(dir, args).unwrap_or_else(|e| panic!("git {args:?}: {e}"))
}

fn commit(dir: &Path, file: &str, text: &str, msg: &str) -> String {
    fs::write(dir.join(file), text).unwrap();
    git(dir, &["add", file]);
    git(dir, &["commit", "-q", "-m", msg]);
    git(dir, &["rev-parse", "HEAD"])
}

/// A caller's repository with one commit on `main` (the approved base).
fn source(t: &Path) -> (PathBuf, String) {
    let dir = t.join("source");
    fs::create_dir_all(&dir).unwrap();
    git(&dir, &["init", "-q", "-b", "main"]);
    let base = commit(&dir, "f", "1\n", "base");
    (dir, base)
}

fn bundle_of(dir: &Path, to: &Path, refs: &[&str]) {
    let mut args = vec!["bundle", "create", "-q", to.to_str().unwrap()];
    args.extend_from_slice(refs);
    git(dir, &args);
}

/// Whether `rev` is reachable from any ref of the working copy. (Its object
/// may still sit in the object store: fetching from a bundle indexes the whole
/// pack. Unreachable objects are never returned, which is what matters.)
fn reachable(work: &Path, rev: &str) -> bool {
    git(work, &["rev-list", "--all"]).lines().any(|l| l == rev)
}

/// What must hold after `fetch_base` on a bundle carrying `unapproved` commits:
/// refused, or none of them is reachable from a ref of the working copy and none
/// of their branches exists. Then, whatever the session adds, the end step returns none of them.
fn only_the_base_came(work: &Path, out: &Path, base: &str, unapproved: &[&str], branches: &[&str]) {
    assert_eq!(
        git(work, &["rev-parse", "HEAD"]),
        base,
        "HEAD isn't the base"
    );
    assert_eq!(
        git(work, &["rev-parse", BASE_REF]),
        base,
        "{BASE_REF} isn't the base"
    );
    for u in unapproved {
        assert!(
            !reachable(work, u),
            "the unapproved commit {u} is reachable from a ref in the session's working copy"
        );
    }
    let heads = git(
        work,
        &["for-each-ref", "--format=%(refname)", "refs/heads/"],
    );
    for b in branches {
        assert!(
            !heads.lines().any(|h| h == format!("refs/heads/{b}")),
            "the unapproved branch {b} exists in the working copy: {heads}"
        );
    }
    // The session does some work on a branch of its own; the end step bundles it.
    if git_out(work, &["symbolic-ref", "-q", "HEAD"]).is_err() {
        git(work, &["checkout", "-q", "-b", "session-work"]);
    }
    commit(work, "g", "session\n", "by the session");
    fs::create_dir_all(out).unwrap();
    let said = check_working_copy(work, out, "r");
    assert_eq!(said, "clean");
    let returned = git(
        work,
        &[
            "bundle",
            "list-heads",
            out.join("r.bundle").to_str().unwrap(),
        ],
    );
    for u in unapproved {
        assert!(
            !returned.contains(u),
            "the returned bundle carries the unapproved commit {u}:\n{returned}"
        );
    }
    for b in branches {
        assert!(
            !returned.contains(&format!("refs/heads/{b}")),
            "the returned bundle carries the unapproved branch {b}:\n{returned}"
        );
    }
}

/// L4: the bundle holds `main` (the approved base) and a second branch `evil`
/// with a commit of its own. Only the base may reach the session, and so only
/// the session's own work can come back.
#[test]
fn an_unapproved_branch_in_the_bundle_does_not_reach_the_session_or_come_back() {
    let t = tempfile::tempdir().unwrap();
    let (src, base) = source(t.path());
    git(&src, &["checkout", "-q", "-b", "evil"]);
    let evil = commit(&src, "evil", "evil\n", "an unapproved commit");
    git(&src, &["checkout", "-q", "main"]);
    let bundle = t.path().join("in.bundle");
    bundle_of(&src, &bundle, &["main", "evil"]);
    let work = t.path().join("work");
    fs::create_dir(&work).unwrap();
    match fetch_base(&work, &bundle, &base) {
        Ok(()) => only_the_base_came(&work, &t.path().join("out"), &base, &[&evil], &["evil"]),
        Err(e) => assert!(!e.trim().is_empty(), "a refusal must say why"),
    }
}

/// L4: the bundle's `main` is AHEAD of the approved base (the caller approved
/// the older commit, and bundled a longer branch). The commits past the base
/// weren't approved either.
#[test]
fn commits_past_the_approved_base_do_not_reach_the_session_or_come_back() {
    let t = tempfile::tempdir().unwrap();
    let (src, base) = source(t.path());
    let ahead = commit(&src, "f", "2\n", "past the base");
    let bundle = t.path().join("in.bundle");
    bundle_of(&src, &bundle, &["main"]);
    let work = t.path().join("work");
    fs::create_dir(&work).unwrap();
    match fetch_base(&work, &bundle, &base) {
        Ok(()) => only_the_base_came(&work, &t.path().join("out"), &base, &[&ahead], &[]),
        Err(e) => assert!(!e.trim().is_empty(), "a refusal must say why"),
    }
}

/// Control (the case the client really sends: one branch, at the base): the
/// session gets the base checked out, the base ref set, a clean work tree.
#[test]
fn a_bundle_of_just_the_approved_base_makes_the_working_copy() {
    let t = tempfile::tempdir().unwrap();
    let (src, base) = source(t.path());
    let bundle = t.path().join("in.bundle");
    bundle_of(&src, &bundle, &["main"]);
    let work = t.path().join("work");
    fs::create_dir(&work).unwrap();
    fetch_base(&work, &bundle, &base)
        .unwrap_or_else(|e| panic!("the normal case was refused: {e}"));
    assert_eq!(git(&work, &["rev-parse", "HEAD"]), base);
    assert_eq!(git(&work, &["rev-parse", BASE_REF]), base);
    assert_eq!(fs::read_to_string(work.join("f")).unwrap(), "1\n");
    assert_eq!(git(&work, &["status", "--porcelain"]), "");
}

/// Control: a bundle that doesn't hold the approved base is refused (today's
/// behaviour: "the bundle doesn't hold the base commit").
#[test]
fn a_bundle_without_the_approved_base_is_refused() {
    let t = tempfile::tempdir().unwrap();
    let (src, _base) = source(t.path());
    let other = t.path().join("other");
    fs::create_dir_all(&other).unwrap();
    git(&other, &["init", "-q", "-b", "main"]);
    let unrelated = commit(&other, "x", "unrelated\n", "unrelated");
    let bundle = t.path().join("in.bundle");
    bundle_of(&other, &bundle, &["main"]);
    let _ = src;
    let work = t.path().join("work");
    fs::create_dir(&work).unwrap();
    let want = "0123456789abcdef0123456789abcdef01234567";
    assert_ne!(unrelated, want);
    assert!(
        fetch_base(&work, &bundle, want).is_err(),
        "a bundle without the approved base was accepted"
    );
}
