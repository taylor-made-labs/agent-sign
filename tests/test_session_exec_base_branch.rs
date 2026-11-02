//! L4 follow-up: which branch the working copy is on after `fetch_base`.
//! The bundle's branch that was at exactly the approved base is checked out
//! (so the session starts on its caller's branch, as before the L4 change);
//! with none, `HEAD` is detached; and a branch name that starts with `-`
//! (git allows it in a bundle) is never handed to git as an option.
//!
//! Runs git, so it is a test program of its own, like
//! `test_session_exec_bundle_refs.rs`.

#![cfg(target_os = "linux")]

use std::fs;
use std::path::Path;
use std::process::Command;

use agent_sign::session_runner::fetch_base;

fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .args(["-c", "user.name=T", "-c", "user.email=t@example.com"])
        .args(["-c", "commit.gpgsign=false"])
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn source(t: &Path) -> (std::path::PathBuf, String) {
    let src = t.join("source");
    fs::create_dir_all(&src).unwrap();
    git(&src, &["init", "-q", "-b", "main"]);
    fs::write(src.join("f"), "1\n").unwrap();
    git(&src, &["add", "f"]);
    git(&src, &["commit", "-q", "-m", "base"]);
    let base = git(&src, &["rev-parse", "HEAD"]);
    (src, base)
}

#[test]
fn the_branch_that_was_at_the_base_is_checked_out() {
    let t = tempfile::tempdir().unwrap();
    let (src, base) = source(t.path());
    let bundle = t.path().join("in.bundle");
    git(
        &src,
        &["bundle", "create", "-q", bundle.to_str().unwrap(), "main"],
    );
    let work = t.path().join("work");
    fs::create_dir(&work).unwrap();
    fetch_base(&work, &bundle, &base).unwrap();
    assert_eq!(git(&work, &["symbolic-ref", "HEAD"]), "refs/heads/main");
    assert_eq!(git(&work, &["rev-parse", "main"]), base);
    assert_eq!(
        git(&work, &["for-each-ref", "--format=%(refname)"]),
        "refs/agent-sign/base\nrefs/heads/main",
        "nothing but the base ref and the branch may remain (the holding refs are deleted)"
    );
}

#[test]
fn with_no_branch_at_the_base_head_is_detached() {
    let t = tempfile::tempdir().unwrap();
    let (src, base) = source(t.path());
    fs::write(src.join("f"), "2\n").unwrap();
    git(&src, &["commit", "-q", "-am", "past the base"]);
    let bundle = t.path().join("in.bundle");
    git(
        &src,
        &["bundle", "create", "-q", bundle.to_str().unwrap(), "main"],
    );
    let work = t.path().join("work");
    fs::create_dir(&work).unwrap();
    fetch_base(&work, &bundle, &base).unwrap();
    assert!(
        Command::new("git")
            .args(["symbolic-ref", "-q", "HEAD"])
            .current_dir(&work)
            .status()
            .map(|s| !s.success())
            .unwrap(),
        "HEAD should be detached"
    );
    assert_eq!(git(&work, &["rev-parse", "HEAD"]), base);
}

#[test]
fn a_branch_name_starting_with_a_dash_is_not_an_option() {
    let t = tempfile::tempdir().unwrap();
    let (src, base) = source(t.path());
    git(&src, &["update-ref", "refs/heads/-x", &base]);
    let bundle = t.path().join("in.bundle");
    git(
        &src,
        &[
            "bundle",
            "create",
            "-q",
            bundle.to_str().unwrap(),
            "refs/heads/-x",
        ],
    );
    let work = t.path().join("work");
    fs::create_dir(&work).unwrap();
    fetch_base(&work, &bundle, &base).unwrap();
    assert_eq!(git(&work, &["rev-parse", "HEAD"]), base);
    assert_eq!(git(&work, &["status", "--porcelain"]), "");
}
