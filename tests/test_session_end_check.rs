//! `agent-sign session-end`'s check of one working copy
//! (`agent_sign::session_runner::check_working_copy`; build step 3): a
//! clean working copy has its new commits bundled; a dirty one is reported.
//! Either way nothing is removed (the suite PM's D6 answer (b), 1 Nov 2026):
//! the whole session folder goes to the slot's Trash, which is the
//! launcher's job (`agent-launchd`), not this step's. It runs git, so it lives here, in a test
//! program of its own, not among the library's unit tests, where a started
//! process would hold copies of other tests' descriptors.

#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use agent_sign::session_runner::{BASE_REF, check_working_copy};

// DELIBERATE EVAL CHANGE (D6 answer (b), 1 Nov 2026): `check_working_copy`
// now returns only the status `String`. The "removable" flag is gone because
// nothing is removed any more. Only the `removable` parts of this test are
// dropped; every other assertion is as it was.
#[test]
fn a_clean_working_copy_is_bundled_and_a_dirty_one_is_not() {
    let t = tempfile::tempdir().unwrap();
    let dir = t.path().join("r");
    let out = t.path().join("out");
    fs::create_dir_all(&dir).unwrap();
    fs::create_dir_all(&out).unwrap();
    let g = |args: &[&str]| {
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
            .current_dir(&dir)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .unwrap();
        assert!(
            s.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&s.stderr)
        );
        String::from_utf8_lossy(&s.stdout).trim().to_string()
    };
    g(&["init", "-q", "-b", "main"]);
    fs::write(dir.join("f"), "1").unwrap();
    g(&["add", "f"]);
    g(&["commit", "-q", "-m", "base"]);
    let base = g(&["rev-parse", "HEAD"]);
    g(&["update-ref", BASE_REF, &base]);
    // Nothing moved: clean, and nothing to bundle.
    let said = check_working_copy(&dir, &out, "r");
    assert_eq!(said, "clean");
    assert!(!out.join("r.bundle").exists());
    // One new commit: clean, and bundled.
    fs::write(dir.join("f"), "2").unwrap();
    g(&["commit", "-q", "-am", "work"]);
    let said = check_working_copy(&dir, &out, "r");
    assert_eq!(said, "clean");
    assert!(out.join("r.bundle").exists());
    // An untracked file: reported, and kept.
    fs::write(dir.join("loose"), "x").unwrap();
    let said = check_working_copy(&dir, &out, "r2");
    assert!(said.starts_with("left:"), "{said}");
    // A stash: reported, and kept.
    fs::remove_file(dir.join("loose")).unwrap();
    fs::write(dir.join("f"), "3").unwrap();
    g(&["stash", "-q"]);
    let said = check_working_copy(&dir, &out, "r3");
    assert!(said.contains("stash"), "{said}");
}

/// Runs git in `dir` with the test's fixed identity; returns trimmed stdout.
fn git_in(dir: &Path, args: &[&str]) -> String {
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
    assert!(
        s.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&s.stderr)
    );
    String::from_utf8_lossy(&s.stdout).trim().to_string()
}

/// Every file under `dir` (the `.git` folder included) with its bytes, keyed
/// by its path inside `dir`.
fn snapshot(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn walk(root: &Path, at: &Path, into: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for e in fs::read_dir(at).unwrap() {
            let p = e.unwrap().path();
            let rel = p.strip_prefix(root).unwrap().to_path_buf();
            let m = fs::symlink_metadata(&p).unwrap();
            if m.is_dir() {
                into.insert(rel, Vec::new());
                walk(root, &p, into);
            } else if m.is_file() {
                into.insert(rel, fs::read(&p).unwrap());
            }
        }
    }
    let mut into = BTreeMap::new();
    walk(dir, dir, &mut into);
    into
}

/// The suite PM's D6 answer (b), 1 Nov 2026: "session-end removes nothing,
/// and the whole session folder goes to the slot's Trash, renamed and
/// logged." So after the end step a clean working copy whose commits are all
/// in its bundle is STILL THERE, byte for byte, for the launcher to rename
/// into the Trash with the rest of the session folder. (The Trash test in
/// `test_launcher_daemon.rs` cannot show this: its systemd stand-in does not
/// run the end step.) Checked through `end_in`, the end step's whole work
/// over a session folder, which needs no slot, uid or unit.
#[test]
fn session_end_removes_nothing_a_clean_bundled_copy_stays_for_the_trash() {
    let t = tempfile::tempdir().unwrap();
    let cur = t.path().join("current");
    let work = cur.join("work");
    fs::create_dir_all(&work).unwrap();
    // r: base recorded, then one new commit, clean.
    let r = work.join("r");
    fs::create_dir_all(&r).unwrap();
    git_in(&r, &["init", "-q", "-b", "main"]);
    fs::write(r.join("f"), "1").unwrap();
    git_in(&r, &["add", "f"]);
    git_in(&r, &["commit", "-q", "-m", "base"]);
    let base = git_in(&r, &["rev-parse", "HEAD"]);
    git_in(&r, &["update-ref", BASE_REF, &base]);
    fs::write(r.join("f"), "2").unwrap();
    git_in(&r, &["commit", "-q", "-am", "work"]);
    // s: clean, nothing moved past the base.
    let s = work.join("s");
    fs::create_dir_all(&s).unwrap();
    git_in(&s, &["init", "-q", "-b", "main"]);
    fs::write(s.join("f"), "1").unwrap();
    git_in(&s, &["add", "f"]);
    git_in(&s, &["commit", "-q", "-m", "base"]);
    let sbase = git_in(&s, &["rev-parse", "HEAD"]);
    git_in(&s, &["update-ref", BASE_REF, &sbase]);
    // t: an untracked file left.
    let tt = work.join("t");
    fs::create_dir_all(&tt).unwrap();
    git_in(&tt, &["init", "-q", "-b", "main"]);
    fs::write(tt.join("f"), "1").unwrap();
    git_in(&tt, &["add", "f"]);
    git_in(&tt, &["commit", "-q", "-m", "base"]);
    let tbase = git_in(&tt, &["rev-parse", "HEAD"]);
    git_in(&tt, &["update-ref", BASE_REF, &tbase]);
    fs::write(tt.join("loose"), "x").unwrap();
    // Let git refresh its index once now, so a later refresh by the check
    // itself is not mistaken for the end step changing the copy.
    for d in [&r, &s, &tt] {
        git_in(d, &["status", "--porcelain=v1"]);
    }
    let before: Vec<_> = [&r, &s, &tt].iter().map(|d| snapshot(d)).collect();

    agent_sign::session_runner::end_in(&cur).expect("the end step failed");

    for (d, was) in [&r, &s, &tt].iter().zip(&before) {
        let name = d.file_name().unwrap().to_string_lossy().to_string();
        assert!(
            d.join(".git").is_dir(),
            "D6 (b): session-end removes nothing, but work/{name} (or its .git) is gone"
        );
        let now = snapshot(d);
        let changed: Vec<_> = was
            .keys()
            .chain(now.keys())
            .filter(|k| was.get(*k) != now.get(*k))
            .collect();
        assert!(
            changed.is_empty(),
            "D6 (b): session-end removes nothing and the whole folder goes to the Trash, \
             but work/{name} changed or lost files: {changed:?}"
        );
    }
    let out = cur.join("out");
    assert!(
        out.join("r.bundle").exists(),
        "D6 (b): r has a new commit, so out/r.bundle must exist before the folder goes to the Trash"
    );
    assert!(
        !out.join("s.bundle").exists(),
        "s never moved past its base: there is nothing to bundle, so out/s.bundle must not exist"
    );
    let text = fs::read_to_string(out.join("status.json")).expect("out/status.json is missing");
    let status: serde_json::Value =
        serde_json::from_str(&text).expect("out/status.json isn't JSON");
    assert_eq!(
        status["r"], "clean",
        "r is clean and bundled; D6 (b) changes only whether it is removed"
    );
    assert_eq!(
        status["s"], "clean",
        "s is clean; D6 (b) changes only whether it is removed"
    );
    assert!(
        status["t"].as_str().is_some_and(|x| x.starts_with("left:")),
        "t holds an untracked file and must be reported as \"left: ...\": {status}"
    );
    let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&out), 0o750, "out/ must end 0750");
    assert_eq!(
        mode(&out.join("status.json")),
        0o640,
        "status.json must end 0640"
    );
}
