//! The public-repository guard: no private deployment details in the tree.
//!
//! agent-sign's history is public. On 2 Nov 2026 the hub's main was found to
//! hold a map of where the signing keys live, the maintainer's tailnet name
//! and machine address, and a home folder. They must never reach GitHub, so
//! `scripts/release/scan-private-details.py` reads a revision's tree and these
//! tests hold it to its rules:
//!
//! * the repository's own tree (HEAD) has 0 findings, which is the check that
//!   fails whenever a private value or record is committed;
//! * each rule fires on a small repository built to break it, and does not
//!   fire on the documentation examples that stay allowed.
//!
//! The forbidden values are built from pieces here too: this file is in the
//! tree it guards.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn scanner() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/release/scan-private-details.py")
}

fn git(dir: &Path, args: &[&str]) {
    let ok = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .status()
        .expect("run git")
        .success();
    assert!(ok, "git {args:?} failed");
}

/// Scans `dir`'s HEAD; returns (exit code, output).
fn scan(dir: &Path) -> (i32, String) {
    let out = Command::new("python3")
        .arg("-I")
        .arg(scanner())
        .arg(dir)
        .output()
        .expect("run python3");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
    )
}

/// A repository whose one commit holds exactly `files`.
fn repo_with(files: &[(&str, String)]) -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    git(d.path(), &["init", "-q"]);
    for (rel, text) in files {
        let p = d.path().join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, text).unwrap();
    }
    git(d.path(), &["add", "-A"]);
    git(
        d.path(),
        &[
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "-m",
            "t",
        ],
    );
    d
}

fn must_flag(rule: &str, files: &[(&str, String)]) {
    let d = repo_with(files);
    let (code, out) = scan(d.path());
    assert_eq!(code, 1, "{rule} should be found:\n{out}");
    assert!(out.contains(rule), "expected rule {rule} in:\n{out}");
}

#[test]
fn this_repositorys_tree_holds_no_private_details() {
    let (code, out) = scan(Path::new(env!("CARGO_MANIFEST_DIR")));
    assert_eq!(code, 0, "private details in the tree:\n{out}");
}

#[test]
fn a_real_tailnet_name_is_found_and_the_example_is_not() {
    let real = format!("https://box.{}{}.ts.net:8200\n", "tail", "0a1b2c");
    must_flag("tailnet-name", &[("a.md", real)]);
    let ok = "https://hetzner.example.ts.net:8200 and example.ts.net\n".to_string();
    let d = repo_with(&[("a.md", ok)]);
    assert_eq!(scan(d.path()).0, 0);
}

#[test]
fn a_tailnet_address_is_found_unless_it_is_a_documentation_example() {
    must_flag(
        "tailnet-address",
        &[("a.md", format!("resolve = \"100.{}.214.99\"\n", 72))],
    );
    must_flag(
        "tailnet-address",
        &[("a.md", format!("{}.1.2\n", "100.127"))],
    );
    let ok = "100.64.0.0/10, 100.100.100.100, 100.64.0.10, 100.63.1.1, 100.128.0.1\n".to_string();
    let d = repo_with(&[("a.md", ok)]);
    let (code, out) = scan(d.path());
    assert_eq!(code, 0, "{out}");
}

#[test]
fn a_real_home_folder_is_found_and_a_placeholder_is_not() {
    let real = format!("HOME=/home/{}{}\n", "tay", "lor");
    must_flag("home-folder", &[("a.sh", real)]);
    must_flag(
        "user-folder",
        &[("a.sh", format!("/Users/{}{}/dev\n", "acc", "ount1"))],
    );
    let ok = "/home/<user>/x /home/agents /Users/me/dev /Users/<name>/x\n".to_string();
    let d = repo_with(&[("a.sh", ok)]);
    let (code, out) = scan(d.path());
    assert_eq!(code, 0, "{out}");
}

#[test]
fn the_signing_key_map_and_real_machine_settings_are_found_by_path() {
    must_flag(
        "private-record",
        &[("docs/signing-step0/README.md", "x\n".into())],
    );
    must_flag(
        "private-record",
        &[("scripts/sitting/files/machine-hetzner.env", "X=1\n".into())],
    );
    let d = repo_with(&[("scripts/sitting/files/machine-example.env", "X=1\n".into())]);
    assert_eq!(scan(d.path()).0, 0);
}
