//! Checks the exact candidate bytes at the service's signature boundary.
//!
//! Changes are measured against the candidate's first parent (the branch's
//! previous state for an ordinary merge), or the empty tree for a root commit.
//! Other parent objects are also required to exist. The checked bytes are the
//! bytes subsequently signed; no index, hook, message-file or worktree snapshot
//! is used as a substitute. Git/object storage and the host remain trusted.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use crate::config::Config;

fn command(repo: &Path) -> Command {
    let mut cmd = Command::new(crate::paths::real_git());
    cmd.args(["--no-replace-objects", "-c", "core.fsmonitor=false", "-C"])
        .arg(repo)
        .current_dir(repo)
        .stdin(Stdio::null())
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_NO_LAZY_FETCH", "1");
    for name in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_CONFIG",
        "GIT_CONFIG_PARAMETERS",
        "GIT_CONFIG_COUNT",
    ] {
        cmd.env_remove(name);
    }
    cmd
}

fn git(repo: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    let out = command(repo)
        .args(args)
        .output()
        .map_err(|e| format!("couldn't inspect candidate objects: {e}"))?;
    if !out.status.success() {
        return Err("couldn't inspect candidate objects; nothing signed".into());
    }
    Ok(out.stdout)
}

fn check_commit_format(repo: &Path, buffer: &[u8]) -> Result<(), String> {
    // Git's object-format parser checks author/committer syntax and header
    // ordering. No -w: this validates without storing the candidate object.
    let mut child = command(repo)
        .args(["hash-object", "-t", "commit", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("couldn't validate candidate format: {e}"))?;
    let written = child
        .stdin
        .take()
        .ok_or("candidate format checker has no input")?
        .write_all(buffer);
    let out = child
        .wait_with_output()
        .map_err(|e| format!("couldn't validate candidate format: {e}"))?;
    if written.is_err() || !out.status.success() {
        return Err("candidate is not a structurally valid commit".into());
    }
    Ok(())
}

fn object_id(s: &str) -> bool {
    matches!(s.len(), 40 | 64) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn require_object(repo: &Path, id: &str, kind: &str) -> Result<(), String> {
    let actual = git(repo, &["cat-file", "-t", id])?;
    if actual.strip_suffix(b"\n").unwrap_or(&actual) != kind.as_bytes() {
        return Err(format!("candidate {kind} is not an existing {kind} object"));
    }
    Ok(())
}

/// Refuses a malformed candidate, unavailable objects, or violated policy.
/// The caller must recheck lease/time after this function's filesystem/Git work.
pub fn validate_candidate(repo: &Path, config: &Config, buffer: &[u8]) -> Result<(), String> {
    let text =
        std::str::from_utf8(buffer).map_err(|_| "candidate is not supported UTF-8 commit data")?;
    let (headers, message) = text
        .split_once("\n\n")
        .ok_or("candidate has no commit header/message separator")?;
    if headers.contains(['\r', '\0']) {
        return Err("candidate has invalid commit header bytes".into());
    }
    let mut lines = headers.lines();
    let tree = lines
        .next()
        .and_then(|l| l.strip_prefix("tree "))
        .filter(|s| object_id(s))
        .ok_or("candidate has no valid tree object ID")?;
    let mut parents = Vec::new();
    let mut authors = 0;
    let mut committers = 0;
    let mut encodings = 0;
    for line in lines {
        if let Some(parent) = line.strip_prefix("parent ") {
            if !object_id(parent) || parent.len() != tree.len() {
                return Err("candidate has an invalid parent object ID".into());
            }
            parents.push(parent);
        } else if line.starts_with("tree ") {
            return Err("candidate has more than one tree".into());
        } else if line.starts_with("author ") {
            authors += 1;
        } else if line.starts_with("committer ") {
            committers += 1;
        } else if let Some(encoding) = line.strip_prefix("encoding ") {
            encodings += 1;
            if encodings > 1 || !encoding.eq_ignore_ascii_case("UTF-8") {
                return Err("candidate has an unsupported or repeated encoding header".into());
            }
        } else if !line.starts_with(' ') && !line.contains(' ') {
            return Err("candidate has a malformed commit header".into());
        }
    }
    if authors != 1 || committers != 1 {
        return Err("candidate needs exactly one author and committer header".into());
    }
    check_commit_format(repo, buffer)?;
    require_object(repo, tree, "tree")?;
    for parent in &parents {
        require_object(repo, parent, "commit")?;
    }
    let base = match parents.first() {
        Some(parent) => format!("{parent}^{{tree}}"),
        None => String::from_utf8(git(repo, &["hash-object", "-t", "tree", "/dev/null"])?)
            .map_err(|_| "couldn't identify empty tree")?
            .trim()
            .to_string(),
    };
    let changed = git(
        repo,
        &[
            "diff",
            "--name-only",
            "-z",
            "--no-renames",
            "--no-relative",
            "--no-ext-diff",
            "--no-textconv",
            "--ignore-submodules=none",
            &base,
            tree,
            "--",
        ],
    )?;
    for raw in changed.split(|b| *b == 0).filter(|p| !p.is_empty()) {
        let path = std::str::from_utf8(raw)
            .map_err(|_| "candidate contains a path whose policy cannot be checked")?;
        for pattern in &config.security.forbidden_paths {
            if matches_glob(path, pattern) {
                return Err(format!(
                    "candidate changes forbidden path {path:?} (rule {pattern:?})"
                ));
            }
        }
    }
    if config.security.max_diff_lines > 0 && crate::paths::env_var_os("ALLOW_LARGE_DIFF").is_none()
    {
        let stats = git(
            repo,
            &[
                "diff",
                "--numstat",
                "-z",
                "--no-renames",
                "--no-relative",
                "--no-ext-diff",
                "--no-textconv",
                "--ignore-submodules=none",
                &base,
                tree,
                "--",
            ],
        )?;
        let mut total = 0usize;
        for record in stats.split(|b| *b == 0).filter(|p| !p.is_empty()) {
            let mut fields = record.split(|b| *b == b'\t');
            let a = fields
                .next()
                .ok_or("candidate diff statistics are malformed")?;
            let d = fields
                .next()
                .ok_or("candidate diff statistics are malformed")?;
            if a == b"-" && d == b"-" {
                continue;
            }
            for value in [a, d] {
                let n = std::str::from_utf8(value)
                    .ok()
                    .and_then(|s| s.parse::<usize>().ok())
                    .ok_or("candidate diff statistics are malformed")?;
                total = total
                    .checked_add(n)
                    .ok_or("candidate diff statistics overflow")?;
            }
        }
        if total > config.security.max_diff_lines {
            return Err(format!(
                "candidate changes {total} lines, exceeding max_diff_lines = {}",
                config.security.max_diff_lines
            ));
        }
    }
    if config.security.enforce_conventional_commits && !is_conventional_commit(message) {
        return Err("candidate message violates conventional commits policy".into());
    }
    Ok(())
}

pub fn matches_glob(path: &str, pattern: &str) -> bool {
    let path = path.trim_start_matches("./");
    let pattern = pattern.trim_start_matches("./");
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix("/*") {
        return path == prefix || path.starts_with(&format!("{prefix}/"));
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        return path.ends_with(&format!(".{suffix}"));
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return path.starts_with(prefix);
    }
    path == pattern
}

pub fn is_conventional_commit(message: &str) -> bool {
    let first = message.lines().next().unwrap_or("").trim();
    [
        "feat", "fix", "docs", "style", "refactor", "perf", "test", "build", "ci", "chore",
    ]
    .iter()
    .any(|kind| first.starts_with(&format!("{kind}:")) || first.starts_with(&format!("{kind}(")))
}
