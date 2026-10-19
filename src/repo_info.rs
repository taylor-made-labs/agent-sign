//! What the service can safely learn about a repository without running git.
//!
//! The approval prompt is the one thing the person reads before a touch
//! gives an agent the key, so what it says must be true, and the agent (which
//! picks the repository and the branch it names over the socket) must not be
//! able to write the prompt's sentence for it. This module is the checks:
//!
//! - [`check_branch_name`]: the branch is a valid git branch name (git's
//!   `check-ref-format` rules, written out here, not by running git) and also
//!   uses only letters, digits and `/ - _ .`. Git itself allows parentheses,
//!   quotes, `#`, non-ASCII letters, invisible fillers such as U+3164 and
//!   right-to-left letters, all of which could make a branch name read as
//!   part of the sentence around it.
//! - [`current_branch`]: the branch the repository has checked out, read from
//!   its `HEAD` file, so an agent can't ask about a branch it isn't on.
//! - [`main_repository`]: for a linked worktree, the repository whose object
//!   store the commits really go into, so the prompt can name that one and
//!   not just the throwaway folder the agent made.
//!
//! None of this runs git: a repository is agent-controlled, and git there
//! may run its hooks or its config's programs.

use std::path::{Path, PathBuf};

/// The longest branch name accepted (git's own limit on a ref name is
/// longer; nothing the person types for a branch needs more).
const MAX_BRANCH_LEN: usize = 200;

/// Whether `name` is a branch name the service will put in a prompt: valid by
/// git's rules, and made only of ASCII letters, digits and `/ - _ .`.
/// `Err` says why not, for the agent.
pub fn check_branch_name(name: &str) -> Result<(), String> {
    let bad = |why: &str| Err(format!("'{name}' {why}"));
    if name.is_empty() {
        return Err("the branch name is empty".to_string());
    }
    if name.chars().count() > MAX_BRANCH_LEN {
        return Err("the branch name is too long".to_string());
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '-' | '_' | '.'))
    {
        return bad(
            "uses characters other than letters, digits and / - _ . (so it can't be shown safely in an approval prompt)",
        );
    }
    // The rest of git's check-ref-format rules that can still apply.
    if name.starts_with('-') {
        return bad("starts with '-', which git doesn't allow");
    }
    if name.ends_with('/') || name.ends_with('.') || name.contains("//") || name.contains("..") {
        return bad("isn't a valid git branch name");
    }
    for part in name.split('/') {
        if part.is_empty() || part.starts_with('.') || part.ends_with(".lock") {
            return bad("isn't a valid git branch name");
        }
    }
    Ok(())
}

/// The directory holding the repository's `HEAD` for this working tree: the
/// `.git` folder, or, where `.git` is a file (a linked worktree or a
/// submodule), the folder it names.
fn git_dir(repo: &Path) -> Option<PathBuf> {
    let dot_git = repo.join(".git");
    if dot_git.is_dir() {
        return Some(dot_git);
    }
    let text = std::fs::read_to_string(&dot_git).ok()?;
    let target = text.lines().next()?.strip_prefix("gitdir:")?.trim();
    let target = Path::new(target);
    Some(if target.is_absolute() {
        target.to_path_buf()
    } else {
        repo.join(target)
    })
}

/// The branch `repo` has checked out, read from `HEAD`: the branch's name,
/// or `HEAD` when detached (as the git wrapper reports it). `None` when it
/// can't be told, which refuses the request.
pub fn current_branch(repo: &Path) -> Option<String> {
    let head = std::fs::read_to_string(git_dir(repo)?.join("HEAD")).ok()?;
    let head = head.trim();
    if let Some(reference) = head.strip_prefix("ref:") {
        return reference
            .trim()
            .strip_prefix("refs/heads/")
            .map(str::to_string);
    }
    let hex = head.len() == 40 || head.len() == 64;
    (hex && head.chars().all(|c| c.is_ascii_hexdigit())).then(|| "HEAD".to_string())
}

/// For a linked worktree, the canonical path of the repository it belongs to
/// (its main working tree, or the bare repository's folder); `None` for an
/// ordinary repository, a submodule, or anything that can't be resolved.
pub fn main_repository(repo: &Path) -> Option<PathBuf> {
    let dot_git = repo.join(".git");
    if !dot_git.is_file() {
        return None;
    }
    let gitdir = git_dir(repo)?;
    let common = std::fs::read_to_string(gitdir.join("commondir")).ok()?;
    let common = std::fs::canonicalize(gitdir.join(common.trim())).ok()?;
    if common.file_name().is_some_and(|n| n == ".git") {
        common.parent().map(Path::to_path_buf)
    } else {
        Some(common)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_branch_names_pass() {
        for name in ["main", "feat/parser", "fix-1.2_x", "release/v0.1", "HEAD"] {
            assert!(check_branch_name(name).is_ok(), "{name}");
        }
    }

    #[test]
    fn names_that_could_pose_as_prompt_text_or_break_git_rules_fail() {
        let bad = [
            "",
            "typo fix in scratch (~/tmp/scratch)",
            "a b",
            "feat/\u{3164}x",
            "feat/\u{2800}x",
            "feat/\u{5d0}\u{5d1}",
            "feat/\u{e9}",
            "-x",
            "a..b",
            "a//b",
            "a/",
            "a.",
            "a/.b",
            "x.lock",
            "a/x.lock/b",
            "a@{b",
            "a~b",
            "a:b",
            "a\"b",
        ];
        for name in bad {
            assert!(check_branch_name(name).is_err(), "{name:?} was accepted");
        }
    }
}
