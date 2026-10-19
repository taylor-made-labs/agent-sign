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
//! - [`worktree_kind`]: for a linked worktree, the repository whose object
//!   store the commits really go into, so the prompt can name that one and
//!   not just the throwaway folder the agent made. Only when that repository
//!   confirms the worktree from its side; a forged claim is shown as the
//!   folder itself, marked unrecognized.
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

/// What a folder is, as far as the approval prompt may say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorktreeKind {
    /// An ordinary repository, a submodule, or not a repository at all: the
    /// prompt names the folder itself.
    NotLinked,
    /// A verified linked worktree of the repository at this canonical path
    /// (its main working tree, or the bare repository's folder).
    Linked(PathBuf),
    /// `.git` is a file that claims a shared repository (`commondir`) but the
    /// claim doesn't check out in both directions. The prompt names the folder
    /// itself and says so.
    Unrecognized,
}

/// Classifies `repo` as a linked worktree only when git's own bookkeeping
/// agrees from both sides, because everything in the folder, including its
/// `.git` file, its gitdir and that gitdir's `commondir`, is the agent's to
/// forge. A folder is a linked worktree of R only if:
///
/// 1. its gitdir, fully resolved (no symlinks), is a direct child of R's
///    `.git/worktrees/` (`R` taken from the resolved `commondir`), and
/// 2. `R/.git/worktrees/<name>/gitdir`, which only R's owner can write,
///    points back at this folder's `.git`.
///
/// The agent can't write inside R, so it can't pass both. A gitdir of its own
/// making fails (1); pointing at a real worktree's gitdir fails (2).
pub fn worktree_kind(repo: &Path) -> WorktreeKind {
    let dot_git = repo.join(".git");
    // `symlink_metadata`: a `.git` that is a symlink is not a plain file.
    match std::fs::symlink_metadata(&dot_git) {
        Ok(m) if m.is_file() => {}
        _ => return WorktreeKind::NotLinked,
    }
    let Some(gitdir_raw) = git_dir(repo) else {
        return WorktreeKind::NotLinked;
    };
    let Ok(common_text) = std::fs::read_to_string(gitdir_raw.join("commondir")) else {
        return WorktreeKind::NotLinked;
    };
    verified_main_repository(&dot_git, &gitdir_raw, common_text.trim())
        .map_or(WorktreeKind::Unrecognized, WorktreeKind::Linked)
}

fn verified_main_repository(dot_git: &Path, gitdir_raw: &Path, common: &str) -> Option<PathBuf> {
    let gitdir = std::fs::canonicalize(gitdir_raw).ok()?;
    let common = std::fs::canonicalize(gitdir_raw.join(common)).ok()?;
    // (1) The gitdir is `<common>/worktrees/<name>`, with no symlink on that
    // path: the resolved gitdir equals the unresolved spelling.
    let worktrees = common.join("worktrees");
    if !std::fs::symlink_metadata(&worktrees).ok()?.is_dir() {
        return None;
    }
    let name = gitdir.file_name()?;
    if gitdir != worktrees.join(name) {
        return None;
    }
    // (2) The worktree's record in R points back at this folder's `.git`.
    let back = std::fs::read_to_string(gitdir.join("gitdir")).ok()?;
    let back = std::fs::canonicalize(back.trim()).ok()?;
    if back != std::fs::canonicalize(dot_git).ok()? {
        return None;
    }
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

    use std::fs;
    use std::process::Command;

    /// A real repository with a real linked worktree, made by git itself
    /// (with the user's global config out of the way), and a canonical root.
    fn real_worktree(root: &Path) -> (PathBuf, PathBuf) {
        let git = |dir: &Path, args: &[&str]| {
            let out = Command::new("git")
                .current_dir(dir)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_SYSTEM", "/dev/null")
                .args([
                    "-c",
                    "user.name=t",
                    "-c",
                    "user.email=t@t",
                    "-c",
                    "commit.gpgsign=false",
                ])
                .args(args)
                .output()
                .unwrap();
            assert!(out.status.success(), "{args:?}: {out:?}");
        };
        let main = root.join("real");
        fs::create_dir(&main).unwrap();
        git(&main, &["init", "-q", "-b", "main"]);
        git(&main, &["commit", "-q", "--allow-empty", "-m", "x"]);
        let wt = root.join("wt");
        git(
            &main,
            &["worktree", "add", "-q", wt.to_str().unwrap(), "-b", "side"],
        );
        (main, wt)
    }

    #[test]
    fn a_real_linked_worktree_is_recognized() {
        let tmp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(tmp.path()).unwrap();
        let (main, wt) = real_worktree(&root);
        assert_eq!(worktree_kind(&wt), WorktreeKind::Linked(main.clone()));
        assert_eq!(worktree_kind(&main), WorktreeKind::NotLinked);
    }

    #[test]
    fn a_forged_commondir_naming_a_real_repository_is_not_a_worktree() {
        let tmp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(tmp.path()).unwrap();
        let (main, _wt) = real_worktree(&root);
        // The agent's folder, its own fake gitdir, a commondir naming the real repo.
        let evil = root.join("evil");
        let fake = root.join("fake-gitdir");
        fs::create_dir_all(&evil).unwrap();
        fs::create_dir_all(&fake).unwrap();
        fs::write(evil.join(".git"), format!("gitdir: {}\n", fake.display())).unwrap();
        fs::write(
            fake.join("commondir"),
            format!("{}\n", main.join(".git").display()),
        )
        .unwrap();
        fs::write(fake.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        fs::write(
            fake.join("gitdir"),
            format!("{}\n", evil.join(".git").display()),
        )
        .unwrap();
        assert_eq!(worktree_kind(&evil), WorktreeKind::Unrecognized);
    }

    #[test]
    fn pointing_at_another_folders_real_worktree_record_is_not_a_worktree() {
        let tmp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(tmp.path()).unwrap();
        let (main, _wt) = real_worktree(&root);
        let record = main.join(".git/worktrees/wt");
        assert!(record.is_dir());
        let evil = root.join("evil");
        fs::create_dir_all(&evil).unwrap();
        fs::write(evil.join(".git"), format!("gitdir: {}\n", record.display())).unwrap();
        // Right place in R, but R's record points back at wt, not at evil.
        assert_eq!(worktree_kind(&evil), WorktreeKind::Unrecognized);
    }

    #[test]
    fn a_symlinked_gitdir_into_a_real_record_is_not_trusted() {
        let tmp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(tmp.path()).unwrap();
        let (main, wt) = real_worktree(&root);
        // A symlink to the real record, in a folder whose back-pointer is genuine
        // for wt but which is spelled through a link: it resolves to the real
        // record, so it is still judged by what it resolves to (wt's), and a
        // different folder using it fails the back-pointer check.
        let link = root.join("link");
        std::os::unix::fs::symlink(main.join(".git/worktrees/wt"), &link).unwrap();
        let evil = root.join("evil");
        fs::create_dir_all(&evil).unwrap();
        fs::write(evil.join(".git"), format!("gitdir: {}\n", link.display())).unwrap();
        assert_eq!(worktree_kind(&evil), WorktreeKind::Unrecognized);
        assert_eq!(worktree_kind(&wt), WorktreeKind::Linked(main));
    }
}
