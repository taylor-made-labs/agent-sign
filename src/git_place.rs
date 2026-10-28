//! Where a git command is writing: the repository's top level and the
//! branch its commits go onto.
//!
//! The wrapper asks this when it gets a token, and the signing program asks
//! it again for every signature, from inside the git run, so the service can
//! refuse a signature whose repository or branch isn't the token's. Before
//! the identity review (28 Oct 2026) a run token signed anything for ten
//! minutes: `git rebase feature main` (started on `feature`, writing `main`)
//! and `rebase --exec 'cd /other && git commit'` made agent-signed commits on
//! `main` and in other repositories. Both sides use this one rule, so an
//! ordinary run sees the same place twice.

use std::path::Path;

/// The repository and branch git is writing, asked through `git`, which runs
/// git with the given arguments (and whatever global options and folder the
/// caller needs) and returns its trimmed output, or `None` if it failed:
///
/// - the repository is the canonical path of `rev-parse --show-toplevel`,
///   so a link or a relative path names the same repository as its real
///   location;
/// - the branch is `branch --show-current`; while a rebase is in progress
///   (HEAD detached), the branch the rebase is rewriting, from
///   `rebase-merge/head-name` or `rebase-apply/head-name` in the git
///   directory; otherwise `HEAD`, which is what git calls a detached HEAD.
///
/// `None` when git can't name the repository.
pub fn repo_and_branch(git: impl Fn(&[&str]) -> Option<String>) -> Option<(String, String)> {
    let top = git(&["rev-parse", "--show-toplevel"]).filter(|t| !t.is_empty())?;
    let repo = std::fs::canonicalize(&top)
        .ok()?
        .to_string_lossy()
        .into_owned();
    let branch = git(&["branch", "--show-current"])
        .filter(|b| !b.is_empty())
        .or_else(|| {
            let git_dir = git(&["rev-parse", "--absolute-git-dir"])?;
            rebasing_branch(Path::new(&git_dir))
        })
        .unwrap_or_else(|| "HEAD".to_string());
    Some((repo, branch))
}

/// The branch a rebase in progress in `git_dir` is rewriting, if any: the
/// `refs/heads/` name in `rebase-merge/head-name` (merge backend) or
/// `rebase-apply/head-name` (apply backend). A rebase of a detached HEAD
/// records "detached HEAD" there, which isn't a branch.
pub fn rebasing_branch(git_dir: &Path) -> Option<String> {
    ["rebase-merge/head-name", "rebase-apply/head-name"]
        .iter()
        .find_map(|f| std::fs::read_to_string(git_dir.join(f)).ok())
        .and_then(|name| {
            name.trim()
                .strip_prefix("refs/heads/")
                .filter(|b| !b.is_empty())
                .map(str::to_string)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_rebase_in_progress_names_the_branch_it_rewrites() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(rebasing_branch(dir.path()), None);
        std::fs::create_dir(dir.path().join("rebase-merge")).unwrap();
        std::fs::write(
            dir.path().join("rebase-merge/head-name"),
            "refs/heads/main\n",
        )
        .unwrap();
        assert_eq!(rebasing_branch(dir.path()).as_deref(), Some("main"));
        std::fs::write(dir.path().join("rebase-merge/head-name"), "detached HEAD\n").unwrap();
        assert_eq!(rebasing_branch(dir.path()), None);
    }
}
