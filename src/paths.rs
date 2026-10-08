//! Where agent-commits keeps its state, and the older agent-sign names it still answers to.
//!
//! agent-commits was called agent-sign. Existing installs keep everything (key, leases,
//! config, socket, binaries) in `~/.agent-sign`; new installs use `~/.agent-commits`.
//! The service moves the old directory to the new place on its first start and
//! leaves a symlink behind (see [`crate::migrate`]), but the programs must work
//! before, during, and after that move, including when an old wrapper talks to a
//! new service or the other way round. So every program finds the state
//! directory with the same rule, [`state_dir_in`], instead of hard-coding
//! either name.
//!
//! The same applies to environment variables: every `AGENT_COMMITS_*` setting also
//! answers to its old `AGENT_SIGN_*` name, with the new name winning when both
//! are set.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// Name of agent-commits' state directory under the home directory.
pub const STATE_DIR_NAME: &str = ".agent-commits";

/// Name of agent-sign's state directory, which agent-commits migrates from.
pub const LEGACY_STATE_DIR_NAME: &str = ".agent-sign";

/// Prefix of agent-commits' environment variables.
pub const ENV_PREFIX: &str = "AGENT_COMMITS_";

/// Prefix of agent-sign's environment variables, still accepted as aliases.
pub const LEGACY_ENV_PREFIX: &str = "AGENT_SIGN_";

/// Per-repository config files, in the order they are merged (later wins).
/// `.agent-sign.toml` is still read so existing repositories keep their settings.
pub const REPO_CONFIG_FILES: [&str; 2] = [".agent-sign.toml", ".agent-commits.toml"];

/// The home directory from `HOME`, or `.` when it is unset (as agent-sign did).
pub fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

/// `<home>/.agent-commits`, whether or not it exists.
pub fn agent_commits_dir_in(home: &Path) -> PathBuf {
    home.join(STATE_DIR_NAME)
}

/// `<home>/.agent-sign`, whether or not it exists.
pub fn legacy_dir_in(home: &Path) -> PathBuf {
    home.join(LEGACY_STATE_DIR_NAME)
}

/// The state directory every agent-commits program uses for a given home.
///
/// 1. `~/.agent-commits` if it is a directory (or a link to one): migrated or new installs.
/// 2. Otherwise `~/.agent-sign` if it is a directory (or a link to one): an
///    agent-sign install the service has not migrated yet. Using it keeps the
///    existing key and leases in use, rather than silently starting a new key.
/// 3. Otherwise `~/.agent-commits`: a fresh install.
pub fn state_dir_in(home: &Path) -> PathBuf {
    let agent_commits_dir = agent_commits_dir_in(home);
    if agent_commits_dir.is_dir() {
        return agent_commits_dir;
    }
    let legacy = legacy_dir_in(home);
    if legacy.is_dir() {
        return legacy;
    }
    agent_commits_dir
}

/// [`state_dir_in`] for the current `HOME`.
pub fn state_dir() -> PathBuf {
    state_dir_in(&home_dir())
}

/// Rewrites a path inside `~/.agent-sign` to the same place inside the state
/// directory, when the state directory is `~/.agent-commits` and `~/.agent-sign` is no
/// longer a real directory (it is the link the migration leaves, or it is gone).
///
/// Config files written by agent-sign may name files by their old absolute path.
/// While the link exists both paths reach the same file; this keeps them working
/// if the link is later removed. Any other path is returned unchanged.
pub fn rebase_legacy_path(path: &Path, home: &Path) -> PathBuf {
    let legacy = legacy_dir_in(home);
    let state = state_dir_in(home);
    if state == legacy {
        return path.to_path_buf();
    }
    let legacy_is_real_dir = std::fs::symlink_metadata(&legacy)
        .map(|m| m.is_dir())
        .unwrap_or(false);
    if legacy_is_real_dir {
        return path.to_path_buf();
    }
    match path.strip_prefix(&legacy) {
        Ok(rest) => state.join(rest),
        Err(_) => path.to_path_buf(),
    }
}

/// Looks up `AGENT_COMMITS_<suffix>`, falling back to `AGENT_SIGN_<suffix>`, using `get`
/// to read a variable. Split out from [`env_var`] so the precedence can be
/// tested without changing the process environment.
pub fn env_var_with<T>(suffix: &str, get: impl Fn(&str) -> Option<T>) -> Option<T> {
    get(&format!("{ENV_PREFIX}{suffix}")).or_else(|| get(&format!("{LEGACY_ENV_PREFIX}{suffix}")))
}

/// The value of `AGENT_COMMITS_<suffix>` or, if that is unset or not valid Unicode,
/// `AGENT_SIGN_<suffix>`.
pub fn env_var(suffix: &str) -> Option<String> {
    env_var_with(suffix, |name| std::env::var(name).ok())
}

/// Like [`env_var`] but for presence checks and paths, where the value need not
/// be Unicode.
pub fn env_var_os(suffix: &str) -> Option<OsString> {
    env_var_with(suffix, |name| std::env::var_os(name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn fresh_home_uses_agent_commits_dir() {
        let home = tempdir().unwrap();
        assert_eq!(
            state_dir_in(home.path()),
            home.path().join(".agent-commits")
        );
    }

    #[test]
    fn unmigrated_agent_sign_home_keeps_using_its_dir() {
        let home = tempdir().unwrap();
        fs::create_dir(home.path().join(".agent-sign")).unwrap();
        assert_eq!(state_dir_in(home.path()), home.path().join(".agent-sign"));
    }

    #[test]
    fn agent_commits_dir_wins_once_it_exists() {
        let home = tempdir().unwrap();
        fs::create_dir(home.path().join(".agent-commits")).unwrap();
        std::os::unix::fs::symlink(
            home.path().join(".agent-commits"),
            home.path().join(".agent-sign"),
        )
        .unwrap();
        assert_eq!(
            state_dir_in(home.path()),
            home.path().join(".agent-commits")
        );
    }

    #[test]
    fn a_file_named_agent_sign_is_not_a_state_dir() {
        let home = tempdir().unwrap();
        fs::write(home.path().join(".agent-sign"), b"not a dir").unwrap();
        assert_eq!(
            state_dir_in(home.path()),
            home.path().join(".agent-commits")
        );
    }

    #[test]
    fn legacy_paths_are_rebased_only_after_migration() {
        let home = tempdir().unwrap();
        let h = home.path();
        let old_key = h.join(".agent-sign/keys/agent_ed25519");

        // Unmigrated: the old path is the real one.
        fs::create_dir(h.join(".agent-sign")).unwrap();
        assert_eq!(rebase_legacy_path(&old_key, h), old_key);

        // Migrated, link in place: rebased to the new home (same file either way).
        fs::rename(h.join(".agent-sign"), h.join(".agent-commits")).unwrap();
        std::os::unix::fs::symlink(h.join(".agent-commits"), h.join(".agent-sign")).unwrap();
        assert_eq!(
            rebase_legacy_path(&old_key, h),
            h.join(".agent-commits/keys/agent_ed25519")
        );

        // Link removed later: still rebased.
        fs::remove_file(h.join(".agent-sign")).unwrap();
        assert_eq!(
            rebase_legacy_path(&old_key, h),
            h.join(".agent-commits/keys/agent_ed25519")
        );

        // Paths elsewhere are untouched.
        let other = Path::new("/opt/keys/agent_ed25519");
        assert_eq!(rebase_legacy_path(other, h), other);
    }

    #[test]
    fn new_env_names_win_and_old_names_still_work() {
        let env: HashMap<&str, &str> = [
            ("AGENT_COMMITS_SOCKET", "/new.sock"),
            ("AGENT_SIGN_SOCKET", "/old.sock"),
            ("AGENT_SIGN_FORCE", "1"),
        ]
        .into_iter()
        .collect();
        let get = |name: &str| env.get(name).map(|v| v.to_string());

        assert_eq!(env_var_with("SOCKET", get).as_deref(), Some("/new.sock"));
        assert_eq!(env_var_with("FORCE", get).as_deref(), Some("1"));
        assert_eq!(env_var_with("SESSION", get), None);
    }
}
