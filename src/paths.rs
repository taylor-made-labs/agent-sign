//! Where agent-sign keeps its state, and how its settings are named.
//!
//! Everything lives in `~/.agent-sign`: the programs (`bin/`), the agent key
//! (`keys/`), `config.toml`, `leases.json`, and the service's socket. It may
//! be a link to a directory kept elsewhere; every program follows it.
//! Every program finds it with the same rule, [`state_dir_in`], and reads
//! settings from `AGENT_SIGN_*` environment variables through [`env_var`].

use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// Name of agent-sign's state directory under the home directory.
pub const STATE_DIR_NAME: &str = ".agent-sign";

/// Prefix of agent-sign's environment variables.
pub const ENV_PREFIX: &str = "AGENT_SIGN_";

/// Per-repository config files, in the order they are merged (later wins).
pub const REPO_CONFIG_FILES: [&str; 1] = [".agent-sign.toml"];

/// The home directory from `HOME`, or `.` when it is unset.
pub fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

/// The state directory for a given home: `<home>/.agent-sign`, whether or
/// not it exists yet.
pub fn state_dir_in(home: &Path) -> PathBuf {
    home.join(STATE_DIR_NAME)
}

/// [`state_dir_in`] for the current `HOME`.
pub fn state_dir() -> PathBuf {
    state_dir_in(&home_dir())
}

/// Looks up `AGENT_SIGN_<suffix>`, using `get` to read a variable. Split out
/// from [`env_var`] so it can be tested without changing the process
/// environment.
pub fn env_var_with<T>(suffix: &str, get: impl Fn(&str) -> Option<T>) -> Option<T> {
    get(&format!("{ENV_PREFIX}{suffix}"))
}

/// The value of `AGENT_SIGN_<suffix>`, if it's set and valid Unicode.
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
    use tempfile::tempdir;

    #[test]
    fn the_state_dir_is_dot_agent_sign_in_the_home() {
        let home = tempdir().unwrap();
        assert_eq!(state_dir_in(home.path()), home.path().join(".agent-sign"));
    }

    #[test]
    fn settings_are_read_with_the_agent_sign_prefix() {
        let env: HashMap<&str, &str> = [("AGENT_SIGN_SOCKET", "/s.sock")].into_iter().collect();
        let get = |name: &str| env.get(name).map(|v| v.to_string());
        assert_eq!(env_var_with("SOCKET", get).as_deref(), Some("/s.sock"));
        assert_eq!(env_var_with("FORCE", get), None);
    }
}
