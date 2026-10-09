//! agent-sign's settings: built-in defaults, then the person's config file in
//! the state directory (`~/.agent-sign/config.toml`), then the repository's
//! `.agent-sign.toml`, then environment variables.

use crate::attribution::AttributionMode;
use crate::paths;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub attribution: AttributionConfig,
    #[serde(default)]
    pub agent: AgentConfig,
    #[serde(default)]
    pub human: HumanConfig,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub ssh: SshConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributionConfig {
    #[serde(default)]
    pub mode: AttributionMode,
    #[serde(default = "default_true")]
    pub include_lease_trailer: bool,
    #[serde(default = "default_true")]
    pub include_signer_trailer: bool,
}

fn default_true() -> bool {
    true
}

impl Default for AttributionConfig {
    fn default() -> Self {
        Self {
            mode: AttributionMode::Split,
            include_lease_trailer: true,
            include_signer_trailer: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    #[serde(default = "default_agent_name")]
    pub name: String,
    #[serde(default = "default_agent_email")]
    pub email: String,
}

fn default_agent_name() -> String {
    "Agent".to_string()
}

fn default_agent_email() -> String {
    "agent@local.internal".to_string()
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            name: default_agent_name(),
            email: default_agent_email(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HumanConfig {
    #[serde(default = "detect_git_user_name")]
    pub name: String,
    #[serde(default = "detect_git_user_email")]
    pub email: String,
    #[serde(default)]
    pub github_username: String,
}

fn detect_git_user_name() -> String {
    let out = Command::new("git")
        .args(["config", "--get", "user.name"])
        .output();
    if let Ok(o) = out {
        let name = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if !name.is_empty() {
            return name;
        }
    }
    "Developer".to_string()
}

fn detect_git_user_email() -> String {
    let out = Command::new("git")
        .args(["config", "--get", "user.email"])
        .output();
    if let Ok(o) = out {
        let email = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if !email.is_empty() {
            return email;
        }
    }
    "developer@example.com".to_string()
}

impl Default for HumanConfig {
    fn default() -> Self {
        Self {
            name: detect_git_user_name(),
            email: detect_git_user_email(),
            github_username: String::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum LeaseMode {
    #[default]
    Identity,
    Timed,
    Process,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum LeaseScope {
    #[default]
    Branch,
    Repo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    #[serde(default)]
    pub lease_mode: LeaseMode,
    #[serde(default)]
    pub lease_scope: LeaseScope,
    #[serde(default = "default_lease_duration_str")]
    pub default_lease_duration: String,
    #[serde(default = "default_max_lease_ceiling")]
    pub max_lease_ceiling: String,
    #[serde(default = "default_block_branches")]
    pub block_branches: Vec<String>,
    #[serde(default)]
    pub allow_main_branch: bool,
    #[serde(default = "default_true")]
    pub allow_branch_switching: bool,
    #[serde(default = "default_max_commits_per_minute")]
    pub max_commits_per_minute: u32,
    #[serde(default)]
    pub auto_approve: bool,
    #[serde(default = "default_forbidden_paths")]
    pub forbidden_paths: Vec<String>,
    #[serde(default = "default_max_diff_lines")]
    pub max_diff_lines: usize,
    #[serde(default)]
    pub enforce_conventional_commits: bool,
}

fn default_lease_duration_str() -> String {
    "2h".to_string()
}

fn default_max_lease_ceiling() -> String {
    "none".to_string()
}

fn default_block_branches() -> Vec<String> {
    vec!["main".to_string(), "master".to_string()]
}

fn default_max_commits_per_minute() -> u32 {
    10
}

fn default_forbidden_paths() -> Vec<String> {
    vec![
        ".github/workflows/*".to_string(),
        ".circleci/*".to_string(),
        "*.pem".to_string(),
        "*.key".to_string(),
        "id_rsa*".to_string(),
        "id_ed25519*".to_string(),
    ]
}

fn default_max_diff_lines() -> usize {
    2000
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            lease_mode: LeaseMode::default(),
            lease_scope: LeaseScope::default(),
            default_lease_duration: default_lease_duration_str(),
            max_lease_ceiling: default_max_lease_ceiling(),
            block_branches: default_block_branches(),
            allow_main_branch: false,
            allow_branch_switching: true,
            max_commits_per_minute: default_max_commits_per_minute(),
            auto_approve: false,
            forbidden_paths: default_forbidden_paths(),
            max_diff_lines: default_max_diff_lines(),
            enforce_conventional_commits: false,
        }
    }
}

impl SecurityConfig {
    pub fn lease_duration(&self) -> Duration {
        parse_duration_string(&self.default_lease_duration).unwrap_or(Duration::from_secs(7200))
    }

    /// The longest a lifetime (`identity`) lease may last, or `None` for no
    /// ceiling ("none" or empty). A value that isn't a duration is an error,
    /// not "no ceiling": the person meant to bound leases, so the service
    /// refuses to start rather than silently leave them unbounded.
    pub fn max_ceiling_duration(&self) -> Result<Option<Duration>, String> {
        let s = self.max_lease_ceiling.trim();
        if s.is_empty() || s.eq_ignore_ascii_case("none") {
            Ok(None)
        } else {
            parse_duration_string(s).map(Some).ok_or_else(|| {
                format!(
                    "max_lease_ceiling = \"{}\" is not a duration; use a number with s, m, h or d (for example \"7d\"), or \"none\"",
                    s
                )
            })
        }
    }
}

pub fn parse_duration_string(s: &str) -> Option<Duration> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if let Some(val) = s.strip_suffix('h') {
        val.parse::<u64>()
            .ok()
            .map(|h| Duration::from_secs(h * 3600))
    } else if let Some(val) = s.strip_suffix('m') {
        val.parse::<u64>().ok().map(|m| Duration::from_secs(m * 60))
    } else if let Some(val) = s.strip_suffix('s') {
        val.parse::<u64>().ok().map(Duration::from_secs)
    } else if let Some(val) = s.strip_suffix('d') {
        val.parse::<u64>()
            .ok()
            .map(|d| Duration::from_secs(d * 86400))
    } else {
        s.parse::<u64>().ok().map(Duration::from_secs)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshConfig {
    #[serde(default = "default_ssh_keygen")]
    pub fallback_program: String,
    #[serde(default = "default_key_path")]
    pub agent_key_path: PathBuf,
}

fn default_ssh_keygen() -> String {
    "/usr/bin/ssh-keygen".to_string()
}

fn default_key_path() -> PathBuf {
    key_path_in(&paths::home_dir())
}

/// The default agent key path for a home: `<state dir>/keys/agent_ed25519`.
fn key_path_in(home: &Path) -> PathBuf {
    paths::state_dir_in(home).join("keys/agent_ed25519")
}

impl Default for SshConfig {
    fn default() -> Self {
        Self {
            fallback_program: default_ssh_keygen(),
            agent_key_path: default_key_path(),
        }
    }
}

fn merge_toml(base: &mut toml::Value, overlay: toml::Value) {
    if let (toml::Value::Table(base_table), toml::Value::Table(overlay_table)) = (base, overlay) {
        for (k, v) in overlay_table {
            if let Some(existing) = base_table.get_mut(&k) {
                if existing.is_table() && v.is_table() {
                    merge_toml(existing, v);
                } else {
                    *existing = v;
                }
            } else {
                base_table.insert(k, v);
            }
        }
    }
}

impl Config {
    pub fn load_from_file(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }

    /// Hierarchical config loading for the current `HOME`:
    /// 1. Default built-in configs
    /// 2. Deep-merged with `<state dir>/config.toml` (if present), where the
    ///    state dir is `~/.agent-sign`
    /// 3. Deep-merged with `<repo_root>/.agent-sign.toml` (if present)
    /// 4. Overlaid with environment variables (`AGENT_SIGN_*`)
    pub fn load(repo_path: Option<&Path>) -> Self {
        Self::load_in_home(&paths::home_dir(), repo_path)
    }

    /// [`Config::load`] for an explicit home directory, so loading can be
    /// tested against temporary homes without changing the process's `HOME`.
    pub fn load_in_home(home: &Path, repo_path: Option<&Path>) -> Self {
        let mut defaults = Config::default();
        defaults.ssh.agent_key_path = key_path_in(home);
        let default_str = toml::to_string(&defaults).unwrap_or_default();
        let mut base_val: toml::Value = toml::from_str(&default_str)
            .unwrap_or_else(|_| toml::Value::Table(toml::map::Map::new()));

        // 1. Overlay global user config
        let global_config = paths::state_dir_in(home).join("config.toml");
        if let Ok(content) = std::fs::read_to_string(&global_config)
            && let Ok(overlay) = toml::from_str::<toml::Value>(&content)
        {
            merge_toml(&mut base_val, overlay);
        }

        // 2. Overlay repo-level config (.agent-sign.toml, then .agent-sign.toml)
        if let Some(repo) = repo_path {
            for name in paths::REPO_CONFIG_FILES {
                let repo_config = repo.join(name);
                if let Ok(content) = std::fs::read_to_string(&repo_config)
                    && let Ok(overlay) = toml::from_str::<toml::Value>(&content)
                {
                    merge_toml(&mut base_val, overlay);
                }
            }
        }

        let mut config: Config = base_val.try_into().unwrap_or_default();

        // 3. Environment overrides
        if let Some(val) = paths::env_var("ALLOW_MAIN") {
            config.security.allow_main_branch = val == "1" || val.eq_ignore_ascii_case("true");
        }

        if let Some(val) = paths::env_var("AUTO_APPROVE") {
            config.security.auto_approve = val == "1" || val.eq_ignore_ascii_case("true");
        }

        if let Some(val) = paths::env_var("LEASE_MODE") {
            match val.to_lowercase().as_str() {
                "identity" => config.security.lease_mode = LeaseMode::Identity,
                "timed" => config.security.lease_mode = LeaseMode::Timed,
                "process" => config.security.lease_mode = LeaseMode::Process,
                _ => {}
            }
        }

        if let Some(val) = paths::env_var("LEASE_SCOPE") {
            match val.to_lowercase().as_str() {
                "branch" => config.security.lease_scope = LeaseScope::Branch,
                "repo" => config.security.lease_scope = LeaseScope::Repo,
                _ => {}
            }
        }

        if let Some(val) = paths::env_var("MAX_LEASE_CEILING") {
            config.security.max_lease_ceiling = val;
        }

        if let Some(val) = paths::env_var("MODE") {
            match val.to_lowercase().as_str() {
                "split" => config.attribution.mode = AttributionMode::Split,
                "trailers" => config.attribution.mode = AttributionMode::Trailers,
                "alias" => config.attribution.mode = AttributionMode::Alias,
                _ => {}
            }
        }

        if let Some(val) = paths::env_var("FALLBACK_PROGRAM")
            && !val.trim().is_empty()
        {
            config.ssh.fallback_program = val;
        }

        config
    }
}
