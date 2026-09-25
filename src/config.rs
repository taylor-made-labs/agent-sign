use crate::attribution::AttributionMode;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

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
}

impl Default for AttributionConfig {
    fn default() -> Self {
        Self {
            mode: AttributionMode::Split,
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
    "Antigravity Agent".to_string()
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
    #[serde(default = "default_human_name")]
    pub name: String,
    #[serde(default = "default_human_email")]
    pub email: String,
    #[serde(default)]
    pub github_username: String,
}

fn default_human_name() -> String {
    "Developer".to_string()
}

fn default_human_email() -> String {
    "developer@example.com".to_string()
}

impl Default for HumanConfig {
    fn default() -> Self {
        Self {
            name: default_human_name(),
            email: default_human_email(),
            github_username: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    #[serde(default = "default_lease_duration")]
    pub default_lease_duration: String,
    #[serde(default = "default_block_branches")]
    pub block_branches: Vec<String>,
    #[serde(default = "default_max_commits_per_minute")]
    pub max_commits_per_minute: u32,
}

fn default_lease_duration() -> String {
    "2h".to_string()
}

fn default_block_branches() -> Vec<String> {
    vec!["main".to_string(), "master".to_string()]
}

fn default_max_commits_per_minute() -> u32 {
    10
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            default_lease_duration: default_lease_duration(),
            block_branches: default_block_branches(),
            max_commits_per_minute: default_max_commits_per_minute(),
        }
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
    dirs_fallback_home().join(".agent-sign/keys/agent_ed25519")
}

impl Default for SshConfig {
    fn default() -> Self {
        Self {
            fallback_program: default_ssh_keygen(),
            agent_key_path: default_key_path(),
        }
    }
}

fn dirs_fallback_home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

impl Config {
    pub fn load_from_file(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }
}
