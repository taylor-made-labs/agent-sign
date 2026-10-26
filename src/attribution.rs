use crate::config::{AgentConfig, AttributionConfig, HumanConfig};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AttributionMode {
    #[default]
    Split,
    Trailers,
    Alias,
}

/// Agents that mark the commands they run with an environment variable,
/// and the name agent-sign gives their commits. Only marks seen in
/// practice or documented by the agent are listed, checked in this order:
///
/// - Claude Code sets `CLAUDECODE=1` in the shell it runs commands in
///   (seen, 7 Oct 2026).
/// - Gemini CLI sets `GEMINI_CLI=1` for its shell tool (its own docs,
///   `docs/tools/shell.md`).
/// - Codex sets `CODEX_THREAD_ID` (named in its binary, 0.156; not yet seen
///   in a running session).
///
/// An agent with no mark (Cursor, Aider) can be started with
/// `AGENT_SIGN_AGENT_NAME` set instead.
pub const KNOWN_AGENTS: &[(&str, &str)] = &[
    ("CLAUDECODE", "Claude Code"),
    ("GEMINI_CLI", "Gemini CLI"),
    ("CODEX_THREAD_ID", "Codex"),
];

/// The default agent names agent-sign and agent-sign have used. A
/// configured name other than these is the person's own choice, so a
/// detected agent never replaces it.
const DEFAULT_AGENT_NAMES: &[&str] = &["Agent", "Antigravity Agent"];

/// Which agent is running the command, from the environment `get` reads:
/// `AGENT_SIGN_AGENT_NAME` if set, otherwise the first agent in
/// [`KNOWN_AGENTS`] whose mark is set (and isn't empty or `0`).
pub fn detect_agent_with(get: impl Fn(&str) -> Option<String>) -> Option<String> {
    if let Some(name) = crate::paths::env_var_with("AGENT_NAME", &get)
        .map(|n| n.trim().to_string())
        .filter(|n| !n.is_empty())
    {
        return Some(name);
    }
    KNOWN_AGENTS
        .iter()
        .find(|(var, _)| get(var).is_some_and(|v| !v.is_empty() && v != "0"))
        .map(|(_, name)| name.to_string())
}

/// Whether one of the [`KNOWN_AGENTS`] marks is set (and isn't empty or
/// `0`). Unlike [`detect_agent_with`], `AGENT_SIGN_AGENT_NAME` doesn't
/// count: it names an agent's commits, and may be set in a terminal the
/// person also types in (an editor's terminal settings, say).
pub fn agent_mark_present_with(get: impl Fn(&str) -> Option<String>) -> bool {
    KNOWN_AGENTS
        .iter()
        .any(|(var, _)| get(var).is_some_and(|v| !v.is_empty() && v != "0"))
}

/// Set by the git wrapper on every git it runs for an agent. Git's own nested
/// runs (a shell alias `!...`, a hook, the commits a rebase replays) use git's
/// internal copy of itself, not the wrapper, and the signing program they call
/// sees only the environment: this mark is how the signing program still
/// knows an agent is behind them, so the person's own key is never used for
/// them. The wrapper's terminal test ignores it (it reaches editors git
/// starts, and terminals opened from those are the person's).
pub const AGENT_RUN_VAR: &str = "AGENT_SIGN_AGENT_RUN";

/// Whether an agent is behind this process, from the environment `get`
/// reads: the wrapper's [`AGENT_RUN_VAR`], or one of the [`KNOWN_AGENTS`]
/// marks (set and not empty or `0`).
pub fn agent_run_with(get: impl Fn(&str) -> Option<String>) -> bool {
    get(AGENT_RUN_VAR).is_some_and(|v| !v.is_empty() && v != "0") || agent_mark_present_with(get)
}

/// Whether a commit is the person's own, to be passed to their normal git
/// and signing untouched: standard input and output are both terminals,
/// nothing forces agent handling (`AGENT_SIGN_FORCE`, `_SESSION`), and no
/// agent has marked the command as its own. The mark matters for agents
/// that run commands in a real terminal (a terminal pane, say), which the
/// terminal test alone would take for the person.
pub fn is_persons_own_commit(
    stdin_is_terminal: bool,
    stdout_is_terminal: bool,
    forced: bool,
    agent_marked: bool,
) -> bool {
    stdin_is_terminal && stdout_is_terminal && !forced && !agent_marked
}

/// [`detect_agent_with`] for this process's environment.
pub fn detect_agent() -> Option<String> {
    detect_agent_with(|k| std::env::var(k).ok())
}

/// The author name for an agent commit: the agent detected, when the
/// configured name is still a default; otherwise the configured name.
/// `AGENT_SIGN_AGENT_NAME` is an explicit choice and always wins.
pub fn effective_agent_name(configured: &str, explicit: bool, detected: Option<String>) -> String {
    match detected {
        Some(name) if explicit || DEFAULT_AGENT_NAMES.contains(&configured) => name,
        _ => configured.to_string(),
    }
}

pub struct AttributionEngine {
    pub mode: AttributionMode,
    pub agent: AgentConfig,
    pub human: HumanConfig,
}

impl AttributionEngine {
    pub fn new(attr_config: AttributionConfig, agent: AgentConfig, human: HumanConfig) -> Self {
        Self {
            mode: attr_config.mode,
            agent,
            human,
        }
    }

    pub fn compute_env_vars(&self, _commit_msg: &str) -> HashMap<String, String> {
        let mut envs = HashMap::new();
        match self.mode {
            AttributionMode::Split => {
                envs.insert("GIT_AUTHOR_NAME".to_string(), self.agent.name.clone());
                envs.insert("GIT_AUTHOR_EMAIL".to_string(), self.agent.email.clone());
                envs.insert("GIT_COMMITTER_NAME".to_string(), self.human.name.clone());
                envs.insert("GIT_COMMITTER_EMAIL".to_string(), self.human.email.clone());
            }
            AttributionMode::Trailers => {
                envs.insert("GIT_AUTHOR_NAME".to_string(), self.human.name.clone());
                envs.insert("GIT_AUTHOR_EMAIL".to_string(), self.human.email.clone());
                envs.insert("GIT_COMMITTER_NAME".to_string(), self.human.name.clone());
                envs.insert("GIT_COMMITTER_EMAIL".to_string(), self.human.email.clone());
            }
            AttributionMode::Alias => {
                let alias_name = format!("{} (Agent)", self.human.name);
                envs.insert("GIT_AUTHOR_NAME".to_string(), alias_name.clone());
                envs.insert("GIT_AUTHOR_EMAIL".to_string(), self.agent.email.clone());
                envs.insert("GIT_COMMITTER_NAME".to_string(), alias_name);
                envs.insert("GIT_COMMITTER_EMAIL".to_string(), self.agent.email.clone());
            }
        }
        envs
    }

    pub fn transform_commit_message(&self, message: &str, lease_id: &str) -> String {
        match self.mode {
            AttributionMode::Trailers => {
                let mut msg = message.trim_end().to_string();
                msg.push_str("\n\n");
                msg.push_str(&format!(
                    "Co-Authored-By: {} <{}>\n",
                    self.agent.name, self.agent.email
                ));
                msg.push_str("X-Agent-Signer: agent-sign/v0.1\n");
                msg.push_str(&format!("X-Agent-Lease: {}\n", lease_id));
                msg
            }
            _ => message.to_string(),
        }
    }
}

#[cfg(test)]
mod agent_run_tests {
    use super::*;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k| map.get(k).cloned()
    }

    #[test]
    fn the_wrappers_mark_or_an_agents_own_mark_means_an_agent_is_behind_it() {
        assert!(agent_run_with(env(&[(AGENT_RUN_VAR, "1")])));
        assert!(agent_run_with(env(&[("CLAUDECODE", "1")])));
        assert!(agent_run_with(env(&[("CODEX_THREAD_ID", "t")])));
        assert!(!agent_run_with(env(&[])));
        assert!(!agent_run_with(env(&[(AGENT_RUN_VAR, "0")])));
        assert!(!agent_run_with(env(&[(AGENT_RUN_VAR, "")])));
        // Naming an agent's commits isn't a mark: it may be set in a
        // terminal the person also types in.
        assert!(!agent_run_with(env(&[("AGENT_SIGN_AGENT_NAME", "Cursor")])));
    }
}
