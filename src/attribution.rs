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
