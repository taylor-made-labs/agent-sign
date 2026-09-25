use crate::config::Config;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SigningAction {
    DelegateToSystemSshKeygen,
    SignWithAgentKey(String),
}

pub struct Multiplexer {
    pub config: Config,
}

impl Multiplexer {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    /// Determines whether the commit should be delegated to the system ssh-keygen / 1Password
    /// or handled by the agent signing key.
    ///
    /// Non-negotiable [INV-1]: Absence or empty token ALWAYS defaults to Human (DelegateToSystemSshKeygen).
    pub fn determine_action(&self, env_token: Option<&str>) -> SigningAction {
        match env_token {
            None => SigningAction::DelegateToSystemSshKeygen,
            Some(token) if token.trim().is_empty() => SigningAction::DelegateToSystemSshKeygen,
            Some(token) => SigningAction::SignWithAgentKey(token.to_string()),
        }
    }

    /// Validates an event token. Fails closed [INV-7] if token is invalid or malformed.
    pub fn validate_event_token(&self, token: Option<&str>) -> Result<String, String> {
        match token {
            None => Err("No AGENT_EVENT_TOKEN found in environment".to_string()),
            Some(t) if t.trim().is_empty() => {
                Err("Empty AGENT_EVENT_TOKEN in environment".to_string())
            }
            Some(t) => {
                // Tokens must be valid UUID or prefixed event tokens: e.g. "ev_..." or UUID
                if (t.starts_with("ev_") && t.len() > 10) || uuid::Uuid::parse_str(t).is_ok() {
                    Ok(t.to_string())
                } else {
                    Err(format!(
                        "Malformed or unrecognized AGENT_EVENT_TOKEN: {}",
                        t
                    ))
                }
            }
        }
    }
}
