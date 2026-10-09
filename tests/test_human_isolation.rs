use agent_sign::config::Config;
use agent_sign::multiplexer::{Multiplexer, SigningAction};

#[test]
fn test_human_terminal_commit_invokes_standard_ssh_agent() {
    // When AGENT_EVENT_TOKEN is absent, multiplexer MUST determine this is a human commit
    // and pass through to system ssh-keygen / 1Password.
    let config = Config::default();
    let multiplexer = Multiplexer::new(config);

    let env_token = None;
    let action = multiplexer.determine_action(env_token);

    assert_eq!(
        action,
        SigningAction::DelegateToSystemSshKeygen,
        "Human commit without AGENT_EVENT_TOKEN must delegate to system ssh-keygen / 1Password"
    );
}

#[test]
fn test_ide_gui_commit_not_intercepted() {
    // When commit is invoked from IDE GUI (or an interactive terminal with no token),
    // it must NEVER be intercepted by the agent signing flow.
    let config = Config::default();
    let multiplexer = Multiplexer::new(config);

    // Empty or whitespace token is treated as absent
    let env_token = Some("".to_string());
    let action = multiplexer.determine_action(env_token.as_deref());

    assert_eq!(
        action,
        SigningAction::DelegateToSystemSshKeygen,
        "IDE GUI commit with empty token must delegate to system ssh-keygen"
    );
}

#[test]
fn test_corrupt_or_invalid_token_fails_closed() {
    // When AGENT_EVENT_TOKEN is provided but invalid/corrupted,
    // the system MUST NOT silently sign or fallback to unverified signing.
    // It must return an explicit validation error (Fail-Closed [INV-7]).
    let config = Config::default();
    let multiplexer = Multiplexer::new(config);

    let invalid_token = Some("definitely-not-a-valid-token-12345");
    let result = multiplexer.validate_event_token(invalid_token);

    assert!(
        result.is_err(),
        "Corrupted or invalid token must fail closed and return an error"
    );
}
