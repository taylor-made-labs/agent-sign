use agent_sign::attribution::{AttributionEngine, AttributionMode};
use agent_sign::config::{AgentConfig, AttributionConfig, HumanConfig};
use agent_sign::interceptor::CommandInterceptor;

#[test]
fn test_agent_git_passes_non_commit_commands_untouched() {
    let interceptor = CommandInterceptor::new();

    let args_status = vec!["status".to_string(), "-s".to_string()];
    let decision_status = interceptor.inspect_command(&args_status);
    assert!(!decision_status.is_commit);

    let args_diff = vec!["diff".to_string(), "HEAD~1".to_string()];
    let decision_diff = interceptor.inspect_command(&args_diff);
    assert!(!decision_diff.is_commit);

    let args_push = vec!["push".to_string(), "origin".to_string(), "main".to_string()];
    let decision_push = interceptor.inspect_command(&args_push);
    assert!(!decision_push.is_commit);
}

#[test]
fn test_agent_git_detects_commit_command() {
    let interceptor = CommandInterceptor::new();

    let args_commit = vec![
        "commit".to_string(),
        "-m".to_string(),
        "feat: something".to_string(),
    ];
    let decision = interceptor.inspect_command(&args_commit);
    assert!(decision.is_commit);

    // Flags before "commit" like `git -C /path commit`
    let args_with_flags = vec!["-C".to_string(), "/path".to_string(), "commit".to_string()];
    let decision_flags = interceptor.inspect_command(&args_with_flags);
    assert!(decision_flags.is_commit);
}

#[test]
fn test_attribution_split_mode() {
    let attr_config = AttributionConfig {
        mode: AttributionMode::Split,
    };
    let agent_config = AgentConfig {
        name: "Antigravity Agent".to_string(),
        email: "agent@local.internal".to_string(),
    };
    let human_config = HumanConfig {
        name: "Human Dev".to_string(),
        email: "dev@example.com".to_string(),
        github_username: "humandev".to_string(),
    };

    let engine = AttributionEngine::new(attr_config, agent_config, human_config);
    let env_vars = engine.compute_env_vars("initial commit message");

    assert_eq!(
        env_vars.get("GIT_AUTHOR_NAME").map(|s| s.as_str()),
        Some("Antigravity Agent")
    );
    assert_eq!(
        env_vars.get("GIT_AUTHOR_EMAIL").map(|s| s.as_str()),
        Some("agent@local.internal")
    );
    assert_eq!(
        env_vars.get("GIT_COMMITTER_NAME").map(|s| s.as_str()),
        Some("Human Dev")
    );
    assert_eq!(
        env_vars.get("GIT_COMMITTER_EMAIL").map(|s| s.as_str()),
        Some("dev@example.com")
    );
}

#[test]
fn test_attribution_trailers_mode() {
    let attr_config = AttributionConfig {
        mode: AttributionMode::Trailers,
    };
    let agent_config = AgentConfig {
        name: "Antigravity Agent".to_string(),
        email: "agent@local.internal".to_string(),
    };
    let human_config = HumanConfig {
        name: "Human Dev".to_string(),
        email: "dev@example.com".to_string(),
        github_username: "humandev".to_string(),
    };

    let engine = AttributionEngine::new(attr_config, agent_config, human_config);
    let original_message = "feat: add secure storage\n\nDetailed explanation of commit.";
    let transformed = engine.transform_commit_message(original_message, "lease-1234");

    assert!(transformed.contains("Co-Authored-By: Antigravity Agent <agent@local.internal>"));
    assert!(transformed.contains("X-Agent-Signer: agent-sign"));
    assert!(transformed.contains("X-Agent-Lease: lease-1234"));
}
