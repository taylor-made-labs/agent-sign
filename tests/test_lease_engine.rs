use agent_commits::lease::{LeaseEngine, LeasePolicy};
use std::time::Duration;

#[test]
fn test_lease_granted_after_single_auth() {
    let policy = LeasePolicy {
        default_ttl: Duration::from_secs(3600),
        block_branches: vec!["main".to_string(), "master".to_string()],
        allow_main_branch: false,
        allow_branch_switching: true,
        max_commits_per_minute: 10,
        ..Default::default()
    };
    let mut engine = LeaseEngine::new(policy);

    assert!(!engine.has_active_lease("my-repo"));

    // Grant a lease
    let lease = engine.grant_lease("my-repo", "feat/my-agent-task", "Adding tests");
    assert_eq!(lease.repo, "my-repo");
    assert_eq!(lease.branch, "feat/my-agent-task");
    assert!(engine.has_active_lease("my-repo"));
}

#[test]
fn test_subsequent_commits_within_ttl_require_zero_prompts() {
    let policy = LeasePolicy {
        default_ttl: Duration::from_secs(3600),
        block_branches: vec![],
        allow_main_branch: false,
        allow_branch_switching: true,
        max_commits_per_minute: 100,
        ..Default::default()
    };
    let mut engine = LeaseEngine::new(policy);
    engine.grant_lease("my-repo", "feat/fast", "Rapid commits");

    // Can issue 5 consecutive commit event tokens without any prompting
    for _ in 0..5 {
        let token_result = engine.issue_commit_token("my-repo", "feat/fast");
        assert!(token_result.is_ok());
    }
}

#[test]
fn test_branch_protection_blocks_main_by_default() {
    let policy = LeasePolicy {
        default_ttl: Duration::from_secs(3600),
        block_branches: vec!["main".to_string(), "master".to_string()],
        allow_main_branch: false,
        allow_branch_switching: true,
        max_commits_per_minute: 10,
        ..Default::default()
    };
    let mut engine = LeaseEngine::new(policy);

    // Attempting to grant on protected branch must fail closed
    let result = engine.try_grant_lease("my-repo", "main", "Unauthorized direct push to main");
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("protected branch"));
}

#[test]
fn test_branch_protection_allows_main_when_configured() {
    let policy = LeasePolicy {
        default_ttl: Duration::from_secs(3600),
        block_branches: vec!["main".to_string(), "master".to_string()],
        allow_main_branch: true, // Configured to permit main commits!
        allow_branch_switching: true,
        max_commits_per_minute: 10,
        ..Default::default()
    };
    let mut engine = LeaseEngine::new(policy);

    // When allow_main_branch is true, granting on main must succeed
    let result = engine.try_grant_lease("my-repo", "main", "Approved direct commit to main");
    assert!(
        result.is_ok(),
        "Expected lease on main to be granted when allow_main_branch is true"
    );
    assert_eq!(result.unwrap().branch, "main");
}

#[test]
fn test_rate_limiter_throttles_rapid_commits() {
    let policy = LeasePolicy {
        default_ttl: Duration::from_secs(3600),
        block_branches: vec![],
        allow_main_branch: false,
        allow_branch_switching: true,
        max_commits_per_minute: 3, // strictly 3 per minute
        ..Default::default()
    };
    let mut engine = LeaseEngine::new(policy);
    engine.grant_lease("my-repo", "feat/loop", "Testing loop protection");

    // First 3 tokens succeed
    assert!(engine.issue_commit_token("my-repo", "feat/loop").is_ok());
    assert!(engine.issue_commit_token("my-repo", "feat/loop").is_ok());
    assert!(engine.issue_commit_token("my-repo", "feat/loop").is_ok());

    // 4th token within the same minute is blocked
    let fourth = engine.issue_commit_token("my-repo", "feat/loop");
    assert!(fourth.is_err());
    assert!(
        fourth
            .unwrap_err()
            .to_string()
            .contains("Rate limit exceeded")
    );
}

#[test]
fn test_branch_switching_during_active_lease() {
    let policy = LeasePolicy {
        default_ttl: Duration::from_secs(3600),
        block_branches: vec!["main".to_string()],
        allow_main_branch: false,
        allow_branch_switching: true,
        max_commits_per_minute: 10,
        ..Default::default()
    };
    let mut engine = LeaseEngine::new(policy);
    engine.grant_lease("my-repo", "feat/step-1", "Initial task");

    assert_eq!(
        engine
            .get_active_lease("my-repo")
            .map(|l| l.branch.as_str()),
        Some("feat/step-1")
    );

    // Switch to step 2
    let switched = engine.switch_branch("my-repo", "feat/step-2");
    assert!(switched.is_ok());
    assert_eq!(switched.unwrap().branch, "feat/step-2");

    // Tokens can now be issued for feat/step-2
    assert!(engine.issue_commit_token("my-repo", "feat/step-2").is_ok());

    // But not for the old branch
    assert!(engine.issue_commit_token("my-repo", "feat/step-1").is_err());

    // Switching to a protected branch is blocked
    let blocked_switch = engine.switch_branch("my-repo", "main");
    assert!(blocked_switch.is_err());
}

#[test]
fn test_lease_revocation() {
    let mut engine = LeaseEngine::new(LeasePolicy::default());
    engine.grant_lease("my-repo", "feat/task", "Intent");
    assert!(engine.has_active_lease("my-repo"));

    // Revoke lease
    assert!(engine.revoke_lease("my-repo"));
    assert!(!engine.has_active_lease("my-repo"));

    // Second revoke returns false
    assert!(!engine.revoke_lease("my-repo"));
}

#[test]
fn test_get_status() {
    let mut engine = LeaseEngine::new(LeasePolicy::default());
    let (active_before, _, _, _) = engine.get_status("my-repo");
    assert!(!active_before);

    let lease = engine.grant_lease("my-repo", "feat/status-test", "Testing status");
    let (active, id, branch, remaining) = engine.get_status("my-repo");
    assert!(active);
    assert_eq!(id, Some(lease.id));
    assert_eq!(branch, Some("feat/status-test".to_string()));
    assert!(remaining.unwrap() > 0);
}
