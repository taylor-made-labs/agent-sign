use agent_sign::lease::{LeaseEngine, LeasePolicy};
use std::time::Duration;

#[test]
fn test_lease_granted_after_single_auth() {
    let policy = LeasePolicy {
        default_ttl: Duration::from_secs(3600),
        block_branches: vec!["main".to_string(), "master".to_string()],
        max_commits_per_minute: 10,
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
        max_commits_per_minute: 100,
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
fn test_branch_protection_blocks_main() {
    let policy = LeasePolicy {
        default_ttl: Duration::from_secs(3600),
        block_branches: vec!["main".to_string(), "master".to_string()],
        max_commits_per_minute: 10,
    };
    let mut engine = LeaseEngine::new(policy);

    // Attempting to grant or commit on protected branch must fail closed
    let result = engine.try_grant_lease("my-repo", "main", "Unauthorized direct push to main");
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("protected branch"));
}

#[test]
fn test_rate_limiter_throttles_rapid_commits() {
    let policy = LeasePolicy {
        default_ttl: Duration::from_secs(3600),
        block_branches: vec![],
        max_commits_per_minute: 3, // strictly 3 per minute
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
