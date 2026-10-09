use agent_sign::config::{LeaseMode, LeaseScope};
use agent_sign::lease::{LeaseEngine, LeasePolicy};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::thread::sleep;
use std::time::Duration;
use tempfile::tempdir;

#[test]
fn test_identity_lease_persists_across_daemon_restarts() {
    let tmp = tempdir().unwrap();
    let storage_file = tmp.path().join("leases.json");

    let policy = LeasePolicy {
        mode: LeaseMode::Identity,
        scope: LeaseScope::Branch,
        ..Default::default()
    };

    // 1. Initial Daemon Session
    {
        let mut engine = LeaseEngine::new_with_storage(policy.clone(), Some(storage_file.clone()));

        assert!(!engine.has_active_lease("corp/repo-a"));

        // Grant worker identity mandate (indefinite)
        let lease = engine.grant_lease("corp/repo-a", "feat/ai-task", "Autonomous feature");
        assert_eq!(lease.mode, LeaseMode::Identity);
        assert_eq!(lease.expires_at_secs, None); // Indefinite lifetime
        assert_eq!(lease.commit_count, 0);

        // Commit 1
        let tok1 = engine.issue_commit_token("corp/repo-a", "feat/ai-task");
        assert!(tok1.is_ok());

        // Commit 2
        let tok2 = engine.issue_commit_token("corp/repo-a", "feat/ai-task");
        assert!(tok2.is_ok());

        // File should exist and have 0600 permissions
        assert!(storage_file.exists());
        let meta = fs::metadata(&storage_file).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    } // Daemon process exits / crashes here

    // 2. Restarted Daemon Session (New process instance loading same file)
    {
        let mut engine = LeaseEngine::new_with_storage(policy.clone(), Some(storage_file.clone()));

        // Mandate must still be active with zero re-prompting
        assert!(engine.has_active_lease("corp/repo-a"));

        let active = engine.get_active_lease("corp/repo-a").unwrap();
        assert_eq!(active.branch, "feat/ai-task");
        assert_eq!(active.mode, LeaseMode::Identity);
        assert_eq!(active.commit_count, 2);
        assert_eq!(active.expires_at_secs, None);

        // Resume work: agent can commit immediately after restart
        let tok3 = engine.issue_commit_token("corp/repo-a", "feat/ai-task");
        assert!(tok3.is_ok());

        let active_after = engine.get_active_lease("corp/repo-a").unwrap();
        assert_eq!(active_after.commit_count, 3);
    }
}

#[test]
fn test_explicit_revocation_persists_across_restarts() {
    let tmp = tempdir().unwrap();
    let storage_file = tmp.path().join("leases.json");

    let policy = LeasePolicy {
        mode: LeaseMode::Identity,
        ..Default::default()
    };

    // Grant and then explicitly revoke
    {
        let mut engine = LeaseEngine::new_with_storage(policy.clone(), Some(storage_file.clone()));
        engine.grant_lease("corp/repo-b", "feat/bugfix", "Fixing bug");
        assert!(engine.has_active_lease("corp/repo-b"));

        // Revoke
        assert!(engine.revoke_lease("corp/repo-b"));
        assert!(!engine.has_active_lease("corp/repo-b"));
    }

    // Restart daemon - revocation must remain enforced
    {
        let mut engine = LeaseEngine::new_with_storage(policy.clone(), Some(storage_file.clone()));
        assert!(!engine.has_active_lease("corp/repo-b"));

        // Issuing token must fail closed
        let tok = engine.issue_commit_token("corp/repo-b", "feat/bugfix");
        assert!(tok.is_err());
    }
}

#[test]
fn test_identity_lease_ceiling_enforcement() {
    let tmp = tempdir().unwrap();
    let storage_file = tmp.path().join("leases.json");

    // A 2-second ceiling. Lease times are whole seconds, so a 1-second
    // ceiling granted just before a second boundary has already ended a
    // moment later; 2 seconds leaves at least one whole second of life.
    let policy = LeasePolicy {
        mode: LeaseMode::Identity,
        max_ceiling: Some(Duration::from_secs(2)),
        ..Default::default()
    };

    let mut engine = LeaseEngine::new_with_storage(policy, Some(storage_file.clone()));
    let lease = engine.grant_lease("corp/repo-c", "feat/ceiling-test", "Short lived ceiling");
    assert!(lease.expires_at_secs.is_some());

    // Initially valid
    assert!(
        engine
            .issue_commit_token("corp/repo-c", "feat/ceiling-test")
            .is_ok()
    );

    // Wait for ceiling to elapse
    sleep(Duration::from_millis(2100));

    // Must be expired
    assert!(!engine.has_active_lease("corp/repo-c"));
    let tok = engine.issue_commit_token("corp/repo-c", "feat/ceiling-test");
    assert!(tok.is_err());
    assert!(tok.unwrap_err().contains("expired"));
}

#[test]
fn test_lease_scope_branch_vs_repo() {
    // 1. Branch Scope (default): commits on other branches fail
    {
        let policy = LeasePolicy {
            mode: LeaseMode::Identity,
            scope: LeaseScope::Branch,
            ..Default::default()
        };
        let mut engine = LeaseEngine::new(policy);
        engine.grant_lease("corp/repo-d", "feat/branch-a", "Task A");

        assert!(
            engine
                .issue_commit_token("corp/repo-d", "feat/branch-a")
                .is_ok()
        );
        let wrong_branch = engine.issue_commit_token("corp/repo-d", "feat/branch-b");
        assert!(wrong_branch.is_err());
        assert!(wrong_branch.unwrap_err().contains("was granted for branch"));
    }

    // 2. Repo Scope: commits on any non-protected branch succeed
    {
        let policy = LeasePolicy {
            mode: LeaseMode::Identity,
            scope: LeaseScope::Repo,
            ..Default::default()
        };
        let mut engine = LeaseEngine::new(policy);
        engine.grant_lease("corp/repo-d", "feat/branch-a", "Task A");

        assert!(
            engine
                .issue_commit_token("corp/repo-d", "feat/branch-a")
                .is_ok()
        );
        // Different branch works without re-prompt or switch!
        assert!(
            engine
                .issue_commit_token("corp/repo-d", "feat/branch-b")
                .is_ok()
        );
    }
}

#[test]
fn test_list_leases_and_revoke_all() {
    let tmp = tempdir().unwrap();
    let storage_file = tmp.path().join("leases.json");

    let policy = LeasePolicy {
        mode: LeaseMode::Identity,
        ..Default::default()
    };

    let mut engine = LeaseEngine::new_with_storage(policy, Some(storage_file.clone()));
    engine.grant_lease("org/repo-1", "feat/one", "Task 1");
    engine.grant_lease("org/repo-2", "feat/two", "Task 2");

    let list = engine.list_leases();
    assert_eq!(list.len(), 2);

    // Revoke all
    let revoked_count = engine.revoke_all();
    assert_eq!(revoked_count, 2);
    assert_eq!(engine.list_leases().len(), 0);
}
