//! agent-commits' lease model, as tests: a lease's terms are fixed when the person
//! approves it and never grow on their own.
//!
//! Each test names the property it holds: a lease survives a restart without
//! asking again, and nothing lets its terms grow without a new approval.

use agent_commits::config::{LeaseMode, LeaseScope};
use agent_commits::lease::{LeaseEngine, LeasePolicy};

/// Branch rules are checked when a token is issued, whatever the lease's
/// scope. Before, a repository-scoped lease signed commits on `main`, because
/// the check only ran when a lease was granted or moved to another branch.
#[test]
fn repo_scoped_lease_never_signs_on_a_protected_branch() {
    let policy = LeasePolicy {
        mode: LeaseMode::Identity,
        scope: LeaseScope::Repo,
        block_branches: vec!["main".into(), "master".into(), "release/*".into()],
        ..Default::default()
    };
    let mut engine = LeaseEngine::new(policy);
    engine.grant_lease("/r", "feat/x", "work");

    assert!(engine.issue_commit_token("/r", "feat/y").is_ok());
    for protected in ["main", "master", "release/1.0"] {
        let err = engine
            .issue_commit_token("/r", protected)
            .expect_err("a lease never covers a protected branch");
        assert!(err.contains("protected"), "{err}");
    }
}

/// The same holds for a branch-scoped lease whose recorded branch is somehow
/// a protected one (for example a leases.json edited by hand).
#[test]
fn branch_rules_apply_even_to_a_lease_recorded_on_a_protected_branch() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("leases.json");
    std::fs::write(
        &file,
        r#"{"/r":{"id":"x","repo":"/r","branch":"main","intent":"i","mode":"identity",
        "scope":"branch","granted_at_secs":1,"last_used_at_secs":1,
        "expires_at_secs":null,"commit_count":0}}"#,
    )
    .unwrap();
    let mut engine = LeaseEngine::new_with_storage(LeasePolicy::default(), Some(file));
    assert!(engine.issue_commit_token("/r", "main").is_err());
}

/// With `allow_main_branch`, the person has allowed protected branches, and a
/// token is issued as before.
#[test]
fn allow_main_branch_still_allows_protected_branches() {
    let policy = LeasePolicy {
        scope: LeaseScope::Repo,
        allow_main_branch: true,
        ..Default::default()
    };
    let mut engine = LeaseEngine::new(policy);
    engine.grant_lease("/r", "main", "work");
    assert!(engine.issue_commit_token("/r", "main").is_ok());
}

// --- Terms are fixed when approved, and only ever narrowed ------------------

use agent_commits::lease::{Lease, current_epoch_secs};
use std::time::Duration;

/// Writes one lease to a leases.json, as an earlier service run would have.
fn lease_file(dir: &std::path::Path, lease: &Lease) -> std::path::PathBuf {
    let file = dir.join("leases.json");
    let map = std::collections::HashMap::from([(lease.repo.clone(), lease.clone())]);
    std::fs::write(&file, serde_json::to_string(&map).unwrap()).unwrap();
    file
}

fn lease(mode: LeaseMode, granted_ago: u64, recorded_end_after: Option<u64>) -> Lease {
    let granted = current_epoch_secs() - granted_ago;
    Lease {
        id: "id".into(),
        repo: "/r".into(),
        branch: "feat/a".into(),
        intent: "work".into(),
        mode,
        scope: LeaseScope::Branch,
        granted_at_secs: granted,
        last_used_at_secs: granted,
        expires_at_secs: recorded_end_after.map(|d| granted + d),
        commit_count: 0,
        follows_branches: Some(true),
    }
}

/// Using a lease, moving it with the agent, and restarting never move its end.
#[test]
fn using_a_lease_never_moves_its_end() {
    for mode in [LeaseMode::Timed, LeaseMode::Identity] {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("leases.json");
        let policy = LeasePolicy {
            mode,
            default_ttl: Duration::from_secs(3600),
            max_ceiling: Some(Duration::from_secs(7 * 86400)),
            max_commits_per_minute: 100,
            ..Default::default()
        };
        let mut engine = LeaseEngine::new_with_storage(policy.clone(), Some(file.clone()));
        let granted = engine.grant_lease("/r", "feat/a", "work");
        let end = engine.effective_end(&granted);
        assert!(end.is_some(), "{mode:?} lease has a fixed end here");

        for _ in 0..5 {
            engine.issue_commit_token("/r", "feat/a").unwrap();
        }
        engine.switch_branch("/r", "feat/b").unwrap();
        let after_use = engine.get_active_lease("/r").unwrap().clone();
        assert_eq!(after_use.expires_at_secs, granted.expires_at_secs);
        assert_eq!(engine.effective_end(&after_use), end);

        let restarted = LeaseEngine::new_with_storage(policy, Some(file));
        let reloaded = restarted.get_active_lease("/r").unwrap();
        assert_eq!(restarted.effective_end(reloaded), end);
        assert_eq!(reloaded.commit_count, 5);
    }
}

/// A longer ceiling set after approval doesn't lengthen a lease already
/// granted; a shorter one brings its end forward.
#[test]
fn a_new_ceiling_narrows_existing_leases_but_never_extends_them() {
    let dir = tempfile::tempdir().unwrap();
    // Granted 3 days ago with a 5-day ceiling: 2 days left.
    let file = lease_file(
        dir.path(),
        &lease(LeaseMode::Identity, 3 * 86400, Some(5 * 86400)),
    );

    let longer = LeasePolicy {
        max_ceiling: Some(Duration::from_secs(30 * 86400)),
        ..Default::default()
    };
    let engine = LeaseEngine::new_with_storage(longer, Some(file.clone()));
    let l = engine.get_active_lease("/r").expect("still in force");
    assert_eq!(engine.effective_end(l), l.expires_at_secs, "not extended");
    drop(engine);

    let shorter = LeasePolicy {
        max_ceiling: Some(Duration::from_secs(86400)),
        ..Default::default()
    };
    let mut engine = LeaseEngine::new_with_storage(shorter, Some(file));
    assert!(!engine.has_active_lease("/r"), "a 1-day ceiling ended it");
    assert!(engine.issue_commit_token("/r", "feat/a").is_err());
}

/// A lifetime lease (recorded end: until revoked) is brought under a ceiling
/// the person sets later, counted from when it was granted.
#[test]
fn a_ceiling_set_later_bounds_a_lifetime_lease_from_its_grant() {
    let dir = tempfile::tempdir().unwrap();
    let file = lease_file(dir.path(), &lease(LeaseMode::Identity, 10 * 86400, None));

    let none = LeaseEngine::new_with_storage(LeasePolicy::default(), Some(file.clone()));
    let l = none.get_active_lease("/r").expect("until revoked");
    assert_eq!(none.effective_end(l), None);
    drop(none);

    let week = LeasePolicy {
        max_ceiling: Some(Duration::from_secs(7 * 86400)),
        ..Default::default()
    };
    let engine = LeaseEngine::new_with_storage(week, Some(file));
    assert!(
        !engine.has_active_lease("/r"),
        "granted 10 days ago, 7-day ceiling"
    );
}

/// A longer default duration doesn't lengthen a timed lease already granted.
#[test]
fn a_longer_default_duration_never_extends_a_timed_lease() {
    let dir = tempfile::tempdir().unwrap();
    let file = lease_file(
        dir.path(),
        &lease(LeaseMode::Timed, 3 * 3600, Some(2 * 3600)),
    );
    let policy = LeasePolicy {
        mode: LeaseMode::Timed,
        default_ttl: Duration::from_secs(24 * 3600),
        ..Default::default()
    };
    let engine = LeaseEngine::new_with_storage(policy, Some(file));
    assert!(
        !engine.has_active_lease("/r"),
        "its 2-hour term ended an hour ago"
    );
}

/// Whether a lease follows the agent to other branches is recorded when it's
/// approved. Turning branch switching on later doesn't widen a one-branch
/// lease; turning it off narrows one that followed.
#[test]
fn branch_following_is_fixed_at_approval_and_only_narrowed() {
    let one_branch = LeasePolicy {
        allow_branch_switching: false,
        ..Default::default()
    };
    let follows = LeasePolicy::default();
    assert!(follows.allow_branch_switching);

    // Approved for one branch, then the config allows switching.
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("leases.json");
    let mut engine = LeaseEngine::new_with_storage(one_branch.clone(), Some(file.clone()));
    let l = engine.grant_lease("/r", "feat/a", "work");
    assert_eq!(l.follows_branches, Some(false));
    drop(engine);
    let mut engine = LeaseEngine::new_with_storage(follows.clone(), Some(file));
    let err = engine.switch_branch("/r", "feat/b").unwrap_err();
    assert!(err.contains("needs a new approval"), "{err}");
    assert!(engine.issue_commit_token("/r", "feat/b").is_err());
    assert!(engine.issue_commit_token("/r", "feat/a").is_ok());

    // Approved to follow, then the config turns switching off.
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("leases.json");
    let mut engine = LeaseEngine::new_with_storage(follows, Some(file.clone()));
    assert_eq!(
        engine.grant_lease("/r", "feat/a", "work").follows_branches,
        Some(true)
    );
    drop(engine);
    let mut engine = LeaseEngine::new_with_storage(one_branch, Some(file));
    assert!(engine.switch_branch("/r", "feat/b").is_err());
}

/// A repository-scoped lease is narrowed the same way when the config no
/// longer allows leases to cover every branch.
#[test]
fn a_repo_lease_is_narrowed_to_its_branch_when_the_config_narrows() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("leases.json");
    let repo_scope = LeasePolicy {
        scope: LeaseScope::Repo,
        ..Default::default()
    };
    let mut engine = LeaseEngine::new_with_storage(repo_scope, Some(file.clone()));
    engine.grant_lease("/r", "feat/a", "work");
    assert!(engine.issue_commit_token("/r", "feat/b").is_ok());
    drop(engine);

    let narrow = LeasePolicy {
        scope: LeaseScope::Branch,
        allow_branch_switching: false,
        ..Default::default()
    };
    let mut engine = LeaseEngine::new_with_storage(narrow, Some(file));
    assert!(engine.issue_commit_token("/r", "feat/b").is_err());
    assert!(engine.issue_commit_token("/r", "feat/a").is_ok());
}

/// Leases saved before agent-commits recorded branch following (the Mac's 14 leases)
/// keep working exactly as before: the current config decides, so the next
/// commit after an upgrade needs no approval.
#[test]
fn leases_saved_before_this_change_keep_working_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("leases.json");
    let granted = current_epoch_secs() - 86400;
    std::fs::write(
        &file,
        format!(
            r#"{{"/r":{{"id":"old","repo":"/r","branch":"feat/a","intent":"i",
            "mode":"identity","scope":"branch","granted_at_secs":{granted},
            "last_used_at_secs":{granted},"expires_at_secs":null,"commit_count":3}}}}"#
        ),
    )
    .unwrap();
    let mut engine = LeaseEngine::new_with_storage(LeasePolicy::default(), Some(file.clone()));
    let l = engine.get_active_lease("/r").expect("still in force");
    assert_eq!(l.follows_branches, None);
    assert!(engine.switch_branch("/r", "feat/b").is_ok());
    assert!(engine.issue_commit_token("/r", "feat/b").is_ok());

    // Saving keeps the file readable by the previous binaries: the new field
    // is left out while it is unknown.
    let saved = std::fs::read_to_string(&file).unwrap();
    assert!(!saved.contains("follows_branches"));
}

// --- The lease file: never overwritten when it can't be read ---------------

/// A lease file that isn't valid leases is moved aside, not overwritten, and
/// the service starts with no leases, so it asks again instead of signing.
#[test]
fn an_invalid_lease_file_is_set_aside_and_nothing_is_signed() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("leases.json");
    std::fs::write(&file, b"{ not leases").unwrap();

    let mut engine = LeaseEngine::new_with_storage(LeasePolicy::default(), Some(file.clone()));
    assert!(engine.issue_commit_token("/r", "feat/a").is_err());

    let aside: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.starts_with("leases.json.unreadable-"))
        .collect();
    assert_eq!(aside.len(), 1, "{aside:?}");
    assert_eq!(
        std::fs::read(dir.path().join(&aside[0])).unwrap(),
        b"{ not leases"
    );
    // A fresh, valid file replaces it, and new grants are saved.
    engine.grant_lease("/r", "feat/a", "work");
    let reloaded = LeaseEngine::new_with_storage(LeasePolicy::default(), Some(file));
    assert!(reloaded.has_active_lease("/r"));
}

/// A lease file that can't be read (here, no read permission) is left exactly
/// as it is; leases granted meanwhile are kept in memory only.
#[test]
fn an_unreadable_lease_file_is_never_overwritten() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let file = lease_file(dir.path(), &lease(LeaseMode::Identity, 60, None));
    let before = std::fs::read(&file).unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::read(&file).is_ok() {
        return; // running as root: permissions can't make it unreadable
    }

    let mut engine = LeaseEngine::new_with_storage(LeasePolicy::default(), Some(file.clone()));
    engine.grant_lease("/r", "feat/a", "work");
    assert!(engine.issue_commit_token("/r", "feat/a").is_ok());

    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(std::fs::read(&file).unwrap(), before);
}

// --- Config values that bound leases -----------------------------------------

/// A ceiling that isn't a duration is an error, never "no ceiling".
#[test]
fn an_unreadable_ceiling_is_an_error_not_unbounded() {
    use agent_commits::config::SecurityConfig;
    let with = |v: &str| SecurityConfig {
        max_lease_ceiling: v.to_string(),
        ..Default::default()
    };
    assert_eq!(with("none").max_ceiling_duration(), Ok(None));
    assert_eq!(with("").max_ceiling_duration(), Ok(None));
    assert_eq!(
        with("7d").max_ceiling_duration(),
        Ok(Some(Duration::from_secs(7 * 86400)))
    );
    for bad in ["7days", "1w", "forever", "-1h"] {
        let err = with(bad).max_ceiling_duration().unwrap_err();
        assert!(err.contains("not a duration"), "{bad}: {err}");
    }
}

/// The service refuses to start with such a ceiling, before it touches its
/// socket, and says why.
#[test]
fn service_refuses_to_start_with_an_unreadable_ceiling() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    std::fs::write(&config, "[security]\nmax_lease_ceiling = \"forever\"\n").unwrap();
    let socket = dir.path().join("daemon.sock");
    std::fs::write(&socket, b"").unwrap(); // stands in for a running service's socket

    let out = std::process::Command::new(env!("CARGO_BIN_EXE_agent-commitsd"))
        .arg("--socket")
        .arg(&socket)
        .arg("--config")
        .arg(&config)
        .env("HOME", dir.path())
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("not a duration"), "{stderr}");
    assert!(socket.exists(), "the existing socket was left alone");
}

// --- What the person is shown when asked ------------------------------------

/// The approval prompt states the lease's scope and end, in plain words, and
/// never calls a lease that ends on a timer "process-bound".
#[test]
fn the_approval_prompt_states_the_fixed_terms() {
    let lifetime = LeasePolicy::default();
    let t = lifetime.describe_terms("feat/a");
    assert_eq!(
        t.covers,
        "every branch of this repository except protected ones (main, master)"
    );
    assert_eq!(t.ends, "when you revoke it (agent-commits revoke)");

    let one_branch_week = LeasePolicy {
        allow_branch_switching: false,
        max_ceiling: Some(Duration::from_secs(7 * 86400)),
        ..Default::default()
    };
    let t = one_branch_week.describe_terms("feat/a");
    assert_eq!(t.covers, "only branch 'feat/a'");
    assert_eq!(t.ends, "7 days after approval, or sooner if you revoke it");

    let timed = LeasePolicy {
        mode: LeaseMode::Timed,
        default_ttl: Duration::from_secs(2 * 3600),
        ..Default::default()
    };
    assert_eq!(
        timed.describe_terms("x").ends,
        "2 hours after approval, or sooner if you revoke it"
    );

    let process = LeasePolicy {
        mode: LeaseMode::Process,
        ..Default::default()
    };
    let ends = process.describe_terms("x").ends;
    assert!(ends.starts_with("2 hours after approval"), "{ends}");
    assert!(ends.contains("not tied to a process"), "{ends}");
}

#[test]
fn durations_are_described_in_whole_units() {
    use agent_commits::lease::describe_duration;
    assert_eq!(describe_duration(Duration::from_secs(86400)), "1 day");
    assert_eq!(
        describe_duration(Duration::from_secs(90 * 60)),
        "90 minutes"
    );
    assert_eq!(describe_duration(Duration::from_secs(45)), "45 seconds");
}

/// `auto_revoke_on_branch_delete` was never implemented and is gone; config
/// files that still set it (every agent-sign install's) load unchanged.
#[test]
fn old_configs_with_the_dropped_auto_revoke_key_still_load() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("config.toml");
    std::fs::write(
        &file,
        "[security]\nlease_mode = \"identity\"\nauto_revoke_on_branch_delete = true\nmax_commits_per_minute = 7\n",
    )
    .unwrap();
    let config = agent_commits::config::Config::load_from_file(&file).unwrap();
    assert_eq!(config.security.max_commits_per_minute, 7);
    assert_eq!(config.security.lease_mode, LeaseMode::Identity);
}
