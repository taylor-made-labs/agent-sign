//! The move from an agent-sign home to a agent-commits home, against temporary homes.
//!
//! Each test builds a synthetic `~/.agent-sign` shaped like the one
//! `scripts/install.sh` and a running agent-signd leave behind (config, key,
//! leases, socket, bin), then checks that after `migrate_state_dir` the key,
//! the leases, and the config mean exactly what they meant before, reachable
//! from both the new and the old path. No test reads or writes the real home.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};

use agent_commits::config::{Config, LeaseMode, LeaseScope};
use agent_commits::crypto::AgentKeyPair;
use agent_commits::lease::{LeaseEngine, LeasePolicy};
use agent_commits::migrate::{MigrationError, MigrationOutcome, migrate_state_dir};
use agent_commits::paths;
use tempfile::tempdir;

/// A fixed test seed; never a real key.
const TEST_SEED: [u8; 32] = [7u8; 32];

/// The config `scripts/install.sh` writes, with values like the person's
/// (identity leases, branch scope, split attribution) but a harmless fallback.
fn installer_config() -> String {
    r#"# Agent-Sign Configuration
[security]
lease_mode = "identity"
lease_scope = "branch"
default_lease_duration = "2h"
auto_revoke_on_branch_delete = true
allow_main_branch = false
block_branches = ["main", "master"]
max_commits_per_minute = 10
auto_approve = false

[attribution]
mode = "split"

[agent]
name = "Agent"
email = "agent@local.internal"

[ssh]
fallback_program = "/usr/bin/ssh-keygen"
"#
    .to_string()
}

/// Builds `<home>/.agent-sign` the way an agent-sign install leaves it and
/// returns the ids of the leases it granted.
fn build_agent_sign_home(home: &Path, config: &str) -> Vec<String> {
    let base = home.join(".agent-sign");
    let keys = base.join("keys");
    let bin = base.join("bin");
    fs::create_dir_all(&keys).unwrap();
    fs::create_dir_all(&bin).unwrap();
    fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&keys, fs::Permissions::from_mode(0o700)).unwrap();

    let kp = AgentKeyPair::from_bytes(&TEST_SEED).unwrap();
    fs::write(keys.join("agent_ed25519"), TEST_SEED).unwrap();
    fs::set_permissions(
        keys.join("agent_ed25519"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    fs::write(keys.join("agent_ed25519.pub"), kp.public_key_openssh()).unwrap();

    fs::write(base.join("config.toml"), config).unwrap();

    for name in ["agent-signd", "agent-sign", "agent-git", "git"] {
        fs::write(
            bin.join(name),
            format!("#!/bin/sh\n# stand-in for {name}\n"),
        )
        .unwrap();
        fs::set_permissions(bin.join(name), fs::Permissions::from_mode(0o755)).unwrap();
    }

    // A stale socket, as a stopped agent-signd leaves one.
    drop(UnixListener::bind(base.join("daemon.sock")).unwrap());

    // Leases written by the real lease engine, as agent-signd writes them.
    let policy = LeasePolicy {
        mode: LeaseMode::Identity,
        scope: LeaseScope::Branch,
        ..Default::default()
    };
    let mut engine = LeaseEngine::new_with_storage(policy, Some(base.join("leases.json")));
    let a = engine.grant_lease(
        "/Users/someone/dev/repo-a",
        "feat/one",
        "Autonomous coding agent commit",
    );
    let b = engine.grant_lease(
        "/Users/someone/dev/repo-b",
        "fix/two",
        "Autonomous coding agent commit",
    );
    engine
        .issue_commit_token("/Users/someone/dev/repo-b", "fix/two")
        .unwrap();
    vec![a.id, b.id]
}

/// Everything about a state directory that must survive the move.
#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    files: BTreeMap<String, Vec<u8>>,
    modes: BTreeMap<String, u32>,
}

fn snapshot(dir: &Path) -> Snapshot {
    let mut files = BTreeMap::new();
    let mut modes = BTreeMap::new();
    for rel in [
        "config.toml",
        "leases.json",
        "keys/agent_ed25519",
        "keys/agent_ed25519.pub",
        "bin/agent-signd",
        "bin/git",
    ] {
        let p = dir.join(rel);
        files.insert(rel.to_string(), fs::read(&p).unwrap());
        modes.insert(
            rel.to_string(),
            fs::metadata(&p).unwrap().permissions().mode() & 0o7777,
        );
    }
    for rel in [".", "keys"] {
        modes.insert(
            rel.to_string(),
            fs::metadata(dir.join(rel)).unwrap().permissions().mode() & 0o7777,
        );
    }
    Snapshot { files, modes }
}

/// The config as the programs see it, with the key path compared separately.
fn config_semantics(home: &Path) -> (String, PathBuf) {
    let mut config = Config::load_in_home(home, None);
    let key = config.ssh.agent_key_path.clone();
    config.ssh.agent_key_path = PathBuf::new();
    (toml::to_string(&config).unwrap(), key)
}

fn lease_engine_at(dir: &Path) -> LeaseEngine {
    LeaseEngine::new_with_storage(LeasePolicy::default(), Some(dir.join("leases.json")))
}

#[test]
fn migration_moves_agent_sign_home_with_identical_leases_key_and_config() {
    let tmp = tempdir().unwrap();
    let home = tmp.path();
    let lease_ids = build_agent_sign_home(home, &installer_config());
    let legacy = home.join(".agent-sign");
    let agent_commits_dir = home.join(".agent-commits");

    // Before: the programs use ~/.agent-sign.
    assert_eq!(paths::state_dir_in(home), legacy);
    let before = snapshot(&legacy);
    let (config_before, key_before) = config_semantics(home);
    assert_eq!(key_before, legacy.join("keys/agent_ed25519"));

    let outcome = migrate_state_dir(home).unwrap();
    assert_eq!(
        outcome,
        MigrationOutcome::Migrated {
            from: legacy.clone(),
            to: agent_commits_dir.clone()
        }
    );

    // The directory moved, and a link to it was left at the old path.
    assert!(fs::symlink_metadata(&agent_commits_dir).unwrap().is_dir());
    assert!(
        fs::symlink_metadata(&legacy)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read_link(&legacy).unwrap(), agent_commits_dir);
    assert_eq!(paths::state_dir_in(home), agent_commits_dir);

    // Same bytes and permissions, through the new path and through the old one.
    assert_eq!(snapshot(&agent_commits_dir), before);
    assert_eq!(snapshot(&legacy), before);

    // The config means the same, and its key path reaches the same key file.
    let (config_after, key_after) = config_semantics(home);
    assert_eq!(config_after, config_before);
    assert_eq!(key_after, agent_commits_dir.join("keys/agent_ed25519"));
    assert_eq!(fs::read(&key_after).unwrap(), TEST_SEED);
    assert_eq!(
        fs::canonicalize(&key_after).unwrap(),
        fs::canonicalize(&key_before).unwrap()
    );

    // The leases are the same leases, and still honoured without a new grant.
    let mut engine = lease_engine_at(&agent_commits_dir);
    let mut ids: Vec<String> = engine
        .list_leases()
        .into_iter()
        .map(|l| l.lease_id)
        .collect();
    ids.sort();
    let mut expected = lease_ids.clone();
    expected.sort();
    assert_eq!(ids, expected);
    let b = engine
        .get_active_lease("/Users/someone/dev/repo-b")
        .unwrap();
    assert_eq!(b.branch, "fix/two");
    assert_eq!(b.commit_count, 1);
    assert_eq!(b.expires_at_secs, None);
    assert!(
        engine
            .issue_commit_token("/Users/someone/dev/repo-a", "feat/one")
            .is_ok()
    );

    // Running it again changes nothing.
    let after_first = snapshot(&agent_commits_dir);
    assert_eq!(
        migrate_state_dir(home).unwrap(),
        MigrationOutcome::AlreadyMigrated
    );
    assert_eq!(snapshot(&agent_commits_dir), after_first);
}

#[test]
fn absolute_agent_sign_paths_in_config_keep_their_meaning() {
    let tmp = tempdir().unwrap();
    let home = tmp.path();
    let config = format!(
        "{}agent_key_path = \"{}\"\n",
        installer_config(),
        home.join(".agent-sign/keys/agent_ed25519").display()
    );
    build_agent_sign_home(home, &config);

    let (_, before) = config_semantics(home);
    assert_eq!(before, home.join(".agent-sign/keys/agent_ed25519"));

    migrate_state_dir(home).unwrap();
    let (_, after) = config_semantics(home);
    assert_eq!(after, home.join(".agent-commits/keys/agent_ed25519"));
    assert_eq!(fs::read(&after).unwrap(), TEST_SEED);

    // Even if the person later removes the link, the old path still resolves.
    fs::remove_file(home.join(".agent-sign")).unwrap();
    let (_, without_link) = config_semantics(home);
    assert_eq!(fs::read(without_link).unwrap(), TEST_SEED);
}

#[test]
fn fresh_home_is_left_alone() {
    let tmp = tempdir().unwrap();
    assert_eq!(
        migrate_state_dir(tmp.path()).unwrap(),
        MigrationOutcome::NothingToMigrate
    );
    assert!(!tmp.path().join(".agent-commits").exists());
    assert!(!tmp.path().join(".agent-sign").exists());
}

#[test]
fn both_homes_holding_state_is_refused_and_nothing_moves() {
    let tmp = tempdir().unwrap();
    let home = tmp.path();
    build_agent_sign_home(home, &installer_config());
    let agent_commits_dir = home.join(".agent-commits");
    fs::create_dir_all(agent_commits_dir.join("keys")).unwrap();
    fs::write(agent_commits_dir.join("keys/agent_ed25519"), [9u8; 32]).unwrap();
    let before = snapshot(&home.join(".agent-sign"));

    let err = migrate_state_dir(home).unwrap_err();
    assert!(matches!(err, MigrationError::Conflict { .. }), "{err}");
    assert!(
        fs::symlink_metadata(home.join(".agent-sign"))
            .unwrap()
            .is_dir()
    );
    assert_eq!(snapshot(&home.join(".agent-sign")), before);
    assert_eq!(
        fs::read(agent_commits_dir.join("keys/agent_ed25519")).unwrap(),
        [9u8; 32]
    );
}

#[test]
fn an_empty_agent_commits_dir_does_not_block_the_move() {
    let tmp = tempdir().unwrap();
    let home = tmp.path();
    build_agent_sign_home(home, &installer_config());
    let before = snapshot(&home.join(".agent-sign"));
    fs::create_dir(home.join(".agent-commits")).unwrap();

    assert!(matches!(
        migrate_state_dir(home).unwrap(),
        MigrationOutcome::Migrated { .. }
    ));
    assert_eq!(snapshot(&home.join(".agent-commits")), before);
}

#[test]
fn an_agent_sign_link_to_elsewhere_is_kept_and_used() {
    let tmp = tempdir().unwrap();
    let home = tmp.path().join("home");
    let elsewhere = tmp.path().join("elsewhere");
    fs::create_dir_all(&home).unwrap();
    build_agent_sign_home(tmp.path(), &installer_config());
    fs::rename(tmp.path().join(".agent-sign"), &elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, home.join(".agent-sign")).unwrap();

    assert_eq!(
        migrate_state_dir(&home).unwrap(),
        MigrationOutcome::LeftLegacyLink {
            target: elsewhere.clone()
        }
    );
    assert!(!home.join(".agent-commits").exists());
    assert_eq!(paths::state_dir_in(&home), home.join(".agent-sign"));
}

#[test]
fn a_file_named_agent_sign_is_an_error_not_a_move() {
    let tmp = tempdir().unwrap();
    fs::write(tmp.path().join(".agent-sign"), b"not a directory").unwrap();
    assert!(matches!(
        migrate_state_dir(tmp.path()).unwrap_err(),
        MigrationError::NotADirectory { .. }
    ));
    assert!(!tmp.path().join(".agent-commits").exists());
}
