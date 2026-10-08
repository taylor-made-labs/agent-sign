//! A rehearsal of the switch described in `docs/MIGRATION.md`, in a temporary
//! home: an agent-sign home with an existing lease gets the new binaries
//! (old names become links), the service is started by its old path the way
//! the LaunchAgent starts it, and an agent commit made through `git` on `PATH`
//! must be signed with the same key, under the same lease, with no approval
//! prompt.
//!
//! The service runs without `--auto-approve`, and a stand-in `osascript` (and
//! `zenity`/`kdialog`) that records any call and answers "Deny" comes first on
//! its `PATH`. So the commit can only succeed if the existing lease was
//! honoured, and no real dialog can appear on the person's screen.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use agent_commits::crypto::AgentKeyPair;
use agent_commits::lease::{LeaseEngine, LeasePolicy};
use tempfile::tempdir;

/// A fixed test seed; never a real key.
const TEST_SEED: [u8; 32] = [7u8; 32];
const BRANCH: &str = "feat/agent-work";
const PERSON_EMAIL: &str = "person@example.com";

struct Service(Child);

impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn write_script(path: &Path, body: &str) {
    fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

/// Runs git with no global or system config, so the person's own settings
/// (signing with 1Password, for one) never apply.
fn plain_git(home: &Path, dir: &Path, args: &[&str]) -> Output {
    Command::new("/usr/bin/git")
        .args(args)
        .current_dir(dir)
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap()
}

/// Installs the built programs the way MIGRATION.md does: new names as files,
/// `git` as a copy of the wrapper, and the old names as links.
fn install_binaries(bin: &Path) {
    for (name, built) in [
        ("agent-commits", env!("CARGO_BIN_EXE_agent-commits")),
        ("agent-commitsd", env!("CARGO_BIN_EXE_agent-commitsd")),
        (
            "agent-commits-ssh-sign",
            env!("CARGO_BIN_EXE_agent-commits-ssh-sign"),
        ),
        ("agent-commits-git", env!("CARGO_BIN_EXE_agent-commits-git")),
        ("git", env!("CARGO_BIN_EXE_agent-commits-git")),
    ] {
        let _ = fs::remove_file(bin.join(name));
        fs::copy(built, bin.join(name)).unwrap();
    }
    for (old, new) in [
        ("agent-sign", "agent-commits"),
        ("agent-signd", "agent-commitsd"),
        ("agent-git", "agent-commits-git"),
    ] {
        let _ = fs::remove_file(bin.join(old));
        std::os::unix::fs::symlink(new, bin.join(old)).unwrap();
    }
}

fn start_service(program: &Path, home: &Path, fakebin: &Path) -> Service {
    let child = Command::new(program)
        .env("HOME", home)
        .env("PATH", format!("{}:/usr/bin:/bin", fakebin.display()))
        .env_remove("DISPLAY")
        .env_remove("WAYLAND_DISPLAY")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to start the service");
    let socket = home.join(".agent-commits/daemon.sock");
    let start = Instant::now();
    while !socket.exists() {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "service did not create {}",
            socket.display()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    Service(child)
}

fn lease_on_disk(state: &Path, repo: &str) -> serde_json::Value {
    let raw = fs::read_to_string(state.join("leases.json")).unwrap();
    let all: serde_json::Value = serde_json::from_str(&raw).unwrap();
    all[repo].clone()
}

#[test]
fn switching_an_agent_sign_install_keeps_signing_with_no_prompt() {
    let tmp = tempdir().unwrap();
    let home = tmp.path().join("home");
    let legacy = home.join(".agent-sign");
    let bin = legacy.join("bin");
    let keys = legacy.join("keys");
    fs::create_dir_all(&bin).unwrap();
    fs::create_dir_all(&keys).unwrap();
    fs::set_permissions(&legacy, fs::Permissions::from_mode(0o700)).unwrap();

    // Stand-ins: approval dialogs that record and deny, and a fallback signer
    // (the person's own, in real life) that records and fails.
    let fakebin = tmp.path().join("fakebin");
    fs::create_dir_all(&fakebin).unwrap();
    let prompts = tmp.path().join("prompts");
    for name in ["osascript", "zenity", "kdialog"] {
        write_script(
            &fakebin.join(name),
            &format!(
                "echo {name} >> '{}'\necho 'button returned:Deny'\nexit 1",
                prompts.display()
            ),
        );
    }
    let fallback_calls = tmp.path().join("fallback-calls");
    let fallback = fakebin.join("person-signer");
    write_script(
        &fallback,
        &format!("echo \"$@\" >> '{}'\nexit 1", fallback_calls.display()),
    );

    // The agent-sign home: key, config as the installer writes it, and a lease
    // granted earlier for the repository and branch the agent is working on.
    let kp = AgentKeyPair::from_bytes(&TEST_SEED).unwrap();
    fs::write(keys.join("agent_ed25519"), TEST_SEED).unwrap();
    fs::set_permissions(
        keys.join("agent_ed25519"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    fs::write(keys.join("agent_ed25519.pub"), kp.public_key_openssh()).unwrap();
    fs::write(
        legacy.join("config.toml"),
        format!(
            "[security]\nlease_mode = \"identity\"\nlease_scope = \"branch\"\nauto_approve = false\nblock_branches = [\"main\", \"master\"]\n\n[attribution]\nmode = \"split\"\n\n[agent]\nname = \"Agent\"\nemail = \"agent@local.internal\"\n\n[ssh]\nfallback_program = \"{}\"\n",
            fallback.display()
        ),
    )
    .unwrap();

    let repo = tmp.path().join("repo");
    fs::create_dir_all(&repo).unwrap();
    assert!(
        plain_git(&home, &repo, &["init", "-q", "-b", BRANCH])
            .status
            .success()
    );
    plain_git(&home, &repo, &["config", "user.name", "Person"]);
    plain_git(&home, &repo, &["config", "user.email", PERSON_EMAIL]);
    let repo_key = fs::canonicalize(&repo)
        .unwrap()
        .to_string_lossy()
        .to_string();

    let lease_id = {
        let mut engine =
            LeaseEngine::new_with_storage(LeasePolicy::default(), Some(legacy.join("leases.json")));
        engine
            .grant_lease(&repo_key, BRANCH, "Autonomous coding agent commit")
            .id
    };

    // Install the new binaries, then start the service by the LaunchAgent's
    // path. It migrates ~/.agent-sign to ~/.agent-commits on start.
    install_binaries(&bin);
    let service = start_service(&bin.join("agent-signd"), &home, &fakebin);
    let agent_commits_dir = home.join(".agent-commits");
    assert!(fs::symlink_metadata(&agent_commits_dir).unwrap().is_dir());
    assert_eq!(fs::read_link(&legacy).unwrap(), agent_commits_dir);
    assert_eq!(
        fs::read(agent_commits_dir.join("keys/agent_ed25519")).unwrap(),
        TEST_SEED
    );

    // An agent commit through `git` on PATH (the ~/.agent-sign/bin entry).
    let agent_path = format!("{}:{}:/usr/bin:/bin", bin.display(), fakebin.display());
    let commit = |file: &str| {
        fs::write(repo.join(file), format!("{file}\n")).unwrap();
        plain_git(&home, &repo, &["add", file]);
        Command::new(bin.join("git"))
            .env_remove("CLAUDECODE")
            .env_remove("GEMINI_CLI")
            .env_remove("CODEX_THREAD_ID")
            .args(["commit", "-q", "-m", &format!("feat: add {file}")])
            .current_dir(&repo)
            .env("HOME", &home)
            .env("PATH", &agent_path)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env_remove("AGENT_COMMITS_SOCKET")
            .env_remove("AGENT_SIGN_SOCKET")
            .env_remove("AGENT_COMMITS_BIN")
            .env_remove("AGENT_SIGN_BIN")
            .stdin(Stdio::null())
            .output()
            .unwrap()
    };
    let out = commit("one.txt");
    assert!(
        out.status.success(),
        "agent commit failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // No approval was asked for, and the person's signer was never involved.
    assert!(!prompts.exists(), "an approval prompt was shown");
    assert!(!fallback_calls.exists(), "the person's signer was called");

    // Same attribution as before, and the signature verifies with the old key.
    let who = plain_git(
        &home,
        &repo,
        &["log", "-1", "--format=%an <%ae> | %cn <%ce>"],
    );
    assert_eq!(
        String::from_utf8_lossy(&who.stdout).trim(),
        format!("Agent <agent@local.internal> | Person <{PERSON_EMAIL}>")
    );
    let allowed = tmp.path().join("allowed_signers");
    fs::write(
        &allowed,
        format!("{PERSON_EMAIL} {}\n", kp.public_key_openssh()),
    )
    .unwrap();
    let verify = |rev: &str| {
        plain_git(
            &home,
            &repo,
            &[
                "-c",
                &format!("gpg.ssh.allowedSignersFile={}", allowed.display()),
                "-c",
                "gpg.ssh.program=ssh-keygen",
                "verify-commit",
                rev,
            ],
        )
    };
    let v = verify("HEAD");
    assert!(
        v.status.success(),
        "verify-commit failed: {}",
        String::from_utf8_lossy(&v.stderr)
    );

    // The same lease was used, not a new one.
    let lease = lease_on_disk(&agent_commits_dir, &repo_key);
    assert_eq!(lease["id"], lease_id.as_str());
    assert_eq!(lease["commit_count"], 1);

    // The old program names still run.
    let run = |name: &str, args: &[&str]| {
        Command::new(bin.join(name))
            .args(args)
            .current_dir(&repo)
            .env("HOME", &home)
            .env("PATH", &agent_path)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .unwrap()
    };
    let leases = run("agent-sign", &["leases"]);
    assert!(leases.status.success());
    assert!(String::from_utf8_lossy(&leases.stdout).contains(BRANCH));
    let status = run("agent-signd", &["status"]);
    assert!(String::from_utf8_lossy(&status.stdout).contains("active"));
    let version = run("agent-git", &["--version"]);
    assert!(String::from_utf8_lossy(&version.stdout).starts_with("git version"));

    // After a restart (now by the new path), the lease still holds.
    drop(service);
    let _ = fs::remove_file(agent_commits_dir.join("daemon.sock"));
    let _service = start_service(
        &agent_commits_dir.join("bin/agent-commitsd"),
        &home,
        &fakebin,
    );
    let out = commit("two.txt");
    assert!(
        out.status.success(),
        "commit after restart failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(verify("HEAD").status.success());
    assert!(
        !prompts.exists(),
        "an approval prompt was shown after restart"
    );
    assert_eq!(
        lease_on_disk(&agent_commits_dir, &repo_key)["commit_count"],
        2
    );
    assert_eq!(
        lease_on_disk(&agent_commits_dir, &repo_key)["id"],
        lease_id.as_str()
    );
}

#[test]
fn a_new_home_gets_only_the_agent_commits_directory() {
    let tmp = tempdir().unwrap();
    let home = tmp.path().join("home");
    fs::create_dir_all(&home).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_agent-commitsd"))
        .arg("setup")
        .env("HOME", &home)
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(home.join(".agent-commits/keys/agent_ed25519").exists());
    assert!(home.join(".agent-commits/keys/agent_ed25519.pub").exists());
    assert!(!home.join(".agent-sign").exists());
}
