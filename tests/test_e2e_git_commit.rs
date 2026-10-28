//! End-to-end: a real service, the git wrapper, the signing program, and git,
//! each in a temporary home with its own socket.
//!

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tempfile::tempdir;

/// The programs and names one run of a scenario uses.
struct Bins {
    daemon: PathBuf,
    git: PathBuf,
    sign: PathBuf,
    env_prefix: &'static str,
}

impl Bins {
    fn new_names() -> Self {
        Bins {
            daemon: PathBuf::from(env!("CARGO_BIN_EXE_agent-signd")),
            git: PathBuf::from(env!("CARGO_BIN_EXE_agent-git")),
            sign: PathBuf::from(env!("CARGO_BIN_EXE_agent-ssh-sign")),
            env_prefix: "AGENT_SIGN_",
        }
    }

    fn env(&self, suffix: &str) -> String {
        format!("{}{}", self.env_prefix, suffix)
    }
}

struct TestDaemon {
    child: Child,
    pub socket_path: std::path::PathBuf,
}

impl Drop for TestDaemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_file(&self.socket_path);
    }
}

fn start_test_daemon(dir: &Path, bins: &Bins) -> TestDaemon {
    let socket_path = dir.join("test_daemon.sock");
    let keys_dir = dir.join("keys");
    fs::create_dir_all(&keys_dir).unwrap();

    let daemon_bin = &bins.daemon;

    // Spawn daemon with test socket and auto-approve
    let child = Command::new(daemon_bin)
        .arg("--socket")
        .arg(&socket_path)
        .arg("--auto-approve")
        .env("HOME", dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn test agent-signd");

    // Poll until socket exists
    let start = std::time::Instant::now();
    while !socket_path.exists() {
        if start.elapsed() > Duration::from_secs(5) {
            panic!("Test daemon failed to create socket in time");
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    TestDaemon { child, socket_path }
}

fn scenario_agent_git_commit_and_verification(bins: &Bins) {
    let dir = tempdir().expect("Failed to create tempdir");
    let test_repo = dir.path().join("repo");
    fs::create_dir_all(&test_repo).unwrap();

    // 1. Start daemon on test socket
    let daemon = start_test_daemon(dir.path(), bins);

    // 2. Initialize real Git repo
    assert!(
        Command::new("git")
            .args(["init", "-b", "feat/my-agent-branch"])
            .current_dir(&test_repo)
            .status()
            .unwrap()
            .success()
    );

    assert!(
        Command::new("git")
            .args(["config", "user.name", "Human Developer"])
            .current_dir(&test_repo)
            .status()
            .unwrap()
            .success()
    );

    assert!(
        Command::new("git")
            .args(["config", "user.email", "dev@example.com"])
            .current_dir(&test_repo)
            .status()
            .unwrap()
            .success()
    );

    // 3. Create a test file and stage it
    let test_file = test_repo.join("hello.txt");
    fs::write(&test_file, "Hello from autonomous agent!\n").unwrap();

    assert!(
        Command::new("git")
            .args(["add", "hello.txt"])
            .current_dir(&test_repo)
            .status()
            .unwrap()
            .success()
    );

    // 4. Execute commit using agent-git
    let agent_git_bin = &bins.git;
    let agent_sign_bin = &bins.sign;

    let commit_output = Command::new(agent_git_bin)
        // No agent marks from whatever runs the tests (see KNOWN_AGENTS).
        .env_remove("CLAUDECODE")
        .env_remove("GEMINI_CLI")
        .env_remove("CODEX_THREAD_ID")
        .env_remove("CODEX_SESSION_ID")
        // The agent says who it is: since the identity review (28 Oct 2026)
        // an unmarked commit with no terminal is left to git, unsigned.
        .env("AGENT_SIGN_AGENT_NAME", "Test Agent")
        .args(["commit", "-m", "feat: first agent commit"])
        .current_dir(&test_repo)
        .env(bins.env("SOCKET"), &daemon.socket_path)
        .env(bins.env("BIN"), agent_sign_bin)
        .env("HOME", dir.path())
        .output()
        .expect("Failed to run agent-git commit");

    let stdout = String::from_utf8_lossy(&commit_output.stdout);
    let stderr = String::from_utf8_lossy(&commit_output.stderr);

    assert!(
        commit_output.status.success(),
        "agent-git commit failed!\nSTDOUT: {}\nSTDERR: {}",
        stdout,
        stderr
    );

    // 5. Verify the commit in Git history
    let log_output = Command::new("git")
        .args(["log", "-1", "--format=%an <%ae> | %cn <%ce>"])
        .current_dir(&test_repo)
        .output()
        .unwrap();

    let log_str = String::from_utf8_lossy(&log_output.stdout);
    println!("Commit Log: {}", log_str);

    // Attribution verified: the agent (named "Test Agent", with no session
    // id) is both author and committer, never the person.
    assert_eq!(
        log_str.trim(),
        "Test Agent <test-agent.nosession@agents.local> | Test Agent <test-agent.nosession@agents.local>"
    );
    assert!(!log_str.contains("Human Developer <dev@example.com>"));

    // 6. Verify the signature under the agents' trust line
    let ca_path = dir.path().join(".agent-sign/keys/agents_ca_ed25519.pub");
    assert!(
        ca_path.exists(),
        "The agents' certificate authority must exist after the service starts"
    );
    let ca = fs::read_to_string(&ca_path).unwrap();

    let allowed_signers = dir.path().join("allowed_signers");
    fs::write(
        &allowed_signers,
        format!(
            "*@agents.local cert-authority,namespaces=\"git\" {}\n",
            ca.trim()
        ),
    )
    .unwrap();

    // Verify with git show-signature
    let sig_check = Command::new("git")
        .args([
            "-c",
            &format!("gpg.ssh.allowedSignersFile={}", allowed_signers.display()),
            "log",
            "-1",
            "--show-signature",
        ])
        .current_dir(&test_repo)
        .output()
        .unwrap();

    let sig_out = String::from_utf8_lossy(&sig_check.stderr);
    let sig_std = String::from_utf8_lossy(&sig_check.stdout);
    println!("Git Show Signature Output:\n{}{}", sig_out, sig_std);

    assert!(
        sig_out.contains("Good \"git\" signature") || sig_std.contains("Good \"git\" signature"),
        "Expected Good \"git\" signature in git log output!"
    );
}

fn scenario_multi_commit_headless_session_flow(bins: &Bins) {
    let dir = tempdir().expect("Failed to create tempdir");
    let test_repo = dir.path().join("repo");
    fs::create_dir_all(&test_repo).unwrap();

    let daemon = start_test_daemon(dir.path(), bins);

    assert!(
        Command::new("git")
            .args(["init", "-b", "feat/autonomous-task"])
            .current_dir(&test_repo)
            .status()
            .unwrap()
            .success()
    );

    assert!(
        Command::new("git")
            .args(["config", "user.name", "Multi Dev"])
            .current_dir(&test_repo)
            .status()
            .unwrap()
            .success()
    );

    assert!(
        Command::new("git")
            .args(["config", "user.email", "multidev@example.com"])
            .current_dir(&test_repo)
            .status()
            .unwrap()
            .success()
    );

    let agent_git_bin = &bins.git;
    let agent_sign_bin = &bins.sign;

    // Execute 3 consecutive commits in the same session/branch
    for i in 1..=3 {
        let file_path = test_repo.join(format!("file_{}.txt", i));
        fs::write(&file_path, format!("Agent content version {}\n", i)).unwrap();

        assert!(
            Command::new("git")
                .args(["add", &format!("file_{}.txt", i)])
                .current_dir(&test_repo)
                .status()
                .unwrap()
                .success()
        );

        let commit_out = Command::new(agent_git_bin)
            // No agent marks from whatever runs the tests (see KNOWN_AGENTS).
            .env_remove("CLAUDECODE")
            .env_remove("GEMINI_CLI")
            .env_remove("CODEX_THREAD_ID")
            .env_remove("CODEX_SESSION_ID")
            // The agent says who it is: since the identity review (28 Oct 2026)
            // an unmarked commit with no terminal is left to git, unsigned.
            .env("AGENT_SIGN_AGENT_NAME", "Test Agent")
            .args(["commit", "-m", &format!("feat: agent commit number {}", i)])
            .current_dir(&test_repo)
            .env(bins.env("SOCKET"), &daemon.socket_path)
            .env(bins.env("BIN"), agent_sign_bin)
            .env("HOME", dir.path())
            .output()
            .expect("Failed to execute agent commit");

        assert!(
            commit_out.status.success(),
            "Commit {} failed! Stderr: {}",
            i,
            String::from_utf8_lossy(&commit_out.stderr)
        );
    }

    // Verify all 3 commits exist and are cryptographically verified, under
    // the agents' trust line
    let ca_path = dir.path().join(".agent-sign/keys/agents_ca_ed25519.pub");
    let ca = fs::read_to_string(&ca_path).unwrap();

    let allowed_signers = dir.path().join("allowed_signers");
    fs::write(
        &allowed_signers,
        format!(
            "*@agents.local cert-authority,namespaces=\"git\" {}\n",
            ca.trim()
        ),
    )
    .unwrap();

    let sig_check = Command::new("git")
        .args([
            "-c",
            &format!("gpg.ssh.allowedSignersFile={}", allowed_signers.display()),
            "log",
            "-n",
            "3",
            "--show-signature",
        ])
        .current_dir(&test_repo)
        .output()
        .unwrap();

    let sig_out = String::from_utf8_lossy(&sig_check.stderr);
    let sig_std = String::from_utf8_lossy(&sig_check.stdout);
    let combined = format!("{}{}", sig_out, sig_std);

    // Count instances of "Good \"git\" signature"
    let verified_count = combined.matches("Good \"git\" signature").count();
    assert_eq!(
        verified_count, 3,
        "All 3 commits must have valid Good git signatures! Output:\n{}",
        combined
    );
}

fn scenario_allow_main_branch_when_configured(bins: &Bins) {
    let dir = tempdir().expect("Failed to create tempdir");
    let test_repo = dir.path().join("repo");
    fs::create_dir_all(&test_repo).unwrap();

    let socket_path = dir.path().join("test_daemon.sock");
    let keys_dir = dir.path().join("keys");
    fs::create_dir_all(&keys_dir).unwrap();

    let daemon_bin = &bins.daemon;

    // Spawn daemon with --allow-main and --auto-approve
    let mut child = Command::new(daemon_bin)
        .arg("--socket")
        .arg(&socket_path)
        .arg("--allow-main") // Explicitly permit main branch commits
        .arg("--auto-approve")
        .env("HOME", dir.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn test agent-signd");

    let start = std::time::Instant::now();
    while !socket_path.exists() {
        if start.elapsed() > Duration::from_secs(5) {
            panic!("Test daemon failed to create socket in time");
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // Initialize Git on branch main!
    assert!(
        Command::new("git")
            .args(["init", "-b", "main"])
            .current_dir(&test_repo)
            .status()
            .unwrap()
            .success()
    );

    let test_file = test_repo.join("main_code.txt");
    fs::write(&test_file, "Commit made directly to main branch\n").unwrap();

    assert!(
        Command::new("git")
            .args(["add", "main_code.txt"])
            .current_dir(&test_repo)
            .status()
            .unwrap()
            .success()
    );

    let agent_git_bin = &bins.git;
    let agent_sign_bin = &bins.sign;

    let commit_out = Command::new(agent_git_bin)
        // No agent marks from whatever runs the tests (see KNOWN_AGENTS).
        .env_remove("CLAUDECODE")
        .env_remove("GEMINI_CLI")
        .env_remove("CODEX_THREAD_ID")
        .env_remove("CODEX_SESSION_ID")
        // The agent says who it is: since the identity review (28 Oct 2026)
        // an unmarked commit with no terminal is left to git, unsigned.
        .env("AGENT_SIGN_AGENT_NAME", "Test Agent")
        .args(["commit", "-m", "feat: commit directly to main"])
        .current_dir(&test_repo)
        .env(bins.env("SOCKET"), &socket_path)
        .env(bins.env("BIN"), agent_sign_bin)
        .env("HOME", dir.path())
        .output()
        .expect("Failed to execute agent commit on main");

    assert!(
        commit_out.status.success(),
        "Agent commit on main failed! Stderr: {}",
        String::from_utf8_lossy(&commit_out.stderr)
    );

    let log_output = Command::new("git")
        .args(["log", "-1", "--format=%s (branch: %D)"])
        .current_dir(&test_repo)
        .output()
        .unwrap();

    let log_str = String::from_utf8_lossy(&log_output.stdout);
    println!("Main commit log: {}", log_str);
    assert!(log_str.contains("feat: commit directly to main"));

    let _ = child.kill();
    let _ = child.wait();
}

fn scenario_branch_switching_in_active_session(bins: &Bins) {
    let dir = tempdir().expect("Failed to create tempdir");
    let test_repo = dir.path().join("repo");
    fs::create_dir_all(&test_repo).unwrap();

    let daemon = start_test_daemon(dir.path(), bins);

    // 1. Initialize git on feat/step-1
    assert!(
        Command::new("git")
            .args(["init", "-b", "feat/step-1"])
            .current_dir(&test_repo)
            .status()
            .unwrap()
            .success()
    );

    assert!(
        Command::new("git")
            .args(["config", "user.name", "Developer"])
            .current_dir(&test_repo)
            .status()
            .unwrap()
            .success()
    );

    assert!(
        Command::new("git")
            .args(["config", "user.email", "dev@example.com"])
            .current_dir(&test_repo)
            .status()
            .unwrap()
            .success()
    );

    let agent_git_bin = &bins.git;
    let agent_sign_bin = &bins.sign;

    // Commit 1 on feat/step-1
    fs::write(test_repo.join("step1.txt"), "Step 1 content\n").unwrap();
    assert!(
        Command::new("git")
            .args(["add", "step1.txt"])
            .current_dir(&test_repo)
            .status()
            .unwrap()
            .success()
    );

    let commit1 = Command::new(agent_git_bin)
        // No agent marks from whatever runs the tests (see KNOWN_AGENTS).
        .env_remove("CLAUDECODE")
        .env_remove("GEMINI_CLI")
        .env_remove("CODEX_THREAD_ID")
        .env_remove("CODEX_SESSION_ID")
        // The agent says who it is: since the identity review (28 Oct 2026)
        // an unmarked commit with no terminal is left to git, unsigned.
        .env("AGENT_SIGN_AGENT_NAME", "Test Agent")
        .args(["commit", "-m", "feat: step 1 commit"])
        .current_dir(&test_repo)
        .env(bins.env("SOCKET"), &daemon.socket_path)
        .env(bins.env("BIN"), agent_sign_bin)
        .env("HOME", dir.path())
        .output()
        .expect("Failed to commit step 1");

    assert!(
        commit1.status.success(),
        "Commit on step 1 failed: {}",
        String::from_utf8_lossy(&commit1.stderr)
    );

    // 2. Switch to feat/step-2 (verifying branch switching does not deadlock!)
    assert!(
        Command::new("git")
            .args(["checkout", "-b", "feat/step-2"])
            .current_dir(&test_repo)
            .status()
            .unwrap()
            .success()
    );

    fs::write(test_repo.join("step2.txt"), "Step 2 content\n").unwrap();
    assert!(
        Command::new("git")
            .args(["add", "step2.txt"])
            .current_dir(&test_repo)
            .status()
            .unwrap()
            .success()
    );

    let commit2 = Command::new(agent_git_bin)
        // No agent marks from whatever runs the tests (see KNOWN_AGENTS).
        .env_remove("CLAUDECODE")
        .env_remove("GEMINI_CLI")
        .env_remove("CODEX_THREAD_ID")
        .env_remove("CODEX_SESSION_ID")
        // The agent says who it is: since the identity review (28 Oct 2026)
        // an unmarked commit with no terminal is left to git, unsigned.
        .env("AGENT_SIGN_AGENT_NAME", "Test Agent")
        .args(["commit", "-m", "feat: step 2 commit on new branch"])
        .current_dir(&test_repo)
        .env(bins.env("SOCKET"), &daemon.socket_path)
        .env(bins.env("BIN"), agent_sign_bin)
        .env("HOME", dir.path())
        .output()
        .expect("Failed to commit step 2");

    assert!(
        commit2.status.success(),
        "Branch switching commit failed: {}",
        String::from_utf8_lossy(&commit2.stderr)
    );

    // Verify commit 2 exists on feat/step-2
    let log_out = Command::new("git")
        .args(["log", "-1", "--format=%s"])
        .current_dir(&test_repo)
        .output()
        .unwrap();

    assert!(String::from_utf8_lossy(&log_out.stdout).contains("feat: step 2 commit on new branch"));
}

fn scenario_trailers_mode_attribution(bins: &Bins) {
    let dir = tempdir().expect("Failed to create tempdir");
    let test_repo = dir.path().join("repo");
    fs::create_dir_all(&test_repo).unwrap();

    let daemon = start_test_daemon(dir.path(), bins);

    assert!(
        Command::new("git")
            .args(["init", "-b", "feat/trailers-test"])
            .current_dir(&test_repo)
            .status()
            .unwrap()
            .success()
    );

    assert!(
        Command::new("git")
            .args(["config", "user.name", "Human Dev"])
            .current_dir(&test_repo)
            .status()
            .unwrap()
            .success()
    );

    assert!(
        Command::new("git")
            .args(["config", "user.email", "human@example.com"])
            .current_dir(&test_repo)
            .status()
            .unwrap()
            .success()
    );

    // mode = "trailers" in the person's own config: since the identity
    // review (28 Oct 2026) a repository's file can't set the attribution
    // mode (it may only tighten [security] rules).
    let state_dir = dir.path().join(".agent-sign");
    fs::create_dir_all(&state_dir).unwrap();
    fs::write(
        state_dir.join("config.toml"),
        "[attribution]\nmode = \"trailers\"\n",
    )
    .unwrap();

    fs::write(test_repo.join("work.txt"), "Important work\n").unwrap();
    assert!(
        Command::new("git")
            .args(["add", "work.txt"])
            .current_dir(&test_repo)
            .status()
            .unwrap()
            .success()
    );

    let agent_git_bin = &bins.git;
    let agent_sign_bin = &bins.sign;

    let commit_out = Command::new(agent_git_bin)
        // No agent marks from whatever runs the tests (see KNOWN_AGENTS).
        .env_remove("CLAUDECODE")
        .env_remove("GEMINI_CLI")
        .env_remove("CODEX_THREAD_ID")
        .env_remove("CODEX_SESSION_ID")
        // The agent says who it is: since the identity review (28 Oct 2026)
        // an unmarked commit with no terminal is left to git, unsigned.
        .env("AGENT_SIGN_AGENT_NAME", "Test Agent")
        .args(["commit", "-m", "feat: implement enterprise compliance"])
        .current_dir(&test_repo)
        .env(bins.env("SOCKET"), &daemon.socket_path)
        .env(bins.env("BIN"), agent_sign_bin)
        .env("HOME", dir.path())
        .output()
        .expect("Failed to execute commit in trailers mode");

    assert!(
        commit_out.status.success(),
        "Trailers mode commit failed: {}",
        String::from_utf8_lossy(&commit_out.stderr)
    );

    // Verify commit message contains trailers
    let log_msg = Command::new("git")
        .args(["log", "-1", "--format=%B"])
        .current_dir(&test_repo)
        .output()
        .unwrap();

    let full_message = String::from_utf8_lossy(&log_msg.stdout);
    println!("Commit message with trailers:\n{}", full_message);

    assert!(full_message.contains("Co-Authored-By: Test Agent <agent@local.internal>"));
    assert!(full_message.contains("X-Agent-Signer: agent-sign/v0.1"));
    assert!(full_message.contains("X-Agent-Lease:"));
}

#[test]
fn test_e2e_agent_git_commit_and_verification() {
    scenario_agent_git_commit_and_verification(&Bins::new_names());
}

#[test]
fn test_e2e_multi_commit_headless_session_flow() {
    scenario_multi_commit_headless_session_flow(&Bins::new_names());
}

#[test]
fn test_e2e_allow_main_branch_when_configured() {
    scenario_allow_main_branch_when_configured(&Bins::new_names());
}

#[test]
fn test_e2e_branch_switching_in_active_session() {
    scenario_branch_switching_in_active_session(&Bins::new_names());
}

#[test]
fn test_e2e_trailers_mode_attribution() {
    scenario_trailers_mode_attribution(&Bins::new_names());
}
