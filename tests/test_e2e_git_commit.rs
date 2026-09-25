use std::fs;
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tempfile::tempdir;

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

fn start_test_daemon(dir: &std::path::Path) -> TestDaemon {
    let socket_path = dir.join("test_daemon.sock");
    let keys_dir = dir.join("keys");
    fs::create_dir_all(&keys_dir).unwrap();

    let daemon_bin = env!("CARGO_BIN_EXE_agent-signd");

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

#[test]
fn test_e2e_agent_git_commit_and_verification() {
    let dir = tempdir().expect("Failed to create tempdir");
    let test_repo = dir.path().join("repo");
    fs::create_dir_all(&test_repo).unwrap();

    // 1. Start daemon on test socket
    let daemon = start_test_daemon(dir.path());

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
    let agent_git_bin = env!("CARGO_BIN_EXE_agent-git");
    let agent_sign_bin = env!("CARGO_BIN_EXE_agent-sign");

    let commit_output = Command::new(agent_git_bin)
        .args(["commit", "-m", "feat: first agent commit"])
        .current_dir(&test_repo)
        .env("AGENT_SIGN_SOCKET", &daemon.socket_path)
        .env("AGENT_SIGN_BIN", &agent_sign_bin)
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

    // Attribution verified: split mode sets Author to Agent, Committer to Human
    assert!(log_str.contains("Antigravity Agent <agent@local.internal>"));
    assert!(log_str.contains("Developer <developer@example.com>"));

    // 6. Verify signature using system ssh-keygen
    let pub_key_path = dir.path().join(".agent-sign/keys/agent_ed25519.pub");
    assert!(
        pub_key_path.exists(),
        "Public key must exist after daemon setup"
    );
    let pub_key = fs::read_to_string(&pub_key_path).unwrap();

    let allowed_signers = dir.path().join("allowed_signers");
    fs::write(
        &allowed_signers,
        format!("developer@example.com {}\n", pub_key.trim()),
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
