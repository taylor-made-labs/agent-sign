use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use agent_sign::attribution::AttributionEngine;
use agent_sign::config::Config;
use agent_sign::interceptor::CommandInterceptor;
use agent_sign::protocol::{Request, Response, default_socket_path, send_request};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    let interceptor = CommandInterceptor::new();
    let decision = interceptor.inspect_command(&args[1..]);

    if !decision.is_commit {
        // Non-commit command: execute real git immediately
        return exec_system_git(&args[1..], &[]);
    }

    // Commit command detected: prepare autonomous signing context
    handle_agent_commit(&args[1..])
}

fn exec_system_git(args: &[String], extra_envs: &[(&str, &str)]) -> ExitCode {
    let mut cmd = Command::new("/usr/bin/git");
    cmd.args(args);
    for (k, v) in extra_envs {
        cmd.env(k, v);
    }

    match cmd.status() {
        Ok(status) => ExitCode::from(status.code().unwrap_or(1) as u8),
        Err(e) => {
            eprintln!("[agent-git] Failed to execute /usr/bin/git: {}", e);
            ExitCode::from(1)
        }
    }
}

fn get_repo_and_branch() -> (String, String) {
    let repo_output = Command::new("/usr/bin/git")
        .args(["rev-parse", "--show-toplevel"])
        .output();

    let repo = if let Ok(out) = repo_output {
        let path_str = String::from_utf8_lossy(&out.stdout).trim().to_string();
        Path::new(&path_str)
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_else(|| "default-repo".to_string())
    } else {
        "default-repo".to_string()
    };

    let branch_output = Command::new("/usr/bin/git")
        .args(["branch", "--show-current"])
        .output();

    let branch = if let Ok(out) = branch_output {
        let b = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if b.is_empty() { "HEAD".to_string() } else { b }
    } else {
        "HEAD".to_string()
    };

    (repo, branch)
}

fn find_agent_sign_bin() -> PathBuf {
    if let Ok(path) = env::var("AGENT_SIGN_BIN") {
        return PathBuf::from(path);
    }

    if let Ok(current_exe) = env::current_exe() {
        let sibling = current_exe.with_file_name("agent-sign");
        if sibling.exists() {
            return sibling;
        }
    }

    let home = env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".agent-sign/bin/agent-sign")
}

fn handle_agent_commit(original_args: &[String]) -> ExitCode {
    let (repo, branch) = get_repo_and_branch();
    let socket_path = env::var("AGENT_SIGN_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|_| default_socket_path());

    // 1. Ensure lease is active (request lease if needed)
    let lease_req = Request::RequestLease {
        repo: repo.clone(),
        branch: branch.clone(),
        intent: "Autonomous coding agent commit".to_string(),
        duration_secs: Some(7200),
    };

    match send_request(&socket_path, &lease_req) {
        Ok(Response::LeaseGranted { .. }) => {}
        Ok(Response::Error { message }) => {
            eprintln!("[agent-git] Signing lease rejected: {}", message);
            return ExitCode::from(1);
        }
        Err(e) => {
            eprintln!(
                "[agent-git] Unable to connect to agent-signd at {}: {}",
                socket_path.display(),
                e
            );
            eprintln!("[agent-git] Hint: Start the daemon with `agent-signd`");
            return ExitCode::from(1);
        }
        other => {
            eprintln!(
                "[agent-git] Unexpected lease response from daemon: {:?}",
                other
            );
            return ExitCode::from(1);
        }
    }

    // 2. Request single-use commit event token
    let token_req = Request::IssueToken {
        repo: repo.clone(),
        branch: branch.clone(),
    };

    let token = match send_request(&socket_path, &token_req) {
        Ok(Response::TokenIssued { token }) => token,
        Ok(Response::Error { message }) => {
            eprintln!("[agent-git] Token issuance failed: {}", message);
            return ExitCode::from(1);
        }
        Err(e) => {
            eprintln!("[agent-git] Token request failed: {}", e);
            return ExitCode::from(1);
        }
        other => {
            eprintln!("[agent-git] Unexpected token response: {:?}", other);
            return ExitCode::from(1);
        }
    };

    // 3. Prepare Git command arguments with configuration overrides
    let agent_sign_bin = find_agent_sign_bin();
    let config = Config::default();
    let attr_engine = AttributionEngine::new(config.attribution, config.agent, config.human);
    let attr_envs = attr_engine.compute_env_vars("commit");

    let mut git_args: Vec<String> = Vec::new();
    // Configure Git to use agent-sign
    git_args.push("-c".to_string());
    git_args.push("commit.gpgsign=true".to_string());
    git_args.push("-c".to_string());
    git_args.push("gpg.format=ssh".to_string());
    git_args.push("-c".to_string());
    git_args.push(format!("gpg.ssh.program={}", agent_sign_bin.display()));
    git_args.push("-c".to_string());
    let pub_key_path = config.ssh.agent_key_path.with_extension("pub");
    git_args.push(format!("user.signingkey={}", pub_key_path.display()));

    git_args.extend_from_slice(original_args);

    let mut env_pairs: Vec<(&str, &str)> = Vec::new();
    env_pairs.push(("AGENT_EVENT_TOKEN", &token));

    let author_name = attr_envs
        .get("GIT_AUTHOR_NAME")
        .map(|s| s.as_str())
        .unwrap_or("");
    let author_email = attr_envs
        .get("GIT_AUTHOR_EMAIL")
        .map(|s| s.as_str())
        .unwrap_or("");
    let committer_name = attr_envs
        .get("GIT_COMMITTER_NAME")
        .map(|s| s.as_str())
        .unwrap_or("");
    let committer_email = attr_envs
        .get("GIT_COMMITTER_EMAIL")
        .map(|s| s.as_str())
        .unwrap_or("");

    if !author_name.is_empty() {
        env_pairs.push(("GIT_AUTHOR_NAME", author_name));
    }
    if !author_email.is_empty() {
        env_pairs.push(("GIT_AUTHOR_EMAIL", author_email));
    }
    if !committer_name.is_empty() {
        env_pairs.push(("GIT_COMMITTER_NAME", committer_name));
    }
    if !committer_email.is_empty() {
        env_pairs.push(("GIT_COMMITTER_EMAIL", committer_email));
    }

    exec_system_git(&git_args, &env_pairs)
}
