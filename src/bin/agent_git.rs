//! `agent-git`: agent-sign's git wrapper, installed first on
//! agents' `PATH` as `git`.
//!
//! Every command except `commit` goes straight to the real git. A commit from
//! an agent is checked against the local rules, gets a lease and a single-use
//! token from the service, and runs the real git with agent-sign's signing program
//! and the configured author and committer.

use std::env;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use agent_sign::attribution::{AttributionEngine, AttributionMode};
use agent_sign::config::Config;
use agent_sign::interceptor::CommandInterceptor;
use agent_sign::paths;
use agent_sign::protocol::{Request, Response, client_socket_path, send_request};
use agent_sign::ssh_sign::EVENT_TOKEN_VAR;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    let interceptor = CommandInterceptor::new();
    let decision = interceptor.inspect_command(&args[1..]);
    let real_git = find_system_git();

    if !decision.is_commit {
        // Non-commit command: execute real git immediately
        return exec_system_git(&real_git, &args[1..], &[]);
    }

    // A commit that asks not to be signed (--no-gpg-sign, or commit.gpgsign
    // set to false for this command or this repository, as test fixtures
    // do for throwaway commits) goes to the real git unchanged: there's
    // nothing to sign, so nothing to ask the person about.
    if signing_declined(&real_git, &args[1..], decision.commit_index) {
        return exec_system_git(&real_git, &args[1..], &[]);
    }

    // Human isolation [INV-1]: a commit typed in an interactive terminal
    // (stdin and stdout both terminals) goes to the person's own git and
    // signing, unless AGENT_SIGN_FORCE / _SESSION is set or an agent has
    // marked the command as its own (see attribution::KNOWN_AGENTS).
    let is_interactive_human = agent_sign::attribution::is_persons_own_commit(
        std::io::stdin().is_terminal(),
        std::io::stdout().is_terminal(),
        paths::env_var_os("FORCE").is_some() || paths::env_var_os("SESSION").is_some(),
        agent_sign::attribution::agent_mark_present_with(|k| env::var(k).ok()),
    );

    if is_interactive_human {
        return exec_system_git(&real_git, &args[1..], &[]);
    }

    // Commit command detected: prepare autonomous signing context
    handle_agent_commit(&real_git, &args[1..], decision.commit_index)
}

/// Whether this commit asks not to be signed: by its own options, or else by
/// `commit.gpgsign = false` in this command's or this repository's config.
fn signing_declined(real_git: &Path, args: &[String], commit_index: Option<usize>) -> bool {
    let Some(at) = commit_index else {
        return false;
    };
    if let Some(sign) = agent_sign::interceptor::signing_flag(&args[at + 1..]) {
        return !sign;
    }
    // The global options before `commit` (such as `-c commit.gpgsign=false`
    // or `-C dir`) apply to the config lookup too.
    Command::new(real_git)
        .args(&args[..at])
        .args([
            "config",
            "--show-scope",
            "--type=bool",
            "--get",
            "commit.gpgsign",
        ])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .is_some_and(|o| {
            agent_sign::interceptor::config_declines_signing(&String::from_utf8_lossy(&o.stdout))
        })
}

fn find_system_git() -> PathBuf {
    if let Some(path) = paths::env_var("REAL_GIT") {
        let p = PathBuf::from(path);
        if p.exists() {
            return p;
        }
    }

    let current_exe = env::current_exe().ok();

    if let Ok(paths) = env::var("PATH") {
        for dir in env::split_paths(&paths) {
            // Skip agent-sign's own bin directories (old and new names)
            if is_agent_sign_bin_dir(&dir) {
                continue;
            }
            let candidate = dir.join("git");
            if candidate.is_file() {
                if let Some(ref cur) = current_exe
                    && let (Ok(c1), Ok(c2)) = (candidate.canonicalize(), cur.canonicalize())
                    && c1 == c2
                {
                    continue;
                }
                return candidate;
            }
        }
    }

    // Standard fallback candidate paths
    let standard_candidates = [
        "/opt/homebrew/bin/git",
        "/usr/local/bin/git",
        "/usr/bin/git",
        "/bin/git",
    ];

    for candidate in &standard_candidates {
        let p = PathBuf::from(candidate);
        if p.is_file() {
            return p;
        }
    }

    PathBuf::from("git")
}

/// Whether a `PATH` entry is agent-sign's bin directory, which holds the
/// wrapper itself: any path with a `.agent-sign` component.
fn is_agent_sign_bin_dir(dir: &Path) -> bool {
    dir.components()
        .any(|c| c.as_os_str() == paths::STATE_DIR_NAME)
}

fn exec_system_git(real_git: &Path, args: &[String], extra_envs: &[(&str, &str)]) -> ExitCode {
    let mut cmd = Command::new(real_git);
    cmd.args(args);
    for (k, v) in extra_envs {
        cmd.env(k, v);
    }

    match cmd.status() {
        Ok(status) => ExitCode::from(status.code().unwrap_or(1) as u8),
        Err(e) => {
            eprintln!(
                "[agent-git] Failed to execute git at {}: {}",
                real_git.display(),
                e
            );
            ExitCode::from(1)
        }
    }
}

/// The repository and branch a commit is for, asked of git with the same
/// global options (`-C`, `--git-dir`, `--work-tree`, `-c`) the commit itself
/// gets, and the same environment (`GIT_DIR`, `GIT_WORK_TREE`), so a commit
/// run with `git -C <repo>` from another folder is identified as that
/// repository. `None` when git can't say: the caller refuses rather than
/// asking about a placeholder, since a dialog that names no repository
/// invites approving everything.
fn get_repo_and_branch(real_git: &Path, global: &[String]) -> Option<(String, String)> {
    let ask = |args: &[&str]| -> Option<String> {
        let out = Command::new(real_git)
            .args(global)
            .args(args)
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
    };
    let top = ask(&["rev-parse", "--show-toplevel"]).filter(|t| !t.is_empty())?;
    // The canonical absolute path, so a link or relative path names the same
    // repository (and the same lease) as its real location.
    let repo = std::fs::canonicalize(&top)
        .ok()?
        .to_string_lossy()
        .to_string();
    // Detached HEAD has no branch; "HEAD" is what git itself calls it.
    let branch = ask(&["branch", "--show-current"])
        .filter(|b| !b.is_empty())
        .unwrap_or_else(|| "HEAD".to_string());
    Some((repo, branch))
}

/// The signing program to hand git as `gpg.ssh.program`:
/// 1. `AGENT_SIGN_BIN`, if set;
/// 2. `agent-ssh-sign` next to this program, else `agent-sign` next to it (an
///    install from before `agent-ssh-sign` existed);
/// 3. `agent-ssh-sign`, else `agent-sign`, in the state directory's `bin`;
/// 4. otherwise `<state dir>/bin/agent-ssh-sign`.
fn find_ssh_sign_bin() -> PathBuf {
    if let Some(path) = paths::env_var("BIN") {
        return PathBuf::from(path);
    }

    if let Ok(current_exe) = env::current_exe() {
        for name in ["agent-ssh-sign", "agent-sign"] {
            let sibling = current_exe.with_file_name(name);
            if sibling.exists() {
                return sibling;
            }
        }
    }

    let bin_dir = paths::state_dir().join("bin");
    for name in ["agent-ssh-sign", "agent-sign"] {
        let candidate = bin_dir.join(name);
        if candidate.exists() {
            return candidate;
        }
    }
    bin_dir.join("agent-ssh-sign")
}

fn apply_trailers_to_args(
    args: &[String],
    attr_engine: &AttributionEngine,
    lease_id: &str,
) -> Vec<String> {
    let mut modified = args.to_vec();
    let mut found_m = false;

    for i in 0..modified.len() {
        if modified[i] == "-m" && i + 1 < modified.len() {
            let original = &modified[i + 1];
            modified[i + 1] = attr_engine.transform_commit_message(original, lease_id);
            found_m = true;
            break;
        } else if modified[i].starts_with("--message=") {
            let original = modified[i].trim_start_matches("--message=");
            let transformed = attr_engine.transform_commit_message(original, lease_id);
            modified[i] = format!("--message={}", transformed);
            found_m = true;
            break;
        }
    }

    if !found_m {
        // If commit without -m / --message, inject trailer flag if message can be appended
        // or pass through untouched
    }

    modified
}

fn handle_agent_commit(
    real_git: &Path,
    original_args: &[String],
    commit_index: Option<usize>,
) -> ExitCode {
    let global = &original_args[..commit_index.unwrap_or(0)];
    let Some((repo, branch)) = get_repo_and_branch(real_git, global) else {
        eprintln!(
            "[agent-git] agent-sign couldn't identify the repository for this commit, so it didn't ask you and didn't sign. \
             Run the commit from inside the repository, or check its -C, --git-dir or GIT_DIR."
        );
        return ExitCode::from(1);
    };
    let socket_path = client_socket_path();

    let repo_path = Path::new(&repo);
    let config = Config::load(Some(repo_path));

    // 0. Enterprise Guardrails: Validate staged paths, diff size, and commit message
    if let Err(err_msg) = validate_guardrails(real_git, repo_path, &config, original_args) {
        eprintln!("[agent-git] Security Policy Violation: {}", err_msg);
        return ExitCode::from(1);
    }

    // 1. Ensure lease is active (request lease if needed)
    let lease_req = Request::RequestLease {
        repo: repo.clone(),
        branch: branch.clone(),
        intent: "Autonomous coding agent commit".to_string(),
        duration_secs: Some(7200),
    };

    let lease_id = match send_request(&socket_path, &lease_req) {
        Ok(Response::LeaseGranted { lease_id, .. }) => lease_id,
        Ok(Response::Error { message }) => {
            eprintln!("[agent-git] No signing lease: {}", message);
            return ExitCode::from(1);
        }
        Err(e) => {
            eprintln!(
                "[agent-git] Unable to connect to the agent-sign service at {}: {}",
                socket_path.display(),
                e
            );
            eprintln!("[agent-git] Hint: Start the service with `agent-signd`");
            return ExitCode::from(1);
        }
        other => {
            eprintln!(
                "[agent-git] Unexpected lease response from daemon: {:?}",
                other
            );
            return ExitCode::from(1);
        }
    };

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
    let ssh_sign_bin = find_ssh_sign_bin();
    // Name the agent in its commits when it can be told (see KNOWN_AGENTS).
    let mut agent = config.agent;
    let explicit = agent_sign::paths::env_var("AGENT_NAME").is_some();
    agent.name = agent_sign::attribution::effective_agent_name(
        &agent.name,
        explicit,
        agent_sign::attribution::detect_agent(),
    );
    let attr_engine = AttributionEngine::new(config.attribution, agent, config.human);
    let attr_envs = attr_engine.compute_env_vars("commit");

    let mut git_args: Vec<String> = Vec::new();
    // Configure Git to use agent-sign's signing program
    git_args.push("-c".to_string());
    git_args.push("commit.gpgsign=true".to_string());
    git_args.push("-c".to_string());
    git_args.push("gpg.format=ssh".to_string());
    git_args.push("-c".to_string());
    git_args.push(format!("gpg.ssh.program={}", ssh_sign_bin.display()));
    git_args.push("-c".to_string());
    let pub_key_path = config.ssh.agent_key_path.with_extension("pub");
    git_args.push(format!("user.signingkey={}", pub_key_path.display()));

    // Apply commit message transformation for trailers mode if applicable
    let final_args = if attr_engine.mode == AttributionMode::Trailers {
        apply_trailers_to_args(original_args, &attr_engine, &lease_id)
    } else {
        original_args.to_vec()
    };

    git_args.extend_from_slice(&final_args);

    let mut env_pairs: Vec<(&str, &str)> = Vec::new();
    env_pairs.push((EVENT_TOKEN_VAR, &token));

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

    exec_system_git(real_git, &git_args, &env_pairs)
}

fn validate_guardrails(
    real_git: &Path,
    repo_path: &Path,
    config: &Config,
    commit_args: &[String],
) -> Result<(), String> {
    // 1. Path-based blast radius check: inspect staged files
    let staged_files_out = Command::new(real_git)
        .current_dir(repo_path)
        .args(["diff", "--cached", "--name-only"])
        .output();

    if let Ok(out) = staged_files_out {
        let stdout = String::from_utf8_lossy(&out.stdout);
        for line in stdout.lines() {
            let path_str = line.trim();
            if path_str.is_empty() {
                continue;
            }

            for pattern in &config.security.forbidden_paths {
                if matches_glob(path_str, pattern) {
                    return Err(format!(
                        "Agent commit touches forbidden path '{}' matching security policy rule '{}'. Bypassing requires human terminal commit or policy adjustment.",
                        path_str, pattern
                    ));
                }
            }
        }
    }

    // 2. Diff size circuit breaker: check total lines changed in staged commit
    if config.security.max_diff_lines > 0 && paths::env_var_os("ALLOW_LARGE_DIFF").is_none() {
        let diff_numstat_out = Command::new(real_git)
            .current_dir(repo_path)
            .args(["diff", "--cached", "--numstat"])
            .output();

        if let Ok(out) = diff_numstat_out {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let mut total_lines = 0usize;
            for line in stdout.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let added: usize = parts[0].parse().unwrap_or(0);
                    let deleted: usize = parts[1].parse().unwrap_or(0);
                    total_lines += added + deleted;
                }
            }

            if total_lines > config.security.max_diff_lines {
                return Err(format!(
                    "Agent commit changes {} lines, more than the limit you set (max_diff_lines = {}). Raise or remove max_diff_lines, or set AGENT_SIGN_ALLOW_LARGE_DIFF=1 for this commit.",
                    total_lines, config.security.max_diff_lines
                ));
            }
        }
    }

    // 3. Conventional commits linter
    if config.security.enforce_conventional_commits {
        let msg = extract_commit_message(commit_args);
        if let Some(m) = msg
            && !is_conventional_commit(&m)
        {
            return Err(format!(
                "Commit message '{}' violates conventional commits policy. Expected format: 'feat|fix|docs|style|refactor|perf|test|build|ci|chore: ...'",
                m
            ));
        }
    }

    Ok(())
}

fn matches_glob(path: &str, pattern: &str) -> bool {
    let path = path.trim_start_matches("./");
    let pattern = pattern.trim_start_matches("./");

    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix("/*") {
        return path == prefix || path.starts_with(&format!("{}/", prefix));
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        return path.ends_with(&format!(".{}", suffix));
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return path.starts_with(prefix);
    }
    path == pattern
}

fn extract_commit_message(args: &[String]) -> Option<String> {
    for i in 0..args.len() {
        if args[i] == "-m" && i + 1 < args.len() {
            return Some(args[i + 1].clone());
        }
        if args[i].starts_with("--message=") {
            return Some(args[i].trim_start_matches("--message=").to_string());
        }
    }
    None
}

fn is_conventional_commit(msg: &str) -> bool {
    let types = [
        "feat", "fix", "docs", "style", "refactor", "perf", "test", "build", "ci", "chore",
    ];
    let first_line = msg.lines().next().unwrap_or("").trim();
    for t in types {
        if first_line.starts_with(&format!("{}:", t)) || first_line.starts_with(&format!("{}(", t))
        {
            return true;
        }
    }
    false
}
