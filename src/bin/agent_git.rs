//! `agent-git`: agent-sign's git wrapper, installed first on
//! agents' `PATH` as `git`.
//!
//! The person's own commands go straight to the real git. A commit from an
//! agent is checked against the local rules, gets a lease and a single-use
//! token from the service, and runs the real git with agent-sign's signing
//! program and the configured author and committer. Any other command from an
//! agent (merge, rebase, cherry-pick, pull, a shell alias...) runs with
//! signing off and the person's signer out of reach, so nothing git creates
//! for an agent is ever signed with the person's own key.

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

/// How many wrappers deep a run may go before the wrapper stops. A git run
/// for an agent can start git again (a hook, an alias, agent-sign's own
/// lookups), but never this deep: reaching it means the wrapper is calling
/// itself, and stopping fails closed instead of filling the process table.
const MAX_DEPTH: u32 = 8;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    let depth = current_depth();
    if depth >= MAX_DEPTH {
        eprintln!(
            "[agent-git] agent-sign's git wrapper is calling itself ({depth} deep), so it stopped \
             without running git. Please report this: https://github.com/taylor-made-labs/agent-sign/issues"
        );
        return ExitCode::from(1);
    }
    let interceptor = CommandInterceptor::new();
    let mut decision = interceptor.inspect_command(&args[1..]);
    let real_git = find_system_git();

    // An alias for commit (`git ci`, with alias.ci = "commit ...") is a
    // commit too: it gets the same handling, with the alias's name where
    // `commit` would be.
    if !decision.is_commit
        && let Some(at) = decision.subcommand_index
        && alias_is_commit(&real_git, &args[1..1 + at], &args[1 + at])
    {
        decision.is_commit = true;
        decision.commit_index = Some(at);
    }

    // Human isolation [INV-1]: a command typed in an interactive terminal
    // (stdin and stdout both terminals) goes to the person's own git and
    // signing, unless AGENT_SIGN_FORCE / _SESSION is set or an agent has
    // marked the command as its own (see attribution::KNOWN_AGENTS). The
    // wrapper's own mark (AGENT_RUN_VAR) doesn't count here: it reaches
    // whatever git starts, such as an editor, and a terminal opened from that
    // later is still the person's. Only the signing program reads it.
    let is_interactive_human = agent_sign::attribution::is_persons_own_commit(
        std::io::stdin().is_terminal(),
        std::io::stdout().is_terminal(),
        paths::env_var_os("FORCE").is_some() || paths::env_var_os("SESSION").is_some(),
        agent_sign::attribution::agent_mark_present_with(|k| env::var(k).ok()),
    );

    if !decision.is_commit {
        if is_interactive_human {
            return exec_persons_git(&real_git, &args[1..]);
        }
        return exec_for_agent(&real_git, &args[1..]);
    }

    // A commit that asks not to be signed (--no-gpg-sign, or commit.gpgsign
    // set to false for this command or this repository, as test fixtures
    // do for throwaway commits) goes to the real git unchanged: there's
    // nothing to sign, so nothing to ask the person about.
    if signing_declined(&real_git, &args[1..], decision.commit_index) {
        return exec_unsigned(&real_git, &args[1..]);
    }

    if is_interactive_human {
        return exec_persons_git(&real_git, &args[1..]);
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
    // GIT_CONFIG is read by `git config` but not by `git commit`, so it
    // mustn't decide what the commit will do.
    git_command(real_git)
        .args(&args[..at])
        .args([
            "config",
            "--show-scope",
            "--type=bool",
            "--get",
            "commit.gpgsign",
        ])
        .env_remove("GIT_CONFIG")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .is_some_and(|o| {
            agent_sign::interceptor::config_declines_signing(&String::from_utf8_lossy(&o.stdout))
        })
}

/// Whether `name` is a git alias that runs `commit`, as git would expand it
/// with these global options, following aliases of aliases (as git does, up
/// to a depth). A shell alias (`!...`) isn't followed: git runs its own copy
/// of itself inside it, not this wrapper, which is an open gap noted in the
/// README's limits.
fn alias_is_commit(real_git: &Path, global: &[String], name: &str) -> bool {
    let interceptor = CommandInterceptor::new();
    let mut name = name.to_string();
    for _ in 0..16 {
        let Some(expansion) = git_command(real_git)
            .args(global)
            .args(["config", "--get", &format!("alias.{name}")])
            // GIT_CONFIG is read by `git config` but not when git expands an
            // alias, so it mustn't hide one.
            .env_remove("GIT_CONFIG")
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        else {
            return false;
        };
        let words: Vec<String> = expansion.split_whitespace().map(str::to_string).collect();
        if words.first().is_some_and(|w| w.starts_with('!')) {
            return false;
        }
        // The expansion may begin with global options (such as `-p`).
        let inner = interceptor.inspect_command(&words);
        if inner.is_commit {
            return true;
        }
        match inner.subcommand_index.and_then(|i| words.get(i)) {
            Some(next) => name = next.clone(),
            None => return false,
        }
    }
    false
}

/// Runs a commit that asked not to be signed, with signing made impossible:
/// every signing program git could call is set to one that always fails.
/// If the wrapper ever reads a commit's options differently from git, the
/// commit fails, rather than git signing it with the person's own key. (Global
/// options the commit itself gives come after these and can override them:
/// an agent setting its own signing program is going around agent-sign on
/// purpose, which it could also do by calling git directly.)
fn exec_unsigned(real_git: &Path, args: &[String]) -> ExitCode {
    let fails = failing_program();
    let mut unsigned: Vec<String> = Vec::new();
    for key in [
        "gpg.program",
        "gpg.openpgp.program",
        "gpg.ssh.program",
        "gpg.x509.program",
    ] {
        unsigned.push("-c".to_string());
        unsigned.push(format!("{key}={fails}"));
    }
    unsigned.extend(args.iter().cloned());
    exec_system_git(real_git, &unsigned, &[])
}

/// A program that always fails, for signing programs that must never run.
fn failing_program() -> &'static str {
    ["/usr/bin/false", "/bin/false"]
        .into_iter()
        .find(|p| Path::new(p).exists())
        .unwrap_or("false")
}

/// Runs a command other than `commit` for an agent. Git creates commits for
/// merge, pull, rebase, cherry-pick, revert and am, and inside shell aliases
/// and hooks, and without this it signs them with whatever the person's
/// global config says: their own key. So here:
/// - signing is off for commits, tags and pushes, so those commits are
///   unsigned (signing them with the agent's own key comes with per-agent
///   identities);
/// - every signing program is agent-sign's, which refuses to sign for an
///   agent without a commit token, and checks signatures with plain
///   `ssh-keygen` or `gpg`, so verifying still works (X.509's program always
///   fails, so X.509 signatures read as unchecked);
/// - [`AGENT_RUN_VAR`] marks the run, so the signing program knows an agent
///   is behind git's nested copies of itself (`-c` settings reach those
///   too, through git's own `GIT_CONFIG_PARAMETERS`).
///
/// An explicit request to sign (`tag -s`, `merge -S`) then fails rather than
/// using the person's key. Author and committer are git's own, as before.
/// As with commits, an agent that sets its own signing program after these
/// settings is going around agent-sign on purpose, which it could also do
/// by calling git directly.
///
/// Nothing here reads agent-sign's config: this runs for every git command an
/// agent makes, including agent-sign's own lookups when the wrapper is first
/// on `PATH`.
///
/// [`AGENT_RUN_VAR`]: agent_sign::attribution::AGENT_RUN_VAR
fn exec_for_agent(real_git: &Path, args: &[String]) -> ExitCode {
    let ssh_sign_bin = find_ssh_sign_bin().display().to_string();
    let settings = [
        ("commit.gpgsign", "false"),
        ("tag.gpgSign", "false"),
        ("push.gpgSign", "false"),
        ("gpg.ssh.program", ssh_sign_bin.as_str()),
        ("gpg.program", ssh_sign_bin.as_str()),
        ("gpg.openpgp.program", ssh_sign_bin.as_str()),
        ("gpg.x509.program", failing_program()),
    ];
    let mut agent_args: Vec<String> = Vec::new();
    for (key, value) in settings {
        agent_args.push("-c".to_string());
        agent_args.push(format!("{key}={value}"));
    }
    agent_args.extend(args.iter().cloned());
    exec_system_git(
        real_git,
        &agent_args,
        &[(agent_sign::attribution::AGENT_RUN_VAR, "1")],
    )
}

fn find_system_git() -> PathBuf {
    paths::real_git()
}

/// The suffix of the variable that counts how many wrappers deep a run is
/// (see [`MAX_DEPTH`]).
const DEPTH_SUFFIX: &str = "DEPTH";

/// How many wrappers deep this run is: 0 unless a wrapper started it.
fn current_depth() -> u32 {
    paths::env_var(DEPTH_SUFFIX)
        .and_then(|d| d.trim().parse().ok())
        .unwrap_or(0)
}

/// A command for the real git, one wrapper deeper. Every git the wrapper
/// starts, its own lookups included, goes through here, so that if the
/// "real" git ever turns out to be a wrapper too (a misconfigured
/// `AGENT_SIGN_REAL_GIT`, a copy of the wrapper elsewhere on `PATH`), the
/// chain stops at [`MAX_DEPTH`] instead of growing without end.
fn git_command(real_git: &Path) -> Command {
    let mut cmd = Command::new(real_git);
    cmd.env(
        format!("{}{DEPTH_SUFFIX}", paths::ENV_PREFIX),
        (current_depth() + 1).to_string(),
    );
    cmd
}

fn run_git(mut cmd: Command, real_git: &Path) -> ExitCode {
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

fn exec_system_git(real_git: &Path, args: &[String], extra_envs: &[(&str, &str)]) -> ExitCode {
    let mut cmd = git_command(real_git);
    cmd.args(args);
    for (k, v) in extra_envs {
        cmd.env(k, v);
    }
    run_git(cmd, real_git)
}

/// Runs the person's own command on the real git. The wrapper's agent mark
/// is removed first: it can reach the person's terminal through an editor an
/// agent's git started, and the signing program would then refuse the
/// person's own signature.
fn exec_persons_git(real_git: &Path, args: &[String]) -> ExitCode {
    let mut cmd = git_command(real_git);
    cmd.args(args)
        .env_remove(agent_sign::attribution::AGENT_RUN_VAR);
    run_git(cmd, real_git)
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
        let out = git_command(real_git)
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
    if let Err(err_msg) = validate_guardrails(real_git, global, &config, original_args) {
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
    // Hooks the commit runs, and any git they start, are the agent's too.
    env_pairs.push((agent_sign::attribution::AGENT_RUN_VAR, "1"));

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

/// Runs git with the commit's own global options, from the same folder, so
/// it sees the same repository the commit will. `None` if git fails: the
/// rules can't be checked, so the commit is refused rather than let through.
fn git_lines(real_git: &Path, global: &[String], args: &[&str]) -> Option<String> {
    let out = git_command(real_git)
        .args(global)
        .args(args)
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).to_string())
}

/// Options that make git list exactly what changed, whatever the person's
/// config says: raw paths separated by NUL (not quoted), the old and new
/// path of a rename both listed, paths from the repository's top (not just
/// the current folder), and no external diff or text conversion.
const EXACT_DIFF: [&str; 5] = [
    "-z",
    "--no-renames",
    "--no-relative",
    "--no-ext-diff",
    "--no-textconv",
];

fn unreadable() -> String {
    "agent-sign couldn't read the changes in this commit, so it can't check its rules; refused"
        .to_string()
}

/// What the new commit will be compared with: HEAD, or for `--amend` (and
/// git's abbreviations of it) HEAD's parent, since the amended commit
/// replaces HEAD and so contains HEAD's changes too; the empty tree when
/// there's no such commit (a repository's first commit).
fn comparison_base(
    real_git: &Path,
    global: &[String],
    commit_args: &[String],
) -> Result<String, String> {
    let amend = commit_args
        .iter()
        .any(|a| a.len() >= 4 && "--amend".starts_with(a.as_str()));
    let target = if amend {
        "HEAD^{commit}^"
    } else {
        "HEAD^{commit}"
    };
    if let Some(sha) = git_lines(
        real_git,
        global,
        &["rev-parse", "--verify", "--quiet", target],
    ) {
        return Ok(sha.trim().to_string());
    }
    git_lines(
        real_git,
        global,
        &["hash-object", "-t", "tree", "/dev/null"],
    )
    .map(|t| t.trim().to_string())
    .ok_or_else(unreadable)
}

/// Every path the commit could contain: what's staged, and also tracked
/// files changed but not staged, which `commit -a` or a commit naming paths
/// would include. Over-counting only means a rule may refuse a change that
/// wasn't going in; under-counting would let one through.
fn paths_the_commit_could_contain(
    real_git: &Path,
    global: &[String],
    base: &str,
) -> Result<Vec<String>, String> {
    let mut paths = Vec::new();
    for staged in [true, false] {
        let mut args = vec!["diff"];
        if staged {
            args.push("--cached");
        }
        args.extend([base, "--name-only"]);
        args.extend(EXACT_DIFF);
        let out = git_lines(real_git, global, &args).ok_or_else(unreadable)?;
        paths.extend(
            out.split('\0')
                .filter(|p| !p.is_empty())
                .map(str::to_string),
        );
    }
    Ok(paths)
}

/// Lines added plus deleted, staged or in the working tree, whichever is
/// more. (Binary files count as none: git gives no line count for them.)
fn lines_the_commit_could_change(
    real_git: &Path,
    global: &[String],
    base: &str,
) -> Result<usize, String> {
    let mut most = 0;
    for staged in [true, false] {
        let mut args = vec!["diff"];
        if staged {
            args.push("--cached");
        }
        args.extend([base, "--numstat"]);
        args.extend(EXACT_DIFF);
        let out = git_lines(real_git, global, &args).ok_or_else(unreadable)?;
        let total: usize = out
            .split('\0')
            .filter_map(|record| {
                let mut fields = record.split('\t');
                let added: usize = fields.next()?.parse().ok()?;
                let deleted: usize = fields.next()?.parse().ok()?;
                Some(added + deleted)
            })
            .sum();
        most = most.max(total);
    }
    Ok(most)
}

fn validate_guardrails(
    real_git: &Path,
    global: &[String],
    config: &Config,
    commit_args: &[String],
) -> Result<(), String> {
    let base = comparison_base(real_git, global, commit_args)?;

    // 1. Path-based blast radius check: every path the commit could contain
    for path_str in paths_the_commit_could_contain(real_git, global, &base)? {
        for pattern in &config.security.forbidden_paths {
            if matches_glob(&path_str, pattern) {
                return Err(format!(
                    "Agent commit touches forbidden path '{}' matching security policy rule '{}'. Bypassing requires human terminal commit or policy adjustment.",
                    path_str, pattern
                ));
            }
        }
    }

    // 2. Diff size circuit breaker, when the person has set one
    if config.security.max_diff_lines > 0 && paths::env_var_os("ALLOW_LARGE_DIFF").is_none() {
        let total_lines = lines_the_commit_could_change(real_git, global, &base)?;
        if total_lines > config.security.max_diff_lines {
            return Err(format!(
                "Agent commit changes {} lines, more than the limit you set (max_diff_lines = {}). Raise or remove max_diff_lines, or set AGENT_SIGN_ALLOW_LARGE_DIFF=1 for this commit.",
                total_lines, config.security.max_diff_lines
            ));
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
