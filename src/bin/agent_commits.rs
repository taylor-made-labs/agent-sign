//! `agent-commits`: the command line for agent-commits (formerly `agent-sign`).
//!
//! `agent-commits leases`, `status`, `revoke`, `doctor`, `--version`, `--help`. Any other
//! arguments are treated as git calling it as `gpg.ssh.program`, exactly as
//! `agent-sign` did, so `agent-sign` can be a link to this program. New setups
//! point git at `agent-commits-ssh-sign` instead.

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, ExitCode};

use agent_commits::config::Config;
use agent_commits::protocol::{Request, Response, client_socket_path, send_request};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();

    // Check for diagnostic / utility subcommands
    if args.len() > 1 {
        let first_arg = args[1].as_str();
        if first_arg == "doctor" {
            return run_doctor();
        }
        if first_arg == "leases" || first_arg == "list-leases" {
            return run_leases();
        }
        if first_arg == "status" {
            return run_status();
        }
        if first_arg == "revoke" {
            return run_revoke(&args[2..]);
        }
        if first_arg == "--version" || first_arg == "-v" || first_arg == "-V" {
            println!("agent-commits {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        if first_arg == "--help" || first_arg == "-h" {
            print_help();
            return ExitCode::SUCCESS;
        }
    }

    // Anything else is git calling us as its signing program, as `agent-sign`
    // was. `agent-commits-ssh-sign` runs the same code.
    agent_commits::ssh_sign::run(&args[1..])
}

fn print_help() {
    println!("agent-commits: git commit signing and leases for AI agents (formerly agent-sign)");
    println!();
    println!("USAGE:");
    println!(
        "  agent-commits-ssh-sign <git-ssh-args...>    (Used internally by Git as gpg.ssh.program)"
    );
    println!(
        "  agent-commits <git-ssh-args...>             (Same as agent-commits-ssh-sign; how agent-sign was used)"
    );
    println!("  agent-commits leases                        (List active leases and their terms)");
    println!(
        "  agent-commits status                        (Check service health and list active leases)"
    );
    println!(
        "  agent-commits revoke <repo|folder|everywhere> (End the lease covering it, as `leases` shows it)"
    );
    println!("  agent-commits revoke --all                  (Revoke all active agent leases)");
    println!(
        "  agent-commits doctor                        (Run full system diagnostics and check health)"
    );
    println!("  agent-commits --version                     (Show version)");
    println!("  agent-commits --help                        (Show this message)");
    println!();
    println!("The old names agent-sign, agent-signd, and agent-git still work.");
}

fn run_leases() -> ExitCode {
    let socket_path = client_socket_path();

    match send_request(&socket_path, &Request::ListLeases) {
        Ok(Response::LeaseList { leases }) => {
            if leases.is_empty() {
                println!("No active agent leases found.");
                return ExitCode::SUCCESS;
            }

            // The repository comes last and in full: it's what `agent-commits revoke`
            // takes, so it mustn't be cut short.
            println!(
                "\x1b[1m{:<20} {:<10} {:<14} {:<18} {:<8} REPOSITORY\x1b[0m",
                "BRANCH / SCOPE", "MODE", "GRANTED", "EXPIRES", "COMMITS"
            );
            println!("{}", "─".repeat(98));

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);

            for lease in leases {
                let granted_desc = format_relative_time(now.saturating_sub(lease.granted_at_epoch));
                let expires_desc = match lease.expires_in_secs {
                    Some(rem) => format!("in {}", format_relative_time(rem)),
                    None => "when revoked".to_string(),
                };
                // A lease wider than one repository covers every unprotected
                // branch; the branch it holds is only where it was approved.
                let wide = lease.covers.starts_with("every repository");
                let branch_display = if wide || lease.branch.is_empty() || lease.branch == "*" {
                    "(all branches)".to_string()
                } else {
                    lease.branch
                };
                let covers_display = if wide {
                    format!("{}  ({})", lease.repo, lease.covers)
                } else {
                    lease.repo
                };

                println!(
                    "{:<20} {:<10} {:<14} {:<18} {:<8} {}",
                    truncate_str(&branch_display, 18),
                    lease.mode,
                    format!("{} ago", granted_desc),
                    expires_desc,
                    lease.commit_count,
                    covers_display
                );
            }
            println!();
            ExitCode::SUCCESS
        }
        Ok(Response::Error { message }) => {
            eprintln!("[agent-commits] Daemon error: {}", message);
            ExitCode::from(1)
        }
        Ok(other) => {
            eprintln!("[agent-commits] Unexpected daemon response: {:?}", other);
            ExitCode::from(1)
        }
        Err(e) => {
            eprintln!(
                "[agent-commits] Failed to communicate with daemon at {}: {}",
                socket_path.display(),
                e
            );
            eprintln!(
                "[agent-commits] Ensure `agent-commitsd` (formerly `agent-signd`) is running."
            );
            ExitCode::from(1)
        }
    }
}

fn run_status() -> ExitCode {
    let socket_path = client_socket_path();

    match send_request(&socket_path, &Request::Ping) {
        Ok(Response::Pong) | Ok(Response::Success) => {
            println!(
                "\x1b[32m✓\x1b[0m Daemon is active and healthy (socket: {})\n",
                socket_path.display()
            );
            run_leases()
        }
        Ok(other) => {
            println!(
                "\x1b[33m⚠\x1b[0m Daemon responded unexpectedly: {:?}\n",
                other
            );
            run_leases()
        }
        Err(e) => {
            eprintln!(
                "\x1b[31m✗\x1b[0m Daemon is not running or unreachable: {}",
                e
            );
            eprintln!("  Socket: {}", socket_path.display());
            ExitCode::from(1)
        }
    }
}

fn run_revoke(args: &[String]) -> ExitCode {
    let socket_path = client_socket_path();

    let mut all = false;
    let mut targets: Vec<String> = Vec::new();
    let mut branch = None;

    let mut idx = 0;
    while idx < args.len() {
        match args[idx].as_str() {
            "--all" | "-a" => {
                all = true;
            }
            "--branch" | "-b" => {
                if idx + 1 < args.len() {
                    branch = Some(args[idx + 1].clone());
                    idx += 1;
                }
            }
            r if !r.starts_with('-') && targets.is_empty() => {
                targets = revoke_targets(r);
            }
            _ => {}
        }
        idx += 1;
    }

    if !all && targets.is_empty() {
        eprintln!("Usage: agent-commits revoke <repository, folder, or everywhere>");
        eprintln!("       agent-commits revoke --all");
        return ExitCode::from(1);
    }

    // Try each thing the argument could name, in order, stopping at the
    // first lease found; the service's "no lease" answer for the last one is
    // what the person sees if none matched.
    let mut repo = String::new();
    let mut result = None;
    for target in if all { vec![String::new()] } else { targets } {
        repo = target;
        let req = Request::RevokeLease {
            repo: repo.clone(),
            branch: branch.clone(),
            all,
        };
        let answer = send_request(&socket_path, &req);
        let matched = !matches!(answer, Ok(Response::Error { .. }));
        result = Some(answer);
        if matched {
            break;
        }
    }
    match result.expect("at least one request was sent") {
        Ok(Response::Success) => {
            if all {
                println!("\x1b[32m✓\x1b[0m All active agent leases revoked.");
            } else {
                println!("\x1b[32m✓\x1b[0m Lease revoked for '{}'.", repo);
            }
            ExitCode::SUCCESS
        }
        Ok(Response::Error { message }) => {
            eprintln!("\x1b[31m✗\x1b[0m Revocation failed: {}", message);
            ExitCode::from(1)
        }
        Ok(other) => {
            eprintln!("[agent-commits] Unexpected daemon response: {:?}", other);
            ExitCode::from(1)
        }
        Err(e) => {
            eprintln!(
                "[agent-commits] Failed to communicate with daemon at {}: {}",
                socket_path.display(),
                e
            );
            eprintln!(
                "[agent-commits] Ensure `agent-commitsd` (formerly `agent-signd`) is running."
            );
            ExitCode::from(1)
        }
    }
}

/// What the argument to `agent-commits revoke` may name, most likely first:
/// the repository it's in (see [`resolve_repo_arg`]), then the path itself,
/// canonical, for a folder lease on a folder that sits inside a repository.
/// `everywhere`, or anything that isn't a path, is passed on unchanged.
fn revoke_targets(arg: &str) -> Vec<String> {
    let mut targets = vec![resolve_repo_arg(arg)];
    if let Ok(path) = fs::canonicalize(arg) {
        let path = path.to_string_lossy().to_string();
        if !targets.contains(&path) {
            targets.push(path);
        }
    }
    targets
}

/// Turns what the person typed after `agent-commits revoke` into the key the service
/// files leases under: the canonical path of the repository's top level, as
/// the git wrapper computes it. So `agent-commits revoke .` inside a repository, or a
/// path through a symlink, names the same lease `agent-commits leases` shows. Anything
/// that isn't an existing path is passed on unchanged.
fn resolve_repo_arg(arg: &str) -> String {
    let path = std::path::Path::new(arg);
    if !path.exists() {
        return arg.to_string();
    }
    let top = Command::new("git")
        .arg("-C")
        .arg(path)
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|t| !t.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| path.to_path_buf());
    fs::canonicalize(&top)
        .unwrap_or(top)
        .to_string_lossy()
        .to_string()
}

fn format_relative_time(secs: u64) -> String {
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86400 {
        let hours = secs / 3600;
        let mins = (secs % 3600) / 60;
        if mins == 0 {
            format!("{}h", hours)
        } else {
            format!("{}h {}m", hours, mins)
        }
    } else {
        let days = secs / 86400;
        let hours = (secs % 86400) / 3600;
        if hours == 0 {
            format!("{}d", days)
        } else {
            format!("{}d {}h", days, hours)
        }
    }
}

fn truncate_str(s: &str, max_len: usize) -> String {
    if s.chars().count() > max_len {
        let truncated: String = s.chars().take(max_len.saturating_sub(1)).collect();
        format!("{}…", truncated)
    } else {
        s.to_string()
    }
}

fn run_doctor() -> ExitCode {
    println!("\x1b[1m══════════════════════════════════════════════════\x1b[0m");
    println!("\x1b[1m            agent-commits Diagnostic Health Check          \x1b[0m");
    println!("\x1b[1m══════════════════════════════════════════════════\x1b[0m\n");

    let mut passes = 0;
    let mut warnings = 0;
    let mut failures = 0;

    let config = Config::load(None);

    // 1. Check Git configuration
    let gpg_format = Command::new("git")
        .args(["config", "--global", "gpg.format"])
        .output();
    let format_val = gpg_format
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    // This is the person's own signing setting. Agent commits don't depend on
    // it (the wrapper sets gpg.format=ssh for each agent commit), so any value
    // is fine; advising a change here would switch the person's own signing.
    let shown = if format_val.is_empty() {
        "not set".to_string()
    } else {
        format_val
    };
    println!(
        "  \x1b[32m✓\x1b[0m Your own git signing format: {} (agent commits use ssh either way)",
        shown
    );
    passes += 1;

    // 2. Check Fallback Program
    let fallback = &config.ssh.fallback_program;
    let fallback_path = PathBuf::from(fallback);
    if fallback_path.exists()
        || Command::new("which")
            .arg(fallback)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    {
        println!("  \x1b[32m✓\x1b[0m Human fallback signer: {}", fallback);
        passes += 1;
    } else {
        println!(
            "  \x1b[31m✗\x1b[0m Human fallback signer not found: {}",
            fallback
        );
        println!(
            "    Hint: Check `fallback_program` in {}",
            agent_commits::paths::state_dir()
                .join("config.toml")
                .display()
        );
        failures += 1;
    }

    // 3. Check Agent Key Files
    let pub_key_path = config.ssh.agent_key_path.with_extension("pub");
    if config.ssh.agent_key_path.exists() && pub_key_path.exists() {
        println!(
            "  \x1b[32m✓\x1b[0m Agent keypair present: {}",
            config.ssh.agent_key_path.display()
        );
        passes += 1;
    } else {
        println!(
            "  \x1b[31m✗\x1b[0m Agent keypair missing at {}",
            config.ssh.agent_key_path.display()
        );
        println!("    Hint: Run `agent-commitsd setup` to generate keys");
        failures += 1;
    }

    // 4. Check Allowed Signers
    let allowed_file_out = Command::new("git")
        .args(["config", "--global", "gpg.ssh.allowedSignersFile"])
        .output();
    let allowed_path_str = allowed_file_out
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    if !allowed_path_str.is_empty() {
        let clean_path = allowed_path_str.replace("~", &std::env::var("HOME").unwrap_or_default());
        let allowed_path = PathBuf::from(&clean_path);
        if allowed_path.exists() {
            println!(
                "  \x1b[32m✓\x1b[0m Local allowed_signers registered: {}",
                clean_path
            );
            passes += 1;
        } else {
            println!(
                "  \x1b[33m⚠\x1b[0m allowed_signers file configured but does not exist at {}",
                clean_path
            );
            warnings += 1;
        }
    } else {
        println!("  \x1b[33m⚠\x1b[0m gpg.ssh.allowedSignersFile is not configured in git");
        warnings += 1;
    }

    // 5. Check Daemon Connection
    let socket_path = client_socket_path();

    let ping_req = Request::Ping;
    match send_request(&socket_path, &ping_req) {
        Ok(Response::Pong) => {
            println!(
                "  \x1b[32m✓\x1b[0m Daemon socket active and responsive: {}",
                socket_path.display()
            );
            passes += 1;
        }
        Ok(_) => {
            println!(
                "  \x1b[32m✓\x1b[0m Daemon responded at {}",
                socket_path.display()
            );
            passes += 1;
        }
        Err(e) => {
            println!("  \x1b[31m✗\x1b[0m Daemon connection failed: {}", e);
            println!("    Hint: Start the service with `agent-commitsd`");
            failures += 1;
        }
    }

    // 6. Check GitHub CLI registration
    if Command::new("which")
        .arg("gh")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        let gh_check = Command::new("gh").args(["ssh-key", "list"]).output();
        if let Ok(o) = gh_check {
            let out_str = String::from_utf8_lossy(&o.stdout);
            if pub_key_path.exists()
                && let Ok(pub_content) = fs::read_to_string(&pub_key_path)
            {
                let key_data = pub_content.split_whitespace().nth(1).unwrap_or("");
                if !key_data.is_empty() && out_str.contains(key_data) {
                    println!("  \x1b[32m✓\x1b[0m GitHub account: Agent signing key registered!");
                    passes += 1;
                } else {
                    println!(
                        "  \x1b[33m⚠\x1b[0m GitHub account: Agent key not found in `gh ssh-key list`"
                    );
                    println!(
                        "    Hint: Run `gh ssh-key add {} --type signing`",
                        pub_key_path.display()
                    );
                    warnings += 1;
                }
            }
        }
    }

    // 7. Check Directory Permissions & Lease Persistence Storage
    let agent_dir = agent_commits::paths::state_dir();
    if agent_dir.exists() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(metadata) = fs::metadata(&agent_dir) {
                let mode = metadata.permissions().mode() & 0o777;
                if mode & 0o077 != 0 {
                    println!(
                        "  \x1b[33m⚠\x1b[0m {} permissions are {:04o} (recommended 0700)",
                        agent_dir.display(),
                        mode
                    );
                    warnings += 1;
                }
            }
        }
    }

    let leases_file = agent_dir.join("leases.json");
    if leases_file.exists() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(metadata) = fs::metadata(&leases_file) {
                let mode = metadata.permissions().mode() & 0o777;
                if mode != 0o600 {
                    println!(
                        "  \x1b[33m⚠\x1b[0m Lease storage permissions are {:04o} (expected 0600) at {}",
                        mode,
                        leases_file.display()
                    );
                    warnings += 1;
                }
            }
        }

        match fs::read_to_string(&leases_file) {
            Ok(content) => match serde_json::from_str::<serde_json::Value>(&content) {
                Ok(val) => {
                    let count = val.as_object().map(|o| o.len()).unwrap_or(0);
                    println!(
                        "  \x1b[32m✓\x1b[0m Persistent lease storage verified: {} ({} lease(s))",
                        leases_file.display(),
                        count
                    );
                    passes += 1;
                }
                Err(e) => {
                    println!(
                        "  \x1b[31m✗\x1b[0m Lease storage file corrupted: {} ({})",
                        leases_file.display(),
                        e
                    );
                    failures += 1;
                }
            },
            Err(e) => {
                println!(
                    "  \x1b[31m✗\x1b[0m Could not read lease storage file: {}",
                    e
                );
                failures += 1;
            }
        }
    } else {
        println!(
            "  \x1b[32m✓\x1b[0m Persistent lease storage ready (will initialize on first lease grant)"
        );
        passes += 1;
    }

    println!();
    if failures == 0 && warnings == 0 {
        println!(
            "\x1b[1;32mAll {} checks passed! System is fully operational.\x1b[0m\n",
            passes
        );
        ExitCode::SUCCESS
    } else if failures == 0 {
        println!(
            "\x1b[1;33m{} passed, {} warning(s). agent-commits is usable.\x1b[0m\n",
            passes, warnings
        );
        ExitCode::SUCCESS
    } else {
        println!(
            "\x1b[1;31m{} passed, {} warning(s), {} failure(s). Please review hints above.\x1b[0m\n",
            passes, warnings, failures
        );
        ExitCode::from(1)
    }
}
