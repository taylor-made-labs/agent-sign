//! `agent-sign`: the command line for agent-sign.
//!
//! `agent-sign leases`, `status`, `revoke`, `trust-line`, `trust install`, `verify`, `launch`, `doctor`, `--version`, `--help`. Any other
//! arguments are treated as git calling it as `gpg.ssh.program`, exactly as
//! `agent-sign` did, so `agent-sign` can be a link to this program. New setups
//! point git at `agent-ssh-sign` instead.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use agent_sign::config::Config;
use agent_sign::protocol::{Request, Response, client_socket_path, send_request};

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
        if first_arg == "pending" {
            return run_pending();
        }
        if first_arg == "deny" {
            return run_deny(&args[2..]);
        }
        if first_arg == "trust-line" {
            return run_trust_line();
        }
        if first_arg == "trust" {
            return run_trust(&args[2..]);
        }
        if first_arg == "verify" {
            return run_verify(&args[2..]);
        }
        if first_arg == "act" {
            return agent_sign::act_cli::run(&args[2..]);
        }
        if first_arg == "launch" {
            return run_launch(&env::args_os().skip(2).collect::<Vec<_>>());
        }
        if first_arg == "session-exec" && args.len() == 2 {
            return run_session_step(true);
        }
        if first_arg == "session-end" && args.len() == 2 {
            return run_session_step(false);
        }
        if first_arg == "--version" || first_arg == "-v" || first_arg == "-V" {
            println!("agent-sign {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        if first_arg == "--help" || first_arg == "-h" {
            print_help();
            return ExitCode::SUCCESS;
        }
    }

    // Anything else is git calling us as its signing program, as `agent-sign`
    // was. `agent-ssh-sign` runs the same code.
    agent_sign::ssh_sign::run(&args[1..])
}

fn print_help() {
    println!("agent-sign: git commit signing and leases for AI agents");
    println!();
    println!("USAGE:");
    println!("  agent-ssh-sign <git-ssh-args...>    (Used internally by Git as gpg.ssh.program)");
    println!(
        "  agent-sign <git-ssh-args...>             (Same as agent-ssh-sign; how agent-sign was used)"
    );
    println!("  agent-sign leases                        (List active leases and their terms)");
    println!(
        "  agent-sign status                        (Check service health and list active leases)"
    );
    println!(
        "  agent-sign revoke <repo|folder|everywhere> (End the lease covering it, as `leases` shows it)"
    );
    println!("  agent-sign revoke --all                  (Revoke all active agent leases)");
    println!(
        "  agent-sign pending                       (List approval requests waiting for an answer)"
    );
    println!(
        "  agent-sign deny <id>|--all               (Deny waiting requests and close their dialogs)"
    );
    println!(
        "  agent-sign trust-line                    (Print the allowed-signers line that trusts agents' signatures)"
    );
    println!(
        "  agent-sign trust install                 (Trust the running service's authority: record it, update agent-sign's block)"
    );
    println!(
        "  agent-sign verify [--format json] <rev>  (Check a commit's signature, then say how its signer's name was established)"
    );
    println!(
        "  agent-sign launch --agent <name> -- <program> [args...]  (Run an agent as a launched session: its own name, sandbox and channel; Linux)"
    );
    println!(
        "  agent-sign launch --agent <name> --identity agent:<id> -- <program> [args...]  (The same, and the session can sign acts as agent:<id>; needs [acts] enabled)"
    );
    println!(
        "  agent-sign act sign|verify|credential|verify-credential|trust-lines  (Signed acts: see `agent-sign act`)"
    );
    println!(
        "  agent-sign launch --collect <session>    (System mode: fetch the bundles of a session whose caller had gone)"
    );
    println!(
        "  agent-sign doctor                        (Run full system diagnostics and check health)"
    );
    println!("  agent-sign --version                     (Show version)");
    println!("  agent-sign --help                        (Show this message)");
    println!();
}

/// The agents' domain the user's config names (`[identity] machine`), and
/// the state folder's keys folder.
fn trust_setting() -> Result<(PathBuf, PathBuf, String), String> {
    let state = agent_sign::paths::state_dir();
    let keys = agent_sign::agents_ca::keys_dir_in(&state);
    let settings = agent_sign::config::IdentityConfig::load_user()?;
    Ok((state, keys, settings.domain()))
}

/// The allowed-signers lines for the authorities `agent-sign trust install`
/// recorded, oldest first, then the running service's live authority if it
/// isn't one of them, each scoped to `domain`. The live line comes only
/// from a service that holds the state lock and wrote it this run
/// (`agent_sign::state_lock::live_authority`), never from a key file left
/// on disk.
fn trust_lines_with_live(state: &Path, keys: &Path, domain: &str) -> Vec<String> {
    let mut lines = agent_sign::agents_ca::trust_lines_in(keys, domain);
    if let Some(live) = agent_sign::state_lock::live_authority(state) {
        let line = agent_sign::agents_ca::trust_line_in(domain, &live);
        if !lines.contains(&line) {
            lines.push(line);
        }
    }
    lines
}

/// Prints the allowed-signers lines that trust the agents' certificate
/// authorities for `*@agents.local` (or `*@<machine>.agents.local` when the
/// user's config sets `[identity] machine`, as agent-sign's managed block
/// does): one per authority `agent-sign trust install` recorded, oldest
/// first, so commits certified before a restart still verify, then the
/// running service's live authority while it runs. Added to the file git's
/// `gpg.ssh.allowedSignersFile` names, they make every agent commit show as
/// a Good signature for that agent's own principal. Printing them changes
/// no trust; `agent-sign trust install` writes it.
fn run_trust_line() -> ExitCode {
    let (state, keys, domain) = match trust_setting() {
        Ok(found) => found,
        Err(e) => {
            eprintln!("agent-sign: {e}");
            return ExitCode::from(1);
        }
    };
    let lines = trust_lines_with_live(&state, &keys, &domain);
    if lines.is_empty() {
        eprintln!(
            "agent-sign: no agents' certificate authority yet: no service is running for {}, \
             and `agent-sign trust install` has recorded none in {}. Start the service \
             (`agent-signd`), then run this again.",
            state.display(),
            keys.display()
        );
        return ExitCode::from(1);
    }
    for line in lines {
        println!("{line}");
    }
    ExitCode::SUCCESS
}

/// `agent-sign trust <install>`.
fn run_trust(args: &[String]) -> ExitCode {
    match args {
        [cmd] if cmd == "install" => run_trust_install(),
        _ => {
            eprintln!("usage: agent-sign trust install");
            ExitCode::from(2)
        }
    }
}

/// `agent-sign trust install`: the only thing that writes trust (decision
/// D2, the suite PM, 31 Oct 2026). It records the running service's live
/// authority in the authority history (`keys/agents_cas.pub`, append-only,
/// once per key), and rewrites agent-sign's managed block in the file git's
/// global `gpg.ssh.allowedSignersFile` names with every recorded authority,
/// scoped to this machine's agents' domain, leaving the rest of the file as
/// it was. The installer runs it once the service is up; run it again after
/// the service restarts. A service's start never does this, so starting
/// another service changes nothing a verifier trusts (P3).
///
/// Exits 1, saying why, when no service is running (nothing live to trust;
/// the block still gets the recorded authorities), or when there is no
/// managed block to write.
fn run_trust_install() -> ExitCode {
    use agent_sign::agents_ca::BlockUpdate;
    let (state, keys, domain) = match trust_setting() {
        Ok(found) => found,
        Err(e) => {
            eprintln!("agent-sign trust install: {e}");
            return ExitCode::from(1);
        }
    };
    let mut failed = false;
    let live = agent_sign::state_lock::live_authority(&state);
    let lines = match &live {
        Some(line) => match agent_sign::agents_ca::record_authority(
            &keys,
            line,
            agent_sign::agents_ca::now_secs(),
            &domain,
        ) {
            Ok(lines) => {
                println!(
                    "Recorded the running service's certificate authority in {}",
                    keys.join(agent_sign::agents_ca::CAS_HISTORY_FILE).display()
                );
                lines
            }
            Err(e) => {
                eprintln!(
                    "agent-sign trust install: the running service's authority can't be \
                     recorded in {} ({e}), so nothing was trusted",
                    keys.display()
                );
                return ExitCode::from(1);
            }
        },
        None => {
            eprintln!(
                "agent-sign trust install: no agent-signd is running for {}, so there is no \
                 live authority to trust. Start the service, then run this again.",
                state.display()
            );
            failed = true;
            agent_sign::agents_ca::trust_lines_in(&keys, &domain)
        }
    };
    match agent_sign::agents_ca::global_allowed_signers_file() {
        Some(file) => match agent_sign::agents_ca::update_allowed_signers(&file, &lines) {
            Ok(BlockUpdate::Rewritten) => println!(
                "Updated agent-sign's block in {}: it trusts {} authorities for *@{domain}",
                file.display(),
                lines.len()
            ),
            Ok(BlockUpdate::Unchanged) => println!(
                "agent-sign's block in {} already trusts these {} authorities for *@{domain}",
                file.display(),
                lines.len()
            ),
            Ok(BlockUpdate::NoBlock) => {
                eprintln!(
                    "agent-sign trust install: {} has no agent-sign block, so nothing in it \
                     was changed. Run the installer again, which adds the block, or add the \
                     lines `agent-sign trust-line` prints yourself.",
                    file.display()
                );
                failed = true;
            }
            Err(e) => {
                eprintln!(
                    "agent-sign trust install: agent-sign's block in {} can't be updated ({e})",
                    file.display()
                );
                failed = true;
            }
        },
        None => {
            eprintln!(
                "agent-sign trust install: git's global config names no \
                 gpg.ssh.allowedSignersFile, so no verifier here reads the trust. Run the \
                 installer again, which sets one up with agent-sign's block, then run this again."
            );
            failed = true;
        }
    }
    if failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

/// `agent-sign verify [--format json] [--allowed-signers <absolute file>] <rev>`, in a
/// repository: checks the commit's signature against the trust file the
/// verifier chooses (`--allowed-signers`, else the system-mode file, else
/// git's system and global config; never the repository's own, see
/// `agent_sign::verify::trust_file`), with ssh-keygen, and only when it
/// verifies prints how the signer's identity was established
/// (`attestation: ...`). Otherwise it prints "not verified: <why>", and no
/// attestation, and exits 1. A relative `--allowed-signers` path is refused
/// (exit 2): it would be read from the current folder, often the checkout
/// being verified, which the session under check can write.
///
/// With `--format json` it prints exactly one JSON object on stdout (the
/// interface a merge step calls, README "Merge gates"). Both forms exit the
/// same way (F3, the second whole-branch review): 0 only when the commit is
/// verified and attested, 2 when the check can't run, else 1. Both come from
/// the one `agent_sign::verify::verdict_with`, and the human form prints
/// nothing a commit controls (the committer's email, a certified name) with
/// its control characters raw.
fn run_verify(args: &[String]) -> ExitCode {
    let usage = || {
        eprintln!(
            "usage: agent-sign verify [--format json] [--allowed-signers <absolute file>] <rev>\n\
             (--allowed-signers takes an absolute path outside the checkout being verified)"
        );
        ExitCode::from(2)
    };
    let mut json = false;
    let mut rev: Option<&String> = None;
    let mut allowed: Option<std::path::PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        let file = if arg == "--allowed-signers" {
            i += 1;
            match args.get(i) {
                Some(f) => Some(f.as_str()),
                None => return usage(),
            }
        } else {
            arg.strip_prefix("--allowed-signers=")
        };
        if let Some(file) = file {
            if allowed.is_some() || file.is_empty() {
                return usage();
            }
            allowed = Some(std::path::PathBuf::from(file));
            i += 1;
            continue;
        }
        let format = if arg == "--format" {
            i += 1;
            match args.get(i) {
                Some(f) => Some(f.as_str()),
                None => return usage(),
            }
        } else {
            arg.strip_prefix("--format=")
        };
        match format {
            Some("json") => json = true,
            Some("human") => json = false,
            Some(_) => return usage(),
            None if rev.is_none() => rev = Some(arg),
            None => return usage(),
        }
        i += 1;
    }
    let Some(rev) = rev else {
        return usage();
    };
    let verdict = match env::current_dir() {
        // A relative path would be read from the current folder, often the
        // checkout being verified, which the session under check can write
        // (V1): refuse it rather than trust a file that session made.
        Ok(_) if allowed.as_deref().is_some_and(|p| !p.is_absolute()) => {
            agent_sign::verify::Verdict::cant_run(format!(
                "--allowed-signers {} is a relative path, which would be read from the \
                 current folder (often the checkout being verified); pass an absolute path \
                 to a file outside the checkout",
                agent_sign::verify::plain_text(&allowed.as_deref().unwrap().display().to_string())
            ))
        }
        Ok(dir) => agent_sign::verify::verdict_with(&dir, rev, allowed.as_deref()),
        Err(e) => agent_sign::verify::Verdict::cant_run(format!("no current folder ({e})")),
    };
    if json {
        println!("{}", verdict.to_json());
        return ExitCode::from(verdict.json_exit_code());
    }
    use agent_sign::verify::plain_text;
    if verdict.verified {
        println!(
            "verified: Good signature for {}",
            plain_text(verdict.signer.as_deref().unwrap_or_default())
        );
        println!(
            "attestation: {}",
            plain_text(verdict.attestation_words.as_deref().unwrap_or_default())
        );
        // The author is the commit's to write, so it is filtered as the
        // committer is (R3). It says whether it is the signer: the signature
        // vouches for the committer, and a gate that needs the author too
        // reads `author_matches_signer` in the JSON form.
        match verdict.author.as_deref() {
            Some(author) => println!(
                "author: {} ({})",
                plain_text(author),
                if verdict.author_matches_signer() {
                    "the signer"
                } else {
                    "not the signer"
                }
            ),
            None => println!("author: none (no single author with an email)"),
        }
        if !verdict.attested {
            println!("note: {}", agent_sign::verify::MERGE_NOTE);
        }
    } else {
        eprintln!(
            "agent-sign verify: not verified: {}",
            plain_text(&verdict.detail)
        );
    }
    ExitCode::from(verdict.json_exit_code())
}

/// `agent-sign session-exec` / `session-end`: a launched session's own
/// steps in system mode, run by systemd as a slot's account (see
/// `agent_sign::session_runner`). They take no arguments.
#[cfg(target_os = "linux")]
fn run_session_step(exec: bool) -> ExitCode {
    if exec {
        agent_sign::session_runner::exec()
    } else {
        agent_sign::session_runner::end()
    }
}

/// Sessions in slot accounts exist only on Linux.
#[cfg(not(target_os = "linux"))]
fn run_session_step(_exec: bool) -> ExitCode {
    eprintln!("agent-sign: launched sessions in slot accounts exist only on Linux");
    ExitCode::from(1)
}

/// `agent-sign launch --agent <name> -- <program> [args...]`: runs the
/// program as a new launched session (see `agent_sign::launch`).
/// `agent-sign launch --collect <session>` (system mode): fetches the
/// bundles of a session whose caller had gone before it ended.
fn run_launch(args: &[std::ffi::OsString]) -> ExitCode {
    let usage = || {
        eprintln!(
            "usage: agent-sign launch --agent <name> [--identity agent:<id>] -- <program> [args...]\n       agent-sign launch --collect <session>"
        );
        ExitCode::from(2)
    };
    if args.first().is_some_and(|a| a == "--collect") {
        let (Some(session), 2) = (args.get(1), args.len()) else {
            return usage();
        };
        return collect(&session.to_string_lossy());
    }
    let mut agent: Option<String> = None;
    let mut identity: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].to_string_lossy();
        if arg == "--" {
            i += 1;
            break;
        } else if arg == "--agent" {
            let Some(value) = args.get(i + 1) else {
                return usage();
            };
            agent = Some(value.to_string_lossy().into_owned());
            i += 2;
        } else if let Some(value) = arg.strip_prefix("--agent=") {
            agent = Some(value.to_string());
            i += 1;
        } else if arg == "--identity" {
            let Some(value) = args.get(i + 1) else {
                return usage();
            };
            identity = Some(value.to_string_lossy().into_owned());
            i += 2;
        } else if let Some(value) = arg.strip_prefix("--identity=") {
            identity = Some(value.to_string());
            i += 1;
        } else {
            return usage();
        }
    }
    let (Some(agent), Some(program)) = (agent, args.get(i)) else {
        return usage();
    };
    agent_sign::launch::run_with_identity(&agent, identity.as_deref(), program, &args[i + 1..])
}

/// `agent-sign launch --collect <session>`: only in system mode, where the
/// launcher keeps a gone caller's bundles.
#[cfg(target_os = "linux")]
fn collect(session: &str) -> ExitCode {
    match agent_sign::launch::system_config() {
        Some(path) => agent_sign::launch_client::collect(&path, session),
        None => {
            eprintln!(
                "agent-sign launch --collect: this machine isn't in system mode, so no launcher \
                 keeps sessions' bundles"
            );
            ExitCode::from(1)
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn collect(_session: &str) -> ExitCode {
    eprintln!("agent-sign launch --collect: launched sessions exist only on Linux");
    ExitCode::from(1)
}

fn run_leases() -> ExitCode {
    let socket_path = client_socket_path();

    match send_request(&socket_path, &Request::ListLeases) {
        Ok(Response::LeaseList { leases }) => {
            if leases.is_empty() {
                println!("No active agent leases found.");
                return ExitCode::SUCCESS;
            }

            // The repository comes last and in full: it's what `agent-sign revoke`
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

            let wide_note = agent_sign::protocol::wide_leases_note(&leases);
            let mut endings: Vec<(String, String)> = Vec::new();
            for lease in leases {
                let granted_desc = format_relative_time(now.saturating_sub(lease.granted_at_epoch));
                // A fixed end, if there is one; the other endings (the work,
                // the idle backstop, revoking) are listed under the table.
                let expires_desc = match lease.expires_in_secs {
                    Some(rem) => format!("by {}", format_relative_time(rem)),
                    None if lease.ends.is_empty() => "when revoked".to_string(),
                    None => "see below".to_string(),
                };
                if !lease.ends.is_empty() {
                    endings.push((lease.repo.clone(), lease.ends.clone()));
                }
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
            if !endings.is_empty() {
                println!();
                println!("Each lease also ends:");
                for (repo, ends) in endings {
                    println!("  {}: {}", repo, ends);
                }
            }
            if let Some(note) = wide_note {
                println!("Note: {note}");
            }
            println!();
            ExitCode::SUCCESS
        }
        Ok(Response::Error { message }) => {
            eprintln!("[agent-sign] Daemon error: {}", message);
            ExitCode::from(1)
        }
        Ok(other) => {
            eprintln!("[agent-sign] Unexpected daemon response: {:?}", other);
            ExitCode::from(1)
        }
        Err(e) => {
            eprintln!(
                "[agent-sign] Failed to communicate with daemon at {}: {}",
                socket_path.display(),
                e
            );
            eprintln!("[agent-sign] Ensure `agent-signd` is running.");
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

/// Lists the approval requests waiting for the person: one per repository
/// and branch, with how many commits are waiting on each.
fn run_pending() -> ExitCode {
    let socket_path = client_socket_path();
    match send_request(&socket_path, &Request::ListPending) {
        Ok(Response::PendingList { pending }) if pending.is_empty() => {
            println!("No approval requests are waiting.");
            ExitCode::SUCCESS
        }
        Ok(Response::PendingList { pending }) => {
            println!("ID        WAITING   COMMITS  REPOSITORY (BRANCH)");
            for p in pending {
                println!(
                    "{:<9} {:<9} {:<8} {} ({})",
                    p.id,
                    format_relative_time(p.waiting_secs),
                    p.waiters,
                    p.repo,
                    p.branch
                );
            }
            println!();
            println!(
                "`agent-sign deny <id>` or `agent-sign deny --all` closes them, answering no."
            );
            ExitCode::SUCCESS
        }
        Ok(Response::Error { message }) => {
            eprintln!("[agent-sign] {}", message);
            ExitCode::from(1)
        }
        Ok(other) => {
            eprintln!("[agent-sign] Unexpected service response: {:?}", other);
            ExitCode::from(1)
        }
        Err(e) => {
            eprintln!(
                "[agent-sign] Couldn't reach the service at {}: {}",
                socket_path.display(),
                e
            );
            ExitCode::from(1)
        }
    }
}

/// Denies waiting approval requests (one by id, or all) and closes their
/// dialogs, so an agent can clean up requests it caused.
fn run_deny(args: &[String]) -> ExitCode {
    let all = args.iter().any(|a| a == "--all" || a == "-a");
    let id = args.iter().find(|a| !a.starts_with('-')).cloned();
    if !all && id.is_none() {
        eprintln!("Usage: agent-sign deny <id>      (an id from `agent-sign pending`)");
        eprintln!("       agent-sign deny --all");
        return ExitCode::from(1);
    }
    let socket_path = client_socket_path();
    match send_request(&socket_path, &Request::DenyPending { id, all }) {
        Ok(Response::Success) => {
            println!("Denied, and the dialogs are closed.");
            ExitCode::SUCCESS
        }
        Ok(Response::Error { message }) => {
            eprintln!("[agent-sign] {}", message);
            ExitCode::from(1)
        }
        Ok(other) => {
            eprintln!("[agent-sign] Unexpected service response: {:?}", other);
            ExitCode::from(1)
        }
        Err(e) => {
            eprintln!(
                "[agent-sign] Couldn't reach the service at {}: {}",
                socket_path.display(),
                e
            );
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
        eprintln!("Usage: agent-sign revoke <repository, folder, or everywhere>");
        eprintln!("       agent-sign revoke --all");
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
            eprintln!("[agent-sign] Unexpected daemon response: {:?}", other);
            ExitCode::from(1)
        }
        Err(e) => {
            eprintln!(
                "[agent-sign] Failed to communicate with daemon at {}: {}",
                socket_path.display(),
                e
            );
            eprintln!("[agent-sign] Ensure `agent-signd` is running.");
            ExitCode::from(1)
        }
    }
}

/// What the argument to `agent-sign revoke` may name, most likely first:
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

/// Turns what the person typed after `agent-sign revoke` into the key the service
/// files leases under: the canonical path of the repository's top level, as
/// the git wrapper computes it. So `agent-sign revoke .` inside a repository, or a
/// path through a symlink, names the same lease `agent-sign leases` shows. Anything
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

/// Doctor's line for a running service whose authority no trust file
/// holds yet (decision D2): said plainly, with the command that fixes it.
fn say_live_authority_not_trusted_yet() {
    println!(
        "  \x1b[33m⚠\x1b[0m The running service's certificate authority isn't trusted yet: \
         agents' commits it signs show as unverified until you run `agent-sign trust install`"
    );
}

/// System mode only (`None` on a laptop): whether the certificate authority
/// OpenBao reports is the one line of `[service] trust_file`, the same
/// comparison the service's issuer makes before it signs anything
/// (`agent_sign::issuer_openbao`). It reads OpenBao's public key endpoint,
/// which needs no login, and only reads the trust file. `Ok` names the trust
/// file; `Err` says what is wrong.
fn system_authority_check() -> Option<Result<String, String>> {
    let active = match agent_sign::system_config::active() {
        Ok(Some(active)) => active,
        Ok(None) => return None,
        Err(e) => return Some(Err(e)),
    };
    let config = &active.config;
    let openbao = match config.openbao(&active.path) {
        Ok(openbao) => openbao,
        Err(e) => return Some(Err(e)),
    };
    let settings = agent_sign::issuer_openbao::Settings {
        address: openbao.address,
        resolve: openbao.resolve.unwrap_or_default(),
        ca_cert: PathBuf::from(openbao.ca_cert),
        mount: openbao.mount,
        role: openbao.role,
        machine: config.machine.clone(),
        trust_file: config.service.trust_file.clone(),
        // Not used: the comparison needs no login.
        credentials_dir: PathBuf::new(),
    };
    Some(
        agent_sign::issuer_openbao::OpenBaoIssuer::new(&settings)
            .and_then(|issuer| issuer.ready())
            .map(|()| config.service.trust_file.display().to_string()),
    )
}

fn run_doctor() -> ExitCode {
    println!("\x1b[1m══════════════════════════════════════════════════\x1b[0m");
    println!("\x1b[1m            agent-sign Diagnostic Health Check          \x1b[0m");
    println!("\x1b[1m══════════════════════════════════════════════════\x1b[0m\n");

    let mut passes = 0;
    let mut warnings = 0;
    let mut failures = 0;

    let config = match Config::try_load(None) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("[agent-sign] Invalid selected config: {e}");
            return ExitCode::from(1);
        }
    };

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
            agent_sign::paths::state_dir().join("config.toml").display()
        );
        failures += 1;
    }

    // 2b. Whether the person's own signing goes through agent-sign: with
    // gpg.ssh.program set to agent-ssh-sign, a signing request from a
    // process an agent marked is refused even when it reaches git without
    // the wrapper (a hook, the real git called directly), and the person's
    // own requests go on to fallback_program. The installer sets this up.
    let own_program = Command::new("git")
        .args([
            "config",
            "--global",
            "--includes",
            "--get",
            "gpg.ssh.program",
        ])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    if Path::new(&own_program).file_name().and_then(|n| n.to_str()) == Some("agent-ssh-sign") {
        println!(
            "  \x1b[32m✓\x1b[0m Your own signing goes through agent-sign ({own_program}), on to {fallback}"
        );
        passes += 1;
    } else {
        println!(
            "  \x1b[33m⚠\x1b[0m Your own signing doesn't go through agent-sign (gpg.ssh.program is {})",
            if own_program.is_empty() {
                "not set"
            } else {
                own_program.as_str()
            }
        );
        println!(
            "    Hint: Run the installer again: it routes it through agent-ssh-sign and keeps your signer as fallback_program"
        );
        warnings += 1;
    }

    // 3. Check the agents' certificate authorities: the ones `agent-sign
    // trust install` recorded, and the running service's live one, scoped
    // to this machine's agents' domain as the managed block is.
    let state_dir = agent_sign::paths::state_dir();
    let keys_dir = agent_sign::agents_ca::keys_dir_in(&state_dir);
    let domain = agent_sign::config::IdentityConfig::load_user()
        .map(|s| s.domain())
        .unwrap_or_else(|_| agent_sign::attribution::AGENTS_DOMAIN.to_string());
    let recorded = agent_sign::agents_ca::trust_lines_in(&keys_dir, &domain);
    let live = agent_sign::state_lock::live_authority(&state_dir)
        .map(|l| agent_sign::agents_ca::trust_line_in(&domain, &l));
    let trust = trust_lines_with_live(&state_dir, &keys_dir, &domain);
    if !recorded.is_empty() {
        println!(
            "  \x1b[32m✓\x1b[0m Agents' certificate authorities recorded by `agent-sign trust install`: {} in {}",
            recorded.len(),
            keys_dir
                .join(agent_sign::agents_ca::CAS_HISTORY_FILE)
                .display()
        );
        passes += 1;
    }
    if live.is_some() {
        println!(
            "  \x1b[32m✓\x1b[0m The running service's certificate authority is live (made in its memory at start)"
        );
        passes += 1;
    }
    if trust.is_empty() {
        println!(
            "  \x1b[31m✗\x1b[0m No agents' certificate authority: no service is running, and none is recorded in {}",
            keys_dir.display()
        );
        println!(
            "    Hint: Start the service (`agent-signd`), then run `agent-sign trust install`"
        );
        failures += 1;
    }
    let unprotected = keys_dir.join(agent_sign::agents_ca::CA_KEY_FILE);
    if fs::symlink_metadata(&unprotected).is_ok() {
        println!(
            "  \x1b[31m✗\x1b[0m An agents' authority private key is stored unprotected: {} (the service won't start while it's there)",
            unprotected.display()
        );
        println!("    Hint: Run the installer again: it deletes it, after asking");
        failures += 1;
    }
    if config.ssh.agent_key_path.exists() {
        println!(
            "  \x1b[33m⚠\x1b[0m The shared agent key of earlier versions is no longer used, and its private half is stored unprotected: {}",
            config.ssh.agent_key_path.display()
        );
        println!(
            "    Hint: Run the installer again: it deletes the private half (after asking) and prints the commands to stop trusting it in allowed_signers and on GitHub"
        );
        warnings += 1;
    }

    // 3b. What an agent's signature means, said plainly so a passing health
    // check isn't read as more (security review fix round, 31 Oct 2026;
    // reworded at the switch, S8 / P7 / D1, 1 Nov 2026). Not a warning:
    // nothing here can fix it in one account.
    println!(
        "  \x1b[36mi\x1b[0m Only an agent a launcher started (`agent-sign launch --agent <name> -- <program>`) or an approval named is signed. \
         Any other agent's commit is unsigned, under its own names, because no launcher started it. \
         In one account a launcher keeps sessions apart from each other, not from other processes of this account"
    );

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
            let content = fs::read_to_string(&allowed_path).unwrap_or_default();
            let has = |line: &String| content.lines().any(|l| l.trim() == line.as_str());
            let missing = trust.iter().filter(|line| !has(line)).count();
            let live_missing = live.as_ref().is_some_and(|l| !has(l));
            let has_block = content
                .lines()
                .any(|l| l == agent_sign::agents_ca::BLOCK_BEGIN);
            if trust.is_empty() {
                // Reported above.
            } else if missing == 0 {
                println!(
                    "  \x1b[32m✓\x1b[0m It trusts agents' signatures ({} authorities{})",
                    trust.len(),
                    if has_block {
                        ", in agent-sign's block, which `agent-sign trust install` keeps current"
                    } else {
                        ""
                    }
                );
                passes += 1;
            } else {
                if live_missing {
                    say_live_authority_not_trusted_yet();
                }
                let older = missing - usize::from(live_missing);
                if older > 0 {
                    println!(
                        "  \x1b[33m⚠\x1b[0m It doesn't trust {older} of the {} recorded agents' authorities: commits they certified show as unverified",
                        recorded.len()
                    );
                }
                if has_block {
                    println!(
                        "    Hint: Run `agent-sign trust install`: it rewrites agent-sign's block"
                    );
                } else {
                    println!(
                        "    Hint: Run the installer again: it adds a block that `agent-sign trust install` keeps current"
                    );
                }
                warnings += 1;
            }
        } else {
            println!(
                "  \x1b[33m⚠\x1b[0m allowed_signers file configured but does not exist at {}",
                clean_path
            );
            warnings += 1;
        }
    } else {
        println!("  \x1b[33m⚠\x1b[0m gpg.ssh.allowedSignersFile is not configured in git");
        if live.is_some() {
            say_live_authority_not_trusted_yet();
            println!(
                "    Hint: Run the installer again: it sets one up with agent-sign's block, which `agent-sign trust install` keeps current"
            );
        }
        warnings += 1;
    }

    // 4b. Whether git here reads an SSH certificate's times correctly. git
    // gives ssh-keygen the commit's date as local time with no zone, which
    // OpenSSH 10.0p2 misreads whenever the clock zone isn't UTC; `agent-sign
    // verify` gives it UTC with a Z and is unaffected. A warning, never a
    // refusal: signing isn't affected.
    match agent_sign::cert_times::check() {
        agent_sign::cert_times::Reading::Correct => {
            println!(
                "  \x1b[32m✓\x1b[0m Git here reads certificate times correctly (checked with this machine's ssh-keygen, in this clock zone)"
            );
            passes += 1;
        }
        agent_sign::cert_times::Reading::Misread => {
            println!(
                "  \x1b[33m⚠\x1b[0m Git here misreads certificate times in this clock zone: this machine's ssh-keygen takes the local time git gives it as UTC, so git's own check of an agent's signature is shifted by the zone's offset (%G?, `git verify-commit`)"
            );
            println!(
                "    `agent-sign verify` is unaffected: it gives ssh-keygen the UTC time, so anything that decides (a merge gate, a server-side check, a hook) must use it, never git's verdict"
            );
            println!(
                "    Hint: Run git with TZ=UTC, or install a newer OpenSSH (10.2p1 reads it correctly)"
            );
            warnings += 1;
        }
        agent_sign::cert_times::Reading::Unknown(why) => {
            println!(
                "  \x1b[33m⚠\x1b[0m Couldn't check whether git here reads certificate times correctly: {why}"
            );
            println!(
                "    Hint: Make sure ssh-keygen (OpenSSH) is on PATH; `agent-sign verify` needs it too"
            );
            warnings += 1;
        }
    }

    // 5. Check Daemon Connection
    let socket_path = client_socket_path();

    let ping_req = Request::Ping;
    match send_request(&socket_path, &ping_req) {
        Ok(Response::Pong) => {
            // `ping: ok` is a contract: the sitting waits for these words.
            println!(
                "  \x1b[32m✓\x1b[0m ping: ok (the service at {} answers)",
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
            println!("    Hint: Start the service with `agent-signd`");
            failures += 1;
        }
    }

    // 5b. System mode: whether OpenBao's certificate authority is the one
    // the root-owned trust file holds (docs/system-mode.md, section 5). The
    // line `authority: OpenBao CA matches the trust file` is a contract the
    // sitting waits for, printed only after the comparison succeeds.
    match system_authority_check() {
        None => {}
        Some(Ok(trust_file)) => {
            println!(
                "  \x1b[32m✓\x1b[0m authority: OpenBao CA matches the trust file ({trust_file})"
            );
            passes += 1;
        }
        Some(Err(why)) => {
            println!("  \x1b[31m✗\x1b[0m authority: {why}");
            failures += 1;
        }
    }

    // Leases from an earlier version that cover more than one repository.
    if let Ok(Response::LeaseList { leases }) = send_request(&socket_path, &Request::ListLeases)
        && let Some(note) = agent_sign::protocol::wide_leases_note(&leases)
    {
        println!("  \x1b[33m⚠\x1b[0m {note}");
        warnings += 1;
    }

    // 6. GitHub: it doesn't check signatures made with SSH certificates, so
    // agents' commits show there as unverified. Earlier versions suggested
    // adding the shared agent key to the person's GitHub account, which made
    // agent commits look like the person's: that key is no longer used.

    // 7. Check Directory Permissions & Lease Persistence Storage
    let agent_dir = agent_sign::paths::state_dir();
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
            "\x1b[1;33m{} passed, {} warning(s). agent-sign is usable.\x1b[0m\n",
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
