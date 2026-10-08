//! `agent-commitsd`: the agent-commits service (formerly `agent-signd`).
//!
//! One per user. It holds the agent signing key and the leases, answers the
//! wrapper, the signing program, and the CLI over a Unix socket in the state
//! directory, and asks the person to approve new leases. `agent-signd` can be a
//! link to this program; the LaunchAgent and systemd unit installed by
//! agent-sign start it by that name.

use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, IsTerminal, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine;
use clap::{Parser, Subcommand};

use agent_commits::config::Config;
use agent_commits::crypto::AgentKeyPair;
use agent_commits::lease::{LeaseEngine, LeasePolicy};
use agent_commits::protocol::{Request, Response, default_socket_path, send_response};

#[derive(Parser)]
#[command(
    name = "agent-commitsd",
    version = "0.1.0",
    about = "agent-commits service: holds the agent signing key and leases (formerly agent-signd)"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    #[arg(long, help = "Path to Unix socket")]
    socket: Option<PathBuf>,

    #[arg(long, help = "Path to custom configuration TOML file")]
    config: Option<PathBuf>,

    #[arg(long, help = "Allow autonomous commits on main/master branches")]
    allow_main: bool,

    #[arg(
        long,
        help = "Auto-approve lease requests (for testing and non-interactive CI)"
    )]
    auto_approve: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize keys and setup directory structure
    Setup,
    /// Query status of active daemon
    Status,
    /// Run daemon in foreground
    Run,
    /// Move ~/.agent-sign to ~/.agent-commits (leaving a link) and report what was done.
    /// `run` and `setup` do this automatically on start.
    Migrate,
}

struct DaemonState {
    lease_engine: LeaseEngine,
    keypair: AgentKeyPair,
    _config: Config,
    valid_tokens: HashMap<String, Instant>,
    auto_approve: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Setup) => {
            migrate_on_start()?;
            run_setup()
        }
        Some(Commands::Status) => run_status(cli.socket.as_deref()),
        Some(Commands::Migrate) => {
            migrate_on_start()?;
            Ok(())
        }
        Some(Commands::Run) | None => {
            migrate_on_start()?;
            run_daemon(
                cli.socket.as_deref(),
                cli.config.as_deref(),
                cli.allow_main,
                cli.auto_approve,
            )
        }
    }
}

/// Moves an agent-sign home to `~/.agent-commits` before anything reads or creates
/// state, so an upgrade needs no action from the person.
///
/// A conflict (both directories hold state) stops the service: carrying on
/// could mean signing with a different key than the one GitHub and
/// `allowed_signers` know. Any other failure is reported and the service
/// carries on with whichever directory `agent_commits::paths::state_dir` finds, which
/// is the old one when the move was undone.
fn migrate_on_start() -> Result<(), Box<dyn std::error::Error>> {
    use agent_commits::migrate::{MigrationError, MigrationOutcome, migrate_state_dir};

    match migrate_state_dir(&agent_commits::paths::home_dir()) {
        Ok(MigrationOutcome::NothingToMigrate) | Ok(MigrationOutcome::AlreadyMigrated) => {}
        Ok(outcome) => eprintln!("[agent-commitsd] {}", outcome),
        Err(e @ (MigrationError::Conflict { .. } | MigrationError::NotADirectory { .. })) => {
            eprintln!("[agent-commitsd] Refusing to start: {}", e);
            return Err(Box::new(e));
        }
        Err(e) => eprintln!(
            "[agent-commitsd] Migration to ~/.agent-commits did not complete: {} (using {})",
            e,
            get_state_dir().display()
        ),
    }
    Ok(())
}

/// The state directory: `~/.agent-commits`, or `~/.agent-sign` if it has not been
/// migrated (see `agent_commits::paths::state_dir_in`).
fn get_state_dir() -> PathBuf {
    agent_commits::paths::state_dir()
}

fn run_setup() -> Result<(), Box<dyn std::error::Error>> {
    let base_dir = get_state_dir();
    let keys_dir = base_dir.join("keys");
    fs::create_dir_all(&keys_dir)?;

    // Set 0700 permissions
    fs::set_permissions(&base_dir, fs::Permissions::from_mode(0o700))?;
    fs::set_permissions(&keys_dir, fs::Permissions::from_mode(0o700))?;

    let priv_key_path = keys_dir.join("agent_ed25519");
    let pub_key_path = keys_dir.join("agent_ed25519.pub");

    let keypair = if priv_key_path.exists() {
        println!("Existing private key found at: {}", priv_key_path.display());
        let bytes = fs::read(&priv_key_path)?;
        AgentKeyPair::from_bytes(&bytes)?
    } else {
        println!("Generating new Ed25519 agent signing keypair...");
        let seed = rand::random::<[u8; 32]>();
        let kp = AgentKeyPair::from_bytes(&seed)?;
        fs::write(&priv_key_path, seed)?;
        fs::set_permissions(&priv_key_path, fs::Permissions::from_mode(0o600))?;
        fs::write(&pub_key_path, kp.public_key_openssh())?;
        kp
    };

    println!("\n========================================================");
    println!(" agent-commits Setup Complete");
    println!("========================================================");
    println!("Private Key: {}", priv_key_path.display());
    println!("Public Key:  {}", pub_key_path.display());
    println!(
        "\nAdd this SSH Signing Key to GitHub (Settings -> SSH Keys -> New Key -> Key Type: Signing Key):"
    );
    println!("\n  {}\n", keypair.public_key_openssh());
    println!("========================================================");

    Ok(())
}

fn run_status(custom_socket: Option<&Path>) -> Result<(), Box<dyn std::error::Error>> {
    let socket_path = custom_socket
        .map(PathBuf::from)
        .unwrap_or_else(default_socket_path);
    if !socket_path.exists() {
        println!(
            "Daemon is not running (socket not found at {})",
            socket_path.display()
        );
        return Ok(());
    }

    match agent_commits::protocol::send_request(&socket_path, &Request::Ping)? {
        Response::Pong => println!(
            "Daemon is active and healthy (socket: {})",
            socket_path.display()
        ),
        other => println!("Unexpected daemon response: {:?}", other),
    }

    if let Ok(Response::LeaseList { leases }) =
        agent_commits::protocol::send_request(&socket_path, &Request::ListLeases)
    {
        if leases.is_empty() {
            println!("Active Leases: None");
        } else {
            println!("\nActive Leases ({}):", leases.len());
            for lease in leases {
                let exp_str = match lease.expires_in_secs {
                    Some(s) => format!("expires in {}s", s),
                    None => "when revoked".to_string(),
                };
                println!(
                    "  - [{}] {} ({}) - {} commits [{}]",
                    lease.mode, lease.repo, lease.branch, lease.commit_count, exp_str
                );
            }
        }
    }

    Ok(())
}

fn run_daemon(
    custom_socket: Option<&Path>,
    custom_config: Option<&Path>,
    allow_main: bool,
    auto_approve: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Read and check the config before touching the key or the socket, so a
    // bad value stops the service without disturbing a running one.
    let mut config = if let Some(cfg_path) = custom_config {
        Config::load_from_file(cfg_path)?
    } else {
        Config::load(None)
    };
    let max_ceiling = config.security.max_ceiling_duration()?;
    if config.security.lease_mode == agent_commits::config::LeaseMode::Process {
        eprintln!(
            "[agent-commitsd] lease_mode = \"process\" is not tied to a process yet: leases end after default_lease_duration ({}), as in \"timed\" mode.",
            config.security.default_lease_duration
        );
    }

    let base_dir = get_state_dir();
    let keys_dir = base_dir.join("keys");
    fs::create_dir_all(&keys_dir)?;

    let priv_key_path = keys_dir.join("agent_ed25519");
    let pub_key_path = keys_dir.join("agent_ed25519.pub");
    let keypair = if priv_key_path.exists() {
        let bytes = fs::read(&priv_key_path)?;
        AgentKeyPair::from_bytes(&bytes)?
    } else {
        let seed = rand::random::<[u8; 32]>();
        let kp = AgentKeyPair::from_bytes(&seed)?;
        fs::write(&priv_key_path, seed)?;
        fs::set_permissions(&priv_key_path, fs::Permissions::from_mode(0o600))?;
        fs::write(&pub_key_path, kp.public_key_openssh())?;
        kp
    };

    let socket_path = custom_socket
        .map(PathBuf::from)
        .unwrap_or_else(default_socket_path);

    // Remove old stale socket
    if socket_path.exists() {
        let _ = fs::remove_file(&socket_path);
    }

    if let Some(parent) = socket_path.parent() {
        fs::create_dir_all(parent)?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    }

    if allow_main {
        config.security.allow_main_branch = true;
    }

    let effective_auto_approve = auto_approve || config.security.auto_approve;

    let storage_path = socket_path.parent().map(|p| p.join("leases.json"));
    let policy = LeasePolicy {
        mode: config.security.lease_mode,
        scope: config.security.lease_scope,
        default_ttl: config.security.lease_duration(),
        max_ceiling,
        block_branches: config.security.block_branches.clone(),
        allow_main_branch: config.security.allow_main_branch,
        allow_branch_switching: config.security.allow_branch_switching,
        max_commits_per_minute: config.security.max_commits_per_minute,
    };

    let state = Arc::new(Mutex::new(DaemonState {
        lease_engine: LeaseEngine::new_with_storage(policy, storage_path),
        keypair,
        _config: config,
        valid_tokens: HashMap::new(),
        auto_approve: effective_auto_approve,
    }));

    let listener = UnixListener::bind(&socket_path)?;
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;

    println!("agent-commitsd running on {}", socket_path.display());

    for stream in listener.incoming() {
        match stream {
            Ok(mut s) => {
                let state_clone = Arc::clone(&state);
                std::thread::spawn(move || {
                    handle_client(&mut s, state_clone);
                });
            }
            Err(e) => {
                eprintln!("Socket accept error: {}", e);
            }
        }
    }

    Ok(())
}

fn handle_client(stream: &mut UnixStream, state: Arc<Mutex<DaemonState>>) {
    let reader_stream = match stream.try_clone() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to clone stream: {}", e);
            return;
        }
    };
    let mut reader = BufReader::new(reader_stream);
    let mut line = String::new();

    if reader.read_line(&mut line).is_err() || line.trim().is_empty() {
        return;
    }

    let request: Request = match serde_json::from_str(&line) {
        Ok(req) => req,
        Err(e) => {
            let _ = send_response(
                stream,
                &Response::Error {
                    message: e.to_string(),
                },
            );
            return;
        }
    };

    let response = match request {
        Request::Ping => Response::Pong,
        Request::RequestLease {
            repo,
            branch,
            intent,
            duration_secs: _,
        } => {
            // Check active lease state without holding lock across UI dialog
            let (
                blocked,
                has_lease,
                same_branch,
                follows,
                lease_id,
                lease_exp,
                auto_approve_val,
                terms,
            ) = {
                let st = state.lock().unwrap();
                let auto = st.auto_approve;
                let mode = st.lease_engine.policy.describe_terms(&branch);
                let blocked = st.lease_engine.is_branch_blocked(&branch);
                if let Some(lease) = st.lease_engine.get_active_lease(&repo) {
                    (
                        blocked,
                        true,
                        st.lease_engine.lease_covers(lease, &branch),
                        st.lease_engine.covers_every_branch(lease),
                        Some(lease.id.clone()),
                        st.lease_engine.effective_end(lease),
                        auto,
                        mode,
                    )
                } else {
                    (blocked, false, false, false, None, None, auto, mode)
                }
            };

            if blocked {
                // No lease ever covers a protected branch, so don't ask the
                // person for one only to refuse it afterwards.
                Response::Error {
                    message: format!(
                        "Branch '{}' is protected: agents can't commit there unless the person allows it, so no lease was asked for",
                        branch
                    ),
                }
            } else if has_lease {
                if same_branch {
                    Response::LeaseGranted {
                        lease_id: lease_id.unwrap_or_else(|| "active".to_string()),
                        expires_at_secs: lease_exp.unwrap_or(u64::MAX),
                    }
                } else {
                    // The agent is on another branch. Follow it only if the
                    // lease was approved (and is still allowed) to cover every
                    // unprotected branch; otherwise ask again.
                    let mut st = state.lock().unwrap();
                    if follows {
                        match st.lease_engine.switch_branch(&repo, &branch) {
                            Ok(updated) => Response::LeaseGranted {
                                expires_at_secs: st
                                    .lease_engine
                                    .effective_end(&updated)
                                    .unwrap_or(u64::MAX),
                                lease_id: updated.id,
                            },
                            Err(e) => Response::Error { message: e },
                        }
                    } else {
                        drop(st); // Release lock before prompting
                        let approval = if auto_approve_val {
                            Approval::Approved
                        } else {
                            request_human_approval(&repo, &branch, &intent, &terms)
                        };

                        if let Some(message) = approval.refusal() {
                            Response::Error { message }
                        } else {
                            let mut st = state.lock().unwrap();
                            match st.lease_engine.try_grant_lease(&repo, &branch, &intent) {
                                Ok(lease) => Response::LeaseGranted {
                                    lease_id: lease.id,
                                    expires_at_secs: lease.expires_at_secs.unwrap_or(u64::MAX),
                                },
                                Err(e) => Response::Error { message: e },
                            }
                        }
                    }
                }
            } else {
                // No active lease: prompt human for approval outside the lock
                let approval = if auto_approve_val {
                    Approval::Approved
                } else {
                    request_human_approval(&repo, &branch, &intent, &terms)
                };

                if let Some(message) = approval.refusal() {
                    Response::Error { message }
                } else {
                    let mut st = state.lock().unwrap();
                    match st.lease_engine.try_grant_lease(&repo, &branch, &intent) {
                        Ok(lease) => Response::LeaseGranted {
                            lease_id: lease.id,
                            expires_at_secs: lease.expires_at_secs.unwrap_or(u64::MAX),
                        },
                        Err(e) => Response::Error { message: e },
                    }
                }
            }
        }
        Request::IssueToken { repo, branch } => {
            let mut st = state.lock().unwrap();
            // Prune expired tokens (> 60s)
            let now = Instant::now();
            st.valid_tokens
                .retain(|_, created_at| now.duration_since(*created_at) < Duration::from_secs(60));

            match st.lease_engine.issue_commit_token(&repo, &branch) {
                Ok(tok) => {
                    st.valid_tokens.insert(tok.clone(), now);
                    Response::TokenIssued { token: tok }
                }
                Err(e) => Response::Error { message: e },
            }
        }
        Request::SignCommit { token, buffer_b64 } => {
            let mut st = state.lock().unwrap();
            let now = Instant::now();
            st.valid_tokens
                .retain(|_, created_at| now.duration_since(*created_at) < Duration::from_secs(60));

            if st.valid_tokens.remove(&token).is_none() {
                Response::Error {
                    message: "Invalid, expired, or already consumed AGENT_EVENT_TOKEN".to_string(),
                }
            } else {
                match base64::engine::general_purpose::STANDARD.decode(buffer_b64) {
                    Ok(buffer) => {
                        let signature = st.keypair.sign_git_buffer(&buffer);
                        Response::Signed {
                            signature_pem: signature.to_armored_pem(),
                        }
                    }
                    Err(e) => Response::Error {
                        message: format!("Base64 decode error: {}", e),
                    },
                }
            }
        }
        Request::GetStatus { repo } => {
            let st = state.lock().unwrap();
            let (active, lease_id, branch, expires_in_secs) = st.lease_engine.get_status(&repo);
            Response::Status {
                active,
                lease_id,
                branch,
                expires_in_secs,
            }
        }
        Request::ListLeases => {
            let st = state.lock().unwrap();
            let leases = st.lease_engine.list_leases();
            Response::LeaseList { leases }
        }
        Request::RevokeLease {
            repo,
            branch: _,
            all,
        } => {
            let mut st = state.lock().unwrap();
            if all {
                st.lease_engine.revoke_all();
                Response::Success
            } else if st.lease_engine.revoke_lease(&repo) {
                Response::Success
            } else {
                // Saying "revoked" here would leave the person believing
                // access had ended when nothing matched.
                Response::Error {
                    message: format!(
                        "no lease for '{}': give the repository's full path, as `agent-commits leases` shows it",
                        repo
                    ),
                }
            }
        }
    };

    let _ = send_response(stream, &response);
}

/// The person's answer to a lease request, or that there was no way to ask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Approval {
    Approved,
    Denied,
    /// No dialog could be shown and the service has no terminal: nobody was
    /// asked, so the lease is refused (failing closed).
    NoWayToAsk,
}

impl Approval {
    /// The error to send back for a refusal, or `None` if approved. The two
    /// refusals are worded differently so that a headless machine doesn't
    /// report that the person said no.
    fn refusal(self) -> Option<String> {
        match self {
            Approval::Approved => None,
            Approval::Denied => Some("the person denied the signing lease".to_string()),
            Approval::NoWayToAsk => Some(NO_WAY_TO_ASK.to_string()),
        }
    }
}

/// Sent back when the service couldn't ask the person, so the agent (and the
/// person reading its output) learns why and what to do.
const NO_WAY_TO_ASK: &str = "agent-commits couldn't ask you to approve a lease: there is no desktop session for a dialog, and the service has no terminal. On a machine without a screen, see \"Headless machines\" in docs/INSTALL.md";

/// Asks the person to approve a lease, showing its fixed terms. The
/// repository, branch, and reason come from the agent's request and are
/// labelled as such.
fn request_human_approval(
    repo: &str,
    branch: &str,
    intent: &str,
    terms: &agent_commits::lease::TermsText,
) -> Approval {
    let prompt_text = format!(
        "An AI agent asks to sign git commits as the agent without asking you again.\n\nRepository: {}\nBranch now: {}\nCovers: {}\nEnds: {}\nReason given by the agent: {}\n\nThese terms are fixed when you approve. They never grow.",
        repo, branch, terms.covers, terms.ends, intent
    );

    // 1. If on macOS, attempt desktop dialog via osascript
    #[cfg(target_os = "macos")]
    {
        let script = format!(
            "display dialog \"{}\" with title \"agent-commits Security Lease\" buttons {{\"Deny\", \"Approve\"}} default button \"Approve\" with icon caution",
            prompt_text.replace('"', "\\\"")
        );

        if let Ok(output) = Command::new("osascript").arg("-e").arg(&script).output() {
            let res = String::from_utf8_lossy(&output.stdout);
            if res.contains("button returned:Approve") {
                return Approval::Approved;
            }
            if res.contains("button returned:Deny") {
                return Approval::Denied;
            }
        }
    }

    // 2. If on Linux with active graphical session (X11 / Wayland)
    #[cfg(target_os = "linux")]
    {
        if std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some() {
            if let Ok(output) = Command::new("zenity")
                .args([
                    "--question",
                    "--title=agent-commits Security Lease",
                    &format!("--text={}", prompt_text),
                ])
                .output()
            {
                // zenity exits 0 for Yes and 1 for No or a closed window; any
                // other failure (no display, say) falls through to the
                // terminal, as before.
                match output.status.code() {
                    Some(0) => return Approval::Approved,
                    Some(1) => return Approval::Denied,
                    _ => {}
                }
            } else if let Ok(output) = Command::new("kdialog")
                .args([
                    "--title",
                    "agent-commits Security Lease",
                    "--yesno",
                    &prompt_text,
                ])
                .output()
            {
                return if output.status.success() {
                    Approval::Approved
                } else {
                    Approval::Denied
                };
            }
        }
    }

    // 3. Fallback to interactive terminal prompt if stdin is a TTY
    if std::io::stdin().is_terminal() {
        eprintln!("\n========================================================");
        eprintln!(" 🔏 agent-commits Security Lease Request");
        eprintln!("========================================================");
        eprintln!("Repository: {}", repo);
        eprintln!("Branch now: {}", branch);
        eprintln!("Covers:     {}", terms.covers);
        eprintln!("Ends:       {}", terms.ends);
        eprintln!("Reason given by the agent: {}", intent);
        eprintln!("========================================================");
        eprintln!("These terms are fixed when you approve. They never grow.");
        eprint!("Approve this lease? [y/N]: ");
        let _ = std::io::stderr().flush();

        let mut input = String::new();
        if std::io::stdin().read_line(&mut input).is_ok() {
            let trimmed = input.trim().to_lowercase();
            return if trimmed == "y" || trimmed == "yes" {
                Approval::Approved
            } else {
                Approval::Denied
            };
        }
    }

    eprintln!("[agent-commitsd] No interactive approval backend available; signing lease denied.");
    eprintln!(
        "[agent-commitsd] Hint: In headless environments, containers, or CI, run with --auto-approve or AGENT_COMMITS_AUTO_APPROVE=1 (AGENT_SIGN_AUTO_APPROVE=1 also works)"
    );
    Approval::NoWayToAsk
}
