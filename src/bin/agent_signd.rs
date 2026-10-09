//! `agent-signd`: the agent-sign service.
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

use agent_sign::config::Config;
use agent_sign::crypto::AgentKeyPair;
use agent_sign::lease::{Coverage, LeaseEngine, LeasePolicy};
use agent_sign::protocol::{Request, Response, default_socket_path, send_response};

#[derive(Parser)]
#[command(
    name = "agent-signd",
    version = "0.1.0",
    about = "agent-sign service: holds the agent signing key and leases"
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
        Some(Commands::Setup) => run_setup(),
        Some(Commands::Status) => run_status(cli.socket.as_deref()),
        Some(Commands::Run) | None => run_daemon(
            cli.socket.as_deref(),
            cli.config.as_deref(),
            cli.allow_main,
            cli.auto_approve,
        ),
    }
}

/// The state directory, `~/.agent-sign` (see `agent_sign::paths`).
fn get_state_dir() -> PathBuf {
    agent_sign::paths::state_dir()
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
    println!(" agent-sign Setup Complete");
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

    match agent_sign::protocol::send_request(&socket_path, &Request::Ping)? {
        Response::Pong => println!(
            "Daemon is active and healthy (socket: {})",
            socket_path.display()
        ),
        other => println!("Unexpected daemon response: {:?}", other),
    }

    if let Ok(Response::LeaseList { leases }) =
        agent_sign::protocol::send_request(&socket_path, &Request::ListLeases)
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
    if config.security.lease_mode == agent_sign::config::LeaseMode::Process {
        eprintln!(
            "[agent-signd] lease_mode = \"process\" is not tied to a process yet: leases end after default_lease_duration ({}), as in \"timed\" mode.",
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

    println!("agent-signd running on {}", socket_path.display());

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
            let (blocked, covering, can_follow, auto_approve_val, terms, choices) = {
                let st = state.lock().unwrap();
                let engine = &st.lease_engine;
                let covering = engine
                    .find_lease(&repo, &branch)
                    .map(|lease| (lease.id.clone(), engine.effective_end(lease)));
                // A lease for this repository alone, approved to follow the
                // agent across branches, moves to the branch it's on now.
                let can_follow = engine.get_active_lease(&repo).is_some_and(|lease| {
                    lease.coverage == Coverage::Repository && engine.covers_every_branch(lease)
                });
                (
                    engine.is_branch_blocked(&branch),
                    covering,
                    can_follow,
                    st.auto_approve,
                    engine.policy.describe_terms(&branch),
                    engine.policy.scope_choices(&repo),
                )
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
            } else if let Some((lease_id, lease_exp)) = covering {
                Response::LeaseGranted {
                    lease_id,
                    expires_at_secs: lease_exp.unwrap_or(u64::MAX),
                }
            } else if can_follow {
                let mut st = state.lock().unwrap();
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
                // Nothing covers this commit: ask the person, outside the lock.
                // Unattended approval only ever grants this repository.
                let approval = if auto_approve_val {
                    Approval::Approved(Coverage::Repository)
                } else {
                    request_human_approval(&repo, &branch, &intent, &terms, &choices)
                };

                match approval {
                    Approval::Approved(coverage) => {
                        let mut st = state.lock().unwrap();
                        match st
                            .lease_engine
                            .try_grant_lease_covering(&repo, &branch, &intent, coverage)
                        {
                            Ok(lease) => Response::LeaseGranted {
                                lease_id: lease.id,
                                expires_at_secs: lease.expires_at_secs.unwrap_or(u64::MAX),
                            },
                            Err(e) => Response::Error { message: e },
                        }
                    }
                    refused => Response::Error {
                        message: refused.refusal().unwrap_or_default(),
                    },
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
                        "no lease for '{}': give the repository's or folder's full path, or `everywhere`, as `agent-sign leases` shows it",
                        repo
                    ),
                }
            }
        }
    };

    let _ = send_response(stream, &response);
}

/// The person's answer to a lease request, or that there was no way to ask.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Approval {
    /// Approved, covering what the person chose.
    Approved(Coverage),
    Denied,
    /// No dialog could be shown and the service has no terminal: nobody was
    /// asked, so the lease is refused (failing closed).
    NoWayToAsk,
}

impl Approval {
    /// The error to send back for a refusal, or `None` if approved. The two
    /// refusals are worded differently so that a headless machine doesn't
    /// report that the person said no.
    fn refusal(&self) -> Option<String> {
        match self {
            Approval::Approved(_) => None,
            Approval::Denied => Some("the person denied the signing lease".to_string()),
            Approval::NoWayToAsk => Some(NO_WAY_TO_ASK.to_string()),
        }
    }

    /// Reads a dialog's answer: the label of one of the choices offered is
    /// approval of that coverage; anything else is a denial, so an answer
    /// that can't be matched never approves more than was shown.
    fn from_answer(answer: &str, choices: &[(Coverage, String)]) -> Approval {
        let answer = answer.trim();
        choices
            .iter()
            .find(|(_, label)| label == answer)
            .map_or(Approval::Denied, |(coverage, _)| {
                Approval::Approved(coverage.clone())
            })
    }
}

/// Sent back when the service couldn't ask the person, so the agent (and the
/// person reading its output) learns why and what to do.
const NO_WAY_TO_ASK: &str = "agent-sign couldn't ask you to approve a lease: there is no desktop session for a dialog, and the service has no terminal. On a machine without a screen, see \"Headless machines\" in docs/INSTALL.md";

/// A string as an AppleScript string literal.
#[cfg(target_os = "macos")]
fn applescript_string(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// Asks the person to approve a lease, showing its fixed terms and letting
/// them choose what it covers (`choices`, the first being the default).
/// The repository, branch, and reason come from the agent's request and are
/// labelled as such. It's one dialog with the narrowest choice preselected,
/// so approving takes one click, as before scopes existed.
fn request_human_approval(
    repo: &str,
    branch: &str,
    intent: &str,
    terms: &agent_sign::lease::TermsText,
    choices: &[(Coverage, String)],
) -> Approval {
    let prompt_text = format!(
        "An AI agent asks to sign git commits as the agent without asking you again.\n\nRepository: {}\nBranch now: {}\nBranches: {}\nEnds: {}\nReason given by the agent: {}\n\nChoose what this approval covers. These terms are fixed when you approve. They never grow.",
        repo, branch, terms.covers, terms.ends, intent
    );
    let labels: Vec<&str> = choices.iter().map(|(_, l)| l.as_str()).collect();

    // 1. If on macOS, a list dialog: Approve with a choice selected, or Deny
    // (which answers "false").
    #[cfg(target_os = "macos")]
    {
        let items: Vec<String> = labels.iter().map(|l| applescript_string(l)).collect();
        let script = format!(
            "choose from list {{{}}} with title \"agent-sign\" with prompt {} default items {{{}}} OK button name \"Approve\" cancel button name \"Deny\"",
            items.join(", "),
            applescript_string(&prompt_text),
            items[0]
        );

        if let Ok(output) = Command::new("osascript").arg("-e").arg(&script).output() {
            let res = String::from_utf8_lossy(&output.stdout);
            // Any answer is the person's; an empty one with a failure means
            // no dialog could be shown, so try the next way to ask.
            if !res.trim().is_empty() || output.status.success() {
                return Approval::from_answer(&res, choices);
            }
        }
    }

    // 2. If on Linux with active graphical session (X11 / Wayland)
    #[cfg(target_os = "linux")]
    {
        if std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some() {
            let mut zenity_args = vec![
                "--list".to_string(),
                "--radiolist".to_string(),
                "--title=agent-sign".to_string(),
                format!("--text={}", prompt_text),
                "--column= ".to_string(),
                "--column=Covers".to_string(),
                "--ok-label=Approve".to_string(),
                "--cancel-label=Deny".to_string(),
                "--width=640".to_string(),
                "--height=420".to_string(),
            ];
            for (i, label) in labels.iter().enumerate() {
                zenity_args.push(if i == 0 { "TRUE" } else { "FALSE" }.to_string());
                zenity_args.push(label.to_string());
            }
            if let Ok(output) = Command::new("zenity").args(&zenity_args).output() {
                // zenity exits 0 with the chosen label, and 1 for Deny or a
                // closed window; any other failure (no display, say) falls
                // through to the terminal, as before.
                match output.status.code() {
                    Some(0) => {
                        return Approval::from_answer(
                            &String::from_utf8_lossy(&output.stdout),
                            choices,
                        );
                    }
                    Some(1) => return Approval::Denied,
                    _ => {}
                }
            } else {
                let mut kdialog_args = vec![
                    "--title".to_string(),
                    "agent-sign".to_string(),
                    "--radiolist".to_string(),
                    prompt_text.clone(),
                ];
                for (i, label) in labels.iter().enumerate() {
                    kdialog_args.push((i + 1).to_string());
                    kdialog_args.push(label.to_string());
                    kdialog_args.push(if i == 0 { "on" } else { "off" }.to_string());
                }
                if let Ok(output) = Command::new("kdialog").args(&kdialog_args).output() {
                    // kdialog prints the chosen tag (the choice's number).
                    let tag = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    let chosen = tag
                        .parse::<usize>()
                        .ok()
                        .and_then(|n| n.checked_sub(1))
                        .and_then(|i| choices.get(i));
                    return match (output.status.success(), chosen) {
                        (true, Some((coverage, _))) => Approval::Approved(coverage.clone()),
                        _ => Approval::Denied,
                    };
                }
            }
        }
    }

    // 3. Fallback to interactive terminal prompt if stdin is a TTY
    if std::io::stdin().is_terminal() {
        eprintln!("\n========================================================");
        eprintln!(" 🔏 agent-sign approval request");
        eprintln!("========================================================");
        eprintln!("Repository: {}", repo);
        eprintln!("Branch now: {}", branch);
        eprintln!("Branches:   {}", terms.covers);
        eprintln!("Ends:       {}", terms.ends);
        eprintln!("Reason given by the agent: {}", intent);
        eprintln!("========================================================");
        eprintln!("These terms are fixed when you approve. They never grow.");
        for (i, label) in labels.iter().enumerate() {
            eprintln!("  {}) {}", i + 1, label);
        }
        eprint!(
            "Approve, covering which? [1-{}, y = 1, N = deny]: ",
            labels.len()
        );
        let _ = std::io::stderr().flush();

        let mut input = String::new();
        if std::io::stdin().read_line(&mut input).is_ok() {
            let trimmed = input.trim().to_lowercase();
            let index = match trimmed.as_str() {
                "y" | "yes" => Some(0),
                n => n.parse::<usize>().ok().and_then(|n| n.checked_sub(1)),
            };
            return match index.and_then(|i| choices.get(i)) {
                Some((coverage, _)) => Approval::Approved(coverage.clone()),
                None => Approval::Denied,
            };
        }
    }

    eprintln!("[agent-signd] No interactive approval backend available; signing lease denied.");
    eprintln!(
        "[agent-signd] Hint: In headless environments, containers, or CI, run with --auto-approve or AGENT_SIGN_AUTO_APPROVE=1 (AGENT_SIGN_AUTO_APPROVE=1 also works)"
    );
    Approval::NoWayToAsk
}
