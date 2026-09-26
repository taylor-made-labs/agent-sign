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
use agent_sign::lease::{LeaseEngine, LeasePolicy};
use agent_sign::protocol::{Request, Response, default_socket_path, send_response};

#[derive(Parser)]
#[command(
    name = "agent-signd",
    version = "0.1.0",
    about = "Agent-Sign Daemon & Credential Manager"
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

fn get_agent_sign_dir() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".agent-sign")
}

fn run_setup() -> Result<(), Box<dyn std::error::Error>> {
    let base_dir = get_agent_sign_dir();
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
    println!(" Agent-Sign Setup Complete");
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

    Ok(())
}

fn run_daemon(
    custom_socket: Option<&Path>,
    custom_config: Option<&Path>,
    allow_main: bool,
    auto_approve: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let base_dir = get_agent_sign_dir();
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

    let mut config = if let Some(cfg_path) = custom_config {
        Config::load_from_file(cfg_path)?
    } else {
        Config::load(None)
    };

    if allow_main {
        config.security.allow_main_branch = true;
    }

    let effective_auto_approve = auto_approve || config.security.auto_approve;

    let policy = LeasePolicy {
        default_ttl: config.security.lease_duration(),
        block_branches: config.security.block_branches.clone(),
        allow_main_branch: config.security.allow_main_branch,
        allow_branch_switching: config.security.allow_branch_switching,
        max_commits_per_minute: config.security.max_commits_per_minute,
    };

    let state = Arc::new(Mutex::new(DaemonState {
        lease_engine: LeaseEngine::new(policy),
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
            duration_secs,
        } => {
            // Check active lease state without holding lock across UI dialog
            let (has_lease, same_branch, lease_id, auto_approve_val) = {
                let st = state.lock().unwrap();
                let auto = st.auto_approve;
                if let Some(lease) = st.lease_engine.get_active_lease(&repo) {
                    (true, lease.branch == branch, Some(lease.id.clone()), auto)
                } else {
                    (false, false, None, auto)
                }
            };

            if has_lease {
                if same_branch {
                    Response::LeaseGranted {
                        lease_id: lease_id.unwrap_or_else(|| "active".to_string()),
                        expires_at_secs: duration_secs.unwrap_or(7200),
                    }
                } else {
                    // Branch has switched! Check if policy allows branch switching
                    let mut st = state.lock().unwrap();
                    if st.lease_engine.policy.allow_branch_switching {
                        match st.lease_engine.switch_branch(&repo, &branch) {
                            Ok(updated) => Response::LeaseGranted {
                                lease_id: updated.id,
                                expires_at_secs: duration_secs.unwrap_or(7200),
                            },
                            Err(e) => Response::Error { message: e },
                        }
                    } else {
                        drop(st); // Release lock before prompting
                        let approved = if auto_approve_val {
                            true
                        } else {
                            request_human_approval(&repo, &branch, &intent)
                        };

                        if !approved {
                            Response::Error {
                                message: "Human rejected the signing lease request for new branch"
                                    .to_string(),
                            }
                        } else {
                            let mut st = state.lock().unwrap();
                            match st.lease_engine.try_grant_lease(&repo, &branch, &intent) {
                                Ok(lease) => Response::LeaseGranted {
                                    lease_id: lease.id,
                                    expires_at_secs: duration_secs.unwrap_or(7200),
                                },
                                Err(e) => Response::Error { message: e },
                            }
                        }
                    }
                }
            } else {
                // No active lease: prompt human for approval outside the lock
                let approved = if auto_approve_val {
                    true
                } else {
                    request_human_approval(&repo, &branch, &intent)
                };

                if !approved {
                    Response::Error {
                        message: "Human rejected the signing lease request".to_string(),
                    }
                } else {
                    let mut st = state.lock().unwrap();
                    match st.lease_engine.try_grant_lease(&repo, &branch, &intent) {
                        Ok(lease) => Response::LeaseGranted {
                            lease_id: lease.id,
                            expires_at_secs: duration_secs.unwrap_or(7200),
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
        Request::RevokeLease { repo } => {
            let mut st = state.lock().unwrap();
            st.lease_engine.revoke_lease(&repo);
            Response::Success
        }
    };

    let _ = send_response(stream, &response);
}

fn request_human_approval(repo: &str, branch: &str, intent: &str) -> bool {
    let prompt_text = format!(
        "AI Agent is requesting a Git Commit Signing Lease.\n\nRepository: {}\nBranch: {}\nIntent: {}\n\nApprove autonomous signing for this session?",
        repo, branch, intent
    );

    // 1. If on macOS, attempt desktop dialog via osascript
    #[cfg(target_os = "macos")]
    {
        let script = format!(
            "display dialog \"{}\" with title \"Agent-Sign Security Lease\" buttons {{\"Deny\", \"Approve\"}} default button \"Approve\" with icon caution",
            prompt_text.replace('"', "\\\"")
        );

        if let Ok(output) = Command::new("osascript").arg("-e").arg(&script).output() {
            let res = String::from_utf8_lossy(&output.stdout);
            if res.contains("button returned:Approve") {
                return true;
            }
            if res.contains("button returned:Deny") {
                return false;
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
                    "--title=Agent-Sign Security Lease",
                    &format!("--text={}", prompt_text),
                ])
                .output()
            {
                if output.status.success() {
                    return true;
                }
            } else if let Ok(output) = Command::new("kdialog")
                .args([
                    "--title",
                    "Agent-Sign Security Lease",
                    "--yesno",
                    &prompt_text,
                ])
                .output()
            {
                if output.status.success() {
                    return true;
                }
            }
        }
    }

    // 3. Fallback to interactive terminal prompt if stdin is a TTY
    if std::io::stdin().is_terminal() {
        eprintln!("\n========================================================");
        eprintln!(" 🔏 Agent-Sign Security Lease Request");
        eprintln!("========================================================");
        eprintln!("Repository: {}", repo);
        eprintln!("Branch:     {}", branch);
        eprintln!("Intent:     {}", intent);
        eprintln!("========================================================");
        eprint!("Approve autonomous signing lease for this session? [y/N]: ");
        let _ = std::io::stderr().flush();

        let mut input = String::new();
        if std::io::stdin().read_line(&mut input).is_ok() {
            let trimmed = input.trim().to_lowercase();
            return trimmed == "y" || trimmed == "yes";
        }
    }

    eprintln!("[agent-signd] No interactive approval backend available; signing lease denied.");
    eprintln!(
        "[agent-signd] Hint: In headless environments, containers, or CI, run with --auto-approve or AGENT_SIGN_AUTO_APPROVE=1"
    );
    false
}
