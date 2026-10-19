//! `agent-signd`: the agent-sign service.
//!
//! One per user. It holds the agent signing key and the leases, answers the
//! wrapper, the signing program, and the CLI over a Unix socket in the state
//! directory, and asks the person to approve new leases. `agent-signd` can be a
//! link to this program; the LaunchAgent and systemd unit installed by
//! agent-sign start it by that name.

use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use base64::Engine;
use clap::{Parser, Subcommand};

use agent_sign::approval::{
    Approval, Asked, BranchReach, MAX_PENDING_REQUESTS, RefusalBackoff, auth_reason, confirm,
    has_unsafe_display_chars, platform_authenticator,
};
use agent_sign::config::Config;
use agent_sign::crypto::AgentKeyPair;
use agent_sign::lease::{Coverage, LeaseEngine, LeasePolicy};
use agent_sign::protocol::{PendingInfo, Request, Response, default_socket_path, send_response};

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
    /// Approval requests waiting for the person, one per repository and
    /// branch, keyed by `pending_key`.
    pending: HashMap<String, Arc<PendingAsk>>,
    /// Holds new requests back after a refused one (see `RefusalBackoff`).
    backoff: RefusalBackoff,
}

/// One approval request waiting for the person. Every commit asking for the
/// same repository and branch while it's open waits on this one answer, so
/// retries and parallel commits never open a second prompt.
struct PendingAsk {
    id: String,
    repo: String,
    branch: String,
    asked_at: Instant,
    /// Commits waiting on the answer. When the last one goes away (its
    /// program timed out or was stopped), the prompt is withdrawn.
    waiters: AtomicUsize,
    /// Set to close the prompt without an answer from it.
    cancel: AtomicBool,
    /// Set by `agent-sign deny`: the request is answered as denied.
    denied_by_command: AtomicBool,
    /// The response every waiting commit gets, once there is one.
    outcome: Mutex<Option<Response>>,
    done: Condvar,
}

fn pending_key(repo: &str, branch: &str) -> String {
    format!("{repo}\n{branch}")
}

/// Whether the client on `stream` has gone away (closed its end) while
/// waiting. A connection carries one request, already read, so a
/// non-blocking read finds either nothing yet ("would block": still there)
/// or the end of the stream (gone).
fn client_gone(stream: &UnixStream) -> bool {
    use std::io::Read;
    if stream.set_nonblocking(true).is_err() {
        return false;
    }
    let mut byte = [0u8; 1];
    let gone = match (&*stream).read(&mut byte) {
        Ok(0) => true,
        Ok(_) => false,
        Err(e) => e.kind() != std::io::ErrorKind::WouldBlock,
    };
    let _ = stream.set_nonblocking(false);
    gone
}

/// Waits for `ask`'s answer while checking that this commit's program is
/// still there. `None` when it has gone: if it was the last one waiting, the
/// prompt is withdrawn.
fn wait_for_answer(ask: &PendingAsk, stream: &UnixStream) -> Option<Response> {
    let mut outcome = ask.outcome.lock().unwrap();
    loop {
        if let Some(response) = outcome.as_ref() {
            return Some(response.clone());
        }
        let (guard, _) = ask
            .done
            .wait_timeout(outcome, Duration::from_millis(200))
            .unwrap();
        outcome = guard;
        if outcome.is_none() && client_gone(stream) {
            if ask.waiters.fetch_sub(1, Ordering::SeqCst) == 1 {
                ask.cancel.store(true, Ordering::SeqCst);
            }
            return None;
        }
    }
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
    let idle_limit = config.security.idle_limit_duration()?;
    let refusal_backoff = config.security.refusal_backoff_duration()?;
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
        idle_limit,
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
        pending: HashMap::new(),
        backoff: RefusalBackoff::new(refusal_backoff),
    }));

    // Leases that cover more than one repository can no longer be granted;
    // ones approved earlier still work, so say so in the log.
    if let Some(note) =
        agent_sign::protocol::wide_leases_note(&state.lock().unwrap().lease_engine.list_leases())
    {
        eprintln!("[agent-signd] {note}");
    }

    let listener = UnixListener::bind(&socket_path)?;
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;

    println!("agent-signd running on {}", socket_path.display());
    #[cfg(feature = "test-authenticator")]
    eprintln!(
        "[agent-signd] WARNING: this is a test build with a stand-in for the device owner (AGENT_SIGN_TEST_AUTH). It must never be installed."
    );

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
            // A lease is only ever for a real repository: an absolute path.
            // Anything else (an old wrapper's "default-repo" placeholder, an
            // empty or relative path) is refused before anyone is asked.
            if !Path::new(&repo).is_absolute() {
                let _ = send_response(
                    stream,
                    &Response::Error {
                        message: format!(
                            "couldn't identify the repository ('{}' isn't a full path), so no approval was asked for",
                            repo
                        ),
                    },
                );
                return;
            }
            // What the person is shown must be what the agent really asked
            // about: a path that exists and holds a git working tree, with
            // no control, invisible or direction-changing characters in it
            // or in the branch name. Refused before anyone is asked.
            if has_unsafe_display_chars(&repo) || has_unsafe_display_chars(&branch) {
                let _ = send_response(
                    stream,
                    &Response::Error {
                        message: "the repository path or branch name contains control or invisible characters, so no approval was asked for".to_string(),
                    },
                );
                return;
            }
            if !Path::new(&repo).join(".git").exists() {
                let _ = send_response(
                    stream,
                    &Response::Error {
                        message: format!(
                            "couldn't identify the repository ('{}' isn't an existing git working tree), so no approval was asked for",
                            repo
                        ),
                    },
                );
                return;
            }
            // Check active lease state without holding the lock across the prompt
            let (blocked, covering, can_follow, auto_approve_val, terms, reach, ends) = {
                let mut st = state.lock().unwrap();
                end_finished_work(&mut st);
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
                    engine.policy.branch_reach(&branch),
                    engine.policy.end_phrase(),
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
                if !auto_approve_val {
                    // The branch goes into the prompt's sentence, and the
                    // agent chose it: it must be a plain, valid branch name
                    // and the one the repository really has checked out.
                    if let Err(message) = check_asked_branch(&repo, &branch) {
                        let _ = send_response(stream, &Response::Error { message });
                        return;
                    }
                    let ask = match join_or_open_request(
                        &state, &repo, &branch, &intent, &terms, &reach, &ends,
                    ) {
                        Ok(ask) => ask,
                        Err(message) => {
                            let _ = send_response(stream, &Response::Error { message });
                            return;
                        }
                    };
                    // `None`: the commit's program is gone, so there's no one
                    // to answer.
                    if let Some(response) = wait_for_answer(&ask, stream) {
                        let _ = send_response(stream, &response);
                    }
                    return;
                }
                let mut st = state.lock().unwrap();
                match st.lease_engine.try_grant_for_work(
                    &repo,
                    &branch,
                    &intent,
                    Coverage::Repository,
                    work_at(&repo, &branch),
                ) {
                    Ok(lease) => Response::LeaseGranted {
                        lease_id: lease.id,
                        expires_at_secs: lease.expires_at_secs.unwrap_or(u64::MAX),
                    },
                    Err(e) => Response::Error { message: e },
                }
            }
        }
        Request::IssueToken { repo, branch } => {
            let mut st = state.lock().unwrap();
            end_finished_work(&mut st);
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
            let mut st = state.lock().unwrap();
            end_finished_work(&mut st);
            let leases = st.lease_engine.list_leases();
            Response::LeaseList { leases }
        }
        Request::ListPending => {
            let st = state.lock().unwrap();
            let mut pending: Vec<PendingInfo> = st
                .pending
                .values()
                .map(|ask| PendingInfo {
                    id: ask.id.clone(),
                    repo: ask.repo.clone(),
                    branch: ask.branch.clone(),
                    waiting_secs: ask.asked_at.elapsed().as_secs(),
                    waiters: ask.waiters.load(Ordering::SeqCst),
                })
                .collect();
            pending.sort_by_key(|p| std::cmp::Reverse(p.waiting_secs));
            Response::PendingList { pending }
        }
        Request::DenyPending { id, all } => {
            let st = state.lock().unwrap();
            let matched: Vec<&Arc<PendingAsk>> = st
                .pending
                .values()
                .filter(|ask| all || id.as_deref() == Some(ask.id.as_str()))
                .collect();
            if matched.is_empty() {
                Response::Error {
                    message: if all {
                        "no approval requests are waiting".to_string()
                    } else {
                        format!(
                            "no waiting request with id '{}': `agent-sign pending` lists them",
                            id.unwrap_or_default()
                        )
                    },
                }
            } else {
                for ask in matched {
                    ask.denied_by_command.store(true, Ordering::SeqCst);
                    ask.cancel.store(true, Ordering::SeqCst);
                }
                Response::Success
            }
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

/// The work an approval asked from `repo` on `branch` is for, if the
/// branch's tip can be read (see `agent_sign::work`). A lease granted with
/// it ends when that work is merged or deleted.
fn work_at(repo: &str, branch: &str) -> Option<agent_sign::lease::Work> {
    let base = agent_sign::work::branch_tip(Path::new(repo), branch)?;
    Some(agent_sign::lease::Work {
        repo: repo.to_string(),
        branch: branch.to_string(),
        base,
    })
}

/// Ends the leases whose work is finished, and says so in the service's log.
fn end_finished_work(st: &mut DaemonState) {
    let ended = st.lease_engine.end_finished_work(|w| {
        agent_sign::work::work_state(Path::new(&w.repo), &w.branch, &w.base)
    });
    for (lease, why) in ended {
        let why = match why {
            agent_sign::work::WorkState::Merged => "was merged",
            _ => "was deleted",
        };
        eprintln!(
            "[agent-signd] Ended the approval for {} ({}): branch '{}' {}",
            lease.repo,
            lease.coverage.describe(),
            lease.work.map(|w| w.branch).unwrap_or_default(),
            why
        );
    }
}

/// Joins the open request for this repository and branch, or opens one: a
/// prompt in its own thread, whose answer every waiting commit receives. The
/// lease, if approved, is granted once, by that thread.
fn join_or_open_request(
    state: &Arc<Mutex<DaemonState>>,
    repo: &str,
    branch: &str,
    intent: &str,
    terms: &agent_sign::lease::TermsText,
    reach: &BranchReach,
    ends: &str,
) -> Result<Arc<PendingAsk>, String> {
    let key = pending_key(repo, branch);
    let mut st = state.lock().unwrap();
    if let Some(ask) = st.pending.get(&key) {
        ask.waiters.fetch_add(1, Ordering::SeqCst);
        return Ok(Arc::clone(ask));
    }
    // A new request: not while approvals are being held back after a
    // refusal, and not past the number that may be open at once.
    if let Some(wait) = st.backoff.remaining(Instant::now()) {
        return Err(format!(
            "agent-sign is not asking again for {} more seconds: the last approval request was refused, and requests are held back after a refusal so that a prompt can't be repeated until someone gives in",
            wait.as_secs() + 1
        ));
    }
    if st.pending.len() >= MAX_PENDING_REQUESTS {
        return Err(format!(
            "agent-sign already has {MAX_PENDING_REQUESTS} approval requests waiting for an answer, so it is not asking about more (see `agent-sign pending`)"
        ));
    }
    let ask = Arc::new(PendingAsk {
        id: uuid::Uuid::new_v4().simple().to_string()[..8].to_string(),
        repo: repo.to_string(),
        branch: branch.to_string(),
        asked_at: Instant::now(),
        waiters: AtomicUsize::new(1),
        cancel: AtomicBool::new(false),
        denied_by_command: AtomicBool::new(false),
        outcome: Mutex::new(None),
        done: Condvar::new(),
    });
    st.pending.insert(key.clone(), Arc::clone(&ask));
    drop(st);

    let state = Arc::clone(state);
    let asking = Arc::clone(&ask);
    let (repo, branch, intent) = (repo.to_string(), branch.to_string(), intent.to_string());
    let (terms, reach, ends) = (terms.clone(), reach.clone(), ends.to_string());
    std::thread::spawn(move || {
        let approval = request_human_approval(&repo, &reach, &ends, &asking.cancel);
        // Read the branch's tip before taking the lock: git runs in a
        // repository the agent controls, and mustn't stall the service.
        let work = match approval {
            Approval::Approved(_) => work_at(&repo, &branch),
            _ => None,
        };
        // The deny check, the grant and leaving the list happen under the one
        // lock `agent-sign deny` also takes, so a deny that reports success
        // can never be followed by a grant.
        let response = {
            let mut st = state.lock().unwrap();
            let by_command = asking.denied_by_command.load(Ordering::SeqCst);
            let approval = if by_command {
                Approval::Denied
            } else {
                approval
            };
            // A refused prompt holds the next one back; an approval clears it.
            // A deny the person typed in a terminal (`agent-sign deny`) is
            // not a refused prompt.
            match &approval {
                Approval::Approved(_) => st.backoff.record_approval(),
                Approval::Denied | Approval::NotAuthenticated(_) if !by_command => {
                    st.backoff.record_refusal(Instant::now())
                }
                _ => {}
            }
            let response = match approval {
                Approval::Approved(coverage) => {
                    match st
                        .lease_engine
                        .try_grant_for_work(&repo, &branch, &intent, coverage, work)
                    {
                        Ok(lease) => {
                            // The prompt is too short to list a lease's terms,
                            // so the service's log records them in full.
                            eprintln!(
                                "[agent-signd] Approved a lease for {repo} (asked from branch '{branch}'). Covers: {}. Ends: {}.",
                                terms.covers, terms.ends
                            );
                            Response::LeaseGranted {
                                lease_id: lease.id,
                                expires_at_secs: lease.expires_at_secs.unwrap_or(u64::MAX),
                            }
                        }
                        Err(e) => Response::Error { message: e },
                    }
                }
                refused => Response::Error {
                    message: refused.refusal().unwrap_or_default(),
                },
            };
            // Out of the list in the same step, so a commit arriving now opens
            // a new request rather than joining one that's answered.
            st.pending.remove(&key);
            response
        };
        *asking.outcome.lock().unwrap() = Some(response);
        asking.done.notify_all();
    });
    Ok(ask)
}

/// One approval prompt at a time, across the whole service: several open at
/// once would each need a touch, and an agent could time one for a moment
/// the person expects a Touch ID prompt anyway.
static PROMPT_LOCK: Mutex<()> = Mutex::new(());

/// Asks the person to approve a lease: one prompt from the platform's own
/// authentication (on macOS, Touch ID or the login password) whose reason
/// says which branch of which repository is being approved. The repository
/// and branch were checked before this (an existing git working tree, no
/// control or invisible characters).
///
/// There is no dialog of our own: a click is not proof of a person, since any
/// program that controls the screen can click. What the lease covers isn't
/// chosen here either; it is the narrowest coverage, this repository (and,
/// unless the config lets leases follow the agent, this branch), and the
/// reason says exactly that ([`BranchReach`]). Cancel, failure, timeout or no
/// authenticator at all denies. Where there is no authenticator (Linux)
/// nobody is asked and the lease is refused: there is no terminal fallback,
/// because an agent can drive its own pseudo-terminal or type into the
/// person's, so a terminal answer proves nothing.
fn request_human_approval(
    repo: &str,
    reach: &BranchReach,
    ends: &str,
    cancel: &AtomicBool,
) -> Approval {
    let Some(authenticator) = platform_authenticator() else {
        eprintln!(
            "[agent-signd] No way to confirm an approval on this machine; signing lease denied. There is no clickable or terminal fallback: anything that can click or type could approve its own lease."
        );
        eprintln!(
            "[agent-signd] Hint: Linux can't approve leases yet. For an unattended machine you trust, use --auto-approve or AGENT_SIGN_AUTO_APPROVE=1."
        );
        return Approval::NoWayToAsk;
    };

    // Wait for our turn, giving up if every commit asking has gone.
    let _one_at_a_time = loop {
        match PROMPT_LOCK.try_lock() {
            Ok(guard) => break guard,
            Err(std::sync::TryLockError::Poisoned(e)) => break e.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => {
                if cancel.load(Ordering::SeqCst) {
                    return Approval::Withdrawn;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    };
    if cancel.load(Ordering::SeqCst) {
        return Approval::Withdrawn;
    }

    // Show the real place, not the spelling the agent used for it, and the
    // person's home folder as `~`.
    let shown_repo = fs::canonicalize(repo)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| repo.to_string());
    let home = fs::canonicalize(agent_sign::paths::home_dir())
        .ok()
        .map(|p| p.to_string_lossy().into_owned());
    // A linked worktree commits into another repository's object store: name
    // that one, but only when it confirms the worktree from its side. A
    // folder that merely claims it is shown as itself, marked unrecognized.
    let kind = agent_sign::repo_info::worktree_kind(Path::new(&shown_repo));
    let main = match &kind {
        agent_sign::repo_info::WorktreeKind::Linked(p) => Some(p.to_string_lossy().into_owned()),
        _ => None,
    };
    let unrecognized = kind == agent_sign::repo_info::WorktreeKind::Unrecognized;
    let asked = match &main {
        Some(main) => Asked {
            repo: main,
            worktree: Some(&shown_repo),
            unrecognized_worktree: false,
            home: home.as_deref(),
            reach,
            ends,
        },
        None => Asked {
            repo: &shown_repo,
            worktree: None,
            unrecognized_worktree: unrecognized,
            home: home.as_deref(),
            reach,
            ends,
        },
    };
    confirm(
        Coverage::Repository,
        authenticator.as_ref(),
        &auth_reason(&asked),
        cancel,
    )
}

/// Whether `branch` may go into an approval prompt about `repo`: a valid git
/// branch name made of plain characters, and the branch the repository has
/// checked out (read from its `HEAD`; `HEAD` for a detached one, as the
/// wrapper reports it). The error is sent to the agent.
fn check_asked_branch(repo: &str, branch: &str) -> Result<(), String> {
    agent_sign::repo_info::check_branch_name(branch)
        .map_err(|why| format!("{why}, so no approval was asked for"))?;
    match agent_sign::repo_info::current_branch(Path::new(repo)) {
        Some(current) if current == branch => Ok(()),
        _ => Err(format!(
            "branch '{branch}' isn't the branch checked out in the repository, so no approval was asked for"
        )),
    }
}
