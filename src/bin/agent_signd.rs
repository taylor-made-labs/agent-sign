//! `agent-signd`: the agent-sign service.
//!
//! One per user. It holds the agents' certificate authority and each agent
//! session's signing key (in memory only: the authority is made anew at each
//! start and its private half is never written anywhere), and the leases. It answers the
//! wrapper, the signing program, and the CLI over a Unix socket in the state
//! directory, signs each agent commit as that agent's own identity, and, only
//! when `[security] approval = "device-owner"`, asks the person to approve new
//! leases. `agent-signd` can be a link to this program; the LaunchAgent and
//! systemd unit installed by agent-sign start it by that name.
//!
//! **Finished work, off the commit's path.** A lease ends when the work it
//! was approved for is merged or deleted (`agent_sign::work`), which takes a
//! git run per lease. An agent commit checks only the lease it uses, at the
//! lease request, the token and the signature, so its cost doesn't grow with
//! the number of open leases (it used to check every lease each time, a few
//! hundred git runs at 20 leases: backlog d37fd952). Every other lease is
//! checked when the leases are listed, and by a background sweep every
//! [`WORK_SWEEP_INTERVAL`]. No git runs while the state lock is held: the
//! work to check is gathered under the lock, checked without it, and only
//! leases still there unchanged are ended (`end_finished_work_of`).
//!
//! The service is the authority on whose names get certificates: it reads
//! `[identity]` from the user's own config at start, and refuses a token for
//! an identity outside this machine's agents' domain or with an agent name
//! that isn't allowed or is a person's (see
//! `agent_sign::attribution::IdentityPolicy`; the people's accounts on the
//! machine are read once, at start: `agent_sign::accounts`; if that read
//! fails, the service refuses to start), and it
//! refuses to sign a commit whose committer date lies outside the signing
//! certificate's validity window (`SessionSigner::check_commit_date`): git
//! checks a certificate at the commit's own date, so a commit backdated or
//! postdated into another window must not get a signature at all. A token's
//! signature is also refused unless the commit's one committer line has the
//! token's principal as its email (P2, docs/caller-identity.md): read by a
//! person, a commit naming the person as committer would show the person
//! with a Good signature. A launched session's commit must also not be
//! authored as another session running now or as a person the service knows
//! (a person's name); any other author is kept, so replayed commits
//! (cherry-pick, rebase, amend, `am`, an earlier session's) still work.
//!
//! **Approved commits** (`SignApproved`, docs/caller-identity.md path 1):
//! when `[approvals] commitments_key` is set, a commit approval signed by
//! that key gets the commit signed as the agent it names, with a one-off
//! key and certificate whose attestation records the approval's hash
//! (`agent_sign::commit_approval` checks the approval and the commit; this
//! file adds the protected branches, the nonce, recorded and synced under
//! the state lock before signing, and the principal never being one the
//! plain path signs as). No lease is asked for or left: the approval is the
//! authority, and a lease would let later callers sign in that working copy
//! without one. Nor does `max_commits_per_minute` apply: the rate there is
//! one signature per approval, each needing the commitments key, so the
//! commitments check decides how many commits an agent makes. Before any
//! lock is taken a request costs one signature check, so a flood of forged
//! approvals costs only CPU.
//!
//! **Launched sessions** (`LaunchSession`, docs/caller-identity.md path 2,
//! decision D4; `agent_sign::launch` and `agent_sign::session`): on Linux,
//! `agent-sign launch` asks for a session on this socket, and only a caller
//! running as this service's own account may (one-account mode; refused
//! once a system config exists). The service makes the session's id and its
//! principal (`<agent>.<8 hex>@<domain>`), after the same name rules as any
//! token, and never one a session, an approval or the plain path has had:
//! `~/.agent-sign/sessions.log` records every session's start and end, and
//! is read at start. It answers with the session's channel attached, and
//! serves every stream that comes in over that channel as the session
//! ([`Caller::Session`]): such a stream's tokens are bound to the session's
//! id, sign only on that session's channel, and get certificates whose
//! attestation records the launcher. The connection the launcher asked on is
//! the registration: when it closes, the session ends, its channel is shut,
//! its tokens and key are dropped, and its id is never used again. The
//! plain path (this socket) never gets a token for a launched session's
//! principal.
//!
//! **The plain path after the switch** (build step S8, P7, decision D1,
//! 1 Nov 2026): a caller on this socket that is not a launched session gets
//! no identity token and no signature, whatever it claims. A token request
//! from it runs the name rules first (so a refusal that names
//! `allowed_agents` or a person keeps its words) and is then refused for not
//! being a session. Its commits are made unsigned by the wrapper after the
//! one policy-only question this service answers for it, `CheckPlainCommit`:
//! the name rules, the protected branches and the rate limit (the commit is
//! counted in the repository's own unsigned window, apart from the window
//! signing uses, so a plain caller cannot use up a session's), and nothing is
//! issued.
//!
//! **System mode** (`/etc/agent-sign/system.toml` exists; docs/system-mode.md,
//! build step 1; `agent_sign::system_config`). The service then reads that
//! file alone (a `config.toml` or `--config` is ignored, with a warning), and
//! refuses to start, before it touches its state folder or opens its socket,
//! unless: the file reads (an unknown key stops the service, naming the key
//! and the file); it runs as `[service] account` and no other; and the file
//! names the `openbao` issuer. The in-memory authority is never made there,
//! so no failure can fall back to a local key: certificates come from the
//! OpenBao adapter (`agent_sign::issuer_openbao`, wired in at build step 2),
//! which signs nothing until OpenBao's authority matches the root-owned
//! trust file, and while its login isn't loaded (`$CREDENTIALS_DIRECTORY`)
//! or its settings can't be used a closed stand-in refuses every signature.
//! Either way plain-path questions are still answered. The service also never
//! runs git in, or reads, a caller's repository in system mode: a lease has
//! no work to check, finished work isn't swept, a signature skips the
//! repository's own rules and content checks (they run in the session's
//! wrapper and at the merge gate), and `CheckPlainCommit` judges the branch
//! the wrapper reports.
//!
//! **Who is asking, in system mode** (docs/system-mode.md section 4, build
//! step 2). Sessions run in static slot accounts (`agent-slot-<n>`, D6),
//! each in its own unit, and are known by the kernel's facts, never by a
//! channel or anything a request says:
//! - **Registration** is on a second, launcher-only socket
//!   (`[service] launcher_socket`), and only from the uid the kernel reports
//!   as `[launcher] account`'s. A `RegisterSession` names the slot, its
//!   account's uid and its unit; the service checks them against the
//!   account database and `[slots]` (`agent_sign::kernel_facts::check_registration`),
//!   that no live session holds the slot (under the lock that records the
//!   new one), the name rules, and answers the principal. The connection is
//!   the registration: when it closes, the session ends and its tokens and
//!   key are dropped, as in one-account mode. Registration is refused on the
//!   ordinary socket.
//! - **A session's own requests** come on the ordinary socket. Each accepted
//!   connection is judged before its request is read
//!   (`agent_sign::kernel_facts::judge`): the session only when the caller's
//!   uid is a registered slot's, its cgroup is exactly that slot's unit, and
//!   its pidfd says the process that connected is still there after the
//!   cgroup was read (a reused pid is caught there and refused outright).
//!   Everything else is a plain caller. Why the order of those reads closes
//!   the pid-reuse race, and the rule on a kernel without `SO_PEERPIDFD`
//!   (never a session), are in that module's documentation.
//! - The certificate's attestation is `launcher session=<id> uid=<slot uid>
//!   isolation=slot-account`.
//! - The sockets come from systemd (`LISTEN_FDS`, named `daemon` and
//!   `launcher` by the socket units) when it passes them; otherwise the
//!   service makes them itself at the paths `system.toml` names.
//!
//! - **A lease ends with the session that obtained it.** Every lease the
//!   service grants because a session asked is recorded against that
//!   session's id (`DaemonState::session_leases`), and `end_session` revokes
//!   each, so the next session on the same repository and branch needs its
//!   own approval. A lease a plain caller holds, handed to a session as the
//!   covering lease, is not the session's and stays. Two live sessions that
//!   share a lease both hold it: it ends with the last of them.
//!
//! In one-account mode none of this applies and the kernel facts are never
//! consulted.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use base64::Engine;
use clap::{Parser, Subcommand};

use agent_sign::agents_ca::{AgentsCa, CertificateIssuer, SessionSigner, SessionSigners};
use agent_sign::approval::{
    Approval, Asked, BranchReach, MAX_PENDING_REQUESTS, RefusalBackoff, auth_reason, confirm,
    has_unsafe_display_chars, platform_authenticator,
};
use agent_sign::attestation::{Attestation, Isolation};
use agent_sign::attribution::{AgentIdentity, IdentityPolicy};
use agent_sign::commit_approval::{ApprovalStore, CommitmentsKey};
use agent_sign::config::{ApprovalMode, Config};
use agent_sign::kernel_facts::{
    Judgement, KernelFacts, LiveSlot, Liveness, RegistrationAsked, SlotBinding, SlotPolicy,
};
use agent_sign::lease::{Coverage, LeaseEngine, LeasePolicy, WorkToCheck};
use agent_sign::protocol::{
    PendingInfo, RUN_TOKEN_LIFETIME, Request, Response, default_socket_path, send_response,
};

#[derive(Parser)]
#[command(
    name = "agent-signd",
    version = "0.1.0",
    about = "agent-sign service: holds the agents' certificate authority, their session keys, and leases"
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
    /// Create the state and keys folders (the agents' certificate authority
    /// itself is made in memory each time the service starts)
    Setup,
    /// Query status of active daemon
    Status,
    /// Run daemon in foreground
    Run,
}

struct DaemonState {
    lease_engine: LeaseEngine,
    /// The agents' certificate authority, behind its port: today the one
    /// made in memory at this start (see `agent_sign::agents_ca`).
    ca: Box<dyn CertificateIssuer>,
    /// Each agent session's key and certificate, by principal; memory only.
    signers: SessionSigners,
    /// Which identities may get certificates: this machine's agents' domain
    /// and the allowed agent names, from the user's own `[identity]`.
    identity: IdentityPolicy,
    _config: Config,
    config_file: Option<PathBuf>,
    /// Single-use commit tokens: when each was issued, and as whom, in which
    /// repository and on which branch it signs.
    valid_tokens: HashMap<String, (Instant, RunToken)>,
    /// Run tokens: one per git run of an identified agent, usable for every
    /// commit that run makes until it ends.
    run_tokens: HashMap<String, RunToken>,
    /// Whether leases need the device owner's approval.
    approval: ApprovalMode,
    auto_approve: bool,
    /// Approval requests waiting for the person, one per repository and
    /// branch, keyed by `pending_key`.
    pending: HashMap<String, Arc<PendingAsk>>,
    /// Holds new requests back after a refused one (see `RefusalBackoff`).
    backoff: RefusalBackoff,
    /// The approval path, when `[approvals] commitments_key` is set.
    approvals: Option<ApprovalPath>,
    /// When every lease's work was last checked, by a listing or the
    /// background sweep; the sweep waits [`WORK_SWEEP_INTERVAL`] from here.
    last_work_sweep: Instant,
    /// The launched sessions in progress, by id.
    sessions: HashMap<String, Arc<LiveSession>>,
    /// Every principal a launched session has ever had (`sessions.log`,
    /// read at start, and this run's): never drawn again, and never signed
    /// by the plain path.
    launched: HashSet<String>,
    /// `~/.agent-sign/sessions.log`.
    session_log: agent_sign::session::SessionLog,
    /// Whether this is system mode (`/etc/agent-sign/system.toml` exists; see
    /// `agent_sign::system_config`). Then the service never runs git in, or
    /// reads, a caller's repository: its checks use only what a request says.
    system: bool,
    /// System mode: the kernel's facts callers are judged by
    /// (`agent_sign::kernel_facts`). `None` in one-account mode, where they
    /// are never consulted.
    kernel: Option<Arc<dyn KernelFacts>>,
    /// System mode: which account registers sessions, and the slots.
    slots: Option<SlotPolicy>,
    /// System mode: uids no slot account may have: the service's own and
    /// the people's accounts read at start (root and the launcher's are
    /// added at each registration).
    never_slot_uids: Vec<u32>,
    /// System mode: the leases each live session obtained, by session id (a
    /// lease the service granted because that session asked, or the one it
    /// shares with another live session). `end_session` revokes them, so a
    /// lease ends with its session and the next session on the same
    /// repository and branch needs its own (review finding F4). Empty in
    /// one-account mode, where a lease's work ends it instead. Memory only:
    /// a session cannot outlive the service, and for that the service ends
    /// every lease it finds in `leases.json` when it starts in system mode
    /// (`run_daemon`), so a crash or restart does not leave one for the next
    /// session to inherit.
    session_leases: HashMap<String, Vec<String>>,
}

/// A session agent-sign's launcher started (see the module documentation).
struct LiveSession {
    /// The id the service made for it.
    id: String,
    /// As whom it signs, the only identity it ever signs as.
    identity: AgentIdentity,
    /// What its certificates record: the launcher, its uid, its isolation.
    attestation: Attestation,
    /// The service's end of the session's channel (one-account mode). A
    /// slot session has none: it is known by its uid and unit.
    channel: Option<OwnedFd>,
    /// System mode: the slot, its account's uid and its unit.
    slot: Option<SlotBinding>,
    /// The uid its log lines record: the launcher's in one-account mode,
    /// the slot account's in system mode.
    uid: u32,
    /// Set when the launcher's registration closed.
    ended: AtomicBool,
}

/// Who is on the other end of a connection: decided by how it came in,
/// never by what it says.
#[derive(Clone)]
enum Caller {
    /// This service's socket: any process that can reach it, naming whom
    /// it likes (today's plain path).
    Plain,
    /// A launched session: a stream that came in over its channel
    /// (one-account mode), or a process of its slot account in its unit
    /// (system mode).
    Session(Arc<LiveSession>),
}

/// The approval path's settings and state (see the module documentation).
struct ApprovalPath {
    /// The commitments approval key: only its approvals are signed on.
    key: CommitmentsKey,
    /// This machine's `[identity] machine`, which every approval must name.
    machine: String,
    /// The used nonces and approved principals, on disk; held under the
    /// state lock, so checking a nonce and recording it are one step.
    store: ApprovalStore,
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
    /// System mode: the launched sessions among the askers (ids), so the
    /// lease granted on the answer is recorded against them and ends with
    /// them (review finding F4).
    sessions: Mutex<Vec<String>>,
    /// System mode: whether a plain caller is among the askers. Then the
    /// lease is granted even if every asking session has ended.
    plain_asked: AtomicBool,
}

impl PendingAsk {
    /// Notes who is waiting on this request.
    fn note_asker(&self, caller: &Caller) {
        match caller {
            Caller::Session(session) => {
                let mut sessions = self.sessions.lock().unwrap();
                if !sessions.contains(&session.id) {
                    sessions.push(session.id.clone());
                }
            }
            Caller::Plain => self.plain_asked.store(true, Ordering::SeqCst),
        }
    }
}

/// System mode: records that `session` obtained the lease `lease_id`, so
/// `end_session` revokes it (review finding F4). The caller has checked,
/// under the same lock hold, that the session is still live.
fn record_session_lease(st: &mut DaemonState, session: &str, lease_id: &str) {
    let leases = st.session_leases.entry(session.to_string()).or_default();
    if !leases.iter().any(|id| id == lease_id) {
        leases.push(lease_id.to_string());
    }
}

/// System mode: a session handed a lease that another live session obtained
/// shares it, so it ends when the last of them ends, not when the first
/// does. A lease no live session obtained (a plain caller's) is not shared
/// in: it is not the session's to take away with it.
fn share_session_lease(st: &mut DaemonState, caller: &Caller, lease_id: &str) {
    let Caller::Session(session) = caller else {
        return;
    };
    if st.system
        && st
            .session_leases
            .iter()
            .any(|(id, leases)| *id != session.id && leases.iter().any(|l| l == lease_id))
    {
        record_session_lease(st, &session.id, lease_id);
    }
}

/// A token's terms: as whom it signs, for which repository and branch (the
/// lease it was issued under), and when it was issued. Single-use commit
/// tokens carry the same terms, so every signature is checked against them.
#[derive(Clone)]
struct RunToken {
    identity: AgentIdentity,
    repo: String,
    branch: String,
    lease_id: String,
    issued: Instant,
    /// The launched session the token was issued to, when it was: it then
    /// signs only on that session's channel, while the session lasts.
    session: Option<String>,
    /// The session's attestation, which its certificate carries.
    attestation: Option<Attestation>,
}

/// How long a single-use commit token can wait to be used.
const COMMIT_TOKEN_LIFETIME: Duration = Duration::from_secs(60);

/// How often the background sweep checks every lease's work, counted from
/// the last full check (a listing counts). A minute: often enough that
/// finished work's leases don't linger, rare enough that a sweep (a git run
/// per lease) seldom coincides with a commit, and never within a minute of
/// a listing. Off the commit's path either way, and outside the lock.
const WORK_SWEEP_INTERVAL: Duration = Duration::from_secs(60);

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
    fs::create_dir_all(&base_dir)?;
    fs::set_permissions(&base_dir, fs::Permissions::from_mode(0o700))?;
    let keys_dir = agent_sign::agents_ca::keys_dir_in(&base_dir);
    fs::create_dir_all(&keys_dir)?;
    fs::set_permissions(&keys_dir, fs::Permissions::from_mode(0o700))?;

    println!("\n========================================================");
    println!(" agent-sign Setup Complete");
    println!("========================================================");
    println!(
        "The agents' certificate authority is made in memory each time the service\n\
         starts, and its private key is never written anywhere. A start never\n\
         changes what verifiers trust: `agent-sign trust install` adds the running\n\
         service's authority to {} and to agent-sign's block in\n\
         the file git's gpg.ssh.allowedSignersFile names.",
        keys_dir
            .join(agent_sign::agents_ca::CAS_HISTORY_FILE)
            .display()
    );
    println!(
        "\nThe installer adds that block and runs `agent-sign trust install` once the\n\
         service is up. After the service restarts, run it again."
    );
    println!("========================================================");

    Ok(())
}

/// Makes this start's agents' certificate authority, in memory, after
/// refusing a private key an earlier build left in a file. The authority
/// lives for this service's lifetime. The start writes only its public half:
/// the live key file (`agent_sign::agents_ca::write_live_key`) and the state
/// lock (`agent_sign::state_lock`), neither a trust entry. It never appends
/// to the authority history or rewrites the managed block in the person's
/// allowed-signers file: only `agent-sign trust install` writes trust
/// (decision D2; P3, docs/caller-identity.md), so starting another service
/// never changes what verifiers trust.
fn start_authority(
    base_dir: &Path,
    lock: &mut agent_sign::state_lock::StateLock,
) -> Result<AgentsCa, Box<dyn std::error::Error>> {
    let keys_dir = agent_sign::agents_ca::keys_dir_in(base_dir);
    agent_sign::agents_ca::refuse_unprotected_key(&keys_dir)?;
    let ca = AgentsCa::generate(&agent_sign::agents_ca::hostname());
    let line = ca.public_key_openssh();
    agent_sign::agents_ca::write_live_key(&keys_dir, &line)?;
    lock.record_live_authority(&line)?;
    // New this start, so nothing trusts it yet.
    eprintln!(
        "[agent-signd] made this start's agents' certificate authority in memory; it isn't \
         trusted yet: run `agent-sign trust install` to trust it"
    );
    Ok(ca)
}

/// Everything system mode checks before the service touches its state
/// folder or opens its socket, in this order (docs/system-mode.md, sections
/// 1, 4 and 5): a warning that `config.toml` (and `--config`) is ignored,
/// since the service reads `system.toml` alone; the account (it runs as
/// `[service] account` and no other); the issuer (OpenBao's alone; a file
/// with no `[authority] issuer = "openbao"` stops the service); and the
/// settings themselves. Returns the config the service runs with and the
/// OpenBao settings. The error is the reason, for the log.
fn start_system_mode(
    system: &agent_sign::system_config::Active,
    custom_config: Option<&Path>,
) -> Result<(Config, agent_sign::system_config::OpenBaoSettings), String> {
    let own_config = agent_sign::paths::state_dir().join("config.toml");
    if own_config.symlink_metadata().is_ok() {
        eprintln!(
            "[agent-signd] system mode: {} is ignored; the service reads only {}",
            own_config.display(),
            system.path.display()
        );
    }
    if let Some(path) = custom_config {
        eprintln!(
            "[agent-signd] system mode: --config {} is ignored; the service reads only {}",
            path.display(),
            system.path.display()
        );
    }
    // SAFETY: geteuid takes no arguments and can't fail.
    let euid = unsafe { libc::geteuid() };
    system.config.check_runs_as(euid, &system.path)?;
    let openbao = system.config.openbao(&system.path)?;
    let config = system.config.to_config(&system.path)?;
    Ok((config, openbao))
}

fn run_status(custom_socket: Option<&Path>) -> Result<(), Box<dyn std::error::Error>> {
    let socket_path = custom_socket
        .map(PathBuf::from)
        .or_else(agent_sign::system_config::client_socket)
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
    // bad value stops the service without disturbing a running one. A
    // system.toml decides the mode: with one, the service reads that file
    // alone, and only as the account it names (`start_system_mode`); a file
    // that doesn't read stops the service, never falls back to a laptop's.
    let system = match agent_sign::system_config::active() {
        Ok(system) => system,
        Err(e) => {
            eprintln!("[agent-signd] refusing to start: {e}");
            std::process::exit(1);
        }
    };
    let (mut config, openbao) = match &system {
        Some(system) => match start_system_mode(system, custom_config) {
            Ok((config, openbao)) => (config, Some(openbao)),
            Err(e) => {
                eprintln!("[agent-signd] refusing to start: {e}");
                std::process::exit(1);
            }
        },
        None => {
            let config = if let Some(cfg_path) = custom_config {
                Config::load_from_file(cfg_path)?
            } else {
                // A setting that doesn't read (a misspelt approval mode, say)
                // would otherwise fall back to the defaults without a word.
                Config::check_file_in_home(&agent_sign::paths::home_dir())?;
                Config::try_load(None)?
            };
            (config, None)
        }
    };
    // System mode's sockets, when systemd made them: taken now, while no
    // other thread runs (the variables naming them are removed).
    let activated = if system.is_some() {
        match activated_sockets() {
            Ok(activated) => activated,
            Err(e) => {
                eprintln!("[agent-signd] refusing to start: {e}");
                std::process::exit(1);
            }
        }
    } else {
        None
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

    // This start's agents' certificate authority, made in memory. The
    // shared agent key of earlier versions (`agent_ed25519`) is no longer
    // used.
    let base_dir = get_state_dir();
    // One service per state folder (decision D2): the exclusive state lock,
    // taken before anything in the state folder is written (the approval
    // store, the live key, a stale socket's removal), and held until this
    // process ends. A second service for the same state stops here.
    let mut state_lock = match agent_sign::state_lock::StateLock::acquire(&base_dir) {
        Ok(lock) => lock,
        Err(e) => {
            eprintln!("[agent-signd] refusing to start: {e}");
            std::process::exit(1);
        }
    };
    // The config's [identity] was checked when it loaded (a bad machine name
    // stops the service there, before the authority is made).
    // People's names, never certified as agents' (M2, 31 Oct 2026): the
    // reserved names and `[identity] people` (in the policy already), the
    // `[human]` the config file sets itself (never git's), and the people's
    // accounts on this machine, read once, now. None of it comes from git.
    let config_path = custom_config
        .map(Path::to_path_buf)
        .unwrap_or_else(|| agent_sign::paths::state_dir().join("config.toml"));
    let (human_name, human_email) = if system.is_some() {
        (None, None)
    } else {
        agent_sign::config::human_set_in_file(&config_path)
    };
    // A failed read stops the service here, before its socket exists: run
    // with no accounts, it would certify an agent under any account holder's
    // name (31 Oct 2026 follow-up, item 3).
    let accounts = match agent_sign::accounts::persons_accounts() {
        Ok(accounts) => accounts,
        Err(e) => {
            eprintln!(
                "[agent-signd] refusing to start: {e}. agent-sign reads the people's accounts \
                 on this machine at start so that no agent is ever certified under a person's \
                 name, and without them it can't keep that promise. Check that the account \
                 database (/etc/passwd and the name service on Linux, Directory Services on \
                 macOS) can be read, then start the service again"
            );
            std::process::exit(1);
        }
    };
    let identity = config
        .identity
        .policy()
        .with_persons(agent_sign::attribution::PersonName::of_human(
            human_name.as_deref(),
            human_email.as_deref(),
        ))
        .with_person_emails(agent_sign::attribution::PersonEmail::of_human(
            human_email.as_deref(),
        ))
        .with_persons(agent_sign::accounts::names_of(&accounts));
    eprintln!(
        "[agent-signd] agents' names: <agent>.<session>@{}",
        identity.domain
    );
    eprintln!(
        "[agent-signd] never an agent's name: root, admin, administrator{}{}{}",
        if config.identity.people.is_empty() {
            String::new()
        } else {
            format!(
                ", the {} people in [identity] people",
                config.identity.people.len()
            )
        },
        if human_name.is_some() || human_email.is_some() {
            ", the [human] name and email"
        } else {
            ""
        },
        if accounts.is_empty() {
            String::new()
        } else {
            format!(
                ", and the people's accounts on this machine ({})",
                accounts
                    .iter()
                    .map(|a| a.login.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }
    );
    // Before any private key exists: no core files, and (Linux) no other
    // program of this user can read this memory. Fails closed.
    agent_sign::hardening::protect_process_memory()?;
    // The approval path, when the user's config names the commitments key
    // (checked when the config loaded, with the machine it needs). Its store
    // must read in full, or the service doesn't start: a store it couldn't
    // trust would let a used approval sign again.
    let approvals = match &config.approvals.commitments_key {
        None => {
            eprintln!(
                "[agent-signd] approvals: off ([approvals] commitments_key isn't set), so \
                 SignApproved requests are refused"
            );
            None
        }
        Some(line) => {
            let key = CommitmentsKey::parse(line)
                .map_err(|e| format!("[approvals] commitments_key: {e}"))?;
            let machine = config
                .identity
                .machine
                .clone()
                .ok_or("[approvals] commitments_key needs [identity] machine")?;
            let store = ApprovalStore::open(&base_dir, agent_sign::agents_ca::now_secs())?;
            eprintln!(
                "[agent-signd] approvals: signs commits approved by the commitments key {} for \
                 machine {machine}",
                key.fingerprint()
            );
            Some(ApprovalPath {
                key,
                machine,
                store,
            })
        }
    };
    // Every principal a launched session ever had, so none is drawn again.
    // A log that can't be read stops the service: it couldn't keep that
    // promise.
    let session_log = agent_sign::session::SessionLog::in_state(&base_dir);
    let launched: HashSet<String> = match session_log.principals() {
        Ok(principals) => principals.into_iter().collect(),
        Err(e) => {
            eprintln!(
                "[agent-signd] refusing to start: {} can't be read ({e}), so the service \
                 couldn't tell which launched sessions' names were already used",
                base_dir
                    .join(agent_sign::session::SESSION_LOG_FILE)
                    .display()
            );
            std::process::exit(1);
        }
    };
    // In system mode the issuer is OpenBao's alone: the in-memory authority
    // is never made, so no failure can fall back to a local key
    // (`system_issuer`). Plain-path questions are answered either way.
    let ca: Box<dyn CertificateIssuer> = match (&openbao, &system) {
        (Some(settings), Some(system)) => system_issuer(settings, &system.config),
        _ => Box::new(start_authority(&base_dir, &mut state_lock)?),
    };

    let socket_path = custom_socket
        .map(PathBuf::from)
        .or_else(|| system.as_ref().map(|s| s.config.service.socket.clone()))
        .unwrap_or_else(default_socket_path);

    // Remove a stale socket, only after the state lock is held, so a second
    // service for this state can't delete a live service's socket. (A
    // `--socket` outside the state folder, shared by services for different
    // state folders, isn't covered by this lock.) Sockets systemd made are
    // left alone.
    let launcher_socket_path = system
        .as_ref()
        .map(|s| s.config.service.launcher_socket.clone());
    if activated.is_none() {
        for path in std::iter::once(&socket_path).chain(launcher_socket_path.as_ref()) {
            if path.exists() {
                let _ = fs::remove_file(path);
            }
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
                // In system mode the sockets' folder belongs to the sitting
                // and the socket units (root's, shared with the launcher):
                // not ours to chmod.
                if system.is_none() {
                    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
                }
            }
        }
    }

    if allow_main {
        config.security.allow_main_branch = true;
    }

    let effective_auto_approve = auto_approve || config.security.auto_approve;

    // Beside the socket on a laptop (the state folder). In system mode the
    // socket is in /run, which is gone at reboot: the leases stay in the
    // state folder.
    let storage_path = if system.is_some() {
        Some(base_dir.join("leases.json"))
    } else {
        socket_path.parent().map(|p| p.join("leases.json"))
    };
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

    let approval = config.security.approval;
    // The approval mode in effect, said once at start: since "none" became
    // the default, a config that didn't say what the person thought it said
    // would otherwise go unnoticed (identity review, 28 Oct 2026).
    eprintln!(
        "[agent-signd] approval = \"{}\": {}",
        match approval {
            ApprovalMode::None => "none",
            ApprovalMode::DeviceOwner => "device-owner",
        },
        match (approval, effective_auto_approve) {
            (ApprovalMode::None, _) => "leases are granted without asking, and logged",
            (ApprovalMode::DeviceOwner, true) => {
                "but auto_approve is on, so leases are granted without asking"
            }
            (ApprovalMode::DeviceOwner, false) => "you approve each lease",
        }
    );
    let state = Arc::new(Mutex::new(DaemonState {
        lease_engine: LeaseEngine::new_with_storage(policy, storage_path),
        ca,
        signers: SessionSigners::default(),
        identity,
        _config: config,
        config_file: if system.is_some() {
            None
        } else {
            custom_config.map(Path::to_path_buf)
        },
        valid_tokens: HashMap::new(),
        run_tokens: HashMap::new(),
        approval,
        auto_approve: effective_auto_approve,
        pending: HashMap::new(),
        backoff: RefusalBackoff::new(refusal_backoff),
        approvals,
        last_work_sweep: Instant::now(),
        sessions: HashMap::new(),
        launched,
        session_log,
        system: system.is_some(),
        kernel: system.as_ref().map(|_| agent_sign::kernel_facts::kernel()),
        slots: system.as_ref().map(|s| SlotPolicy {
            launcher_account: s.config.launcher.account.clone(),
            account_prefix: s.config.slots.account_prefix.clone(),
            count: s.config.slots.count,
        }),
        never_slot_uids: {
            // SAFETY: getuid takes no arguments and can't fail.
            let mut uids = vec![unsafe { libc::getuid() }];
            uids.extend(accounts.iter().map(|a| a.uid));
            uids
        },
        session_leases: HashMap::new(),
    }));

    // Every lease's work, checked now and then, off any commit's path. Not
    // in system mode: that check is a git run in the lease's repository.
    if system.is_none() {
        let state = Arc::clone(&state);
        std::thread::spawn(move || sweep_finished_work(&state));
    }

    // System mode: no session outlives the service, and the record of which
    // lease belongs to which session is in memory, so a lease still in
    // `leases.json` at start may belong to a session that died with the
    // service (a crash, a restart) and would be inherited by the next one on
    // the same repository and branch, its device-owner approval with it
    // (review finding F4). Every lease ends here, saved to the file; a plain
    // caller asks again, which costs one request (or one prompt under
    // `approval = "device-owner"`).
    if system.is_some() {
        let mut st = state.lock().unwrap();
        match st.lease_engine.revoke_all_durable() {
            Ok(0) => {}
            Ok(n) => eprintln!(
                "[agent-signd] system mode: ended {n} lease(s) left from before this start, \
                 since a session cannot outlive the service"
            ),
            Err(e) => {
                eprintln!("[agent-signd] refusing to start: {e}");
                std::process::exit(1);
            }
        }
    }

    // Leases that cover more than one repository can no longer be granted;
    // ones approved earlier still work, so say so in the log.
    if let Some(note) =
        agent_sign::protocol::wide_leases_note(&state.lock().unwrap().lease_engine.list_leases())
    {
        eprintln!("[agent-signd] {note}");
    }

    let (listener, launcher_listener) = match activated {
        Some((daemon, launcher)) => {
            eprintln!(
                "[agent-signd] system mode: serving the sockets systemd made (daemon and \
                 launcher)"
            );
            (daemon, Some(launcher))
        }
        None => {
            let listener = UnixListener::bind(&socket_path)?;
            // In system mode every caller is judged by the uid the kernel
            // reports, so the socket is for everyone, as the socket unit
            // makes it (docs/system-mode.md, section 1).
            let mode = if system.is_some() { 0o666 } else { 0o600 };
            fs::set_permissions(&socket_path, fs::Permissions::from_mode(mode))?;
            let launcher = match &launcher_socket_path {
                Some(path) => {
                    let l = UnixListener::bind(path)?;
                    // Made by the service itself, it can't be given to the
                    // launcher's group; the uid check decides either way.
                    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
                    eprintln!(
                        "[agent-signd] system mode: the launcher-only socket is {}",
                        path.display()
                    );
                    Some(l)
                }
                None => None,
            };
            (listener, launcher)
        }
    };

    if let Some(launcher_listener) = launcher_listener {
        let state = Arc::clone(&state);
        let limit = ConnectionLimit::new(MAX_LAUNCHER_CONNECTIONS, MAX_LAUNCHER_CONNECTIONS);
        std::thread::spawn(move || {
            for stream in launcher_listener.incoming() {
                match stream {
                    Ok(s) => {
                        let state = Arc::clone(&state);
                        spawn_connection("launcher", &limit, s, move |s, _slot| {
                            serve_launcher(s, state)
                        });
                    }
                    Err(e) => eprintln!("Launcher socket accept error: {e}"),
                }
            }
        });
    }

    println!("agent-signd running on {}", socket_path.display());
    #[cfg(feature = "test-authenticator")]
    eprintln!(
        "[agent-signd] WARNING: this is a test build with a stand-in for the device owner (AGENT_SIGN_TEST_AUTH). It must never be installed."
    );

    let limit = ConnectionLimit::new(MAX_CONNECTIONS, MAX_CONNECTIONS_PER_UID);
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let state_clone = Arc::clone(&state);
                spawn_connection("main", &limit, s, move |mut s, slot| {
                    // Who is asking is decided before the request is read.
                    match identify(&state_clone, &s) {
                        Ok(caller) => handle_client(&mut s, state_clone, caller, slot),
                        Err(message) => {
                            let _ = send_response(&mut s, &Response::Error { message });
                        }
                    }
                });
            }
            Err(e) => {
                eprintln!("Socket accept error: {}", e);
            }
        }
    }

    Ok(())
}

/// The most bytes one request line may have on the main socket. Requests are
/// JSON of a few hundred bytes; the largest legitimate one carries a commit or
/// tag object (base64), a few KiB. 1 MiB leaves a wide margin, and bounds
/// what one connection, which any account may open, can make the service
/// hold (review finding L6).
const MAX_REQUEST_BYTES: u64 = 1024 * 1024;

/// The longest a whole request line may take to arrive, counted from the
/// first read, not per read, so a client that sends one byte at a time gets
/// no longer than one that sends nothing. Callers are local programs on a Unix
/// socket and send a line at once, so 10 s is generous; the test of this
/// limit allows 20 s.
const REQUEST_READ_DEADLINE: Duration = Duration::from_secs(10);

/// Reads from a socket until a fixed moment: before every read it sets the
/// socket's read timeout to the time left, so the deadline covers the whole
/// request rather than each read.
struct DeadlineReader {
    stream: UnixStream,
    deadline: Instant,
}

impl Read for DeadlineReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let left = self.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(std::io::ErrorKind::TimedOut.into());
        }
        self.stream.set_read_timeout(Some(left))?;
        self.stream.read(buf)
    }
}

/// Reads one line (at most `limit` bytes, within `within` in total) from
/// `stream`. `None` when the line is too long, too slow, or unreadable: the
/// caller just drops the connection. A line ended by the client closing its
/// side, with no newline, still counts (as before). The read timeout is
/// cleared afterwards, so later reads on the same socket are unaffected.
fn read_request_line(stream: &UnixStream, limit: u64, within: Duration) -> Option<String> {
    let reader = DeadlineReader {
        stream: stream.try_clone().ok()?,
        deadline: Instant::now() + within,
    };
    let mut reader = BufReader::new(reader.take(limit));
    let mut line = String::new();
    let outcome = reader.read_line(&mut line);
    let _ = stream.set_read_timeout(None);
    if outcome.is_err() || (!line.ends_with('\n') && line.len() as u64 >= limit) {
        return None;
    }
    Some(line)
}

/// The most connections the main socket serves at once, all accounts
/// together. Each one has a thread and may hold a request line of up to
/// [`MAX_REQUEST_BYTES`] (1 MiB) for [`REQUEST_READ_DEADLINE`], so the memory
/// a crowd can pin is the number of connections times about 1 MiB (plus the
/// thread's stack, well under that in use): 256 bounds it at about 270 MiB,
/// the most this service may be made to hold by accounts that only need to
/// reach a world-writable socket. Real use is a handful: a few sessions,
/// each making one short connection per commit, plus the commits waiting on
/// an approval prompt (they hold theirs until it is answered), so 256 is
/// far above it. Review finding G-signd-2.
const MAX_CONNECTIONS: usize = 256;

/// The most of [`MAX_CONNECTIONS`] one account (the kernel's uid for the
/// connection) may hold, so one account that floods the socket cannot use up
/// the places the sessions' accounts need. A session's account needs a
/// handful; 64 is several times more. In one-account mode every caller is
/// the one account, and this is the cap that applies.
const MAX_CONNECTIONS_PER_UID: usize = 64;

/// The most connections the launcher-only socket serves at once. Only the
/// launcher's account is served there, and each live session keeps one open
/// as its registration (the slots are at most a few dozen), so 64 is more
/// than the launcher ever holds. The memory bound is as for
/// [`MAX_CONNECTIONS`], with a 64 KiB line limit here: 64 x 64 KiB = 4 MiB.
const MAX_LAUNCHER_CONNECTIONS: usize = 64;

/// The most connections one launched session's channel serves at once
/// (one-account mode): a session's git runs commit a few at a time.
const MAX_CHANNEL_CONNECTIONS: usize = 64;

/// Counts the connections a socket has open, in total and per account, and
/// refuses new ones past its caps. A [`ConnectionSlot`] is taken when the
/// connection is accepted and given back when its thread ends (or at once if
/// the thread cannot start), so nothing that ends a connection can leak a
/// place.
struct ConnectionLimit {
    total: usize,
    per_uid: usize,
    open: Mutex<(usize, HashMap<u32, usize>)>,
}

/// One place in a [`ConnectionLimit`], given back when dropped.
struct ConnectionSlot {
    limit: Arc<ConnectionLimit>,
    uid: Option<u32>,
}

impl ConnectionLimit {
    fn new(total: usize, per_uid: usize) -> Arc<ConnectionLimit> {
        Arc::new(ConnectionLimit {
            total,
            per_uid,
            open: Mutex::new((0, HashMap::new())),
        })
    }

    /// A place for a connection from `uid` (`None` when the kernel would not
    /// say: it then counts only in the total), or why there is none.
    fn take(self: &Arc<Self>, uid: Option<u32>) -> Result<ConnectionSlot, &'static str> {
        let mut open = self.open.lock().unwrap_or_else(|e| e.into_inner());
        if open.0 >= self.total {
            return Err("the service has too many connections open right now; try again");
        }
        if let Some(uid) = uid {
            let held = open.1.entry(uid).or_insert(0);
            if *held >= self.per_uid {
                return Err("this account has too many connections open right now; try again");
            }
            *held += 1;
        }
        open.0 += 1;
        Ok(ConnectionSlot {
            limit: Arc::clone(self),
            uid,
        })
    }
}

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        let mut open = self.limit.open.lock().unwrap_or_else(|e| e.into_inner());
        open.0 = open.0.saturating_sub(1);
        if let Some(uid) = self.uid
            && let Some(held) = open.1.get_mut(&uid)
        {
            *held = held.saturating_sub(1);
            if *held == 0 {
                open.1.remove(&uid);
            }
        }
    }
}

/// Starts a thread for one connection, if `limit` has a place for it. Past
/// the limit, or if the thread cannot be started (the account's thread
/// limit, memory), that connection is answered with an error and closed, and
/// the service carries on (`std::thread::spawn` would panic here and take the
/// whole service down; review findings L6 and G-signd-2). The refusal is
/// written without waiting for the client, on a connection that has nothing
/// in its buffer yet.
///
/// `work` is given the connection's place so that a connection that turns
/// into a long-lived session registration can give it back (see
/// [`launch_session`]): it no longer holds a request, only a thread.
fn spawn_connection<F>(what: &str, limit: &Arc<ConnectionLimit>, stream: UnixStream, work: F)
where
    F: FnOnce(UnixStream, &mut Option<ConnectionSlot>) + Send + 'static,
{
    let refusal = stream.try_clone().ok();
    let uid = agent_sign::session::peer_uid(stream.as_raw_fd()).ok();
    let slot = match limit.take(uid) {
        Ok(slot) => slot,
        Err(message) => {
            if let Some(mut refused) = refusal {
                let _ = refused.set_write_timeout(Some(Duration::from_secs(1)));
                let _ = send_response(
                    &mut refused,
                    &Response::Error {
                        message: message.into(),
                    },
                );
            }
            return;
        }
    };
    if let Err(e) = std::thread::Builder::new().spawn(move || {
        let mut slot = Some(slot);
        work(stream, &mut slot)
    }) {
        eprintln!("[agent-signd] cannot start a thread for a {what} connection: {e}");
        if let Some(mut refused) = refusal {
            let _ = refused.set_write_timeout(Some(Duration::from_secs(1)));
            let _ = send_response(
                &mut refused,
                &Response::Error {
                    message: "the service is too busy to start another connection; try again"
                        .into(),
                },
            );
        }
    }
}

/// Answers the one request on `stream`, from `caller`.
///
/// `slot` is the connection's place in its [`ConnectionLimit`]; a launch
/// request gives it back once the connection has become the session's
/// registration.
fn handle_client(
    stream: &mut UnixStream,
    state: Arc<Mutex<DaemonState>>,
    caller: Caller,
    slot: &mut Option<ConnectionSlot>,
) {
    // The socket is writable by every account, so the request is read under
    // a size limit and a total deadline (review finding L6).
    let Some(line) = read_request_line(stream, MAX_REQUEST_BYTES, REQUEST_READ_DEADLINE) else {
        return;
    };
    if line.trim().is_empty() {
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

    if let Caller::Session(session) = &caller {
        if !session_live(&state, session) {
            let _ = send_response(
                stream,
                &Response::Error {
                    message: "this launched session has ended, so its channel is refused".into(),
                },
            );
            return;
        }
        if !allowed_from_session(&request) {
            let _ = send_response(
                stream,
                &Response::Error {
                    message: "a launched session's channel takes only its own commits' requests"
                        .into(),
                },
            );
            return;
        }
    }

    let response = match request {
        Request::Ping => Response::Pong,
        Request::LaunchSession { agent } => {
            // The connection stays open as the session's registration.
            launch_session(stream, &state, &agent, slot);
            return;
        }
        Request::RegisterSession { .. } => Response::Error {
            message: "sessions are registered only on the launcher-only socket, by the \
                      launcher's account"
                .into(),
        },
        Request::SessionIdentity => match &caller {
            Caller::Session(session) => Response::SessionIdentity {
                identity: session.identity.clone(),
            },
            Caller::Plain => Response::Error {
                message: "not a launched session: only a launched session (a stream over its \
                          own channel, or in system mode a process of its slot account in its \
                          unit) has a session identity"
                    .into(),
            },
        },
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
            // One name per repository: a link or `..` would otherwise get a
            // lease, and a rate window, of its own.
            let repo = canonical_repo(&repo);
            // In system mode the service can't see callers' repositories
            // (and never opens one), so it can't check that this is one.
            let system = state.lock().unwrap().system;
            if !system && !Path::new(&repo).join(".git").exists() {
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
            // End the leases this request could use whose work is
            // finished (the covering one, and the one that may follow the
            // agent to this branch), until none of them is: then a wider
            // lease left in force is checked too. Only these, so the cost
            // doesn't grow with the leases open elsewhere.
            while end_finished_work_of(&state, |st| {
                let engine = &st.lease_engine;
                let in_use: Vec<String> = [
                    engine.find_lease(&repo, &branch),
                    engine.get_active_lease(&repo),
                ]
                .into_iter()
                .flatten()
                .map(|lease| lease.id.clone())
                .collect();
                engine.work_to_check(|lease| in_use.contains(&lease.id))
            }) > 0
            {}
            // Check active lease state without holding the lock across the prompt
            let (blocked, covering, can_follow, grant_unasked, terms, reach, ends) = {
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
                    // Nobody is asked with approval = "none", or when the
                    // person chose unattended approval.
                    st.approval == ApprovalMode::None || st.auto_approve,
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
                share_session_lease(&mut state.lock().unwrap(), &caller, &lease_id);
                Response::LeaseGranted {
                    lease_id,
                    expires_at_secs: lease_exp.unwrap_or(u64::MAX),
                }
            } else if can_follow {
                let mut st = state.lock().unwrap();
                match st.lease_engine.switch_branch(&repo, &branch) {
                    Ok(updated) => {
                        share_session_lease(&mut st, &caller, &updated.id);
                        Response::LeaseGranted {
                            expires_at_secs: st
                                .lease_engine
                                .effective_end(&updated)
                                .unwrap_or(u64::MAX),
                            lease_id: updated.id,
                        }
                    }
                    Err(e) => Response::Error { message: e },
                }
            } else {
                // Nothing covers this commit: ask the person, outside the lock,
                // when approval = "device-owner". Granting without asking only
                // ever grants this repository.
                if !grant_unasked {
                    // The branch goes into the prompt's sentence, and the
                    // agent chose it: it must be a plain, valid branch name
                    // and the one the repository really has checked out.
                    if let Err(message) = check_asked_branch(&repo, &branch, system) {
                        let _ = send_response(stream, &Response::Error { message });
                        return;
                    }
                    let ask = match join_or_open_request(
                        &state,
                        &caller,
                        &repo,
                        &branch,
                        &intent,
                        &ShownTerms {
                            terms: &terms,
                            reach: &reach,
                            ends: &ends,
                        },
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
                // System mode: the lease is the asking session's and ends
                // with it, so a session that ended while this request was
                // read gets none (checked under the lock that records it).
                if let Caller::Session(session) = &caller
                    && st.system
                    && !st.sessions.contains_key(&session.id)
                {
                    let _ = send_response(
                        stream,
                        &Response::Error {
                            message: "this launched session has ended, so no lease was granted"
                                .into(),
                        },
                    );
                    return;
                }
                let unasked = st.approval == ApprovalMode::None;
                match st.lease_engine.try_grant_for_work(
                    &repo,
                    &branch,
                    &intent,
                    Coverage::Repository,
                    work_at(system, &repo, &branch),
                ) {
                    Ok(lease) => {
                        if let Caller::Session(session) = &caller
                            && st.system
                        {
                            record_session_lease(&mut st, &session.id, &lease.id);
                        }
                        // The record of what was granted without anyone's
                        // approval; each identity's use of it is logged as
                        // its tokens are issued.
                        if unasked {
                            eprintln!(
                                "[agent-signd] Granted lease {} for {repo} (branch '{branch}') without asking: approval = \"none\"",
                                lease.id
                            );
                        }
                        Response::LeaseGranted {
                            lease_id: lease.id,
                            expires_at_secs: lease.expires_at_secs.unwrap_or(u64::MAX),
                        }
                    }
                    Err(e) => Response::Error { message: e },
                }
            }
        }
        Request::CheckPlainCommit {
            repo,
            branch,
            identity,
        } => check_plain_commit(&state, repo, branch, identity, &caller),
        Request::IssueToken { .. } => Response::Error {
            // A wrapper from before per-agent identities, which doesn't say
            // who is committing. Nobody's commit is signed as an
            // "unidentified agent" any more (identity review, 28 Oct 2026).
            message: "this git wrapper is older than the agent-sign service and doesn't say which agent is committing: run agent-sign's installer again to update it".to_string(),
        },
        Request::IssueIdentifiedToken {
            repo,
            branch,
            identity,
        } => issue_token(&state, repo, branch, identity, false, &caller),
        Request::IssueRunToken {
            repo,
            branch,
            identity,
        } => issue_token(&state, repo, branch, identity, true, &caller),
        Request::SignCommit {
            token,
            buffer_b64,
            repo,
            branch,
        } => {
            match sign_candidate(&state, &token, &buffer_b64, repo, branch, &caller) {
                Ok(signature_pem) => Response::Signed { signature_pem },
                Err(message) => Response::Error { message },
            }
        }
        Request::SignApproved {
            approval,
            approval_signature,
            buffer_b64,
            repo,
            branch,
        } => match sign_approved(
            &state,
            &approval,
            &approval_signature,
            &buffer_b64,
            &repo,
            &branch,
        ) {
            Ok(signature_pem) => Response::Signed { signature_pem },
            Err(message) => {
                eprintln!("[agent-signd] Refused an approved commit: {message}");
                Response::Error { message }
            }
        },
        Request::GetStatus { repo } => {
            let st = state.lock().unwrap();
            let (active, lease_id, branch, expires_in_secs) =
                st.lease_engine.get_status(&canonical_repo(&repo));
            Response::Status {
                active,
                lease_id,
                branch,
                expires_in_secs,
            }
        }
        Request::ListLeases => {
            // Every lease's work, so the listing shows only what's in force.
            end_all_finished_work(&state);
            let st = state.lock().unwrap();
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
            let result = if all {
                st.lease_engine.revoke_all_durable().map(|_| true)
            } else {
                match st.lease_engine.revoke_lease_durable(&repo) {
                    Ok(false) => st.lease_engine.revoke_lease_durable(&canonical_repo(&repo)),
                    result => result,
                }
            };
            match result {
                Ok(true) => Response::Success,
                Ok(false) => Response::Error { message: format!("no lease for '{repo}': give the repository's or folder's full path, or everywhere, as agent-sign leases shows it") },
                Err(message) => Response::Error { message },
            }
        }
    };

    let _ = send_response(stream, &response);
}

/// Drops commit tokens older than [`COMMIT_TOKEN_LIFETIME`] and run tokens
/// older than [`RUN_TOKEN_LIFETIME`].
fn prune_tokens(st: &mut DaemonState) {
    let now = Instant::now();
    st.valid_tokens
        .retain(|_, (created_at, _)| now.duration_since(*created_at) < COMMIT_TOKEN_LIFETIME);
    st.run_tokens
        .retain(|_, run| now.duration_since(run.issued) < RUN_TOKEN_LIFETIME);
}

/// The canonical path of a repository as a client named it, or the name
/// unchanged when it can't be resolved (it then matches no lease). Leases,
/// tokens and the rate window are all keyed by it, so a link to a repository
/// or a path with `..` in it is the same repository, with one lease and one
/// rate window (identity review, 28 Oct 2026).
fn canonical_repo(repo: &str) -> String {
    fs::canonicalize(repo)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| repo.to_string())
}

/// Whom a signature with `token` signs as, after checking that the git run
/// asking writes where the token allows: the repository and branch the
/// signing program reports must be the token's (a run token used to sign
/// anything for ten minutes, so `git rebase feature main` and `rebase --exec
/// 'cd /other && git commit'` made agent-signed commits on `main` and in
/// other repositories), the branch must not be protected, and for a run
/// token its lease must still be in force and the repository's rate window
/// not full (each signature counts). A single-use token is burned whatever
/// the answer.
fn consume_signature_token(
    st: &mut DaemonState,
    token: &str,
    repo: Option<String>,
    branch: Option<String>,
    caller: &Caller,
) -> Result<(RunToken, bool), String> {
    prune_tokens(st);
    // Who may use the token is checked before a single-use one is burned,
    // so a process that captured a session's token can't spoil it either.
    let held = st
        .valid_tokens
        .get(token)
        .map(|(_, terms)| terms)
        .or_else(|| st.run_tokens.get(token))
        .ok_or("Invalid, expired, or already consumed AGENT_EVENT_TOKEN")?;
    token_fits_caller(held, caller, &st.sessions)?;
    let (terms, run) = match st.valid_tokens.remove(token) {
        Some((_, terms)) => (terms, false),
        None => match st.run_tokens.get(token) {
            Some(run) => (run.clone(), true),
            None => return Err("Invalid, expired, or already consumed AGENT_EVENT_TOKEN".into()),
        },
    };
    let (Some(repo), Some(branch)) = (repo, branch) else {
        return Err("the signing program didn't identify its repository and branch".into());
    };
    if canonical_repo(&repo) != terms.repo || branch != terms.branch {
        return Err("this token signs only for its own repository and branch".into());
    }
    Ok((terms, run))
}

/// Whether `caller` may use a token with these `terms`: a launched
/// session's token only on that session's own channel while the session
/// lasts (bound to the session's id, not to the stream it was issued on: the
/// signing program asks on a stream of its own), and a plain token only on
/// the plain path.
fn token_fits_caller(
    terms: &RunToken,
    caller: &Caller,
    sessions: &HashMap<String, Arc<LiveSession>>,
) -> Result<(), String> {
    match (&terms.session, caller) {
        (None, Caller::Plain) => Ok(()),
        (Some(id), Caller::Session(session))
            if *id == session.id
                && !session.ended.load(Ordering::SeqCst)
                && sessions.contains_key(id) =>
        {
            Ok(())
        }
        (Some(_), _) => Err(
            "this token belongs to a launched session: it signs only on that session's own \
             channel, while the session lasts"
                .into(),
        ),
        (None, Caller::Session(_)) => {
            Err("a launched session signs only with tokens issued on its own channel".into())
        }
    }
}

fn sign_candidate(
    state: &Arc<Mutex<DaemonState>>,
    token: &str,
    encoded: &str,
    repo: Option<String>,
    branch: Option<String>,
    caller: &Caller,
) -> Result<String, String> {
    // Burn a one-use token even when candidate/config checking refuses it.
    let (terms, run, selected_config, system_config, names, other_live) = {
        let mut st = state.lock().unwrap();
        let (terms, run) = consume_signature_token(&mut st, token, repo, branch, caller)?;
        // System mode: the settings the service already holds (from
        // system.toml), with nothing read from, or run in, the repository.
        let system_config = st.system.then(|| st._config.clone());
        (
            terms,
            run,
            st.config_file.clone(),
            system_config,
            st.identity.clone(),
            // The other launched sessions running now, by principal.
            st.sessions
                .values()
                .map(|s| s.identity.principal.clone())
                .collect::<Vec<_>>(),
        )
    };
    let buffer = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| "candidate is not valid base64")?;
    check_committer(&buffer, &terms.identity.principal)?;
    // A launched session's commit must not be authored as a session running
    // now, or as a person's name: the launcher-attested certificate would
    // otherwise sit on a commit that reads as the person's or another live
    // agent's work (review finding F7). Any other author is fine, so a
    // replayed commit (cherry-pick, rebase, amend, `am`) keeps the author it
    // was written under, including an earlier session's.
    if terms.session.is_some() {
        check_author(&buffer, &terms.identity.principal, &names, &other_live)?;
    }
    let system = system_config.is_some();
    let config = match system_config {
        Some(config) => config,
        None => {
            Config::try_load_selected(selected_config.as_deref(), Some(Path::new(&terms.repo)))?
        }
    };
    if agent_sign::lease::branch_matches_blocked(
        &terms.branch,
        &config.security.repo_block_branches,
    ) {
        return Err("candidate branch is protected by the selected repository policy".into());
    }
    // The content rules (forbidden paths, diff size) are git runs in the
    // caller's repository. In system mode they run in the session's git
    // wrapper and at the merge gate instead (docs/system-mode.md, section 2).
    if !system {
        agent_sign::guardrails::validate_candidate(Path::new(&terms.repo), &config, &buffer)?;
    }
    // Complete all potentially blocking object/work reads before the last
    // time, generation and lease check and the actual signature. Only the
    // token's own lease is checked for finished work (an ended one is
    // refused below); the others are left to the listing and the sweep.
    end_finished_work_of(state, |st| {
        st.lease_engine
            .work_to_check(|lease| lease.id == terms.lease_id)
    });
    let mut st = state.lock().unwrap();
    if run {
        let current = st
            .lease_engine
            .find_lease(&terms.repo, &terms.branch)
            .ok_or("the signing lease has ended or was revoked")?;
        if current.id != terms.lease_id {
            return Err("the original signing lease was revoked or replaced".into());
        }
    }
    if st.lease_engine.is_branch_blocked(&terms.branch) {
        return Err(format!(
            "Branch '{}' is protected: no signature was made",
            terms.branch
        ));
    }
    let lifetime = if run {
        RUN_TOKEN_LIFETIME
    } else {
        COMMIT_TOKEN_LIFETIME
    };
    if terms.issued.elapsed() >= lifetime {
        return Err("token expired while checking its candidate".into());
    }
    let lease = st
        .lease_engine
        .find_lease(&terms.repo, &terms.branch)
        .ok_or("the signing lease has ended or was revoked")?;
    if lease.id != terms.lease_id {
        return Err("the original signing lease was revoked or replaced".into());
    }
    if let Some(id) = &terms.session
        && !st.sessions.contains_key(id)
    {
        return Err("the launched session ended before its commit was signed".into());
    }
    let st = &mut *st;
    let signer = match &terms.attestation {
        Some(attestation) => st.signers.signer_for_attested(
            st.ca.as_ref(),
            &terms.identity.principal,
            attestation,
        )?,
        None => st
            .signers
            .signer_for(st.ca.as_ref(), &terms.identity.principal)?,
    };
    signer.check_commit_date(&buffer)?;
    // Recorded as a use of the lease (its commit count and idle clock) only
    // now, once nothing can refuse the signature: a commit refused for its
    // date was recorded before (security review fix round, 31 Oct 2026, L8).
    if run {
        st.lease_engine
            .record_signature(&terms.repo, &terms.branch)?;
    }
    Ok(signer.sign_git_buffer(&buffer))
}

/// Refuses a commit `buffer` unless it has exactly one `committer` line and
/// that line's email is `principal`, the identity the signature is for (P2,
/// docs/caller-identity.md): a Good signature on a commit whose committer is
/// the person, or another agent, would read as theirs. The wrapper always
/// commits under the agent's own name and principal (see
/// `agent_sign::attribution::identity_env`), so only a hand-made request
/// is refused.
fn check_committer(buffer: &[u8], principal: &str) -> Result<(), String> {
    let email = one_ident_email(buffer, "committer")?;
    if email != Some(principal) {
        return Err(format!(
            "the commit's committer isn't {principal}, the agent this signature is for, so it \
             wasn't signed: an agent's commit names the agent as its committer"
        ));
    }
    Ok(())
}

/// Refuses a launched session's commit `buffer` when its one `author` line
/// names an identity the service knows to be someone else's right now: the
/// principal of another session running now (`other_live`), a person's
/// email address (the whole address is one of `policy`'s `person_emails`: the
/// `[human]` email and any `[identity] people` entry written as an address),
/// or a person's name (the local part of the email, slugged, is one of
/// `policy`'s people: the reserved names, `[identity] people`, the `[human]`
/// and the machine's accounts). All are compared folded the way names are
/// (case and look-alike forms don't get round it, NFKC then lowercase), and
/// with a plus-address `+tag` dropped from the local part first, so
/// `dana+x@example.org` is refused when `dana@example.org` is (P1, re-check
/// leftover). The
/// address check is what catches a person's address whose local part has no
/// ASCII letter or digit, which slugs to nothing, and the person's address
/// whatever the display name beside it says. The session's own principal passes.
/// A commit without exactly one author line, or an author with no email, is
/// refused, as `check_committer` does for the committer.
///
/// Why only that, and not "the author must be the session" (this rule's
/// first form, review finding F7): a session also replays other work
/// (cherry-pick, rebase, amend, `am`), which keeps each commit's original
/// author and names the agent only as committer; and every new session has a
/// new principal, so an agent that rebases or amends its own earlier
/// session's commits replays another principal's authorship as a matter of
/// course. Requiring the session as author refused all of it. What the review
/// asked to stop is a signature sitting on a commit that reads as the
/// person's or as another agent's own work being made right now, and that is
/// an author who is a live session or a person. An ended session's principal
/// is just history and passes. The display name is free.
fn check_author(
    buffer: &[u8],
    principal: &str,
    policy: &IdentityPolicy,
    other_live: &[String],
) -> Result<(), String> {
    use agent_sign::attribution::{normalize_name, slug_of, without_plus_tag};
    let Some(email) = one_ident_email(buffer, "author")? else {
        return Err("the commit's author has no email, so it wasn't signed".into());
    };
    if email == principal {
        return Ok(());
    }
    let folded = normalize_name(email);
    // Plus-addressing (`dana+x@...`) is the same mailbox as `dana@...`, so the
    // tag is stripped before the name-slug check (`person_email` strips it for
    // the whole-address check).
    let untagged = without_plus_tag(&folded);
    let local = untagged
        .rsplit_once('@')
        .map_or(untagged.as_str(), |(l, _)| l);
    let claims_a_live_session = other_live.iter().any(|p| normalize_name(p) == folded);
    let claims_a_person_email = policy.person_email(email).is_some();
    let claims_a_person = policy.person(&slug_of(local)).is_some();
    if claims_a_live_session || claims_a_person_email || claims_a_person {
        return Err(format!(
            "the commit's author is {email}, which is {}, not {principal}, the session this \
             signature is for, so it wasn't signed: a session's commit names the session (or \
             someone who isn't a session running now or a person this machine knows) as its \
             author",
            if claims_a_live_session {
                "another running session's identity"
            } else if claims_a_person_email {
                "a person's email address"
            } else {
                "a person's name"
            },
        ));
    }
    Ok(())
}

/// The email of the commit's one `role` line (`author` or `committer`), read
/// from the headers only (the text before the first blank line). `None` for a
/// line with no `<email>`; an error when the commit isn't UTF-8 or doesn't
/// have exactly one such line.
fn one_ident_email<'a>(buffer: &'a [u8], role: &str) -> Result<Option<&'a str>, String> {
    let text = std::str::from_utf8(buffer).map_err(|_| "the commit isn't UTF-8")?;
    let headers = text.split_once("\n\n").map_or(text, |(h, _)| h);
    let prefix = format!("{role} ");
    let mut lines = headers.split('\n').filter_map(|l| l.strip_prefix(&prefix));
    let (Some(line), None) = (lines.next(), lines.next()) else {
        return Err(format!(
            "the commit doesn't have exactly one {role} line, so it wasn't signed"
        ));
    };
    Ok(line
        .split_once('<')
        .and_then(|(_, rest)| rest.split_once('>'))
        .map(|(email, _)| email))
}

/// Whether the plain path (a token of today's git wrapper) is signing as
/// `principal` in this run: a token for it is outstanding, or its session
/// signer is held. The approval path refuses such a principal, so one name
/// is never claimed one way and established another.
fn plain_path_holds(st: &DaemonState, principal: &str) -> bool {
    st.signers.holds(principal)
        || st
            .valid_tokens
            .values()
            .any(|(_, t)| t.identity.principal == principal)
        || st
            .run_tokens
            .values()
            .any(|t| t.identity.principal == principal)
}

/// Signs the commit in `buffer_b64` as the agent a commit approval names
/// (see the module documentation and `agent_sign::commit_approval`). Every
/// check that needs no service state runs first, without the lock; then,
/// under the lock, the branch, the principal and the nonce are checked, the
/// nonce is recorded and synced to disk, and only then is the signature
/// made, with a one-off key whose certificate records the approval's hash.
/// A refusal before that leaves the approval unused.
fn sign_approved(
    state: &Arc<Mutex<DaemonState>>,
    approval: &str,
    approval_signature: &str,
    buffer_b64: &str,
    repo: &str,
    branch: &str,
) -> Result<String, String> {
    let (key, machine, policy, selected_config) = {
        let st = state.lock().unwrap();
        let Some(path) = &st.approvals else {
            return Err(
                "the approval path is off: agent-sign's config sets no [approvals] \
                 commitments_key"
                    .into(),
            );
        };
        (
            path.key.clone(),
            path.machine.clone(),
            st.identity.clone(),
            st.config_file.clone(),
        )
    };
    let buffer = base64::engine::general_purpose::STANDARD
        .decode(buffer_b64)
        .map_err(|_| "the commit is not valid base64")?;
    let canonical = fs::canonicalize(repo)
        .map(|p| p.to_string_lossy().into_owned())
        .map_err(|_| format!("approval refused: the working copy {repo:?} doesn't exist"))?;
    let approved = agent_sign::commit_approval::check(
        &agent_sign::commit_approval::Context {
            key: &key,
            machine: &machine,
            policy: &policy,
            now: agent_sign::agents_ca::now_secs(),
        },
        &agent_sign::commit_approval::Presented {
            text: approval,
            signature: approval_signature,
            buffer: &buffer,
            repo: &canonical,
            branch,
        },
    )?;
    // The repository's own protected branches (its file can only add some).
    let config =
        Config::try_load_selected(selected_config.as_deref(), Some(Path::new(&canonical)))?;
    if agent_sign::lease::branch_matches_blocked(branch, &config.security.repo_block_branches) {
        return Err(format!(
            "approval refused: branch '{branch}' is protected by the repository's policy"
        ));
    }

    let mut st = state.lock().unwrap();
    if st.lease_engine.is_branch_blocked(branch) {
        return Err(format!("approval refused: branch '{branch}' is protected"));
    }
    let principal = approved.approval.principal.as_str();
    if plain_path_holds(&st, principal) {
        return Err(format!(
            "approval refused: {principal} is signing through the git wrapper's plain path in \
             this run, so an approval can't name it too"
        ));
    }
    if st.launched.contains(principal) {
        return Err(format!(
            "approval refused: {principal} is a launched session's name, so an approval can't \
             name it too"
        ));
    }
    let st = &mut *st;
    let path = st.approvals.as_mut().ok_or("the approval path is off")?;
    if path.store.is_used(&approved.approval.nonce) {
        return Err("approval refused: it was already used".into());
    }
    let attestation = Attestation::Approval {
        sha256: approved.sha256.clone(),
    };
    let signer = SessionSigner::attested(
        st.ca.as_ref(),
        principal,
        agent_sign::agents_ca::now_secs(),
        &attestation,
    )?;
    signer.check_commit_date(&buffer)?;
    path.store.record(
        &approved.approval.nonce,
        approved.approval.expires_at,
        principal,
    )?;
    eprintln!(
        "[agent-signd] An approved commit signs as {principal} in {canonical:?} on branch \
         '{branch}' (approval sha256 {})",
        approved.sha256
    );
    Ok(signer.sign_git_buffer(&buffer))
}

/// Issues a token that signs as `identity` in `repo` on `branch`: a
/// single-use one for a commit, or (`run`) one for every commit a git run
/// makes. Either needs a lease in force for the repository and branch, which
/// also applies the branch rules and the rate limit, and every one issued is
/// logged: the record of which identity committed where.
fn issue_token(
    state: &Arc<Mutex<DaemonState>>,
    repo: String,
    branch: String,
    identity: AgentIdentity,
    run: bool,
    caller: &Caller,
) -> Response {
    // A launched session signs as itself, and only as itself: the identity
    // it names must be the one the service gave it.
    if let Caller::Session(session) = caller
        && identity != session.identity
    {
        return Response::Error {
            message: format!(
                "agent identity refused: a launched session signs only as itself ({}), and this \
                 request named {}",
                session.identity.principal, identity.principal
            ),
        };
    }
    let policy = state.lock().unwrap().identity.clone();
    if let Err(message) = policy.check(&identity) {
        return Response::Error { message };
    }
    let repo = canonical_repo(&repo);
    // End the lease this token would be issued under if its work is
    // finished, then any wider one found next; only these, as for a lease
    // request.
    while end_finished_work_of(state, |st| {
        let engine = &st.lease_engine;
        let in_use = engine
            .find_lease(&repo, &branch)
            .map(|lease| lease.id.clone());
        engine.work_to_check(|lease| Some(&lease.id) == in_use.as_ref())
    }) > 0
    {}
    let mut st = state.lock().unwrap();
    prune_tokens(&mut st);
    if let Some(message) = name_held_elsewhere(&st, &identity, caller) {
        return Response::Error { message };
    }
    // S8 (P7, D1): the plain path, where the caller names itself, gets no
    // identity token. The name rules above ran first, so a refusal that
    // names allowed_agents or a person keeps its wording; only then is the
    // caller refused for not being a launched session.
    if matches!(caller, Caller::Plain) {
        return Response::Error {
            message: format!(
                "no token for {}: agent-sign signs an agent's commit only for a session a \
                 launcher started (`agent-sign launch --agent <name> -- <program>`), and this \
                 caller isn't one. Its commit goes through unsigned instead",
                identity.principal
            ),
        };
    }
    let (session, attestation) = match caller {
        Caller::Session(s) => (Some(s.id.clone()), Some(s.attestation.clone())),
        Caller::Plain => (None, None),
    };
    let issued = if run {
        st.lease_engine.issue_run_token(&repo, &branch)
    } else {
        st.lease_engine.issue_commit_token(&repo, &branch)
    };
    match issued {
        Ok(token) => {
            eprintln!(
                "[agent-signd] {} signs as {} in {repo} on branch '{branch}'",
                if run { "A git run" } else { "A commit" },
                identity.principal
            );
            let Some(lease_id) = st
                .lease_engine
                .find_lease(&repo, &branch)
                .map(|l| l.id.clone())
            else {
                return Response::Error {
                    message: "lease expired before its token could be issued".into(),
                };
            };
            let terms = RunToken {
                identity,
                repo,
                branch,
                lease_id,
                issued: Instant::now(),
                session,
                attestation,
            };
            if run {
                st.run_tokens.insert(token.clone(), terms);
            } else {
                st.valid_tokens
                    .insert(token.clone(), (Instant::now(), terms));
            }
            Response::TokenIssued { token }
        }
        Err(e) => Response::Error { message: e },
    }
}

/// Why `identity`'s name can't be used by this caller, when another path
/// holds it: a principal an approval was signed for is the approval path's
/// alone, and a launched session's name is that session's alone (the plain
/// path, where the caller names itself, never signs as either). Checked
/// under the same lock hold that stores a token, so an approval recorded
/// meanwhile can't slip between the check and the token.
fn name_held_elsewhere(
    st: &DaemonState,
    identity: &AgentIdentity,
    caller: &Caller,
) -> Option<String> {
    if st
        .approvals
        .as_ref()
        .is_some_and(|a| a.store.was_approved(&identity.principal))
    {
        return Some(format!(
            "agent identity refused: {} was named by a commit approval, so only an \
             approval signs as it",
            identity.principal
        ));
    }
    if matches!(caller, Caller::Plain) && st.launched.contains(&identity.principal) {
        return Some(format!(
            "agent identity refused: {} is a launched session's name, so only that session, \
             through its own channel, signs as it",
            identity.principal
        ));
    }
    None
}

/// The longest repository path a plain-path check is kept for: Linux's own
/// `PATH_MAX`. The check's rate window is keyed by the path, and in system
/// mode the service cannot tell whether a path exists, so without a bound a
/// caller could make each window as big as a request line (review finding
/// F5; see `agent_sign::lease::MAX_RATE_WINDOWS` for the count bound).
const MAX_REPO_PATH_BYTES: usize = 4096;

/// Answers [`Request::CheckPlainCommit`] (D1): the policy-only question the
/// wrapper asks for a commit by an agent nobody launched, which goes through
/// unsigned. The same name rules as a token, then the protected branches and
/// the rate limit (counting the commit), and nothing is issued: no lease, no
/// token, no signature. A launched session's channel is refused before this
/// runs (`allowed_from_session`), and a session's own commits sign instead.
fn check_plain_commit(
    state: &Arc<Mutex<DaemonState>>,
    repo: String,
    branch: String,
    identity: AgentIdentity,
    caller: &Caller,
) -> Response {
    if !matches!(caller, Caller::Plain) {
        return Response::Error {
            message: "a launched session's commits are signed, not checked as unsigned".into(),
        };
    }
    let policy = state.lock().unwrap().identity.clone();
    if let Err(message) = policy.check(&identity) {
        return Response::Error { message };
    }
    if !Path::new(&repo).is_absolute()
        || has_unsafe_display_chars(&repo)
        || has_unsafe_display_chars(&branch)
        || repo.len() > MAX_REPO_PATH_BYTES
    {
        return Response::Error {
            message: format!(
                "couldn't identify the repository (it isn't a full path of at most \
                 {MAX_REPO_PATH_BYTES} bytes, or it or the branch has control or invisible \
                 characters)"
            ),
        };
    }
    let repo = canonical_repo(&repo);
    let system = state.lock().unwrap().system;
    // In system mode the service doesn't open the repository (it can't see
    // `/home`): it judges the branch the wrapper reports. That costs
    // nothing, because a plain commit gets no signature.
    if !system && !Path::new(&repo).join(".git").exists() {
        return Response::Error {
            message: format!(
                "couldn't identify the repository ('{repo}' isn't an existing git working tree)"
            ),
        };
    }
    let mut st = state.lock().unwrap();
    if let Some(message) = name_held_elsewhere(&st, &identity, caller) {
        return Response::Error { message };
    }
    match st.lease_engine.check_unsigned_commit(&repo, &branch) {
        Ok(()) => {
            eprintln!(
                "[agent-signd] An unsigned commit by {} (no launcher started it) in {repo} on \
                 branch '{branch}'",
                identity.principal
            );
            Response::Success
        }
        Err(message) => Response::Error { message },
    }
}

/// System mode's certificate issuer (docs/system-mode.md, section 5): the
/// OpenBao adapter, wired in at build step 2. It still fails closed: while
/// the login isn't loaded (`$CREDENTIALS_DIRECTORY`, which the unit's
/// `LoadCredentialEncrypted=` sets) or the settings can't be used, a closed
/// stand-in refuses every signature; and the adapter itself signs nothing
/// until OpenBao's authority matches the root-owned trust file. Never the
/// in-memory authority. The first check against OpenBao runs in the
/// background, so an OpenBao that is down never delays the start.
fn system_issuer(
    settings: &agent_sign::system_config::OpenBaoSettings,
    system: &agent_sign::system_config::SystemConfig,
) -> Box<dyn CertificateIssuer> {
    let closed = |why: String| -> Box<dyn CertificateIssuer> {
        eprintln!(
            "[agent-signd] system mode: every signature is refused: {why}; plain-path questions \
             are answered"
        );
        Box::new(agent_sign::system_config::ClosedIssuer::new(format!(
            "system mode: nothing is signed: {why}"
        )))
    };
    let Some(credentials) = std::env::var_os("CREDENTIALS_DIRECTORY").filter(|v| !v.is_empty())
    else {
        return closed(
            "the OpenBao login isn't loaded ($CREDENTIALS_DIRECTORY isn't set; the service's \
             unit loads it with LoadCredentialEncrypted=)"
                .into(),
        );
    };
    let adapter = agent_sign::issuer_openbao::Settings {
        address: settings.address.clone(),
        resolve: settings.resolve.clone().unwrap_or_default(),
        ca_cert: PathBuf::from(&settings.ca_cert),
        mount: settings.mount.clone(),
        role: settings.role.clone(),
        machine: system.machine.clone(),
        trust_file: system.service.trust_file.clone(),
        credentials_dir: PathBuf::from(credentials),
    };
    match agent_sign::issuer_openbao::OpenBaoIssuer::new(&adapter) {
        Err(why) => closed(why),
        Ok(issuer) => {
            eprintln!(
                "[agent-signd] system mode: the issuer is OpenBao ({}, mount {}, role {})",
                settings.address, settings.mount, settings.role
            );
            let issuer = Arc::new(issuer);
            let checking = Arc::clone(&issuer);
            std::thread::spawn(move || match checking.ready() {
                Ok(()) => eprintln!(
                    "[agent-signd] system mode: OpenBao's certificate authority matches the trust \
                     file; launched sessions' commits are signed through it"
                ),
                Err(why) => eprintln!(
                    "[agent-signd] system mode: OpenBao can't sign yet: {why}. It is tried again \
                     at each signature"
                ),
            });
            Box::new(SharedIssuer(issuer))
        }
    }
}

/// The OpenBao adapter, shared with the background check `system_issuer`
/// starts.
struct SharedIssuer(Arc<agent_sign::issuer_openbao::OpenBaoIssuer>);

impl CertificateIssuer for SharedIssuer {
    fn public_key_openssh(&self) -> String {
        self.0.public_key_openssh()
    }

    fn issue(
        &self,
        principal: &str,
        subject: &ed25519_dalek::VerifyingKey,
        now: u64,
        attestation: Option<&Attestation>,
    ) -> Result<ssh_key::Certificate, String> {
        self.0.issue(principal, subject, now, attestation)
    }
}

/// System mode's two sockets, when systemd made them and started this
/// service with them (`LISTEN_PID`, `LISTEN_FDS`, `LISTEN_FDNAMES`): the
/// ordinary one named `daemon` and the launcher-only one named `launcher`
/// (`FileDescriptorName=` in `agent-signd.socket` and
/// `agent-signd-launcher.socket`). `Ok(None)` when systemd passed none to
/// this process: the service then makes them itself. An error when it passed
/// anything but exactly those two listening Unix stream sockets, since a
/// socket of unknown purpose must never be served as either. The variables
/// are removed, so no program the service runs inherits them; this runs
/// before any other thread exists.
#[cfg(target_os = "linux")]
fn activated_sockets() -> Result<Option<(UnixListener, UnixListener)>, String> {
    use std::os::fd::{FromRawFd, RawFd};
    let Ok(pid) = std::env::var("LISTEN_PID") else {
        return Ok(None);
    };
    if pid.trim().parse::<u32>().ok() != Some(std::process::id()) {
        return Ok(None);
    }
    let count: usize = std::env::var("LISTEN_FDS")
        .ok()
        .and_then(|n| n.trim().parse().ok())
        .ok_or("systemd set LISTEN_PID but no readable LISTEN_FDS")?;
    let names: Vec<String> = std::env::var("LISTEN_FDNAMES")
        .unwrap_or_default()
        .split(':')
        .map(str::to_string)
        .collect();
    // SAFETY: called at start, before this process starts any thread, so
    // nothing reads the environment meanwhile.
    unsafe {
        std::env::remove_var("LISTEN_PID");
        std::env::remove_var("LISTEN_FDS");
        std::env::remove_var("LISTEN_FDNAMES");
    }
    let mut daemon = None;
    let mut launcher = None;
    for i in 0..count {
        let fd = 3 + i as RawFd;
        let name = names.get(i).map(String::as_str).unwrap_or("");
        let option = |opt: libc::c_int| -> Option<libc::c_int> {
            let mut value: libc::c_int = 0;
            let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
            // SAFETY: getsockopt writes at most `len` bytes into `value`.
            let rc = unsafe {
                libc::getsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    opt,
                    &mut value as *mut libc::c_int as *mut libc::c_void,
                    &mut len,
                )
            };
            (rc == 0).then_some(value)
        };
        if option(libc::SO_DOMAIN) != Some(libc::AF_UNIX)
            || option(libc::SO_TYPE) != Some(libc::SOCK_STREAM)
            || option(libc::SO_ACCEPTCONN) != Some(1)
        {
            return Err(format!(
                "systemd passed descriptor {fd} ({name:?}), which isn't a listening Unix stream \
                 socket"
            ));
        }
        // SAFETY: systemd passed this descriptor to this process, and
        // nothing else here owns it.
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        // SAFETY: fcntl on the descriptor just taken.
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFD);
            if flags >= 0 {
                libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC);
            }
        }
        let slot = match name {
            "daemon" => &mut daemon,
            "launcher" => &mut launcher,
            other => {
                return Err(format!(
                    "systemd passed a socket named {other:?}; the service takes only `daemon` \
                     and `launcher`"
                ));
            }
        };
        if slot.is_some() {
            return Err(format!("systemd passed two sockets named {name:?}"));
        }
        *slot = Some(UnixListener::from(owned));
    }
    match (daemon, launcher) {
        (Some(d), Some(l)) => Ok(Some((d, l))),
        _ => Err(
            "systemd passed sockets, but not both `daemon` and `launcher` (agent-signd.socket \
             and agent-signd-launcher.socket)"
                .into(),
        ),
    }
}

/// No socket activation off Linux.
#[cfg(not(target_os = "linux"))]
fn activated_sockets() -> Result<Option<(UnixListener, UnixListener)>, String> {
    Ok(None)
}

/// Who is on the other end of a connection on the ordinary socket. In
/// one-account mode always the plain path (a session comes in over its
/// channel instead). In system mode, by the kernel's facts alone
/// (`agent_sign::kernel_facts::judge`): a registered session only when the
/// uid, the unit's cgroup and the live process all match; an error, and no
/// answer to the request, when the process that connected is gone (or the
/// kernel wouldn't say). The facts are read without the state lock; the
/// sessions are matched under it.
fn identify(state: &Arc<Mutex<DaemonState>>, stream: &UnixStream) -> Result<Caller, String> {
    let kernel = state.lock().unwrap().kernel.clone();
    let Some(kernel) = kernel else {
        return Ok(Caller::Plain);
    };
    let facts = kernel
        .peer(stream)
        .map_err(|e| format!("couldn't tell who is asking ({e}), so the request is refused"))?;
    let st = state.lock().unwrap();
    let live = st.sessions.values().filter_map(|s| {
        let binding = s.slot.as_ref()?;
        (!s.ended.load(Ordering::SeqCst)).then_some(LiveSlot {
            session: &s.id,
            uid: binding.uid,
            unit: &binding.unit,
        })
    });
    match agent_sign::kernel_facts::judge(&facts, live) {
        Judgement::Session(id) => Ok(st
            .sessions
            .get(&id)
            .map_or(Caller::Plain, |s| Caller::Session(Arc::clone(s)))),
        Judgement::Plain => Ok(Caller::Plain),
        Judgement::Refused(message) => Err(message),
    }
}

/// Refuses a registration on the launcher-only socket, saying why, in the
/// log too.
fn refuse_registration(stream: &mut UnixStream, message: String) {
    eprintln!("[agent-signd] Refused a session registration: {message}");
    let _ = send_response(stream, &Response::Error { message });
}

/// The longest registration line read on the launcher-only socket.
const MAX_REGISTRATION_BYTES: u64 = 64 * 1024;

/// Serves one connection on the launcher-only socket (system mode): one
/// request, from the `[launcher] account`'s uid as the kernel reports it,
/// and only `RegisterSession` (or `Ping`). A registration that passes every
/// check is answered with the principal and held: the session lasts while
/// the launcher keeps the connection open, and ends when it closes.
fn serve_launcher(mut stream: UnixStream, state: Arc<Mutex<DaemonState>>) {
    let (kernel, policy, never) = {
        let st = state.lock().unwrap();
        (
            st.kernel.clone(),
            st.slots.clone(),
            st.never_slot_uids.clone(),
        )
    };
    let (Some(kernel), Some(policy)) = (kernel, policy) else {
        return;
    };
    // One line, and at most MAX_REGISTRATION_BYTES of it: a registration is
    // a few hundred bytes, and nothing that connects may grow this memory.
    // It also has the whole-request deadline, so a connection that sends
    // nothing, or drips, cannot hold its thread.
    let Some(line) = read_request_line(&stream, MAX_REGISTRATION_BYTES, REQUEST_READ_DEADLINE)
    else {
        return;
    };
    if !line.ends_with('\n') {
        return;
    }
    // Who asks, by the kernel's uid: the launcher's account and no other.
    let facts = match kernel.peer(&stream) {
        Ok(facts) => facts,
        Err(e) => {
            refuse_registration(&mut stream, format!("couldn't tell who asked ({e})"));
            return;
        }
    };
    if facts.process == Liveness::Gone {
        refuse_registration(
            &mut stream,
            "the process that asked has already ended".into(),
        );
        return;
    }
    let launcher_uid = match kernel.account_uid(&policy.launcher_account) {
        Ok(Some(uid)) => uid,
        Ok(None) => {
            refuse_registration(
                &mut stream,
                format!(
                    "[launcher] account, {}, isn't an account on this machine",
                    policy.launcher_account
                ),
            );
            return;
        }
        Err(e) => {
            refuse_registration(&mut stream, e);
            return;
        }
    };
    if facts.uid != launcher_uid {
        refuse_registration(
            &mut stream,
            format!(
                "only the launcher's account, {} (uid {launcher_uid}), registers sessions, and \
                 uid {} asked",
                policy.launcher_account, facts.uid
            ),
        );
        return;
    }
    let request: Request = match serde_json::from_str(&line) {
        Ok(request) => request,
        Err(e) => {
            refuse_registration(&mut stream, e.to_string());
            return;
        }
    };
    let (asked, agent) = match request {
        Request::Ping => {
            let _ = send_response(&mut stream, &Response::Pong);
            return;
        }
        Request::RegisterSession {
            slot,
            uid,
            unit,
            agent,
        } => (RegistrationAsked { slot, uid, unit }, agent),
        _ => {
            refuse_registration(
                &mut stream,
                "the launcher-only socket takes only RegisterSession".into(),
            );
            return;
        }
    };
    let mut never = never;
    never.push(launcher_uid);
    let binding =
        match agent_sign::kernel_facts::check_registration(&asked, &policy, &*kernel, &never) {
            Ok(binding) => binding,
            Err(message) => {
                refuse_registration(&mut stream, message);
                return;
            }
        };
    let Some((slug, name)) = agent_sign::attribution::named_agent(&agent) else {
        refuse_registration(&mut stream, "no agent name was given".into());
        return;
    };
    let (slot, uid, unit) = (binding.slot, binding.uid, binding.unit.clone());
    let session = match start_session(&state, &slug, &name, uid, Some(binding)) {
        Ok((session, _)) => session,
        Err(message) => {
            refuse_registration(&mut stream, message);
            return;
        }
    };
    eprintln!(
        "[agent-signd] Registered session {} in slot {slot} (uid {uid}, {unit}): signs as {}, \
         in an account of its own",
        session.id, session.identity.principal
    );
    let answer = Response::SessionStarted {
        principal: session.identity.principal.clone(),
        session: session.id.clone(),
    };
    if send_response(&mut stream, &answer).is_err() {
        end_session(&state, &session);
        return;
    }
    // The registration: the session lasts while the launcher keeps this
    // connection open. Anything it sends is ignored.
    let mut buf = [0u8; 256];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(_) => continue,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    end_session(&state, &session);
}

/// Whether a launched session is still in progress.
fn session_live(state: &Arc<Mutex<DaemonState>>, session: &LiveSession) -> bool {
    !session.ended.load(Ordering::SeqCst)
        && state.lock().unwrap().sessions.contains_key(&session.id)
}

/// What a launched session's channel takes: its own commits' requests, and
/// nothing else. Leases are listed, revoked and denied by the person, on the
/// service's socket, never from inside a session; an approval is presented
/// by the job runner that holds it (it names another principal, never the
/// session's own), and a session starting another session is refused.
fn allowed_from_session(request: &Request) -> bool {
    matches!(
        request,
        Request::Ping
            | Request::SessionIdentity
            | Request::RequestLease { .. }
            | Request::IssueIdentifiedToken { .. }
            | Request::IssueRunToken { .. }
            | Request::SignCommit { .. }
    )
}

/// Refuses a `LaunchSession` on `stream`, saying why, in the log too.
fn refuse_session(stream: &mut UnixStream, message: String) {
    eprintln!("[agent-signd] Refused to launch a session: {message}");
    let _ = send_response(stream, &Response::Error { message });
}

/// Starts a launched session for `agent` (see the module documentation),
/// answers with its channel attached, serves the channel, and holds the
/// session until the launcher's registration (`stream`) closes. Off Linux
/// there are no PID namespaces to keep a session apart from other processes
/// (see `agent_sign::launch`), so no session is started there.
fn launch_session(
    stream: &mut UnixStream,
    state: &Arc<Mutex<DaemonState>>,
    agent: &str,
    slot: &mut Option<ConnectionSlot>,
) {
    if cfg!(not(target_os = "linux")) {
        refuse_session(
            stream,
            "launched sessions need Linux PID namespaces, and this system has none, so \
             agent-sign makes no attested session here"
                .into(),
        );
        return;
    }
    if let Some(path) = agent_sign::launch::system_config() {
        refuse_session(stream, agent_sign::launch::system_mode_refusal(&path));
        return;
    }
    // SAFETY: getuid takes no arguments and can't fail.
    let own = unsafe { libc::getuid() };
    match agent_sign::session::peer_uid(stream.as_raw_fd()) {
        Ok(uid) if uid == own => {}
        Ok(uid) => {
            refuse_session(
                stream,
                format!(
                    "in one-account mode only the service's own account launches sessions, and \
                     uid {uid} asked"
                ),
            );
            return;
        }
        Err(e) => {
            refuse_session(stream, format!("couldn't tell who asked ({e})"));
            return;
        }
    }
    // A launched session (in a PID namespace of its own) can't start another
    // one, which would let it pick itself a new name.
    match agent_sign::session::peer_in_other_pid_namespace(stream.as_raw_fd()) {
        Ok(false) => {}
        Ok(true) => {
            refuse_session(
                stream,
                "a launched session can't launch another session: only a process outside any \
                 sandbox launches"
                    .into(),
            );
            return;
        }
        Err(e) => {
            refuse_session(
                stream,
                format!("couldn't tell where the request came from ({e})"),
            );
            return;
        }
    }
    let Some((slug, name)) = agent_sign::attribution::named_agent(agent) else {
        refuse_session(stream, "no agent name was given (--agent)".into());
        return;
    };
    let (session, client_end) = match start_session(state, &slug, &name, own, None) {
        Ok((session, Some(client_end))) => (session, client_end),
        Ok((session, None)) => {
            end_session(state, &session);
            refuse_session(stream, "the session's channel wasn't made".into());
            return;
        }
        Err(message) => {
            refuse_session(stream, message);
            return;
        }
    };
    eprintln!(
        "[agent-signd] Launched session {} signs as {} (uid {own}, one account: isolated from \
         other launched sessions, not from other processes of this account)",
        session.id, session.identity.principal
    );
    let answer = match serde_json::to_string(&Response::SessionStarted {
        principal: session.identity.principal.clone(),
        session: session.id.clone(),
    }) {
        Ok(json) => format!("{json}\n"),
        Err(_) => {
            end_session(state, &session);
            return;
        }
    };
    if agent_sign::session::send_with_fd(
        stream.as_raw_fd(),
        answer.as_bytes(),
        client_end.as_raw_fd(),
    )
    .is_err()
    {
        end_session(state, &session);
        return;
    }
    drop(client_end);
    {
        let state = Arc::clone(state);
        let session = Arc::clone(&session);
        std::thread::spawn(move || serve_channel(state, session));
    }
    // The registration: the session lasts while the launcher keeps this
    // connection open. Anything it sends is ignored. It holds a thread and a
    // 256-byte buffer for as long as the session lives, not a request, and
    // only the service's own account can open one (checked above), so it
    // gives its place in the connection limit back: otherwise the sessions
    // open at once would be capped at the limit.
    drop(slot.take());
    let mut buf = [0u8; 256];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(_) => continue,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    end_session(state, &session);
}

/// Draws a new session for `slug` (display `name`) under the lock: its id,
/// a principal no session, approval or plain-path signer has had, after the
/// name rules; records its start in `sessions.log`, synced; and, in
/// one-account mode (`slot` is `None`), makes its channel. Returns the
/// session and the channel's end for the launcher. A slot session (system
/// mode) has no channel, and is refused while its slot or its account's uid
/// has a live session: checked under the same lock hold that records it, so
/// two registrations can't both take a slot.
fn start_session(
    state: &Arc<Mutex<DaemonState>>,
    slug: &str,
    name: &str,
    uid: u32,
    slot: Option<SlotBinding>,
) -> Result<(Arc<LiveSession>, Option<OwnedFd>), String> {
    let mut st = state.lock().unwrap();
    if let Some(binding) = &slot
        && st.sessions.values().any(|s| {
            s.slot
                .as_ref()
                .is_some_and(|b| b.slot == binding.slot || b.uid == binding.uid)
        })
    {
        return Err(format!(
            "slot {} already has a live session: its registration must close first",
            binding.slot
        ));
    }
    let mut drawn = None;
    for _ in 0..16 {
        let id = agent_sign::session::new_session_id();
        let identity = AgentIdentity::new(slug, name, Some(&id)).in_domain(&st.identity.domain);
        // The name rules first: a reserved or person's name, or one not
        // allowed, gets no session and the program never runs.
        st.identity.check(&identity)?;
        let principal = identity.principal.as_str();
        let used = st.launched.contains(principal)
            || plain_path_holds(&st, principal)
            || st
                .approvals
                .as_ref()
                .is_some_and(|a| a.store.was_approved(principal));
        if !used {
            drawn = Some((id, identity));
            break;
        }
    }
    let (id, identity) = drawn.ok_or("couldn't draw a session name never used before")?;
    st.session_log
        .append("start", &id, &identity.principal, uid)
        .map_err(|e| {
            format!("couldn't record the session in sessions.log ({e}), so none was started")
        })?;
    let (service_end, client_end, isolation) = match &slot {
        Some(_) => (None, None, Isolation::SlotAccount),
        None => {
            let (service_end, client_end) = agent_sign::session::seqpacket_pair()
                .map_err(|e| format!("couldn't make the session's channel ({e})"))?;
            (Some(service_end), Some(client_end), Isolation::PidNamespace)
        }
    };
    let session = Arc::new(LiveSession {
        attestation: Attestation::Launcher {
            session: id.clone(),
            uid,
            isolation,
        },
        id,
        identity,
        channel: service_end,
        slot,
        uid,
        ended: AtomicBool::new(false),
    });
    st.launched.insert(session.identity.principal.clone());
    st.sessions.insert(session.id.clone(), Arc::clone(&session));
    Ok((session, client_end))
}

/// Serves a launched session's channel: every stream a process of the
/// session sends over it is answered as that session, until the session
/// ends (its channel is then shut, and this returns).
fn serve_channel(state: Arc<Mutex<DaemonState>>, session: Arc<LiveSession>) {
    let Some(fd) = session.channel.as_ref().map(|c| c.as_raw_fd()) else {
        return;
    };
    let limit = ConnectionLimit::new(MAX_CHANNEL_CONNECTIONS, MAX_CHANNEL_CONNECTIONS);
    loop {
        let mut buf = [0u8; 1];
        match agent_sign::session::recv_with_fd(fd, &mut buf) {
            Ok((0, None)) | Err(_) => break,
            Ok((_, None)) => continue,
            Ok((_, Some(stream_fd))) => {
                if session.ended.load(Ordering::SeqCst) {
                    break;
                }
                if !is_socket(&stream_fd) {
                    continue;
                }
                let stream = UnixStream::from(stream_fd);
                let state = Arc::clone(&state);
                let caller = Caller::Session(Arc::clone(&session));
                spawn_connection(
                    "session channel",
                    &limit,
                    stream,
                    move |mut stream, slot| handle_client(&mut stream, state, caller, slot),
                );
            }
        }
    }
}

/// Whether `fd` is a socket (a session sends the service one end of a
/// stream pair; anything else is ignored).
fn is_socket(fd: &OwnedFd) -> bool {
    // SAFETY: an all-zero stat is a valid buffer for fstat to fill.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: fstat on a descriptor this process owns.
    unsafe {
        libc::fstat(fd.as_raw_fd(), &mut st) == 0 && (st.st_mode & libc::S_IFMT) == libc::S_IFSOCK
    }
}

/// Ends a launched session: its channel is shut (so every later request on
/// it is refused, and a process that outlived the launcher keeps a dead
/// channel), its tokens and key are dropped, and the end is logged. Its
/// principal stays in `launched`, so it is never drawn or signed again.
fn end_session(state: &Arc<Mutex<DaemonState>>, session: &LiveSession) {
    session.ended.store(true, Ordering::SeqCst);
    if let Some(channel) = &session.channel {
        // SAFETY: shutdown on the service's own end of the channel, which
        // the session still holds open.
        unsafe {
            libc::shutdown(channel.as_raw_fd(), libc::SHUT_RDWR);
        }
    }
    let mut st = state.lock().unwrap();
    st.sessions.remove(&session.id);
    st.valid_tokens
        .retain(|_, (_, t)| t.session.as_deref() != Some(session.id.as_str()));
    st.run_tokens
        .retain(|_, t| t.session.as_deref() != Some(session.id.as_str()));
    st.signers.forget(&session.identity.principal);
    // System mode: the leases the session obtained end with it (review
    // finding F4), so the next session on the same repository and branch,
    // in the same slot or another, starts with none and needs its own
    // approval. One a live session also holds stays until that one ends.
    for lease_id in st.session_leases.remove(&session.id).unwrap_or_default() {
        if st
            .session_leases
            .values()
            .any(|held| held.contains(&lease_id))
        {
            continue;
        }
        match st.lease_engine.revoke_lease_by_id(&lease_id) {
            Ok(true) => eprintln!(
                "[agent-signd] Ended lease {lease_id} with session {}",
                session.id
            ),
            Ok(false) => {}
            Err(e) => eprintln!(
                "[agent-signd] couldn't save the end of lease {lease_id} (session {}): {e}",
                session.id
            ),
        }
    }
    if let Err(e) =
        st.session_log
            .append("end", &session.id, &session.identity.principal, session.uid)
    {
        eprintln!(
            "[agent-signd] couldn't record session {}'s end ({e})",
            session.id
        );
    }
    eprintln!(
        "[agent-signd] Session {} ({}) ended",
        session.id, session.identity.principal
    );
}

/// The work an approval asked from `repo` on `branch` is for, if the
/// branch's tip can be read (see `agent_sign::work`). A lease granted with
/// it ends when that work is merged or deleted. In system mode there is
/// none: reading the tip is a git run in the caller's repository, which the
/// service never makes there (a session's lease ends with the session).
fn work_at(system: bool, repo: &str, branch: &str) -> Option<agent_sign::lease::Work> {
    if system {
        return None;
    }
    let base = agent_sign::work::branch_tip(Path::new(repo), branch)?;
    Some(agent_sign::lease::Work {
        repo: repo.to_string(),
        branch: branch.to_string(),
        base,
    })
}

/// Ends the leases `pick` chooses whose work is finished, and says so in the
/// service's log. Returns how many ended.
///
/// The git runs (`agent_sign::work::work_state`) happen without the state
/// lock, so a slow check never holds up another client: `pick` gathers the
/// work under the lock, the lock is released while git runs, and it is taken
/// again to end only the leases still there unchanged (same lease, same
/// work; see `LeaseEngine::end_checked_work`).
fn end_finished_work_of(
    state: &Arc<Mutex<DaemonState>>,
    pick: impl FnOnce(&mut DaemonState) -> Vec<WorkToCheck>,
) -> usize {
    use agent_sign::work::WorkState;
    let mut st = state.lock().unwrap();
    // System mode never runs git in a caller's repository, and that check is
    // exactly such a run.
    if st.system {
        return 0;
    }
    let to_check = pick(&mut st);
    drop(st);
    if to_check.is_empty() {
        return 0;
    }
    let checked: Vec<(WorkToCheck, WorkState)> = to_check
        .into_iter()
        .map(|item| {
            let w = &item.work;
            let found = agent_sign::work::work_state(Path::new(&w.repo), &w.branch, &w.base);
            (item, found)
        })
        .collect();
    if checked
        .iter()
        .all(|(_, found)| *found == WorkState::Ongoing)
    {
        return 0;
    }
    let ended = state.lock().unwrap().lease_engine.end_checked_work(checked);
    for (lease, why) in &ended {
        let why = match why {
            WorkState::Merged => "was merged",
            _ => "was deleted",
        };
        eprintln!(
            "[agent-signd] Ended the approval for {} ({}): branch '{}' {}",
            lease.repo,
            lease.coverage.describe(),
            lease
                .work
                .as_ref()
                .map(|w| w.branch.as_str())
                .unwrap_or_default(),
            why
        );
    }
    ended.len()
}

/// Checks every lease's work (a listing, or the background sweep) and ends
/// the finished ones, restarting the sweep's interval.
fn end_all_finished_work(state: &Arc<Mutex<DaemonState>>) {
    end_finished_work_of(state, |st| {
        st.last_work_sweep = Instant::now();
        st.lease_engine.work_to_check(|_| true)
    });
}

/// The background sweep: every [`WORK_SWEEP_INTERVAL`] after the last full
/// check, every lease's work is checked, so leases for finished work end
/// even when nobody lists them and no agent commits under them.
fn sweep_finished_work(state: &Arc<Mutex<DaemonState>>) {
    loop {
        let due = state.lock().unwrap().last_work_sweep + WORK_SWEEP_INTERVAL;
        let now = Instant::now();
        if now < due {
            std::thread::sleep(due - now);
            continue;
        }
        end_all_finished_work(state);
    }
}

/// What an approval request tells the person about the lease: its terms in
/// words, how far it reaches across branches, and how it ends.
struct ShownTerms<'a> {
    terms: &'a agent_sign::lease::TermsText,
    reach: &'a BranchReach,
    ends: &'a str,
}

/// Joins the open request for this repository and branch, or opens one: a
/// prompt in its own thread, whose answer every waiting commit receives. The
/// lease, if approved, is granted once, by that thread.
fn join_or_open_request(
    state: &Arc<Mutex<DaemonState>>,
    caller: &Caller,
    repo: &str,
    branch: &str,
    intent: &str,
    shown: &ShownTerms,
) -> Result<Arc<PendingAsk>, String> {
    let key = pending_key(repo, branch);
    let mut st = state.lock().unwrap();
    if let Some(ask) = st.pending.get(&key) {
        ask.waiters.fetch_add(1, Ordering::SeqCst);
        ask.note_asker(caller);
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
        sessions: Mutex::new(Vec::new()),
        plain_asked: AtomicBool::new(false),
    });
    ask.note_asker(caller);
    st.pending.insert(key.clone(), Arc::clone(&ask));
    drop(st);

    let state = Arc::clone(state);
    let asking = Arc::clone(&ask);
    let (repo, branch, intent) = (repo.to_string(), branch.to_string(), intent.to_string());
    let (terms, reach, ends) = (
        shown.terms.clone(),
        shown.reach.clone(),
        shown.ends.to_string(),
    );
    std::thread::spawn(move || {
        let approval = request_human_approval(&repo, &reach, &ends, &asking.cancel);
        // Read the branch's tip before taking the lock: git runs in a
        // repository the agent controls, and mustn't stall the service.
        let system = state.lock().unwrap().system;
        let work = match approval {
            Approval::Approved(_) => work_at(system, &repo, &branch),
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
            // System mode: the sessions among the askers that are still live.
            // The lease is theirs and ends with them (review finding F4); if
            // every asking session has ended and no plain caller asked, it
            // would belong to no one, so it is not granted.
            let askers: Vec<String> = if st.system {
                asking
                    .sessions
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|id| st.sessions.contains_key(*id))
                    .cloned()
                    .collect()
            } else {
                Vec::new()
            };
            let response = match approval {
                Approval::Approved(_)
                    if st.system
                        && askers.is_empty()
                        && !asking.plain_asked.load(Ordering::SeqCst) =>
                {
                    Response::Error {
                        message: "the launched session that asked has ended, so no lease was \
                                  granted"
                            .into(),
                    }
                }
                Approval::Approved(coverage) => {
                    match st
                        .lease_engine
                        .try_grant_for_work(&repo, &branch, &intent, coverage, work)
                    {
                        Ok(lease) => {
                            for id in &askers {
                                record_session_lease(&mut st, id, &lease.id);
                            }
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
/// wrapper reports it). The error is sent to the agent. In system mode the
/// repository isn't opened, so only the branch's name is checked.
fn check_asked_branch(repo: &str, branch: &str, system: bool) -> Result<(), String> {
    agent_sign::repo_info::check_branch_name(branch)
        .map_err(|why| format!("{why}, so no approval was asked for"))?;
    if system {
        return Ok(());
    }
    match agent_sign::repo_info::current_branch(Path::new(repo)) {
        Some(current) if current == branch => Ok(()),
        _ => Err(format!(
            "branch '{branch}' isn't the branch checked out in the repository, so no approval was asked for"
        )),
    }
}
