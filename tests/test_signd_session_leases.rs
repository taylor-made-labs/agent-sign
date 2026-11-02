//! Round 2 of the whole-branch security review (second reviewer), system
//! half, written before the fix as its eval by an agent other than the
//! builder. Items F4, F5 and the system-mode side of F7. Each test says in
//! its doc comment which finding it covers and how it fails today.
//!
//! - **F4 (medium): a lease does not end with its session.** `end_session`
//!   never touched the lease engine, and in system mode `work_at` gives a
//!   lease no work to finish, so a used lease lived on. The next session on
//!   the same repository and branch (a slot is reused, and the next session
//!   may be another agent) inherited it, device-owner approval and all.
//!   Interface I-F4: in system mode every lease the service grants for a
//!   session is recorded against that session's id, and `end_session`
//!   revokes each (with its approval, if any); the next session starts with
//!   none and needs its own. One-account mode is unchanged. A lease a plain
//!   caller holds is not the session's, and is not revoked with it.
//! - **F5 (low): unsigned checks share the signing rate window, and the
//!   window map grows without eviction.** Interface I-F5: plain-path
//!   (unsigned) checks are counted in their own per-repository window,
//!   separate from signing, so a plain caller cannot starve a session (nor
//!   the reverse); the map of windows is capped by a named constant and
//!   evicts oldest or expired entries first.
//! - **F7 (low), the author half, in system mode.** Interface I-F7-author:
//!   the launcher-attested signing path requires the commit's author email
//!   to equal the session's principal, as approvals already require;
//!   otherwise it refuses with a plain message. (The signing itself, with a
//!   real authority, is in `test_signd_session_author.rs`; here the
//!   authority is the closed stand-in, so the check is seen as the message
//!   a refusal carries, which comes before the authority is asked.)
//!
//! **Harness.** The service is the real `agent-signd` in system mode with
//! the kernel-facts seam, as `test_caller_registration.rs` defines it (a
//! test file cannot import another, so the pieces used here are copied).
//! Sessions are slots 1 and 2, registered on the launcher-only socket; a
//! plain caller is a person's uid outside every unit. The authority is the
//! closed stand-in, so nothing here signs: tokens are issued (they need a
//! lease and count in the rate window) and requests are refused or granted.
//!
//! Run on hetzner, never on the Mac:
//! `cargo test --locked --test test_signd_session_leases`.

#![cfg(target_os = "linux")]

use std::ffi::OsString;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use base64::Engine;
use serde_json::json;
use tempfile::{TempDir, tempdir};

use agent_sign::agents_ca::trust_line_in;
use agent_sign::attribution::AgentIdentity;
use agent_sign::protocol::{LeaseInfo, Request, Response, send_request_waiting};

const MACHINE: &str = "hetzner";
const DOMAIN: &str = "hetzner.agents.local";
const MOUNT: &str = "ssh-agents-hetzner";
const ROLE: &str = "agent-sign-hetzner";
const LAUNCHER_ACCOUNT: &str = "agent-launch";
const LAUNCHER_UID: u32 = 61900;
const PERSON_UID: u32 = 1000;
const START_LIMIT: Duration = Duration::from_secs(10);

fn slot_uid(n: u32) -> u32 {
    61000 + n
}
fn unit(n: u32) -> String {
    format!("agent-session@{n}.service")
}

// ---------------------------------------------------------------------------
// The kernel-facts seam, as a test drives it (copied from
// test_caller_registration.rs).
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct Peer {
    uid: u32,
    cgroup: String,
}

impl Peer {
    fn session_of(n: u32) -> Peer {
        Peer {
            uid: slot_uid(n),
            cgroup: format!("0::/system.slice/{}", unit(n)),
        }
    }
    fn launcher() -> Peer {
        Peer {
            uid: LAUNCHER_UID,
            cgroup: "0::/system.slice/agent-launchd.service".into(),
        }
    }
    /// A person's or the agents' account, outside every session unit: the
    /// plain path.
    fn plain() -> Peer {
        Peer {
            uid: PERSON_UID,
            cgroup: "0::/user.slice".into(),
        }
    }
}

/// What a test changes about the service it starts.
#[derive(Default, Clone)]
struct Opts {
    /// Extra `[security]` lines.
    security: String,
    /// Extra environment for the service.
    env: Vec<(String, OsString)>,
}

static STARTS: AtomicUsize = AtomicUsize::new(0);

struct Service {
    child: Child,
    log: PathBuf,
}

impl Service {
    fn log(&self) -> String {
        fs::read_to_string(&self.log).unwrap_or_default()
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct World {
    _dir: TempDir,
    root: PathBuf,
    home: PathBuf,
    socket: PathBuf,
    launcher_socket: PathBuf,
    facts: PathBuf,
    trust: PathBuf,
    repo: PathBuf,
}

/// The launcher's registration of a session: it lasts while this is held.
struct Registration {
    stream: Option<UnixStream>,
    principal: String,
    session: String,
}

impl Registration {
    /// The launcher's connection closes: the session ends.
    fn end(&mut self) {
        self.stream = None;
    }
}

impl World {
    fn new() -> World {
        let dir = tempdir().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        let home = root.join("home");
        fs::create_dir_all(agent_sign::paths::state_dir_in(&home)).unwrap();
        fs::create_dir_all(root.join("service-cwd")).unwrap();
        let repo = root.join("repo");
        fs::create_dir_all(&repo).unwrap();
        let w = World {
            socket: root.join("daemon.sock"),
            launcher_socket: root.join("launcher.sock"),
            facts: root.join("kernel-facts.json"),
            trust: root.join("allowed_signers"),
            _dir: dir,
            root,
            home,
            repo,
        };
        let key = ed25519_dalek::SigningKey::from_bytes(&[21; 32]);
        fs::write(
            &w.trust,
            format!(
                "{}\n",
                trust_line_in(
                    DOMAIN,
                    agent_sign::crypto::openssh_ed25519_line(&key.verifying_key()).trim()
                )
            ),
        )
        .unwrap();
        w.set_peer(&Peer::plain());
        w
    }

    fn repo_s(&self) -> String {
        self.repo.to_string_lossy().into_owned()
    }

    fn set_peer(&self, peer: &Peer) {
        let mut accounts = serde_json::Map::new();
        accounts.insert(LAUNCHER_ACCOUNT.into(), json!(LAUNCHER_UID));
        accounts.insert("taylor".into(), json!(PERSON_UID));
        for n in 1..=8 {
            accounts.insert(format!("agent-slot-{n}"), json!(slot_uid(n)));
        }
        let facts = json!({
            "accounts": accounts,
            "peer": {"uid": peer.uid, "cgroup": peer.cgroup, "process": "alive"}
        });
        let tmp = self.root.join("kernel-facts.json.tmp");
        fs::write(&tmp, facts.to_string()).unwrap();
        fs::rename(&tmp, &self.facts).unwrap();
    }

    fn system_toml(&self, opts: &Opts) -> String {
        // SAFETY: getuid takes no arguments and can't fail.
        let uid = unsafe { libc::getuid() };
        let account = fs::read_to_string("/etc/passwd")
            .unwrap_or_default()
            .lines()
            .find_map(|l| {
                let f: Vec<&str> = l.split(':').collect();
                (f.len() >= 3 && f[2].parse::<u32>() == Ok(uid)).then(|| f[0].to_string())
            })
            .expect("an account for this uid");
        let r = &self.root;
        format!(
            "machine = \"{MACHINE}\"\n\n[service]\naccount = \"{account}\"\nsocket = \"{}\"\n\
             launcher_socket = \"{}\"\ntrust_file = \"{}\"\nclient_accounts = [\"{account}\"]\n\n\
             [launcher]\naccount = \"{LAUNCHER_ACCOUNT}\"\nsocket = \"{}\"\npeople_accounts = [\"taylor\"]\n\
             approvers = []\n\n[slots]\ncount = 8\naccount_prefix = \"agent-slot-\"\nroot = \"{}\"\n\
             max_duration = \"12h\"\n\n[identity]\npeople = [\"Taylor\"]\n\n[authority]\n\
             issuer = \"openbao\"\naddress = \"https://127.0.0.1:1\"\n\
             ca_cert = \"/etc/ssl/certs/ca-certificates.crt\"\nresolve = \"127.0.0.1\"\n\
             mount = \"{MOUNT}\"\nrole = \"{ROLE}\"\n\n[security]\n{}\n",
            self.socket.display(),
            self.launcher_socket.display(),
            self.trust.display(),
            r.join("launch.sock").display(),
            r.join("slots").display(),
            opts.security,
        )
    }

    fn start(&self, opts: &Opts) -> Service {
        fs::write(self.root.join("system.toml"), self.system_toml(opts)).unwrap();
        let _ = fs::remove_file(&self.socket);
        let n = STARTS.fetch_add(1, Ordering::SeqCst);
        let log_path = self.root.join(format!("service-{n}.log"));
        let log = fs::File::create(&log_path).unwrap();
        let path = std::env::var_os("PATH").unwrap_or_default();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_agent-signd"));
        cmd.arg("--socket")
            .arg(&self.socket)
            .env_clear()
            .env("HOME", &self.home)
            .env("PATH", path)
            .env("TZ", "UTC")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("AGENT_SIGN_TEST_AUTH", "fail")
            .env("AGENT_SIGN_REFUSAL_BACKOFF", "none")
            .env("AGENT_SIGN_CONNECT_WAIT_MS", "200")
            .env(
                "AGENT_SIGN_TEST_SYSTEM_CONFIG",
                self.root.join("system.toml"),
            )
            .env("AGENT_SIGN_TEST_KERNEL_FACTS", &self.facts)
            .current_dir(self.root.join("service-cwd"))
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log));
        if let Some(tmp) = std::env::var_os("TMPDIR") {
            cmd.env("TMPDIR", tmp);
        }
        for (k, v) in &opts.env {
            cmd.env(k, v);
        }
        let mut child = cmd.spawn().expect("couldn't start agent-signd");
        let started = Instant::now();
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                panic!(
                    "CONTROL: the service stopped at start ({status}); log:\n{}",
                    fs::read_to_string(&log_path).unwrap_or_default()
                );
            }
            if self.socket.exists() {
                return Service {
                    child,
                    log: log_path,
                };
            }
            if started.elapsed() > START_LIMIT {
                let _ = child.kill();
                let _ = child.wait();
                panic!("CONTROL: the service never opened its socket");
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    /// One ordinary request on the service's socket from a process the
    /// kernel describes as `peer`.
    fn ask_as(&self, peer: &Peer, req: &Request) -> Result<Response, String> {
        self.set_peer(peer);
        send_request_waiting(&self.socket, req, Duration::from_secs(10)).map_err(|e| e.to_string())
    }

    /// The launcher registers slot `n` for `agent`.
    fn register(&self, n: u32, agent: &str) -> Registration {
        self.set_peer(&Peer::launcher());
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut stream = loop {
            match UnixStream::connect(&self.launcher_socket) {
                Ok(s) => break s,
                Err(e) if Instant::now() > deadline => {
                    panic!("CONTROL: can't connect to the launcher socket: {e}")
                }
                Err(_) => thread::sleep(Duration::from_millis(50)),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let req = json!({"type": "RegisterSession", "payload":
            {"slot": n, "uid": slot_uid(n), "unit": unit(n), "agent": agent}});
        stream.write_all(format!("{req}\n").as_bytes()).unwrap();
        let mut line = String::new();
        BufReader::new(stream.try_clone().unwrap())
            .read_line(&mut line)
            .unwrap_or_else(|e| panic!("CONTROL: no answer to a registration ({e})"));
        match serde_json::from_str::<Response>(&line) {
            Ok(Response::SessionStarted { principal, session }) => Registration {
                stream: Some(stream),
                principal,
                session,
            },
            other => panic!("CONTROL: slot {n} didn't register: {other:?} ({line})"),
        }
    }

    fn identity_of(&self, n: u32) -> AgentIdentity {
        match self.ask_as(&Peer::session_of(n), &Request::SessionIdentity) {
            Ok(Response::SessionIdentity { identity }) => identity,
            other => panic!("CONTROL: slot {n} has no session identity: {other:?}"),
        }
    }

    /// Waits until the service no longer counts slot `n`'s process as a
    /// session (the registration closed and the service noticed).
    fn wait_session_over(&self, n: u32) {
        let started = Instant::now();
        loop {
            if !matches!(
                self.ask_as(&Peer::session_of(n), &Request::SessionIdentity),
                Ok(Response::SessionIdentity { .. })
            ) {
                // Give the end its own step in the service: the identity
                // judgement and the lease handling are not one lock hold.
                thread::sleep(Duration::from_millis(300));
                return;
            }
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "CONTROL: the service still counts slot {n} as a session 5 s after its \
                 registration closed"
            );
            thread::sleep(Duration::from_millis(30));
        }
    }

    fn lease(&self, who: &Peer, repo: &str, branch: &str) -> Result<Response, String> {
        self.ask_as(
            who,
            &Request::RequestLease {
                repo: repo.into(),
                branch: branch.into(),
                intent: "test".into(),
                duration_secs: Some(600),
            },
        )
    }

    fn granted(&self, who: &Peer, repo: &str, branch: &str) -> String {
        match self.lease(who, repo, branch) {
            Ok(Response::LeaseGranted { lease_id, .. }) => lease_id,
            other => panic!("CONTROL: no lease for {repo} on {branch}: {other:?}"),
        }
    }

    fn run_token(
        &self,
        who: &Peer,
        repo: &str,
        branch: &str,
        identity: &AgentIdentity,
    ) -> Result<Response, String> {
        self.ask_as(
            who,
            &Request::IssueRunToken {
                repo: repo.into(),
                branch: branch.into(),
                identity: identity.clone(),
            },
        )
    }

    fn leases(&self) -> Vec<LeaseInfo> {
        match self.ask_as(&Peer::plain(), &Request::ListLeases) {
            Ok(Response::LeaseList { leases }) => leases,
            other => panic!("CONTROL: no lease list: {other:?}"),
        }
    }

    fn unsigned_check(&self, repo: &str, branch: &str, identity: &AgentIdentity) -> Response {
        self.ask_as(
            &Peer::plain(),
            &Request::CheckPlainCommit {
                repo: repo.into(),
                branch: branch.into(),
                identity: identity.clone(),
            },
        )
        .unwrap_or_else(|e| Response::Error { message: e })
    }
}

/// An agent nobody launched, as the plain path names itself.
fn plain_identity() -> AgentIdentity {
    AgentIdentity::new("claude-code", "Claude Code", Some("0123456789abcdef")).in_domain(DOMAIN)
}

fn is_token(r: &Result<Response, String>) -> bool {
    matches!(r, Ok(Response::TokenIssued { .. }))
}

fn ids(leases: &[LeaseInfo]) -> Vec<String> {
    leases.iter().map(|l| l.lease_id.clone()).collect()
}

// ---------------------------------------------------------------------------
// F4: a lease ends with the session that obtained it.
// ---------------------------------------------------------------------------

/// F4, the plain fact: a lease a session obtained is in force while the
/// session lasts (the control: it lists, and a token is issued under it),
/// and gone when the session ends. Fails today: the listing still has it.
#[test]
fn a_lease_a_session_obtained_ends_with_the_session() {
    let w = World::new();
    let svc = w.start(&Opts::default());
    let repo = w.repo_s();
    let mut a = w.register(1, "claude-code");
    let me = Peer::session_of(1);
    let id = w.granted(&me, &repo, "work");
    let who = w.identity_of(1);
    assert_eq!(who.principal, a.principal, "CONTROL: identity");
    assert!(
        is_token(&w.run_token(&me, &repo, "work", &who)),
        "CONTROL: a live session cannot use its own lease\n{}",
        svc.log()
    );
    assert!(
        ids(&w.leases()).contains(&id),
        "CONTROL: the lease isn't listed while its session lasts: {:?}",
        w.leases()
    );
    a.end();
    w.wait_session_over(1);
    let left = w.leases();
    assert!(
        !ids(&left).contains(&id),
        "F4: session {} ended but the lease it obtained ({id}) is still in force: {left:?}",
        a.session
    );
    assert!(
        left.iter().all(|l| l.repo != repo),
        "F4: a lease for {repo} is still in force after its session ended: {left:?}"
    );
}

/// The reviewer's scenario, F4: session A obtains a lease on a repository
/// and branch and ends; session B on the same repository and branch cannot
/// sign with it, and needs its own. `(slot, agent)` is B: the same slot and
/// agent as A (a slot is reused), and another slot and agent (the lease
/// inherited by another agent).
fn next_session_needs_its_own_lease(slot_b: u32, agent_b: &str) {
    let w = World::new();
    let svc = w.start(&Opts::default());
    let repo = w.repo_s();
    let mut a = w.register(1, "claude-code");
    let a_id = w.granted(&Peer::session_of(1), &repo, "work");
    a.end();
    w.wait_session_over(1);

    let b = w.register(slot_b, agent_b);
    assert_ne!(b.principal, a.principal, "CONTROL: B is a new session");
    let me = Peer::session_of(slot_b);
    let who = w.identity_of(slot_b);
    // B has asked for nothing. A's lease must not carry it.
    let inherited = w.run_token(&me, &repo, "work", &who);
    assert!(
        !is_token(&inherited),
        "F4: session B ({agent_b}, slot {slot_b}) got a run token on {repo} / work from the \
         lease its predecessor A obtained ({a_id}), without asking for its own: {inherited:?}\n{}",
        svc.log()
    );
    // B asks, and gets a lease of its own: not A's.
    let b_id = w.granted(&me, &repo, "work");
    assert_ne!(
        b_id, a_id,
        "F4: B's lease is A's old lease ({a_id}), not one of its own"
    );
    assert!(
        is_token(&w.run_token(&me, &repo, "work", &who)),
        "CONTROL: B cannot use the lease it asked for\n{}",
        svc.log()
    );
}

/// F4, the reviewer's scenario with the slot reused by the same agent. Fails
/// today: B gets a token without asking.
#[test]
fn the_next_session_in_the_same_slot_needs_its_own_lease() {
    next_session_needs_its_own_lease(1, "claude-code");
}

/// F4, the reviewer's scenario with another agent in another slot (the
/// "possibly for another agent" of the finding). Fails today the same way.
#[test]
fn another_agents_session_on_the_same_repository_and_branch_needs_its_own_lease() {
    next_session_needs_its_own_lease(2, "codex");
}

/// F4 with the device owner's approval: `approval = "device-owner"` and a
/// stand-in owner who allows and logs every prompt. A's lease was approved
/// once (one prompt). When A ends, B's request on the same repository and
/// branch must be asked again (a second prompt) and get a lease of its own.
/// Fails today: B's request is answered with A's lease, with no prompt, so
/// one agent's approval carries another's.
#[test]
fn a_device_owner_approval_does_not_carry_to_the_next_session() {
    let w = World::new();
    let prompts = w.root.join("prompts.log");
    let svc = w.start(&Opts {
        security: "approval = \"device-owner\"".into(),
        env: vec![
            ("AGENT_SIGN_TEST_AUTH".into(), "allow".into()),
            ("AGENT_SIGN_TEST_AUTH_LOG".into(), prompts.clone().into()),
        ],
    });
    let asked = || {
        fs::read_to_string(&prompts)
            .unwrap_or_default()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .count()
    };
    let repo = w.repo_s();
    let mut a = w.register(1, "claude-code");
    let a_id = w.granted(&Peer::session_of(1), &repo, "work");
    assert_eq!(
        asked(),
        1,
        "CONTROL: A's lease should have cost exactly one prompt\n{}",
        svc.log()
    );
    a.end();
    w.wait_session_over(1);

    let _b = w.register(2, "codex");
    let me = Peer::session_of(2);
    let who = w.identity_of(2);
    let inherited = w.run_token(&me, &repo, "work", &who);
    assert!(
        !is_token(&inherited),
        "F4: another agent's session got a run token under A's approved lease ({a_id}) without \
         being approved: {inherited:?}"
    );
    let b_id = w.granted(&me, &repo, "work");
    assert_eq!(
        asked(),
        2,
        "F4: B's lease on the same repository and branch was granted without asking the device \
         owner again (prompts so far: {}); an approval is for one session\n{}",
        asked(),
        svc.log()
    );
    assert_ne!(b_id, a_id, "F4: B was handed A's approved lease");
}

/// F4, the lease stays gone: a lease revoked at a session's end is revoked
/// durably (the engine's own revocation, saved to `leases.json`), so a
/// restart of the service does not bring it back. Fails today: nothing
/// revokes it, and the restart reads it from the file.
#[test]
fn a_lease_revoked_at_the_end_of_its_session_stays_gone_after_a_restart() {
    let w = World::new();
    let svc = w.start(&Opts::default());
    let repo = w.repo_s();
    let mut a = w.register(1, "claude-code");
    let id = w.granted(&Peer::session_of(1), &repo, "work");
    a.end();
    w.wait_session_over(1);
    drop(svc);
    let svc = w.start(&Opts::default());
    let left = w.leases();
    assert!(
        !ids(&left).contains(&id),
        "F4: the lease ({id}) of a session that ended came back when the service restarted: \
         {left:?}\n{}",
        svc.log()
    );
}

/// F4 across a crash or restart: the service keeps which lease belongs to
/// which session in memory only, and `leases.json` outlives it, so a session
/// that died with the service (no end was ever recorded) left its lease, and
/// its device-owner approval, for the next session on the same repository
/// and branch. In system mode the service ends every lease it finds at start.
/// The service is stopped with the session still registered (its end is never
/// seen), started again, and the lease must be gone and the next session in
/// the slot must be granted a new one. Fails without the revoke at start: the
/// old lease id is handed to the next session.
#[test]
fn a_lease_of_a_session_that_died_with_the_service_is_not_inherited() {
    let w = World::new();
    let svc = w.start(&Opts::default());
    let repo = w.repo_s();
    let _a = w.register(1, "claude-code");
    let old = w.granted(&Peer::session_of(1), &repo, "work");
    drop(svc);
    let svc = w.start(&Opts::default());
    let left = w.leases();
    assert!(
        !ids(&left).contains(&old),
        "F4: the lease ({old}) of a session that died with the service was still there after \
         the restart: {left:?}\n{}",
        svc.log()
    );
    let _b = w.register(1, "codex");
    let new = w.granted(&Peer::session_of(1), &repo, "work");
    assert_ne!(
        new,
        old,
        "F4: the next session in the slot was handed the dead session's lease\n{}",
        svc.log()
    );
}

/// F4, the guard against over-revoking: a session's ending revokes the leases
/// it was granted, and no others. (a) A lease a plain caller holds on another
/// repository stays. (b) A lease a plain caller held first, on the very
/// repository and branch the session then asked for, is a covering lease:
/// the session was handed it, not granted it, so it stays too. (Leases are
/// one per repository, so each case has its own.) Passes today and must pass
/// after the fix.
#[test]
fn ending_a_session_does_not_revoke_a_lease_it_was_not_granted() {
    let w = World::new();
    let _svc = w.start(&Opts::default());
    let elsewhere = w.root.join("other-repo");
    fs::create_dir_all(&elsewhere).unwrap();
    let elsewhere = elsewhere.to_string_lossy().into_owned();
    let shared = w.repo_s();
    let plain = Peer::plain();
    let plain_other = w.granted(&plain, &elsewhere, "work");
    let plain_shared = w.granted(&plain, &shared, "work");

    let mut a = w.register(1, "claude-code");
    let me = Peer::session_of(1);
    let covering = w.granted(&me, &shared, "work");
    assert_eq!(
        covering, plain_shared,
        "CONTROL: a covering lease is handed out as it is"
    );
    a.end();
    w.wait_session_over(1);

    let left = ids(&w.leases());
    assert!(
        left.contains(&plain_other),
        "a plain caller's lease on another repository was revoked with the session: {left:?}"
    );
    assert!(
        left.contains(&plain_shared),
        "a lease the plain caller held first was revoked with the session that merely used it: \
         {left:?}"
    );
}

// ---------------------------------------------------------------------------
// F5: unsigned checks have their own rate window; the window map is bounded.
// ---------------------------------------------------------------------------

const RATE: u32 = 4;

fn rate_opts() -> Opts {
    Opts {
        security: format!("max_commits_per_minute = {RATE}"),
        env: Vec::new(),
    }
}

/// F5, a plain caller cannot starve a session: `RATE` unsigned checks fill
/// the plain window for a repository (and the next one is refused: the
/// unsigned path is still limited). A session working in the same
/// repository then still gets its tokens. Fails today: the unsigned checks
/// used the window signing uses, so the session's first token is refused
/// with "Rate limit exceeded".
#[test]
fn unsigned_checks_do_not_use_up_a_sessions_signing_window() {
    let w = World::new();
    let svc = w.start(&rate_opts());
    let repo = w.repo_s();
    let plain = plain_identity();
    for i in 1..=RATE {
        let r = w.unsigned_check(&repo, "work", &plain);
        assert!(
            matches!(r, Response::Success),
            "CONTROL: unsigned check {i} of {RATE} was refused: {r:?}\n{}",
            svc.log()
        );
    }
    let over = w.unsigned_check(&repo, "work", &plain);
    assert!(
        matches!(&over, Response::Error { message } if message.contains("Rate limit")),
        "CONTROL: the unsigned path must still be rate limited itself: {over:?}"
    );
    let _a = w.register(1, "claude-code");
    let me = Peer::session_of(1);
    let who = w.identity_of(1);
    let _ = w.granted(&me, &repo, "work");
    let first = w.run_token(&me, &repo, "work", &who);
    assert!(
        is_token(&first),
        "F5: a plain caller's {RATE} unsigned checks used up the repository's window and the \
         session's first token was refused: {first:?}"
    );
}

/// F5, and the other way: a session's `RATE` run tokens fill the signing
/// window (and the next token is refused: signing is still limited), yet an
/// unsigned check on the same repository is still allowed. Fails today for
/// the same shared window.
#[test]
fn a_sessions_signing_does_not_use_up_the_unsigned_window() {
    let w = World::new();
    let svc = w.start(&rate_opts());
    let repo = w.repo_s();
    let _a = w.register(1, "claude-code");
    let me = Peer::session_of(1);
    let who = w.identity_of(1);
    let _ = w.granted(&me, &repo, "work");
    for i in 1..=RATE {
        assert!(
            is_token(&w.run_token(&me, &repo, "work", &who)),
            "CONTROL: token {i} of {RATE} was refused\n{}",
            svc.log()
        );
    }
    let over = w.run_token(&me, &repo, "work", &who);
    assert!(
        matches!(&over, Ok(Response::Error { message }) if message.contains("Rate limit")),
        "CONTROL: signing must still be rate limited itself: {over:?}"
    );
    let r = w.unsigned_check(&repo, "work", &plain_identity());
    assert!(
        matches!(r, Response::Success),
        "F5: the session's {RATE} tokens used up the window and a plain caller's unsigned check \
         was refused: {r:?}"
    );
}

/// The service's resident memory, in bytes (VmRSS of its process).
fn rss_bytes(pid: u32) -> u64 {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
    let kb: u64 = status
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))
        .and_then(|v| v.trim().trim_end_matches("kB").trim().parse().ok())
        .unwrap_or(0);
    kb * 1024
}

/// F5, the window map is bounded. The service cannot see callers'
/// repositories in system mode, so a plain caller may name as many
/// repositories as it likes, none of which exists; each used to leave an
/// entry in the rate-window map for good. The map's cap is the builder's
/// named constant; what a test can see from outside is the service's
/// memory. `FLOOD` distinct repository paths of about 110 bytes each are
/// checked (from 8 connections at once), and the service's resident memory
/// must grow by less than `GROWTH_LIMIT` (10 MiB). Measured on the unfixed
/// service: 37 MiB of growth (about 310 bytes per entry: key, window, table
/// slot). The same flood over only 1,000 distinct paths grows the service
/// by 2.7 MiB (connections, threads, the log), which is the noise floor. A
/// cap therefore passes if it holds fewer than about 20,000 entries of this
/// size, and the limit is also the largest cap this test accepts. Bytes, not
/// entries, are what bound memory, so a cap that also bounds the key length
/// is better still; that is not tested here.
#[test]
fn the_rate_window_map_does_not_grow_with_every_repository_named() {
    const FLOOD: usize = 120_000;
    const WORKERS: usize = 8;
    const GROWTH_LIMIT: u64 = 10 * 1024 * 1024;
    let w = World::new();
    let svc = w.start(&Opts {
        security: "max_commits_per_minute = 1000".into(),
        env: Vec::new(),
    });
    w.set_peer(&Peer::plain());
    let pid = svc.child.id();
    let identity = plain_identity();
    let socket = w.socket.clone();
    let check = move |i: usize| -> bool {
        let repo = format!("/nonexistent/flood/{i:09}/{}", "x".repeat(80));
        let req = Request::CheckPlainCommit {
            repo,
            branch: "work".into(),
            identity: identity.clone(),
        };
        matches!(
            send_request_waiting(&socket, &req, Duration::from_secs(10)),
            Ok(Response::Success)
        )
    };
    // Warm up: threads, buffers and the first windows are not growth.
    for i in 0..2_000 {
        assert!(
            check(i),
            "CONTROL: a plain check was refused\n{}",
            svc.log()
        );
    }
    let before = rss_bytes(pid);
    assert!(before > 0, "CONTROL: cannot read the service's memory");
    let next = std::sync::Arc::new(AtomicUsize::new(10_000));
    let refused = std::sync::Arc::new(AtomicUsize::new(0));
    let workers: Vec<_> = (0..WORKERS)
        .map(|_| {
            let (next, refused, check) = (next.clone(), refused.clone(), check.clone());
            thread::spawn(move || {
                loop {
                    let i = next.fetch_add(1, Ordering::SeqCst);
                    if i >= 10_000 + FLOOD {
                        return;
                    }
                    if !check(i) {
                        refused.fetch_add(1, Ordering::SeqCst);
                    }
                }
            })
        })
        .collect();
    for t in workers {
        t.join().unwrap();
    }
    assert_eq!(
        refused.load(Ordering::SeqCst),
        0,
        "CONTROL: some of the flood's checks were refused (each names its own repository)\n{}",
        svc.log()
    );
    let grew = rss_bytes(pid).saturating_sub(before);
    assert!(
        grew < GROWTH_LIMIT,
        "F5: naming {FLOOD} distinct nonexistent repositories grew the service's memory by \
         {} KiB (limit {} KiB): the rate-window map has no cap",
        grew / 1024,
        GROWTH_LIMIT / 1024
    );
}

// ---------------------------------------------------------------------------
// F7, the author half, in system mode.
// ---------------------------------------------------------------------------

fn commit_buffer(author: &str, committer: &str) -> Vec<u8> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    format!(
        "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\nauthor Agent <{author}> {now} +0000\n\
         committer Agent <{committer}> {now} +0000\n\nan agent's commit\n"
    )
    .into_bytes()
}

fn sign_request(token: &str, repo: &str, buffer: &[u8]) -> Request {
    Request::SignCommit {
        token: token.into(),
        buffer_b64: base64::engine::general_purpose::STANDARD.encode(buffer),
        repo: Some(repo.into()),
        branch: Some("work".into()),
    }
}

/// F7, the author half: a session's commit whose author is not the session's
/// principal (its committer is) is refused with a plain message naming the
/// author, before the authority is asked. The controls: a commit whose
/// author and committer are both the principal gets past the author and
/// committer checks (the closed stand-in authority then refuses, with its
/// own words, which do not mention the author), and a commit with a wrong
/// committer is refused as it is today, naming the committer. Fails today:
/// the author is never looked at, so the wrong-author commit gets the same
/// answer as the right one.
#[test]
fn a_sessions_commit_must_name_the_session_as_its_author() {
    let w = World::new();
    let svc = w.start(&Opts::default());
    let repo = w.repo_s();
    let _a = w.register(1, "claude-code");
    let me = Peer::session_of(1);
    let who = w.identity_of(1);
    let p = who.principal.clone();
    let _ = w.granted(&me, &repo, "work");
    let token = match w.run_token(&me, &repo, "work", &who) {
        Ok(Response::TokenIssued { token }) => token,
        other => panic!("CONTROL: no run token: {other:?}\n{}", svc.log()),
    };
    let message = |buffer: &[u8]| -> String {
        match w.ask_as(&me, &sign_request(&token, &repo, buffer)) {
            Ok(Response::Error { message }) => message,
            Ok(Response::Signed { .. }) => "SIGNED".into(),
            other => format!("{other:?}"),
        }
    };
    // DELIBERATE EVAL CHANGE: strengthened. The rule was narrowed in round 2:
    // an author the service does not know (a replayed commit's) is fine.
    let replayed = message(&commit_buffer("original.author@example.invalid", &p));
    let _other = w.register(2, "codex");
    let other_p = w.identity_of(2).principal;
    assert!(
        !replayed.to_lowercase().contains("author") && !replayed.contains("committer"),
        "CONTROL: a replayed commit by a stranger was refused over its author: {replayed}"
    );
    let right = message(&commit_buffer(&p, &p));
    assert!(
        !right.to_lowercase().contains("author") && !right.contains("committer"),
        "CONTROL: a commit with the right author and committer was refused over them: {right}"
    );
    let wrong_committer = message(&commit_buffer(&p, "taylor@example.com"));
    assert!(
        wrong_committer.contains("committer"),
        "CONTROL: a wrong committer should still be refused as the committer: {wrong_committer}"
    );
    for (what, author) in [
        ("the person", "taylor@example.com"),
        ("another session running now", &other_p),
        ("the session in capitals", &p.to_uppercase()),
    ] {
        let wrong = message(&commit_buffer(author, &p));
        assert!(
            wrong.to_lowercase().contains("author"),
            "F7: a session's commit authored as {what} ({author}) was not refused for its \
             author; the answer was: {wrong}"
        );
        assert!(
            wrong.contains(&p),
            "F7: the refusal should name the principal the author must be ({p}): {wrong}"
        );
    }
}
