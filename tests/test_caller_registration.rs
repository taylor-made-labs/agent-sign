//! System mode, build step 2: who is asking (docs/system-mode.md, section 4
//! and "Build order" step 2; the suite PM's decisions of 1 Nov 2026).
//!
//! Written before the build, as its eval, by an agent other than its
//! builder. Every test that needs the new behaviour fails today; each says in
//! its doc comment why. The work is done when every test here passes on
//! hetzner (`--ignored` included), with no assertion changed.
//!
//! **The port.** The design puts the kernel's facts behind a small port so
//! that tests need no root and no real slot accounts:
//!
//! ```text
//! trait KernelFacts {
//!     fn account_uid(&self, name: &str) -> Option<u32>;   // the launcher's and slots' accounts, by name
//!     fn peer(&self, conn: &UnixStream) -> PeerFacts;     // SO_PEERCRED uid + pidfd
//! }
//! struct PeerFacts { uid: u32, cgroup: String, still_alive: bool }
//!     // cgroup: the line of /proc/<pid>/cgroup (cgroup v2, "0::/..."), read
//!     // BEFORE the pidfd is asked whether the process is still the same one
//!     // (a recycled pid must be caught by that second step).
//! ```
//!
//! The service is a program, so the tests reach the port through a seam in
//! the test build (the `test-authenticator` feature, never installed, like
//! `AGENT_SIGN_TEST_AUTH` and `AGENT_SIGN_TEST_SYSTEM_CONFIG`):
//! `AGENT_SIGN_TEST_KERNEL_FACTS=<file>`, read by the service **on every
//! accepted connection, on both sockets** (so the test can change it between
//! connections). The file is JSON:
//!
//! ```text
//! { "accounts": { "<account name>": <uid>, ... },
//!   "peer": { "uid": <uid>, "cgroup": "<line>", "process": "alive" | "gone" } }
//! ```
//!
//! - `accounts` replaces the account database for the names the service
//!   looks up in system mode (`[launcher] account`, and
//!   `<account_prefix><n>`); a name not listed does not exist.
//! - `peer` is what the kernel reports about whoever connects next: its uid,
//!   the cgroup line of its process, and whether the pidfd still names that
//!   process (`"gone"`: the process ended and its number may have been
//!   reused). In one-account mode the seam is not consulted at all (a guard
//!   below).
//!
//! **The protocol the tests fix** (the rest is the builder's choice). A new
//! request on the launcher-only socket, sent as raw JSON so that this file
//! compiles whatever the builder names the Rust type:
//! `{"type":"RegisterSession","payload":{"slot":<n>,"uid":<uid>,"unit":"agent-session@<n>.service","agent":"<name>"}}`,
//! answered `Response::SessionStarted { principal, session }` (no channel
//! descriptor is attached in system mode) or `Response::Error`. The
//! connection stays open as the registration, as in one-account mode. A
//! session's own requests come on the ordinary socket as ordinary requests;
//! `SessionIdentity` there answers `Response::SessionIdentity` for a
//! session and an error for anyone else.
//!
//! **Attestation.** `launcher session=<id> uid=<slot uid> isolation=slot-account`.
//!
//! **Doctor.** `agent-sign doctor`, with `system.toml` present (the same seam
//! as `test_system_config.rs`), prints the lines `ping: ok` and, when the
//! OpenBao CA equals the trust file's line, `authority: OpenBao CA matches the
//! trust file`. The sitting script waits for both (scripts/sitting).
//!
//! **The dev server** (tests marked `#[ignore]`): `bao server -dev` on
//! loopback with its root token in the environment only, a python3 TLS front
//! whose keys live in anonymous memory files (copied from
//! `test_issuer_openbao.rs`, which this file cannot import), the SSH mount, CA,
//! the decided role and an AppRole login made through the `bao` command. No
//! private key is written to a file anywhere here.
//!
//! Run on hetzner, never on the Mac:
//! `cargo test --locked --test test_caller_registration [-- --ignored]`.

#![cfg(target_os = "linux")]

use std::ffi::OsString;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::json;
use ssh_key::Certificate;
use tempfile::{TempDir, tempdir};

use agent_sign::agents_ca::trust_line_in;
use agent_sign::attestation::{Attestation, EXTENSION};
use agent_sign::protocol::{Request, Response, send_request_waiting};

const MACHINE: &str = "hetzner";
const DOMAIN: &str = "hetzner.agents.local";
const MOUNT: &str = "ssh-agents-hetzner";
const ROLE: &str = "agent-sign-hetzner";
const HOSTNAME: &str = "openbao.test";
const START_LIMIT: Duration = Duration::from_secs(10);
const RUN_LIMIT: Duration = Duration::from_secs(30);

const LAUNCHER_ACCOUNT: &str = "agent-launch";
const LAUNCHER_UID: u32 = 61900;
const PERSON_UID: u32 = 1000;
const OTHER_UID: u32 = 61950;
const AGENT: &str = "claude-code";

fn slot_uid(n: u32) -> u32 {
    61000 + n
}
fn unit(n: u32) -> String {
    format!("agent-session@{n}.service")
}
fn unit_cgroup(n: u32) -> String {
    format!("0::/system.slice/{}", unit(n))
}

// ---------------------------------------------------------------------------
// Small helpers.
// ---------------------------------------------------------------------------

/// Collects every failed check, so one run reports all of them.
#[derive(Default)]
struct Problems(Vec<String>);

impl Problems {
    fn check(&mut self, ok: bool, what: impl FnOnce() -> String) {
        if !ok {
            self.0.push(what());
        }
    }
    fn finish(self, test: &str) {
        assert!(
            self.0.is_empty(),
            "{test}: {} failed assertion(s):\n- {}",
            self.0.len(),
            self.0.join("\n- ")
        );
    }
}

fn passwd_name_of_uid() -> String {
    // SAFETY: getuid takes no arguments and can't fail.
    let uid = unsafe { libc::getuid() };
    fs::read_to_string("/etc/passwd")
        .unwrap_or_default()
        .lines()
        .find_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            (f.len() >= 3 && f[2].parse::<u32>() == Ok(uid)).then(|| f[0].to_string())
        })
        .unwrap_or_else(|| panic!("no account in /etc/passwd has uid {uid}"))
}

fn cleaned_path() -> OsString {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let kept: Vec<PathBuf> = std::env::split_paths(&path)
        .filter(|p| !p.to_string_lossy().contains(".agent-sign"))
        .collect();
    std::env::join_paths(kept).unwrap()
}

fn find_on(path: &OsString, name: &str) -> PathBuf {
    std::env::split_paths(path)
        .map(|d| d.join(name))
        .find(|p| p.is_file())
        .unwrap_or_else(|| panic!("no {name} on the cleaned PATH"))
}

fn run_within(mut cmd: Command, what: &str) -> Output {
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("{what}: couldn't start: {e}"));
    let start = Instant::now();
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if start.elapsed() > RUN_LIMIT {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{what} didn't finish within {RUN_LIMIT:?}");
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn hex(n: usize) -> String {
    let mut s = String::new();
    while s.len() < n {
        s += &uuid::Uuid::new_v4().simple().to_string();
    }
    s.truncate(n);
    s
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

// ---------------------------------------------------------------------------
// The kernel-facts seam, as a test drives it.
// ---------------------------------------------------------------------------

/// What the kernel reports about the next connection.
#[derive(Clone)]
struct Peer {
    uid: u32,
    cgroup: String,
    process: &'static str,
}

impl Peer {
    fn new(uid: u32, cgroup: &str) -> Peer {
        Peer {
            uid,
            cgroup: cgroup.to_string(),
            process: "alive",
        }
    }
    /// A process of slot `n`'s account inside slot `n`'s session unit.
    fn session_of(n: u32) -> Peer {
        Peer::new(slot_uid(n), &unit_cgroup(n))
    }
    /// The launcher: its account, in its own service.
    fn launcher() -> Peer {
        Peer::new(LAUNCHER_UID, "0::/system.slice/agent-launchd.service")
    }
    fn gone(mut self) -> Peer {
        self.process = "gone";
        self
    }
}

// ---------------------------------------------------------------------------
// The isolated world and the service under test.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    System,
    OneAccount,
}

/// Where `[authority]` points.
enum Authority<'a> {
    /// The `openbao` issuer at a loopback port nothing listens on.
    Closed,
    /// The dev server behind its TLS front.
    Bao(&'a BaoWorld),
}

struct World {
    _dir: TempDir,
    root: PathBuf,
    home: PathBuf,
    socket: PathBuf,
    launcher_socket: PathBuf,
    facts: PathBuf,
    trust: PathBuf,
    path: OsString,
    real_git: PathBuf,
}

#[allow(dead_code)]
struct Service {
    child: Child,
    log: PathBuf,
}

#[allow(dead_code)]
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

static LAUNCHES: AtomicUsize = AtomicUsize::new(0);

impl World {
    fn new() -> World {
        let dir = tempdir().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        let home = root.join("home");
        fs::create_dir_all(agent_sign::paths::state_dir_in(&home)).unwrap();
        fs::create_dir_all(root.join("service-cwd")).unwrap();
        fs::create_dir_all(root.join("repo")).unwrap();
        let path = cleaned_path();
        let w = World {
            real_git: find_on(&path, "git"),
            socket: root.join("daemon.sock"),
            launcher_socket: root.join("launcher.sock"),
            facts: root.join("kernel-facts.json"),
            trust: root.join("allowed_signers"),
            _dir: dir,
            root,
            home,
            path,
        };
        // The trust file holds a public key made in memory from a fixed seed
        // (nothing here signs with it).
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
        w.set_peer(&Peer::new(PERSON_UID, "0::/user.slice"));
        w
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
            "peer": {"uid": peer.uid, "cgroup": peer.cgroup, "process": peer.process}
        });
        let tmp = self.root.join("kernel-facts.json.tmp");
        fs::write(&tmp, facts.to_string()).unwrap();
        fs::rename(&tmp, &self.facts).unwrap();
    }

    fn system_toml(&self, authority: &Authority) -> String {
        let account = passwd_name_of_uid();
        let r = &self.root;
        let auth = match authority {
            Authority::Closed => "address = \"https://127.0.0.1:1\"\nca_cert = \"/etc/ssl/certs/ca-certificates.crt\"\n\
                 resolve = \"127.0.0.1\"\n"
                .to_string(),
            Authority::Bao(b) => format!(
                "address = \"https://{HOSTNAME}:{}\"\nca_cert = \"{}\"\nresolve = \"127.0.0.1\"\n",
                b.front.port,
                b.front.ca_pem.display()
            ),
        };
        format!(
            "machine = \"{MACHINE}\"\n\n[service]\naccount = \"{account}\"\nsocket = \"{}\"\n\
             launcher_socket = \"{}\"\ntrust_file = \"{}\"\nclient_accounts = [\"{account}\"]\n\n\
             [launcher]\naccount = \"{LAUNCHER_ACCOUNT}\"\nsocket = \"{}\"\npeople_accounts = [\"taylor\"]\n\
             approvers = []\n\n[slots]\ncount = 8\naccount_prefix = \"agent-slot-\"\nroot = \"{}\"\n\
             max_duration = \"12h\"\n\n[identity]\npeople = [\"Taylor\"]\n\n[authority]\n\
             issuer = \"openbao\"\n{auth}mount = \"{MOUNT}\"\nrole = \"{ROLE}\"\n\n\
             [security]\nmax_commits_per_minute = 100\n",
            self.socket.display(),
            self.launcher_socket.display(),
            self.trust.display(),
            r.join("launch.sock").display(),
            r.join("slots").display(),
        )
    }

    /// The environment every program here starts from.
    fn env(&self, mode: Mode) -> Vec<(String, OsString)> {
        let seam = match mode {
            Mode::System => self.root.join("system.toml"),
            Mode::OneAccount => self.root.join("no-system.toml"),
        };
        let mut env: Vec<(String, OsString)> = Vec::new();
        for keep in ["TMPDIR", "USER", "LOGNAME", "LANG", "LC_ALL"] {
            if let Some(v) = std::env::var_os(keep) {
                env.push((keep.into(), v));
            }
        }
        env.extend([
            ("HOME".into(), self.home.clone().into_os_string()),
            ("PATH".into(), self.path.clone()),
            ("TZ".into(), "UTC".into()),
            ("GIT_CONFIG_GLOBAL".into(), "/dev/null".into()),
            ("GIT_CONFIG_NOSYSTEM".into(), "1".into()),
            ("GIT_TERMINAL_PROMPT".into(), "0".into()),
            ("AGENT_SIGN_TEST_AUTH".into(), "fail".into()),
            ("AGENT_SIGN_CONNECT_WAIT_MS".into(), "200".into()),
            (
                "AGENT_SIGN_TEST_SYSTEM_CONFIG".into(),
                seam.into_os_string(),
            ),
            (
                "AGENT_SIGN_TEST_KERNEL_FACTS".into(),
                self.facts.clone().into_os_string(),
            ),
            (
                "AGENT_SIGN_REAL_GIT".into(),
                self.real_git.clone().into_os_string(),
            ),
        ]);
        env
    }

    /// Writes `system.toml` (system mode) or a laptop's `config.toml`, and
    /// starts `agent-signd`; waits for its socket. `creds` is the folder the
    /// service's login credentials are in, if any.
    fn start(
        &self,
        mode: Mode,
        authority: &Authority,
        creds: Option<&Path>,
    ) -> Result<Service, String> {
        match mode {
            Mode::System => {
                fs::write(self.root.join("system.toml"), self.system_toml(authority)).unwrap()
            }
            Mode::OneAccount => fs::write(
                agent_sign::paths::state_dir_in(&self.home).join("config.toml"),
                format!("[identity]\nmachine = \"{MACHINE}\"\n"),
            )
            .unwrap(),
        }
        let _ = fs::remove_file(&self.socket);
        let n = LAUNCHES.fetch_add(1, Ordering::SeqCst);
        let log_path = self.root.join(format!("service-{n}.log"));
        let log = fs::File::create(&log_path).unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_agent-signd"));
        cmd.arg("--socket")
            .arg(&self.socket)
            .env_clear()
            .envs(self.env(mode))
            .current_dir(self.root.join("service-cwd"))
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log));
        if let Some(c) = creds {
            cmd.env("CREDENTIALS_DIRECTORY", c);
        }
        let mut child = cmd.spawn().expect("couldn't start agent-signd");
        let read_log = || fs::read_to_string(&log_path).unwrap_or_default();
        let start = Instant::now();
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                return Err(format!(
                    "the service stopped at start ({status}); log:\n{}",
                    read_log()
                ));
            }
            if self.socket.exists() {
                return Ok(Service {
                    child,
                    log: log_path,
                });
            }
            if start.elapsed() > START_LIMIT {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!(
                    "the service never opened its socket; log:\n{}",
                    read_log()
                ));
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn start_ok(&self, mode: Mode, authority: &Authority, creds: Option<&Path>) -> Service {
        self.start(mode, authority, creds)
            .unwrap_or_else(|e| panic!("CONTROL: {e}"))
    }

    /// One ordinary request on the service's socket from a process the
    /// kernel describes as `peer`.
    fn ask_as(&self, peer: &Peer, req: &Request) -> Result<Response, String> {
        self.set_peer(peer);
        send_request_waiting(&self.socket, req, Duration::from_secs(3)).map_err(|e| e.to_string())
    }

    /// The launcher's registration of slot `n` on `socket`, as `peer`,
    /// naming `uid` and `unit`. The stream is kept: the session lasts while
    /// it is open.
    fn register_on(
        &self,
        socket: &Path,
        peer: &Peer,
        slot: u32,
        uid: u32,
        unit_name: &str,
    ) -> Result<Registration, String> {
        self.set_peer(peer);
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut stream = loop {
            match UnixStream::connect(socket) {
                Ok(s) => break s,
                Err(e) if Instant::now() > deadline => {
                    return Err(format!("can't connect to {}: {e}", socket.display()));
                }
                Err(_) => thread::sleep(Duration::from_millis(50)),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let req = json!({"type": "RegisterSession", "payload":
            {"slot": slot, "uid": uid, "unit": unit_name, "agent": AGENT}});
        stream
            .write_all(format!("{req}\n").as_bytes())
            .map_err(|e| format!("write: {e}"))?;
        let mut line = String::new();
        BufReader::new(stream.try_clone().unwrap())
            .read_line(&mut line)
            .map_err(|e| format!("no answer ({e})"))?;
        match serde_json::from_str::<Response>(&line) {
            Ok(Response::SessionStarted { principal, session }) => Ok(Registration {
                _stream: stream,
                principal,
                session,
            }),
            Ok(Response::Error { message }) => Err(message),
            other => Err(format!("unexpected answer {other:?} to {line:?}")),
        }
    }

    /// The launcher registers slot `n` properly, on the launcher-only socket.
    fn register_slot(&self, n: u32) -> Result<Registration, String> {
        self.register_on(
            &self.launcher_socket,
            &Peer::launcher(),
            n,
            slot_uid(n),
            &unit(n),
        )
    }

    /// What the service says a caller is: `Some(principal)` only for a
    /// session; `None` for an error or silence.
    fn session_principal(&self, peer: &Peer) -> Option<String> {
        match self.ask_as(peer, &Request::SessionIdentity) {
            Ok(Response::SessionIdentity { identity }) => Some(identity.principal),
            _ => None,
        }
    }

    fn pongs(&self, peer: &Peer) -> bool {
        matches!(self.ask_as(peer, &Request::Ping), Ok(Response::Pong))
    }

    /// Slot 1 registered, and the positive control that its own process is
    /// that session: every refusal test starts from this, so that none passes
    /// merely because nothing works yet.
    fn slot1_with_control(&self) -> (Registration, String) {
        let reg = self
            .register_slot(1)
            .unwrap_or_else(|e| panic!("CONTROL: the launcher couldn't register slot 1: {e}"));
        let got = self.session_principal(&Peer::session_of(1));
        assert_eq!(
            got.as_deref(),
            Some(reg.principal.as_str()),
            "CONTROL: a slot-1 process in its unit isn't the registered session"
        );
        let p = reg.principal.clone();
        (reg, p)
    }
}

struct Registration {
    _stream: UnixStream,
    principal: String,
    session: String,
}

// ---------------------------------------------------------------------------
// 1. A request counts as a session only on uid + unit + live process.
// ---------------------------------------------------------------------------

/// The positive case. Fails today: there is no launcher-only socket and no
/// registration, so slot 1 can't be registered, and the ordinary socket
/// knows sessions only by channel.
#[test]
fn a_slot_process_in_its_session_unit_is_that_session() {
    let w = World::new();
    let svc = w.start_ok(Mode::System, &Authority::Closed, None);
    let reg = w.register_slot(1);
    let mut p = Problems::default();
    match &reg {
        Err(e) => p.check(false, || {
            format!("the launcher couldn't register slot 1: {e}")
        }),
        Ok(r) => {
            let got = w.session_principal(&Peer::session_of(1));
            p.check(got.as_deref() == Some(r.principal.as_str()), || {
                format!(
                    "a slot-1 process in {} got identity {got:?}, wanted {:?}",
                    unit(1),
                    r.principal
                )
            });
            p.check(r.principal.ends_with(&format!("@{DOMAIN}")), || {
                format!("principal {} isn't in {DOMAIN}", r.principal)
            });
        }
    }
    drop(svc);
    p.finish("a_slot_process_in_its_session_unit_is_that_session");
}

/// Another uid is refused, even inside the unit, and even when it is the uid
/// of a different slot that is itself registered. Fails today at the control.
#[test]
fn another_uid_in_the_unit_is_not_the_session() {
    let w = World::new();
    let _svc = w.start_ok(Mode::System, &Authority::Closed, None);
    let (_one, _) = w.slot1_with_control();
    let _two = w.register_slot(2).expect("CONTROL: slot 2 registers");
    let mut p = Problems::default();
    for (what, peer) in [
        (
            "slot 2's account in slot 1's unit",
            Peer::new(slot_uid(2), &unit_cgroup(1)),
        ),
        (
            "an unrelated account in slot 1's unit",
            Peer::new(OTHER_UID, &unit_cgroup(1)),
        ),
        (
            "Taylor's account in slot 1's unit",
            Peer::new(PERSON_UID, &unit_cgroup(1)),
        ),
    ] {
        let got = w.session_principal(&peer);
        p.check(got.is_none(), || {
            format!("{what} was taken for the session {got:?}")
        });
    }
    p.finish("another_uid_in_the_unit_is_not_the_session");
}

/// The right uid outside the unit is a plain caller: no session, but still
/// answered on the plain path. Fails today at the control.
#[test]
fn the_right_uid_outside_its_unit_is_plain() {
    let w = World::new();
    let _svc = w.start_ok(Mode::System, &Authority::Closed, None);
    let (_one, _) = w.slot1_with_control();
    let _two = w.register_slot(2).expect("CONTROL: slot 2 registers");
    let mut p = Problems::default();
    for (what, peer) in [
        (
            "slot 1's account in a login scope (a cron job, say)",
            Peer::new(
                slot_uid(1),
                "0::/user.slice/user-61001.slice/session-3.scope",
            ),
        ),
        (
            "slot 1's account in slot 2's unit",
            Peer::new(slot_uid(1), &unit_cgroup(2)),
        ),
        (
            "slot 1's account in the service's own unit",
            Peer::new(slot_uid(1), "0::/system.slice/agent-signd.service"),
        ),
    ] {
        let got = w.session_principal(&peer);
        p.check(got.is_none(), || {
            format!("{what} was taken for the session {got:?}")
        });
        p.check(w.pongs(&peer), || {
            format!("{what} wasn't answered on the plain path")
        });
    }
    p.finish("the_right_uid_outside_its_unit_is_plain");
}

/// A recycled pid: the cgroup read matched, but the pidfd says the process
/// is not the one that was read. Refused outright, never a session and never
/// answered. Fails today at the control.
#[test]
fn a_caller_whose_process_is_gone_is_refused() {
    let w = World::new();
    let _svc = w.start_ok(Mode::System, &Authority::Closed, None);
    let (_one, _) = w.slot1_with_control();
    let mut p = Problems::default();
    for (what, peer) in [
        (
            "a gone process with slot 1's uid and unit",
            Peer::session_of(1).gone(),
        ),
        (
            "a gone process of an unrelated account",
            Peer::new(OTHER_UID, "0::/user.slice").gone(),
        ),
    ] {
        let got = w.session_principal(&peer);
        p.check(got.is_none(), || {
            format!("{what} was taken for the session {got:?}")
        });
        p.check(!w.pongs(&peer), || {
            format!("{what} was answered, not refused")
        });
    }
    p.finish("a_caller_whose_process_is_gone_is_refused");
}

// ---------------------------------------------------------------------------
// 2. Registration: the launcher-only socket, from the launcher's account.
// ---------------------------------------------------------------------------

/// Any other peer uid is refused on the launcher-only socket, and a refusal
/// leaves the slot free for the real launcher. Fails today: the control (the
/// launcher registering) finds no launcher socket.
#[test]
fn only_the_launcher_account_registers() {
    let w = World::new();
    let _svc = w.start_ok(Mode::System, &Authority::Closed, None);
    let mut p = Problems::default();
    for (what, peer) in [
        ("slot 1's own account", Peer::session_of(1)),
        ("Taylor's account", Peer::new(PERSON_UID, "0::/user.slice")),
        (
            "an unrelated account",
            Peer::new(OTHER_UID, "0::/user.slice"),
        ),
        (
            "the service's own account",
            Peer::new(
                unsafe { libc::getuid() },
                "0::/system.slice/agent-signd.service",
            ),
        ),
    ] {
        let r = w.register_on(&w.launcher_socket, &peer, 1, slot_uid(1), &unit(1));
        p.check(r.is_err(), || {
            format!("{what} registered a session on the launcher socket")
        });
        drop(r);
    }
    // Control, last: none of the refusals took the slot.
    let r = w.register_slot(1);
    p.check(r.is_ok(), || {
        format!(
            "the configured launcher account couldn't register slot 1: {:?}",
            r.err()
        )
    });
    p.finish("only_the_launcher_account_registers");
}

/// Registration is not accepted on the ordinary socket, not even from the
/// launcher account. Fails today at the control.
#[test]
fn registration_is_accepted_only_on_the_launcher_socket() {
    let w = World::new();
    let _svc = w.start_ok(Mode::System, &Authority::Closed, None);
    let mut p = Problems::default();
    let r = w.register_on(&w.socket, &Peer::launcher(), 1, slot_uid(1), &unit(1));
    p.check(r.is_err(), || {
        "the launcher registered a session on the ordinary socket".into()
    });
    drop(r);
    let c = w.register_slot(1);
    p.check(c.is_ok(), || {
        format!(
            "the launcher socket didn't take the registration: {:?}",
            c.err()
        )
    });
    p.finish("registration_is_accepted_only_on_the_launcher_socket");
}

// ---------------------------------------------------------------------------
// 3. The attestation's words.
// ---------------------------------------------------------------------------

/// `isolation=slot-account` reads back as itself, and `verify` (which words
/// an attestation with `Attestation::describe`, and treats a launcher
/// attestation as attested) never calls it claimed or unattested. Fails
/// today: `slot-account` isn't an isolation `decode` knows, so the
/// extension would read as unreadable, which `verify` words as "claimed".
#[test]
fn a_slot_account_attestation_is_worded_without_claimed_or_unattested() {
    let words = "launcher session=0123456789abcdef uid=61001 isolation=slot-account";
    let mut p = Problems::default();
    let decoded = Attestation::decode(words);
    p.check(decoded.is_some(), || format!("{words:?} doesn't decode"));
    if let Some(a) = decoded {
        p.check(a.encode() == words, || {
            format!("it re-encodes as {:?}", a.encode())
        });
        let said = a.describe();
        p.check(
            !said.contains("claimed") && !said.contains("unattested"),
            || format!("verify words it as {said:?}"),
        );
        p.check(said.contains("own account"), || {
            format!("verify doesn't say the session ran in an account of its own: {said:?}")
        });
        p.check(!said.contains("shared account"), || {
            format!("it says shared account: {said:?}")
        });
    }
    p.finish("a_slot_account_attestation_is_worded_without_claimed_or_unattested");
}

// ---------------------------------------------------------------------------
// 4. System mode signs through the OpenBao issuer (dev server).
// ---------------------------------------------------------------------------

/// A slot session signs a commit in system mode; the certificate is
/// OpenBao's (the trust file holds only OpenBao's CA, so the signature
/// verifies only if OpenBao's CA issued it) and carries
/// `isolation=slot-account` with the slot's uid and the session's id. Fails
/// today: the closed stand-in refuses every signature, and there are no
/// slot sessions.
#[test]
#[ignore = "needs bao on PATH (and python3 with the cryptography module for the in-memory TLS front)"]
fn system_mode_signs_through_the_openbao_issuer() {
    let w = World::new();
    let bao = BaoWorld::new(&w.root);
    fs::write(
        &w.trust,
        format!("{}\n", trust_line_in(DOMAIN, &bao.ca_line)),
    )
    .unwrap();
    let _svc = w.start_ok(Mode::System, &Authority::Bao(&bao), Some(&bao.creds));
    let reg = w
        .register_slot(1)
        .unwrap_or_else(|e| panic!("CONTROL: slot 1 didn't register: {e}"));
    let me = Peer::session_of(1);
    let mut p = Problems::default();
    let repo = w.root.join("repo").to_string_lossy().into_owned();
    let identity = match w.ask_as(&me, &Request::SessionIdentity) {
        Ok(Response::SessionIdentity { identity }) => identity,
        other => panic!("CONTROL: no session identity: {other:?}"),
    };
    match w.ask_as(
        &me,
        &Request::RequestLease {
            repo: repo.clone(),
            branch: "work".into(),
            intent: "test".into(),
            duration_secs: Some(600),
        },
    ) {
        Ok(Response::LeaseGranted { .. }) => {}
        other => panic!("CONTROL: no lease: {other:?}"),
    }
    let token = match w.ask_as(
        &me,
        &Request::IssueRunToken {
            repo: repo.clone(),
            branch: "work".into(),
            identity: identity.clone(),
        },
    ) {
        Ok(Response::TokenIssued { token }) => token,
        other => panic!("CONTROL: no token: {other:?}"),
    };
    let buffer = commit_buffer(&identity.principal);
    use base64::Engine;
    let signed = w.ask_as(
        &me,
        &Request::SignCommit {
            token,
            buffer_b64: base64::engine::general_purpose::STANDARD.encode(&buffer),
            repo: Some(repo),
            branch: Some("work".into()),
        },
    );
    match signed {
        Ok(Response::Signed { signature_pem }) => {
            p.check(
                good_under(
                    &w.trust,
                    &identity.principal,
                    &signature_pem,
                    &buffer,
                    &w.root,
                ),
                || "the signature doesn't verify under OpenBao's CA in the trust file".into(),
            );
            let cert = agent_sign::verify::sshsig_public_key(&signature_pem)
                .and_then(|blob| Certificate::from_bytes(&blob).ok());
            match cert {
                None => p.check(false, || "the signature carries no certificate".into()),
                Some(c) => {
                    let ext = c.extensions().get(EXTENSION).cloned();
                    let want = format!(
                        "launcher session={} uid={} isolation=slot-account",
                        reg.session,
                        slot_uid(1)
                    );
                    p.check(ext.as_deref() == Some(want.as_str()), || {
                        format!("the certificate's attestation is {ext:?}, wanted {want:?}")
                    });
                }
            }
        }
        other => p.check(false, || {
            format!("the slot session's commit wasn't signed: {other:?}")
        }),
    }
    p.finish("system_mode_signs_through_the_openbao_issuer");
}

fn commit_buffer(principal: &str) -> Vec<u8> {
    let now = now_secs();
    format!(
        "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\nauthor Agent <{principal}> {now} +0000\n\
         committer Agent <{principal}> {now} +0000\n\nan agent's commit\n"
    )
    .into_bytes()
}

fn good_under(trust: &Path, principal: &str, signature: &str, data: &[u8], scratch: &Path) -> bool {
    let sig_file = scratch.join(format!("check-{}.sig", hex(6)));
    fs::write(&sig_file, signature).unwrap();
    let mut child = Command::new("ssh-keygen")
        .args(["-Y", "verify", "-n", "git", "-I", principal, "-f"])
        .arg(trust)
        .arg("-s")
        .arg(&sig_file)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("ssh-keygen");
    child.stdin.take().unwrap().write_all(data).unwrap();
    let ok = child.wait().unwrap().success();
    let _ = fs::remove_file(&sig_file);
    ok
}

// ---------------------------------------------------------------------------
// 5. Doctor in system mode.
// ---------------------------------------------------------------------------

fn doctor(w: &World) -> String {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_agent-sign"));
    cmd.arg("doctor")
        .env_clear()
        .envs(w.env(Mode::System))
        .current_dir(&w.home)
        .stdin(Stdio::null());
    let out = run_within(cmd, "agent-sign doctor");
    format!("{}{}", text(&out.stdout), text(&out.stderr))
}

/// With a running system-mode service, doctor finds its socket through
/// `system.toml` (no `AGENT_SIGN_SOCKET`) and prints `ping: ok`, the exact
/// line the sitting waits for. Fails today: doctor prints "Daemon socket
/// active and responsive", never `ping: ok`.
#[test]
fn doctor_in_system_mode_prints_ping_ok() {
    let w = World::new();
    let _svc = w.start_ok(Mode::System, &Authority::Closed, None);
    let out = doctor(&w);
    assert!(
        out.contains("ping: ok"),
        "doctor didn't print `ping: ok`; it said:\n{out}"
    );
}

/// Doctor prints `authority: OpenBao CA matches the trust file` when the CA
/// OpenBao reports is the trust file's, and does not when the trust file
/// holds another key (so the line is a check, not a constant). Fails today:
/// doctor knows nothing of OpenBao.
#[test]
#[ignore = "needs bao on PATH (and python3 with the cryptography module for the in-memory TLS front)"]
fn doctor_says_the_openbao_ca_matches_the_trust_file_when_it_does() {
    const MATCH: &str = "authority: OpenBao CA matches the trust file";
    let w = World::new();
    let bao = BaoWorld::new(&w.root);
    let good = trust_line_in(DOMAIN, &bao.ca_line);
    let mut p = Problems::default();
    {
        fs::write(&w.trust, format!("{good}\n")).unwrap();
        let _svc = w.start_ok(Mode::System, &Authority::Bao(&bao), Some(&bao.creds));
        let out = doctor(&w);
        p.check(out.contains("ping: ok"), || {
            format!("no `ping: ok` in:\n{out}")
        });
        p.check(out.contains(MATCH), || {
            format!("no `{MATCH}` with the matching trust file; doctor said:\n{out}")
        });
    }
    {
        // Another key in the trust file: the line must not appear.
        let other = ed25519_dalek::SigningKey::from_bytes(&[77; 32]);
        let line = trust_line_in(
            DOMAIN,
            agent_sign::crypto::openssh_ed25519_line(&other.verifying_key()).trim(),
        );
        fs::write(&w.trust, format!("{line}\n")).unwrap();
        let _svc = w.start_ok(Mode::System, &Authority::Bao(&bao), Some(&bao.creds));
        let out = doctor(&w);
        p.check(!out.contains(MATCH), || {
            format!("doctor says the CA matches although the trust file holds another key:\n{out}")
        });
    }
    p.finish("doctor_says_the_openbao_ca_matches_the_trust_file_when_it_does");
}

// ---------------------------------------------------------------------------
// 6. Guard: one-account mode on a laptop is unchanged.
// ---------------------------------------------------------------------------

/// Without `system.toml` the seam is not consulted, no launcher socket is
/// made, the old `LaunchSession` and its channel still work, and a plain
/// process is plain even if the (ignored) kernel facts claim it is in a slot
/// unit. Passes today and must keep passing.
#[test]
fn one_account_mode_is_unchanged() {
    use agent_sign::session::{Channel, read_line_with_fd};
    let w = World::new();
    let _svc = w.start_ok(Mode::OneAccount, &Authority::Closed, None);
    // Facts that would make this process slot 1's session in system mode.
    w.set_peer(&Peer::session_of(1));
    let mut p = Problems::default();
    p.check(!w.launcher_socket.exists(), || {
        "a launcher socket exists in one-account mode".into()
    });
    p.check(w.session_principal(&Peer::session_of(1)).is_none(), || {
        "a plain process was taken for a session because of kernel facts".into()
    });
    p.check(w.pongs(&Peer::session_of(1)), || {
        "the plain socket doesn't answer".into()
    });
    let mut reg = UnixStream::connect(&w.socket).unwrap();
    reg.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let req = serde_json::to_string(&Request::LaunchSession {
        agent: AGENT.into(),
    })
    .unwrap();
    reg.write_all(format!("{req}\n").as_bytes()).unwrap();
    match read_line_with_fd(&reg) {
        Ok((line, Some(fd))) => match serde_json::from_str::<Response>(&line) {
            Ok(Response::SessionStarted { principal, .. }) => {
                match Channel::check(fd.as_raw_fd()) {
                    Ok(ch) => match ch.ask(&Request::SessionIdentity) {
                        Ok(Response::SessionIdentity { identity }) => p
                            .check(identity.principal == principal, || {
                                format!("channel identity {} != {principal}", identity.principal)
                            }),
                        other => p.check(false, || format!("channel SessionIdentity: {other:?}")),
                    },
                    Err(e) => p.check(false, || format!("the channel isn't one: {e}")),
                }
            }
            other => p.check(false, || format!("LaunchSession answered {other:?}")),
        },
        other => p.check(false, || {
            format!("LaunchSession gave no channel: {other:?}")
        }),
    }
    p.finish("one_account_mode_is_unchanged");
}

// ---------------------------------------------------------------------------
// The dev server and its TLS front (from test_issuer_openbao.rs).
// ---------------------------------------------------------------------------

const FRONT: &str = r#"
import os, sys, ssl, socket, select, threading, datetime
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

upstream, variant, ca_out, host = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
now = datetime.datetime.now(datetime.timezone.utc)
day = datetime.timedelta(days=1)
def nm(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
def usage(**kw):
    base = dict(digital_signature=False, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False)
    base.update(kw)
    return x509.KeyUsage(**base)
ca_key = ec.generate_private_key(ec.SECP256R1())
ca = (x509.CertificateBuilder().subject_name(nm("front test CA")).issuer_name(nm("front test CA"))
      .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
      .not_valid_before(now - day).not_valid_after(now + day)
      .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
      .add_extension(usage(key_cert_sign=True, crl_sign=True), critical=True)
      .sign(ca_key, hashes.SHA256()))
leaf_key = ec.generate_private_key(ec.SECP256R1())
dns = "elsewhere.test" if variant == "wrong-name" else host
leaf = (x509.CertificateBuilder().subject_name(nm(dns)).issuer_name(ca.subject)
        .public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - day).not_valid_after(now + day)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(dns)]), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(usage(digital_signature=True), critical=True)
        .sign(ca_key, hashes.SHA256()))
del ca_key
with open(ca_out, "wb") as f:
    f.write(ca.public_bytes(serialization.Encoding.PEM))
def mem(data):
    fd = os.memfd_create("front", 0)
    os.write(fd, data)
    return "/proc/self/fd/%d" % fd
cert_path = mem(leaf.public_bytes(serialization.Encoding.PEM))
key_path = mem(leaf_key.private_bytes(serialization.Encoding.PEM,
                                      serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
del leaf_key
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
if variant == "tls12":
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
else:
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
ctx.load_cert_chain(cert_path, key_path)

def handle(raw):
    try:
        tls = ctx.wrap_socket(raw, server_side=True)
    except Exception:
        try:
            raw.close()
        except Exception:
            pass
        return
    try:
        up = socket.create_connection(("127.0.0.1", upstream), timeout=10)
    except Exception:
        try:
            tls.close()
        except Exception:
            pass
        return
    # One thread per connection: an SSL object must not be used from two
    # threads at once (OpenSSL aborts the process), so one loop moves both ways.
    tls.settimeout(30)
    up.settimeout(30)
    client_open = True
    began = __import__('time').time()
    try:
        while __import__('time').time() - began < 120:
            watch = [up] + ([tls] if client_open else [])
            ready = select.select(watch, [], [], 5.0)[0]
            if client_open and (tls in ready or tls.pending()):
                d = tls.recv(65536)
                if d:
                    up.sendall(d)
                else:
                    client_open = False
                    up.shutdown(socket.SHUT_WR)
            if up in ready:
                d = up.recv(65536)
                if not d:
                    break
                tls.sendall(d)
    except Exception:
        pass
    try:
        tls.settimeout(2)
        tls = tls.unwrap()
    except Exception:
        pass
    for s in (tls, up):
        try:
            s.close()
        except Exception:
            pass

srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 0))
srv.listen(64)
print("READY", srv.getsockname()[1], flush=True)
while True:
    raw, _ = srv.accept()
    threading.Thread(target=handle, args=(raw,), daemon=True).start()
"#;

struct Front {
    child: Child,
    port: u16,
    ca_pem: PathBuf,
}

impl Front {
    fn start(dir: &Path, upstream: u16) -> Front {
        let ca_pem = dir.join("front-ca.pem");
        let err_path = dir.join("front.err");
        let mut child = Command::new("python3")
            .arg("-I")
            .arg("-c")
            .arg(FRONT)
            .arg(upstream.to_string())
            .arg("good")
            .arg(&ca_pem)
            .arg(HOSTNAME)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(fs::File::create(&err_path).unwrap())
            .spawn()
            .unwrap_or_else(|e| panic!("NEEDS python3 for the in-memory TLS front: {e}"));
        let mut stdout = child.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let mut line = Vec::new();
            let mut byte = [0u8; 1];
            while stdout.read(&mut byte).is_ok_and(|n| n == 1) && byte[0] != b'\n' {
                line.push(byte[0]);
            }
            let _ = tx.send(text(&line));
        });
        let line = rx.recv_timeout(Duration::from_secs(30)).unwrap_or_default();
        let port = line
            .strip_prefix("READY ")
            .and_then(|p| p.trim().parse::<u16>().ok())
            .unwrap_or_else(|| {
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "NEEDS python3 with the cryptography module for the TLS front; it said {line:?}: {}",
                    fs::read_to_string(&err_path).unwrap_or_default()
                )
            });
        Front {
            child,
            port,
            ca_pem,
        }
    }
}

impl Drop for Front {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A throwaway OpenBao set up the way the sitting will, behind a TLS front.
struct BaoWorld {
    child: Child,
    front: Front,
    ca_line: String,
    creds: PathBuf,
}

impl Drop for BaoWorld {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn bindable(port: u16) -> bool {
    TcpListener::bind(("127.0.0.1", port)).is_ok()
}

impl BaoWorld {
    fn new(dir: &Path) -> BaoWorld {
        match Command::new("bao").arg("version").output() {
            Ok(o) if o.status.success() => {}
            _ => panic!("NEEDS bao on PATH: `bao version` didn't run"),
        }
        let root = hex(32);
        let seed = std::process::id() as u64 * 2654435761
            + SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .subsec_nanos() as u64;
        let mut port = 30000 + (seed % 15000) as u16;
        while !(bindable(port) && bindable(port + 1)) {
            port += 2;
        }
        let log = fs::File::create(dir.join("bao.log")).unwrap();
        let child = Command::new("bao")
            .args(["server", "-dev", "-dev-no-store-token"])
            .arg(format!("-dev-listen-address=127.0.0.1:{port}"))
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", dir)
            .env("BAO_DEV_ROOT_TOKEN_ID", &root)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .unwrap_or_else(|e| panic!("NEEDS bao on PATH: {e}"));
        let mut me = BaoWorld {
            child,
            front: Front {
                child: Command::new("true").spawn().unwrap(),
                port: 0,
                ca_pem: PathBuf::new(),
            },
            ca_line: String::new(),
            creds: dir.join("creds"),
        };
        let start = Instant::now();
        loop {
            if let Ok(mut s) = TcpStream::connect(("127.0.0.1", port)) {
                let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
                let _ = s.write_all(b"GET /v1/sys/health HTTP/1.0\r\n\r\n");
                let mut got = String::new();
                let _ = s.read_to_string(&mut got);
                if got.starts_with("HTTP/1.1 200") || got.starts_with("HTTP/1.0 200") {
                    break;
                }
            }
            if start.elapsed() > Duration::from_secs(25) {
                panic!(
                    "the dev server wouldn't start: {}",
                    fs::read_to_string(dir.join("bao.log")).unwrap_or_default()
                );
            }
            thread::sleep(Duration::from_millis(50));
        }
        let cli = |args: &[&str], stdin: Option<&str>| -> String {
            let mut cmd = Command::new("bao");
            cmd.args(args)
                .env_clear()
                .env("PATH", std::env::var_os("PATH").unwrap_or_default())
                .env("HOME", dir)
                .env("BAO_ADDR", format!("http://127.0.0.1:{port}"))
                .env("BAO_TOKEN", &root)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let mut c = cmd.spawn().expect("bao");
            if let Some(s) = stdin {
                c.stdin.take().unwrap().write_all(s.as_bytes()).unwrap();
            } else {
                drop(c.stdin.take());
            }
            let out = c.wait_with_output().unwrap();
            assert!(out.status.success(), "bao {args:?}: {}", text(&out.stderr));
            text(&out.stdout).trim().to_string()
        };
        cli(
            &["secrets", "enable", &format!("-path={MOUNT}"), "ssh"],
            None,
        );
        cli(
            &[
                "write",
                &format!("{MOUNT}/config/ca"),
                "generate_signing_key=true",
                "key_type=ed25519",
            ],
            None,
        );
        me.ca_line = cli(
            &["read", "-field=public_key", &format!("{MOUNT}/config/ca")],
            None,
        );
        // The decided role (suite PM, 1 Nov 2026).
        let role = json!({
            "key_type": "ca", "allow_user_certificates": true, "allow_host_certificates": false,
            "allowed_users": "*", "allow_user_key_ids": false,
            "allowed_extensions": EXTENSION, "default_extensions": {},
            "allowed_critical_options": "none@agent-sign", "default_critical_options": {},
            "allowed_user_key_lengths": {"ed25519": 0},
            "ttl": "12h", "max_ttl": "12h", "not_before_duration": "5m"
        });
        cli(
            &["write", &format!("{MOUNT}/roles/{ROLE}"), "-"],
            Some(&role.to_string()),
        );
        cli(&["auth", "enable", "approle"], None);
        let policy = format!(
            "path \"{MOUNT}/sign/{ROLE}\" {{ capabilities = [\"update\"] }}\n\
             path \"auth/token/revoke-self\" {{ capabilities = [\"update\"] }}\n"
        );
        cli(&["policy", "write", ROLE, "-"], Some(&policy));
        cli(
            &[
                "write",
                &format!("auth/approle/role/{ROLE}"),
                &format!("token_policies={ROLE}"),
                "token_no_default_policy=true",
                "token_ttl=15m",
                "token_max_ttl=1h",
            ],
            None,
        );
        let role_id = cli(
            &[
                "read",
                "-field=role_id",
                &format!("auth/approle/role/{ROLE}/role-id"),
            ],
            None,
        );
        let secret_id = cli(
            &[
                "write",
                "-f",
                "-field=secret_id",
                &format!("auth/approle/role/{ROLE}/secret-id"),
            ],
            None,
        );
        fs::create_dir(&me.creds).unwrap();
        for (name, value) in [("role-id", role_id), ("secret-id", secret_id)] {
            let f = me.creds.join(name);
            fs::write(&f, value).unwrap();
            fs::set_permissions(&f, fs::Permissions::from_mode(0o600)).unwrap();
        }
        me.front = Front::start(dir, port);
        me
    }
}
