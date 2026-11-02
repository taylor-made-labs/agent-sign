//! System mode, build step 1: the settings file and the mode switch
//! (docs/system-mode.md, sections 1, 2, 4 and 5, and "Build order" step 1;
//! the suite PM's decisions of 1 Nov 2026, changes (a) and Q3).
//!
//! Written before the build, as its eval. Every test fails today, for the
//! reason in its own doc comment: the service doesn't read
//! `/etc/agent-sign/system.toml` yet (only one-account launch looks at
//! whether the file exists), so it ignores everything in it.
//!
//! **How the tests reach the file.** They can't write `/etc`, so they use
//! the debug-test-only seam `AGENT_SIGN_TEST_SYSTEM_CONFIG`
//! (`agent_sign::launch::system_config_path`, already there for D4) and
//! point it at a `system.toml` in a temporary directory. It is set in the
//! environment of the service or the client under test, so no test changes
//! its own process's environment and the tests can run in parallel. Each
//! test has its own temporary directory, which holds the HOME, the
//! settings file, every socket and every repository; nothing is written
//! anywhere else, and no key of any kind is written to a file (the one
//! public key in the trust file comes from an in-memory ed25519 key, as in
//! `test_launcher_policy.rs`).
//!
//! **What they assume of the build, taken from the design.** The programs
//! are black boxes (`agent-signd`, `agent-sign`), so the builder chooses the
//! module and the wording of messages; the tests fix only these:
//! - the file is the one in the design's example (docs/system-mode.md,
//!   "The settings file"), with the same table and key names; a key the
//!   service doesn't know, in any table or outside any, makes it stop at
//!   start, naming the key and the file, before it touches the state
//!   folder or opens its socket;
//! - the service runs in system mode as the account `[service] account`
//!   and no other; the account is checked first of all ("stops at once,
//!   before it makes anything");
//! - in system mode the authority is OpenBao's alone (section 5): a file
//!   with no `[authority]` issuer, or with an issuer other than `openbao`,
//!   stops the service, naming the word "issuer". A file that names the
//!   `openbao` issuer lets the service start even when OpenBao can't be
//!   reached (section 5, "Fails closed": the service still starts and still
//!   answers plain-path questions), so the tests point `[authority]` at a
//!   loopback port nothing listens on. The CA file named there is the
//!   machine's own public bundle of certificate authorities
//!   (`/etc/ssl/certs/ca-certificates.crt`): public data, no key;
//! - in system mode the service reads only `system.toml`: a `config.toml`
//!   in its state folder is ignored with a warning that names it and says
//!   "ignored", printed when the settings are read, so before anything that
//!   can stop the service for a missing piece. `[security]` takes the keys
//!   it takes in `config.toml`;
//! - the service is started with `--socket <the file's socket>` as well, so
//!   whichever of the two the builder honours, they agree.
//!
//! **One thing this file cannot do yet.** The design asks that system mode
//! never run git in a caller's repository "for a plain-path check and a
//! session sign". A launched session can't exist in system mode until step
//! 2 builds the launcher's registration (one-account launch is refused
//! there, by design), so the signing half of that, which only a session's
//! token reaches (`guardrails::validate_candidate`), has no caller yet. The
//! test here sends every request a plain caller can send, signing requests
//! included, and counts git; step 2's owner extends it with a slot session
//! once one can be made behind the kernel-facts port.
//!
//! Run on a server, never on the Mac:
//! `cargo test --test test_system_config`.

#![cfg(target_os = "linux")]

use std::ffi::OsString;
use std::fs;
use std::io::{BufRead, BufReader};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use tempfile::{TempDir, tempdir};

use agent_sign::attribution::AgentIdentity;
use agent_sign::crypto::openssh_ed25519_line;
use agent_sign::protocol::{Request, Response, send_request_waiting, send_response};

/// The machine every test service is named for, and its agents' domain.
const MACHINE: &str = "hetzner";
const DOMAIN: &str = "hetzner.agents.local";
/// How long a service gets to open its socket or stop at start.
const START_LIMIT: Duration = Duration::from_secs(10);
/// Every program run to completion gets at most this long.
const RUN_LIMIT: Duration = Duration::from_secs(30);
/// The seed of the in-memory key whose public half is the trust file's line.
const TRUST_SEED: [u8; 32] = [21; 32];

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

    fn add(&mut self, what: String) {
        self.0.push(what);
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

fn passwd() -> Vec<(String, u32)> {
    fs::read_to_string("/etc/passwd")
        .unwrap_or_default()
        .lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split(':').collect();
            (f.len() >= 3).then(|| (f[0].to_string(), f[2].parse().unwrap_or(u32::MAX)))
        })
        .collect()
}

/// The login name of the account running the tests.
fn current_account() -> String {
    // SAFETY: getuid takes no arguments and can't fail.
    let uid = unsafe { libc::getuid() };
    passwd()
        .into_iter()
        .find(|(_, u)| *u == uid)
        .map(|(name, _)| name)
        .unwrap_or_else(|| panic!("no account in /etc/passwd has uid {uid}"))
}

/// An account that exists here and isn't `me`.
fn another_existing_account(me: &str) -> String {
    ["root", "nobody", "daemon"]
        .into_iter()
        .find(|c| *c != me && passwd().iter().any(|(n, _)| n == c))
        .expect("none of root, nobody or daemon exists to stand for another account")
        .to_string()
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

/// Runs `cmd` to completion, killing it and failing the test after
/// [`RUN_LIMIT`].
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
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// One request to the service at `socket`, answered `Ok` for
/// `Response::Success` and `Err(message)` for anything else.
fn ask(socket: &Path, request: &Request) -> Result<Response, String> {
    send_request_waiting(socket, request, Duration::from_secs(2)).map_err(|e| e.to_string())
}

fn verdict(answer: Result<Response, String>) -> Result<(), String> {
    match answer {
        Ok(Response::Success) => Ok(()),
        Ok(Response::Error { message }) => Err(message),
        Ok(other) => Err(format!("unexpected answer {other:?}")),
        Err(e) => Err(format!("no answer ({e})")),
    }
}

/// The identity a plain agent process names itself with: no session, on
/// this machine.
fn plain_identity() -> AgentIdentity {
    AgentIdentity::new("claude-code", "Claude Code", None).in_domain(DOMAIN)
}

fn check_plain(socket: &Path, repo: &str, branch: &str) -> Result<(), String> {
    verdict(ask(
        socket,
        &Request::CheckPlainCommit {
            repo: repo.to_string(),
            branch: branch.to_string(),
            identity: plain_identity(),
        },
    ))
}

/// The files and folders in `dir`, as sorted relative paths (recursive).
fn listing(dir: &Path) -> Vec<String> {
    fn walk(base: &Path, dir: &Path, out: &mut Vec<String>) {
        for entry in fs::read_dir(dir).into_iter().flatten().flatten() {
            let path = entry.path();
            out.push(path.strip_prefix(base).unwrap().display().to_string());
            if path.is_dir() {
                walk(base, &path, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out);
    out.sort();
    out
}

// ---------------------------------------------------------------------------
// The settings file, as the design's example writes it.
// ---------------------------------------------------------------------------

/// What `[authority]` holds in a test's `system.toml`.
#[derive(Clone)]
enum Authority {
    /// The design's block, with the `openbao` issuer, pointed at a loopback
    /// port nothing listens on.
    OpenBao,
    /// No `[authority]` table at all.
    Absent,
    /// This text as the table's body.
    Body(&'static str),
}

/// A `system.toml` in the design's shape, with the changes a test wants.
#[derive(Clone)]
struct Doc {
    dir: PathBuf,
    account: String,
    socket: PathBuf,
    authority: Authority,
    max_commits: u32,
    /// `(table, line)`: `""` is the top level; a table the file doesn't
    /// normally have becomes a table of its own at the end.
    extra: Vec<(&'static str, &'static str)>,
    /// If set, the file's whole text instead.
    raw: Option<String>,
}

impl Doc {
    fn account(mut self, account: &str) -> Doc {
        self.account = account.to_string();
        self
    }

    fn socket(mut self, socket: &Path) -> Doc {
        self.socket = socket.to_path_buf();
        self
    }

    fn authority(mut self, authority: Authority) -> Doc {
        self.authority = authority;
        self
    }

    fn max_commits(mut self, n: u32) -> Doc {
        self.max_commits = n;
        self
    }

    fn extra(mut self, table: &'static str, line: &'static str) -> Doc {
        self.extra.push((table, line));
        self
    }

    fn raw(mut self, text: &str) -> Doc {
        self.raw = Some(text.to_string());
        self
    }

    fn render(&self) -> String {
        if let Some(raw) = &self.raw {
            return raw.clone();
        }
        const KNOWN: [&str; 7] = [
            "",
            "service",
            "launcher",
            "slots",
            "identity",
            "authority",
            "security",
        ];
        let d = &self.dir;
        let extras = |table: &str| -> String {
            self.extra
                .iter()
                .filter(|(t, _)| *t == table)
                .map(|(_, line)| format!("{line}\n"))
                .collect()
        };
        let mut s = String::new();
        s += &format!("machine = \"{MACHINE}\"\n{}", extras(""));
        s += &format!(
            "\n[service]\naccount = \"{}\"\nsocket = \"{}\"\nlauncher_socket = \"{}\"\n\
             trust_file = \"{}\"\nclient_accounts = [\"{}\"]\n{}",
            self.account,
            self.socket.display(),
            d.join("launcher.sock").display(),
            d.join("allowed_signers").display(),
            self.account,
            extras("service")
        );
        s += &format!(
            "\n[launcher]\naccount = \"agent-launch\"\nsocket = \"{}\"\n\
             people_accounts = [\"taylor\"]\napprovers = []\n{}",
            d.join("launch.sock").display(),
            extras("launcher")
        );
        s += &format!(
            "\n[slots]\ncount = 8\naccount_prefix = \"agent-slot-\"\nroot = \"{}\"\n\
             max_duration = \"12h\"\n{}",
            d.join("slots").display(),
            extras("slots")
        );
        s += &format!(
            "\n[identity]\npeople = [\"Taylor\"]\n{}",
            extras("identity")
        );
        match &self.authority {
            Authority::OpenBao => {
                s += &format!(
                    "\n[authority]\nissuer = \"openbao\"\naddress = \"https://127.0.0.1:1\"\n\
                     ca_cert = \"/etc/ssl/certs/ca-certificates.crt\"\nresolve = \"127.0.0.1\"\n\
                     mount = \"ssh-agents-{MACHINE}\"\nrole = \"agent-sign-{MACHINE}\"\n{}",
                    extras("authority")
                );
            }
            Authority::Absent => {}
            Authority::Body(body) => {
                s += &format!("\n[authority]\n{body}\n{}", extras("authority"));
            }
        }
        s += &format!(
            "\n[security]\nmax_commits_per_minute = {}\n{}",
            self.max_commits,
            extras("security")
        );
        for (table, line) in &self.extra {
            if !KNOWN.contains(table) {
                s += &format!("\n[{table}]\n{line}\n");
            }
        }
        s
    }
}

// ---------------------------------------------------------------------------
// The isolated world and the service under test.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Mode {
    /// The seam points at the test's `system.toml`.
    System,
    /// The seam points at a path that doesn't exist: a laptop.
    OneAccount,
}

struct World {
    _dir: TempDir,
    root: PathBuf,
    home: PathBuf,
    state: PathBuf,
    socket: PathBuf,
    path: OsString,
    real_git: PathBuf,
}

/// A running service; stopped when dropped.
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

/// What starting the service came to.
enum Outcome {
    /// It opened its socket.
    Running(Service),
    /// It stopped at start, with this status and log.
    Exited(ExitStatus, String),
    /// It neither opened its socket nor stopped within [`START_LIMIT`].
    Hung(String),
}

impl Outcome {
    fn describe(&self) -> String {
        match self {
            Outcome::Running(s) => {
                format!("it started and opened its socket; its log:\n{}", s.log())
            }
            Outcome::Exited(status, log) => {
                format!("it stopped at start ({status}); its log:\n{log}")
            }
            Outcome::Hung(log) => format!("it neither started nor stopped; its log:\n{log}"),
        }
    }
}

static LAUNCHES: AtomicUsize = AtomicUsize::new(0);

impl World {
    fn new() -> World {
        let dir = tempdir().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        let home = root.join("home");
        let state = agent_sign::paths::state_dir_in(&home);
        fs::create_dir_all(&state).unwrap();
        fs::create_dir_all(root.join("service-cwd")).unwrap();
        let path = cleaned_path();
        let key = SigningKey::from_bytes(&TRUST_SEED);
        fs::write(
            root.join("allowed_signers"),
            format!(
                "*@{DOMAIN} cert-authority,namespaces=\"git\" {}\n",
                openssh_ed25519_line(&key.verifying_key())
            ),
        )
        .unwrap();
        World {
            real_git: find_on(&path, "git"),
            socket: root.join("daemon.sock"),
            _dir: dir,
            root,
            home,
            state,
            path,
        }
    }

    /// The `system.toml` this world's tests write (and `Mode::System` names).
    fn system_toml(&self) -> PathBuf {
        self.root.join("system.toml")
    }

    /// A path with nothing at it: the seam's value for `Mode::OneAccount`.
    fn no_system_toml(&self) -> PathBuf {
        self.root.join("no-system.toml")
    }

    fn doc(&self) -> Doc {
        Doc {
            dir: self.root.clone(),
            account: current_account(),
            socket: self.socket.clone(),
            authority: Authority::OpenBao,
            max_commits: 100,
            extra: Vec::new(),
            raw: None,
        }
    }

    fn write_system(&self, doc: &Doc) {
        fs::write(self.system_toml(), doc.render()).unwrap();
    }

    /// An ordinary `config.toml` for the one-account service (and, in
    /// system mode, the file that must be ignored): the machine's name, and
    /// whatever `extra` adds.
    fn write_config_toml(&self, extra: &str) {
        fs::write(
            self.state.join("config.toml"),
            format!("[identity]\nmachine = \"{MACHINE}\"\n{extra}"),
        )
        .unwrap();
    }

    fn seam(&self, mode: Mode) -> PathBuf {
        match mode {
            Mode::System => self.system_toml(),
            Mode::OneAccount => self.no_system_toml(),
        }
    }

    /// The environment every program here starts from.
    fn env(&self, seam: &Path) -> Vec<(String, OsString)> {
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
                seam.as_os_str().to_os_string(),
            ),
        ]);
        env
    }

    /// Starts `agent-signd` on this world's socket and waits for it to open
    /// the socket or stop. `shim`, if given, is the `AGENT_SIGN_REAL_GIT` it
    /// runs git through.
    fn launch(&self, mode: Mode, shim: Option<&Path>) -> Outcome {
        let n = LAUNCHES.fetch_add(1, Ordering::SeqCst);
        let log_path = self.root.join(format!("service-{n}.log"));
        let log = fs::File::create(&log_path).unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_agent-signd"));
        cmd.arg("--socket")
            .arg(&self.socket)
            .env_clear()
            .envs(self.env(&self.seam(mode)))
            .env(
                "AGENT_SIGN_REAL_GIT",
                shim.unwrap_or(self.real_git.as_path()),
            )
            .current_dir(self.root.join("service-cwd"))
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log));
        let mut child = cmd.spawn().expect("couldn't start agent-signd");
        let read_log = || fs::read_to_string(&log_path).unwrap_or_default();
        let start = Instant::now();
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                return Outcome::Exited(status, read_log());
            }
            if self.socket.exists() {
                return Outcome::Running(Service {
                    child,
                    log: log_path,
                });
            }
            if start.elapsed() > START_LIMIT {
                let _ = child.kill();
                let _ = child.wait();
                return Outcome::Hung(read_log());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// `Ok(log)` when the service refused to start in the way a refusal
    /// must look: it stopped, with a failure status, before it opened its
    /// socket. `Err` says what happened instead.
    fn refused(&self, outcome: Outcome) -> Result<String, String> {
        match outcome {
            Outcome::Exited(status, log) if !status.success() && !self.socket.exists() => Ok(log),
            other => Err(format!("it was not refused: {}", other.describe())),
        }
    }

    /// A repository called `name` with one commit, on `branch`; its
    /// canonical path.
    fn make_repo(&self, name: &str, branch: &str) -> PathBuf {
        let dir = self.home.join(name);
        fs::create_dir_all(&dir).unwrap();
        let git = |args: &[&str]| {
            let out = Command::new(&self.real_git)
                .args(args)
                .current_dir(&dir)
                .env_clear()
                .env("PATH", &self.path)
                .env("HOME", &self.home)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "setup git {args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        };
        git(&["init", "-q", "-b", branch]);
        fs::write(dir.join("a.txt"), "a\n").unwrap();
        git(&["add", "a.txt"]);
        git(&[
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.com",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "-m",
            "a",
        ]);
        fs::canonicalize(dir).unwrap()
    }

    /// A git that logs every run (its working directory and arguments) to a
    /// file and then runs the real one: `AGENT_SIGN_REAL_GIT` for a service.
    /// Returns the shim and its log.
    fn counting_git(&self) -> (PathBuf, PathBuf) {
        let log = self.root.join("git-runs.log");
        let shim = self.root.join("counting-git");
        fs::write(
            &shim,
            format!(
                "#!/bin/sh\nprintf 'cwd=%s args=%s\\n' \"$PWD\" \"$*\" >> '{}'\nexec '{}' \"$@\"\n",
                log.display(),
                self.real_git.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&shim, fs::Permissions::from_mode(0o755)).unwrap();
        (shim, log)
    }
}

// ---------------------------------------------------------------------------
// A stand-in service that only counts who connects to it.
// ---------------------------------------------------------------------------

struct FakeService {
    hits: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl FakeService {
    /// Listens at `path`, answers every request with an empty lease list,
    /// and counts the connections.
    fn start(path: &Path) -> FakeService {
        let listener = UnixListener::bind(path).unwrap();
        listener.set_nonblocking(true).unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (h, s) = (Arc::clone(&hits), Arc::clone(&stop));
        let thread = std::thread::spawn(move || {
            while !s.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        h.fetch_add(1, Ordering::SeqCst);
                        let _ = stream.set_nonblocking(false);
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                        let mut line = String::new();
                        let _ = BufReader::new(&stream).read_line(&mut line);
                        let _ = send_response(&mut stream, &Response::LeaseList { leases: vec![] });
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(10)),
                }
            }
        });
        FakeService {
            hits,
            stop,
            thread: Some(thread),
        }
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

impl Drop for FakeService {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

// ===========================================================================
// 1. system.toml parses, and refuses unknown keys.
// ===========================================================================

/// Docs/system-mode.md, "The settings file" and "Build order" step 1.
///
/// The design's whole example parses, is what the service reads (and
/// `config.toml` is ignored with a warning, section 1), and any key the
/// service doesn't know is refused: in any table, outside any table, a
/// whole unknown table, a misspelt `[security]` key, and a file that isn't
/// TOML at all. A refusal names the key and the file, stops the service
/// before it opens its socket, and leaves the state folder as it was.
///
/// Fails today because the service never reads `system.toml`:
/// - A: it starts, but says nothing about ignoring `config.toml`, and uses
///   `config.toml`'s `max_commits_per_minute = 1000` instead of the file's
///   `1`, so a second plain-commit check in the same minute is accepted;
/// - B: every file with an unknown key is accepted, and the service starts
///   and opens its socket (and writes its keys folder).
#[test]
fn system_toml_parses_and_refuses_unknown_keys() {
    let mut p = Problems::default();

    // A. The example parses and is the only file read.
    {
        let w = World::new();
        w.write_config_toml("[security]\nmax_commits_per_minute = 1000\n");
        w.write_system(&w.doc().max_commits(1));
        let repo = w.make_repo("work-repo", "work");
        let repo = repo.to_string_lossy().into_owned();
        match w.launch(Mode::System, None) {
            Outcome::Running(service) => {
                let first = check_plain(&w.socket, &repo, "feature/a");
                p.check(first.is_ok(), || {
                    format!("A: the first plain-commit check was refused: {first:?}")
                });
                let second = check_plain(&w.socket, &repo, "feature/a");
                p.check(
                    matches!(&second, Err(m) if m.contains("Rate limit")),
                    || {
                        format!(
                            "A: system.toml sets [security] max_commits_per_minute = 1 (config.toml \
                             says 1000, and must be ignored), but a second plain-commit check in the \
                             same minute got {second:?} instead of a rate-limit refusal"
                        )
                    },
                );
                let log = service.log().to_lowercase();
                p.check(log.contains("config.toml") && log.contains("ignor"), || {
                    format!(
                        "A: no warning that config.toml is ignored in system mode (it must name \
                         config.toml and say \"ignored\"); the service's log:\n{}",
                        service.log()
                    )
                });
            }
            other => p.add(format!(
                "A: the design's example system.toml was not accepted: {}",
                other.describe()
            )),
        }
    }

    // B. Unknown keys and tables are refused, naming the key and the file.
    let unknown: [(&str, &'static str, &'static str, &'static str); 9] = [
        (
            "a key outside any table",
            "",
            "bogus_top_level = 1",
            "bogus_top_level",
        ),
        (
            "an unknown key in [service]",
            "service",
            "bogus_service_key = 1",
            "bogus_service_key",
        ),
        (
            "an unknown key in [launcher]",
            "launcher",
            "bogus_launcher_key = 1",
            "bogus_launcher_key",
        ),
        (
            "an unknown key in [slots]",
            "slots",
            "bogus_slots_key = 1",
            "bogus_slots_key",
        ),
        (
            "an unknown key in [identity]",
            "identity",
            "bogus_identity_key = 1",
            "bogus_identity_key",
        ),
        (
            "an unknown key in [authority]",
            "authority",
            "bogus_authority_key = 1",
            "bogus_authority_key",
        ),
        (
            "an unknown key in [security]",
            "security",
            "bogus_security_key = 1",
            "bogus_security_key",
        ),
        (
            "a misspelt [security] key",
            "security",
            "max_commits_per_minut = 5",
            "max_commits_per_minut",
        ),
        ("an unknown table", "bogus_table", "x = 1", "bogus_table"),
    ];
    for (label, table, line, needle) in unknown {
        let w = World::new();
        w.write_system(&w.doc().extra(table, line));
        match w.refused(w.launch(Mode::System, None)) {
            Ok(log) => {
                p.check(log.contains(needle), || {
                    format!("B: {label}: the refusal doesn't name `{needle}`; log:\n{log}")
                });
                p.check(log.contains("system.toml"), || {
                    format!("B: {label}: the refusal doesn't name system.toml; log:\n{log}")
                });
            }
            Err(e) => p.add(format!("B: {label}: {e}")),
        }
        p.check(listing(&w.state).is_empty(), || {
            format!(
                "B: {label}: the service touched its state folder before refusing: {:?}",
                listing(&w.state)
            )
        });
    }

    // C. A file that isn't TOML is refused too, and named.
    {
        let w = World::new();
        w.write_system(&w.doc().raw("[service\naccount = \n"));
        match w.refused(w.launch(Mode::System, None)) {
            Ok(log) => p.check(log.contains("system.toml"), || {
                format!(
                    "C: the refusal of a file that isn't TOML doesn't name system.toml; log:\n{log}"
                )
            }),
            Err(e) => p.add(format!("C: a system.toml that isn't TOML: {e}")),
        }
    }

    p.finish("system_toml_parses_and_refuses_unknown_keys");
}

// ===========================================================================
// 2. The client socket: environment, then system.toml, then the default.
// ===========================================================================

/// Docs/system-mode.md, section 4: "Clients find the system socket by
/// themselves. The order is `AGENT_SIGN_SOCKET` if set, then the socket
/// `system.toml` names, then today's default."
///
/// Three stand-in services listen at the three places (the variable's, the
/// file's `[service] socket`, and `~/.agent-sign/daemon.sock`); the CLI
/// (`agent-sign leases`, which asks the service for its leases) is run three
/// times and the test records which listener it connected to:
/// 1. variable set, `system.toml` present: the variable's;
/// 2. variable unset, `system.toml` present: the file's;
/// 3. variable unset, no `system.toml`: the default (a laptop, unchanged).
///
/// Fails today at case 2: `protocol::client_socket_path` knows only the
/// variable and the default, so the CLI connects to the default.
#[test]
fn clients_use_the_system_socket_when_system_toml_exists() {
    let w = World::new();
    let env_sock = w.root.join("from-env.sock");
    let system_sock = w.root.join("from-system-toml.sock");
    let default_sock = w.state.join("daemon.sock");
    let fakes = [
        FakeService::start(&env_sock),
        FakeService::start(&system_sock),
        FakeService::start(&default_sock),
    ];
    w.write_system(&w.doc().socket(&system_sock));
    let mut p = Problems::default();

    // [the variable's, system.toml's, the default]
    let cases: [(&str, PathBuf, Option<&Path>, [bool; 3]); 3] = [
        (
            "AGENT_SIGN_SOCKET set and system.toml present",
            w.system_toml(),
            Some(env_sock.as_path()),
            [true, false, false],
        ),
        (
            "AGENT_SIGN_SOCKET unset and system.toml present",
            w.system_toml(),
            None,
            [false, true, false],
        ),
        (
            "AGENT_SIGN_SOCKET unset and no system.toml",
            w.no_system_toml(),
            None,
            [false, false, true],
        ),
    ];
    for (label, seam, env_socket, expect) in cases {
        let before: Vec<usize> = fakes.iter().map(FakeService::hits).collect();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_agent-sign"));
        cmd.arg("leases")
            .env_clear()
            .envs(w.env(&seam))
            .current_dir(&w.root)
            .stdin(Stdio::null());
        if let Some(socket) = env_socket {
            cmd.env("AGENT_SIGN_SOCKET", socket);
        }
        let out = run_within(cmd, "agent-sign leases");
        let hit: Vec<bool> = fakes
            .iter()
            .zip(&before)
            .map(|(f, b)| f.hits() > *b)
            .collect();
        p.check(hit == expect, || {
            format!(
                "{label}: the CLI connected to [variable's, system.toml's, default] = {hit:?}, \
                 expected {expect:?}; it said: {}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            )
        });
    }
    p.finish("clients_use_the_system_socket_when_system_toml_exists");
}

// ===========================================================================
// 3. The service runs as the configured account, and no other.
// ===========================================================================

/// Docs/system-mode.md, section 4: "In system mode the service refuses to
/// start as any account but `[service] account`. A copy of `agent-signd`
/// started by the agents account (sitting test P3) stops at once, before it
/// makes anything."
///
/// The file names another account that exists (`root`, or `nobody` when the
/// tests run as root) and then one that doesn't; either way the service,
/// run by this account, must stop with a failure status before it opens its
/// socket, saying "account" and the configured name, and leave its state
/// folder empty (no lock, no keys). With this account configured instead,
/// it must not be refused for that: it starts, or it stops for the next
/// missing piece (the issuer or the trust, named).
///
/// Fails today because the service never reads `[service] account`: it
/// starts under any account, opens its socket and writes its state folder.
#[test]
fn the_service_refuses_system_mode_as_another_account() {
    let me = current_account();
    let other = another_existing_account(&me);
    let mut p = Problems::default();

    for (label, configured) in [
        ("an account that exists", other.as_str()),
        (
            "an account that doesn't exist",
            "agent-sign-no-such-account",
        ),
    ] {
        let w = World::new();
        w.write_system(&w.doc().account(configured));
        match w.refused(w.launch(Mode::System, None)) {
            Ok(log) => {
                p.check(log.contains(configured), || {
                    format!(
                        "{label}: the refusal doesn't name the configured account \
                         `{configured}`; log:\n{log}"
                    )
                });
                p.check(log.to_lowercase().contains("account"), || {
                    format!("{label}: the refusal doesn't say it is about the account; log:\n{log}")
                });
            }
            Err(e) => p.add(format!(
                "{label}: system.toml names `{configured}` and the service runs as `{me}`: {e}"
            )),
        }
        p.check(listing(&w.state).is_empty(), || {
            format!(
                "{label}: the service made things in its state folder before refusing: {:?}",
                listing(&w.state)
            )
        });
    }

    // The configured account itself is not the reason to refuse.
    let w = World::new();
    w.write_system(&w.doc().account(&me));
    match w.launch(Mode::System, None) {
        Outcome::Running(_) => {}
        Outcome::Exited(_, log) => {
            let lower = log.to_lowercase();
            let next_piece = [
                "issuer",
                "openbao",
                "authority",
                "trust",
                "credential",
                "socket",
                "launcher",
            ];
            p.check(next_piece.iter().any(|word| lower.contains(word)), || {
                format!(
                    "configured account `{me}` (the one running): the service stopped, but its \
                     message names no missing piece (issuer, OpenBao, trust, ...); log:\n{log}"
                )
            });
        }
        Outcome::Hung(log) => p.add(format!(
            "configured account `{me}`: the service neither started nor stopped; log:\n{log}"
        )),
    }
    p.finish("the_service_refuses_system_mode_as_another_account");
}

// ===========================================================================
// 4. System mode never runs git in a caller's repository.
// ===========================================================================

/// What the plain caller's requests were, and the git runs that named the
/// caller's repository (its path anywhere in the run's working directory or
/// arguments, `-C <repo>` included), for a service in `mode`.
fn drive_plain_caller(mode: Mode) -> Result<(Vec<String>, Vec<String>), String> {
    let w = World::new();
    w.write_config_toml("");
    w.write_system(&w.doc());
    let repo = w.make_repo("callers-repo", "work");
    let repo_s = repo.to_string_lossy().into_owned();
    let (shim, log) = w.counting_git();
    let service = match w.launch(mode, Some(&shim)) {
        Outcome::Running(service) => service,
        other => return Err(format!("{mode:?}: {}", other.describe())),
    };
    let identity = plain_identity();
    let requests = vec![
        (
            "CheckPlainCommit",
            Request::CheckPlainCommit {
                repo: repo_s.clone(),
                branch: "feature/a".into(),
                identity: identity.clone(),
            },
        ),
        (
            "RequestLease",
            Request::RequestLease {
                repo: repo_s.clone(),
                branch: "work".into(),
                intent: "system-mode git probe".into(),
                duration_secs: None,
            },
        ),
        (
            "RequestLease (again, under the lease)",
            Request::RequestLease {
                repo: repo_s.clone(),
                branch: "work".into(),
                intent: "system-mode git probe".into(),
                duration_secs: None,
            },
        ),
        ("ListLeases", Request::ListLeases),
        (
            "IssueIdentifiedToken",
            Request::IssueIdentifiedToken {
                repo: repo_s.clone(),
                branch: "work".into(),
                identity: identity.clone(),
            },
        ),
        (
            "IssueRunToken",
            Request::IssueRunToken {
                repo: repo_s.clone(),
                branch: "work".into(),
                identity: identity.clone(),
            },
        ),
        (
            "SignCommit",
            Request::SignCommit {
                token: "not-a-token".into(),
                buffer_b64: "dHJlZSAw".into(),
                repo: Some(repo_s.clone()),
                branch: Some("work".into()),
            },
        ),
        (
            "CheckPlainCommit (again)",
            Request::CheckPlainCommit {
                repo: repo_s.clone(),
                branch: "feature/a".into(),
                identity,
            },
        ),
    ];
    let mut transcript = Vec::new();
    for (name, request) in requests {
        transcript.push(format!("{name}: {:?}", ask(&w.socket, &request)));
    }
    // Anything the service runs in the background gets a moment to show.
    std::thread::sleep(Duration::from_millis(300));
    drop(service);
    let runs = fs::read_to_string(&log).unwrap_or_default();
    let in_repo = runs
        .lines()
        .filter(|line| line.contains(&repo_s))
        .map(str::to_string)
        .collect();
    Ok((in_repo, transcript))
}

/// Docs/system-mode.md, section 2, "What the service itself no longer does
/// in system mode: run git in callers' repositories" (the PM's change (a)
/// and Q3). Running git there as `agent-sign` would let the repository's own
/// configuration act as the account that holds the signing login.
///
/// `AGENT_SIGN_REAL_GIT` points at a shim that logs the working directory
/// and arguments of every git run and then runs the real git, so the test
/// counts exactly the runs that name the caller's repository. A plain
/// caller then sends every request it can (a plain-path check, lease
/// requests, the list of leases, token requests, a signing request); the
/// count must be 0. A control runs the same requests against a
/// one-account service and needs at least one such run, so the 0 is not
/// the shim being blind.
///
/// Fails today in system mode because nothing reads `system.toml`: a lease
/// request runs `git rev-parse` in the caller's repository (`work_at` ->
/// `work::branch_tip`) to record the branch's tip as the lease's work, and
/// listing the leases runs the finished-work check for that lease the same
/// way. The signing half of the design's "a session sign" (guardrails) is
/// reachable only by a session, which needs step 2; see the module notes.
#[test]
fn system_mode_never_runs_git_in_a_callers_repository() {
    let mut p = Problems::default();

    match drive_plain_caller(Mode::OneAccount) {
        Ok((runs, transcript)) => p.check(!runs.is_empty(), || {
            format!(
                "control: even a one-account service made no git run naming the caller's \
                 repository, so the counting shim proves nothing; answers: {transcript:#?}"
            )
        }),
        Err(e) => p.add(format!("control (one-account mode): {e}")),
    }

    match drive_plain_caller(Mode::System) {
        Ok((runs, transcript)) => p.check(runs.is_empty(), || {
            format!(
                "the service in system mode ran git {} time(s) in the caller's repository:\n  {}\n\
                 the requests and their answers: {transcript:#?}",
                runs.len(),
                runs.join("\n  ")
            )
        }),
        Err(e) => p.add(format!("system mode: {e}")),
    }
    p.finish("system_mode_never_runs_git_in_a_callers_repository");
}

// ===========================================================================
// 5. CheckPlainCommit takes the branch the wrapper reports.
// ===========================================================================

enum Expect {
    Accepted,
    /// Refused, with this (lowercase) word in the message.
    Refused(&'static str),
}

/// Docs/system-mode.md, section 2: "`CheckPlainCommit` (the plain path's
/// policy question) takes the branch the wrapper reports and doesn't open
/// the repository. A plain commit gets no signature, so believing its branch
/// costs nothing. Without this change, every plain commit by the agents
/// account would be refused once the service can't read `/home`."
///
/// In system mode the service is asked about:
/// - a repository on `work` and on `main`, reporting `feature/reported`:
///   accepted whatever the repository's own branch is;
/// - a repository on `work`, reporting `main`: refused as protected (the
///   reported branch is the one judged);
/// - a repository the service cannot see at all (a path with nothing at it,
///   which is what `/home` is to the service): accepted for
///   `feature/reported`, and refused as protected for `main`, not for
///   being "an existing git working tree".
///
/// A control shows that a one-account (laptop) service still refuses a
/// repository that isn't one, as today.
///
/// Fails today at the two unseen-repository cases: `check_plain_commit`
/// refuses any path with no `.git` ("isn't an existing git working tree"),
/// so a hidden repository is refused for the wrong reason, and a hidden one
/// reporting a harmless branch is refused when it must be accepted.
#[test]
fn a_plain_commit_check_in_system_mode_takes_the_reported_branch() {
    let mut p = Problems::default();

    {
        let w = World::new();
        w.write_config_toml("");
        w.write_system(&w.doc());
        let on_work = w
            .make_repo("on-work", "work")
            .to_string_lossy()
            .into_owned();
        let on_main = w
            .make_repo("on-main", "main")
            .to_string_lossy()
            .into_owned();
        let hidden = w
            .root
            .join("not-visible-to-the-service")
            .join("repo")
            .to_string_lossy()
            .into_owned();
        let cases: [(&str, &str, &str, Expect); 5] = [
            (
                "a repository on `work`, reporting a feature branch",
                &on_work,
                "feature/reported",
                Expect::Accepted,
            ),
            (
                "a repository on `main`, reporting a feature branch",
                &on_main,
                "feature/reported",
                Expect::Accepted,
            ),
            (
                "a repository on `work`, reporting `main`",
                &on_work,
                "main",
                Expect::Refused("protected"),
            ),
            (
                "a repository the service can't see, reporting a feature branch",
                &hidden,
                "feature/reported",
                Expect::Accepted,
            ),
            (
                "a repository the service can't see, reporting `main`",
                &hidden,
                "main",
                Expect::Refused("protected"),
            ),
        ];
        match w.launch(Mode::System, None) {
            Outcome::Running(_service) => {
                for (label, repo, branch, expect) in cases {
                    let got = check_plain(&w.socket, repo, branch);
                    match (&expect, &got) {
                        (Expect::Accepted, Ok(())) => {}
                        (Expect::Refused(word), Err(m)) if m.to_lowercase().contains(word) => {}
                        _ => p.add(format!(
                            "{label}: got {got:?}, expected {}",
                            match expect {
                                Expect::Accepted => "it accepted".to_string(),
                                Expect::Refused(word) => format!("a refusal saying \"{word}\""),
                            }
                        )),
                    }
                }
            }
            other => p.add(format!("system mode: {}", other.describe())),
        }
    }

    // Control: on a laptop nothing changes.
    {
        let w = World::new();
        w.write_config_toml("");
        let hidden = w
            .root
            .join("not-visible-to-the-service")
            .join("repo")
            .to_string_lossy()
            .into_owned();
        match w.launch(Mode::OneAccount, None) {
            Outcome::Running(_service) => {
                let got = check_plain(&w.socket, &hidden, "feature/reported");
                p.check(
                    matches!(&got, Err(m) if m.contains("git working tree")),
                    || {
                        format!(
                            "control (one-account mode): a path that isn't a repository must still \
                             be refused as not a git working tree, got {got:?}"
                        )
                    },
                );
            }
            other => p.add(format!("control (one-account mode): {}", other.describe())),
        }
    }
    p.finish("a_plain_commit_check_in_system_mode_takes_the_reported_branch");
}

// ===========================================================================
// 6. System mode has no local authority.
// ===========================================================================

/// How many files the service's keys folder holds (0 if there is none): its
/// authority's public half is written there by the in-memory authority.
fn keys_files(w: &World) -> usize {
    fs::read_dir(agent_sign::agents_ca::keys_dir_in(&w.state))
        .map(|d| d.flatten().count())
        .unwrap_or(0)
}

/// Docs/system-mode.md, section 5: "In system mode [the OpenBao issuer] is
/// the only issuer: the in-memory authority is never used there, so a
/// failure never falls back to a local key." Build step 1: "the in-memory
/// issuer is never used in system mode."
///
/// With no issuer configured (no `[authority]` table, a table without
/// `issuer`, or an issuer that isn't `openbao`, such as `memory` or
/// `local`), the service must stop at start, with a failure status and
/// before it opens its socket or makes anything in its state folder, and its
/// message must say "issuer". With the `openbao` issuer configured it must
/// never make a local authority: no file in its keys folder, and no log line
/// saying it made one. A control shows a one-account (laptop) service still
/// makes its in-memory authority and writes the public half.
///
/// Fails today because the service makes the in-memory authority at every
/// start, whatever the settings: the four missing/wrong-issuer files are
/// accepted and the service starts, and with `openbao` configured it still
/// writes the authority's public key into its keys folder.
#[test]
fn system_mode_has_no_local_authority() {
    let mut p = Problems::default();

    let without_issuer: [(&str, Authority); 4] = [
        ("no [authority] table", Authority::Absent),
        (
            "an [authority] table with no issuer",
            Authority::Body("address = \"https://127.0.0.1:1\""),
        ),
        (
            "issuer = \"memory\"",
            Authority::Body("issuer = \"memory\""),
        ),
        ("issuer = \"local\"", Authority::Body("issuer = \"local\"")),
    ];
    for (label, authority) in without_issuer {
        let w = World::new();
        w.write_system(&w.doc().authority(authority));
        match w.refused(w.launch(Mode::System, None)) {
            Ok(log) => p.check(log.to_lowercase().contains("issuer"), || {
                format!("{label}: the refusal doesn't say \"issuer\"; log:\n{log}")
            }),
            Err(e) => p.add(format!("{label}: {e}")),
        }
        p.check(keys_files(&w) == 0, || {
            format!("{label}: the service made a local authority in its keys folder anyway")
        });
        p.check(listing(&w.state).is_empty(), || {
            format!(
                "{label}: the service made things in its state folder: {:?}",
                listing(&w.state)
            )
        });
    }

    // With OpenBao named as the issuer, no local authority either.
    {
        let w = World::new();
        w.write_system(&w.doc());
        let outcome = w.launch(Mode::System, None);
        let log = match &outcome {
            Outcome::Running(s) => s.log(),
            Outcome::Exited(_, log) | Outcome::Hung(log) => log.clone(),
        };
        p.check(keys_files(&w) == 0, || {
            format!(
                "issuer = \"openbao\": the service still wrote a local authority's public key \
                 into its keys folder: {:?}",
                listing(&w.state)
            )
        });
        p.check(
            !log.contains("made this start's agents' certificate authority"),
            || {
                format!(
                    "issuer = \"openbao\": the service says it made a local authority; log:\n{log}"
                )
            },
        );
    }

    // Control: a laptop keeps its in-memory authority.
    {
        let w = World::new();
        w.write_config_toml("");
        match w.launch(Mode::OneAccount, None) {
            Outcome::Running(_service) => p.check(keys_files(&w) > 0, || {
                "control (one-account mode): the service wrote no authority public key; a laptop \
                 must keep its in-memory authority as today"
                    .to_string()
            }),
            other => p.add(format!("control (one-account mode): {}", other.describe())),
        }
    }
    p.finish("system_mode_has_no_local_authority");
}
