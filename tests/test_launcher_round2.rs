//! System mode, round 2 of the whole-branch security review (the Sonnet
//! half), LAUNCH area: F6, F7's launcher half, and G-launch-1.
//!
//! Written before the fix, as its eval, by an agent other than the builder.
//! Each test's doc comment says which item it covers and why it is red now.
//! The work is done when every test here passes on hetzner with no assertion
//! changed. Tests named `*_control_*` already pass and must stay green; the
//! `g1_*` test is a test of a round-1 fix, so it passes today, and it was
//! shown able to fail (see its doc comment).
//!
//! - F6: `agent-sign launch` fetches returned bundles with git's fsck on
//!   (`transfer.fsckObjects`, `fetch.fsckObjects`): a malformed object is
//!   refused, not stored. The test runs the real client (`--collect`) against
//!   a stand-in launcher that returns a bundle holding a commit with no
//!   author line.
//! - F7 (launcher): a limit on launches per caller account, a `[launcher]`
//!   setting in system.toml. The builder names the setting; these tests find
//!   it as the one `pub` field `LauncherSection` gains, so they do not fix its
//!   name, only that it is a count of launches (a value of N lets one account
//!   launch N times in the window the setting counts, and refuses the
//!   N+1th at once). `sessions.log` stays whole (a control), and the docs say
//!   how fast it grows.
//! - G-launch-1: a `bundles_follow` launch with a bad or spent approval is
//!   refused from its head alone, before one bundle byte is read.
//!
//! Not testable here: that the launcher's in-memory record of launched
//! sessions is bounded. The launcher keeps no such set in memory (the set of
//! launched sessions the review meant is in the service, the SIGND area; the
//! launcher's own growing state is the used-nonce map, bounded by what the
//! per-caller limit lets in, and `sessions.log`, which is kept whole by
//! design); memory is not observable from outside the process. Nor the default
//! limit's value in production (only that it is positive and reasoned).
//!
//! The harness is a copy of `test_launcher_hardening.rs`'s (a test file can't
//! import another), with `World::new_with` to add lines to `[launcher]`.
//!
//! Run on hetzner, never on the Mac:
//! `cargo test --locked --test test_launcher_round2`.

#![cfg(target_os = "linux")]
#![allow(dead_code)]

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256, Sha512};
use tempfile::{TempDir, tempdir};

use agent_sign::crypto::openssh_ed25519_line;

const MACHINE: &str = "hetzner";
const DOMAIN: &str = "hetzner.agents.local";
const AGENT: &str = "claude-code";
const COUNT: u32 = 3;
const LAUNCH_NAMESPACE: &str = "agent-sign-launch-approval";

const PERSON_UID: u32 = 1000;
const AGENTS_UID: u32 = 1001;
const STRANGER_UID: u32 = 1234;
const LAUNCHER_UID: u32 = 61900;
fn slot_uid(n: u32) -> u32 {
    61000 + n
}
fn unit(n: u32) -> String {
    format!("agent-session@{n}.service")
}

const APPROVER_SEED: [u8; 32] = [21; 32];
const LONG: Duration = Duration::from_secs(15);
const MIB: usize = 1024 * 1024;

// ---------------------------------------------------------------------------
// Signing helpers (copies of test_launcher_daemon.rs's).
// ---------------------------------------------------------------------------

fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn plain_key_blob(k: &SigningKey) -> Vec<u8> {
    let mut blob = Vec::new();
    put_string(&mut blob, b"ssh-ed25519");
    put_string(&mut blob, k.verifying_key().as_bytes());
    blob
}

fn sshsig(k: &SigningKey, namespace: &str, data: &[u8]) -> String {
    let public_blob = plain_key_blob(k);
    let hash = Sha512::digest(data);
    let mut signed = b"SSHSIG".to_vec();
    put_string(&mut signed, namespace.as_bytes());
    put_string(&mut signed, b"");
    put_string(&mut signed, b"sha512");
    put_string(&mut signed, &hash);
    let sig = k.sign(&signed);
    let mut sig_blob = Vec::new();
    put_string(&mut sig_blob, b"ssh-ed25519");
    put_string(&mut sig_blob, &sig.to_bytes());
    let mut raw = b"SSHSIG".to_vec();
    raw.extend_from_slice(&1u32.to_be_bytes());
    put_string(&mut raw, &public_blob);
    put_string(&mut raw, namespace.as_bytes());
    put_string(&mut raw, b"");
    put_string(&mut raw, b"sha512");
    put_string(&mut raw, &sig_blob);
    let b64 = base64::engine::general_purpose::STANDARD.encode(&raw);
    let mut pem = String::from("-----BEGIN SSH SIGNATURE-----\n");
    for chunk in b64.as_bytes().chunks(70) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str("-----END SSH SIGNATURE-----\n");
    pem
}

fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn b64(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn fresh() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

fn wait_for(what: &str, limit: Duration, mut f: impl FnMut() -> bool) {
    let start = Instant::now();
    while !f() {
        assert!(start.elapsed() < limit, "timed out waiting for: {what}");
        thread::sleep(Duration::from_millis(40));
    }
}

// ---------------------------------------------------------------------------
// The world: temp roots, the stand-ins, the program.
// ---------------------------------------------------------------------------

struct World {
    _dir: TempDir,
    root: PathBuf,
    slots: PathBuf,
    state: PathBuf,
    io: PathBuf,
    sysd: PathBuf,
    facts: PathBuf,
    config: PathBuf,
    launch_sock: PathBuf,
    shim_dir: PathBuf,
    real_git: PathBuf,
    registrations: Arc<Mutex<Vec<Value>>>,
    extra_env: Vec<(String, String)>,
    child: Option<Child>,
    log: PathBuf,
}

impl Drop for World {
    fn drop(&mut self) {
        for d in [self.io.join("specs"), self.io.join("logs"), self.io.clone()] {
            let _ = fs::set_permissions(&d, fs::Permissions::from_mode(0o700));
        }
        if let Some(c) = self.child.as_mut() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

fn find_git() -> PathBuf {
    for dir in std::env::var("PATH").unwrap_or_default().split(':') {
        let p = Path::new(dir).join("git");
        if p.is_file() {
            return p;
        }
    }
    panic!("no git on PATH");
}

impl World {
    /// Everything made and `agent-launchd` running. `approvers` are the public
    /// keys that may sign a launch approval; `extra_env` is added to the
    /// launcher's environment (the two NEW seams).
    fn new(approvers: &[String], extra_env: &[(&str, &str)]) -> World {
        World::new_with(approvers, extra_env, "")
    }

    /// As `new`, with `launcher_extra` (whole `key = value` lines) added to the
    /// `[launcher]` table of the test's system.toml.
    fn new_with(approvers: &[String], extra_env: &[(&str, &str)], launcher_extra: &str) -> World {
        let dir = tempdir().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        let slots = root.join("slots");
        let state = root.join("launch-state");
        let sysd = root.join("systemd");
        let shim_dir = root.join("shim");
        for d in [&slots, &state, &sysd, &shim_dir] {
            fs::create_dir_all(d).unwrap();
        }
        for sub in ["active", "stuck"] {
            fs::create_dir_all(sysd.join(sub)).unwrap();
        }
        fs::write(sysd.join("calls.log"), "").unwrap();
        for n in 1..=COUNT {
            let d = slots.join(n.to_string());
            fs::create_dir_all(&d).unwrap();
            fs::set_permissions(&d, fs::Permissions::from_mode(0o750)).unwrap();
        }
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();

        // The sitting's part of I-A2: every slot's spec and log pre-made and
        // empty, the folders closed to 0550.
        let io = root.join("launch-io");
        for sub in ["specs", "logs"] {
            fs::create_dir_all(io.join(sub)).unwrap();
        }
        for n in 1..=COUNT {
            for name in [format!("specs/{n}.json"), format!("logs/{n}.out")] {
                let f = io.join(name);
                fs::write(&f, "").unwrap();
                fs::set_permissions(&f, fs::Permissions::from_mode(0o600)).unwrap();
            }
        }
        for d in [io.join("specs"), io.join("logs"), io.clone()] {
            fs::set_permissions(&d, fs::Permissions::from_mode(0o550)).unwrap();
        }

        let real_git = find_git();
        let shim = shim_dir.join("git");
        fs::write(
            &shim,
            format!("#!/bin/sh\nexec '{}' \"$@\"\n", real_git.display()),
        )
        .unwrap();
        fs::set_permissions(&shim, fs::Permissions::from_mode(0o755)).unwrap();

        let facts = root.join("kernel-facts.json");
        let config = root.join("system.toml");
        let launch_sock = root.join("launch.sock");
        let svc_sock = root.join("launcher-only.sock");
        let list = approvers
            .iter()
            .map(|a| format!("\"{a}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let toml = format!(
            "machine = \"{MACHINE}\"\n\n[service]\naccount = \"agent-sign\"\nsocket = \"{}\"\n\
             launcher_socket = \"{}\"\ntrust_file = \"{}\"\nclient_accounts = [\"agents\", \"taylor\"]\n\n\
             [launcher]\naccount = \"agent-launch\"\nsocket = \"{}\"\npeople_accounts = [\"taylor\"]\n\
             approvers = [{list}]\n{launcher_extra}\n[slots]\ncount = {COUNT}\naccount_prefix = \"agent-slot-\"\n\
             root = \"{}\"\nmax_duration = \"12h\"\n\n[identity]\npeople = [\"Taylor\"]\n\n\
             [authority]\nissuer = \"openbao\"\naddress = \"https://127.0.0.1:1\"\n\
             ca_cert = \"/etc/ssl/certs/ca-certificates.crt\"\nresolve = \"127.0.0.1\"\n\
             mount = \"ssh-agents-hetzner\"\nrole = \"agent-sign-hetzner\"\n",
            root.join("daemon.sock").display(),
            svc_sock.display(),
            root.join("allowed_signers").display(),
            launch_sock.display(),
            slots.display(),
        );
        fs::write(&config, &toml).unwrap();
        agent_sign::system_config::SystemConfig::parse(&toml, &config)
            .expect("the test's system.toml must parse");

        let mut accounts = json!({
            "taylor": PERSON_UID, "agents": AGENTS_UID, "agent-launch": LAUNCHER_UID,
        });
        for n in 1..=COUNT {
            accounts[format!("agent-slot-{n}")] = json!(slot_uid(n));
        }
        let mut w = World {
            _dir: dir,
            root: root.clone(),
            slots,
            state,
            io,
            sysd,
            facts,
            config,
            launch_sock,
            shim_dir,
            real_git,
            registrations: Arc::new(Mutex::new(Vec::new())),
            extra_env: extra_env
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            child: None,
            log: root.join("launchd.log"),
        };
        fs::write(
            &w.facts,
            json!({"accounts": accounts, "peer": peer(PERSON_UID)}).to_string(),
        )
        .unwrap();
        w.start_stand_in_service(&svc_sock);
        w.start_launchd();
        w
    }

    fn start_stand_in_service(&self, sock: &Path) {
        let listener = UnixListener::bind(sock).unwrap();
        let regs = self.registrations.clone();
        thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(conn) = conn else { return };
                let regs = regs.clone();
                thread::spawn(move || {
                    let mut reader = BufReader::new(conn.try_clone().unwrap());
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        return;
                    }
                    let v: Value = serde_json::from_str(line.trim()).unwrap_or(Value::Null);
                    let mut conn = conn;
                    if v["type"] != "RegisterSession" {
                        let _ = conn.write_all(
                            b"{\"type\":\"Error\",\"payload\":{\"message\":\"stand-in: only RegisterSession\"}}\n",
                        );
                        return;
                    }
                    regs.lock().unwrap().push(v["payload"].clone());
                    let session = fresh();
                    let answer = json!({"type": "SessionStarted", "payload": {
                        "principal": format!("{AGENT}.{}@{DOMAIN}", &session[..8]),
                        "session": session}});
                    let _ = conn.write_all(format!("{answer}\n").as_bytes());
                    let mut rest = String::new();
                    loop {
                        rest.clear();
                        match reader.read_line(&mut rest) {
                            Ok(0) | Err(_) => break,
                            Ok(_) => {}
                        }
                    }
                });
            }
        });
    }

    fn launchd_bin() -> PathBuf {
        let p = Path::new(env!("CARGO_BIN_EXE_agent-signd")).with_file_name("agent-launchd");
        assert!(p.exists(), "agent-launchd isn't built ({})", p.display());
        p
    }

    fn start_launchd(&mut self) {
        let bin = Self::launchd_bin();
        let log = fs::File::create(&self.log).unwrap();
        let path = format!(
            "{}:{}",
            self.shim_dir.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let mut cmd = Command::new(bin);
        cmd.env_clear()
            .env("PATH", path)
            .env("HOME", self.root.join("home"))
            .env("TMPDIR", &self.root)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("AGENT_SIGN_REAL_GIT", self.shim_dir.join("git"))
            .env("AGENT_SIGN_TEST_SYSTEM_CONFIG", &self.config)
            .env("AGENT_SIGN_TEST_KERNEL_FACTS", &self.facts)
            .env("AGENT_SIGN_TEST_LAUNCH_STATE", &self.state)
            .env("AGENT_SIGN_TEST_LAUNCH_IO", &self.io)
            .env("AGENT_SIGN_TEST_SYSTEMD", &self.sysd)
            .current_dir(&self.root)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log));
        for (k, v) in &self.extra_env {
            cmd.env(k, v);
        }
        self.child = Some(cmd.spawn().expect("couldn't start agent-launchd"));
        let start = Instant::now();
        while !self.launch_sock.exists() {
            if let Some(status) = self.child.as_mut().unwrap().try_wait().unwrap() {
                panic!(
                    "agent-launchd stopped at start ({status}); log:\n{}",
                    fs::read_to_string(&self.log).unwrap_or_default()
                );
            }
            assert!(
                start.elapsed() < LONG,
                "agent-launchd never made its launch socket"
            );
            thread::sleep(Duration::from_millis(40));
        }
    }

    fn spec_path(&self, n: u32) -> PathBuf {
        self.io.join("specs").join(format!("{n}.json"))
    }
    fn log_path(&self, n: u32) -> PathBuf {
        self.io.join("logs").join(format!("{n}.out"))
    }

    fn calls(&self) -> String {
        fs::read_to_string(self.sysd.join("calls.log")).unwrap_or_default()
    }
    fn started(&self, u: &str) -> usize {
        self.calls()
            .lines()
            .filter(|l| *l == format!("start {u}"))
            .count()
    }
    fn stopped(&self, u: &str) -> usize {
        self.calls()
            .lines()
            .filter(|l| *l == format!("stop {u}"))
            .count()
    }
    fn marker(&self, u: &str) -> PathBuf {
        self.sysd.join("active").join(u)
    }
    /// The unit's program exits (false) or is left running (true).
    fn set_active(&self, u: &str, on: bool) {
        if on {
            fs::write(self.marker(u), "").unwrap();
        } else {
            let _ = fs::remove_file(self.marker(u));
        }
    }

    fn current(&self, n: u32) -> PathBuf {
        self.slots.join(n.to_string()).join("current")
    }
    fn trash_entries(&self, n: u32) -> Vec<PathBuf> {
        match fs::read_dir(self.slots.join(n.to_string()).join("trash")) {
            Ok(rd) => rd.map(|e| e.unwrap().path()).collect(),
            Err(_) => Vec::new(),
        }
    }
    fn sessions_log(&self) -> String {
        fs::read_to_string(self.state.join("sessions.log")).unwrap_or_default()
    }
    fn registrations(&self) -> Vec<Value> {
        self.registrations.lock().unwrap().clone()
    }
    /// The used launch nonces, as the launcher keeps them.
    fn nonce_store(&self) -> String {
        fs::read_to_string(self.state.join("approvals").join("launch-nonces")).unwrap_or_default()
    }

    /// Points the stand-in kernel at `uid` and connects. The launcher reads the
    /// peer's facts at accept; callers that open several connections in a row
    /// must pause between them (see `settle`).
    fn connect_as(&self, uid: u32) -> Client {
        let mut facts: Value =
            serde_json::from_str(&fs::read_to_string(&self.facts).unwrap()).unwrap();
        facts["peer"] = peer(uid);
        let tmp = self.facts.with_extension("tmp");
        fs::write(&tmp, facts.to_string()).unwrap();
        fs::rename(&tmp, &self.facts).unwrap();
        let stream =
            UnixStream::connect(&self.launch_sock).expect("can't connect to the launch socket");
        Client {
            reader: BufReader::new(stream.try_clone().unwrap()),
            stream,
            raw: String::new(),
        }
    }

    fn launch(&self, uid: u32, req: &Req) -> (Client, Result<Launched, String>) {
        let mut c = self.connect_as(uid);
        c.send_req(req);
        let r = c.until("Launched", LONG).map(|v| Launched {
            slot: v["payload"]["slot"].as_u64().expect("Launched.slot") as u32,
            session: v["payload"]["session"].as_str().unwrap_or("").to_string(),
        });
        (c, r)
    }

    fn taylor_launch(&self, req: &Req) -> (Client, Launched) {
        let (c, r) = self.launch(PERSON_UID, req);
        (
            c,
            r.unwrap_or_else(|e| panic!("Taylor's launch was refused: {e}")),
        )
    }

    fn end_and_wait(&self, n: u32, c: &mut Client) -> Value {
        self.set_active(&unit(n), false);
        c.until("Ended", LONG)
            .unwrap_or_else(|e| panic!("the session in slot {n} never ended: {e}"))
    }

    fn git(&self, dir: &Path, args: &[&str]) -> String {
        let out = Command::new(&self.real_git)
            .args(args)
            .current_dir(dir)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_AUTHOR_NAME", "T")
            .env("GIT_AUTHOR_EMAIL", "t@example.com")
            .env("GIT_COMMITTER_NAME", "T")
            .env("GIT_COMMITTER_EMAIL", "t@example.com")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    /// A repository with one commit holding `size` incompressible bytes;
    /// returns (head sha, bundle bytes). The bundle is about `size` long.
    fn repo_bundle(&self, name: &str, size: usize) -> (String, Vec<u8>) {
        let dir = self.root.join(format!("caller-{name}-{}", fresh()));
        fs::create_dir_all(&dir).unwrap();
        self.git(&dir, &["init", "-q", "-b", "main"]);
        let mut data = Vec::with_capacity(size + 32);
        let mut h = Sha256::digest(name.as_bytes());
        while data.len() < size {
            data.extend_from_slice(&h);
            h = Sha256::digest(h);
        }
        data.truncate(size);
        fs::write(dir.join("big.bin"), &data).unwrap();
        self.git(&dir, &["add", "big.bin"]);
        self.git(
            &dir,
            &["-c", "commit.gpgsign=false", "commit", "-q", "-m", "c0"],
        );
        let head = self.git(&dir, &["rev-parse", "main"]);
        let file = dir.join("x.bundle");
        self.git(
            &dir,
            &["bundle", "create", "-q", file.to_str().unwrap(), "main"],
        );
        (head, fs::read(&file).unwrap())
    }
}

/// Gives the launcher the moment it needs to accept a connection and read the
/// stand-in kernel's facts before the test changes them for the next one.
fn settle() {
    thread::sleep(Duration::from_millis(200));
}

fn peer(uid: u32) -> Value {
    json!({"uid": uid, "cgroup": "0::/user.slice/user-1000.slice/session-1.scope", "process": "alive"})
}

struct Launched {
    slot: u32,
    session: String,
}

struct Client {
    stream: UnixStream,
    reader: BufReader<UnixStream>,
    raw: String,
}

impl Client {
    fn send_req(&mut self, req: &Req) {
        // A launcher that hangs up before it has read everything is fine
        // here: its refusal is what the caller reads next.
        let _ = self
            .stream
            .write_all(format!("{}\n", req.wire()).as_bytes());
    }

    fn next(&mut self, limit: Duration) -> Option<Value> {
        self.reader.get_ref().set_read_timeout(Some(limit)).ok()?;
        let mut line = String::new();
        match self.reader.read_line(&mut line) {
            Ok(0) | Err(_) => None,
            Ok(_) => {
                self.raw.push_str(&line);
                serde_json::from_str(line.trim()).ok()
            }
        }
    }

    /// Reads until a message of type `ty`. An `Error` message or silence is an `Err`.
    fn until(&mut self, ty: &str, limit: Duration) -> Result<Value, String> {
        let deadline = Instant::now() + limit;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(format!("no {ty} within {limit:?}"));
            }
            match self.next(left) {
                Some(v) if v["type"] == ty => return Ok(v),
                Some(v) if v["type"] == "Error" => {
                    let m = v["payload"]["message"].as_str().unwrap_or("").to_string();
                    return Err(if m.is_empty() {
                        "Error with no message".into()
                    } else {
                        m
                    });
                }
                Some(_) => {}
                None => return Err(format!("the launcher sent no {ty} (silence or closed)")),
            }
        }
    }
}

/// One launch request.
#[derive(Clone)]
struct Req {
    command: Vec<String>,
    repos: Vec<(String, String, Vec<u8>)>,
    approval: Option<(String, String)>,
    /// The environment the caller sends, as name/value pairs.
    env: Vec<(String, String)>,
    /// When set, this exact JSON text replaces the `env` object on the wire
    /// (to send a name twice, which a map can't hold).
    raw_env: Option<String>,
}

impl Req {
    fn sleep() -> Req {
        Req {
            command: vec!["sleep".into(), "3600".into()],
            repos: vec![],
            approval: None,
            env: vec![],
            raw_env: None,
        }
    }
    fn with_env(mut self, pairs: &[(&str, &str)]) -> Req {
        self.env = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        self
    }
    fn with_raw_env(mut self, raw: &str) -> Req {
        self.raw_env = Some(raw.to_string());
        self
    }
    /// THE ONE PLACE the request's layout on the socket is written (see the
    /// module documentation). With repositories, the launcher reads a head
    /// with no bundle bytes in it (`bundles_follow`), verifies it, and only
    /// then reads a second line holding the bundles (L2: bundle bytes follow
    /// the verification). With none, one JSON object. The caller adds the
    /// final newline.
    fn wire(&self) -> String {
        let env_value = if self.raw_env.is_some() {
            json!("@@RAW_ENV@@")
        } else {
            let mut m = Map::new();
            for (k, v) in &self.env {
                m.insert(k.clone(), json!(v));
            }
            Value::Object(m)
        };
        let follow = !self.repos.is_empty();
        let v = json!({"type": "Launch", "payload": {
            "agent": AGENT, "command": self.command, "env": env_value,
            "repos": self.repos.iter().map(|(n, b, _)|
                json!({"name": n, "base": b})).collect::<Vec<_>>(),
            "approval": self.approval.as_ref().map(|(t, s)| json!({"text": t, "signature": s})),
            "bundles_follow": follow,
        }});
        let mut s = v.to_string();
        if let Some(raw) = &self.raw_env {
            s = s.replacen("\"@@RAW_ENV@@\"", raw, 1);
        }
        if follow {
            let bundles: Vec<String> = self.repos.iter().map(|(_, _, bytes)| b64(bytes)).collect();
            s.push('\n');
            s.push_str(&json!({"bundles_b64": bundles}).to_string());
        }
        s
    }
}

/// A launch approval's text for `req`. It binds the agent, machine, program
/// and repositories; by design it says nothing about the environment (M1).
fn approval_text(req: &Req, nonce: &str, expires_at: u64) -> String {
    json!({
        "kind": "launch", "machine": MACHINE, "agent": AGENT,
        "repos": req.repos.iter().map(|(n, b, _)| json!({"name": n, "base": b})).collect::<Vec<_>>(),
        "program": sha256_hex(serde_json::to_string(&req.command).unwrap().as_bytes()),
        "expires_at": expires_at, "nonce": nonce,
    })
    .to_string()
}

fn approver() -> SigningKey {
    SigningKey::from_bytes(&APPROVER_SEED)
}

fn approver_line() -> String {
    openssh_ed25519_line(&approver().verifying_key())
        .trim()
        .to_string()
}

fn world_with_approver(extra_env: &[(&str, &str)]) -> World {
    World::new(&[approver_line()], extra_env)
}

/// `req` with a genuine approval (signed by the listed approver, good for ten
/// minutes). The approval does not cover the environment, so a relayer can
/// still add one afterwards with `.with_env(..)`.
fn good_approval(req: &Req, nonce: &str) -> Req {
    let text = approval_text(req, nonce, now_secs() + 600);
    let sig = sshsig(&approver(), LAUNCH_NAMESPACE, text.as_bytes());
    Req {
        approval: Some((text, sig)),
        ..req.clone()
    }
}

fn nonce() -> String {
    format!("nonce-{}", fresh())
}

fn read_spec(w: &World, n: u32) -> Result<Value, String> {
    let text = fs::read_to_string(w.spec_path(n)).map_err(|e| e.to_string())?;
    serde_json::from_str(&text).map_err(|e| format!("{e}: {text:?}"))
}

// ---------------------------------------------------------------------------
// F6: `agent-sign launch` fetches returned bundles with fsck on.
// ---------------------------------------------------------------------------

/// A caller's repository (one commit) and a bundle of it. With `malformed`,
/// the branch points at a commit object that git's own `fsck` refuses (no
/// `author` line: `missingAuthor` is an error, not a warning), made with
/// `hash-object --literally`, which git allows because it is how fsck's own
/// tests make such objects. Returns (bundle bytes, the branch tip's id).
fn session_bundle(w: &World, malformed: bool) -> (Vec<u8>, String) {
    let dir = w.root.join(format!("session-repo-{}", fresh()));
    fs::create_dir_all(&dir).unwrap();
    w.git(&dir, &["init", "-q", "-b", "main"]);
    fs::write(dir.join("f"), "hello").unwrap();
    w.git(&dir, &["add", "f"]);
    w.git(
        &dir,
        &["-c", "commit.gpgsign=false", "commit", "-q", "-m", "c0"],
    );
    if malformed {
        let tree = w.git(&dir, &["rev-parse", "HEAD^{tree}"]);
        let commit = format!("tree {tree}\ncommitter T <t@example.com> 1 +0000\n\nno author\n");
        let mut child = Command::new(&w.real_git)
            .args([
                "hash-object",
                "-t",
                "commit",
                "--literally",
                "-w",
                "--stdin",
            ])
            .current_dir(&dir)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(commit.as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success(), "hash-object --literally failed");
        let bad = String::from_utf8(out.stdout).unwrap().trim().to_string();
        w.git(&dir, &["update-ref", "refs/heads/main", &bad]);
    }
    let tip = w.git(&dir, &["rev-parse", "refs/heads/main"]);
    let file = dir.join("s.bundle");
    w.git(
        &dir,
        &["bundle", "create", "-q", file.to_str().unwrap(), "main"],
    );
    (fs::read(&file).unwrap(), tip)
}

/// What `agent-sign launch --collect SESSION` did, run for real in a fresh
/// caller repository against a stand-in launcher that answers `Ended` with
/// `bundle`. `repo_config` is written into the caller repository's own git
/// config first. Returns (exit success, stderr, the repository's session
/// branches as `ref objectid` lines, whether `tip` is in the repository).
fn collect_into_fresh_repo(
    w: &World,
    bundle: &[u8],
    tip: &str,
    repo_config: &[(&str, &str)],
) -> (bool, String, Vec<String>, bool) {
    let caller = w.root.join(format!("caller-repo-{}", fresh()));
    fs::create_dir_all(&caller).unwrap();
    w.git(&caller, &["init", "-q", "-b", "main"]);
    for (k, v) in repo_config {
        w.git(&caller, &["config", k, v]);
    }
    let sock = w.root.join(format!("standin-{}.sock", fresh()));
    let listener = UnixListener::bind(&sock).unwrap();
    let answer = json!({"type": "Ended", "payload": {"status": "ok",
        "bundles": [{"name": "r", "bundle_b64": b64(bundle)}]}});
    let standin = thread::spawn(move || {
        if let Ok((conn, _)) = listener.accept() {
            let mut line = String::new();
            let _ = BufReader::new(conn.try_clone().unwrap()).read_line(&mut line);
            let mut conn = conn;
            let _ = conn.write_all(format!("{answer}\n").as_bytes());
        }
    });
    let config = w.root.join(format!("collect-{}.toml", fresh()));
    fs::write(
        &config,
        format!(
            "machine = \"{MACHINE}\"\n\n[launcher]\nsocket = \"{}\"\n",
            sock.display()
        ),
    )
    .unwrap();
    let session = fresh();
    let out = Command::new(env!("CARGO_BIN_EXE_agent-sign"))
        .args(["launch", "--collect", &session])
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", w.root.join("home"))
        .env("TMPDIR", &w.root)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("AGENT_SIGN_TEST_SYSTEM_CONFIG", &config)
        .current_dir(&caller)
        .stdin(Stdio::null())
        .output()
        .expect("couldn't run agent-sign launch --collect");
    let _ = standin.join();
    let refs = Command::new(&w.real_git)
        .args([
            "for-each-ref",
            "--format=%(refname) %(objectname)",
            "refs/heads/session",
        ])
        .current_dir(&caller)
        .env_clear()
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap();
    let have_tip = Command::new(&w.real_git)
        .args(["cat-file", "-e", tip])
        .current_dir(&caller)
        .env_clear()
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .status()
        .unwrap()
        .success();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stderr).to_string(),
        String::from_utf8_lossy(&refs.stdout)
            .lines()
            .map(String::from)
            .collect(),
        have_tip,
    )
}

/// F6 CONTROL. A sound bundle is fetched: the command succeeds and the
/// session's branch is under `session/collected-<id>/`. Green today; it shows
/// the stand-in launcher and the caller repository work, so the red test
/// below fails for fsck and nothing else.
#[test]
fn f6_control_a_sound_returned_bundle_is_fetched() {
    let w = World::new(&[], &[]);
    let (bundle, tip) = session_bundle(&w, false);
    let (ok, err, refs, have_tip) = collect_into_fresh_repo(&w, &bundle, &tip, &[]);
    assert!(ok, "the command failed on a sound bundle: {err}");
    assert!(
        have_tip,
        "the sound bundle's commit isn't in the repository"
    );
    assert_eq!(refs.len(), 1, "want one session branch, got {refs:?}");
    assert!(
        refs[0].contains("/collected-") && refs[0].ends_with(&tip),
        "{refs:?}"
    );
}

/// F6. A returned bundle holding a malformed object (the session's account
/// wrote it; the caller must not trust it) is refused by the fetch, because
/// the command runs `git fetch` with `transfer.fsckObjects` and
/// `fetch.fsckObjects` on: the command fails, no session branch is made, and
/// the malformed commit is not stored in the caller's repository. Both for a
/// repository with no such setting and for one whose own config turns fsck
/// off (the command line's `-c` outranks the repository's config, so the
/// rule is the command's, not the caller's settings). Red today: `git fetch`
/// runs with git's default (no fsck), the object is stored and the branch
/// made.
#[test]
fn f6_a_malformed_object_in_a_returned_bundle_is_refused() {
    let w = World::new(&[], &[]);
    let (bundle, tip) = session_bundle(&w, true);
    let mut bad = Vec::new();
    let off = [
        ("transfer.fsckObjects", "false"),
        ("fetch.fsckObjects", "false"),
    ];
    let cases: [(&str, &[(&str, &str)]); 2] = [
        ("default git config", &[]),
        ("the repository turns fsck off", &off),
    ];
    for (what, cfg) in cases {
        let (ok, err, refs, have_tip) = collect_into_fresh_repo(&w, &bundle, &tip, cfg);
        if ok {
            bad.push(format!(
                "{what}: the command succeeded on a malformed bundle"
            ));
        }
        if !refs.is_empty() {
            bad.push(format!("{what}: a session branch was made: {refs:?}"));
        }
        if have_tip {
            bad.push(format!(
                "{what}: the malformed commit is stored in the repository"
            ));
        }
        if !ok && !err.contains("fetched") {
            bad.push(format!(
                "{what}: refused, but not in the command's own words: {err}"
            ));
        }
    }
    assert!(bad.is_empty(), "F6:\n  {}", bad.join("\n  "));
}

// ---------------------------------------------------------------------------
// F7 (launcher half): a limit on launches per caller.
// ---------------------------------------------------------------------------

/// The `[launcher]` settings that existed before this round
/// (`src/system_config.rs`); any other `pub` field of `LauncherSection` is the
/// rate limit this round adds. The builder names it; the tests find it.
const OLD_LAUNCHER_KEYS: [&str; 4] = ["account", "socket", "people_accounts", "approvers"];

fn system_config_source() -> String {
    fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/system_config.rs"))
        .expect("src/system_config.rs")
}

/// The new `[launcher]` setting: (name, its doc comment). Err if
/// `LauncherSection` has none.
fn launcher_rate_setting() -> Result<(String, String), String> {
    let text = system_config_source();
    let at = text
        .find("pub struct LauncherSection {")
        .ok_or("no LauncherSection in system_config.rs")?;
    let body = &text[at..];
    let body = &body[..body.find("\n}\n").ok_or("LauncherSection never ends")?];
    let mut doc = String::new();
    let mut found = Vec::new();
    for l in body.lines().skip(1) {
        let t = l.trim();
        if let Some(d) = t.strip_prefix("///") {
            doc.push_str(d.trim());
            doc.push(' ');
        } else if let Some(f) = t.strip_prefix("pub ") {
            let name = f.split(':').next().unwrap_or("").trim().to_string();
            if !OLD_LAUNCHER_KEYS.contains(&name.as_str()) {
                found.push((name, doc.clone()));
            }
            doc.clear();
        } else if !t.starts_with("#[") {
            doc.clear();
        }
    }
    found.into_iter().next().ok_or_else(|| {
        "F7: [launcher] (LauncherSection) has no setting for a limit on launches per caller; it \
         still has only account, socket, people_accounts and approvers"
            .to_string()
    })
}

/// F7. The limit is a `[launcher]` setting with a default that is justified:
/// (1) `LauncherSection` has the setting; (2) it parses from system.toml, and
/// without it the default is a positive number (read from the section's
/// `Debug` text, `name: N`); (3) a doc comment (on the field, its default, or
/// a constant) names launches per caller and derives the default from the
/// slots and the session length, not a guess; (4) docs/system-mode.md
/// documents the setting by name. Red today: there is no such setting.
#[test]
fn f7_the_launch_limit_is_a_launcher_setting_with_a_reasoned_default() {
    let (key, field_doc) = launcher_rate_setting().unwrap_or_else(|e| panic!("{e}"));
    let dir = tempdir().unwrap();
    let path = dir.path().join("system.toml");
    let base = "machine = \"hetzner\"\n[service]\naccount = \"agent-sign\"\nsocket = \"/tmp/r2/daemon.sock\"\nlauncher_socket = \"/tmp/r2/launcher.sock\"\ntrust_file = \"/tmp/r2/allowed_signers\"\nclient_accounts = [\"agents\"]\n[slots]\ncount = 3\naccount_prefix = \"agent-slot-\"\nroot = \"/tmp/r2/slots\"\nmax_duration = \"12h\"\n[authority]\nissuer = \"openbao\"\naddress = \"https://127.0.0.1:1\"\nca_cert = \"/etc/ssl/certs/ca-certificates.crt\"\nresolve = \"127.0.0.1\"\nmount = \"m\"\nrole = \"r\"\n[identity]\npeople = [\"Taylor\"]\n";
    let cfg = agent_sign::system_config::SystemConfig::parse(base, &path)
        .unwrap_or_else(|e| panic!("the baseline test config doesn't parse: {e}"));
    let shown = format!("{:?}", cfg.launcher);
    let needle = format!("{key}: ");
    let default: u64 = shown
        .split(&needle)
        .nth(1)
        .map(|r| {
            r.chars()
                .take_while(char::is_ascii_digit)
                .collect::<String>()
        })
        .and_then(|d| d.parse().ok())
        .unwrap_or_else(|| panic!("F7: the default of `{key}` isn't a plain number in {shown}"));
    assert!(default > 0, "F7: the default of `{key}` is 0");
    // The setting parses when written.
    let with = format!("{base}\n[launcher]\n{key} = 7\n");
    agent_sign::system_config::SystemConfig::parse(&with, &path)
        .unwrap_or_else(|e| panic!("F7: `[launcher] {key} = 7` doesn't parse: {e}"));
    // A doc block (any in system_config.rs) that justifies the default.
    let mut blocks = vec![field_doc];
    let mut cur = String::new();
    for l in system_config_source().lines() {
        if let Some(d) = l.trim().strip_prefix("///") {
            cur.push_str(d.trim());
            cur.push(' ');
        } else if !cur.is_empty() {
            blocks.push(std::mem::take(&mut cur));
        }
    }
    let ok = blocks.iter().any(|b| {
        let b = b.to_lowercase();
        (b.contains(&key) || b.contains("launches"))
            && b.contains("slot")
            && (b.contains("max_duration") || b.contains("session length") || b.contains("longest"))
    });
    assert!(
        ok,
        "F7: no doc comment in system_config.rs ties `{key}`'s default to the slots and the \
         session length"
    );
    let docs =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/system-mode.md"))
            .unwrap();
    assert!(
        docs.contains(&key),
        "F7: docs/system-mode.md doesn't document the setting `{key}`"
    );
}

/// Counts the `start` calls to any session unit (not its end unit; systemd's
/// stand-in log).
fn all_starts(w: &World) -> usize {
    w.calls()
        .lines()
        .filter(|l| l.starts_with("start agent-session@"))
        .count()
}

/// F7. With the limit set to 2: an account that isn't a person's, holding
/// genuine approvals, launches twice; the third launch is refused at once in
/// plain words about launching too often (not about a nonce or a free slot),
/// starts no unit, and does NOT use up the third approval's nonce (a refused
/// approval is not spent: it is still good for another caller). The limit is
/// per caller: another account with an approval, and a person's account,
/// still launch. Red today: with no such setting there is no limit and the
/// third launch starts (this test needs the setting, found as in
/// `launcher_rate_setting`, so until it exists the test stops there).
#[test]
fn f7_launches_are_limited_per_caller_and_a_refusal_spends_nothing() {
    let (key, _) = launcher_rate_setting().unwrap_or_else(|e| panic!("{e}"));
    let w = World::new_with(&[approver_line()], &[], &format!("{key} = 2\n"));
    for i in 0..2 {
        let (mut c, r) = w.launch(AGENTS_UID, &good_approval(&Req::sleep(), &nonce()));
        let l = r.unwrap_or_else(|e| panic!("launch {} of 2 was refused: {e}", i + 1));
        w.end_and_wait(l.slot, &mut c);
    }
    let starts = all_starts(&w);
    let third_nonce = nonce();
    let (_c, r) = w.launch(AGENTS_UID, &good_approval(&Req::sleep(), &third_nonce));
    match r {
        Ok(l) => panic!(
            "F7: a third launch by the same account within the limit of 2 started (slot {})",
            l.slot
        ),
        Err(e) => {
            let m = e.to_lowercase();
            assert!(
                m.contains("launch")
                    && ["too many", "too often", "limit", "rate", "wait", "slow"]
                        .iter()
                        .any(|w| m.contains(w)),
                "F7: the refusal doesn't say that launching is limited: {e}"
            );
            assert!(
                !m.contains("already used") && !m.contains("no slot") && !m.contains("reading"),
                "F7: the third launch was refused for another reason: {e}"
            );
        }
    }
    assert_eq!(
        all_starts(&w),
        starts,
        "a refused launch still started a unit"
    );
    assert!(
        !w.nonce_store().contains(&third_nonce),
        "F7: a launch refused for the limit used up its approval's nonce"
    );
    // Per caller: neither another account nor a person is held back by it.
    let (mut c, r) = w.launch(STRANGER_UID, &good_approval(&Req::sleep(), &nonce()));
    let l = r.unwrap_or_else(|e| {
        panic!("F7: another account was held back by the first account's limit: {e}")
    });
    w.end_and_wait(l.slot, &mut c);
    let (mut c, l) = w.taylor_launch(&Req::sleep());
    w.end_and_wait(l.slot, &mut c);
    // The refused approval is not spent: another caller can still use it.
    let again = good_approval(&Req::sleep(), &third_nonce);
    let (mut c, r) = w.launch(STRANGER_UID, &again);
    let l = r.unwrap_or_else(|e| panic!("the refused approval could not be used afterwards: {e}"));
    w.end_and_wait(l.slot, &mut c);
}

/// F7 CONTROL. `sessions.log` is an audit log and is not trimmed to make room:
/// after five launches and endings by a person, every session's id is in it.
/// Green today and must stay green (a fix that bounds memory by trimming the
/// log would turn it red).
#[test]
fn f7_control_sessions_log_keeps_every_session() {
    let w = World::new(&[], &[]);
    let mut ids = Vec::new();
    for _ in 0..5 {
        let (mut c, l) = w.taylor_launch(&Req::sleep());
        ids.push(l.session.clone());
        w.end_and_wait(l.slot, &mut c);
    }
    wait_for("the fifth session in sessions.log", LONG, || {
        w.sessions_log().contains(&ids[4])
    });
    let log = w.sessions_log();
    for id in &ids {
        assert!(
            log.contains(id),
            "sessions.log lost the session {id}:\n{log}"
        );
    }
}

/// F7. docs/system-mode.md says how big `sessions.log` grows per launch (the
/// log is kept whole, so its growth must be stated): a paragraph that names
/// `sessions.log`, a size in bytes (or KiB) and "per" or "each" launch or
/// session. Red today: the document never gives a size.
#[test]
fn f7_the_docs_say_how_big_sessions_log_grows_per_launch() {
    let docs =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/system-mode.md"))
            .unwrap();
    let ok = docs.split("\n\n").any(|p| {
        let p = p.to_lowercase();
        p.contains("sessions.log")
            && (p.contains("byte") || p.contains("kib"))
            && [
                "per launch",
                "each launch",
                "every launch",
                "per session",
                "each session",
            ]
            .iter()
            .any(|s| p.contains(s))
    });
    assert!(
        ok,
        "F7: docs/system-mode.md has no paragraph giving sessions.log's growth per launch in bytes"
    );
}

// ---------------------------------------------------------------------------
// G-launch-1: no bundle byte is read before the head is verified.
// ---------------------------------------------------------------------------

/// The head line of `req` as sent for a `bundles_follow` launch: the first
/// line of [`Req::wire`], newline included. The bundles line is left unsent.
fn head_line(req: &Req) -> Vec<u8> {
    let wire = req.wire();
    let head = wire.split('\n').next().unwrap();
    assert!(
        head.contains("\"bundles_follow\":true"),
        "the helper's request isn't a bundles_follow one"
    );
    format!("{head}\n").into_bytes()
}

/// Sends `head`, waits (5 s) for the launcher's answer WITHOUT sending a
/// single bundle byte, then floods bundle-line bytes until the launcher stops
/// taking them. Returns (the answer or why none, bytes the flood got in).
fn head_then_flood(w: &World, uid: u32, head: &[u8]) -> (Result<Value, String>, usize) {
    let mut c = w.connect_as(uid);
    settle();
    c.stream.write_all(head).unwrap();
    let answer = c.until("Launched", Duration::from_secs(5));
    let mut s = c.stream.try_clone().unwrap();
    s.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut sent = 0usize;
    let chunk = vec![b'A'; 64 * 1024];
    let prefix = br#"{"bundles_b64":[""#;
    if s.write_all(prefix).is_ok() {
        while sent < 16 * MIB {
            match s.write(&chunk) {
                Ok(0) | Err(_) => break,
                Ok(k) => sent += k,
            }
        }
    }
    (answer, sent)
}

/// Sends `head` and, with no pause, 16 MiB of bundle-line bytes after it;
/// returns how many bytes the launcher took before it hung up on us.
fn head_and_flood_together(w: &World, uid: u32, head: &[u8]) -> usize {
    let mut c = w.connect_as(uid);
    settle();
    c.stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    if c.stream.write_all(head).is_err() {
        return 0;
    }
    let chunk = vec![b'A'; 64 * 1024];
    let mut sent = 0usize;
    while sent < 16 * MIB {
        match c.stream.write(&chunk) {
            Ok(0) | Err(_) => break,
            Ok(k) => sent += k,
        }
    }
    sent
}

/// G-launch-1. A `bundles_follow` launch whose approval is bad or already
/// spent is refused ON THE HEAD ALONE: the launcher answers without one bundle
/// byte having been sent (within 5 s, where a launcher that read the bundles
/// first would wait for them), and a flood that follows is not taken (under
/// 4 MiB: the connection is already closed). Four heads from an account that
/// isn't a person's: an approval signed by a key that isn't an approver; a
/// genuine approval for other repositories than the request names; a genuine
/// approval whose nonce a launch already used; and no approval at all. The
/// flood is also sent with no pause after the head (the other order) and is
/// not taken either. Finally a genuine approval's request still gets in with
/// its bundles (the control that the verified path reads them). Green today
/// (round-1 fix); the test can fail: with the launcher changed to read the
/// bundles line before it refuses, the answer never comes.
#[test]
fn g1_a_bad_or_spent_approval_is_refused_on_the_head_before_any_bundle_byte() {
    let w = world_with_approver(&[]);
    let (base, bundle) = w.repo_bundle("r", 50 * 1024);
    let mut plain = Req::sleep();
    plain.repos = vec![("r".into(), base.clone(), bundle.clone())];

    // A spent approval: a genuine launch uses it up first.
    let spent_nonce = nonce();
    let spent = good_approval(&plain, &spent_nonce);
    let (mut c, r) = w.launch(AGENTS_UID, &spent);
    let l = r.unwrap_or_else(|e| panic!("the genuine launch was refused: {e}"));
    w.end_and_wait(l.slot, &mut c);
    wait_for("the nonce to be recorded", LONG, || {
        w.nonce_store().contains(&spent_nonce)
    });

    // A genuine approval, but for a request with no repositories.
    let mut other_repos = plain.clone();
    other_repos.approval = good_approval(&Req::sleep(), &nonce()).approval;

    // Signed by a key that isn't an approver.
    let text = approval_text(&plain, &nonce(), now_secs() + 600);
    let stranger_key = SigningKey::from_bytes(&[99; 32]);
    let mut wrong_key = plain.clone();
    wrong_key.approval = Some((
        text.clone(),
        sshsig(&stranger_key, LAUNCH_NAMESPACE, text.as_bytes()),
    ));

    let mut none = plain.clone();
    none.approval = None;

    let cases: [(&str, Req, Option<&str>); 4] = [
        ("an approval signed by a non-approver", wrong_key, None),
        ("an approval for other repositories", other_repos, None),
        ("an already spent approval", spent, Some("used")),
        ("no approval", none, None),
    ];
    let mut bad = Vec::new();
    for (what, req, want) in &cases {
        let head = head_line(req);
        let (answer, flooded) = head_then_flood(&w, AGENTS_UID, &head);
        match answer {
            Ok(_) => bad.push(format!("{what}: the launch was ACCEPTED")),
            Err(e) if e.contains("the launcher sent no") || e.contains("no Launched within") => bad
                .push(format!(
                    "{what}: no refusal came within 5 s of the head, with no bundle byte sent: {e}"
                )),
            Err(e) => {
                if let Some(word) = want
                    && !e.to_lowercase().contains(word)
                {
                    bad.push(format!("{what}: refused, but not as '{word}': {e}"));
                }
            }
        }
        if flooded >= 4 * MIB {
            bad.push(format!(
                "{what}: the launcher took {} MiB of bundle bytes after refusing",
                flooded / MIB
            ));
        }
        let together = head_and_flood_together(&w, AGENTS_UID, &head);
        if together >= 4 * MIB {
            bad.push(format!(
                "{what}: head and flood together: the launcher took {} MiB",
                together / MIB
            ));
        }
    }
    assert!(bad.is_empty(), "G-launch-1:\n  {}", bad.join("\n  "));
    // Nothing started, nothing spent but the one genuine launch's nonce.
    assert_eq!(
        all_starts(&w),
        1,
        "a refused request started a session: {}",
        w.calls()
    );
    assert_eq!(
        w.nonce_store()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .count(),
        1,
        "a refused request used a nonce: {}",
        w.nonce_store()
    );
    // Control: a genuine approval with its bundles still launches.
    let (base, bundle) = w.repo_bundle("s", 50 * 1024);
    let mut real = Req::sleep();
    real.repos = vec![("s".into(), base, bundle.clone())];
    let (mut c, r) = w.launch(AGENTS_UID, &good_approval(&real, &nonce()));
    let l = r.unwrap_or_else(|e| panic!("a genuine approved launch with bundles was refused: {e}"));
    let ins: Vec<Vec<u8>> = fs::read_dir(w.current(l.slot).join("in"))
        .expect("no current/in/")
        .map(|e| fs::read(e.unwrap().path()).unwrap())
        .collect();
    assert_eq!(ins, vec![bundle], "the verified path changed the bundle");
    w.end_and_wait(l.slot, &mut c);
}
