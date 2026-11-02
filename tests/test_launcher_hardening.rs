//! System mode, round 2 of the whole-branch security review: the LAUNCH
//! area's findings M1, L1, L2 (code), L3 and L4's launcher half
//! (`agent-launchd`, the launch socket, a launch approval's reach).
//!
//! Written before the fix, as its eval, by an agent other than the builder.
//! Each test says in its doc comment which finding it fixes and why it is red
//! on f61ed17. The work is done when every test here passes on hetzner with no
//! assertion changed. Tests that already pass today are CONTROLS: they show
//! the oracle works and must stay green (they are the "don't break the
//! working case" half). Interfaces are the orchestrator's (I-M1, I-L2/L1/L3/L4).
//!
//! **The wire format lives in one place.** [`Req::wire`] is the only code here
//! that knows how a request is laid out on the socket (today: one JSON line).
//! If L2 changes the protocol (for instance a header line that is verified
//! before bundle bytes follow), the builder may change `Req::wire`,
//! `Client::send_req` and the flood helper's prefix, and nothing else; no
//! assertion may change. The tests that need the format to stay as it is are
//! the ones named `*_control`.
//!
//! **Two NEW debug-test-build seams** (`#[cfg(feature = "test-authenticator")]`
//! only, like `AGENT_SIGN_TEST_LAUNCH_IO`; the static tests at the end check
//! they are gated and documented in docs/system-mode.md), because the real
//! values are minutes long and a test can't wait that:
//!
//! - `AGENT_SIGN_TEST_REQUEST_DEADLINE_MS=<n>`: replaces the total deadline for
//!   reading one whole request (L1), whatever the request's size.
//! - `AGENT_SIGN_TEST_SEND_TIMEOUT_MS=<n>`: replaces the write timeout on every
//!   send to a caller (L3).
//!
//! The harness (signing helpers, `World`, `Client`) is a trimmed copy of
//! `test_launcher_daemon.rs`'s: a test file can't import another.
//!
//! Not testable here, only on a real machine: that the real deadline and write
//! timeout have sensible production values (the seams replace them); that
//! the kernel's socket buffers are the size this file assumes (the flood
//! tests use a generous 4 MiB margin); anything about root-owned units.
//!
//! Run on hetzner, never on the Mac:
//! `cargo test --locked --test test_launcher_hardening`.

#![cfg(target_os = "linux")]
#![allow(dead_code)]

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
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
             approvers = [{list}]\n\n[slots]\ncount = {COUNT}\naccount_prefix = \"agent-slot-\"\n\
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
// M1: a launch approval doesn't cover the environment.
// ---------------------------------------------------------------------------

/// The reviewer's probe: five variables an approval never named, each a way to
/// run code (a different API host, git's config injected through the
/// environment, a preloaded library) inside an attested session.
const PROBE: [(&str, &str); 5] = [
    ("ANTHROPIC_BASE_URL", "https://attacker.example"),
    ("GIT_CONFIG_COUNT", "1"),
    ("GIT_CONFIG_KEY_0", "core.fsmonitor"),
    ("GIT_CONFIG_VALUE_0", "touch-pwned"),
    ("LD_PRELOAD", "evil.so"),
];

/// Names that are not LANG or TERM: all refused (I-M1: "any other name"),
/// whatever they are. Includes the probe, other loaders and interpreters'
/// hooks, a near-miss spelling of each allowed name, and the identity claims
/// the launcher used to strip silently (they are now refused, not stripped).
const OTHER_NAMES: [&str; 17] = [
    "ANTHROPIC_BASE_URL",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_KEY_0",
    "GIT_CONFIG_VALUE_0",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "PATH",
    "HOME",
    "GIT_SSH_COMMAND",
    "BASH_ENV",
    "NODE_OPTIONS",
    "LC_ALL",
    "lang",
    "TERM2",
    "AGENT_SIGN_SOCKET",
    "AGENT_SIGN_AGENT",
    "CLAUDE_CODE_SESSION_ID",
];

/// Launches as `uid`; if it is wrongly accepted, says so (with the spec's
/// environment) and ends that session so the slot is free for the next try.
/// `Ok` means refused, with a message that names `name`.
fn expect_refused(w: &World, uid: u32, req: &Req, name: &str) -> Result<(), String> {
    let (mut c, r) = w.launch(uid, req);
    match r {
        Err(e) if e.contains(name) => Ok(()),
        Err(e) => Err(format!(
            "{name}: refused, but the message doesn't name the variable: {e}"
        )),
        Ok(l) => {
            let env = read_spec(w, l.slot)
                .map(|s| s["env"].clone())
                .unwrap_or(Value::Null);
            w.set_active(&unit(l.slot), false);
            let _ = c.until("Ended", LONG);
            Err(format!(
                "{name}: the launch was ACCEPTED (slot {}); the session's spec env is {env}",
                l.slot
            ))
        }
    }
}

/// Nothing happened for the refused requests: no unit call, no registration,
/// no `current/`, no spec bytes written.
fn nothing_started(w: &World) -> Vec<String> {
    let mut bad = Vec::new();
    if !w.calls().trim().is_empty() {
        bad.push(format!("systemd was called: {}", w.calls().trim()));
    }
    if !w.registrations().is_empty() {
        bad.push(format!(
            "{} session(s) were registered with the service",
            w.registrations().len()
        ));
    }
    for n in 1..=COUNT {
        if w.current(n).exists() {
            bad.push(format!("slot {n}'s current/ was made"));
        }
        let spec = fs::read(w.spec_path(n)).unwrap_or_default();
        if !spec.is_empty() {
            bad.push(format!(
                "slot {n}'s spec was written: {}",
                String::from_utf8_lossy(&spec)
            ));
        }
    }
    bad
}

/// Launches as `uid`, reads the session's spec env, ends the session. The
/// spec's `env` is the answer.
fn launch_and_spec_env(w: &World, uid: u32, req: &Req) -> Result<Value, String> {
    let (mut c, r) = w.launch(uid, req);
    let l = r?;
    let env = read_spec(w, l.slot)?["env"].clone();
    w.end_and_wait(l.slot, &mut c);
    Ok(env)
}

/// M1, person's account. Every variable but LANG and TERM is refused by name:
/// nothing is started and no spec is written (the spec files stay empty). Red
/// today: the launcher keeps every variable that isn't an identity claim and
/// writes it into the spec (all five probe variables reached it).
#[test]
fn m1_a_persons_launch_with_any_other_variable_is_refused_by_name() {
    let w = World::new(&[], &[]);
    let mut bad = Vec::new();
    for name in OTHER_NAMES {
        if let Err(e) = expect_refused(&w, PERSON_UID, &Req::sleep().with_env(&[(name, "x")]), name)
        {
            bad.push(e);
        }
    }
    // The reviewer's probe, all five at once.
    let (mut c, r) = w.launch(PERSON_UID, &Req::sleep().with_env(&PROBE));
    match r {
        Err(e) if PROBE.iter().any(|(k, _)| e.contains(k)) => {}
        Err(e) => bad.push(format!(
            "the probe was refused without naming a variable: {e}"
        )),
        Ok(l) => {
            bad.push(format!(
                "the probe (5 unapproved variables) was ACCEPTED: spec env {}",
                read_spec(&w, l.slot)
                    .map(|s| s["env"].clone())
                    .unwrap_or(Value::Null)
            ));
            w.set_active(&unit(l.slot), false);
            let _ = c.until("Ended", LONG);
        }
    }
    assert!(bad.is_empty(), "M1 (person):\n  {}", bad.join("\n  "));
    let started = nothing_started(&w);
    assert!(
        started.is_empty(),
        "M1 (person): refused requests still did things:\n  {}",
        started.join("\n  ")
    );
}

/// M1, the approval path (the reviewer's attack): a genuine approval, signed
/// by an approver, relayed by the agents account with one unapproved variable
/// added (the approval never covered the environment). Each is refused by
/// name; nothing is started; no spec is written; and NO nonce is used up.
/// Red today: the launch is accepted and the variable reaches the spec.
#[test]
fn m1_a_relayed_approval_with_any_other_variable_is_refused_by_name_and_keeps_its_nonce() {
    let w = world_with_approver(&[]);
    let mut bad = Vec::new();
    for name in OTHER_NAMES {
        let relayed = good_approval(&Req::sleep(), &nonce()).with_env(&[(name, "x")]);
        if let Err(e) = expect_refused(&w, AGENTS_UID, &relayed, name) {
            bad.push(e);
        }
    }
    // One approval, the whole probe added by the relayer.
    let n = nonce();
    let genuine = good_approval(&Req::sleep(), &n);
    let relayed = genuine.clone().with_env(&PROBE);
    let (mut c, r) = w.launch(AGENTS_UID, &relayed);
    match r {
        Err(e) if PROBE.iter().any(|(k, _)| e.contains(k)) => {}
        Err(e) => bad.push(format!(
            "the probe was refused without naming a variable: {e}"
        )),
        Ok(l) => {
            bad.push(format!(
                "the probe was ACCEPTED on a genuine approval: spec env {}",
                read_spec(&w, l.slot)
                    .map(|s| s["env"].clone())
                    .unwrap_or(Value::Null)
            ));
            w.set_active(&unit(l.slot), false);
            let _ = c.until("Ended", LONG);
        }
    }
    assert!(bad.is_empty(), "M1 (approval):\n  {}", bad.join("\n  "));
    let started = nothing_started(&w);
    assert!(
        started.is_empty(),
        "M1 (approval): refused requests still did things:\n  {}",
        started.join("\n  ")
    );
    assert!(
        w.nonce_store().trim().is_empty(),
        "M1 (approval): a refused request used up a nonce: {}",
        w.nonce_store()
    );
    // The nonce is still good: the genuine approval, sent as signed, launches.
    let (mut c2, r) = w.launch(AGENTS_UID, &genuine);
    let l = r.unwrap_or_else(|e| {
        panic!("M1: the approval whose relayed copy was refused can't launch as signed: {e}")
    });
    assert_eq!(w.started(&unit(l.slot)), 1);
    assert!(
        w.nonce_store().contains(&n),
        "the launch didn't record the nonce"
    );
    w.end_and_wait(l.slot, &mut c2);
}

/// M1 control: LANG and TERM still pass, from a person and from an approval's
/// holder, singly and together, and the spec holds exactly them. Green today
/// and must stay green.
#[test]
fn m1_control_lang_and_term_still_pass_and_are_all_the_spec_holds() {
    let w = world_with_approver(&[]);
    let pairs: [&[(&str, &str)]; 4] = [
        &[],
        &[("LANG", "en_US.UTF-8")],
        &[("TERM", "xterm-256color")],
        &[("LANG", "en_US.UTF-8"), ("TERM", "xterm-256color")],
    ];
    let mut bad = Vec::new();
    for p in pairs {
        let want: Map<String, Value> = p.iter().map(|(k, v)| (k.to_string(), json!(v))).collect();
        let want = Value::Object(want);
        for who in ["person", "approval"] {
            let req = if who == "person" {
                Req::sleep().with_env(p)
            } else {
                good_approval(&Req::sleep(), &nonce()).with_env(p)
            };
            let uid = if who == "person" {
                PERSON_UID
            } else {
                AGENTS_UID
            };
            match launch_and_spec_env(&w, uid, &req) {
                Ok(env) if env == want => {}
                Ok(env) => bad.push(format!("{who} {p:?}: the spec's env is {env}, want {want}")),
                Err(e) => bad.push(format!("{who} {p:?}: refused: {e}")),
            }
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// M1, values (I-M1: 1 to 64 bytes of `[A-Za-z0-9._@+-]`). Bad values for LANG
/// and TERM are refused by name; the longest and the oddest good ones pass.
/// Red today for every bad value but NUL (the launcher takes any value).
#[test]
fn m1_lang_and_term_values_are_one_to_64_bytes_of_plain_characters() {
    let w = World::new(&[], &[]);
    let long64 = "a".repeat(64);
    let long65 = "a".repeat(65);
    let bad_values: Vec<(&str, String)> = vec![
        ("empty", String::new()),
        ("65 bytes", long65),
        ("a space", "a b".into()),
        ("a slash", "a/b".into()),
        ("a semicolon", "a;b".into()),
        ("an equals sign", "a=b".into()),
        ("a colon", "a:b".into()),
        ("a newline", "a\nb".into()),
        ("a NUL", "a\u{0}b".into()),
        ("a non-ASCII letter", "caf\u{e9}".into()),
        ("a dollar sign", "$HOME".into()),
        ("a quote", "a\"b".into()),
        ("a tilde", "~".into()),
    ];
    let mut bad = Vec::new();
    for var in ["LANG", "TERM"] {
        for (what, value) in &bad_values {
            let req = Req::sleep().with_env(&[(var, value)]);
            if let Err(e) = expect_refused(&w, PERSON_UID, &req, var) {
                bad.push(format!("{var} with {what}: {e}"));
            }
        }
    }
    assert!(bad.is_empty(), "M1 (values):\n  {}", bad.join("\n  "));
    // Controls: good values go through unchanged (the limits are inclusive).
    let good: [&[(&str, &str)]; 2] = [
        &[("LANG", &long64), ("TERM", "a.b_c@d+e-f")],
        &[("LANG", "x"), ("TERM", "xterm-256color")],
    ];
    for p in good {
        let want: Map<String, Value> = p.iter().map(|(k, v)| (k.to_string(), json!(v))).collect();
        match launch_and_spec_env(&w, PERSON_UID, &Req::sleep().with_env(p)) {
            Ok(env) => assert_eq!(env, Value::Object(want), "{p:?}"),
            Err(e) => panic!("a good value was refused ({p:?}): {e}"),
        }
    }
}

/// M1, "each at most once": a name sent twice in the env object (JSON allows
/// it; a map keeps the last) refuses the whole request, by name, even when the
/// two values are equal. Person's account and approval path. Red today: the
/// last value wins and the launch is accepted.
#[test]
fn m1_a_name_sent_twice_refuses_the_whole_request() {
    let w = world_with_approver(&[]);
    let raws = [
        (r#"{"LANG":"en_US.UTF-8","LANG":"C"}"#, "LANG"),
        (r#"{"TERM":"a","TERM":"b"}"#, "TERM"),
        (r#"{"LANG":"C","TERM":"x","TERM":"x"}"#, "TERM"),
    ];
    let mut bad = Vec::new();
    for (raw, name) in raws {
        if let Err(e) = expect_refused(&w, PERSON_UID, &Req::sleep().with_raw_env(raw), name) {
            bad.push(format!("person, {raw}: {e}"));
        }
        let relayed = good_approval(&Req::sleep(), &nonce()).with_raw_env(raw);
        if let Err(e) = expect_refused(&w, AGENTS_UID, &relayed, name) {
            bad.push(format!("approval, {raw}: {e}"));
        }
    }
    assert!(bad.is_empty(), "M1 (duplicates):\n  {}", bad.join("\n  "));
    assert!(
        w.nonce_store().trim().is_empty(),
        "a request refused for a repeated name used up a nonce: {}",
        w.nonce_store()
    );
}

/// M1, the client: `agent-sign launch` run for real in system mode, with the
/// reviewer's probe (and PATH-like variables) in its own environment, still
/// launches, because it sends only LANG and TERM; the spec holds exactly those.
/// Green today; it must stay green once the launcher refuses everything else
/// (it fails if the client starts sending more, or the launcher's rule is
/// wrong for what the client sends).
#[test]
fn m1_control_the_real_client_sends_only_lang_and_term() {
    let w = World::new(&[], &[]);
    let cwd = w.root.join("not-a-repo");
    fs::create_dir_all(&cwd).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_agent-sign"));
    cmd.args(["launch", "--agent", AGENT, "--", "sleep", "3600"])
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", w.root.join("home"))
        .env("TMPDIR", &w.root)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("AGENT_SIGN_TEST_SYSTEM_CONFIG", &w.config)
        .env("LANG", "en_US.UTF-8")
        .env("TERM", "xterm-256color")
        .current_dir(&cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    for (k, v) in PROBE {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().expect("couldn't run agent-sign launch");
    let u = unit(1);
    let started = Instant::now();
    while w.started(&u) == 0 {
        if let Some(st) = child.try_wait().unwrap() {
            let mut err = String::new();
            if let Some(mut e) = child.stderr.take() {
                let _ = std::io::Read::read_to_string(&mut e, &mut err);
            }
            panic!("agent-sign launch ended ({st}) before a session started: {err}");
        }
        assert!(
            started.elapsed() < LONG,
            "the real client's launch never started a session"
        );
        thread::sleep(Duration::from_millis(40));
    }
    let spec = read_spec(&w, 1).expect("slot 1's spec");
    assert_eq!(
        spec["env"],
        json!({"LANG": "en_US.UTF-8", "TERM": "xterm-256color"}),
        "the client sent more than LANG and TERM, or the launcher changed them"
    );
    w.set_active(&u, false);
    let st = {
        let t = Instant::now();
        loop {
            if let Some(st) = child.try_wait().unwrap() {
                break st;
            }
            assert!(t.elapsed() < LONG, "the client never ended");
            thread::sleep(Duration::from_millis(40));
        }
    };
    assert!(st.success(), "the client ended with {st}");
}

// ---------------------------------------------------------------------------
// L1: a total deadline on reading a whole request.
// ---------------------------------------------------------------------------

/// A request prefix with no newline: a request that never completes.
const UNFINISHED: &[u8] = br#"{"type":"Launch","payload":{"agent":"claude-code","command":["sleep","3600"],"env":{},"repos":[],"approval":null}"#;

/// L1. A client that sends one byte every 300 ms (so no single read ever waits
/// long) is cut off at the total deadline (2 s under the seam) and told
/// why, from a person's account and from another's. Its connection is closed
/// well within 10 s. Red today: each byte restarts the 120 s per-read timeout,
/// so the connection stays open for as long as the client likes.
#[test]
fn l1_a_client_that_drips_its_request_is_cut_off_at_a_total_deadline() {
    let w = World::new(&[], &[("AGENT_SIGN_TEST_REQUEST_DEADLINE_MS", "2000")]);
    // Control: a prompt request is not cut off by the short deadline.
    let (mut c, l) = w.taylor_launch(&Req::sleep());
    w.end_and_wait(l.slot, &mut c);
    let mut bad = Vec::new();
    for (who, uid) in [
        ("a stranger's account", STRANGER_UID),
        ("a person's", PERSON_UID),
    ] {
        let c = w.connect_as(uid);
        settle();
        let mut s = c.stream;
        let start = Instant::now();
        let mut closed_after = None;
        'drip: for b in UNFINISHED {
            if s.write_all(&[*b]).is_err() {
                closed_after = Some(start.elapsed());
                break 'drip;
            }
            thread::sleep(Duration::from_millis(300));
            if start.elapsed() > Duration::from_secs(12) {
                break;
            }
        }
        match closed_after {
            Some(t) if t < Duration::from_secs(10) => {}
            Some(t) => bad.push(format!("{who}: cut off only after {t:?}")),
            None => bad.push(format!(
                "{who}: still being served after {:?} of one byte per 300 ms: no total deadline",
                start.elapsed()
            )),
        }
    }
    assert!(bad.is_empty(), "L1:\n  {}", bad.join("\n  "));
}

/// L1, the consequence: four slow-drip clients (the four places for requests
/// from accounts that aren't people's) can't lock everyone else out. While they
/// drip, a fifth caller is told the launcher is busy (the control: the places
/// are held); within 15 s of the drips starting, a genuine approved launch gets
/// in, because the drips hit the deadline (2 s under the seam). Red today: the
/// places are held for as long as the drips continue.
#[test]
fn l1_four_slow_clients_cannot_keep_everyone_else_out() {
    let w = world_with_approver(&[("AGENT_SIGN_TEST_REQUEST_DEADLINE_MS", "2000")]);
    let mut drips = Vec::new();
    // DELIBERATE EVAL CHANGE (re-check R1, fix round, 1 Nov 2026; again for
    // Q1, 1 Nov 2026): an account other than a person's now holds at most one
    // small place, and such accounts together at most three of the four
    // (MAX_OTHERS_PER_UID, MAX_PEOPLE_SMALL_RESERVED), so the four slow clients
    // come from four accounts, one each: three hold every place another
    // account may take, the fourth is turned away. The test still expects the
    // held places to be let go at the deadline; only the setup follows the
    // per-account cap.
    for i in 0..4 {
        drips.push(w.connect_as(STRANGER_UID + i).stream);
        settle();
    }
    let stop = Arc::new(AtomicBool::new(false));
    let dripper = {
        let stop = stop.clone();
        thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                for s in &mut drips {
                    let _ = s.write_all(b" ");
                }
                thread::sleep(Duration::from_millis(300));
            }
        })
    };
    let begun = Instant::now();
    // Control: right now the places are taken.
    let (_c, r) = w.launch(AGENTS_UID, &good_approval(&Req::sleep(), &nonce()));
    assert!(
        r.is_err(),
        "setup: the four slow clients didn't hold the launcher's places (the probe launched)"
    );
    let n = nonce();
    let req = good_approval(&Req::sleep(), &n);
    let mut last = String::new();
    let mut got_in = false;
    while begun.elapsed() < Duration::from_secs(15) {
        let (_c, r) = w.launch(AGENTS_UID, &req);
        match r {
            Ok(_) => {
                got_in = true;
                break;
            }
            Err(e) => last = e,
        }
        thread::sleep(Duration::from_millis(500));
    }
    stop.store(true, Ordering::SeqCst);
    let _ = dripper.join();
    assert!(
        got_in,
        "L1: still locked out {:?} after four slow clients began (last answer: {last})",
        begun.elapsed()
    );
}

// ---------------------------------------------------------------------------
// L2 (code): an unverified caller can't make the launcher hold 512 MiB.
// ---------------------------------------------------------------------------

/// Sends an unfinished request that is mostly bundle bytes, as fast as the
/// launcher takes it, up to `total` bytes; returns how many bytes the
/// launcher accepted before it hung up on us (or stopped reading for 5 s).
/// Part of "the wire format lives in one place": the prefix is Launch's.
fn bytes_accepted(w: &World, uid: u32, total: usize) -> usize {
    let c = w.connect_as(uid);
    settle();
    let mut s = c.stream;
    s.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    let prefix = br#"{"type":"Launch","payload":{"agent":"claude-code","command":["sleep","3600"],"env":{},"repos":[{"name":"r","base":"0123456789abcdef0123456789abcdef01234567","bundle_b64":""#;
    let mut sent = 0usize;
    if s.write_all(prefix).is_err() {
        return sent;
    }
    sent += prefix.len();
    let chunk = vec![b'A'; 64 * 1024];
    while sent < total {
        match s.write(&chunk) {
            Ok(0) | Err(_) => break,
            Ok(k) => sent += k,
        }
    }
    sent
}

/// L2. A caller that isn't a person and hasn't been verified is read for at
/// most 64 KiB, even when `[launcher] approvers` is set: a flood of bundle
/// bytes is refused at the limit, so the launcher has taken well under 4 MiB
/// (64 KiB plus what the kernel buffers) when it hangs up. Red today: with
/// approvers set the limit is 512 MiB, and the full 16 MiB is taken (four
/// such callers at once is 2 GiB).
#[test]
fn l2_an_unverified_caller_is_read_for_64_kib_not_512_mib() {
    let w = world_with_approver(&[]);
    let taken = bytes_accepted(&w, AGENTS_UID, 16 * MIB);
    assert!(
        taken < 4 * MIB,
        "L2: the launcher read {} MiB from a caller it hadn't verified (limit should be 64 KiB)",
        taken / MIB
    );
}

/// L2 control: with no approvers at all the limit already is 64 KiB (the
/// launcher's existing small-request rule), so the same flood is cut off. This
/// is the oracle's own check: it is green today, and it shows the measure
/// (bytes the launcher takes before it hangs up) separates 64 KiB from more.
#[test]
fn l2_control_with_no_approvers_the_same_flood_is_cut_off_at_the_small_limit() {
    let w = World::new(&[], &[]);
    let taken = bytes_accepted(&w, AGENTS_UID, 16 * MIB);
    assert!(
        taken < 4 * MIB,
        "the control itself fails: the launcher read {} MiB",
        taken / MIB
    );
}

/// L2 control: verified callers still bring real bundles. A person's launch
/// with a 1 MiB bundle, and an approved launch with a 300 KB bundle from the
/// agents account, both start, and the bundle is in the slot's `in/` byte
/// for byte. Green today. It depends on the wire format (`Req::wire`): if the
/// builder changes the protocol so bundle bytes follow the verification, only
/// the helper may change, and this must still pass.
#[test]
fn l2_control_verified_callers_can_still_send_real_bundles() {
    let w = world_with_approver(&[]);
    let (base, bundle) = w.repo_bundle("r", MIB);
    let mut req = Req::sleep();
    req.repos = vec![("r".into(), base, bundle.clone())];
    let (mut c, l) = w.taylor_launch(&req);
    let ins: Vec<Vec<u8>> = fs::read_dir(w.current(l.slot).join("in"))
        .expect("no current/in/")
        .map(|e| fs::read(e.unwrap().path()).unwrap())
        .collect();
    assert_eq!(ins, vec![bundle], "the person's 1 MiB bundle changed");
    w.end_and_wait(l.slot, &mut c);

    let (base, bundle) = w.repo_bundle("s", 300 * 1024);
    let mut plain = Req::sleep();
    plain.repos = vec![("s".into(), base, bundle.clone())];
    let (mut c, r) = w.launch(AGENTS_UID, &good_approval(&plain, &nonce()));
    let l =
        r.unwrap_or_else(|e| panic!("an approved launch with a 300 KB bundle was refused: {e}"));
    let ins: Vec<Vec<u8>> = fs::read_dir(w.current(l.slot).join("in"))
        .expect("no current/in/")
        .map(|e| fs::read(e.unwrap().path()).unwrap())
        .collect();
    assert_eq!(ins, vec![bundle], "the approved launch's bundle changed");
    w.end_and_wait(l.slot, &mut c);
}

// ---------------------------------------------------------------------------
// L3: a write timeout on every send to a caller.
// ---------------------------------------------------------------------------

/// L3, output. A caller that has stopped reading (but stays connected) must not
/// pin the session loop: after the session writes more output than the
/// socket holds, the launcher's send times out (1.5 s under the seam), counts
/// the caller as gone, stops the unit, ends the session (its folder in the
/// Trash, "the caller went away" logged) and frees the slot. Red today: the
/// launcher blocks in a write forever, never stops the unit and never ends the
/// session; the slot is lost until the launcher restarts.
#[test]
fn l3_a_caller_that_stops_reading_does_not_pin_the_session_loop() {
    let w = World::new(&[], &[("AGENT_SIGN_TEST_SEND_TIMEOUT_MS", "1500")]);
    let (c, l) = w.taylor_launch(&Req::sleep());
    assert_eq!(l.slot, 1);
    // The session writes 6 MiB of output; the caller never reads it. (`c`
    // stays open and unread until the end of the test.)
    let mut f = fs::OpenOptions::new()
        .append(true)
        .open(w.log_path(1))
        .unwrap();
    let line = format!("{}\n", "o".repeat(1023));
    for _ in 0..(6 * 1024) {
        f.write_all(line.as_bytes()).unwrap();
    }
    drop(f);
    wait_for(
        "the launcher to stop the unit of a caller that stopped reading (L3)",
        Duration::from_secs(25),
        || w.stopped(&unit(1)) > 0,
    );
    wait_for(
        "the stuck-caller session's folder in the Trash (L3)",
        Duration::from_secs(25),
        || !w.trash_entries(1).is_empty(),
    );
    // DELIBERATE EVAL CHANGE (deflake, same assertion): the launcher writes
    // sessions.log just after the Trash move, so on a loaded host the line can
    // land a moment after the folder appears (3 failures in 14 runs at load
    // ~12). Wait for it within the same limit instead of reading once.
    wait_for(
        "sessions.log to record that the caller went away (L3)",
        Duration::from_secs(25),
        || w.sessions_log().contains("the caller went away"),
    );
    let (_c2, l2) = w.taylor_launch(&Req::sleep());
    assert_eq!(l2.slot, 1, "slot 1 wasn't freed");
    drop(c);
}

/// L3, the end. A caller that has stopped reading when the session ends
/// (its returned bundles make the `Ended` message several MiB) doesn't pin the
/// thread: the send times out, the caller counts as gone, and the bundles are
/// kept for `agent-sign launch --collect`, for the account that launched it.
/// Red today: the send blocks forever, so nothing is kept.
#[test]
fn l3_a_caller_that_stops_reading_before_the_end_gets_its_bundles_kept_for_collect() {
    let w = World::new(&[], &[("AGENT_SIGN_TEST_SEND_TIMEOUT_MS", "1500")]);
    let (base, bundle) = w.repo_bundle("r", 1024);
    let mut req = Req::sleep();
    req.repos = vec![("r".into(), base, bundle)];
    let (c, l) = w.taylor_launch(&req);
    // What the end step would have left: a bundle of several MiB.
    let mut big = b"# v2 git bundle\n".to_vec();
    big.extend(std::iter::repeat_n(b'z', 6 * MIB));
    let cur = w.current(l.slot);
    fs::create_dir_all(cur.join("out")).unwrap();
    fs::write(cur.join("out/r.bundle"), &big).unwrap();
    fs::write(
        cur.join("out/status.json"),
        json!({"r": "clean"}).to_string(),
    )
    .unwrap();
    // The program exits; the caller (still connected) never reads again.
    w.set_active(&unit(l.slot), false);
    let kept = w.state.join("out").join(&l.session);
    wait_for(
        "the bundles of a caller that stopped reading to be kept for --collect (L3)",
        Duration::from_secs(25),
        || kept.join("owner").exists(),
    );
    assert_eq!(
        fs::read_to_string(kept.join("owner")).unwrap().trim(),
        PERSON_UID.to_string(),
        "the kept bundles aren't the launching account's"
    );
    assert_eq!(
        fs::read(kept.join("r.bundle")).unwrap(),
        big,
        "the kept bundle isn't what the session left"
    );
    drop(c);
}

// ---------------------------------------------------------------------------
// Static checks: the seams, the deadline's constant, session-exec's own check.
// ---------------------------------------------------------------------------

fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            rs_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// The two new seams are read only behind `#[cfg(feature =
/// "test-authenticator")]` (a production build ignores them: they are not
/// compiled in) and are documented in docs/system-mode.md. A static check, as
/// for `AGENT_SIGN_TEST_LAUNCH_IO`; it can't show a release build ignores
/// them, only that the read is gated. Red today: no source reads them.
#[test]
fn the_new_test_seams_are_debug_test_builds_only_and_documented() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rs_files(&root.join("src"), &mut files);
    let docs = fs::read_to_string(root.join("docs/system-mode.md")).unwrap();
    for var in [
        "AGENT_SIGN_TEST_REQUEST_DEADLINE_MS",
        "AGENT_SIGN_TEST_SEND_TIMEOUT_MS",
    ] {
        let mut reads = Vec::new();
        for f in &files {
            let text = fs::read_to_string(f).unwrap();
            let lines: Vec<&str> = text.lines().collect();
            for (i, l) in lines.iter().enumerate() {
                if l.trim_start().starts_with("//") || !l.contains(&format!("\"{var}\"")) {
                    continue;
                }
                let guarded = lines[i.saturating_sub(6)..i]
                    .iter()
                    .any(|p| p.contains("cfg(feature = \"test-authenticator\")"));
                reads.push((format!("{}:{}", f.display(), i + 1), guarded));
            }
        }
        assert!(!reads.is_empty(), "no source file reads {var}");
        let unguarded: Vec<_> = reads.iter().filter(|(_, g)| !g).collect();
        assert!(
            unguarded.is_empty(),
            "{var} is read outside #[cfg(feature = \"test-authenticator\")]: {unguarded:?}"
        );
        assert!(
            docs.contains(var),
            "docs/system-mode.md doesn't document the test seam {var}"
        );
    }
}

/// L1: "in a named constant with its reasoning". `agent_launchd.rs` has a
/// `const ..DEADLINE..` for the total time to read a request, and its doc
/// comment (two lines at least) gives the reasoning in terms of a rate (the
/// slowest sender the launcher waits for). Red today: no such constant.
#[test]
fn the_total_read_deadline_is_a_named_constant_with_its_reasoning() {
    let src =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/bin/agent_launchd.rs"))
            .unwrap();
    let lines: Vec<&str> = src.lines().collect();
    let at = lines.iter().position(|l| {
        let t = l.trim_start();
        !t.starts_with("//")
            && (t.starts_with("const ") || t.starts_with("pub const "))
            && t.split(':').next().is_some_and(|n| n.contains("DEADLINE"))
    });
    let at = at.expect("agent_launchd.rs has no `const ..DEADLINE..` for reading a whole request");
    let mut doc = Vec::new();
    let mut i = at;
    while i > 0 && lines[i - 1].trim_start().starts_with("///") {
        doc.push(lines[i - 1].trim_start().trim_start_matches('/').trim());
        i -= 1;
    }
    let doc = doc.join(" ").to_lowercase();
    assert!(
        doc.matches(' ').count() >= 15
            && ["rate", "per second", "/s", "bytes a second"]
                .iter()
                .any(|w| doc.contains(w)),
        "{}'s doc comment gives no reasoning in terms of a minimum rate (bytes per second): {doc:?}",
        lines[at].trim()
    );
}

/// M1, defence in depth: `session-exec` itself refuses a spec whose
/// environment holds any name but LANG and TERM, by calling
/// `agent_sign::launcher::check_env` (the rule `test_launch_env_rule.rs`
/// tests) on `spec.env` before it runs the program. `exec_inner` can't be run
/// here (it needs a slot's cgroup and bind mount), so this is a static
/// check of the source order; the real thing can only be shown on a machine.
/// Red today: `session_runner.rs` never calls it.
#[test]
fn session_exec_checks_the_specs_environment_before_it_runs_the_program() {
    let src =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/session_runner.rs"))
            .unwrap();
    let code: Vec<(usize, &str)> = src
        .lines()
        .scan(0usize, |off, l| {
            let o = *off;
            *off += l.len() + 1;
            Some((o, l))
        })
        .filter(|(_, l)| !l.trim_start().starts_with("//"))
        .collect();
    let find = |needle: &str| {
        code.iter()
            .find(|(_, l)| l.contains(needle))
            .map(|(o, _)| *o)
    };
    let check = find("check_env(").expect(
        "session_runner.rs never calls check_env(..) on the spec's environment (defence in depth)",
    );
    let run = find("Command::new(program)").expect("session_runner.rs no longer runs the program");
    assert!(
        check < run,
        "check_env is called after the program is already set up to run"
    );
}
