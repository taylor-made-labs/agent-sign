//! Re-check lows R1 and R2 (launcher): written before the fix, as its eval,
//! by an agent other than the builder. Each test says which finding it covers
//! and why it is red on a20d72a. Tests marked CONTROL pass today and must stay
//! green (they pin what the fix must not break).
//!
//! R1: one local account can keep all four of the launcher's small read places
//! busy by reconnecting; the fix is a per-uid cap on them.
//! R2: an approval's nonce is reserved as soon as it verifies (before any
//! bulk read); a second presentation of a reserved or spent nonce is refused
//! before it takes a bulk place; a launch that fails before a slot is claimed
//! gives the reservation back; and people's accounts have a bulk place of
//! their own, so a relayer can never keep a person out.
//!
//! Assumptions the tests make about the fix (the orchestrator's decisions):
//! relayers (accounts that are not people's) still have at least two bulk
//! places between them, and a person has one that no relayer can take. The
//! per-uid cap is not named: the tests only need it to be below four and at
//! least one.
//!
//! The harness is a trimmed copy of `test_launcher_hardening.rs`'s (a test file
//! cannot import another). The debug-test seam that file documents
//! (`AGENT_SIGN_TEST_REQUEST_DEADLINE_MS`) shortens every request deadline here.
//!
//! Run on hetzner, never on the Mac:
//! `cargo test --locked --test test_rechecks_lows_launcher`.

#![cfg(target_os = "linux")]
#![allow(dead_code)]
#![allow(unused_imports)]

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
// Helpers for this file.
// ---------------------------------------------------------------------------

/// A request with one small repository (so its bundles follow on a second
/// line).
fn bundle_req(w: &World, name: &str) -> Req {
    let (base, bundle) = w.repo_bundle(name, 4096);
    let mut req = Req::sleep();
    req.repos = vec![(name.to_string(), base, bundle)];
    req
}

/// Connects as `uid`, sends only the request's first line (the head, with its
/// approval) and nothing after it: the launcher verifies the head and then
/// waits for the bundles, holding whatever it holds while it reads.
fn send_head_only(w: &World, uid: u32, req: &Req) -> Client {
    let mut c = w.connect_as(uid);
    settle();
    let wire = req.wire();
    let head = wire.split('\n').next().unwrap();
    c.stream.write_all(format!("{head}\n").as_bytes()).unwrap();
    c
}

/// The launcher's refusal, if one comes within `limit`.
fn refusal_within(c: &mut Client, limit: Duration) -> Option<String> {
    let deadline = Instant::now() + limit;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return None;
        }
        match c.next(left) {
            Some(v) if v["type"] == "Error" => {
                return Some(v["payload"]["message"].as_str().unwrap_or("").to_string());
            }
            Some(_) => {}
            None => return None,
        }
    }
}

const SEAM: (&str, &str) = ("AGENT_SIGN_TEST_REQUEST_DEADLINE_MS", "8000");

// ---------------------------------------------------------------------------
// R1: a per-uid cap on the small read places.
// ---------------------------------------------------------------------------

/// R1. One account (here an unknown uid) connects four times and sends
/// nothing. The launcher has four small places for requests from accounts
/// that are not people's; with a per-uid cap, that account holds fewer than
/// four: at least one of its four connections is turned away at once, at
/// least one is held (the control: it is not shut out entirely), and another
/// account (the relayer, with a genuinely approved launch) still gets a place
/// and starts. A person is unaffected either way (control).
///
/// Red today: all four connections are held, the next caller is told the
/// launcher is reading other requests, and nobody is turned away.
#[test]
fn r1_one_account_reconnecting_cannot_hold_all_the_small_places() {
    let w = world_with_approver(&[("AGENT_SIGN_TEST_REQUEST_DEADLINE_MS", "30000")]);
    let mut conns = Vec::new();
    for _ in 0..4 {
        let c = w.connect_as(STRANGER_UID);
        settle();
        conns.push(c);
    }
    let mut turned_away = 0;
    for c in conns.iter_mut() {
        if refusal_within(c, Duration::from_millis(700)).is_some() {
            turned_away += 1;
        }
    }
    assert!(
        turned_away >= 1,
        "R1: one account kept all four small places busy; none of its four connections was turned away"
    );
    assert!(
        turned_away <= 3,
        "R1 control: the account was shut out entirely ({turned_away} of 4 turned away); a cap of at least 1 is meant"
    );
    let (mut c, r) = w.launch(AGENTS_UID, &good_approval(&Req::sleep(), &nonce()));
    let l = r.unwrap_or_else(|e| {
        panic!("R1: another account was refused while one account held its cap of places: {e}")
    });
    w.end_and_wait(l.slot, &mut c);
    let (mut c, l) = w.taylor_launch(&Req::sleep());
    w.end_and_wait(l.slot, &mut c);
}

// ---------------------------------------------------------------------------
// R2: nonce reserved when the approval verifies; people have a place of their own.
// ---------------------------------------------------------------------------

/// R2(a). The same valid approval presented twice at once: the first is read
/// (it waits for its bundles), and the second is refused promptly, within 3 s,
/// without waiting for a bulk place or for the request deadline (8 s under the
/// seam).
///
/// Red today: the second presentation takes the second bulk place and waits
/// for bundles that never come; nothing is said to it until the deadline.
#[test]
fn r2_the_same_approval_presented_twice_at_once_is_refused_the_second_time() {
    let w = world_with_approver(&[SEAM]);
    let req = good_approval(&bundle_req(&w, "r"), &nonce());
    let _first = send_head_only(&w, AGENTS_UID, &req);
    thread::sleep(Duration::from_millis(500));
    let mut second = send_head_only(&w, AGENTS_UID, &req);
    let said = refusal_within(&mut second, Duration::from_secs(3));
    assert!(
        said.is_some(),
        "R2: a second presentation of an approval already being read was not refused within 3 s"
    );
}

/// R2(a), the consequence. The same approval replayed once while the first is
/// read holds one bulk place, not two: a different, genuine approved launch
/// from the same relayer account still gets a place and starts while both
/// presentations are open.
///
/// Red today: the two presentations hold both bulk places and the third
/// caller is told the launcher is reading other bundles.
#[test]
fn r2_a_replayed_approval_does_not_take_a_second_bulk_place_from_other_launches() {
    let w = world_with_approver(&[SEAM]);
    let stalled = good_approval(&bundle_req(&w, "r"), &nonce());
    let _first = send_head_only(&w, AGENTS_UID, &stalled);
    thread::sleep(Duration::from_millis(500));
    let _second = send_head_only(&w, AGENTS_UID, &stalled);
    thread::sleep(Duration::from_millis(500));
    let other = good_approval(&bundle_req(&w, "s"), &nonce());
    let (mut c, r) = w.launch(AGENTS_UID, &other);
    let l = r.unwrap_or_else(|e| {
        panic!("R2: a different approved launch was refused while one approval was replayed: {e}")
    });
    w.end_and_wait(l.slot, &mut c);
}

/// R2(b). Two relayed bundles are being read (two different valid approvals,
/// heads sent, bundles not yet): a person's launch with a bundle of its own
/// still gets a bulk place and starts at once (well before the 8 s deadline).
///
/// Red today: the relayers hold both shared bulk places and the person is
/// told the launcher is reading other requests.
#[test]
fn r2_a_person_gets_a_bulk_place_while_two_relayed_bundles_are_being_read() {
    let w = world_with_approver(&[SEAM]);
    let a = good_approval(&bundle_req(&w, "a"), &nonce());
    let b = good_approval(&bundle_req(&w, "b"), &nonce());
    let _ca = send_head_only(&w, AGENTS_UID, &a);
    thread::sleep(Duration::from_millis(300));
    let _cb = send_head_only(&w, AGENTS_UID, &b);
    thread::sleep(Duration::from_millis(500));
    let begun = Instant::now();
    let (mut c, r) = w.launch(PERSON_UID, &bundle_req(&w, "p"));
    let l = r.unwrap_or_else(|e| {
        panic!("R2: a person was refused while two relayed bundles were being read: {e}")
    });
    assert!(
        begun.elapsed() < Duration::from_secs(5),
        "R2: the person only got in after {:?}",
        begun.elapsed()
    );
    w.end_and_wait(l.slot, &mut c);
}

/// R2 CONTROL. A launch that fails before a slot is claimed gives the nonce
/// back: the head is sent and the bundles never come (the request deadline,
/// 2.5 s under the seam, ends it), and the very same approval then launches
/// with its bundles. Green today (the nonce is only spent at the claim); it
/// must stay green once the nonce is reserved at verification.
#[test]
fn r2_control_a_launch_that_timed_out_before_a_slot_gives_the_nonce_back() {
    let w = world_with_approver(&[("AGENT_SIGN_TEST_REQUEST_DEADLINE_MS", "2500")]);
    let req = good_approval(&bundle_req(&w, "r"), &nonce());
    let mut first = send_head_only(&w, AGENTS_UID, &req);
    let said = refusal_within(&mut first, Duration::from_secs(8));
    assert!(said.is_some(), "setup: the stalled launch was never ended");
    let (mut c, r) = w.launch(AGENTS_UID, &req);
    let l = r.unwrap_or_else(|e| {
        panic!("R2: the approval was not given back after a launch that never got a slot: {e}")
    });
    w.end_and_wait(l.slot, &mut c);
}

/// R2 CONTROL. Another way to fail before a slot is claimed: the second line
/// carries the wrong number of bundles. The refusal gives the nonce back, and
/// the same approval then launches. Green today; must stay green.
#[test]
fn r2_control_a_refusal_before_a_slot_does_not_use_up_the_nonce() {
    let w = world_with_approver(&[]);
    let req = good_approval(&bundle_req(&w, "r"), &nonce());
    let mut bad = w.connect_as(AGENTS_UID);
    settle();
    let wire = req.wire();
    let head = wire.split('\n').next().unwrap();
    bad.stream
        .write_all(format!("{head}\n{{\"bundles_b64\":[]}}\n").as_bytes())
        .unwrap();
    let said = refusal_within(&mut bad, Duration::from_secs(5));
    assert!(
        said.is_some(),
        "setup: the wrong bundle count was not refused"
    );
    let (mut c, r) = w.launch(AGENTS_UID, &req);
    let l = r.unwrap_or_else(|e| {
        panic!("R2: the nonce was used up by a launch refused before its slot: {e}")
    });
    w.end_and_wait(l.slot, &mut c);
}

/// R2 CONTROL. Once a launch has started a session its nonce stays spent for
/// good: the same approval, presented again, is refused. Green today.
#[test]
fn r2_control_a_launched_approval_stays_spent() {
    let w = world_with_approver(&[]);
    let req = good_approval(&bundle_req(&w, "r"), &nonce());
    let (mut c, r) = w.launch(AGENTS_UID, &req);
    let l = r.unwrap_or_else(|e| panic!("setup: the first launch was refused: {e}"));
    let (_c2, again) = w.launch(AGENTS_UID, &req);
    assert!(
        again.is_err(),
        "R2: a spent approval launched a second session"
    );
    w.end_and_wait(l.slot, &mut c);
}

// ---------------------------------------------------------------------------
// Fix round: a refusal is written after the request lets go; a person is no
// worse placed than when the bulk places were all shared.
// ---------------------------------------------------------------------------

/// A person whose own bulk place is held (a silent connection from a people's
/// account holds it) still gets in at once by a relayers' place that is free,
/// so that the people's pool of one is not a weaker place than the two
/// places all callers shared before R2(b). (That relayers can't take the
/// person's own place is the test before the controls.)
///
/// Red with the person's pool alone: the second person is told the launcher
/// is reading other requests.
#[test]
fn r2_a_person_whose_own_place_is_taken_uses_a_free_relayers_place() {
    let w = world_with_approver(&[SEAM]);
    let _silent = w.connect_as(PERSON_UID);
    settle();
    let begun = Instant::now();
    let (mut c, r) = w.launch(PERSON_UID, &bundle_req(&w, "p"));
    let l = r.unwrap_or_else(|e| {
        panic!("a person was refused while only one other person's connection was being read: {e}")
    });
    assert!(
        begun.elapsed() < Duration::from_secs(5),
        "the person only got in after {:?}",
        begun.elapsed()
    );
    w.end_and_wait(l.slot, &mut c);
}

/// A refusal is written after the request has let go of what it held (the
/// nonce's reservation). A refusal that echoes a megabyte or two of the
/// caller's own text is too big for the socket's buffers, so the launcher's
/// write blocks until the caller reads (or gives up after its write patience).
/// That makes the order deterministic: a relayer presents an approval and then
/// a bundles line whose `bundles_b64` is a 2 MiB string (serde's refusal
/// repeats it), and never reads the answer. While that write is stuck, the
/// very same approval, presented again with its real bundles, must launch:
/// the first request already gave its nonce back. Written the other way round
/// (the answer first, the nonce let go after) it is told that another request
/// is presenting the approval until the stuck write times out.
#[test]
fn r2_a_stuck_refusal_does_not_hold_the_nonce_it_refuses_to_use() {
    let w = world_with_approver(&[]);
    let req = good_approval(&bundle_req(&w, "r"), &nonce());
    let wire = req.wire();
    let head = wire.split('\n').next().unwrap().to_string();
    let mut stuck = w.connect_as(AGENTS_UID);
    let junk = "A".repeat(2 * MIB);
    stuck
        .stream
        .write_all(format!("{head}\n{{\"bundles_b64\":\"{junk}\"}}\n").as_bytes())
        .unwrap();
    // The launcher has read it all and is now writing a 2 MiB refusal nobody
    // reads.
    thread::sleep(Duration::from_millis(700));
    let (mut c, r) = w.launch(AGENTS_UID, &req);
    let l = r.unwrap_or_else(|e| {
        panic!("the approval was still held by a request whose refusal was being written: {e}")
    });
    w.end_and_wait(l.slot, &mut c);
    drop(stuck);
}

/// The same for a place for reading. Both relayers' bulk places are held by
/// silent relayed heads. A person's connection sends a request line that
/// serde refuses with a 2 MiB message (an unknown request type of 2 MiB,
/// repeated in the refusal) and never reads the answer, so the launcher's
/// write of it is stuck. A second person's launch must still get in: the
/// first one's place was given back before the refusal was written. Written
/// the other way round the people's place is held for as long as the stuck
/// write lasts, and the second person is told the launcher is busy.
#[test]
fn r2_a_stuck_refusal_does_not_hold_a_persons_place() {
    let w = world_with_approver(&[SEAM]);
    let a = good_approval(&bundle_req(&w, "a"), &nonce());
    let b = good_approval(&bundle_req(&w, "b"), &nonce());
    let _ca = send_head_only(&w, AGENTS_UID, &a);
    thread::sleep(Duration::from_millis(300));
    let _cb = send_head_only(&w, AGENTS_UID, &b);
    thread::sleep(Duration::from_millis(300));
    let mut stuck = w.connect_as(PERSON_UID);
    let junk = "A".repeat(2 * MIB);
    stuck
        .stream
        .write_all(format!("{{\"type\":\"{junk}\"}}\n").as_bytes())
        .unwrap();
    thread::sleep(Duration::from_millis(700));
    let (mut c, r) = w.launch(PERSON_UID, &bundle_req(&w, "p"));
    let l = r.unwrap_or_else(|e| {
        panic!("a person was refused while another person's refusal was being written: {e}")
    });
    w.end_and_wait(l.slot, &mut c);
    drop(stuck);
}

// ---------------------------------------------------------------------------
// Sitting review 3 lows: Q1 (small places across accounts), Q2 (approval
// presentations count against the caller's launch rate). No existing
// assertion above is changed by these tests.
// ---------------------------------------------------------------------------

/// Any uid with no entry in the machine's accounts: a non-person caller.
const OTHER_UIDS: [u32; 4] = [STRANGER_UID, 2345, 3456, 4567];

/// Stops the launcher, writes `launches_per_hour = n` into `[launcher]` and
/// starts it again (the test world builds a config with the default of 48).
fn restart_with_launches_per_hour(w: &mut World, n: u32) {
    if let Some(mut c) = w.child.take() {
        let _ = c.kill();
        let _ = c.wait();
    }
    let _ = fs::remove_file(&w.launch_sock);
    let toml = fs::read_to_string(&w.config).unwrap();
    let anchor = "people_accounts = [\"taylor\"]\n";
    assert_eq!(
        toml.matches(anchor).count(),
        1,
        "setup: config layout changed"
    );
    fs::write(
        &w.config,
        toml.replace(anchor, &format!("{anchor}launches_per_hour = {n}\n")),
    )
    .unwrap();
    w.start_launchd();
}

/// Opens `per_account` silent connections for each uid in `uids` and counts
/// the ones held (not turned away within 400 ms) for each account.
fn held_per_account(w: &World, uids: &[u32], per_account: usize) -> Vec<usize> {
    let mut conns: Vec<(usize, Client)> = Vec::new();
    for (i, uid) in uids.iter().enumerate() {
        for _ in 0..per_account {
            let c = w.connect_as(*uid);
            settle();
            conns.push((i, c));
        }
    }
    let mut held = vec![0; uids.len()];
    for (i, c) in conns.iter_mut() {
        if refusal_within(c, Duration::from_millis(400)).is_none() {
            held[*i] += 1;
        }
    }
    held
}

/// Q1(a). Two accounts that are not people's each connect four times and send
/// nothing. With one small place at most per other account, together they
/// hold two of the four places, never all four. Each still holds one (control:
/// no account is shut out).
///
/// Red today: each holds two (MAX_OTHERS_PER_UID = 2), all four are taken.
#[test]
fn q1_two_accounts_together_cannot_fill_all_the_small_places() {
    let w = world_with_approver(&[("AGENT_SIGN_TEST_REQUEST_DEADLINE_MS", "30000")]);
    let held = held_per_account(&w, &[STRANGER_UID, AGENTS_UID], 4);
    let total: usize = held.iter().sum();
    assert!(
        total <= 3,
        "Q1: two accounts together hold {total} of the 4 small places ({held:?}); a person's small place must stay free"
    );
    assert!(
        held.iter().all(|h| *h >= 1),
        "Q1 control: an account was shut out entirely ({held:?})"
    );
    assert!(
        held.iter().all(|h| *h <= 1),
        "Q1: an account other than a person's holds more than 1 small place at once ({held:?})"
    );
}

/// Q1(b). Four different accounts that are not people's each hold one small
/// place: the fourth is turned away, because one place is kept for people's
/// accounts. A person then still gets in and launches (control).
///
/// Red today: all four accounts are held, none turned away.
#[test]
fn q1_a_person_still_gets_a_place_while_four_other_accounts_hold_theirs() {
    let w = world_with_approver(&[("AGENT_SIGN_TEST_REQUEST_DEADLINE_MS", "30000")]);
    let held = held_per_account(&w, &OTHER_UIDS, 1);
    let total: usize = held.iter().sum();
    assert!(
        total <= 3,
        "Q1: four other accounts took all four small places ({held:?}); none is kept for people"
    );
    let (mut c, r) = w.launch(PERSON_UID, &Req::sleep());
    let l = r.unwrap_or_else(|e| {
        panic!("Q1: a person was refused while other accounts held small places: {e}")
    });
    w.end_and_wait(l.slot, &mut c);
}

/// Q2. A relayer holding several valid approvals presents them one after the
/// other and walks away each time (no launch ever succeeds). The launcher is
/// set to 3 launches an hour; every presentation is charged, so the fourth is
/// refused with the rate-limit message within 3 s, though nothing launched. A
/// person (a different caller, own allowance) is unaffected (control).
///
/// Red today: only a launch that gets a slot is counted, so the fourth
/// presentation is read like the others and nothing is said to it.
#[test]
fn q2_presenting_approvals_in_a_loop_runs_out_the_callers_rate() {
    let mut w = world_with_approver(&[SEAM]);
    restart_with_launches_per_hour(&mut w, 3);
    for i in 0..3 {
        let req = good_approval(&bundle_req(&w, &format!("q{i}")), &nonce());
        let c = send_head_only(&w, AGENTS_UID, &req);
        thread::sleep(Duration::from_millis(400));
        drop(c);
        thread::sleep(Duration::from_millis(400));
    }
    let req = good_approval(&bundle_req(&w, "q3"), &nonce());
    let mut fourth = send_head_only(&w, AGENTS_UID, &req);
    let said = refusal_within(&mut fourth, Duration::from_secs(3));
    let said = said.unwrap_or_else(|| {
        panic!("Q2: a fourth approval presentation (rate 3 an hour, none launched) was not refused")
    });
    assert!(
        said.contains("launches_per_hour"),
        "Q2: refused, but not for the launch rate: {said}"
    );
    let (mut c, l) = w.taylor_launch(&Req::sleep());
    w.end_and_wait(l.slot, &mut c);
}
