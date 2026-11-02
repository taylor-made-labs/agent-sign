//! System mode, build step 3: the launcher (`agent-launchd`), its slots and
//! the end of a session (docs/system-mode.md, sections 2 and 3, "D6", "How
//! working copies are shared", and "Build order" step 3; the suite PM's
//! decisions of 31 Oct and 1 Nov 2026).
//!
//! Written before the build, as its eval, by an agent other than its
//! builder. Every test here fails today, because `agent-launchd` does not
//! exist (no `src/bin/agent_launchd.rs`, no `[[bin]]` entry), and each says
//! in its doc comment which rule it fixes. The work is done when every test
//! here passes on hetzner with no assertion changed. This file covers only:
//! who may launch, picking a free slot, D6 (no leftovers), bundles in and
//! out, link-refusing reads, and slot reuse. `session-exec`, `session-end`,
//! `launch --collect` and the launcher-restart sweep have their own tests.
//!
//! **How the tests reach the program.** `agent-launchd` is a program, so the
//! tests run it, as the test's own account, with the seams a debug test
//! build (the `test-authenticator` feature, never installed) gives it. The
//! first three exist already (`AGENT_SIGN_TEST_SYSTEM_CONFIG`,
//! `AGENT_SIGN_TEST_KERNEL_FACTS`); the other two are NEW and fixed here,
//! because the design names no interface for them:
//!
//! - `AGENT_SIGN_TEST_SYSTEM_CONFIG=<file>`: the `system.toml`.
//! - `AGENT_SIGN_TEST_KERNEL_FACTS=<file>`: as `test_caller_registration.rs`
//!   defines it, read again on every call. `accounts` gives the uid of
//!   `taylor`, `agents`, the launcher and `agent-slot-<n>`; `peer.uid` is
//!   the uid the kernel reports for whoever connects to the launch socket
//!   next (all test callers really share one uid).
//! - `AGENT_SIGN_TEST_LAUNCH_STATE=<dir>`: the launcher's state folder
//!   (`/var/lib/agent-launch` in production): `sessions.log`, the
//!   launch-approval nonces, specs, logs.
//! - `AGENT_SIGN_TEST_LAUNCH_IO=<dir>`: the launcher's I/O folder
//!   (`/var/lib/agent-launch-io` in production; interface I-A2, review
//!   finding A-2): `specs/<n>.json` and `logs/<n>.out`, pre-made by the
//!   sitting and only OPENED by the launcher (never created). Debug test
//!   builds only, compiled and documented like the two seams above. DELIBERATE
//!   EVAL CHANGE (I-A2): `World` now makes this folder, pre-creates the files,
//!   sets all three folders 0550 and passes the variable, so every test here
//!   launches through it; no existing assertion was changed. Section 7 holds
//!   the tests of the folder's own rules.
//! - `AGENT_SIGN_TEST_SYSTEMD=<dir>`: THE PORT'S STAND-IN. The launcher asks
//!   systemd for three things only: start a unit, stop a unit, is it
//!   active. With this variable set it asks this folder instead:
//!   - `start U`: appends the line `start U` to `<dir>/calls.log`. For
//!     `agent-session@N.service` it creates the marker `<dir>/active/U`
//!     (the unit is active until the test deletes the marker, which stands
//!     for the session's program exiting, or the launcher stops it). For
//!     `agent-session-end@N.service` it creates no marker: the end step
//!     completes at once and does nothing (the tests write what the end step
//!     would have left in `current/out/` themselves).
//!   - `stop U`: appends `stop U` and deletes the marker, unless the file
//!     `<dir>/stuck/U` exists, in which case the unit stays active (a
//!     process that won't die).
//!   - `is-active U`: true exactly while `<dir>/active/U` exists. Not logged.
//!     The test may create markers itself (a unit left running).
//!
//! **The service** is a stand-in too: the test listens on `[service]
//! launcher_socket` itself and answers the launcher's `RegisterSession`
//! (the protocol of step 2) with `SessionStarted`. It records each
//! registration, what `calls.log` held when it arrived (registration must
//! come BEFORE the unit starts), and when the launcher closed the connection.
//!
//! **The launch socket's protocol** is the builder's choice except what is
//! fixed here: one JSON object per line, `{"type":..,"payload":..}` as
//! `protocol.rs` does. The caller sends
//! `Launch {agent, command:[program, args..], env:{}, repos:[{name, base,
//! bundle_b64}], approval: null | {text, signature}}`. The launcher answers
//! `Launched {session, slot, principal}` once the session's unit is started,
//! and later, when the session has ended and its folder is in the Trash,
//! `Ended {status, bundles:[{name, bundle_b64}]}`; any refusal is
//! `Error {message}`. A bundle is a git bundle; it is written to
//! `<slots root>/<n>/current/in/` (any file name; its bytes are the
//! bundle's), and the end step's output is read from
//! `current/out/<name>.bundle` and `current/out/status.json`, whose test
//! content is `{"<name>": "clean"}`. The launch approval's text has the
//! fields of design section 3 (`kind` "launch", `machine`, `agent`,
//! `repos:[{name, base}]`, `program`, `expires_at`, `nonce`), where
//! `program` is the lowercase hex SHA-256 of the compact JSON text of the
//! `command` array, signed in namespace `agent-sign-launch-approval` by a key
//! listed in `[launcher] approvers`. The signing helpers are copies of
//! `test_approval_binds_commit.rs`'s (a test file can't import another).
//!
//! **Ownership** can't be tested without root (nothing here can chown), so
//! "a session can't read X" is checked as the design's table says it
//! works: the mode bits of each folder the launcher makes, with the owners
//! the design gives (owner `agent-launch`, group `agent-slot-<n>`), against
//! the account that would be asking. See `slot_may_enter`.
//!
//! Run on hetzner, never on the Mac:
//! `cargo test --locked --test test_launcher_daemon`.

#![cfg(target_os = "linux")]

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt, symlink};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256, Sha512};
use tempfile::{TempDir, tempdir};

use agent_sign::crypto::openssh_ed25519_line;

const MACHINE: &str = "hetzner";
const DOMAIN: &str = "hetzner.agents.local";
const AGENT: &str = "claude-code";
const COUNT: u32 = 3;
const LAUNCH_NAMESPACE: &str = "agent-sign-launch-approval";
const COMMIT_NAMESPACE: &str = "agent-sign-commit-approval";

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
fn end_unit(n: u32) -> String {
    format!("agent-session-end@{n}.service")
}

const APPROVER_SEED: [u8; 32] = [21; 32];
const OTHER_SEED: [u8; 32] = [22; 32];
const LONG: Duration = Duration::from_secs(15);

// ---------------------------------------------------------------------------
// Signing helpers (copies of test_approval_binds_commit.rs's).
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

fn unb64(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD.decode(s).unwrap()
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

fn mode(p: &Path) -> u32 {
    fs::symlink_metadata(p)
        .unwrap_or_else(|e| panic!("{}: {e}", p.display()))
        .permissions()
        .mode()
        & 0o7777
}

/// Whether slot `me`'s account could enter a folder with `mode` that the
/// design gives to group `agent-slot-<group_slot>` (owner `agent-launch`):
/// through the group bits if it is that slot, the "other" bits if not.
fn slot_may_enter(me: u32, group_slot: u32, mode: u32) -> bool {
    let bits = if me == group_slot { mode >> 3 } else { mode } & 0o7;
    bits & 0o1 != 0
}

fn slot_may_list(me: u32, group_slot: u32, mode: u32) -> bool {
    let bits = if me == group_slot { mode >> 3 } else { mode } & 0o7;
    bits & 0o5 == 0o5
}

// ---------------------------------------------------------------------------
// The world: temp roots, the stand-ins, the program.
// ---------------------------------------------------------------------------

/// One registration the stand-in service saw.
#[derive(Clone, Debug)]
struct Registered {
    payload: Value,
    /// What the stand-in systemd's `calls.log` held when it arrived.
    calls_then: String,
    /// `calls.log` when the launcher closed the connection, if it has.
    closed_with: Option<String>,
}

struct World {
    _dir: TempDir,
    root: PathBuf,
    slots: PathBuf,
    state: PathBuf,
    /// The launcher's I/O folder (`specs/`, `logs/`), closed to 0550.
    io: PathBuf,
    sysd: PathBuf,
    facts: PathBuf,
    config: PathBuf,
    launch_sock: PathBuf,
    git_log: PathBuf,
    shim_dir: PathBuf,
    real_git: PathBuf,
    registrations: Arc<Mutex<Vec<Registered>>>,
    child: Option<Child>,
    log: PathBuf,
}

impl Drop for World {
    fn drop(&mut self) {
        // The I/O folders are 0550: open them so the temp folder can be removed.
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
    /// Everything made and `agent-launchd` running. `approvers` are the
    /// public keys that may sign a launch request.
    fn new(approvers: &[String]) -> World {
        World::new_with_io(approvers, |_, _| {})
    }

    /// As [`World::new`], with `setup(root, io)` run on the I/O folder after
    /// the sitting's part (the pre-made files, empty, 0600) and before the
    /// folders are closed to 0550 and the launcher starts.
    fn new_with_io(approvers: &[String], setup: impl FnOnce(&Path, &Path)) -> World {
        World::build(approvers, setup, |_| {}, None)
    }

    /// As [`World::new_with_io`], with `after_close(io)` run once the three
    /// folders are closed to 0550 and before the launcher starts (L1: to
    /// give a folder a mode the sitting never would), and, when `io_at` is
    /// given, the launcher's I/O folder is that existing path instead of one
    /// the test makes (L1: a folder whose owner is not this account).
    fn build(
        approvers: &[String],
        setup: impl FnOnce(&Path, &Path),
        after_close: impl FnOnce(&Path),
        io_at: Option<PathBuf>,
    ) -> World {
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
        // The sitting makes each slot's folder: launcher's, group the slot, 0750.
        for n in 1..=COUNT {
            let d = slots.join(n.to_string());
            fs::create_dir_all(&d).unwrap();
            fs::set_permissions(&d, fs::Permissions::from_mode(0o750)).unwrap();
        }
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();

        // The sitting's part of I-A2: the I/O folder, with every slot's spec
        // and log pre-made (regular, 0600, one link), then closed to 0550 so
        // that no entry can be made, renamed or removed in it.
        let made_io = io_at.is_none();
        let io = io_at.unwrap_or_else(|| root.join("launch-io"));
        for sub in ["specs", "logs"] {
            if made_io {
                fs::create_dir_all(io.join(sub)).unwrap();
            }
        }
        for n in 1..=COUNT {
            if !made_io {
                break;
            }
            for name in [format!("specs/{n}.json"), format!("logs/{n}.out")] {
                let f = io.join(name);
                fs::write(&f, "").unwrap();
                fs::set_permissions(&f, fs::Permissions::from_mode(0o600)).unwrap();
            }
        }
        if made_io {
            setup(&root, &io);
            for d in [io.join("specs"), io.join("logs"), io.clone()] {
                fs::set_permissions(&d, fs::Permissions::from_mode(0o550)).unwrap();
            }
            after_close(&io);
        }

        // A git that counts every run, then runs the real one.
        let real_git = find_git();
        let git_log = root.join("git-runs.log");
        fs::write(&git_log, "").unwrap();
        let shim = shim_dir.join("git");
        fs::write(
            &shim,
            format!(
                "#!/bin/sh\necho \"$PWD: $*\" >> '{}'\nexec '{}' \"$@\"\n",
                git_log.display(),
                real_git.display()
            ),
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
        // Control: the settings the tests write are ones agent-sign reads.
        agent_sign::system_config::SystemConfig::parse(&toml, &config)
            .expect("the test's system.toml must parse");

        let mut accounts = json!({
            "taylor": PERSON_UID, "agents": AGENTS_UID, "agent-launch": LAUNCHER_UID,
        });
        for n in 1..=COUNT {
            accounts[format!("agent-slot-{n}")] = json!(slot_uid(n));
        }
        let w = World {
            _dir: dir,
            root: root.clone(),
            slots,
            state,
            io,
            sysd,
            facts,
            config,
            launch_sock,
            git_log,
            shim_dir,
            real_git,
            registrations: Arc::new(Mutex::new(Vec::new())),
            child: None,
            log: root.join("launchd.log"),
        };
        fs::write(
            &w.facts,
            json!({"accounts": accounts, "peer": peer(PERSON_UID)}).to_string(),
        )
        .unwrap();
        w.start_stand_in_service(&svc_sock);
        let mut w = w;
        w.start_launchd();
        w
    }

    fn start_stand_in_service(&self, sock: &Path) {
        let listener = UnixListener::bind(sock).unwrap();
        let regs = self.registrations.clone();
        let calls = self.sysd.join("calls.log");
        thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(conn) = conn else { return };
                let regs = regs.clone();
                let calls = calls.clone();
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
                    let index = {
                        let mut r = regs.lock().unwrap();
                        r.push(Registered {
                            payload: v["payload"].clone(),
                            calls_then: fs::read_to_string(&calls).unwrap_or_default(),
                            closed_with: None,
                        });
                        r.len() - 1
                    };
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
                    regs.lock().unwrap()[index].closed_with =
                        Some(fs::read_to_string(&calls).unwrap_or_default());
                });
            }
        });
    }

    fn launchd_bin() -> PathBuf {
        let p = Path::new(env!("CARGO_BIN_EXE_agent-signd")).with_file_name("agent-launchd");
        assert!(
            p.exists(),
            "agent-launchd isn't built: src/bin/agent_launchd.rs and its [[bin]] entry don't exist yet ({})",
            p.display()
        );
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
        let child = Command::new(bin)
            .env_clear()
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
            .stderr(Stdio::from(log))
            .spawn()
            .expect("couldn't start agent-launchd");
        self.child = Some(child);
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

    // -- the I/O folder ----------------------------------------------------------

    fn io_specs(&self) -> PathBuf {
        self.io.join("specs")
    }
    fn io_logs(&self) -> PathBuf {
        self.io.join("logs")
    }
    fn spec_path(&self, n: u32) -> PathBuf {
        self.io_specs().join(format!("{n}.json"))
    }
    fn log_path(&self, n: u32) -> PathBuf {
        self.io_logs().join(format!("{n}.out"))
    }

    // -- the stand-in systemd ------------------------------------------------

    fn calls(&self) -> String {
        fs::read_to_string(self.sysd.join("calls.log")).unwrap_or_default()
    }
    fn started(&self, u: &str) -> usize {
        self.calls()
            .lines()
            .filter(|l| *l == format!("start {u}"))
            .count()
    }
    fn marker(&self, u: &str) -> PathBuf {
        self.sysd.join("active").join(u)
    }
    /// The unit's program exits (or a unit is left running).
    fn set_active(&self, u: &str, on: bool) {
        if on {
            fs::write(self.marker(u), "").unwrap();
        } else {
            let _ = fs::remove_file(self.marker(u));
        }
    }
    fn set_stuck(&self, u: &str, on: bool) {
        let p = self.sysd.join("stuck").join(u);
        if on {
            fs::write(p, "").unwrap();
        } else {
            let _ = fs::remove_file(p);
        }
    }

    // -- slots ---------------------------------------------------------------

    fn current(&self, n: u32) -> PathBuf {
        self.slots.join(n.to_string()).join("current")
    }
    fn trash(&self, n: u32) -> PathBuf {
        self.slots.join(n.to_string()).join("trash")
    }
    fn trash_entries(&self, n: u32) -> Vec<PathBuf> {
        match fs::read_dir(self.trash(n)) {
            Ok(rd) => rd.map(|e| e.unwrap().path()).collect(),
            Err(_) => Vec::new(),
        }
    }
    fn sessions_log(&self) -> String {
        fs::read_to_string(self.state.join("sessions.log")).unwrap_or_default()
    }
    fn registrations(&self) -> Vec<Registered> {
        self.registrations.lock().unwrap().clone()
    }

    // -- callers ---------------------------------------------------------------

    fn connect_as(&self, uid: u32) -> Client {
        let mut accounts: Value =
            serde_json::from_str(&fs::read_to_string(&self.facts).unwrap()).unwrap();
        accounts["peer"] = peer(uid);
        let tmp = self.facts.with_extension("tmp");
        fs::write(&tmp, accounts.to_string()).unwrap();
        fs::rename(&tmp, &self.facts).unwrap();
        let stream =
            UnixStream::connect(&self.launch_sock).expect("can't connect to the launch socket");
        // The kernel's answer is read at accept: give the launcher the moment it needs.
        Client {
            reader: BufReader::new(stream.try_clone().unwrap()),
            stream,
            raw: String::new(),
        }
    }

    /// Launches as `uid`; the caller stays connected for the session.
    fn launch(&self, uid: u32, req: &Req) -> (Client, Result<Launched, String>) {
        let mut c = self.connect_as(uid);
        c.send(&req.json());
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

    /// The program in `n`'s session exits and the caller waits for the end.
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

    /// A repository with `commits` commits; returns (dir, head sha, bundle bytes).
    fn repo_bundle(&self, name: &str, commits: u32) -> (PathBuf, String, Vec<u8>) {
        let dir = self.root.join(format!("caller-{name}-{}", fresh()));
        fs::create_dir_all(&dir).unwrap();
        self.git(&dir, &["init", "-q", "-b", "main"]);
        for i in 0..commits {
            fs::write(dir.join("f.txt"), format!("{name} {i}\n")).unwrap();
            self.git(&dir, &["add", "f.txt"]);
            self.git(
                &dir,
                &[
                    "-c",
                    "commit.gpgsign=false",
                    "commit",
                    "-q",
                    "-m",
                    &format!("c{i}"),
                ],
            );
        }
        let head = self.git(&dir, &["rev-parse", "main"]);
        let file = dir.join("x.bundle");
        self.git(
            &dir,
            &["bundle", "create", "-q", file.to_str().unwrap(), "main"],
        );
        let bytes = fs::read(&file).unwrap();
        (dir, head, bytes)
    }
}

fn peer(uid: u32) -> Value {
    json!({"uid": uid, "cgroup": "0::/user.slice/user-1000.slice/session-1.scope", "process": "alive"})
}

struct Launched {
    slot: u32,
    session: String,
}

/// A connection to the launch socket.
struct Client {
    stream: UnixStream,
    reader: BufReader<UnixStream>,
    /// Everything the launcher has sent, as text.
    raw: String,
}

impl Client {
    fn send(&mut self, v: &Value) {
        self.stream.write_all(format!("{v}\n").as_bytes()).unwrap();
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
}

impl Req {
    fn sleep() -> Req {
        Req {
            command: vec!["sleep".into(), "3600".into()],
            repos: vec![],
            approval: None,
        }
    }
    fn json(&self) -> Value {
        json!({"type": "Launch", "payload": {
            "agent": AGENT, "command": self.command, "env": {},
            "repos": self.repos.iter().map(|(n, b, bytes)|
                json!({"name": n, "base": b, "bundle_b64": b64(bytes)})).collect::<Vec<_>>(),
            "approval": self.approval.as_ref().map(|(t, s)| json!({"text": t, "signature": s})),
        }})
    }
}

/// A launch approval's text for `req`, as design section 3 lists its fields.
fn approval_text(req: &Req, kind: &str, machine: &str, nonce: &str, expires_at: u64) -> String {
    json!({
        "kind": kind, "machine": machine, "agent": AGENT,
        "repos": req.repos.iter().map(|(n, b, _)| json!({"name": n, "base": b})).collect::<Vec<_>>(),
        "program": sha256_hex(serde_json::to_string(&req.command).unwrap().as_bytes()),
        "expires_at": expires_at, "nonce": nonce,
    })
    .to_string()
}

fn signed(req: &Req, text: String, key: &SigningKey, ns: &str) -> Req {
    let sig = sshsig(key, ns, text.as_bytes());
    Req {
        approval: Some((text, sig)),
        ..req.clone()
    }
}

fn approver() -> SigningKey {
    SigningKey::from_bytes(&APPROVER_SEED)
}

fn world_with_approver() -> World {
    World::new(&[openssh_ed25519_line(&approver().verifying_key())
        .trim()
        .to_string()])
}

fn good_approval(req: &Req, nonce: &str) -> Req {
    signed(
        req,
        approval_text(req, "launch", MACHINE, nonce, now_secs() + 600),
        &approver(),
        LAUNCH_NAMESPACE,
    )
}

// ---------------------------------------------------------------------------
// 1. Who may launch.
// ---------------------------------------------------------------------------

/// Design section 3 and sitting test P1: Taylor's uid (a `[launcher]
/// people_accounts` name, looked up in the account database) launches with
/// no signature; the agents account, and any other uid, is refused with a
/// reason and nothing happens (no registration, no unit, no folder). Taylor's
/// launch is the control: the refusals aren't from a launcher that refuses
/// everything.
#[test]
fn taylors_account_may_launch_and_the_agents_account_may_not() {
    let w = World::new(&[]);
    for (who, uid) in [
        ("the agents account", AGENTS_UID),
        ("an unknown account", STRANGER_UID),
    ] {
        let (_c, r) = w.launch(uid, &Req::sleep());
        let why = r
            .err()
            .unwrap_or_else(|| panic!("{who} launched a session"));
        assert!(!why.trim().is_empty(), "{who} was refused with no reason");
    }
    assert!(
        w.calls().is_empty(),
        "a refused launch still called systemd: {}",
        w.calls()
    );
    assert!(
        w.registrations().is_empty(),
        "a refused launch still registered a session"
    );
    for n in 1..=COUNT {
        assert!(
            !w.current(n).exists(),
            "a refused launch still made slot {n}'s folder"
        );
    }
    let (_c, l) = w.taylor_launch(&Req::sleep());
    assert!(l.slot >= 1 && l.slot <= COUNT);
}

/// Design section 3, way 2: a kind "launch" approval signed by a key in
/// `approvers` lets any caller (the agents account here) launch, once: the
/// nonce is recorded, and presenting the same approval again is refused with
/// nothing started. Without the approval the same caller is refused (control).
#[test]
fn any_other_account_needs_a_signed_launch_approval_used_once() {
    let w = world_with_approver();
    let plain = Req::sleep();
    let (_c0, r) = w.launch(AGENTS_UID, &plain);
    assert!(r.is_err(), "the agents account launched with no approval");

    let nonce = format!("nonce-{}", fresh());
    let req = good_approval(&plain, &nonce);
    let (_c1, r) = w.launch(AGENTS_UID, &req);
    let first = r.unwrap_or_else(|e| panic!("a valid signed launch approval was refused: {e}"));
    assert_eq!(w.started(&unit(first.slot)), 1);

    let (_c2, r) = w.launch(AGENTS_UID, &req);
    assert!(
        r.is_err(),
        "the same launch approval launched a second session (nonce reused)"
    );
    assert_eq!(
        w.calls()
            .lines()
            .filter(|l| l.starts_with("start agent-session@"))
            .count(),
        1,
        "the replayed approval started a unit"
    );
}

/// Design section 3: the launcher checks the signature (the approvers' key,
/// the launch namespace), the kind, the machine, the expiry, and that the
/// request is exactly what was approved. Each of these is refused with
/// nothing started, and none of them uses the nonce up: after all of them,
/// the genuine approval with that same nonce still launches.
#[test]
fn a_launch_approval_that_is_not_the_commitments_keys_or_not_for_this_request_is_refused() {
    let w = world_with_approver();
    let plain = Req::sleep();
    let nonce = format!("nonce-{}", fresh());
    let other = SigningKey::from_bytes(&OTHER_SEED);
    let mut cases: Vec<(&str, Req)> = vec![
        (
            "signed by another key",
            signed(
                &plain,
                approval_text(&plain, "launch", MACHINE, &nonce, now_secs() + 600),
                &other,
                LAUNCH_NAMESPACE,
            ),
        ),
        (
            "signed in the commit-approval namespace",
            signed(
                &plain,
                approval_text(&plain, "launch", MACHINE, &nonce, now_secs() + 600),
                &approver(),
                COMMIT_NAMESPACE,
            ),
        ),
        (
            "kind commit",
            signed(
                &plain,
                approval_text(&plain, "commit", MACHINE, &nonce, now_secs() + 600),
                &approver(),
                LAUNCH_NAMESPACE,
            ),
        ),
        (
            "another machine",
            signed(
                &plain,
                approval_text(&plain, "launch", "pi", &nonce, now_secs() + 600),
                &approver(),
                LAUNCH_NAMESPACE,
            ),
        ),
        (
            "expired",
            signed(
                &plain,
                approval_text(&plain, "launch", MACHINE, &nonce, now_secs() - 5),
                &approver(),
                LAUNCH_NAMESPACE,
            ),
        ),
    ];
    // Approved for one program, presented with another.
    let mut swapped = good_approval(&plain, &nonce);
    swapped.command = vec!["sh".into(), "-c".into(), "id".into()];
    cases.push(("another program than approved", swapped));
    // Approved text altered after signing.
    let mut altered = good_approval(&plain, &nonce);
    if let Some((t, _)) = altered.approval.as_mut() {
        *t = t.replace(MACHINE, "hetzneR");
    }
    cases.push(("text altered after signing", altered));

    let mut failures = Vec::new();
    for (what, req) in &cases {
        let (_c, r) = w.launch(AGENTS_UID, req);
        if r.is_ok() {
            failures.push(format!("launched with an approval {what}"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
    assert!(
        w.calls().is_empty(),
        "a refused approval still called systemd: {}",
        w.calls()
    );
    let (_c, r) = w.launch(AGENTS_UID, &good_approval(&plain, &nonce));
    assert!(
        r.is_ok(),
        "the genuine approval was refused after refused ones (a refused approval was used up): {:?}",
        r.err()
    );
}

// ---------------------------------------------------------------------------
// 2. Picking a slot, registering, staying up.
// ---------------------------------------------------------------------------

/// Design sections 2 and 4: the launcher registers the session with the
/// service (slot, the slot account's uid looked up by name, the unit name,
/// the agent) BEFORE it starts `agent-session@N`; it starts that unit
/// through the port exactly once; it answers `Launched` with the session
/// the service made; it stays up (the registration connection stays open,
/// no `Ended`) while the unit is active; when the unit goes inactive it
/// starts the end unit, sends `Ended`, and only then closes the registration.
#[test]
fn a_launch_registers_then_starts_the_unit_and_stays_up_until_the_session_ends() {
    let w = World::new(&[]);
    let (mut c, l) = w.taylor_launch(&Req::sleep());
    assert_eq!(l.slot, 1, "the lowest free slot is 1");
    let regs = w.registrations();
    assert_eq!(
        regs.len(),
        1,
        "the launcher registered {} sessions",
        regs.len()
    );
    let p = &regs[0].payload;
    assert_eq!(p["slot"], 1);
    assert_eq!(p["uid"], slot_uid(1));
    assert_eq!(p["unit"], unit(1));
    assert_eq!(p["agent"], AGENT);
    assert!(
        !regs[0].calls_then.contains("agent-session@1"),
        "the unit was started before the session was registered: {}",
        regs[0].calls_then
    );
    assert_eq!(w.started(&unit(1)), 1);
    assert_eq!(w.started(&unit(2)) + w.started(&unit(3)), 0);
    assert!(l.session.len() >= 8, "Launched carries no session id");

    // Stays up while the unit is active.
    assert!(
        c.next(Duration::from_millis(1200)).is_none(),
        "the launcher said something (ended?) while the session's unit was active"
    );
    assert!(
        w.registrations()[0].closed_with.is_none(),
        "the registration closed while the session ran"
    );

    let ended = w.end_and_wait(1, &mut c);
    assert!(ended["payload"]["status"].is_string() || ended["payload"]["status"].is_object());
    let calls = w.calls();
    let end_at = calls
        .find(&format!("start {}", end_unit(1)))
        .expect("the end unit was never started");
    assert!(end_at > calls.find(&format!("start {}", unit(1))).unwrap());
    wait_for("the registration to close", LONG, || {
        w.registrations()[0].closed_with.is_some()
    });
}

/// Design section 2 ("the lowest free slot"), D6 and `is-active`: a slot
/// whose session unit OR end unit is active is not free. Slot 1's session
/// unit and slot 2's end unit are left active; the launch goes to slot 3.
#[test]
fn a_launch_skips_slots_whose_units_are_active() {
    let w = World::new(&[]);
    w.set_active(&unit(1), true);
    w.set_active(&end_unit(2), true);
    let (_c, l) = w.taylor_launch(&Req::sleep());
    assert_eq!(l.slot, 3, "launched in a slot with an active unit");
    assert_eq!(w.started(&unit(1)) + w.started(&unit(2)), 0);
}

/// With every slot busy (a session unit, an end unit, a session unit) the
/// launch is refused with a reason; nothing is started, registered or made.
#[test]
fn a_launch_with_no_free_slot_is_refused_and_starts_nothing() {
    let w = World::new(&[]);
    w.set_active(&unit(1), true);
    w.set_active(&end_unit(2), true);
    w.set_active(&unit(3), true);
    let (_c, r) = w.launch(PERSON_UID, &Req::sleep());
    let why = r.err().expect("a launch was accepted with every slot busy");
    assert!(!why.trim().is_empty());
    assert!(w.calls().is_empty(), "{}", w.calls());
    assert!(w.registrations().is_empty());
    for n in 1..=COUNT {
        assert!(!w.current(n).exists());
    }
}

// ---------------------------------------------------------------------------
// 3. D6: no leftovers.
// ---------------------------------------------------------------------------

/// D6: each session gets a new `current/` (a different folder from the last
/// session's, with none of its files), and its bundles are its own: the
/// second session in slot 1 is given a different repository than the first,
/// and `current/in/` holds only the second's bundle.
#[test]
fn each_session_gets_a_fresh_folder_and_fresh_clones() {
    let w = World::new(&[]);
    let (_d1, base1, bundle1) = w.repo_bundle("one", 1);
    let (_d2, base2, bundle2) = w.repo_bundle("two", 2);
    assert_ne!(bundle1, bundle2);

    let mut req = Req::sleep();
    req.repos = vec![("r".into(), base1, bundle1.clone())];
    let (mut c, l) = w.taylor_launch(&req);
    assert_eq!(l.slot, 1);
    let cur = w.current(1);
    let first_id = (
        fs::metadata(&cur).unwrap().dev(),
        fs::metadata(&cur).unwrap().ino(),
    );
    fs::create_dir_all(cur.join("work/r")).unwrap();
    fs::write(cur.join("work/r/uncommitted.txt"), "FIRST-SESSIONS-SECRET").unwrap();
    fs::create_dir_all(cur.join("home")).unwrap();
    fs::write(cur.join("home/transcript.txt"), "FIRST-TRANSCRIPT").unwrap();
    fs::write(cur.join("loose.txt"), "LOOSE").unwrap();
    w.end_and_wait(1, &mut c);

    req.repos = vec![("r".into(), base2, bundle2.clone())];
    let (_c2, l2) = w.taylor_launch(&req);
    assert_eq!(l2.slot, 1, "the slot was free again, so the lowest is 1");
    let cur = w.current(1);
    let second_id = (
        fs::metadata(&cur).unwrap().dev(),
        fs::metadata(&cur).unwrap().ino(),
    );
    assert_ne!(
        first_id, second_id,
        "the second session got the first session's folder"
    );
    for gone in ["work/r/uncommitted.txt", "home/transcript.txt", "loose.txt"] {
        assert!(
            !cur.join(gone).exists(),
            "the previous session's {gone} is in the new folder"
        );
    }
    let mut bundles = Vec::new();
    for e in fs::read_dir(cur.join("in")).expect("the new session has no in/ folder") {
        bundles.push(fs::read(e.unwrap().path()).unwrap());
    }
    assert_eq!(
        bundles,
        vec![bundle2],
        "current/in/ must hold exactly the second session's bundle"
    );
}

/// D6: at the end, `current/` is RENAMED into the slot's Trash (a folder
/// made 0700 for the launcher alone), never deleted: the uncommitted file
/// and the home folder are still there, byte for byte; and `sessions.log`
/// (in the launcher's state) says which session went to which Trash folder.
#[test]
fn a_finished_session_folder_always_goes_to_the_slots_trash_and_is_logged() {
    let w = World::new(&[]);
    let (mut c, l) = w.taylor_launch(&Req::sleep());
    let cur = w.current(l.slot);
    fs::create_dir_all(cur.join("work/r")).unwrap();
    fs::write(cur.join("work/r/dirty.txt"), "UNCOMMITTED-WORK").unwrap();
    fs::create_dir_all(cur.join("home")).unwrap();
    fs::write(cur.join("home/transcript.txt"), "THE-TRANSCRIPT").unwrap();
    let ino = fs::metadata(&cur).unwrap().ino();
    w.end_and_wait(l.slot, &mut c);

    let entries = w.trash_entries(l.slot);
    assert_eq!(
        entries.len(),
        1,
        "the Trash should hold exactly this session's folder: {entries:?}"
    );
    let t = &entries[0];
    assert_eq!(
        fs::metadata(t).unwrap().ino(),
        ino,
        "the Trash folder isn't the session's own folder renamed"
    );
    assert_eq!(
        fs::read_to_string(t.join("work/r/dirty.txt")).unwrap(),
        "UNCOMMITTED-WORK"
    );
    assert_eq!(
        fs::read_to_string(t.join("home/transcript.txt")).unwrap(),
        "THE-TRANSCRIPT"
    );
    assert_eq!(
        mode(&w.trash(l.slot)) & 0o077,
        0,
        "the Trash must be closed to the slot (0700)"
    );
    assert!(
        !w.current(l.slot).join("work").exists(),
        "the session's work is still in current/"
    );
    let name = t.file_name().unwrap().to_string_lossy().to_string();
    let log = w.sessions_log();
    assert!(
        log.lines()
            .any(|line| line.contains(&l.session) && line.contains(&name)),
        "sessions.log has no line naming session {} and Trash folder {name}:\n{log}",
        l.session
    );
}

/// D6: while sessions run in slots 1 and 2, neither account could reach the
/// other's worktree (checked through the modes of the folders the launcher
/// makes, against the design's owners; see the module documentation), nor
/// its own slot's Trash; each session's own folder is usable by its own slot
/// (the control: the modes aren't merely closed to everyone); and the input
/// bundle is not writable by the session.
#[test]
fn a_session_cannot_read_another_slots_worktree_or_its_own_slots_trash() {
    let w = World::new(&[]);
    let (_d, base, bundle) = w.repo_bundle("r", 1);
    let mut req = Req::sleep();
    req.repos = vec![("r".into(), base, bundle)];
    let (_c1, l1) = w.taylor_launch(&req);
    let (_c2, l2) = w.taylor_launch(&req);
    assert_eq!((l1.slot, l2.slot), (1, 2));
    for (mine, theirs) in [(1u32, 2u32), (2, 1)] {
        let slot_dir = w.slots.join(theirs.to_string());
        let cur = w.current(theirs);
        assert!(
            !slot_may_enter(mine, theirs, mode(&slot_dir))
                || !slot_may_enter(mine, theirs, mode(&cur)),
            "slot {mine} could enter slot {theirs}'s current/ (modes {:o} and {:o})",
            mode(&slot_dir),
            mode(&cur)
        );
        assert_eq!(
            mode(&cur) & 0o007,
            0,
            "slot {theirs}'s current/ is open to other accounts"
        );
        assert!(
            !(slot_may_enter(mine, theirs, mode(&slot_dir))
                && slot_may_list(mine, theirs, mode(&slot_dir))),
            "slot {mine} could list slot {theirs}'s folder"
        );
        // Its own folder works for it.
        assert!(
            slot_may_enter(mine, mine, mode(&w.slots.join(mine.to_string())))
                && slot_may_enter(mine, mine, mode(&w.current(mine)))
                && mode(&w.current(mine)) & 0o070 == 0o070,
            "slot {mine}'s own folder isn't usable by slot {mine} (modes {:o}, {:o})",
            mode(&w.slots.join(mine.to_string())),
            mode(&w.current(mine))
        );
        // Its own Trash does not.
        let trash = w.slots.join(mine.to_string()).join("trash");
        if trash.exists() {
            assert!(
                !slot_may_enter(mine, mine, mode(&trash)),
                "slot {mine} could enter its own Trash"
            );
        }
    }
    for e in fs::read_dir(w.current(1).join("in")).unwrap() {
        let m = mode(&e.unwrap().path());
        assert_eq!(
            m & 0o027,
            0,
            "the input bundle is writable by the session or open to others ({m:o})"
        );
    }
}

// ---------------------------------------------------------------------------
// 4. Git as bundles; the launcher never runs git.
// ---------------------------------------------------------------------------

/// Design, "bundles in, bundles out": the caller's bundle is written to
/// `current/in/` byte for byte; the bundle the end step leaves in
/// `current/out/` comes back to the caller over the same connection, byte for
/// byte, and holds the session's new commit. In all of it the launcher runs
/// git zero times (a counting git is first on its `PATH` and its
/// `AGENT_SIGN_REAL_GIT`; the control shows the counter counts).
#[test]
fn git_moves_in_and_out_as_bundles_and_the_launcher_never_runs_git() {
    let w = World::new(&[]);
    // Control: the counting git counts.
    let ctl = w.root.join("ctl");
    fs::create_dir_all(&ctl).unwrap();
    assert!(
        Command::new(w.shim_dir.join("git"))
            .arg("--version")
            .current_dir(&ctl)
            .output()
            .unwrap()
            .status
            .success()
    );
    assert_eq!(
        fs::read_to_string(&w.git_log).unwrap().lines().count(),
        1,
        "the git counter doesn't count"
    );
    fs::write(&w.git_log, "").unwrap();

    let (src, base, bundle) = w.repo_bundle("r", 1);
    let mut req = Req::sleep();
    req.repos = vec![("r".into(), base.clone(), bundle.clone())];
    let (mut c, l) = w.taylor_launch(&req);
    let cur = w.current(l.slot);
    let ins: Vec<Vec<u8>> = fs::read_dir(cur.join("in"))
        .expect("no current/in/")
        .map(|e| fs::read(e.unwrap().path()).unwrap())
        .collect();
    assert_eq!(
        ins,
        vec![bundle],
        "current/in/ must hold the caller's bundle, byte for byte"
    );

    // What the session and its end step would leave: one more commit, bundled.
    fs::write(src.join("f.txt"), "session work\n").unwrap();
    w.git(&src, &["add", "f.txt"]);
    w.git(
        &src,
        &[
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "-m",
            "by the session",
        ],
    );
    let new_head = w.git(&src, &["rev-parse", "main"]);
    let out_file = w.root.join("out.bundle");
    w.git(
        &src,
        &["bundle", "create", "-q", out_file.to_str().unwrap(), "main"],
    );
    let out_bytes = fs::read(&out_file).unwrap();
    fs::create_dir_all(cur.join("out")).unwrap();
    fs::write(cur.join("out/r.bundle"), &out_bytes).unwrap();
    fs::write(
        cur.join("out/status.json"),
        json!({"r": "clean"}).to_string(),
    )
    .unwrap();

    let ended = w.end_and_wait(l.slot, &mut c);
    let bundles = ended["payload"]["bundles"]
        .as_array()
        .expect("Ended.bundles");
    assert_eq!(bundles.len(), 1, "{bundles:?}");
    assert_eq!(bundles[0]["name"], "r");
    let back = unb64(bundles[0]["bundle_b64"].as_str().unwrap());
    assert_eq!(back, out_bytes, "the bundle came back changed");
    let got = root_file(&w, "back.bundle", &back);
    let heads = w.git(&w.root, &["bundle", "list-heads", got.to_str().unwrap()]);
    assert!(
        heads.contains(&new_head),
        "the returned bundle lacks the session's commit: {heads}"
    );

    let runs = fs::read_to_string(&w.git_log).unwrap();
    // Only the test's own `git bundle` runs go through the shim's directory, none from the launcher.
    assert!(
        !runs
            .lines()
            .any(|l| l.contains("slots") || l.contains("launch-state")),
        "the launcher ran git in a slot or its state:\n{runs}"
    );
    assert!(runs.trim().is_empty(), "the launcher ran git:\n{runs}");
}

fn root_file(w: &World, name: &str, bytes: &[u8]) -> PathBuf {
    let p = w.root.join(name);
    fs::write(&p, bytes).unwrap();
    p
}

// ---------------------------------------------------------------------------
// 5. Reads refuse links.
// ---------------------------------------------------------------------------

/// Plants `plant` in a new session's `current/` and ends the session;
/// returns what the caller was sent (all of it, as text) and the Ended message.
fn session_with_planted(w: &World, plant: impl FnOnce(&Path)) -> (String, Value, u32) {
    let (mut c, l) = w.taylor_launch(&Req::sleep());
    plant(&w.current(l.slot));
    let ended = w.end_and_wait(l.slot, &mut c);
    (c.raw.clone(), ended, l.slot)
}

/// Design D6 step 4: the launcher opens the end step's files refusing links.
/// A session plants `out/status.json` and `out/r.bundle` as links to files in
/// the launcher's own state; nothing from them reaches the caller (not as
/// text, not as base64), the targets are untouched, and the session's folder
/// still goes to the Trash with the links in it, unfollowed.
#[test]
fn the_launcher_never_follows_a_link_out_of_a_slot_folder() {
    let w = World::new(&[]);
    let secret = w.state.join("secret.bin");
    let secret_status = w.state.join("secret-status.json");
    fs::write(&secret, "LAUNCHER-SECRET-BYTES").unwrap();
    fs::write(
        &secret_status,
        "{\"r\": \"clean\", \"LAUNCHER-SECRET-STATUS\": 1}",
    )
    .unwrap();
    let leaks = |raw: &str| {
        let mut bad = Vec::new();
        for s in ["LAUNCHER-SECRET-BYTES", "LAUNCHER-SECRET-STATUS"] {
            if raw.contains(s) || raw.contains(&b64(s.as_bytes())) {
                bad.push(s);
            }
        }
        bad
    };

    // A planted link to a file.
    let (raw, _ended, slot) = session_with_planted(&w, |cur| {
        fs::create_dir_all(cur.join("out")).unwrap();
        symlink(&secret, cur.join("out/r.bundle")).unwrap();
        symlink(&secret_status, cur.join("out/status.json")).unwrap();
    });
    assert!(
        leaks(&raw).is_empty(),
        "the launcher followed a link and sent {:?} to the caller",
        leaks(&raw)
    );
    assert_eq!(
        fs::read_to_string(&secret).unwrap(),
        "LAUNCHER-SECRET-BYTES"
    );
    let t = w.trash_entries(slot);
    assert_eq!(
        t.len(),
        1,
        "the folder with links in it wasn't moved to the Trash: {t:?}"
    );
    assert!(
        fs::symlink_metadata(t[0].join("out/r.bundle"))
            .unwrap()
            .file_type()
            .is_symlink()
    );

    // A planted link where the out/ folder should be.
    let outside = w.state.join("outside-out");
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("r.bundle"), "LAUNCHER-SECRET-BYTES").unwrap();
    fs::write(
        outside.join("status.json"),
        "{\"r\": \"clean\", \"LAUNCHER-SECRET-STATUS\": 1}",
    )
    .unwrap();
    let (raw, _ended, slot) = session_with_planted(&w, |cur| {
        symlink(&outside, cur.join("out")).unwrap();
    });
    assert!(
        leaks(&raw).is_empty(),
        "the launcher followed a linked out/ folder and sent {:?}",
        leaks(&raw)
    );
    assert_eq!(
        w.trash_entries(slot).len(),
        2,
        "the second folder wasn't moved to the Trash"
    );
    assert!(
        outside.join("r.bundle").exists(),
        "the launcher touched the link's target"
    );
}

// ---------------------------------------------------------------------------
// 6. A slot is reused only after its units are inactive.
// ---------------------------------------------------------------------------

/// D6 and design section 2: the caller leaves while the session's unit
/// refuses to stop (`stuck`). The launcher asks it to stop, but until the unit
/// is inactive it neither starts the end step nor moves the folder, and slot 1
/// is not given to a new session (the next goes to slot 2). Once the unit is
/// inactive the end step runs and the folder goes to the Trash, and the next
/// launch gets slot 1 again.
#[test]
fn a_slot_is_reused_only_after_its_unit_is_inactive() {
    let w = World::new(&[]);
    w.set_stuck(&unit(1), true);
    let (c, l) = w.taylor_launch(&Req::sleep());
    assert_eq!(l.slot, 1);
    fs::write(w.current(1).join("keep.txt"), "STILL-RUNNING").unwrap();
    drop(c); // the caller goes away: the launcher must stop the session
    wait_for(
        "the launcher to ask systemd to stop the session",
        LONG,
        || w.calls().contains(&format!("stop {}", unit(1))),
    );

    let (_c2, l2) = w.taylor_launch(&Req::sleep());
    assert_eq!(
        l2.slot, 2,
        "slot 1 was reused while its unit was still active"
    );

    thread::sleep(Duration::from_millis(1500));
    assert_eq!(
        w.started(&end_unit(1)),
        0,
        "the end step started while the session's unit was still active"
    );
    assert!(
        w.current(1).join("keep.txt").exists(),
        "slot 1's folder was moved while its unit was still active"
    );
    assert!(w.trash_entries(1).is_empty());

    // The unit finally dies.
    w.set_stuck(&unit(1), false);
    w.set_active(&unit(1), false);
    wait_for("the end step and the Trash move", LONG, || {
        w.started(&end_unit(1)) == 1 && w.trash_entries(1).len() == 1
    });
    let calls = w.calls();
    assert!(
        calls.find(&format!("start {}", end_unit(1))).unwrap()
            > calls.find(&format!("stop {}", unit(1))).unwrap()
    );
    let (_c3, l3) = w.taylor_launch(&Req::sleep());
    assert_eq!(
        l3.slot, 1,
        "slot 1 wasn't reused after its units became inactive"
    );
}

// ---------------------------------------------------------------------------
// 7. The launcher's I/O folder (interface I-A2, review finding A-2).
//
// systemd opens `LoadCredential=spec:` and `StandardOutput=append:` as root,
// without O_NOFOLLOW, before it drops privilege. So those files must live in
// a folder only root can change: `/var/lib/agent-launch-io/{specs,logs}`, all
// three folders root:agent-launch 0750, the files pre-made by the sitting as
// regular files owned by agent-launch, 0600. The launcher opens those
// existing files only (O_NOFOLLOW, never O_CREAT, then fstat: regular file,
// its own uid, one link), and never creates, renames, links or removes an
// entry there. `World` makes the folder and then sets it 0550: the test
// account can no more create an entry in it than the launcher could in
// production, so "never creates" is enforced by the kernel, and listings
// before and after prove nothing was made or swapped.
//
// What these tests cannot show: ownership (the owner check: nothing here can
// chown, so a file owned by another uid can't be planted), and root's own
// behaviour (that systemd, as root, finds nothing planted: that is the
// sitting's folder modes and the unit files, tested in the sitting's area).
// ---------------------------------------------------------------------------

fn kind(m: &fs::Metadata) -> &'static str {
    let t = m.file_type();
    if t.is_symlink() {
        "link"
    } else if t.is_dir() {
        "dir"
    } else if t.is_file() {
        "file"
    } else if t.is_socket() {
        "socket"
    } else {
        "other"
    }
}

/// Every entry of the I/O folder and its two sub-folders, with what the
/// launcher must never change: the kind, the inode (a file replaced by
/// rename or re-creation gets a new one), the link count, and the folders'
/// modes. Contents and times are left out: the launcher legitimately writes
/// into the existing files.
fn io_listing(w: &World) -> Vec<String> {
    let mut out = Vec::new();
    for d in [w.io.clone(), w.io_specs(), w.io_logs()] {
        let m = fs::symlink_metadata(&d).unwrap_or_else(|e| panic!("{}: {e}", d.display()));
        out.push(format!(
            "{} {} mode={:o} ino={}",
            d.display(),
            kind(&m),
            m.permissions().mode() & 0o7777,
            m.ino()
        ));
        let mut entries: Vec<PathBuf> = fs::read_dir(&d)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        entries.sort();
        for p in entries {
            let m = fs::symlink_metadata(&p).unwrap();
            out.push(format!(
                "{} {} ino={} nlink={}",
                p.display(),
                kind(&m),
                m.ino(),
                m.nlink()
            ));
        }
    }
    out
}

fn tree_files(dir: &Path, out: &mut Vec<PathBuf>) {
    if let Ok(rd) = fs::read_dir(dir) {
        for e in rd {
            let p = e.unwrap().path();
            if fs::symlink_metadata(&p).unwrap().is_dir() {
                tree_files(&p, out);
            } else {
                out.push(p);
            }
        }
    }
}

/// Files under the launcher's own state folder's `specs/` and `logs/`: after
/// A-2 there must be none (the folders may stay, empty).
fn state_slot_files(w: &World) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for sub in ["specs", "logs"] {
        tree_files(&w.state.join(sub), &mut out);
    }
    out
}

fn read_spec(w: &World, n: u32) -> Result<Value, String> {
    let text = fs::read_to_string(w.spec_path(n)).map_err(|e| e.to_string())?;
    serde_json::from_str(&text).map_err(|e| format!("{e}: {text:?}"))
}

/// Reads `Output` messages until what they carry contains `needle`.
fn output_until(c: &mut Client, needle: &str) -> String {
    let mut got: Vec<u8> = Vec::new();
    let deadline = Instant::now() + LONG;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match c.until("Output", left) {
            Ok(v) => got.extend(unb64(v["payload"]["data_b64"].as_str().unwrap_or(""))),
            Err(e) => panic!(
                "no session output containing {needle:?} reached the caller ({e}); got {:?}",
                String::from_utf8_lossy(&got)
            ),
        }
        let s = String::from_utf8_lossy(&got).to_string();
        if s.contains(needle) {
            return s;
        }
    }
}

/// A-2, the working case: with the I/O folder non-writable (0550) and its
/// files pre-made (holding stale bytes from an earlier boot), a launch still
/// works end to end. The launcher writes the spec INTO the existing
/// `specs/<n>.json` (same inode, still 0600, one link, valid JSON naming the
/// session), truncates `logs/<n>.out` before the session starts (so the
/// stale bytes are gone and are never sent to the caller), and streams what
/// the session then appends to it. A second session in the same slot gets a
/// fresh spec and a truncated log. Fails today because the launcher writes
/// its specs and logs under its own state folder and ignores the I/O folder.
#[test]
fn launches_work_end_to_end_in_a_read_only_io_folder_of_pre_made_files() {
    let w = World::new_with_io(&[], |_, io| {
        fs::write(io.join("specs/1.json"), "STALE-SPEC-FROM-AN-EARLIER-BOOT").unwrap();
        fs::write(
            io.join("logs/1.out"),
            "STALE-OUTPUT-FROM-AN-EARLIER-SESSION\n",
        )
        .unwrap();
    });
    // Controls: the folders are non-writable, and this account really can't
    // create an entry there (a root test run would make this meaningless).
    for d in [w.io.clone(), w.io_specs(), w.io_logs()] {
        assert_eq!(mode(&d), 0o550, "{} should be 0550", d.display());
    }
    let probe = w.io_specs().join("probe");
    if fs::File::create(&probe).is_ok() {
        let _ = fs::remove_file(&probe);
        panic!(
            "the test account can create entries in a 0550 folder: don't run these tests as root"
        );
    }

    let spec_ino = fs::metadata(w.spec_path(1)).unwrap().ino();
    let log_ino = fs::metadata(w.log_path(1)).unwrap().ino();
    let (mut c, l) = w.taylor_launch(&Req::sleep());
    assert_eq!(l.slot, 1, "the lowest free slot is 1");

    let spec = read_spec(&w, 1)
        .unwrap_or_else(|e| panic!("slot 1's spec file in the I/O folder holds no spec: {e}"));
    assert_eq!(spec["session"], l.session);
    assert_eq!(spec["slot"], 1);
    assert_eq!(spec["agent"], AGENT);
    assert_eq!(spec["command"], json!(["sleep", "3600"]));
    let sm = fs::metadata(w.spec_path(1)).unwrap();
    assert_eq!(
        sm.ino(),
        spec_ino,
        "the spec file was replaced, not written in place"
    );
    assert_eq!((sm.nlink(), sm.permissions().mode() & 0o7777), (1, 0o600));

    let lm = fs::metadata(w.log_path(1)).unwrap();
    assert_eq!(
        lm.ino(),
        log_ino,
        "the log file was replaced, not written in place"
    );
    assert_eq!(
        lm.len(),
        0,
        "the log wasn't truncated before the session started: {:?}",
        fs::read_to_string(w.log_path(1))
    );

    // The session (systemd's append:) writes; the launcher streams it.
    let mut f = fs::OpenOptions::new()
        .append(true)
        .open(w.log_path(1))
        .unwrap();
    f.write_all(b"HELLO-FROM-THE-SESSION\n").unwrap();
    drop(f);
    let seen = output_until(&mut c, "HELLO-FROM-THE-SESSION");
    assert!(
        !seen.contains("STALE-OUTPUT"),
        "stale output reached the caller: {seen:?}"
    );
    assert!(
        !c.raw.contains("STALE-OUTPUT") && !c.raw.contains(&b64(b"STALE-OUTPUT")),
        "stale output reached the caller"
    );

    // The slot's next session: fresh spec, truncated log, same two files.
    w.end_and_wait(1, &mut c);
    let (_c2, l2) = w.taylor_launch(&Req::sleep());
    assert_eq!(l2.slot, 1, "slot 1 is free again");
    assert_ne!(l2.session, l.session);
    let spec2 = read_spec(&w, 1).unwrap_or_else(|e| panic!("second spec: {e}"));
    assert_eq!(
        spec2["session"], l2.session,
        "the spec still names the first session"
    );
    assert_eq!(fs::metadata(w.spec_path(1)).unwrap().ino(), spec_ino);
    assert_eq!(fs::metadata(w.log_path(1)).unwrap().ino(), log_ino);
    assert_eq!(
        fs::metadata(w.log_path(1)).unwrap().len(),
        0,
        "the previous session's output wasn't truncated before the next session"
    );
}

/// A-2, "never creates, renames, links or removes an entry": over two
/// concurrent sessions, an end, and a reuse of the slot, the I/O folder's
/// listing (names, kinds, inodes, link counts, the folders' modes) is exactly
/// what the sitting made, with no `.N.json.new` temporary or any other new
/// name. The launch itself must have worked: each slot's spec is in its
/// pre-made file (so this isn't passing because the I/O folder was ignored).
#[test]
fn the_launcher_never_creates_renames_or_removes_an_entry_in_the_io_folder() {
    let w = World::new(&[]);
    let before = io_listing(&w);
    assert_eq!(
        before.len(),
        5 + 2 * COUNT as usize,
        "the test's own setup is wrong: {before:#?}"
    );
    let (mut c1, l1) = w.taylor_launch(&Req::sleep());
    let (_c2, l2) = w.taylor_launch(&Req::sleep());
    assert_eq!((l1.slot, l2.slot), (1, 2));
    assert_eq!(
        read_spec(&w, 2).unwrap_or_else(|e| panic!("slot 2's spec: {e}"))["session"],
        l2.session,
        "slot 2's spec isn't in the I/O folder"
    );
    w.end_and_wait(1, &mut c1);
    let (_c3, l3) = w.taylor_launch(&Req::sleep());
    assert_eq!(l3.slot, 1);
    assert_eq!(
        read_spec(&w, 1).unwrap_or_else(|e| panic!("slot 1's spec: {e}"))["session"],
        l3.session
    );
    assert_eq!(
        io_listing(&w),
        before,
        "the launcher changed the I/O folder's entries"
    );
}

/// A-2, "no longer writes specs or logs under its own state folder": after a
/// launch, session output and an end, nothing is under `<state>/specs` or
/// `<state>/logs` (the folders may remain, empty). Fails today: the spec is
/// written to `<state>/specs/1.json` and the log made at `<state>/logs/1.out`.
#[test]
fn the_launcher_no_longer_writes_specs_or_logs_under_its_own_state_folder() {
    let w = World::new(&[]);
    let (mut c, l) = w.taylor_launch(&Req::sleep());
    let files = state_slot_files(&w);
    assert!(
        files.is_empty(),
        "right after a launch, the launcher keeps specs or logs in its own state folder: {files:?}"
    );
    // The session writes output (that the caller gets it is the first test's job).
    let mut f = fs::OpenOptions::new()
        .append(true)
        .open(w.log_path(l.slot))
        .unwrap();
    f.write_all(b"SOME-OUTPUT\n").unwrap();
    drop(f);
    thread::sleep(Duration::from_millis(400));
    w.end_and_wait(l.slot, &mut c);
    let (_c2, _l2) = w.taylor_launch(&Req::sleep());
    let files = state_slot_files(&w);
    assert!(
        files.is_empty(),
        "after output, an end and a reuse, the launcher keeps specs or logs in its own state folder: {files:?}"
    );
}

/// What one run with a broken slot 1 left behind.
struct BrokenRun {
    w: World,
    /// The launch that finally worked, if any (the caller's connection is kept).
    launched: Option<(Client, Launched)>,
    /// Every refusal message, in order.
    refused: Vec<String>,
    /// Everything every caller was sent, as text.
    raw: String,
    listing_before: Vec<String>,
}

/// Makes the world, lets `setup(root, io)` break slot 1's entries (before the
/// launcher starts and before the folders are closed), then launches as
/// Taylor up to `COUNT` times, keeping the sessions up, until one launch
/// works. `elsewhere/target` is a file this account owns outside the I/O
/// folder, for links to point at.
fn run_with_broken_slot_one(setup: impl FnOnce(&Path, &Path)) -> BrokenRun {
    let w = World::new_with_io(&[], |root, io| {
        let elsewhere = root.join("elsewhere");
        fs::create_dir_all(&elsewhere).unwrap();
        fs::write(elsewhere.join("target"), TARGET_CONTENT).unwrap();
        fs::set_permissions(elsewhere.join("target"), fs::Permissions::from_mode(0o600)).unwrap();
        setup(io, &elsewhere);
    });
    let listing_before = io_listing(&w);
    let mut refused = Vec::new();
    let mut raw = String::new();
    let mut launched = None;
    let mut kept = Vec::new();
    for _ in 0..COUNT {
        let (c, r) = w.launch(PERSON_UID, &Req::sleep());
        match r {
            Ok(l) => {
                launched = Some((c, l));
                break;
            }
            Err(e) => {
                refused.push(e);
                kept.push(c);
            }
        }
    }
    for c in &kept {
        raw.push_str(&c.raw);
    }
    if let Some((c, _)) = &launched {
        raw.push_str(&c.raw);
    }
    BrokenRun {
        w,
        launched,
        refused,
        raw,
        listing_before,
    }
}

const TARGET_CONTENT: &str = "TARGET-ORIGINAL-CONTENT-OF-A-FILE-THE-LAUNCHER-MUST-NOT-TOUCH\n";

/// The checks every broken-slot case shares. Returns what failed.
fn check_broken_slot_one(run: &BrokenRun) -> Vec<String> {
    let w = &run.w;
    let mut bad = Vec::new();
    // Another free slot is still used, with its spec in its own pre-made file.
    match &run.launched {
        None => bad.push(format!(
            "no launch worked although slots 2 and 3 are fine; refusals: {:?}",
            run.refused
        )),
        Some((_, l)) => {
            if l.slot == 1 {
                bad.push("the broken slot 1 was used".into());
            } else if read_spec(w, l.slot).map(|s| s["session"] == l.session) != Ok(true) {
                bad.push(format!(
                    "slot {}'s spec isn't in its file in the I/O folder: {:?}",
                    l.slot,
                    read_spec(w, l.slot)
                ));
            }
        }
    }
    if w.started(&unit(1)) != 0 {
        bad.push("slot 1's session unit was started".into());
    }
    // A plain message names the slot (in the refusal or in the launcher's log).
    let log = fs::read_to_string(&w.log).unwrap_or_default();
    let said: Vec<&str> = run
        .refused
        .iter()
        .map(|s| s.as_str())
        .chain(log.lines().filter(|l| !l.contains("started for uid")))
        .filter(|l| l.contains("slot 1") || l.contains("1.json") || l.contains("1.out"))
        .collect();
    if said.is_empty() {
        bad.push(format!(
            "nothing said, in a refusal ({:?}) or the launcher's log, that slot 1 is out of use and why",
            run.refused
        ));
    }
    // Nothing created, replaced or removed, in the I/O folder or as a fallback in the state folder.
    let after = io_listing(w);
    if after != run.listing_before {
        bad.push(format!(
            "the I/O folder's entries changed:\nbefore {:#?}\nafter {:#?}",
            run.listing_before, after
        ));
    }
    let fallback = state_slot_files(w);
    if !fallback.is_empty() {
        bad.push(format!(
            "the launcher fell back to files in its state folder: {fallback:?}"
        ));
    }
    // The link target and everything else outside is untouched and was never sent.
    let target = w.root.join("elsewhere/target");
    if fs::read_to_string(&target).ok().as_deref() != Some(TARGET_CONTENT) {
        bad.push(format!(
            "the link target was changed: {:?}",
            fs::read_to_string(&target)
        ));
    }
    if run.raw.contains("TARGET-ORIGINAL-CONTENT")
        || run.raw.contains(&b64(TARGET_CONTENT.as_bytes()))
    {
        bad.push("the link target's content reached a caller".into());
    }
    bad
}

/// A-2, links: a symlink in place of `specs/1.json` or `logs/1.out` is NEVER
/// followed (not written, truncated, appended to or read, whether it points
/// at a file the test owns or at nothing); that slot is refused with a plain
/// message and stays out of use; nothing is created (a dangling link's target
/// isn't made, the link isn't replaced); another free slot is still used.
/// Fails today because the launcher doesn't look at the I/O folder at all
/// (slot 1 launches normally from its state folder). On a build that does
/// look at it, a launcher that opened with O_CREAT, or without O_NOFOLLOW,
/// fails the untouched-target and no-new-entry checks here.
#[test]
fn a_link_in_place_of_a_spec_or_log_file_is_never_followed() {
    type Setup = fn(&Path, &Path);
    let cases: Vec<(&str, Setup)> = vec![
        ("specs/1.json is a link to a file", |io: &Path, e: &Path| {
            fs::remove_file(io.join("specs/1.json")).unwrap();
            symlink(e.join("target"), io.join("specs/1.json")).unwrap();
        }),
        ("logs/1.out is a link to a file", |io: &Path, e: &Path| {
            fs::remove_file(io.join("logs/1.out")).unwrap();
            symlink(e.join("target"), io.join("logs/1.out")).unwrap();
        }),
        (
            "specs/1.json is a link to nothing",
            |io: &Path, e: &Path| {
                fs::remove_file(io.join("specs/1.json")).unwrap();
                symlink(e.join("not-there-spec"), io.join("specs/1.json")).unwrap();
            },
        ),
        ("logs/1.out is a link to nothing", |io: &Path, e: &Path| {
            fs::remove_file(io.join("logs/1.out")).unwrap();
            symlink(e.join("not-there-log"), io.join("logs/1.out")).unwrap();
        }),
    ];
    let mut failures = Vec::new();
    for (what, setup) in cases {
        let run = run_with_broken_slot_one(setup);
        let mut bad = check_broken_slot_one(&run);
        for dangling in ["not-there-spec", "not-there-log"] {
            if run.w.root.join("elsewhere").join(dangling).exists() {
                bad.push(format!("{dangling} was created through a link"));
            }
        }
        for b in bad {
            failures.push(format!("{what}: {b}"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// A-2, "a missing file, a file with two links, or a non-regular file is
/// refused the same way and nothing is created": for each of the spec and the
/// log, an entry that is missing, has a second hard link (to a file the test
/// owns; the launcher must not write through it), is a folder, or is a socket
/// keeps slot 1 out of use with a plain message; nothing is created (the
/// missing file stays missing, no fallback in the state folder); another slot
/// is used. Not testable here: a regular file with the right shape but owned
/// by another uid (nothing in a test can chown).
#[test]
fn a_missing_two_link_or_non_regular_io_entry_keeps_its_slot_out_of_use_and_creates_nothing() {
    type Setup = fn(&Path, &Path);
    let cases: Vec<(&str, Setup)> = vec![
        ("specs/1.json is missing", |io: &Path, _: &Path| {
            fs::remove_file(io.join("specs/1.json")).unwrap();
        }),
        ("logs/1.out is missing", |io: &Path, _: &Path| {
            fs::remove_file(io.join("logs/1.out")).unwrap();
        }),
        ("specs/1.json has two links", |io: &Path, e: &Path| {
            fs::remove_file(e.join("target")).unwrap();
            fs::hard_link(io.join("specs/1.json"), e.join("target")).unwrap();
            fs::write(io.join("specs/1.json"), TARGET_CONTENT).unwrap();
        }),
        ("logs/1.out has two links", |io: &Path, e: &Path| {
            fs::remove_file(e.join("target")).unwrap();
            fs::hard_link(io.join("logs/1.out"), e.join("target")).unwrap();
            fs::write(io.join("logs/1.out"), TARGET_CONTENT).unwrap();
        }),
        ("specs/1.json is a folder", |io: &Path, _: &Path| {
            fs::remove_file(io.join("specs/1.json")).unwrap();
            fs::create_dir(io.join("specs/1.json")).unwrap();
        }),
        ("logs/1.out is a folder", |io: &Path, _: &Path| {
            fs::remove_file(io.join("logs/1.out")).unwrap();
            fs::create_dir(io.join("logs/1.out")).unwrap();
        }),
        ("specs/1.json is a socket", |io: &Path, _: &Path| {
            fs::remove_file(io.join("specs/1.json")).unwrap();
            drop(UnixListener::bind(io.join("specs/1.json")).unwrap());
        }),
        ("logs/1.out is a socket", |io: &Path, _: &Path| {
            fs::remove_file(io.join("logs/1.out")).unwrap();
            drop(UnixListener::bind(io.join("logs/1.out")).unwrap());
        }),
    ];
    let mut failures = Vec::new();
    for (what, setup) in cases {
        let run = run_with_broken_slot_one(setup);
        let mut bad = check_broken_slot_one(&run);
        let io = &run.w.io;
        if what.contains("missing") {
            let name = if what.starts_with("specs") {
                "specs/1.json"
            } else {
                "logs/1.out"
            };
            if io.join(name).symlink_metadata().is_ok() {
                bad.push(format!("{name} was created"));
            }
        }
        for b in bad {
            failures.push(format!("{what}: {b}"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// A-2, per slot: slot 1's spec is missing and slot 2's log has two links;
/// slot 3 is fine. Each bad slot is taken out of use on its own (a launch
/// that hits one doesn't also take out the others), a launch ends up in slot
/// 3, and once slot 3 is busy the next launch is refused with a reason and
/// starts nothing. Nothing in the I/O folder changes, and the hard link's
/// other name is untouched.
#[test]
fn each_bad_io_entry_takes_only_its_own_slot_out_of_use() {
    let w = World::new_with_io(&[], |root, io| {
        let e = root.join("elsewhere");
        fs::create_dir_all(&e).unwrap();
        fs::hard_link(io.join("logs/2.out"), e.join("twin")).unwrap();
        fs::write(io.join("logs/2.out"), TARGET_CONTENT).unwrap();
        fs::remove_file(io.join("specs/1.json")).unwrap();
    });
    let before = io_listing(&w);
    let mut refused = Vec::new();
    let mut kept = Vec::new();
    let mut got = None;
    for _ in 0..COUNT {
        let (c, r) = w.launch(PERSON_UID, &Req::sleep());
        match r {
            Ok(l) => {
                got = Some((c, l));
                break;
            }
            Err(e) => {
                refused.push(e);
                kept.push(c);
            }
        }
    }
    let (_c, l) = got.unwrap_or_else(|| {
        panic!("no launch worked although slot 3 is fine; refusals: {refused:?}")
    });
    assert_eq!(
        l.slot, 3,
        "only slot 3 has good files; refusals: {refused:?}"
    );
    assert!(
        refused.iter().all(|m| !m.trim().is_empty()),
        "a refusal had no message: {refused:?}"
    );
    assert_eq!(w.started(&unit(1)) + w.started(&unit(2)), 0);
    assert_eq!(
        read_spec(&w, 3).unwrap_or_else(|e| panic!("slot 3's spec: {e}"))["session"],
        l.session
    );
    // Everything is taken now: slot 3 is busy and 1 and 2 are out of use.
    let (_c4, r) = w.launch(PERSON_UID, &Req::sleep());
    let why = r
        .err()
        .expect("a launch worked with every slot busy or out of use");
    assert!(!why.trim().is_empty());
    assert_eq!(
        w.calls()
            .lines()
            .filter(|l| l.starts_with("start agent-session@"))
            .count(),
        1,
        "{}",
        w.calls()
    );
    assert_eq!(io_listing(&w), before, "the I/O folder's entries changed");
    assert_eq!(
        fs::read_to_string(w.root.join("elsewhere/twin")).unwrap(),
        TARGET_CONTENT,
        "the launcher wrote or truncated through the second hard link"
    );
}

/// A-2: with every slot's log missing, no launch works: each is refused with
/// a reason, no session unit is started, nothing is created in the I/O folder
/// or as a fallback in the state folder. (The same world with good files
/// launches in every other test here: that is the control.)
#[test]
fn with_every_slots_log_missing_every_launch_is_refused_and_nothing_is_made() {
    let w = World::new_with_io(&[], |_, io| {
        for n in 1..=COUNT {
            fs::remove_file(io.join(format!("logs/{n}.out"))).unwrap();
        }
    });
    let before = io_listing(&w);
    for _ in 0..=COUNT {
        let (_c, r) = w.launch(PERSON_UID, &Req::sleep());
        let why = r
            .err()
            .expect("a launch worked with every slot's log missing");
        assert!(!why.trim().is_empty(), "a refusal had no message");
    }
    assert!(
        !w.calls()
            .lines()
            .any(|l| l.starts_with("start agent-session@")),
        "a session unit was started: {}",
        w.calls()
    );
    assert_eq!(
        io_listing(&w),
        before,
        "something was made in the I/O folder"
    );
    let fallback = state_slot_files(&w);
    assert!(
        fallback.is_empty(),
        "fell back to the state folder: {fallback:?}"
    );
}

/// A-2, the seam: the I/O folder is `/var/lib/agent-launch-io` in production,
/// and only a debug test build (`#[cfg(feature = "test-authenticator")]`, as
/// `AGENT_SIGN_TEST_LAUNCH_STATE` and `AGENT_SIGN_TEST_SYSTEMD` are) may move
/// it with `AGENT_SIGN_TEST_LAUNCH_IO`; and docs/system-mode.md documents it.
/// A static check of the source: it can't show that a release build ignores
/// the variable (the tests only have the debug test build), only that the
/// read of it is behind the feature gate.
#[test]
fn the_io_folders_place_is_fixed_in_production_and_movable_only_in_debug_test_builds() {
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
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rs_files(&root.join("src"), &mut files);
    let mut production_path = false;
    let mut seam = Vec::new();
    for f in &files {
        let text = fs::read_to_string(f).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        for (i, l) in lines.iter().enumerate() {
            if l.trim_start().starts_with("//") {
                continue;
            }
            if l.contains("/var/lib/agent-launch-io") {
                production_path = true;
            }
            if l.contains("\"AGENT_SIGN_TEST_LAUNCH_IO\"") {
                let guarded = lines[i.saturating_sub(6)..i]
                    .iter()
                    .any(|p| p.contains("cfg(feature = \"test-authenticator\")"));
                seam.push((format!("{}:{}", f.display(), i + 1), guarded));
            }
        }
    }
    assert!(
        production_path,
        "no source file names the production path /var/lib/agent-launch-io"
    );
    assert!(
        !seam.is_empty(),
        "no source file reads AGENT_SIGN_TEST_LAUNCH_IO"
    );
    let unguarded: Vec<_> = seam.iter().filter(|(_, g)| !g).collect();
    assert!(
        unguarded.is_empty(),
        "AGENT_SIGN_TEST_LAUNCH_IO is read outside #[cfg(feature = \"test-authenticator\")]: {unguarded:?}"
    );
    let docs = fs::read_to_string(root.join("docs/system-mode.md")).unwrap();
    assert!(
        docs.contains("AGENT_SIGN_TEST_LAUNCH_IO") && docs.contains("/var/lib/agent-launch-io"),
        "docs/system-mode.md doesn't document the I/O folder and its test seam"
    );
}

// -- L1: the I/O folder's owner and mode check -----------------------------

/// Every launch in a world whose I/O folder was changed by `after_close` (or
/// is `io_at`) is refused, with `needle` in the reasons; no session unit is
/// started; nothing in the folder changes. Returns what failed.
fn io_folder_refused_everywhere(
    what: &str,
    after_close: impl FnOnce(&Path),
    io_at: Option<PathBuf>,
    needle: &str,
) -> Vec<String> {
    let w = World::build(&[], |_, _| {}, after_close, io_at);
    let before = if w.io.starts_with(&w.root) {
        Some(io_listing(&w))
    } else {
        None
    };
    let mut bad = Vec::new();
    let mut kept = Vec::new();
    for _ in 0..=COUNT {
        let (c, r) = w.launch(PERSON_UID, &Req::sleep());
        match r {
            Ok(l) => bad.push(format!("{what}: slot {} launched", l.slot)),
            Err(e) => {
                if !e.contains("isn't root's with no write for its group or others") {
                    bad.push(format!("{what}: refused for another reason: {e}"));
                } else if !e.contains(needle) {
                    bad.push(format!("{what}: reason doesn't name {needle:?}: {e}"));
                }
            }
        }
        kept.push(c);
    }
    if w.calls()
        .lines()
        .any(|l| l.starts_with("start agent-session@"))
    {
        bad.push(format!("{what}: a session unit was started: {}", w.calls()));
    }
    if let Some(b) = before
        && io_listing(&w) != b
    {
        bad.push(format!("{what}: the folder's entries changed"));
    }
    bad
}

/// L1 (group and other write): the I/O folder and each of its two sub-folders
/// must have no write for group or others, or the launcher (in the folder's
/// group) could make, rename or remove an entry in a folder systemd, as
/// root, opens paths in. For each of the three folders and each of group-write
/// and other-write, every launch is refused naming the folder, and nothing
/// is started. The control is every other test in this file, which launch
/// from the same folders at 0550. Fails if `check_io_folder` is made to
/// always pass (then slot 1 launches).
#[test]
fn an_io_folder_writable_by_its_group_or_others_is_never_used() {
    let mut failures = Vec::new();
    for folder in ["", "specs", "logs"] {
        for (who, bits) in [("group", 0o570u32), ("others", 0o557u32)] {
            let what = format!(
                "{} writable by {who}",
                if folder.is_empty() {
                    "the I/O folder"
                } else {
                    folder
                }
            );
            let f = folder.to_string();
            let name = if folder.is_empty() {
                "launch-io"
            } else {
                folder
            };
            failures.extend(io_folder_refused_everywhere(
                &what,
                move |io| {
                    let d = if f.is_empty() {
                        io.to_path_buf()
                    } else {
                        io.join(&f)
                    };
                    fs::set_permissions(&d, fs::Permissions::from_mode(bits)).unwrap();
                },
                None,
                name,
            ));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// L1 (owner): a folder that is not owned by the expected account is refused
/// even when its mode is fine. Under the test stand-in for the kernel
/// (`AGENT_SIGN_TEST_KERNEL_FACTS`, debug test builds only) the expected
/// owner is the test's own account, because a test can't make a folder
/// root's; in production it is uid 0 (the static check below). So the test
/// points the I/O folder at `/usr`, which root owns with mode 0755 (a good
/// mode): the refusal must be about the owner. Not testable here: that, with
/// the stand-in off, the expected owner is root (needs a root-owned folder
/// and the production kernel facts); covered by the static check only.
#[test]
fn an_io_folder_owned_by_another_account_is_never_used() {
    let usr = PathBuf::from("/usr");
    let m = fs::metadata(&usr).unwrap();
    assert!(
        m.uid() != unsafe { libc::geteuid() } && m.permissions().mode() & 0o022 == 0,
        "this test needs /usr owned by another account with no group/other write"
    );
    let bad = io_folder_refused_everywhere("io folder owned by root", |_| {}, Some(usr), "uid 0");
    assert!(bad.is_empty(), "{bad:#?}");
}

/// L1 (owner, static): the expected owner is uid 0 unless the test
/// stand-in is on, and the stand-in is the only thing that changes it. A
/// source check: it fails if the production branch is anything but a literal 0
/// or the check no longer compares the owner.
#[test]
fn the_io_folders_expected_owner_is_root_outside_the_test_stand_in() {
    let src =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/bin/agent_launchd.rs"))
            .unwrap();
    let start = src
        .find("fn io_folder_owner() -> u32")
        .expect("io_folder_owner is gone");
    let body: String = src[start..].lines().take(7).collect::<Vec<_>>().join("\n");
    let squashed: String = body.split_whitespace().collect();
    assert_eq!(
        squashed,
        "fnio_folder_owner()->u32{ifagent_sign::kernel_facts::is_stand_in(){euid()}else{0}}",
        "{body}"
    );
    assert!(
        src.contains("st.st_uid != io_folder_owner() || st.st_mode & 0o022 != 0"),
        "check_io_folder no longer compares the owner and the group/other write bits"
    );
}
