#![allow(dead_code)]
//! Shared plumbing for the signed-acts evals (`tests/test_act_signing.rs`, and the held-out file on its own branch).
//!
//! Written before the build, by someone other than the builder, as the eval for "agent-sign signs an act"
//! (role-commitments needs it: until agent-sign can sign exact bytes as an agent, Taylor or the launcher, no real role
//! assignment can be made). Included with `#[path = "support/act_harness.rs"] mod act_harness;`; the including file
//! must also include `die_with_parent`, `key_agent`, `memory_keys` and `no_plain_keys` from this folder.
//!
//! # The interface this file pins (every name below is the contract)
//!
//! * **Sign, as an agent** (inside a launched session only):
//!   `agent-sign act sign [--payload-file ABS]` reads the exact bytes to sign from stdin (or the file), 1 to 65536
//!   bytes, and prints ONE JSON object on stdout, the *signature member*:
//!   `{"schema":"agent-sign/act-signature/1","signature":"<armored SSH signature>","certificate":"<OpenSSH
//!   certificate line>"|null}`. The SSH signature is made in the SSH-signature namespace `agent-sign/act/1` (the
//!   domain separation: a git-commit signature is in `git`, a credential in `agent-sign/credential/1`) over exactly
//!   the bytes given, by the session's own in-memory key; the certificate is the session's. The identity is
//!   `agent:<name>` and comes from the launch: `agent-sign launch --agent <slug> --identity agent:<name> -- cmd`.
//!   A session launched without `--identity` cannot sign acts. No option, variable or file lets a session pick or
//!   change its identity; `--identity` takes only `agent:` names (`person:` and `harness:` are reserved).
//! * **Sign, as an assigner** (never inside a session): `agent-sign act sign --assigner person:taylor --trust-file
//!   ABS` signs through the ssh-agent at `SSH_AUTH_SOCK` with the key the trust file lists for that identity, so
//!   Taylor's key stays in his agent or device; `agent-sign act sign --assigner harness:launcher` asks the running
//!   service, which signs with the launcher's key: held in memory only (`[acts] launcher_assigner = "memory"`, for
//!   short-lived test services) or in OpenBao (`"openbao"`, system mode). No other value starts. A signature made by
//!   an assigner has no certificate (`null`).
//! * **Trust file** (`agent-sign/acts-trust/1`): lines, `#` comments and blank lines ignored. The first
//!   non-comment line must be `agent-sign/acts-trust/1`. Then `authority <domain> <public key line>` (a certificate
//!   authority for agents' sessions), `assigner <person:..|harness:..> <public key line>`, and
//!   `revoked <identity>`. `agent-sign act trust-lines` prints the running service's `authority` and
//!   `assigner harness:launcher` lines. A file with another first line, an unknown word, a malformed line, two
//!   different identities for one key or a key listed under two kinds is refused whole.
//! * **Verify**: `agent-sign act verify --format json --trust-file ABS [--now UNIX]` reads ONE JSON object on stdin,
//!   `{"payload_b64": <standard base64 of the exact bytes>, "signature": <a signature member>}` (no other key), and
//!   prints exactly one JSON object `{"verified","signer","kind","reason","detail","trust_sha256"}`: `kind` is
//!   `"agent"` or `"assigner"` or null, `signer` is `agent:..`/`person:..`/`harness:..` or null, `trust_sha256` is
//!   the SHA-256 (hex) of the exact trust-file bytes it read. Exit 0 only when verified, 1 for every other verdict
//!   about a signature, 2 when the check cannot run (no or bad trust file, relative path, unreadable input). The
//!   signer comes from the trust file and the certificate, never from any text in the signature member.
//!   `reason` is one of `ok, bad_signature, wrong_namespace, untrusted_key, untrusted_authority, outside_window,
//!   revoked, no_act_identity, malformed, stale, no_trust_file, error`.
//! * **Credential** (how a session shows who it is to `identify`): `agent-sign act credential` (inside a session)
//!   prints `{"schema":"agent-sign/act-credential/1","issued_at":<unix>,"signature":<member in namespace
//!   agent-sign/credential/1 over the ASCII bytes "agent-sign/credential/1\n<issued_at>">}`. `agent-sign act
//!   verify-credential --format json --trust-file ABS [--now UNIX]` reads that object on stdin and prints the same
//!   verdict object; a credential older than 300 s (or dated in the future by more than 60 s) is `stale`; only
//!   agents have credentials.
//! * Agents' keys, the launcher's key and the session certificate authority exist only in memory (or OpenBao): no
//!   file under the service's home ever holds a private key.

use std::ffi::OsString;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use ssh_key::private::PrivateKey;
use tempfile::{TempDir, tempdir};
use zeroize::Zeroizing;

use crate::die_with_parent::DieWithParent;
use crate::key_agent::TestAgent;
use crate::memory_keys;
use crate::no_plain_keys;

pub const RUN_LIMIT: Duration = Duration::from_secs(60);
pub const ACT_NAMESPACE: &str = "agent-sign/act/1";
pub const CREDENTIAL_NAMESPACE: &str = "agent-sign/credential/1";
pub const TRUST_HEADER: &str = "agent-sign/acts-trust/1";

/// What role-commitments really signs for an assignment: its context line, then canonical JSON.
pub fn assignment_payload(holder: &str, role: &str, work: &str, id: &str) -> Vec<u8> {
    let body = format!(
        "{{\"body\":{{\"assignment_id\":\"{id}\",\"holder\":\"{holder}\",\"role\":\"{role}\",\"schema\":\"role-commitments/assignment/1\",\"verdict\":\"role-assigned\",\"work\":\"{work}\"}},\"kind\":\"decision\"}}"
    );
    let mut bytes = b"role-commitments/act/1\n".to_vec();
    bytes.extend_from_slice(body.as_bytes());
    bytes
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub fn text(out: &Output) -> String {
    format!(
        "status: {}\nstdout: {}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
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

/// Runs `cmd` with `input` on stdin, killing it and failing the test after [`RUN_LIMIT`].
pub fn run_within(mut cmd: Command, input: Option<&[u8]>, what: &str) -> Output {
    cmd.stdin(if input.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    })
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    if let Some(bytes) = input {
        let mut stdin = child.stdin.take().unwrap();
        let bytes = bytes.to_vec();
        std::thread::spawn(move || {
            let _ = stdin.write_all(&bytes);
        });
    }
    let (mut out, mut err) = (child.stdout.take().unwrap(), child.stderr.take().unwrap());
    let o = std::thread::spawn(move || {
        let mut v = Vec::new();
        let _ = out.read_to_end(&mut v);
        v
    });
    let e = std::thread::spawn(move || {
        let mut v = Vec::new();
        let _ = err.read_to_end(&mut v);
        v
    });
    let start = Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        if start.elapsed() > RUN_LIMIT {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{what} didn't finish within {RUN_LIMIT:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    Output {
        status,
        stdout: o.join().unwrap(),
        stderr: e.join().unwrap(),
    }
}

/// Adds a plain (uncertified) ed25519 key to an ssh-agent over its socket, the way `ssh-add` would; the key never
/// touches a file. (`key_agent.rs` only adds certified keys.)
pub fn add_plain_ed25519(socket: &Path, key: &PrivateKey) {
    fn put(out: &mut Vec<u8>, bytes: &[u8]) {
        out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(bytes);
    }
    let pair = key.key_data().ed25519().expect("an ed25519 key");
    // `Ed25519Keypair::to_bytes` is already private || public (64 bytes), which is the form ssh-agent wants.
    let secret = Zeroizing::new(pair.to_bytes().to_vec());
    let mut body = Zeroizing::new(vec![17u8]);
    put(&mut body, b"ssh-ed25519");
    put(&mut body, pair.public.as_ref());
    put(&mut body, &secret);
    put(&mut body, b"taylor test key");
    let mut stream = UnixStream::connect(socket).unwrap();
    let mut request = Zeroizing::new((body.len() as u32).to_be_bytes().to_vec());
    request.extend_from_slice(&body);
    stream.write_all(&request).unwrap();
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).unwrap();
    let mut reply = vec![0u8; u32::from_be_bytes(len) as usize];
    stream.read_exact(&mut reply).unwrap();
    assert_eq!(
        reply.first().copied(),
        Some(6),
        "the test ssh-agent refused the key"
    );
}

/// A key that lives in a test ssh-agent: the stand-in for Taylor's device key.
pub struct Device {
    pub agent: TestAgent,
    pub public_line: String,
    pub public_file: PathBuf,
}

pub struct ActWorld {
    pub dir: TempDir,
    pub home: PathBuf,
    pub path: OsString,
    pub socket: PathBuf,
    pub real_git: PathBuf,
    pub ssh_keygen: PathBuf,
    pub repo: PathBuf,
    service: Option<Child>,
    counter: std::sync::atomic::AtomicU32,
}

impl Drop for ActWorld {
    fn drop(&mut self) {
        self.stop_service();
        if !std::thread::panicking() {
            no_plain_keys::assert_no_plain_private_keys(&self.home);
        }
    }
}

impl ActWorld {
    /// A private home, a config naming the acts feature when `acts` is true (`launcher_assigner` is the value of
    /// `[acts] launcher_assigner`), a one-commit repository for sessions to work in, and a running test service.
    pub fn new(acts: bool) -> ActWorld {
        Self::with_config(if acts { Some("memory") } else { None })
    }

    pub fn with_config(launcher_assigner: Option<&str>) -> ActWorld {
        let mut w = Self::unstarted(launcher_assigner);
        w.start_service();
        w
    }

    pub fn unstarted(launcher_assigner: Option<&str>) -> ActWorld {
        let dir = tempdir().unwrap();
        let home = dir.path().to_path_buf();
        let path = cleaned_path();
        let w = ActWorld {
            socket: home.join("agent-sign-test.sock"),
            real_git: find_on(&path, "git"),
            ssh_keygen: find_on(&path, "ssh-keygen"),
            repo: home.join("repo"),
            home,
            path,
            service: None,
            counter: std::sync::atomic::AtomicU32::new(0),
            dir,
        };
        fs::create_dir_all(w.home.join(".agent-sign")).unwrap();
        let mut config = String::new();
        if let Some(value) = launcher_assigner {
            config.push_str(&format!(
                "[acts]\nenabled = true\nlauncher_assigner = \"{value}\"\n"
            ));
        }
        fs::write(w.home.join(".agent-sign/config.toml"), config).unwrap();
        fs::write(
            w.home.join("gitconfig"),
            "[user]\n\tname = Human Developer\n\temail = dev@example.com\n[commit]\n\tgpgsign = false\n",
        )
        .unwrap();
        fs::create_dir_all(&w.repo).unwrap();
        for args in [
            vec!["init", "-q", "-b", "work"],
            vec!["commit", "-q", "--allow-empty", "-m", "base"],
        ] {
            let out = w
                .cmd(&w.real_git)
                .args(&args)
                .current_dir(&w.repo)
                .output()
                .unwrap();
            assert!(out.status.success(), "setup git {args:?}: {}", text(&out));
        }
        w
    }

    pub fn base_env(&self) -> Vec<(String, OsString)> {
        let mut env: Vec<(String, OsString)> = Vec::new();
        for keep in ["TMPDIR", "USER", "LOGNAME", "LANG", "LC_ALL"] {
            if let Some(v) = std::env::var_os(keep) {
                env.push((keep.into(), v));
            }
        }
        let s = |p: &Path| p.as_os_str().to_os_string();
        env.extend([
            ("HOME".into(), s(&self.home)),
            ("PATH".into(), self.path.clone()),
            ("TZ".into(), "UTC".into()),
            ("GIT_CONFIG_GLOBAL".into(), s(&self.home.join("gitconfig"))),
            ("GIT_CONFIG_NOSYSTEM".into(), "1".into()),
            ("GIT_TERMINAL_PROMPT".into(), "0".into()),
            ("AGENT_SIGN_SOCKET".into(), s(&self.socket)),
            ("AGENT_SIGN_REAL_GIT".into(), s(&self.real_git)),
            (
                "AGENT_SIGN_BIN".into(),
                env!("CARGO_BIN_EXE_agent-ssh-sign").into(),
            ),
            ("AGENT_SIGN_CONNECT_WAIT_MS".into(), "200".into()),
        ]);
        env
    }

    pub fn cmd(&self, program: &Path) -> Command {
        let mut cmd = Command::new(program);
        cmd.env_clear().envs(self.base_env());
        cmd
    }

    pub fn agent_sign(&self) -> Command {
        self.cmd(Path::new(env!("CARGO_BIN_EXE_agent-sign")))
    }

    pub fn service_log(&self) -> String {
        fs::read_to_string(self.home.join("service.log")).unwrap_or_default()
    }

    /// Starts the service; `Err(log)` if it stopped at start.
    pub fn try_start_service(&mut self) -> Result<(), String> {
        let log = fs::File::create(self.home.join("service.log")).unwrap();
        let mut cmd = self.cmd(Path::new(env!("CARGO_BIN_EXE_agent-signd")));
        cmd.die_with_parent();
        cmd.arg("--socket")
            .arg(&self.socket)
            .arg("--auto-approve")
            .env("AGENT_SIGN_TEST_AUTH", "fail")
            .env("AGENT_SIGN_REFUSAL_BACKOFF", "none")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(log));
        let mut child = cmd.spawn().unwrap();
        let start = Instant::now();
        while !self.socket.exists() {
            if let Some(status) = child.try_wait().unwrap() {
                return Err(format!(
                    "stopped at start ({status}); its log:\n{}",
                    self.service_log()
                ));
            }
            if start.elapsed() > Duration::from_secs(10) {
                let _ = child.kill();
                let _ = child.wait();
                return Err("didn't open its socket within 10 s".into());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        self.service = Some(child);
        Ok(())
    }

    pub fn start_service(&mut self) {
        self.try_start_service()
            .unwrap_or_else(|e| panic!("the test service {e}"));
    }

    pub fn stop_service(&mut self) {
        if let Some(mut child) = self.service.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    pub fn fresh(&self, what: &str) -> PathBuf {
        let n = self
            .counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            + 1;
        self.home.join(format!("{what}-{n}"))
    }

    pub fn write(&self, what: &str, bytes: &[u8]) -> PathBuf {
        let p = self.fresh(what);
        fs::write(&p, bytes).unwrap();
        // 0600 whatever the umask: act verify and act sign refuse a group- or world-writable trust or payload
        // file (fix round 1, F4), and this account's umask is 0002.
        fs::set_permissions(&p, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
        p
    }

    // -- sessions ---------------------------------------------------------------------------------------------

    /// `agent-sign launch --agent claude-code [--identity ID] -- program args`, in the test repository.
    pub fn launched(
        &self,
        identity: Option<&str>,
        program: &Path,
        args: &[&str],
        extra_env: &[(&str, &str)],
    ) -> Output {
        let mut cmd = self.agent_sign();
        cmd.args(["launch", "--agent", "claude-code"]);
        if let Some(id) = identity {
            cmd.args(["--identity", id]);
        }
        cmd.arg("--")
            .arg(program)
            .args(args)
            .current_dir(&self.repo);
        for (k, v) in extra_env {
            cmd.env(k, v);
        }
        run_within(
            cmd,
            None,
            &format!("launched {identity:?} running {program:?} {args:?}"),
        )
    }

    /// A launched session of `identity` runs `agent-sign act <args...>` (payload given as a file, since a session's
    /// stdin is not wired through).
    pub fn in_session(
        &self,
        identity: Option<&str>,
        act_args: &[&str],
        extra_env: &[(&str, &str)],
    ) -> Output {
        let mut args = vec!["act"];
        args.extend_from_slice(act_args);
        self.launched(
            identity,
            Path::new(env!("CARGO_BIN_EXE_agent-sign")),
            &args,
            extra_env,
        )
    }

    /// The signature member an agent session makes over `payload`. Panics if it does not.
    pub fn agent_signs(&self, identity: &str, payload: &[u8]) -> Value {
        let file = self.write("payload", payload);
        let out = self.in_session(
            Some(identity),
            &["sign", "--payload-file", file.to_str().unwrap()],
            &[],
        );
        assert!(
            out.status.success(),
            "{identity} could not sign:\n{}",
            text(&out)
        );
        serde_json::from_slice(&out.stdout)
            .unwrap_or_else(|e| panic!("sign output is not one JSON object ({e}):\n{}", text(&out)))
    }

    pub fn credential_of(&self, identity: &str) -> Value {
        let out = self.in_session(Some(identity), &["credential"], &[]);
        assert!(
            out.status.success(),
            "{identity} could not make a credential:\n{}",
            text(&out)
        );
        serde_json::from_slice(&out.stdout)
            .unwrap_or_else(|e| panic!("credential is not one JSON object ({e}):\n{}", text(&out)))
    }

    /// The launcher signs as an assigner (outside any session).
    pub fn launcher_signs(&self, payload: &[u8]) -> Output {
        let mut cmd = self.agent_sign();
        cmd.args(["act", "sign", "--assigner", "harness:launcher"]);
        run_within(cmd, Some(payload), "launcher signs")
    }

    // -- trust ------------------------------------------------------------------------------------------------

    pub fn trust_lines(&self) -> String {
        let mut cmd = self.agent_sign();
        cmd.args(["act", "trust-lines"]);
        let out = run_within(cmd, None, "act trust-lines");
        assert!(
            out.status.success(),
            "act trust-lines failed:\n{}",
            text(&out)
        );
        String::from_utf8(out.stdout).unwrap()
    }

    /// A trust file: header, the service's lines, then `extra` lines. Returns its absolute path.
    pub fn trust_file(&self, extra: &[String]) -> PathBuf {
        let mut body = format!("{TRUST_HEADER}\n{}\n", self.trust_lines().trim_end());
        for line in extra {
            body.push_str(line);
            body.push('\n');
        }
        self.write("acts-trust", body.as_bytes())
    }

    pub fn trust_file_text(&self, body: &str) -> PathBuf {
        self.write("acts-trust", body.as_bytes())
    }

    // -- verification -------------------------------------------------------------------------------------------

    pub fn verify_raw(&self, stdin: &[u8], trust: &Path, now: Option<u64>) -> Output {
        let mut cmd = self.agent_sign();
        cmd.args(["act", "verify", "--format", "json", "--trust-file"])
            .arg(trust);
        if let Some(n) = now {
            cmd.args(["--now", &n.to_string()]);
        }
        run_within(cmd, Some(stdin), "act verify")
    }

    pub fn envelope(payload: &[u8], signature: &Value) -> Vec<u8> {
        serde_json::to_vec(&json!({"payload_b64": base64::engine::general_purpose::STANDARD.encode(payload), "signature": signature})).unwrap()
    }

    /// `(exit code, verdict object)` of verifying `signature` over `payload` against `trust`.
    pub fn verify(
        &self,
        payload: &[u8],
        signature: &Value,
        trust: &Path,
        now: Option<u64>,
    ) -> (i32, Value) {
        let out = self.verify_raw(&Self::envelope(payload, signature), trust, now);
        (out.status.code().unwrap_or(-1), verdict_of(&out))
    }

    pub fn verify_credential(
        &self,
        credential: &Value,
        trust: &Path,
        now: Option<u64>,
    ) -> (i32, Value) {
        let mut cmd = self.agent_sign();
        cmd.args([
            "act",
            "verify-credential",
            "--format",
            "json",
            "--trust-file",
        ])
        .arg(trust);
        if let Some(n) = now {
            cmd.args(["--now", &n.to_string()]);
        }
        let out = run_within(
            cmd,
            Some(&serde_json::to_vec(credential).unwrap()),
            "act verify-credential",
        );
        (out.status.code().unwrap_or(-1), verdict_of(&out))
    }

    // -- Taylor's device ------------------------------------------------------------------------------------------

    /// A test ssh-agent holding a fresh in-memory key, standing for Taylor's device.
    pub fn device(&self, comment: &str) -> Device {
        let key = memory_keys::new_ed25519(comment);
        let agent = TestAgent::start();
        add_plain_ed25519(agent.socket(), &key);
        let public_file = self.fresh("device.pub");
        memory_keys::write_public_file(&public_file, &key);
        Device {
            public_line: memory_keys::public_line(&key),
            public_file,
            agent,
        }
    }

    /// An SSH signature by the device key in `namespace` over `payload`, made by plain `ssh-keygen -Y sign` through
    /// the device's agent: an oracle that does not use agent-sign's code. Returned as a signature member.
    pub fn oracle_signature(&self, device: &Device, namespace: &str, payload: &[u8]) -> Value {
        let file = self.write("oracle-payload", payload);
        let mut cmd = Command::new(&self.ssh_keygen);
        cmd.env_clear()
            .env("PATH", &self.path)
            .env("SSH_AUTH_SOCK", device.agent.socket())
            .args(["-Y", "sign", "-n", namespace, "-f"])
            .arg(&device.public_file)
            .arg(&file);
        let out = run_within(cmd, None, "ssh-keygen -Y sign");
        assert!(
            out.status.success(),
            "oracle signing failed:\n{}",
            text(&out)
        );
        let armor = fs::read_to_string(format!("{}.sig", file.display())).unwrap();
        json!({"schema": "agent-sign/act-signature/1", "signature": armor, "certificate": null})
    }

    /// `agent-sign act sign --assigner person:taylor --trust-file T` against `device`'s agent.
    pub fn taylor_signs(&self, device: Option<&Device>, trust: &Path, payload: &[u8]) -> Output {
        let mut cmd = self.agent_sign();
        cmd.args(["act", "sign", "--assigner", "person:taylor", "--trust-file"])
            .arg(trust);
        if let Some(d) = device {
            cmd.env("SSH_AUTH_SOCK", d.agent.socket());
        }
        run_within(cmd, Some(payload), "taylor signs")
    }

    pub fn taylor_line(device: &Device) -> String {
        format!("assigner person:taylor {}", device.public_line)
    }
}

pub fn verdict_of(out: &Output) -> Value {
    serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("verify did not print one JSON object ({e}):\n{}", text(out)))
}

pub fn member_of(out: &Output) -> Value {
    assert!(out.status.success(), "signing failed:\n{}", text(out));
    serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("sign did not print one JSON object ({e}):\n{}", text(out)))
}

/// Collects failed assertions so one run reports them all.
#[derive(Default)]
pub struct Problems(Vec<String>);

impl Problems {
    pub fn check(&mut self, ok: bool, what: impl FnOnce() -> String) {
        if !ok {
            self.0.push(what());
        }
    }
    pub fn finish(self) {
        assert!(
            self.0.is_empty(),
            "{} assertion(s) failed:\n- {}",
            self.0.len(),
            self.0.join("\n- ")
        );
    }
}

/// The signature armor with one character of its body changed.
pub fn corrupt_armor(armor: &str) -> String {
    let mut lines: Vec<String> = armor.lines().map(String::from).collect();
    let i = lines.len() / 2;
    let mut chars: Vec<char> = lines[i].chars().collect();
    chars[3] = if chars[3] == 'A' { 'B' } else { 'A' };
    lines[i] = chars.into_iter().collect();
    lines.join("\n") + "\n"
}
