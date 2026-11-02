//! Caller identity: no process can sign as an agent it isn't.
//!
//! These tests were written before the fix, as its eval (independent
//! security review of `feat/servers` at f3c9278, 31 Oct 2026; the design is
//! in `docs/caller-identity.md`). Each test is one impersonation attempt that
//! must be refused. They fail today; the fix is done when every test here
//! passes, and every test in `test_caller_identity_sitting.rs` passes on the
//! server after its sitting.
//!
//! **The flaw.** Every agent on a server runs as one Unix account, and the
//! service has no peer check: who an agent is comes from what it says (an
//! environment variable naming a session, a socket message naming a
//! principal). So any process in the account can say it is any session.
//!
//! **The properties** (each test names the one it checks):
//! - P1. No signature as another agent session or agent name, by any claim:
//!   environment, arguments, socket messages, reused session ids.
//! - P2. No signature as another machine's domain, or as taylor, root, admin
//!   or the person's name, whatever the configs say.
//! - P3. An agent process can't read or change agent-sign's keys, config,
//!   trust store or authority history, and can't start a service whose
//!   authority any verifier trusts.
//! - P4. An agent process can't read another agent's environment, open file
//!   descriptors, memory or signing channel.
//! - P5. A signing request or approval captured from one agent can't be
//!   replayed for another agent, machine, working copy or later content.
//! - P6. Only the commitments approval key's approvals are accepted.
//! - P7. A process the trusted launcher didn't start gets no agent
//!   signature; at most one that verification labels "unattested".
//! - P8. Verification says how the caller's identity was established;
//!   today's self-asserted signatures are "claimed by a process in a shared
//!   account", never proven.
//!
//! **The interface these tests hold the fix to.** Only what a test needs is
//! fixed here; everything else is the fix's choice.
//! - `agent-sign launch --agent <slug> -- <program> [args...]`: the trusted
//!   launcher. It runs `<program>` in the current directory as a new agent
//!   session whose identity the launcher chooses (the slug it was given, a
//!   fresh session it makes, this machine's domain), never one the program
//!   or its environment names. The program's standard input, output and
//!   error and exit status are the launcher's; its environment is the
//!   launcher's, apart from anything that would claim an identity. Inside,
//!   `agent-git` (called by its full path) signs as that session, Good under
//!   `agent-sign trust-line`.
//! - `agent-sign verify <rev>`, in a repository: checks the commit's
//!   signature against git's `gpg.ssh.allowedSignersFile` and prints a line
//!   `attestation: <words>`. For a certificate that records no attestation
//!   (every one made before the fix) the words include "claimed by a process
//!   in a shared account"; for one the launcher didn't attest, "unattested";
//!   for one made on an approval, "approval".
//! - The approval path (the suite's model layer): agent-sign's own config
//!   names the commitments approval key, `[approvals] commitments_key =
//!   "<OpenSSH public key line>"`, and the service signs on a request
//!   `{"type": "SignApproved", "payload": {"approval", "approval_signature",
//!   "buffer_b64", "repo", "branch"}}`. `approval` is the JSON text below,
//!   `approval_signature` an armored SSHSIG over exactly that text, namespace
//!   [`APPROVAL_NAMESPACE`], by the commitments key. The approval names the
//!   principal, machine, working copy, branch, tree and parents, a nonce
//!   (single use) and an expiry; the service signs as that principal only
//!   when every one matches the request and the commit, and the commit's
//!   committer is that principal. (The field names are this test's; align
//!   them with the commitments approval format when it is written, as one
//!   change to this file.)
//! - Starting the service never changes what verifiers trust: trust is
//!   extended by an install step, not by whoever starts a service.
//!
//! **Before the launcher exists** (today), a "session" is started the way
//! agents start today: a plain process whose environment claims an identity
//! (Claude Code's marks, or `AGENT_SIGN_AGENT_NAME`). That only makes each
//! attack easier, never harder, so it can't make a test pass. Tests about
//! what the launcher itself does fail with "NO TRUSTED LAUNCHER" until it
//! exists. Approval tests start with a control (a valid approval is signed),
//! so a refusal can never be the path not existing.
//!
//! **What runs where.** Everything here runs as one account with no root
//! (Linux; the `/proc` and namespace tests are Linux-only). What needs more
//! than one account (agent-sign's own, the launcher's, a uid per session)
//! is in `test_caller_identity_sitting.rs`, every test marked
//! `#[ignore = "needs the server sitting: ..."]`, failing (never passing)
//! when the accounts aren't there.
//!
//! Isolation as in `test_machine_names.rs`: an empty environment plus a
//! temporary HOME (under `TMPDIR`), a temporary global git config, no system
//! config, a PATH without agent-sign's installed `bin`, a socket in the
//! temporary directory. No private key is ever written to a file: every key
//! here is made in memory from a fixed seed. Every wait is bounded, and
//! every process a test starts is stopped when it ends.

use std::cell::Cell;
use std::ffi::OsString;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;
use sha2::{Digest, Sha256, Sha512};
use ssh_key::certificate::{Builder, CertType};
use ssh_key::private::{Ed25519Keypair, PrivateKey};
use ssh_key::public::{Ed25519PublicKey, KeyData};
use tempfile::{TempDir, tempdir};

use agent_sign::crypto::openssh_ed25519_line;
use agent_sign::protocol::Response;

/// The machine every test service is named for.
const MACHINE: &str = "hetzner";
/// Its agents' domain.
const DOMAIN: &str = "hetzner.agents.local";
const PERSON_NAME: &str = "Human Developer";
const PERSON_EMAIL: &str = "dev@example.com";
/// Every program run gets at most this long.
const RUN_LIMIT: Duration = Duration::from_secs(30);
/// The SSHSIG namespace of a commit approval.
const APPROVAL_NAMESPACE: &str = "agent-sign-commit-approval";
const BLOCK_BEGIN: &str = "# agent-sign: agents' certificate authorities, managed; do not edit";
const BLOCK_END: &str = "# agent-sign: end of agents' certificate authorities";
/// What the launcher probe prints when `agent-sign launch` ran its program.
const LAUNCH_PROBE: &str = "caller-identity-launch-probe";
/// In every attacker program's command line, so a search for a victim's
/// marker never finds the attacker itself.
const ATTACKER_TAG: &str = "caller-identity-attacker";

/// The seeds of the in-memory keys.
const PERSON_SEED: [u8; 32] = [3; 32];
const APPROVAL_SEED: [u8; 32] = [21; 32];
const OTHER_SEED: [u8; 32] = [22; 32];
const LEGACY_CA_SEED: [u8; 32] = [11; 32];
const LEGACY_SUBJECT_SEED: [u8; 32] = [12; 32];

// ---------------------------------------------------------------------------
// Identities and keys, computed here, independently of agent-sign.
// ---------------------------------------------------------------------------

fn session8(session: &str) -> String {
    Sha256::digest(session.as_bytes())[..4]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn principal_for(slug: &str, session: &str) -> String {
    format!("{slug}.{}@{DOMAIN}", session8(session))
}

fn fresh() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn machine_config() -> String {
    format!("[identity]\nmachine = \"{MACHINE}\"\n")
}

fn key(seed: [u8; 32]) -> SigningKey {
    SigningKey::from_bytes(&seed)
}

fn pub_line(k: &SigningKey) -> String {
    openssh_ed25519_line(&k.verifying_key())
}

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

/// An armored SSHSIG (OpenSSH `PROTOCOL.sshsig`, sha512) over `data` in
/// `namespace`, by `k`, carrying `public_blob` as its public key. Written
/// here so the tests don't trust agent-sign's own signing code.
fn sshsig(public_blob: &[u8], k: &SigningKey, namespace: &str, data: &[u8]) -> String {
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
    put_string(&mut raw, public_blob);
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

/// A certificate exactly as agent-sign issued them before the fix (key id
/// "<principal> on <host>", no critical options, no extensions), for
/// `subject`, from the authority with `ca_seed`. Built here with ssh-key, so
/// it stays the old format whatever the fix changes.
fn legacy_cert(ca_seed: [u8; 32], principal: &str, subject: &SigningKey) -> Vec<u8> {
    let now = now_secs();
    let data = KeyData::Ed25519(Ed25519PublicKey(subject.verifying_key().to_bytes()));
    let mut b = Builder::new(vec![9u8; 32], data, now - 300, now + 3600).unwrap();
    b.serial(1)
        .unwrap()
        .key_id(format!("{principal} on legacy-host"))
        .unwrap()
        .cert_type(CertType::User)
        .unwrap()
        .valid_principal(principal)
        .unwrap();
    let ca = PrivateKey::from(Ed25519Keypair::from_seed(&ca_seed));
    b.sign(&ca).unwrap().to_bytes().unwrap()
}

// ---------------------------------------------------------------------------
// The isolated world.
// ---------------------------------------------------------------------------

struct World {
    _dir: TempDir,
    home: PathBuf,
    global_config: PathBuf,
    path: OsString,
    real_git: PathBuf,
    ssh_keygen: PathBuf,
    socket: PathBuf,
    service: Option<Child>,
    /// Whether `agent-sign launch` works, once probed.
    launcher: Cell<Option<bool>>,
}

impl Drop for World {
    fn drop(&mut self) {
        self.stop_service();
    }
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

fn text(out: &Output) -> String {
    format!(
        "status: {}\nstdout: {}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// Runs `cmd`, killing it and failing the test after [`RUN_LIMIT`].
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

fn wait_for_file(path: &Path, limit: Duration) -> bool {
    let start = Instant::now();
    while !path.exists() {
        if start.elapsed() > limit {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    true
}

impl World {
    fn new(config: &str) -> World {
        let dir = tempdir().unwrap();
        let home = dir.path().to_path_buf();
        let path = cleaned_path();
        let world = World {
            global_config: home.join("person.gitconfig"),
            socket: home.join("agent-sign-test.sock"),
            real_git: find_on(&path, "git"),
            ssh_keygen: find_on(&path, "ssh-keygen"),
            home,
            path,
            service: None,
            launcher: Cell::new(None),
            _dir: dir,
        };
        world.write_person_setup(config);
        world
    }

    /// The environment every program here starts from.
    fn base_env(&self) -> Vec<(String, OsString)> {
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
            // DELIBERATE EVAL CHANGE (1 Nov 2026): environment only; host clock zones must not change results.
            ("TZ".into(), "UTC".into()),
            ("GIT_CONFIG_GLOBAL".into(), s(&self.global_config)),
            ("GIT_CONFIG_NOSYSTEM".into(), "1".into()),
            ("GIT_EDITOR".into(), "true".into()),
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

    fn cmd(&self, program: &Path) -> Command {
        let mut cmd = Command::new(program);
        cmd.env_clear().envs(self.base_env()).stdin(Stdio::null());
        cmd
    }

    fn config_path(&self) -> PathBuf {
        self.home.join(".agent-sign/config.toml")
    }

    /// The person's public key (from an in-memory key), the fake signer, the
    /// person's global git config, and agent-sign's config.toml.
    fn write_person_setup(&self, config: &str) {
        let person_pub = self.home.join("person_key.pub");
        fs::write(
            &person_pub,
            format!("{} person\n", pub_line(&key(PERSON_SEED))),
        )
        .unwrap();
        let fake = self.home.join("person-signer.sh");
        fs::write(&fake, "#!/bin/sh\nexit 1\n").unwrap();
        fs::set_permissions(&fake, fs::Permissions::from_mode(0o755)).unwrap();
        fs::create_dir_all(self.home.join(".agent-sign")).unwrap();
        fs::write(self.config_path(), config).unwrap();
        fs::write(
            &self.global_config,
            format!(
                "[user]\n\tname = {PERSON_NAME}\n\temail = {PERSON_EMAIL}\n\tsigningkey = \"{}\"\n\
                 [commit]\n\tgpgsign = true\n[gpg]\n\tformat = ssh\n[gpg \"ssh\"]\n\tprogram = \"{}\"\n",
                person_pub.display(),
                fake.display()
            ),
        )
        .unwrap();
    }

    /// Makes git name a new allowed-signers file holding only agent-sign's
    /// empty managed block, so a service keeps its block there.
    fn managed_allowed_signers(&self) -> PathBuf {
        let file = self.home.join("allowed_signers");
        fs::write(&file, format!("{BLOCK_BEGIN}\n{BLOCK_END}\n")).unwrap();
        self.name_allowed_signers_file(&file);
        file
    }

    fn name_allowed_signers_file(&self, file: &Path) {
        let mut config = fs::read_to_string(&self.global_config).unwrap();
        config.push_str(&format!(
            "[gpg \"ssh\"]\n\tallowedSignersFile = \"{}\"\n",
            file.display()
        ));
        fs::write(&self.global_config, config).unwrap();
    }

    fn service_log(&self) -> String {
        fs::read_to_string(self.home.join("service.log")).unwrap_or_default()
    }

    fn service_command(&self, socket: &Path, log: &str) -> Command {
        let log = fs::File::create(self.home.join(log)).unwrap();
        let mut cmd = self.cmd(Path::new(env!("CARGO_BIN_EXE_agent-signd")));
        cmd.arg("--socket")
            .arg(socket)
            .arg("--auto-approve")
            .env("AGENT_SIGN_TEST_AUTH", "fail")
            .env("AGENT_SIGN_REFUSAL_BACKOFF", "none")
            .stdout(Stdio::null())
            .stderr(Stdio::from(log));
        cmd
    }

    /// Starts a service on `socket` and waits for it: `Ok(child)`, or
    /// `Err(log)` when it stopped at start.
    fn spawn_service(&self, socket: &Path, log: &str) -> Result<Child, String> {
        let mut child = self.service_command(socket, log).spawn().unwrap();
        let start = Instant::now();
        while !socket.exists() {
            if let Some(status) = child.try_wait().unwrap() {
                let log = fs::read_to_string(self.home.join(log)).unwrap_or_default();
                return Err(format!("stopped at start ({status}); its log:\n{log}"));
            }
            if start.elapsed() > Duration::from_secs(10) {
                let _ = child.kill();
                let _ = child.wait();
                return Err("didn't open its socket within 10 s".into());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        Ok(child)
    }

    fn start_service(&mut self) {
        self.try_start_service()
            .unwrap_or_else(|e| panic!("the test service {e}"));
    }

    fn try_start_service(&mut self) -> Result<(), String> {
        let socket = self.socket.clone();
        let child = self.spawn_service(&socket, "service.log")?;
        self.service = Some(child);
        Ok(())
    }

    fn stop_service(&mut self) {
        if let Some(mut child) = self.service.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    fn git(&self, repo: &Path, args: &[&str]) -> Output {
        self.cmd(&self.real_git)
            .args(args)
            .current_dir(repo)
            .output()
            .unwrap()
    }

    fn git_ok(&self, repo: &Path, args: &[&str]) -> String {
        let out = self.git(repo, args);
        assert!(out.status.success(), "setup git {args:?}: {}", text(&out));
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    fn git_stdin(&self, repo: &Path, args: &[&str], input: &[u8]) -> String {
        let mut child = self
            .cmd(&self.real_git)
            .args(args)
            .current_dir(repo)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(input).unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success(), "setup git {args:?}: {}", text(&out));
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    fn commit(&self, repo: &Path, file: &str) {
        fs::write(repo.join(file), format!("{file}\n")).unwrap();
        self.git_ok(repo, &["add", file]);
        self.git_ok(
            repo,
            &["-c", "commit.gpgsign=false", "commit", "-q", "-m", file],
        );
    }

    /// A repository called `name` with two unsigned commits, on branch `work`.
    fn repo_named(&self, name: &str) -> PathBuf {
        let repo = self.home.join(name);
        fs::create_dir_all(&repo).unwrap();
        self.git_ok(&repo, &["init", "-q", "-b", "work"]);
        self.commit(&repo, "base.txt");
        self.commit(&repo, "w1.txt");
        repo
    }

    fn repo(&self) -> PathBuf {
        self.repo_named("repo")
    }

    fn stage(&self, repo: &Path, path: &str, content: &str) {
        fs::write(repo.join(path), content).unwrap();
        self.git_ok(repo, &["add", path]);
    }

    fn rev(&self, repo: &Path, rev: &str) -> String {
        self.git_ok(repo, &["rev-parse", rev])
    }

    fn canonical(&self, repo: &Path) -> String {
        fs::canonicalize(repo)
            .unwrap()
            .to_string_lossy()
            .into_owned()
    }

    /// A tree: `base`'s tree plus `file` with `content`, written with a
    /// throwaway index so the repository's own index is never touched (a
    /// commit in progress holds it).
    fn tree_with(&self, repo: &Path, base: &str, file: &str, content: &str) -> String {
        let index = self.home.join(format!("index-{}", fresh()));
        let blob = self.git_stdin(repo, &["hash-object", "-w", "--stdin"], content.as_bytes());
        let with_index = |args: &[&str]| {
            let out = self
                .cmd(&self.real_git)
                .env("GIT_INDEX_FILE", &index)
                .args(args)
                .current_dir(repo)
                .output()
                .unwrap();
            assert!(out.status.success(), "setup git {args:?}: {}", text(&out));
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        with_index(&["read-tree", base]);
        with_index(&[
            "update-index",
            "--add",
            "--cacheinfo",
            &format!("100644,{blob},{file}"),
        ]);
        let tree = with_index(&["write-tree"]);
        let _ = fs::remove_file(&index);
        tree
    }

    /// A commit object storing `buffer` with `signature` as its `gpgsig`.
    fn write_signed_commit(&self, repo: &Path, buffer: &[u8], signature: &str) -> String {
        let text = std::str::from_utf8(buffer).unwrap();
        let (headers, message) = text.split_once("\n\n").unwrap();
        let lines: Vec<&str> = signature.trim_end().lines().collect();
        let object = format!("{headers}\ngpgsig {}\n\n{message}", lines.join("\n "));
        self.git_stdin(
            repo,
            &["hash-object", "-t", "commit", "-w", "--stdin"],
            object.as_bytes(),
        )
    }

    // -- Trust, as a verifier on this machine sees it --------------------

    /// What a verifier here trusts: the lines `agent-sign trust-line`
    /// prints, plus the allowed-signers file git names, if any.
    fn trust(&self) -> String {
        let out = self
            .cmd(Path::new(env!("CARGO_BIN_EXE_agent-sign")))
            .arg("trust-line")
            .output()
            .unwrap();
        let mut all = if out.status.success() {
            String::from_utf8_lossy(&out.stdout).into_owned()
        } else {
            String::new()
        };
        let named = self.git(
            &self.home,
            &["config", "--global", "gpg.ssh.allowedSignersFile"],
        );
        let named = String::from_utf8_lossy(&named.stdout).trim().to_string();
        if !named.is_empty() {
            all.push_str(&fs::read_to_string(&named).unwrap_or_default());
        }
        all
    }

    fn trust_file(&self) -> PathBuf {
        let file = self
            .home
            .join(format!("verify_allowed_signers-{}", fresh()));
        fs::write(&file, self.trust()).unwrap();
        file
    }

    /// `(%G?, %GS)` of `rev`, checked by plain ssh-keygen against [`World::trust`].
    fn signature_of(&self, repo: &Path, rev: &str) -> (String, String) {
        let file = self.trust_file();
        let program = format!("gpg.ssh.program={}", self.ssh_keygen.display());
        let setting = format!("gpg.ssh.allowedSignersFile={}", file.display());
        let out = self.git(
            repo,
            &[
                "-c",
                &program,
                "-c",
                &setting,
                "log",
                "-1",
                "--format=%G?%x1f%GS",
                rev,
            ],
        );
        let fmt = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let (g, s) = fmt.split_once('\x1f').unwrap_or((fmt.as_str(), ""));
        (g.to_string(), s.to_string())
    }

    /// Whether `sig` over `data` is Good for `principal` under [`World::trust`].
    fn good_as(&self, principal: &str, sig: &str, data: &[u8]) -> bool {
        let allowed = self.trust_file();
        let sig_file = self.home.join(format!("check-{}.sig", fresh()));
        fs::write(&sig_file, sig).unwrap();
        let mut child = Command::new(&self.ssh_keygen)
            .args(["-Y", "verify", "-n", "git", "-I", principal, "-f"])
            .arg(&allowed)
            .arg("-s")
            .arg(&sig_file)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(data).unwrap();
        child.wait_with_output().unwrap().status.success()
    }

    /// `agent-sign verify <rev>` in `repo`, with git's allowed-signers file
    /// set to what this machine trusts ([`World::trust`]): its output and
    /// errors together.
    fn verify_text(&self, repo: &Path, rev: &str) -> String {
        let trust = self.trust_file();
        let mut cmd = self.cmd(Path::new(env!("CARGO_BIN_EXE_agent-sign")));
        // The trust file is named to the verifier itself (`--allowed-signers`, what a
        // gate passes), not through GIT_CONFIG_* variables, which `verify` no longer
        // reads: a trust file the environment or the repository names is the
        // session's to choose (second whole-branch review, F2).
        cmd.args(["verify", "--allowed-signers"])
            .arg(&trust)
            .arg(rev)
            .current_dir(repo);
        let out = run_within(cmd, "agent-sign verify");
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    }

    // -- Sessions ---------------------------------------------------------

    /// Whether `agent-sign launch` exists and runs its program.
    fn has_launcher(&self) -> bool {
        if let Some(known) = self.launcher.get() {
            return known;
        }
        let mut cmd = self.cmd(Path::new(env!("CARGO_BIN_EXE_agent-sign")));
        cmd.args(["launch", "--agent", "claude-code", "--", "/bin/sh", "-c"])
            .arg(format!("echo {LAUNCH_PROBE}"))
            .current_dir(&self.home);
        let out = run_within(cmd, "the launcher probe");
        let works =
            out.status.success() && String::from_utf8_lossy(&out.stdout).contains(LAUNCH_PROBE);
        self.launcher.set(Some(works));
        works
    }

    fn require_launcher(&self, property: &str) {
        assert!(
            self.has_launcher(),
            "{property}: NO TRUSTED LAUNCHER. `agent-sign launch --agent <slug> -- <program>` \
             doesn't exist yet, so nothing starts an agent session with an identity the \
             service checks for itself; every identity is whatever the process says"
        );
    }

    /// A command that runs `program args` as a new session of `slug` in
    /// `dir`: through the launcher when it exists, otherwise the way agents
    /// run today, a plain process whose environment claims the identity.
    /// `claims` is extra environment the session's caller sets; today it
    /// overrides the identity, and the launcher must ignore it for that.
    fn session_command(
        &self,
        dir: &Path,
        slug: &str,
        claims: &[(&str, &str)],
        program: &Path,
        args: &[&str],
    ) -> Command {
        let mut cmd;
        if self.has_launcher() {
            cmd = self.cmd(Path::new(env!("CARGO_BIN_EXE_agent-sign")));
            cmd.args(["launch", "--agent", slug, "--"])
                .arg(program)
                .args(args);
        } else {
            cmd = self.cmd(program);
            cmd.args(args);
            let session = fresh();
            if slug == "claude-code" {
                cmd.env("CLAUDECODE", "1")
                    .env("CLAUDE_CODE_SESSION_ID", &session);
            } else {
                cmd.env("AGENT_SIGN_AGENT_NAME", slug)
                    .env("AGENT_SIGN_SESSION_ID", &session);
            }
        }
        for (k, v) in claims {
            cmd.env(k, v);
        }
        cmd.current_dir(dir);
        cmd
    }

    /// Runs one session to its end.
    fn run_session(
        &self,
        dir: &Path,
        slug: &str,
        claims: &[(&str, &str)],
        program: &Path,
        args: &[&str],
    ) -> Output {
        run_within(
            self.session_command(dir, slug, claims, program, args),
            &format!("session {slug} running {program:?} {args:?}"),
        )
    }

    /// One agent commit of the staged changes in `repo`, made by a new
    /// session of `slug`.
    fn session_commit(&self, repo: &Path, slug: &str, claims: &[(&str, &str)]) -> Output {
        self.run_session(
            repo,
            slug,
            claims,
            Path::new(env!("CARGO_BIN_EXE_agent-git")),
            &["commit", "-q", "-m", "session commit"],
        )
    }

    /// The wrapper run directly by a plain process with `marks`: no
    /// launcher, ever.
    fn plain_agent(&self, repo: &Path, marks: &[(&str, &str)], args: &[&str]) -> Output {
        let mut cmd = self.cmd(Path::new(env!("CARGO_BIN_EXE_agent-git")));
        for (k, v) in marks {
            cmd.env(k, v);
        }
        cmd.args(args).current_dir(repo);
        run_within(cmd, &format!("plain agent git {args:?}"))
    }
}

/// A commit object without a signature, dated now.
fn commit_buffer(
    tree: &str,
    parents: &[&str],
    author: &str,
    committer: &str,
    msg: &str,
) -> Vec<u8> {
    let now = now_secs();
    let parents: String = parents.iter().map(|p| format!("parent {p}\n")).collect();
    format!("tree {tree}\n{parents}author {author} {now} +0000\ncommitter {committer} {now} +0000\n\n{msg}\n")
        .into_bytes()
}

fn agent_ident(principal: &str) -> String {
    let slug = principal.split('.').next().unwrap_or("agent");
    let name = if slug == "claude-code" {
        "Claude Code"
    } else {
        slug
    };
    format!("{name} <{principal}>")
}

// ---------------------------------------------------------------------------
// The service's socket, spoken to directly, as any process in the account can.
// ---------------------------------------------------------------------------

fn ask_at(socket: &Path, request: serde_json::Value) -> Option<Response> {
    let mut stream = UnixStream::connect(socket).ok()?;
    stream.set_read_timeout(Some(RUN_LIMIT)).ok()?;
    writeln!(stream, "{request}").ok()?;
    let mut line = String::new();
    BufReader::new(&stream).read_line(&mut line).ok()?;
    serde_json::from_str(&line).ok()
}

fn identity_json(principal: &str) -> serde_json::Value {
    let slug = principal.split('.').next().unwrap_or("agent");
    let name = if slug == "claude-code" {
        "Claude Code"
    } else {
        slug
    };
    json!({"slug": slug, "name": name, "principal": principal})
}

fn token_request(
    socket: &Path,
    kind: &str,
    repo: &str,
    branch: &str,
    principal: &str,
) -> Option<Response> {
    ask_at(
        socket,
        json!({"type": kind, "payload": {"repo": repo, "branch": branch, "identity": identity_json(principal)}}),
    )
}

fn sign_with_token(
    socket: &Path,
    token: &str,
    buffer: &[u8],
    repo: &str,
    branch: &str,
) -> Option<String> {
    let b64 = base64::engine::general_purpose::STANDARD.encode(buffer);
    match ask_at(
        socket,
        json!({"type": "SignCommit", "payload": {"token": token, "buffer_b64": b64, "repo": repo, "branch": branch}}),
    ) {
        Some(Response::Signed { signature_pem }) => Some(signature_pem),
        _ => None,
    }
}

/// Every signature a process gets by asking `socket`, in its own words, to
/// sign `buffer` as `principal`: a lease, then each kind of token, then the
/// signature.
fn signatures_claiming(
    socket: &Path,
    repo: &str,
    branch: &str,
    principal: &str,
    buffer: &[u8],
) -> Vec<String> {
    let _ = ask_at(
        socket,
        json!({"type": "RequestLease", "payload": {"repo": repo, "branch": branch, "intent": "caller-identity test", "duration_secs": null}}),
    );
    let mut sigs = Vec::new();
    for kind in ["IssueIdentifiedToken", "IssueRunToken"] {
        if let Some(Response::TokenIssued { token }) =
            token_request(socket, kind, repo, branch, principal)
            && let Some(sig) = sign_with_token(socket, &token, buffer, repo, branch)
        {
            sigs.push(sig);
        }
    }
    sigs
}

// ---------------------------------------------------------------------------
// /proc, as any process of the account sees it (Linux).
// ---------------------------------------------------------------------------

/// The processes whose command line holds `marker`, other than attackers.
fn pids_with(marker: &str) -> Vec<u32> {
    let me = std::process::id();
    let mut pids = Vec::new();
    for entry in fs::read_dir("/proc").into_iter().flatten().flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        if pid == me {
            continue;
        }
        let Ok(cmdline) = fs::read(entry.path().join("cmdline")) else {
            continue;
        };
        let cmdline = String::from_utf8_lossy(&cmdline);
        if cmdline.contains(marker) && !cmdline.contains(ATTACKER_TAG) {
            pids.push(pid);
        }
    }
    pids
}

fn environ_of(pid: u32) -> Vec<(String, String)> {
    fs::read(format!("/proc/{pid}/environ"))
        .map(|raw| {
            raw.split(|b| *b == 0)
                .filter_map(|kv| {
                    let kv = String::from_utf8_lossy(kv);
                    kv.split_once('=')
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// A session that commits its staged changes, then stays alive until the
/// test ends (at most a minute), so its process can be looked at.
struct LiveSession {
    child: Child,
    stop: PathBuf,
    marker: String,
}

impl Drop for LiveSession {
    fn drop(&mut self) {
        let _ = fs::write(&self.stop, "");
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(3) {
            if let Ok(Some(_)) = self.child.try_wait() {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

const LIVE_SCRIPT: &str = r#"cd "$1" && "$2" commit -q -m live-session && : > "$3"; i=0; while [ $i -lt 600 ] && [ ! -e "$4" ]; do sleep 0.1; i=$((i+1)); done"#;

impl World {
    /// Starts a [`LiveSession`] of `slug` committing the staged changes in
    /// `repo`, and waits for its commit.
    fn live_session(&self, repo: &Path, slug: &str) -> LiveSession {
        let marker = format!("caller-identity-victim-{}", fresh());
        // DELIBERATE EVAL CHANGE (D4, 1 Nov 2026): the ready and stop files
        // were in HOME. Under D4 a launched session can write only its own
        // working copy and a private tmp, so they are in `repo` now, as
        // tests/test_launcher_policy.rs has them. No assertion changed.
        let done = repo.join(format!(".{marker}.done"));
        let stop = repo.join(format!(".{marker}.stop"));
        let repo_s = repo.to_string_lossy().into_owned();
        let done_s = done.to_string_lossy().into_owned();
        let stop_s = stop.to_string_lossy().into_owned();
        let log = self.home.join(format!("{marker}.log"));
        let mut cmd = self.session_command(
            repo,
            slug,
            &[],
            Path::new("/bin/sh"),
            &[
                "-c",
                LIVE_SCRIPT,
                &marker,
                &repo_s,
                env!("CARGO_BIN_EXE_agent-git"),
                &done_s,
                &stop_s,
            ],
        );
        let file = fs::File::create(&log).unwrap();
        cmd.stdout(Stdio::from(file.try_clone().unwrap()))
            .stderr(Stdio::from(file));
        let child = cmd.spawn().unwrap();
        let mut session = LiveSession {
            child,
            stop,
            marker,
        };
        if !wait_for_file(&done, RUN_LIMIT) {
            let _ = session.child.try_wait();
            panic!(
                "CONTROL: the {slug} session's own commit didn't finish; its output:\n{}\nservice log:\n{}",
                fs::read_to_string(&log).unwrap_or_default(),
                self.service_log()
            );
        }
        session
    }

    /// The principal a session's last commit in `repo` is Good for.
    fn session_principal(&self, repo: &Path) -> String {
        let (g, principal) = self.signature_of(repo, "HEAD");
        assert_eq!(
            g,
            "G",
            "CONTROL: the session's own commit isn't Good under this machine's trust ({principal:?});\nservice log:\n{}",
            self.service_log()
        );
        principal
    }
}

// ---------------------------------------------------------------------------
// The approval path.
// ---------------------------------------------------------------------------

/// What one commit approval names.
#[derive(Clone)]
struct Ask {
    principal: String,
    machine: String,
    repo: String,
    branch: String,
    tree: String,
    parents: Vec<String>,
    nonce: String,
    expires_at: u64,
    // DELIBERATE EVAL CHANGE (D3, 31 Oct 2026): approvals bind the whole commit.
    // The lowercase hex SHA-256 of the exact unsigned commit buffer the
    // approval is for (the buffer `fresh_ask` returns beside it).
    commit_sha256: String,
}

impl Ask {
    fn text(&self) -> String {
        json!({
            "kind": "commit",
            "principal": self.principal,
            "machine": self.machine,
            "repo": self.repo,
            "branch": self.branch,
            "tree": self.tree,
            "parents": self.parents,
            "nonce": self.nonce,
            "expires_at": self.expires_at,
            // DELIBERATE EVAL CHANGE (D3, 31 Oct 2026): approvals bind the whole commit.
            "commit_sha256": self.commit_sha256,
        })
        .to_string()
    }

    /// The approval text, signed by the commitments approval key.
    fn signed(&self) -> (String, String) {
        let text = self.text();
        let k = key(APPROVAL_SEED);
        let sig = sshsig(&plain_key_blob(&k), &k, APPROVAL_NAMESPACE, text.as_bytes());
        (text, sig)
    }
}

/// A world whose agent-sign config names the commitments approval key, its
/// service started; fails as a CONTROL when the service refuses the setting.
fn approval_world() -> World {
    let config = format!(
        "{}\n[approvals]\ncommitments_key = \"{}\"\n",
        machine_config(),
        pub_line(&key(APPROVAL_SEED))
    );
    let mut w = World::new(&config);
    if let Err(e) = w.try_start_service() {
        panic!(
            "CONTROL: the service doesn't accept `[approvals] commitments_key`, so the approval \
             path doesn't exist yet and no refusal can be told apart from it. The service {e}"
        );
    }
    w
}

fn present(
    w: &World,
    approval: &str,
    signature: &str,
    buffer: &[u8],
    repo: &str,
    branch: &str,
) -> Option<Response> {
    let b64 = base64::engine::general_purpose::STANDARD.encode(buffer);
    ask_at(
        &w.socket,
        json!({"type": "SignApproved", "payload": {
            "approval": approval, "approval_signature": signature,
            "buffer_b64": b64, "repo": repo, "branch": branch}}),
    )
}

/// The lowercase hex SHA-256 an approval's commit_sha256 names (D3).
fn sha_hex(buffer: &[u8]) -> String {
    Sha256::digest(buffer)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A fresh approval for a new commit in `repo` adding `file`, and its buffer.
fn fresh_ask(w: &World, repo: &Path, file: &str) -> (Ask, Vec<u8>) {
    let parent = w.rev(repo, "HEAD");
    let tree = w.tree_with(repo, "HEAD", file, &format!("{file} {}\n", fresh()));
    let principal = principal_for("claude-code", "approved-run");
    let ident = agent_ident(&principal);
    let buffer = commit_buffer(
        &tree,
        &[&parent],
        &ident,
        &ident,
        &format!("approved: {file}"),
    );
    let ask = Ask {
        principal: principal.clone(),
        machine: MACHINE.into(),
        repo: w.canonical(repo),
        branch: "work".into(),
        tree: tree.clone(),
        parents: vec![parent.clone()],
        nonce: fresh(),
        expires_at: now_secs() + 600,
        // DELIBERATE EVAL CHANGE (D3, 31 Oct 2026): approvals bind the whole commit.
        commit_sha256: Sha256::digest(&buffer)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
    };
    (ask, buffer)
}

/// The control every approval test starts with: a valid approval from the
/// commitments key gets a signature Good for its principal.
fn approval_control(w: &World, repo: &Path) {
    let (ask, buffer) = fresh_ask(w, repo, "control.txt");
    let (text, sig) = ask.signed();
    let answer = present(w, &text, &sig, &buffer, &ask.repo, &ask.branch);
    let Some(Response::Signed { signature_pem }) = answer else {
        panic!(
            "CONTROL: a valid approval from the commitments key wasn't signed ({answer:?}): the \
             approval path (`SignApproved`) doesn't exist yet, so no refusal can be told apart \
             from it.\nservice log:\n{}",
            w.service_log()
        );
    };
    assert!(
        w.good_as(&ask.principal, &signature_pem, &buffer),
        "CONTROL: an approved commit's signature isn't Good for {} under this machine's trust",
        ask.principal
    );
}

fn refused(answer: &Option<Response>) -> bool {
    !matches!(answer, Some(Response::Signed { .. }))
}

// ===========================================================================
// P1. No signature as another session or agent name, by any claim.
// ===========================================================================

/// P1, environment claims. A live session commits; another process of the
/// account copies the session's whole environment from
/// `/proc/<pid>/environ` (readable by the same account today) and commits in
/// its own repository with exactly that environment. It must not get a
/// signature Good as the session. Fails today: the identity is the
/// environment, so the copy signs as the session.
#[cfg(target_os = "linux")]
#[test]
fn p1_a_process_with_a_copy_of_a_sessions_environment_cant_sign_as_it() {
    let mut w = World::new(&machine_config());
    w.start_service();
    let victim_repo = w.repo_named("victim");
    w.stage(&victim_repo, "v.txt", "victim\n");
    let session = w.live_session(&victim_repo, "claude-code");
    let victim = w.session_principal(&victim_repo);

    let mut copied: Vec<(String, String)> = Vec::new();
    for pid in pids_with(&session.marker) {
        copied.extend(environ_of(pid));
    }
    let attacker_repo = w.repo_named("attacker");
    w.stage(&attacker_repo, "a.txt", "attacker\n");
    let mut cmd = w.cmd(Path::new(env!("CARGO_BIN_EXE_agent-git")));
    cmd.envs(copied.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .args(["commit", "-q", "-m", "copied environment"])
        .current_dir(&attacker_repo);
    let _ = run_within(cmd, "agent git with a copied environment");
    let (g, signer) = w.signature_of(&attacker_repo, "HEAD");
    assert!(
        !(g == "G" && signer == victim),
        "P1: a process that copied session {victim}'s environment ({} variables from /proc) got a \
         Good signature as that session",
        copied.len()
    );
}

/// P1, socket messages. A live session commits; another process of the
/// account asks the service directly, on every socket it can find, for a
/// token for the session's principal, and signs its own commit with it. It
/// must get no signature Good as the session. Fails today: the service
/// believes the principal in the message.
#[test]
fn p1_a_socket_message_naming_a_session_gets_no_signature_as_it() {
    let mut w = World::new(&machine_config());
    w.start_service();
    let victim_repo = w.repo_named("victim");
    w.stage(&victim_repo, "v.txt", "victim\n");
    w.session_commit(&victim_repo, "claude-code", &[]);
    let victim = w.session_principal(&victim_repo);

    let attacker_repo = w.repo_named("attacker");
    let repo = w.canonical(&attacker_repo);
    let head = w.rev(&attacker_repo, "HEAD");
    let tree = w.tree_with(&attacker_repo, "HEAD", "a.txt", "attacker\n");
    let ident = agent_ident(&victim);
    let buffer = commit_buffer(&tree, &[&head], &ident, &ident, "claimed by message");
    let mut sockets = vec![w.socket.clone()];
    for entry in fs::read_dir(w.home.join(".agent-sign"))
        .into_iter()
        .flatten()
        .flatten()
    {
        if entry.file_type().is_ok_and(|t| !t.is_dir() && !t.is_file()) {
            sockets.push(entry.path());
        }
    }
    let mut good = 0;
    for socket in &sockets {
        for sig in signatures_claiming(socket, &repo, "work", &victim, &buffer) {
            if w.good_as(&victim, &sig, &buffer) {
                good += 1;
            }
        }
    }
    assert!(
        good == 0,
        "P1: a process that named session {victim} in socket messages got {good} signature(s) Good as it"
    );
}

/// P1, a session renaming itself. Inside one session, a commit made with
/// every identity variable set to another agent and session
/// (`AGENT_SIGN_AGENT_NAME=Codex`, `AGENT_SIGN_SESSION_ID`,
/// `CODEX_SESSION_ID`, `CLAUDE_CODE_SESSION_ID`) is still signed as the
/// session itself, or not at all. Fails today: the variables are the
/// identity.
#[test]
fn p1_identity_variables_set_inside_a_session_dont_change_who_signs() {
    let mut w = World::new(&machine_config());
    w.start_service();
    let repo = w.repo();
    let script = r#"cd "$1" && echo one > one.txt && "$2" add one.txt && "$2" commit -q -m one && echo two > two.txt && "$2" add two.txt && AGENT_SIGN_AGENT_NAME=Codex AGENT_SIGN_SESSION_ID=other-session CODEX_SESSION_ID=other-session CLAUDE_CODE_SESSION_ID=other-session "$2" commit -q -m two"#;
    let repo_s = repo.to_string_lossy().into_owned();
    let out = w.run_session(
        &repo,
        "claude-code",
        &[],
        Path::new("/bin/sh"),
        &["-c", script, "sh", &repo_s, env!("CARGO_BIN_EXE_agent-git")],
    );
    let (g1, own) = w.signature_of(&repo, "HEAD~1");
    assert_eq!(
        g1,
        "G",
        "CONTROL: the session's first commit isn't Good ({own:?}):\n{}\nservice log:\n{}",
        text(&out),
        w.service_log()
    );
    let (g2, renamed) = w.signature_of(&repo, "HEAD");
    assert!(
        !(g2 == "G" && renamed != own),
        "P1: a session signing as {own} set identity variables and its next commit was Good as {renamed}"
    );
}

/// P1, reused session ids. A session commits and ends. Afterwards, a plain
/// process with the ended session's whole environment, and a new session
/// started with that environment as its caller's, each commit: neither is
/// Good as the ended session. Fails today: the same session id makes the
/// same principal.
#[test]
fn p1_an_ended_sessions_id_is_never_signed_again() {
    let mut w = World::new(&machine_config());
    w.start_service();
    let first = w.repo_named("first");
    // DELIBERATE EVAL CHANGE (D4, 1 Nov 2026): a launched session can write only its own
    // working copy and tmp, so a dump in HOME stayed empty and the replay checks ran with no
    // environment at all. Dump into the first session's working copy instead.
    let dump = first.join(".first-session.env");
    let dump_s = dump.to_string_lossy().into_owned();
    let first_s = first.to_string_lossy().into_owned();
    let script =
        r#"cd "$1" && echo f > f.txt && "$2" add f.txt && "$2" commit -q -m first && env > "$3""#;
    let out = w.run_session(
        &first,
        "claude-code",
        &[],
        Path::new("/bin/sh"),
        &[
            "-c",
            script,
            "sh",
            &first_s,
            env!("CARGO_BIN_EXE_agent-git"),
            &dump_s,
        ],
    );
    let (g, ended) = w.signature_of(&first, "HEAD");
    assert_eq!(
        g,
        "G",
        "CONTROL: the first session's commit isn't Good:\n{}",
        text(&out)
    );
    let env: Vec<(String, String)> = fs::read_to_string(&dump)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            l.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
        })
        .collect();

    // A plain process with the ended session's environment.
    let plain = w.repo_named("plain");
    w.stage(&plain, "p.txt", "plain\n");
    let mut cmd = w.cmd(Path::new(env!("CARGO_BIN_EXE_agent-git")));
    cmd.envs(env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .args(["commit", "-q", "-m", "reused environment"])
        .current_dir(&plain);
    let _ = run_within(cmd, "agent git with an ended session's environment");
    let (g, signer) = w.signature_of(&plain, "HEAD");
    assert!(
        !(g == "G" && signer == ended),
        "P1: after session {ended} ended, a process with its environment got a Good signature as it"
    );

    // A new session whose caller hands it the ended session's environment.
    let second = w.repo_named("second");
    w.stage(&second, "s.txt", "second\n");
    let claims: Vec<(&str, &str)> = env
        .iter()
        .filter(|(k, _)| k.contains("SESSION") || k.contains("AGENT") || k == "CLAUDECODE")
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    w.session_commit(&second, "claude-code", &claims);
    let (g, signer) = w.signature_of(&second, "HEAD");
    assert!(
        !(g == "G" && signer == ended),
        "P1: a new session started with ended session {ended}'s identity variables was Good as it"
    );
}

// ===========================================================================
// P2. No other machine's domain, no reserved or human names.
// ===========================================================================

/// P2, reserved names. Even when agent-sign's config lists them as allowed
/// agents, taylor, root, admin and administrator are never certified:
/// neither a token request naming one, nor a session started as one, gets
/// one signed. (The service may instead refuse to start on such a config.)
/// The person's own name, from `[human]` or git's `user.name` and
/// `user.email`, is refused already (the service won't start with it
/// listed: `test_allowed_agents.rs`), so it isn't listed here, where it
/// would stop the service before the other names are tried. Fails today:
/// the other listed names are certified.
#[test]
fn p2_reserved_names_are_never_certified_whatever_the_config_says() {
    let names = ["taylor", "root", "admin", "administrator"];
    let list: Vec<String> = names.iter().map(|n| format!("\"{n}\"")).collect();
    let config = format!(
        "{}allowed_agents = [{}]\n",
        machine_config(),
        list.join(", ")
    );
    let mut w = World::new(&config);
    if w.try_start_service().is_err() {
        return; // A service that refuses this config certifies nothing.
    }
    let repo_path = w.repo();
    let repo = w.canonical(&repo_path);
    let _ = ask_at(
        &w.socket,
        json!({"type": "RequestLease", "payload": {"repo": repo, "branch": "work", "intent": "t", "duration_secs": null}}),
    );
    for name in names {
        let principal = principal_for(name, "reserved-name-session");
        let answer = token_request(&w.socket, "IssueIdentifiedToken", &repo, "work", &principal);
        assert!(
            !matches!(answer, Some(Response::TokenIssued { .. })),
            "P2: the service issued a token for {principal} because agent-sign's config listed `{name}`"
        );
        w.stage(&repo_path, &format!("{name}.txt"), name);
        w.session_commit(&repo_path, name, &[]);
        let (g, signer) = w.signature_of(&repo_path, "HEAD");
        assert!(
            !(g == "G" && signer.starts_with(&format!("{name}."))),
            "P2: a session started as `{name}` got a Good signature as {signer}"
        );
    }
}

/// P2, the person as committer. A commit whose committer line is the
/// person's (`Human Developer <dev@example.com>`, from git config) is never
/// signed, whatever principal the signature is for: read by a person, the
/// commit would show the person with a Good signature. First through the
/// service's socket, then on an approval. Fails today: the service signs any
/// committer line.
#[test]
fn p2_a_commit_naming_the_person_as_committer_is_never_signed() {
    let mut w = World::new(&machine_config());
    w.start_service();
    let repo_path = w.repo();
    let repo = w.canonical(&repo_path);
    let principal = principal_for("claude-code", "committer-session");
    let head = w.rev(&repo_path, "HEAD");
    let tree = w.tree_with(&repo_path, "HEAD", "c.txt", "c\n");
    let person = format!("{PERSON_NAME} <{PERSON_EMAIL}>");
    let buffer = commit_buffer(&tree, &[&head], &person, &person, "as the person");
    let sigs = signatures_claiming(&w.socket, &repo, "work", &principal, &buffer);
    assert!(
        sigs.is_empty(),
        "P2: the service signed, as {principal}, {} commit(s) whose committer is the person ({person})",
        sigs.len()
    );
    drop(w);

    let w = approval_world();
    let repo_path = w.repo();
    approval_control(&w, &repo_path);
    let (mut ask, _) = fresh_ask(&w, &repo_path, "c.txt");
    let ident = agent_ident(&ask.principal);
    let buffer = commit_buffer(
        &ask.tree,
        &[&ask.parents[0]],
        &ident,
        &person,
        "as the person",
    );
    // DELIBERATE EVAL CHANGE (D3, 31 Oct 2026): bind the approval to the commit this test actually
    // sends, so the refusal it asserts comes from its own check, not from a hash mismatch.
    ask.commit_sha256 = sha_hex(&buffer);
    let (text, sig) = ask.signed();
    let answer = present(&w, &text, &sig, &buffer, &ask.repo, &ask.branch);
    assert!(
        refused(&answer),
        "P2: an approval for {} signed a commit whose committer is the person ({person})",
        ask.principal
    );
}

/// P2, other machines and reserved names on the approval path. Approvals
/// correctly signed by the commitments key, but naming a principal in
/// another machine's domain, plain `@agents.local`, another machine, or a
/// reserved name, are refused by this machine's service. Fails today: the
/// approval path doesn't exist (its control fails).
#[test]
fn p2_an_approval_never_names_another_machine_or_a_reserved_name() {
    let w = approval_world();
    let repo = w.repo();
    approval_control(&w, &repo);
    let s8 = session8("approved-run");
    let cases: Vec<(&str, String, &str)> = vec![
        (
            "another machine's domain",
            format!("claude-code.{s8}@pi.agents.local"),
            MACHINE,
        ),
        (
            "plain @agents.local",
            format!("claude-code.{s8}@agents.local"),
            MACHINE,
        ),
        (
            "another machine",
            format!("claude-code.{s8}@pi.agents.local"),
            "pi",
        ),
        ("taylor", format!("taylor.{s8}@{DOMAIN}"), MACHINE),
        ("root", format!("root.{s8}@{DOMAIN}"), MACHINE),
        ("admin", format!("admin.{s8}@{DOMAIN}"), MACHINE),
    ];
    for (what, principal, machine) in cases {
        let (mut ask, _) = fresh_ask(&w, &repo, "m.txt");
        ask.principal = principal.clone();
        ask.machine = machine.into();
        let ident = agent_ident(&principal);
        let buffer = commit_buffer(&ask.tree, &[&ask.parents[0]], &ident, &ident, what);
        // DELIBERATE EVAL CHANGE (D3, 31 Oct 2026): bind the approval to the commit this test actually
        // sends, so the refusal it asserts comes from its own check, not from a hash mismatch.
        ask.commit_sha256 = sha_hex(&buffer);
        let (text, sig) = ask.signed();
        let answer = present(&w, &text, &sig, &buffer, &ask.repo, &ask.branch);
        assert!(
            refused(&answer),
            "P2: machine {MACHINE}'s service signed an approval naming {what} ({principal}, machine {machine})"
        );
    }
}

// ===========================================================================
// P3. Agent-sign's state, and who can extend trust.
// ===========================================================================

/// P3, a service of one's own. With this machine's service running, another
/// `agent-signd` started by the same account against the same HOME (its own
/// socket) must not change what verifiers trust: the allowed-signers file
/// git names and the lines `agent-sign trust-line` prints stay exactly as
/// they were. Fails today: every start writes its new authority into both.
/// (That such a service's signatures are trusted by no verifier at all needs
/// agent-sign's own account: see the sitting tests.)
#[test]
fn p3_starting_another_service_never_changes_what_verifiers_trust() {
    let mut w = World::new(&machine_config());
    let allowed = w.managed_allowed_signers();
    w.start_service();
    let file_before = fs::read_to_string(&allowed).unwrap();
    let trust_before = w.trust();
    let history = w.home.join(".agent-sign/keys/agents_cas.pub");
    let history_before = fs::read_to_string(&history).unwrap_or_default();

    let rogue_socket = w.home.join("rogue.sock");
    // A second service that refuses to start is fine too: what verifiers
    // trust is checked either way.
    let rogue = w.spawn_service(&rogue_socket, "rogue.log").ok();
    let file_after = fs::read_to_string(&allowed).unwrap();
    let trust_after = w.trust();
    let history_after = fs::read_to_string(&history).unwrap_or_default();
    if let Some(mut rogue) = rogue {
        let _ = rogue.kill();
        let _ = rogue.wait();
    }

    assert_eq!(
        file_after,
        file_before,
        "P3: starting a second agent-signd in the same account rewrote the allowed-signers file \
         git trusts ({})",
        allowed.display()
    );
    assert_eq!(
        trust_after, trust_before,
        "P3: starting a second agent-signd in the same account changed the lines \
         `agent-sign trust-line` prints"
    );
    assert_eq!(
        history_after, history_before,
        "P3: starting a second agent-signd in the same account added to the authority history"
    );
}

// ===========================================================================
// P4. One session can't look into another.
// ===========================================================================

/// What the attacker session tries on every process whose command line
/// holds the victim's marker; prints what it managed, as JSON.
const PEEK_SCRIPT: &str = r#"
import ctypes, json, os, sys
marker = sys.argv[2]
me = os.getpid()
out = {"found": [], "environ": [], "fds": [], "mem": [], "getfd": []}
libc = ctypes.CDLL(None, use_errno=True)
for d in os.listdir('/proc'):
    if not d.isdigit() or int(d) == me:
        continue
    try:
        with open('/proc/%s/cmdline' % d, 'rb') as f:
            cl = f.read()
    except Exception:
        continue
    if marker.encode() not in cl or sys.argv[1].encode() in cl:
        continue
    pid = int(d)
    out["found"].append(pid)
    try:
        with open('/proc/%d/environ' % pid, 'rb') as f:
            if f.read():
                out["environ"].append(pid)
    except Exception:
        pass
    try:
        if os.listdir('/proc/%d/fd' % pid):
            out["fds"].append(pid)
    except Exception:
        pass
    try:
        with open('/proc/%d/maps' % pid) as f:
            start = int(f.readline().split()[0].split('-')[0], 16)
        fd = os.open('/proc/%d/mem' % pid, os.O_RDONLY)
        try:
            if os.pread(fd, 16, start):
                out["mem"].append(pid)
        finally:
            os.close(fd)
    except Exception:
        pass
    try:
        pfd = os.pidfd_open(pid)
        for t in range(16):
            r = libc.syscall(438, pfd, t, 0)
            if r >= 0:
                os.close(r)
                out["getfd"].append([pid, t])
        os.close(pfd)
    except Exception:
        pass
print(json.dumps(out))
"#;

/// P4. A live session commits and stays; a second session (another agent)
/// looks for it in `/proc` and tries to read its environment, list its open
/// files, read its memory, and take its descriptors (`pidfd_getfd`), the
/// signing channel among them. Every attempt must fail. Fails today: both
/// are plain processes of one account, so the environment is readable.
#[cfg(target_os = "linux")]
#[test]
fn p4_one_session_cant_read_anothers_environment_files_memory_or_channel() {
    let mut w = World::new(&machine_config());
    w.start_service();
    let python = find_on(&w.path, "python3");
    let victim_repo = w.repo_named("victim");
    w.stage(&victim_repo, "v.txt", "victim\n");
    let session = w.live_session(&victim_repo, "claude-code");
    let attacker_dir = w.repo_named("attacker");
    let out = w.run_session(
        &attacker_dir,
        "codex",
        &[],
        &python,
        &["-I", "-c", PEEK_SCRIPT, ATTACKER_TAG, &session.marker],
    );
    let report: serde_json::Value = serde_json::from_str(
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .last()
            .unwrap_or(""),
    )
    .unwrap_or_else(|e| {
        panic!(
            "CONTROL: the attacker session printed no report ({e}):\n{}",
            text(&out)
        )
    });
    for (what, field) in [
        ("environment", "environ"),
        ("open file descriptors", "fds"),
        ("memory", "mem"),
        ("descriptors, through pidfd_getfd", "getfd"),
    ] {
        let got = &report[field];
        assert!(
            got.as_array().is_some_and(|a| a.is_empty()),
            "P4: one agent session read another session's {what} (processes {got}; found {})",
            report["found"]
        );
    }
}

// ===========================================================================
// P5. Nothing captured from one session signs anything else.
// ===========================================================================

/// P5, a captured token. A session commits in a repository whose
/// pre-commit hook (the session's own code, so it sees everything the
/// session's git run has) writes the run's environment to a file and waits.
/// From outside the session, another process uses every token in that
/// environment to sign different content in the same working copy. Nothing
/// may be signed. Fails today: the token in `AGENT_EVENT_TOKEN` signs
/// whatever it's sent with.
#[test]
fn p5_a_token_captured_from_a_sessions_git_run_signs_nothing_else() {
    let mut w = World::new(&machine_config());
    w.start_service();
    let repo = w.repo();
    // DELIBERATE EVAL CHANGE (D4, 1 Nov 2026): the hook's dump and go files
    // were in HOME, which a launched session can no longer write (D4: only
    // its own working copy and a private tmp). They are in the working copy
    // now. No assertion changed.
    let dump = repo.join(".hook.env");
    let go = repo.join(".hook.go");
    let hook = repo.join(".git/hooks/pre-commit");
    fs::write(
        &hook,
        format!(
            "#!/bin/sh\nenv > '{d}.tmp' && mv '{d}.tmp' '{d}'\ni=0\nwhile [ $i -lt 200 ] && [ ! -e '{g}' ]; do sleep 0.1; i=$((i+1)); done\nexit 0\n",
            d = dump.display(),
            g = go.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&hook, fs::Permissions::from_mode(0o755)).unwrap();
    w.stage(&repo, "v.txt", "victim\n");
    let log = w.home.join("hooked-session.log");
    let mut cmd = w.session_command(
        &repo,
        "claude-code",
        &[],
        Path::new(env!("CARGO_BIN_EXE_agent-git")),
        &["commit", "-q", "-m", "hooked"],
    );
    let file = fs::File::create(&log).unwrap();
    cmd.stdout(Stdio::from(file.try_clone().unwrap()))
        .stderr(Stdio::from(file));
    let mut victim = cmd.spawn().unwrap();
    if !wait_for_file(&dump, RUN_LIMIT) {
        let _ = victim.kill();
        let _ = victim.wait();
        panic!(
            "CONTROL: the session's pre-commit hook never ran:\n{}",
            fs::read_to_string(&log).unwrap_or_default()
        );
    }
    let env: Vec<(String, String)> = fs::read_to_string(&dump)
        .unwrap()
        .lines()
        .filter_map(|l| {
            l.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
        })
        .collect();
    let get = |k: &str| env.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
    let committer = match (get("GIT_COMMITTER_NAME"), get("GIT_COMMITTER_EMAIL")) {
        (Some(n), Some(e)) => format!("{n} <{e}>"),
        _ => agent_ident(&principal_for("claude-code", "unknown")),
    };
    let tokens: Vec<(String, String)> = env
        .iter()
        .filter(|(k, _)| k.contains("TOKEN"))
        .cloned()
        .collect();
    let mut sockets = vec![w.socket.clone()];
    if let Some(s) = get("AGENT_SIGN_SOCKET") {
        sockets.push(PathBuf::from(s));
    }
    let canonical = w.canonical(&repo);
    let head = w.rev(&repo, "HEAD");
    let tree = w.tree_with(
        &repo,
        "HEAD",
        "other.txt",
        "content the session never asked for\n",
    );
    let buffer = commit_buffer(&tree, &[&head], &committer, &committer, "replayed");
    let mut signed = Vec::new();
    for socket in &sockets {
        for (name, token) in &tokens {
            if sign_with_token(socket, token, &buffer, &canonical, "work").is_some() {
                signed.push(name.clone());
            }
        }
    }
    fs::write(&go, "").unwrap();
    let start = Instant::now();
    while victim.try_wait().unwrap().is_none() && start.elapsed() < RUN_LIMIT {
        std::thread::sleep(Duration::from_millis(20));
    }
    let _ = victim.kill();
    let _ = victim.wait();
    assert!(
        signed.is_empty(),
        "P5: from outside the session, a token captured from its git run ({}) signed content the \
         session never asked for, as {committer}",
        signed.join(", ")
    );
}

/// P5, approvals. A captured approval, correctly signed by the commitments
/// key, is refused when replayed for another agent (the commit's committer
/// isn't the approved principal), another machine, another working copy,
/// later content (another tree, or another parent), a second time, or after
/// it expired. Fails today: the approval path doesn't exist (its control
/// fails).
#[test]
fn p5_an_approval_signs_only_what_it_names_once_and_in_time() {
    let w = approval_world();
    let repo = w.repo();
    let other_repo = w.repo_named("other");
    approval_control(&w, &repo);

    // Another agent.
    let (mut ask, _) = fresh_ask(&w, &repo, "a.txt");
    let other_agent = agent_ident(&principal_for("codex", "someone-else"));
    let buffer = commit_buffer(
        &ask.tree,
        &[&ask.parents[0]],
        &other_agent,
        &other_agent,
        "other agent",
    );
    // DELIBERATE EVAL CHANGE (D3, 31 Oct 2026): bind the approval to the commit this test actually
    // sends, so the refusal it asserts comes from its own check, not from a hash mismatch.
    ask.commit_sha256 = sha_hex(&buffer);
    let (text, sig) = ask.signed();
    assert!(
        refused(&present(&w, &text, &sig, &buffer, &ask.repo, &ask.branch)),
        "P5: an approval for {} signed a commit by another agent ({other_agent})",
        ask.principal
    );

    // Another machine.
    let (mut ask, buffer) = fresh_ask(&w, &repo, "b.txt");
    ask.machine = "pi".into();
    let (text, sig) = ask.signed();
    assert!(
        refused(&present(&w, &text, &sig, &buffer, &ask.repo, &ask.branch)),
        "P5: an approval for machine pi was signed on machine {MACHINE}"
    );

    // Another working copy: the approval names `repo`, the request and its
    // commit are in `other_repo`.
    let (other_ask, other_buffer) = fresh_ask(&w, &other_repo, "c.txt");
    let mut ask = other_ask.clone();
    ask.repo = w.canonical(&repo);
    let (text, sig) = ask.signed();
    assert!(
        refused(&present(
            &w,
            &text,
            &sig,
            &other_buffer,
            &other_ask.repo,
            "work"
        )),
        "P5: an approval for working copy {} signed a commit in {}",
        ask.repo,
        other_ask.repo
    );

    // Later content: another tree, then another parent.
    let (mut ask, _) = fresh_ask(&w, &repo, "d.txt");
    let later_tree = w.tree_with(&repo, "HEAD", "d.txt", "later content\n");
    let ident = agent_ident(&ask.principal);
    let later = commit_buffer(&later_tree, &[&ask.parents[0]], &ident, &ident, "later");
    // DELIBERATE EVAL CHANGE (D3, 31 Oct 2026): bind the approval to the commit this test actually
    // sends, so the refusal it asserts comes from its own check, not from a hash mismatch.
    ask.commit_sha256 = sha_hex(&later);
    let (text, sig) = ask.signed();
    assert!(
        refused(&present(&w, &text, &sig, &later, &ask.repo, &ask.branch)),
        "P5: an approval for tree {} signed a commit of tree {later_tree}",
        ask.tree
    );
    let (mut ask, _) = fresh_ask(&w, &repo, "e.txt");
    let grandparent = w.rev(&repo, "HEAD~1");
    let moved = commit_buffer(&ask.tree, &[&grandparent], &ident, &ident, "moved");
    // DELIBERATE EVAL CHANGE (D3, 31 Oct 2026): bind the approval to the commit this test actually
    // sends, so the refusal it asserts comes from its own check, not from a hash mismatch.
    ask.commit_sha256 = sha_hex(&moved);
    let (text, sig) = ask.signed();
    assert!(
        refused(&present(&w, &text, &sig, &moved, &ask.repo, &ask.branch)),
        "P5: an approval for parent {} signed a commit on parent {grandparent}",
        ask.parents[0]
    );

    // A second time.
    let (ask, buffer) = fresh_ask(&w, &repo, "f.txt");
    let (text, sig) = ask.signed();
    let first = present(&w, &text, &sig, &buffer, &ask.repo, &ask.branch);
    assert!(
        !refused(&first),
        "CONTROL: a fresh approval was refused the first time: {first:?}"
    );
    std::thread::sleep(Duration::from_secs(1));
    let again = commit_buffer(&ask.tree, &[&ask.parents[0]], &ident, &ident, "again");
    assert!(
        refused(&present(&w, &text, &sig, &again, &ask.repo, &ask.branch)),
        "P5: an approval (nonce {}) was used a second time",
        ask.nonce
    );

    // Expired.
    let (mut ask, buffer) = fresh_ask(&w, &repo, "g.txt");
    ask.expires_at = now_secs() - 1;
    let (text, sig) = ask.signed();
    assert!(
        refused(&present(&w, &text, &sig, &buffer, &ask.repo, &ask.branch)),
        "P5: an expired approval was signed"
    );
}

// ===========================================================================
// P6. Only the commitments approval key approves.
// ===========================================================================

/// P6. Approvals signed by anything but the commitments key are refused:
/// another key, the person's key, the commitments key in git's namespace
/// instead of the approval one, the commitments key over other text than
/// what's presented, and no signature at all. Fails today: the approval
/// path doesn't exist (its control fails).
#[test]
fn p6_only_the_commitments_approval_key_can_approve() {
    let w = approval_world();
    let repo = w.repo();
    approval_control(&w, &repo);
    let approval_key = key(APPROVAL_SEED);
    let other = key(OTHER_SEED);
    let person = key(PERSON_SEED);
    type Forge = Box<dyn Fn(&str) -> (String, String)>;
    let forgeries: Vec<(&str, Forge)> = vec![
        (
            "another key",
            Box::new(move |t: &str| {
                (
                    t.to_string(),
                    sshsig(
                        &plain_key_blob(&other),
                        &other,
                        APPROVAL_NAMESPACE,
                        t.as_bytes(),
                    ),
                )
            }) as Forge,
        ),
        (
            "the person's key",
            Box::new(move |t: &str| {
                (
                    t.to_string(),
                    sshsig(
                        &plain_key_blob(&person),
                        &person,
                        APPROVAL_NAMESPACE,
                        t.as_bytes(),
                    ),
                )
            }) as Forge,
        ),
        (
            "the commitments key in git's namespace",
            Box::new({
                let k = approval_key.clone();
                move |t: &str| {
                    (
                        t.to_string(),
                        sshsig(&plain_key_blob(&k), &k, "git", t.as_bytes()),
                    )
                }
            }) as Forge,
        ),
        (
            "the commitments key over other text",
            Box::new({
                let k = approval_key.clone();
                move |t: &str| {
                    let signed_text = t.replace("\"expires_at\"", "\"expires_at_\"");
                    (
                        t.to_string(),
                        sshsig(
                            &plain_key_blob(&k),
                            &k,
                            APPROVAL_NAMESPACE,
                            signed_text.as_bytes(),
                        ),
                    )
                }
            }) as Forge,
        ),
        (
            "no signature",
            Box::new(|t: &str| (t.to_string(), String::new())) as Forge,
        ),
    ];
    for (what, forge) in forgeries {
        let (ask, buffer) = fresh_ask(&w, &repo, "forged.txt");
        let (text, sig) = forge(&ask.text());
        assert!(
            refused(&present(&w, &text, &sig, &buffer, &ask.repo, &ask.branch)),
            "P6: an approval signed by {what} was accepted"
        );
    }
}

// ===========================================================================
// P7. No launcher, no attested signature.
// ===========================================================================

/// P7. A plain process of the account, which no launcher started, runs the
/// git wrapper with Claude Code's marks. If it gets a signature at all, that
/// signature is not Good for any principal in this machine's agents' domain,
/// and `agent-sign verify` calls it "unattested". Fails today: it is Good
/// as `claude-code.<session>@hetzner.agents.local`.
#[test]
fn p7_a_process_no_launcher_started_gets_no_attested_signature() {
    let mut w = World::new(&machine_config());
    w.start_service();
    let repo = w.repo();
    let before = w.rev(&repo, "HEAD");
    w.stage(&repo, "plain.txt", "plain\n");
    let session = fresh();
    let marks = [
        ("CLAUDECODE", "1"),
        ("CLAUDE_CODE_SESSION_ID", session.as_str()),
    ];
    let _ = w.plain_agent(&repo, &marks, &["commit", "-q", "-m", "plain shell"]);
    if w.rev(&repo, "HEAD") == before {
        return; // Refused outright: no signature at all.
    }
    let (g, signer) = w.signature_of(&repo, "HEAD");
    assert!(
        !(g == "G" && signer.ends_with(&format!("@{DOMAIN}"))),
        "P7: a plain process no launcher started got a signature Good as {signer}, in the attested \
         agents' domain @{DOMAIN}"
    );
    if g == "G" {
        let said = w.verify_text(&repo, "HEAD");
        assert!(
            said.contains("unattested"),
            "P7: `agent-sign verify` didn't call a launcher-less signature unattested: {said}"
        );
    }
}

// ===========================================================================
// P8. Verification says how the identity was established.
// ===========================================================================

/// P8, today's signatures. A commit signed as agent-sign signed them before
/// the fix (a certificate with no attestation, from an authority the
/// verifier trusts for this machine's agents) is reported by
/// `agent-sign verify` as "claimed by a process in a shared account", and
/// never as proven. Fails today: there is no `agent-sign verify`.
#[test]
fn p8_a_self_asserted_signature_is_reported_as_claimed_never_as_proven() {
    let w = World::new(&machine_config());
    let repo = w.repo();
    let principal = principal_for("claude-code", "legacy-session");
    let subject = key(LEGACY_SUBJECT_SEED);
    let cert = legacy_cert(LEGACY_CA_SEED, &principal, &subject);
    let head = w.rev(&repo, "HEAD");
    let tree = w.tree_with(&repo, "HEAD", "legacy.txt", "legacy\n");
    let ident = agent_ident(&principal);
    let buffer = commit_buffer(&tree, &[&head], &ident, &ident, "legacy");
    let sig = sshsig(&cert, &subject, "git", &buffer);
    let commit = w.write_signed_commit(&repo, &buffer, &sig);
    let allowed = w.home.join("legacy_allowed_signers");
    fs::write(
        &allowed,
        format!(
            "*@{DOMAIN} cert-authority {}\n",
            pub_line(&key(LEGACY_CA_SEED))
        ),
    )
    .unwrap();
    w.name_allowed_signers_file(&allowed);
    assert_eq!(
        w.signature_of(&repo, &commit),
        ("G".to_string(), principal.clone()),
        "CONTROL: the legacy commit should be Good for {principal} under its authority"
    );
    let said = w.verify_text(&repo, &commit);
    assert!(
        said.contains("claimed by a process in a shared account"),
        "P8: `agent-sign verify` didn't report a self-asserted signature as claimed by a process \
         in a shared account; it said: {said}"
    );
    assert!(
        !said.to_lowercase().contains("proven"),
        "P8: `agent-sign verify` called a self-asserted signature proven: {said}"
    );
}

/// P8 and the launcher's control. A session the launcher started signs a
/// commit Good as its own principal (`claude-code.<8 hex>@hetzner.agents.local`),
/// and `agent-sign verify` states how the identity was established
/// (`attestation: ...`), neither "claimed" nor "unattested". Fails today:
/// there is no launcher.
#[test]
fn p8_a_launched_sessions_signature_says_how_its_identity_was_established() {
    let mut w = World::new(&machine_config());
    w.start_service();
    w.require_launcher("P8 (control: a launched session signs as itself)");
    let repo = w.repo();
    w.stage(&repo, "l.txt", "launched\n");
    let out = w.session_commit(&repo, "claude-code", &[]);
    let (g, signer) = w.signature_of(&repo, "HEAD");
    assert!(
        g == "G" && signer.starts_with("claude-code.") && signer.ends_with(&format!("@{DOMAIN}")),
        "CONTROL: a launched session's commit isn't Good as a claude-code principal ({g} {signer}):\n{}",
        text(&out)
    );
    let said = w.verify_text(&repo, "HEAD");
    assert!(
        said.contains("attestation:") && !said.contains("claimed") && !said.contains("unattested"),
        "P8: `agent-sign verify` didn't state how a launched session's identity was established: {said}"
    );
}

/// P8 on the approval path: `agent-sign verify` says an approved commit's
/// identity came from an approval. Fails today: the approval path doesn't
/// exist.
#[test]
fn p8_an_approved_commits_signature_says_it_came_from_an_approval() {
    let w = approval_world();
    let repo = w.repo();
    let (ask, buffer) = fresh_ask(&w, &repo, "approved.txt");
    let (text, sig) = ask.signed();
    let answer = present(&w, &text, &sig, &buffer, &ask.repo, &ask.branch);
    let Some(Response::Signed { signature_pem }) = answer else {
        panic!("CONTROL: a valid approval wasn't signed: {answer:?}");
    };
    let commit = w.write_signed_commit(&repo, &buffer, &signature_pem);
    let said = w.verify_text(&repo, &commit);
    assert!(
        said.contains("attestation:") && said.contains("approval"),
        "P8: `agent-sign verify` didn't say an approved commit's identity came from an approval: {said}"
    );
}
