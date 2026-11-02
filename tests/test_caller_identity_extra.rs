//! Caller identity, extra tests: what an independent critique of the build
//! plan found the first test file does not hold the fix to.
//!
//! `test_caller_identity.rs` is the eval for the fix (design in
//! `docs/caller-identity.md`). An independent critique of the build plan
//! (31 Oct 2026) found four gaps that file would let a wrong build pass
//! through. Each test here covers one, and fails today for its stated
//! reason. They are part of the same eval: the fix is done when these pass
//! too. Nothing in `test_caller_identity.rs` is changed or loosened.
//!
//! The findings:
//! 1. **Verify only after verification.** `agent-sign verify` must print an
//!    attestation only for a signature that verifies against the trust file.
//!    A certificate from an authority nobody trusts can carry any
//!    `attestation@agent-sign` words it likes. The first file only checks the
//!    words on Good signatures, so a `verify` that reads the extension before
//!    (or regardless of) the signature check would pass all of it.
//! 2. **The approval binds the author.** The approval names the principal;
//!    the commit's author line must be that principal too. Otherwise whoever
//!    presents an approval first gets a Good signature on a commit that says
//!    it was authored by someone else, the person included.
//! 3. **The approval nonce is single use under concurrency.** The nonce
//!    check and its recording must be one atomic step; two requests at the
//!    same moment must not both pass the check.
//! 4. **No lease on the approval path.** The approval is the authority. A
//!    signature on the approval path must not need a lease, and must not
//!    leave one behind (a lease would widen what other callers may sign).
//!
//! The harness pieces (the isolated world, the in-memory keys, the SSHSIG
//! writer, the approval helpers) are copied from `test_caller_identity.rs`
//! so this file stands alone; keep them in step with it. The same isolation
//! applies: an empty environment, a temporary HOME, a temporary global git
//! config, no system config, a socket in the temporary directory, no private
//! key ever written to a file, every wait bounded, every process stopped.
//!
//! **Before the build** (today) there is no `agent-sign verify` and no
//! `SignApproved`: the approval world's service doesn't know the request,
//! so the controls that begin tests 2 and 4 fail first, as in the first
//! file, and tests 1 and 3 fail on their own assertions.

use std::ffi::OsString;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Arc, Barrier};
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

/// The seeds of the in-memory keys.
const PERSON_SEED: [u8; 32] = [3; 32];
const APPROVAL_SEED: [u8; 32] = [21; 32];
/// An authority no verifier here trusts, and the key it certifies.
const ROGUE_CA_SEED: [u8; 32] = [41; 32];
const ROGUE_SUBJECT_SEED: [u8; 32] = [42; 32];

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
        self.good_under(&self.trust_file(), principal, sig, data)
    }

    /// Whether plain `ssh-keygen -Y verify` accepts `sig` over `data` for
    /// `principal` under the allowed-signers file `allowed`.
    fn good_under(&self, allowed: &Path, principal: &str, sig: &str, data: &[u8]) -> bool {
        let sig_file = self.home.join(format!("check-{}.sig", fresh()));
        fs::write(&sig_file, sig).unwrap();
        let mut child = Command::new(&self.ssh_keygen)
            .args(["-Y", "verify", "-n", "git", "-I", principal, "-f"])
            .arg(allowed)
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
    /// set to `trust`: what it did, exit status included.
    fn verify_output(&self, repo: &Path, rev: &str, trust: &Path) -> Output {
        let mut cmd = self.cmd(Path::new(env!("CARGO_BIN_EXE_agent-sign")));
        // The trust file is named to the verifier itself (`--allowed-signers`, what a
        // gate passes), not through GIT_CONFIG_* variables, which `verify` no longer
        // reads: a trust file the environment or the repository names is the
        // session's to choose (second whole-branch review, F2).
        cmd.args(["verify", "--allowed-signers"])
            .arg(trust)
            .arg(rev)
            .current_dir(repo);
        run_within(cmd, "agent-sign verify")
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

// ---------------------------------------------------------------------------
// What the extra tests need beyond the first file's harness.
// ---------------------------------------------------------------------------

/// The name of the certificate extension that records how an identity was
/// established (`docs/caller-identity.md`, P8).
const ATTESTATION_EXTENSION: &str = "attestation@agent-sign";

/// A certificate for the rogue subject key from the rogue authority, for
/// `principal`, carrying `attestation` in the attestation extension. The
/// authority is in no trust file, so the certificate is self-made: it says
/// whatever its maker likes about how the identity was established.
fn rogue_cert(principal: &str, attestation: &str) -> Vec<u8> {
    let now = now_secs();
    let subject = key(ROGUE_SUBJECT_SEED);
    let data = KeyData::Ed25519(Ed25519PublicKey(subject.verifying_key().to_bytes()));
    let mut b = Builder::new(vec![7u8; 32], data, now - 300, now + 3600).unwrap();
    b.serial(1)
        .unwrap()
        .key_id(format!("{principal} on rogue-host"))
        .unwrap()
        .cert_type(CertType::User)
        .unwrap()
        .valid_principal(principal)
        .unwrap()
        .extension(ATTESTATION_EXTENSION, attestation)
        .unwrap();
    let ca = PrivateKey::from(Ed25519Keypair::from_seed(&ROGUE_CA_SEED));
    b.sign(&ca).unwrap().to_bytes().unwrap()
}

/// Whether any line of `said` is an attestation line.
fn has_attestation_line(said: &str) -> bool {
    said.lines()
        .any(|l| l.trim_start().to_lowercase().starts_with("attestation:"))
}

/// Everything a program printed, stdout then stderr.
fn all_output(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// `request` sent on its own connection at the same moment as every other
/// call sharing `gate`: connected first, then released together.
fn ask_together(socket: &Path, request: serde_json::Value, gate: &Barrier) -> Option<Response> {
    let stream = UnixStream::connect(socket).ok();
    gate.wait();
    let mut stream = stream?;
    stream.set_read_timeout(Some(RUN_LIMIT)).ok()?;
    writeln!(stream, "{request}").ok()?;
    let mut line = String::new();
    BufReader::new(&stream).read_line(&mut line).ok()?;
    serde_json::from_str(&line).ok()
}

// ===========================================================================
// Finding 1. Verify prints an attestation only after the signature verifies.
// ===========================================================================

/// Finding "verify only after verification". A commit signed with a
/// certificate from an authority that is NOT in the trust file, and carrying
/// the `attestation@agent-sign` extension with `launcher ...` or
/// `approval ...`, is a forgery of an attestation: anyone can mint such a
/// certificate. `agent-sign verify <rev>` must exit non-zero, say "not
/// verified" with a reason, and print no `attestation:` line (and none of the
/// extension's words). A `verify` that reads the extension before, or
/// regardless of, the signature check passes every test in
/// `test_caller_identity.rs`, which only look at Good signatures.
///
/// Premises checked first, so the refusal is attributable to the missing
/// trust and nothing else: plain `ssh-keygen` rejects the commit under this
/// machine's trust, and accepts it once the rogue authority is added. The
/// control: a real approved commit does verify and prints its attestation.
///
/// Fails today: there is no `agent-sign verify`, so nothing says "not
/// verified" (and the control has no approval path either).
#[test]
fn verify_prints_an_attestation_only_for_a_signature_that_verifies() {
    let mut w = World::new(&machine_config());
    w.start_service();
    let repo = w.repo();
    let principal = principal_for("claude-code", "rogue-session");
    let subject = key(ROGUE_SUBJECT_SEED);
    let ident = agent_ident(&principal);
    let rogue_pub = pub_line(&key(ROGUE_CA_SEED));

    // Words nobody but the rogue authority's owner chose; none may be echoed.
    let forged: [(&str, String); 2] = [
        (
            "launcher",
            "launcher session=forged-session-marker uid=0 isolation=dynamic-user".into(),
        ),
        ("approval", format!("approval sha256={}", "f0".repeat(32))),
    ];
    for (n, (kind, words)) in forged.iter().enumerate() {
        let head = w.rev(&repo, "HEAD");
        let tree = w.tree_with(&repo, "HEAD", "rogue.txt", &format!("rogue {n}\n"));
        let buffer = commit_buffer(&tree, &[&head], &ident, &ident, &format!("rogue {kind}"));
        let cert = rogue_cert(&principal, words);
        let sig = sshsig(&cert, &subject, "git", &buffer);
        let commit = w.write_signed_commit(&repo, &buffer, &sig);

        // Premises: untrusted authority, otherwise a well-formed signature.
        assert_ne!(
            w.signature_of(&repo, &commit).0,
            "G",
            "PREMISE: the rogue commit is Good under this machine's trust, so it says nothing about verify"
        );
        let with_rogue = w.home.join(format!("rogue_allowed_signers-{}", fresh()));
        fs::write(
            &with_rogue,
            format!("{}*@{DOMAIN} cert-authority {rogue_pub}\n", w.trust()),
        )
        .unwrap();
        assert!(
            w.good_under(&with_rogue, &principal, &sig, &buffer),
            "PREMISE: the rogue commit isn't a valid signature even under its own authority"
        );

        // The finding: verify against the trust the machine really has.
        let trust = w.trust_file();
        let out = w.verify_output(&repo, &commit, &trust);
        let said = all_output(&out);
        assert!(
            !out.status.success(),
            "FINDING (verify only after verification): `agent-sign verify` exited 0 for a commit \
             signed by an authority in no trust file, with an extension saying {kind:?}: {}",
            text(&out)
        );
        assert!(
            said.to_lowercase().contains("not verified"),
            "FINDING (verify only after verification): `agent-sign verify` didn't say \"not \
             verified\" (with a reason) for a commit from an untrusted authority carrying a \
             {kind:?} attestation; it said: {}",
            text(&out)
        );
        assert!(
            !has_attestation_line(&said),
            "FINDING (verify only after verification): `agent-sign verify` printed an \
             `attestation:` line for a commit from an untrusted authority with a forged {kind:?} \
             extension: {}",
            text(&out)
        );
        for marker in ["forged-session-marker", &"f0".repeat(32)] {
            assert!(
                !said.contains(marker),
                "FINDING (verify only after verification): `agent-sign verify` echoed the \
                 forged extension's words ({marker}) for an untrusted certificate: {}",
                text(&out)
            );
        }
    }

    // Control: a real approved commit verifies and prints its attestation.
    let real = approval_world();
    let real_repo = real.repo();
    let (ask, buffer) = fresh_ask(&real, &real_repo, "approved.txt");
    let (approval, approval_sig) = ask.signed();
    let answer = present(
        &real,
        &approval,
        &approval_sig,
        &buffer,
        &ask.repo,
        &ask.branch,
    );
    let Some(Response::Signed { signature_pem }) = answer else {
        panic!(
            "CONTROL: a valid approval wasn't signed ({answer:?}): the approval path \
             (`SignApproved`) doesn't exist yet, so there is no real attested commit to verify.\n\
             service log:\n{}",
            real.service_log()
        );
    };
    let commit = real.write_signed_commit(&real_repo, &buffer, &signature_pem);
    let trust = real.trust_file();
    let out = real.verify_output(&real_repo, &commit, &trust);
    let said = all_output(&out);
    assert!(
        out.status.success() && has_attestation_line(&said) && said.contains("approval"),
        "CONTROL: `agent-sign verify` didn't verify a real approved commit and print its \
         attestation: {}",
        text(&out)
    );
}

// ===========================================================================
// Finding 2. The approval binds the author.
// ===========================================================================

/// Finding "approval binds the author". With an otherwise valid approval
/// (right principal as committer, right tree and parents, right repo and
/// branch, in time, unused), a commit whose AUTHOR is not the approved
/// principal gets no signature. Without this, whoever presents a captured
/// approval first gets a Good signature on a commit that says it was
/// written by the person, or by another agent. Two authors are tried: the
/// person-looking `Taylor <taylor@example.com>`, and another agent's
/// principal in the same domain. The control first: the same shape of
/// commit with the author equal to the principal is signed.
///
/// Fails today: there is no `SignApproved` (the control fails).
#[test]
fn an_approval_signs_only_a_commit_authored_by_the_approved_principal() {
    let w = approval_world();
    let repo = w.repo();
    approval_control(&w, &repo);

    let others = [
        ("the person", "Taylor <taylor@example.com>".to_string()),
        (
            "another agent",
            agent_ident(&principal_for("codex", "someone-else")),
        ),
    ];
    for (who, author) in others {
        let (mut ask, _) = fresh_ask(&w, &repo, &format!("author-{}.txt", fresh()));
        let committer = agent_ident(&ask.principal);
        let buffer = commit_buffer(
            &ask.tree,
            &[&ask.parents[0]],
            &author,
            &committer,
            "authored by someone else",
        );
        // DELIBERATE EVAL CHANGE (D3, 31 Oct 2026): bind the approval to the commit this test actually
        // sends, so the refusal it asserts comes from its own check, not from a hash mismatch.
        ask.commit_sha256 = sha_hex(&buffer);
        let (approval, sig) = ask.signed();
        let answer = present(&w, &approval, &sig, &buffer, &ask.repo, &ask.branch);
        assert!(
            refused(&answer),
            "FINDING (approval binds the author): an approval for {} signed a commit whose \
             author is {who} ({author}) and whose committer is the approved principal \
             ({answer:?})",
            ask.principal
        );
    }
}

// ===========================================================================
// Finding 3. The approval nonce is single use under concurrency.
// ===========================================================================

/// How many times the same approval is presented at once, per round.
const RACE_ROUNDS: usize = 12;

/// Finding "the nonce is single use under concurrency". The same approval
/// (same text, same signature, so the same nonce) and the same commit are
/// presented on two connections at the same moment: exactly one request gets
/// a signature. Checking the nonce and recording it must be one step under
/// one lock; if both requests can pass the check before either records it,
/// one approval signs twice. Repeated for [`RACE_ROUNDS`] fresh approvals,
/// because a race is only sometimes lost; every round must give exactly one
/// `Signed`. (A build that records the nonce atomically passes every round;
/// one that races will, over these rounds, very probably give two in one.)
///
/// Fails today: there is no `SignApproved`, so no round gives a `Signed`.
#[test]
fn the_same_approval_presented_twice_at_once_is_signed_exactly_once() {
    let w = approval_world();
    let repo = w.repo();
    let mut bad = Vec::new();
    for round in 0..RACE_ROUNDS {
        let (ask, buffer) = fresh_ask(&w, &repo, &format!("race-{round}.txt"));
        let (approval, sig) = ask.signed();
        let b64 = base64::engine::general_purpose::STANDARD.encode(&buffer);
        let request = json!({"type": "SignApproved", "payload": {
            "approval": approval, "approval_signature": sig,
            "buffer_b64": b64, "repo": ask.repo, "branch": ask.branch}});
        let gate = Arc::new(Barrier::new(2));
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let socket = w.socket.clone();
                let request = request.clone();
                let gate = Arc::clone(&gate);
                std::thread::spawn(move || ask_together(&socket, request, &gate))
            })
            .collect();
        let answers: Vec<Option<Response>> =
            handles.into_iter().map(|h| h.join().unwrap()).collect();
        let signed = answers
            .iter()
            .filter(|a| matches!(a, Some(Response::Signed { .. })))
            .count();
        if signed != 1 {
            bad.push(format!(
                "round {round} (nonce {}): {signed} signatures{}",
                ask.nonce,
                if bad.is_empty() {
                    format!("; the answers were {answers:?}")
                } else {
                    String::new()
                }
            ));
        }
    }
    assert!(
        bad.is_empty(),
        "FINDING (nonce single use under concurrency): the same approval presented on two \
         connections at once must give exactly one signature, but in {} of {RACE_ROUNDS} \
         rounds it did not:\n{}\nservice log:\n{}",
        bad.len(),
        bad.join("\n"),
        w.service_log()
    );
}

// ===========================================================================
// Finding 4. No lease on the approval path.
// ===========================================================================

/// Finding "no lease on the approval path". The approval is the authority, so
/// `SignApproved` signs when no `RequestLease` was ever made for the working
/// copy, and leaves no lease behind: `agent-sign leases` shows none for that
/// repository afterwards. A lease left by the approval path would let later
/// callers sign in that working copy without an approval of their own; a
/// lease required by it would make the suite's runner ask for one it has no
/// right to. Premise: before the approval, `leases` works and shows none.
///
/// Fails today: there is no `SignApproved`, so nothing is signed.
#[test]
fn an_approval_signs_without_any_lease_and_leaves_none_behind() {
    let w = approval_world();
    let repo = w.repo();
    let leases = |w: &World| {
        let mut cmd = w.cmd(Path::new(env!("CARGO_BIN_EXE_agent-sign")));
        cmd.arg("leases").current_dir(&w.home);
        run_within(cmd, "agent-sign leases")
    };

    let before = leases(&w);
    assert!(
        before.status.success() && all_output(&before).contains("No active agent leases found."),
        "PREMISE: `agent-sign leases` didn't show an empty list before any request: {}",
        text(&before)
    );

    let (ask, buffer) = fresh_ask(&w, &repo, "no-lease.txt");
    let (approval, sig) = ask.signed();
    let answer = present(&w, &approval, &sig, &buffer, &ask.repo, &ask.branch);
    let Some(Response::Signed { signature_pem }) = answer else {
        panic!(
            "FINDING (no lease on the approval path): a valid approval wasn't signed when no \
             lease had been requested for {} ({answer:?}): either `SignApproved` doesn't exist \
             yet or it asks for a lease.\nservice log:\n{}",
            ask.repo,
            w.service_log()
        );
    };
    assert!(
        w.good_as(&ask.principal, &signature_pem, &buffer),
        "CONTROL: the approved commit's signature isn't Good for {} under this machine's trust",
        ask.principal
    );

    let after = leases(&w);
    let listed = all_output(&after);
    assert!(
        after.status.success(),
        "PREMISE: `agent-sign leases` failed after the approval: {}",
        text(&after)
    );
    assert!(
        !listed.contains(&ask.repo),
        "FINDING (no lease on the approval path): `agent-sign leases` shows a lease for {} \
         after a SignApproved: {listed}",
        ask.repo
    );
}
