//! `agent-sign verify`, round 2: the independent whole-branch security
//! review's findings F1, F2, F3 and the verify parts of F7, as tests.
//!
//! Written before the fixes, as their eval (1 Nov 2026). Every test whose
//! doc comment says "Fails today" must fail on the code at `f61ed17` for the
//! reason it names, and pass once the finding is fixed with no assertion
//! changed. The tests marked "Control" pin what must keep working and need
//! not fail today (but several do, because they use the new `trust_file`
//! field or `--allowed-signers`).
//!
//! **The interface the tests hold the builder to** (decided by the
//! orchestrator):
//! - I-F1: every git that `verify` runs ignores replace refs, and `verify`
//!   re-hashes the commit object it read and requires it to equal the oid it
//!   is verifying; a mismatch is reason `error`, exit 1, `verified` false.
//! - I-F2: `agent-sign verify --allowed-signers <file>` names the trust
//!   file. Without it, in system mode (`/etc/agent-sign/system.toml` exists)
//!   the trust file is `/etc/agent-sign/allowed_signers`, always; otherwise
//!   `gpg.ssh.allowedSignersFile` is read only from the system and global
//!   git config scopes (never local, worktree, `includeIf` inside a
//!   repository's config, `GIT_CONFIG_COUNT`/`GIT_CONFIG_PARAMETERS`).
//!   `GIT_CONFIG_GLOBAL`/`GIT_CONFIG_SYSTEM`/`GIT_CONFIG_NOSYSTEM` are the
//!   verifier's own environment and are honoured. The JSON gains a
//!   `trust_file` field naming the file used (additive: the six existing
//!   fields stay).
//! - I-F3: the human form exits exactly as the JSON form does.
//! - I-F7: `ssh-keygen` is run by absolute path; commit-controlled text is
//!   filtered of control characters before the human form prints it.
//!
//! **Seam assumed for system mode.** The tests cannot write `/etc`. They use
//! the debug-test-only seam that already exists,
//! `AGENT_SIGN_TEST_SYSTEM_CONFIG` (see `agent_sign::launch`), which makes
//! the file it names stand in for `/etc/agent-sign/system.toml`. One test
//! (`system_mode_trust_file_sits_next_to_the_system_config`) additionally
//! assumes that, with that seam set, the trust file is `allowed_signers` in
//! the same folder as that file (the stand-in for
//! `/etc/agent-sign/allowed_signers`). The other system-mode test needs no
//! such assumption: it only needs `/etc/agent-sign/allowed_signers` (and
//! the file next to the stand-in) not to hold the test's authority.
//!
//! **What the commits are**: as in `test_verify_json.rs` (whose helpers are
//! copied below, since test files are separate crates): certificates minted
//! in memory from fixed seeds, no private key ever written to a file.
//! Isolation: an empty environment plus a temporary HOME, a temporary global
//! git config, no system config, a PATH without agent-sign's installed
//! `bin`. `GIT_NO_REPLACE_OBJECTS` is never set. Every wait is bounded.
#![allow(dead_code)]
#![cfg(unix)]

use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::Value;
use sha2::{Digest, Sha256, Sha512};
use ssh_key::certificate::{Builder, CertType};
use ssh_key::private::{Ed25519Keypair, PrivateKey};
use ssh_key::public::{Ed25519PublicKey, KeyData};
use tempfile::{TempDir, tempdir};

use agent_sign::crypto::openssh_ed25519_line;

const MACHINE: &str = "hetzner";
const DOMAIN: &str = "hetzner.agents.local";
const PERSON_NAME: &str = "Human Developer";
const PERSON_EMAIL: &str = "dev@example.com";
/// Every program run gets at most this long.
const RUN_LIMIT: Duration = Duration::from_secs(30);
/// How far outside the certificate's window a commit is dated: two days.
const OUTSIDE: u64 = 2 * 24 * 3600;

/// The seeds of the in-memory keys.
const TRUSTED_CA_SEED: [u8; 32] = [11; 32];
const UNTRUSTED_CA_SEED: [u8; 32] = [41; 32];
const SUBJECT_SEED: [u8; 32] = [12; 32];

/// The attestation extensions, as the service writes them
/// (`src/attestation.rs`).
const EXTENSION: &str = "attestation@agent-sign";
const LAUNCHER: &str = "launcher session=0123456789abcdef uid=1000 isolation=pid-namespace";
const UNATTESTED: &str = "unattested";

/// The reasons the interface allows, and the attestations.
const REASONS: [&str; 9] = [
    "ok",
    "unsigned",
    "unattested",
    "claimed",
    "untrusted_authority",
    "outside_window",
    "bad_signature",
    "no_trust_file",
    "error",
];
const ATTESTATIONS: [&str; 5] = ["launcher", "approval", "unattested", "claimed", "none"];
const FIELDS: [&str; 6] = [
    "verified",
    "attested",
    "attestation",
    "signer",
    "reason",
    "detail",
];

// ---------------------------------------------------------------------------
// Keys, certificates and signatures, computed here, independently of agent-sign.
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

/// A certificate for `subject` naming `principal`, from the authority with
/// `ca_seed`, valid from five minutes before now to an hour after, carrying
/// `attestation` in the attestation extension when given. Built here with
/// ssh-key.
fn cert(
    ca_seed: [u8; 32],
    principal: &str,
    subject: &SigningKey,
    attestation: Option<&str>,
) -> Vec<u8> {
    let now = now_secs();
    let data = KeyData::Ed25519(Ed25519PublicKey(subject.verifying_key().to_bytes()));
    let mut b = Builder::new(vec![9u8; 32], data, now - 300, now + 3600).unwrap();
    b.serial(1)
        .unwrap()
        .key_id(format!("{principal} on test-host"))
        .unwrap()
        .cert_type(CertType::User)
        .unwrap()
        .valid_principal(principal)
        .unwrap();
    if let Some(words) = attestation {
        b.extension(EXTENSION, words).unwrap();
    }
    let ca = PrivateKey::from(Ed25519Keypair::from_seed(&ca_seed));
    b.sign(&ca).unwrap().to_bytes().unwrap()
}

/// A commit object (unsigned) with the committer date `when`.
fn commit_buffer_at(tree: &str, parents: &[&str], ident: &str, when: u64, msg: &str) -> Vec<u8> {
    let parents: String = parents.iter().map(|p| format!("parent {p}\n")).collect();
    format!("tree {tree}\n{parents}author {ident} {when} +0000\ncommitter {ident} {when} +0000\n\n{msg}\n")
        .into_bytes()
}

fn agent_ident(principal: &str) -> String {
    format!("Claude Code <{principal}>")
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
    fn new() -> World {
        let dir = tempdir().unwrap();
        let home = dir.path().to_path_buf();
        let path = cleaned_path();
        let world = World {
            global_config: home.join("person.gitconfig"),
            real_git: find_on(&path, "git"),
            home,
            path,
            _dir: dir,
        };
        fs::create_dir_all(world.home.join(".agent-sign")).unwrap();
        fs::write(
            world.home.join(".agent-sign/config.toml"),
            format!("[identity]\nmachine = \"{MACHINE}\"\n"),
        )
        .unwrap();
        fs::write(
            &world.global_config,
            format!(
                "[user]\n\tname = {PERSON_NAME}\n\temail = {PERSON_EMAIL}\n\
                 [commit]\n\tgpgsign = false\n[gpg]\n\tformat = ssh\n"
            ),
        )
        .unwrap();
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
            ("TZ".into(), "UTC".into()),
            ("GIT_CONFIG_GLOBAL".into(), s(&self.global_config)),
            ("GIT_CONFIG_NOSYSTEM".into(), "1".into()),
            ("GIT_EDITOR".into(), "true".into()),
            ("GIT_TERMINAL_PROMPT".into(), "0".into()),
            ("AGENT_SIGN_SOCKET".into(), s(&self.home.join("none.sock"))),
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

    /// A repository with one unsigned commit, on branch `work`.
    fn repo(&self) -> PathBuf {
        let repo = self.home.join("repo");
        fs::create_dir_all(&repo).unwrap();
        self.git_ok(&repo, &["init", "-q", "-b", "work"]);
        fs::write(repo.join("base.txt"), "base\n").unwrap();
        self.git_ok(&repo, &["add", "base.txt"]);
        self.git_ok(&repo, &["commit", "-q", "-m", "base"]);
        repo
    }

    /// A tree: HEAD's plus `file` with `content`, made with a throwaway
    /// index.
    fn tree_with(&self, repo: &Path, file: &str, content: &str) -> String {
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
        with_index(&["read-tree", "HEAD"]);
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

    /// Makes git name `file` as its allowed-signers file.
    fn name_allowed_signers_file(&self, file: &Path) {
        let mut config = fs::read_to_string(&self.global_config).unwrap();
        config.push_str(&format!(
            "[gpg \"ssh\"]\n\tallowedSignersFile = \"{}\"\n",
            file.display()
        ));
        fs::write(&self.global_config, config).unwrap();
    }
}

// ---------------------------------------------------------------------------
// The fixture: a repository, a trust file holding one authority, and
// commits signed in the ways the verdicts tell apart.
// ---------------------------------------------------------------------------

struct Fixture {
    w: World,
    repo: PathBuf,
    head: String,
    principal: String,
    subject: SigningKey,
}

impl Fixture {
    /// With a trust file naming the authority with [`TRUSTED_CA_SEED`] for
    /// this machine's agents.
    fn new() -> Fixture {
        let f = Fixture::without_trust_file();
        let allowed = f.w.home.join("trusted_allowed_signers");
        fs::write(
            &allowed,
            format!(
                "*@{DOMAIN} cert-authority {}\n",
                pub_line(&key(TRUSTED_CA_SEED))
            ),
        )
        .unwrap();
        f.w.name_allowed_signers_file(&allowed);
        f
    }

    /// As [`Fixture::new`], but git names no allowed-signers file.
    fn without_trust_file() -> Fixture {
        let w = World::new();
        let repo = w.repo();
        let head = w.git_ok(&repo, &["rev-parse", "HEAD"]);
        Fixture {
            w,
            repo,
            head,
            principal: principal_for("claude-code", "verify-json-session"),
            subject: key(SUBJECT_SEED),
        }
    }

    /// A commit signed with a certificate from the authority with `ca_seed`
    /// carrying `attestation`, dated `when`.
    fn commit(
        &self,
        ca_seed: [u8; 32],
        attestation: Option<&str>,
        when: u64,
        name: &str,
    ) -> String {
        let cert = cert(ca_seed, &self.principal, &self.subject, attestation);
        let tree = self.w.tree_with(&self.repo, name, &format!("{name}\n"));
        let ident = agent_ident(&self.principal);
        let buffer = commit_buffer_at(&tree, &[&self.head], &ident, when, name);
        let sig = sshsig(&cert, &self.subject, "git", &buffer);
        self.w.write_signed_commit(&self.repo, &buffer, &sig)
    }

    /// A trusted, attested-by-`attestation` commit dated now.
    fn trusted(&self, attestation: Option<&str>, name: &str) -> String {
        self.commit(TRUSTED_CA_SEED, attestation, now_secs(), name)
    }

    fn agent_sign(&self, args: &[&str]) -> Output {
        let mut cmd = self.w.cmd(Path::new(env!("CARGO_BIN_EXE_agent-sign")));
        cmd.args(args).current_dir(&self.repo);
        run_within(cmd, "agent-sign verify")
    }

    /// `agent-sign verify --format json <rev>`: the output, and the single
    /// JSON object it must have printed (a failure of the test, with what
    /// was printed, when it isn't one).
    fn json(&self, rev: &str) -> (Output, Value) {
        let out = self.agent_sign(&["verify", "--format", "json", rev]);
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let value = parse_one_object(&stdout).unwrap_or_else(|why| {
            panic!(
                "`agent-sign verify --format json {rev}` didn't print one JSON object ({why}):\n{}",
                text(&out)
            )
        });
        (out, value)
    }

    /// `agent-sign verify <rev>`, the human form.
    fn human(&self, rev: &str) -> Output {
        self.agent_sign(&["verify", rev])
    }
}

/// `stdout` parsed as exactly one JSON object: nothing before it, nothing
/// after it.
fn parse_one_object(stdout: &str) -> Result<Value, String> {
    let trimmed = stdout.trim();
    if !trimmed.starts_with('{') {
        return Err("stdout doesn't start with {".to_string());
    }
    match serde_json::from_str::<Value>(trimmed) {
        Ok(v) if v.is_object() => Ok(v),
        Ok(_) => Err("it isn't an object".to_string()),
        Err(e) => Err(format!("{e}")),
    }
}

// ---------------------------------------------------------------------------
// Helpers for this file.
// ---------------------------------------------------------------------------

/// The seed of a plain (non-certificate) signing key.
const PLAIN_SEED: [u8; 32] = [77; 32];
/// The trust file the system-mode path names.
const SYSTEM_TRUST_FILE: &str = "/etc/agent-sign/allowed_signers";
/// A committer email's control bytes: an ANSI colour escape.
const ESC: &str = "\u{1b}[31m";

fn plain_key_blob(k: &SigningKey) -> Vec<u8> {
    let mut blob = Vec::new();
    put_string(&mut blob, b"ssh-ed25519");
    put_string(&mut blob, k.verifying_key().as_bytes());
    blob
}

/// A zlib stream holding `data` in stored (uncompressed) deflate blocks, so
/// the tests need no compression library. `data` is at most 65535 bytes.
fn zlib_stored(data: &[u8]) -> Vec<u8> {
    assert!(data.len() <= 0xffff, "test object too large for one block");
    let mut out = vec![0x78, 0x01, 0x01];
    out.extend_from_slice(&(data.len() as u16).to_le_bytes());
    out.extend_from_slice(&(!(data.len() as u16)).to_le_bytes());
    out.extend_from_slice(data);
    let (mut a, mut b) = (1u32, 0u32);
    for byte in data {
        a = (a + u32::from(*byte)) % 65521;
        b = (b + a) % 65521;
    }
    out.extend_from_slice(&((b << 16) | a).to_be_bytes());
    out
}

/// What `stdout`/`stderr` must not hold: any control byte but a newline or
/// tab (ESC included), or DEL.
fn has_control_bytes(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .any(|b| (*b < 0x20 && *b != b'\n' && *b != b'\t') || *b == 0x7f)
}

fn same_file(a: &str, b: &Path) -> bool {
    match (fs::canonicalize(a), fs::canonicalize(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => Path::new(a) == b,
    }
}

impl Fixture {
    /// A trust file naming only an authority the attacker made.
    fn attacker_trust(&self) -> PathBuf {
        let path = self.w.home.join("attacker_allowed_signers");
        fs::write(
            &path,
            format!(
                "*@{DOMAIN} cert-authority {}\n",
                pub_line(&key(UNTRUSTED_CA_SEED))
            ),
        )
        .unwrap();
        path
    }

    /// The real trust file [`Fixture::new`] wrote (and global config names).
    fn real_trust(&self) -> PathBuf {
        self.w.home.join("trusted_allowed_signers")
    }

    /// A commit by the attacker's own authority, claiming a launcher.
    fn attacker_commit(&self, name: &str) -> String {
        self.commit(UNTRUSTED_CA_SEED, Some(LAUNCHER), now_secs(), name)
    }

    /// agent-sign in `dir` with `args`, `set` added to the environment and
    /// `unset` removed from it.
    fn run_in(
        &self,
        dir: &Path,
        args: &[&str],
        set: &[(&str, OsString)],
        unset: &[&str],
    ) -> Output {
        let mut cmd = self.w.cmd(Path::new(env!("CARGO_BIN_EXE_agent-sign")));
        cmd.args(args).current_dir(dir);
        for name in unset {
            cmd.env_remove(name);
        }
        for (name, value) in set {
            cmd.env(name, value);
        }
        run_within(cmd, "agent-sign verify")
    }

    /// `verify --format json <flags...> <rev>` in `dir`: the output and the
    /// one JSON object.
    fn json_in(
        &self,
        dir: &Path,
        flags: &[&str],
        rev: &str,
        set: &[(&str, OsString)],
        unset: &[&str],
    ) -> (Output, Value) {
        let mut args = vec!["verify", "--format", "json"];
        args.extend_from_slice(flags);
        args.push(rev);
        let out = self.run_in(dir, &args, set, unset);
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let value = parse_one_object(&stdout).unwrap_or_else(|why| {
            panic!(
                "`agent-sign {args:?}` didn't print one JSON object ({why}):\n{}",
                text(&out)
            )
        });
        (out, value)
    }

    /// The exact bytes of commit `rev`'s object, as git reads it.
    fn raw_commit(&self, rev: &str) -> Vec<u8> {
        let out = self.w.git(&self.repo, &["cat-file", "commit", rev]);
        assert!(out.status.success(), "setup cat-file: {}", text(&out));
        out.stdout
    }

    /// An unsigned commit object with a tree of its own.
    fn unsigned_commit(&self, name: &str) -> String {
        let tree = self.w.tree_with(&self.repo, name, &format!("{name}\n"));
        let buffer = commit_buffer_at(
            &tree,
            &[&self.head],
            &agent_ident(&self.principal),
            now_secs(),
            name,
        );
        self.w.git_stdin(
            &self.repo,
            &["hash-object", "-t", "commit", "-w", "--stdin"],
            &buffer,
        )
    }

    /// The allowed-signers file git (with `set` added to its environment)
    /// reads in `dir`, or "" if it names none: the precondition of every
    /// F2 test, so a broken setup can't pass for a fixed verifier.
    fn git_names(&self, dir: &Path, set: &[(&str, OsString)]) -> String {
        let mut cmd = self.w.cmd(&self.w.real_git);
        cmd.args(["config", "--get", "--path", "gpg.ssh.allowedSignersFile"])
            .current_dir(dir);
        for (name, value) in set {
            cmd.env(name, value);
        }
        let out = run_within(cmd, "git config");
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }
}

/// An F2 verdict: the attacker's commit is neither verified nor attested,
/// the reason is one of the two that mean "your trust file doesn't hold the
/// authority", and the exit status is 1.
fn assert_attacker_refused(out: &Output, v: &Value, how: &str) {
    assert!(
        v["reason"] == "untrusted_authority" || v["reason"] == "no_trust_file",
        "{how}: reason must be untrusted_authority or no_trust_file, not {}: {}",
        v["reason"],
        text(out)
    );
    assert_eq!(v["verified"], false, "{how}: verified: {}", text(out));
    assert_eq!(v["attested"], false, "{how}: attested: {}", text(out));
    assert_eq!(
        v["attestation"],
        "none",
        "{how}: attestation: {}",
        text(out)
    );
    assert_eq!(
        out.status.code(),
        Some(1),
        "{how}: exit code: {}",
        text(out)
    );
}

/// A verdict of "launcher, ok, exit 0" whose `trust_file` names `file`.
fn assert_ok_with_trust_file(out: &Output, v: &Value, file: &Path, how: &str) {
    assert_eq!(v["reason"], "ok", "{how}: reason: {}", text(out));
    assert_eq!(v["verified"], true, "{how}: verified: {}", text(out));
    assert_eq!(v["attested"], true, "{how}: attested: {}", text(out));
    assert_eq!(
        v["attestation"],
        "launcher",
        "{how}: attestation: {}",
        text(out)
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "{how}: exit code: {}",
        text(out)
    );
    for field in FIELDS {
        assert!(
            v.get(field).is_some(),
            "{how}: the six existing fields stay ({field} missing): {}",
            text(out)
        );
    }
    let named = v["trust_file"].as_str().unwrap_or_else(|| {
        panic!(
            "{how}: the JSON must name the trust file used in `trust_file`: {}",
            text(out)
        )
    });
    assert!(
        same_file(named, file),
        "{how}: trust_file is {named}, expected {}: {}",
        file.display(),
        text(out)
    );
}

// ---------------------------------------------------------------------------
// F1: replace refs and planted objects.
// ---------------------------------------------------------------------------

/// The reviewer's probe. An attacker pushes `refs/replace/<U>` pointing at a
/// real attested commit G; U is unsigned. `GIT_NO_REPLACE_OBJECTS` is not set
/// by the test. `verify U` must say what U is (unsigned, exit 1), never
/// what G is.
///
/// Fails today: `verify` runs git without `--no-replace-objects`, so
/// `cat-file commit U` returns G's bytes and the verdict is verified,
/// attested, "launcher", exit 0.
#[test]
fn f1_a_replace_ref_cannot_turn_an_unsigned_commit_into_an_attested_one() {
    let f = Fixture::new();
    assert!(
        std::env::var_os("GIT_NO_REPLACE_OBJECTS").is_none(),
        "the test must not set GIT_NO_REPLACE_OBJECTS"
    );
    let g = f.trusted(Some(LAUNCHER), "g.txt");
    let u = f.unsigned_commit("u.txt");
    f.w.git_ok(&f.repo, &["update-ref", &format!("refs/replace/{u}"), &g]);
    // The probe is real: git itself, asked for U, serves G.
    assert_eq!(
        f.raw_commit(&u),
        f.raw_commit(&g),
        "setup: the replace ref doesn't make git serve G for U"
    );
    let (out, v) = f.json(&u);
    assert_eq!(v["verified"], false, "verified: {}", text(&out));
    assert_eq!(v["attested"], false, "attested: {}", text(&out));
    assert_eq!(v["attestation"], "none", "attestation: {}", text(&out));
    assert_eq!(
        v["reason"],
        "unsigned",
        "reason (U is unsigned): {}",
        text(&out)
    );
    assert_eq!(out.status.code(), Some(1), "exit code: {}", text(&out));
}

/// A loose object planted at U's own path holds G's content (a zlib stream of
/// `commit <len>\0` and G's bytes), so `git cat-file commit U` returns G's
/// bytes. `verify U` must refuse because the bytes it read don't hash to U:
/// reason `error`, exit 1 (I-F1), not verified, not attested, and the detail
/// says the object doesn't match its name (it names U and says "hash" or
/// "match").
///
/// Defence in depth, and honest about it: on git 2.53 `rev-parse --verify
/// U^{commit}` already refuses such an object ("hash mismatch"; tried with
/// and without a commit-graph), so today `verify` never reaches `cat-file`
/// and does not report G's verdict. It is red today only in HOW it refuses:
/// the generic "isn't a commit in this repository", exit 2, instead of the
/// re-hash mismatch message and exit 1. The re-hash is what keeps this
/// closed if git's own check is ever bypassed.
#[test]
fn f1_a_planted_object_whose_content_does_not_hash_to_its_name_is_refused() {
    let f = Fixture::new();
    let g = f.trusted(Some(LAUNCHER), "g.txt");
    let g_raw = f.raw_commit(&g);
    let u = f.unsigned_commit("u.txt");
    let path = f.repo.join(".git/objects").join(&u[..2]).join(&u[2..]);
    assert!(path.is_file(), "setup: U isn't a loose object");
    let mut body = format!("commit {}\0", g_raw.len()).into_bytes();
    body.extend_from_slice(&g_raw);
    fs::remove_file(&path).unwrap();
    fs::write(&path, zlib_stored(&body)).unwrap();
    // The probe is real: git itself, asked for U, serves G's bytes.
    assert_eq!(
        f.raw_commit(&u),
        g_raw,
        "setup: git doesn't serve G's bytes for the planted object"
    );
    let (out, v) = f.json(&u);
    assert_eq!(v["verified"], false, "verified: {}", text(&out));
    assert_eq!(v["attested"], false, "attested: {}", text(&out));
    assert_eq!(v["reason"], "error", "reason: {}", text(&out));
    assert_eq!(
        out.status.code(),
        Some(1),
        "exit code (I-F1: 1, not 0): {}",
        text(&out)
    );
    let detail = v["detail"].as_str().unwrap_or_default().to_lowercase();
    assert!(
        detail.contains(&u) && (detail.contains("hash") || detail.contains("match")),
        "the detail must name the object and say its content doesn't match (hash/match): {}",
        text(&out)
    );
    assert!(!detail.contains("good signature"), "{}", text(&out));
}

// ---------------------------------------------------------------------------
// F2: where the trust file comes from.
// ---------------------------------------------------------------------------

/// The attacker's own certificate authority, trusted only through the
/// repository's own `.git/config`: the verdict stays not ok.
///
/// Fails today: `verify` asks git with no scope flag, so local config wins
/// over the person's global one, and the verdict is ok, launcher, exit 0.
#[test]
fn f2_a_trust_file_named_in_the_repos_own_config_is_not_believed() {
    let f = Fixture::new();
    let attacker = f.attacker_trust();
    let evil = f.attacker_commit("evil.txt");
    f.w.git_ok(
        &f.repo,
        &[
            "config",
            "--local",
            "gpg.ssh.allowedSignersFile",
            attacker.to_str().unwrap(),
        ],
    );
    assert_eq!(
        f.git_names(&f.repo, &[]),
        attacker.to_str().unwrap(),
        "setup"
    );
    let (out, v) = f.json(&evil);
    assert_attacker_refused(&out, &v, ".git/config");
}

/// As above, through a linked worktree's `config.worktree`
/// (`extensions.worktreeConfig`), with `verify` run in the worktree.
///
/// Fails today: worktree-scope config is read like any other.
#[test]
fn f2_a_trust_file_named_in_a_worktrees_config_is_not_believed() {
    let f = Fixture::new();
    let attacker = f.attacker_trust();
    let evil = f.attacker_commit("evil.txt");
    f.w.git_ok(&f.repo, &["config", "extensions.worktreeConfig", "true"]);
    let wt = f.w.home.join("wt");
    f.w.git_ok(
        &f.repo,
        &[
            "worktree",
            "add",
            "-q",
            "--detach",
            wt.to_str().unwrap(),
            "HEAD",
        ],
    );
    f.w.git_ok(
        &wt,
        &[
            "config",
            "--worktree",
            "gpg.ssh.allowedSignersFile",
            attacker.to_str().unwrap(),
        ],
    );
    assert_eq!(f.git_names(&wt, &[]), attacker.to_str().unwrap(), "setup");
    let (out, v) = f.json_in(&wt, &[], &evil, &[], &[]);
    assert_attacker_refused(&out, &v, "config.worktree");
}

/// As above, through `GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_0`/`GIT_CONFIG_VALUE_0`
/// in `verify`'s own environment (what a session that can set the
/// environment of the gate's run would use).
///
/// Fails today: git honours command-scope config.
#[test]
fn f2_a_trust_file_named_in_git_config_count_variables_is_not_believed() {
    let f = Fixture::new();
    let attacker = f.attacker_trust();
    let evil = f.attacker_commit("evil.txt");
    let set: Vec<(&str, OsString)> = vec![
        ("GIT_CONFIG_COUNT", "1".into()),
        ("GIT_CONFIG_KEY_0", "gpg.ssh.allowedSignersFile".into()),
        ("GIT_CONFIG_VALUE_0", attacker.clone().into_os_string()),
    ];
    assert_eq!(
        f.git_names(&f.repo, &set),
        attacker.to_str().unwrap(),
        "setup"
    );
    let (out, v) = f.json_in(&f.repo, &[], &evil, &set, &[]);
    assert_attacker_refused(&out, &v, "GIT_CONFIG_COUNT");
}

/// As above, through `GIT_CONFIG_PARAMETERS` (the variable `git -c` sets
/// and passes to its children).
///
/// Fails today: git honours command-scope config.
#[test]
fn f2_a_trust_file_named_in_git_config_parameters_is_not_believed() {
    let f = Fixture::new();
    let attacker = f.attacker_trust();
    let evil = f.attacker_commit("evil.txt");
    let set: Vec<(&str, OsString)> = vec![(
        "GIT_CONFIG_PARAMETERS",
        format!("'gpg.ssh.allowedsignersfile={}'", attacker.display()).into(),
    )];
    assert_eq!(
        f.git_names(&f.repo, &set),
        attacker.to_str().unwrap(),
        "setup"
    );
    let (out, v) = f.json_in(&f.repo, &[], &evil, &set, &[]);
    assert_attacker_refused(&out, &v, "GIT_CONFIG_PARAMETERS");
}

/// As above, through an `includeIf` in the repository's config that pulls
/// in a file naming the attacker's trust file.
///
/// Fails today: includes in the repository's config are followed.
#[test]
fn f2_a_trust_file_named_through_an_includeif_in_the_repo_config_is_not_believed() {
    let f = Fixture::new();
    let attacker = f.attacker_trust();
    let evil = f.attacker_commit("evil.txt");
    let inc = f.w.home.join("attacker.inc.gitconfig");
    fs::write(
        &inc,
        format!(
            "[gpg \"ssh\"]\n\tallowedSignersFile = \"{}\"\n",
            attacker.display()
        ),
    )
    .unwrap();
    let repo = fs::canonicalize(&f.repo).unwrap();
    let config = repo.join(".git/config");
    let mut text_now = fs::read_to_string(&config).unwrap();
    text_now.push_str(&format!(
        "[includeIf \"gitdir:{}/\"]\n\tpath = {}\n",
        repo.display(),
        inc.display()
    ));
    fs::write(&config, text_now).unwrap();
    assert_eq!(
        f.git_names(&f.repo, &[]),
        attacker.to_str().unwrap(),
        "setup"
    );
    let (out, v) = f.json(&evil);
    assert_attacker_refused(&out, &v, "includeIf");
}

/// The same attack when git names no trust file at all outside the
/// repository (the person's global config is bare): the attacker's file in
/// `.git/config` must still not be believed (reason `no_trust_file`, or
/// `untrusted_authority`).
///
/// Fails today: the local file is the only one, and it is believed.
#[test]
fn f2_with_no_global_trust_file_the_repos_own_config_still_gives_none() {
    let f = Fixture::without_trust_file();
    let attacker = f.attacker_trust();
    let evil = f.attacker_commit("evil.txt");
    f.w.git_ok(
        &f.repo,
        &[
            "config",
            "--local",
            "gpg.ssh.allowedSignersFile",
            attacker.to_str().unwrap(),
        ],
    );
    let (out, v) = f.json(&evil);
    assert_attacker_refused(&out, &v, "no global trust file");
}

/// Control: with a hostile `.git/config` naming a file that lacks the real
/// authority, a good commit still verifies ok through the global config the
/// person set (`GIT_CONFIG_GLOBAL`), and the JSON names that file.
///
/// Fails today: the hostile local file wins (untrusted_authority), and
/// there is no `trust_file` field.
#[test]
fn f2_control_the_global_config_names_the_trust_file_and_the_json_says_which() {
    let f = Fixture::new();
    let attacker = f.attacker_trust();
    let good = f.trusted(Some(LAUNCHER), "good.txt");
    f.w.git_ok(
        &f.repo,
        &[
            "config",
            "--local",
            "gpg.ssh.allowedSignersFile",
            attacker.to_str().unwrap(),
        ],
    );
    let (out, v) = f.json(&good);
    assert_ok_with_trust_file(&out, &v, &f.real_trust(), "global config");
}

/// Control: the plain case, no hostile config at all: global config names
/// the trust file, the commit verifies ok, and the JSON names the file.
///
/// Fails today only on the missing `trust_file` field.
#[test]
fn f2_control_a_good_commit_verifies_and_the_json_names_the_global_trust_file() {
    let f = Fixture::new();
    let good = f.trusted(Some(LAUNCHER), "good.txt");
    let (out, v) = f.json(&good);
    assert_ok_with_trust_file(&out, &v, &f.real_trust(), "plain");
}

/// Control: `--allowed-signers <the real trust file>` names the trust file
/// explicitly and wins over a hostile `.git/config`: the good commit
/// verifies ok and the JSON names that file.
///
/// Fails today: `--allowed-signers` isn't an option.
#[test]
fn f2_control_allowed_signers_names_the_trust_file_explicitly() {
    let f = Fixture::new();
    let attacker = f.attacker_trust();
    let good = f.trusted(Some(LAUNCHER), "good.txt");
    f.w.git_ok(
        &f.repo,
        &[
            "config",
            "--local",
            "gpg.ssh.allowedSignersFile",
            attacker.to_str().unwrap(),
        ],
    );
    let real = f.real_trust();
    let (out, v) = f.json_in(
        &f.repo,
        &["--allowed-signers", real.to_str().unwrap()],
        &good,
        &[],
        &[],
    );
    assert_ok_with_trust_file(&out, &v, &real, "--allowed-signers");
}

/// Control: with no trust file in any git config, `--allowed-signers` alone
/// is enough (what a server-side gate with a bare environment does).
///
/// Fails today: `--allowed-signers` isn't an option.
#[test]
fn f2_control_allowed_signers_needs_no_git_config_at_all() {
    let f = Fixture::without_trust_file();
    let real = f.w.home.join("gate_allowed_signers");
    fs::write(
        &real,
        format!(
            "*@{DOMAIN} cert-authority {}\n",
            pub_line(&key(TRUSTED_CA_SEED))
        ),
    )
    .unwrap();
    let good = f.trusted(Some(LAUNCHER), "good.txt");
    let (out, v) = f.json_in(
        &f.repo,
        &["--allowed-signers", real.to_str().unwrap()],
        &good,
        &[],
        &[],
    );
    assert_ok_with_trust_file(&out, &v, &real, "--allowed-signers alone");
}

/// Control: the system git config scope (`GIT_CONFIG_SYSTEM`, with
/// `GIT_CONFIG_NOSYSTEM` unset) is read, since it is the machine's own.
///
/// Fails today only on the missing `trust_file` field.
#[test]
fn f2_control_the_system_git_config_scope_is_read() {
    let f = Fixture::without_trust_file();
    let real = f.w.home.join("sysscope_allowed_signers");
    fs::write(
        &real,
        format!(
            "*@{DOMAIN} cert-authority {}\n",
            pub_line(&key(TRUSTED_CA_SEED))
        ),
    )
    .unwrap();
    let sys_config = f.w.home.join("system.gitconfig");
    fs::write(
        &sys_config,
        format!(
            "[gpg \"ssh\"]\n\tallowedSignersFile = \"{}\"\n",
            real.display()
        ),
    )
    .unwrap();
    let good = f.trusted(Some(LAUNCHER), "good.txt");
    let (out, v) = f.json_in(
        &f.repo,
        &[],
        &good,
        &[("GIT_CONFIG_SYSTEM", sys_config.clone().into_os_string())],
        &["GIT_CONFIG_NOSYSTEM"],
    );
    assert_ok_with_trust_file(&out, &v, &real, "system git config scope");
}

/// System mode (`/etc/agent-sign/system.toml` exists, here the stand-in
/// named by `AGENT_SIGN_TEST_SYSTEM_CONFIG`): the trust file is
/// `/etc/agent-sign/allowed_signers`, always, so a good commit that
/// verifies under the person's global config does NOT verify here, since
/// that file (and the one next to the stand-in) doesn't hold the test's
/// authority. Exit 1, reason `no_trust_file` or `untrusted_authority`.
///
/// Fails today: the global config is believed in system mode (ok, exit 0).
///
/// Needs no seam assumption beyond `AGENT_SIGN_TEST_SYSTEM_CONFIG`.
#[test]
fn f2_system_mode_pins_the_trust_file_whatever_git_config_says() {
    let f = Fixture::new();
    let good = f.trusted(Some(LAUNCHER), "good.txt");
    let system_dir = f.w.home.join("etc-agent-sign");
    fs::create_dir_all(&system_dir).unwrap();
    let stand_in = system_dir.join("system.toml");
    fs::write(&stand_in, "# system mode, for the test\n").unwrap();
    assert!(
        !Path::new(SYSTEM_TRUST_FILE).exists(),
        "setup: this machine has {SYSTEM_TRUST_FILE}; the test needs it absent"
    );
    let (out, v) = f.json_in(
        &f.repo,
        &[],
        &good,
        &[("AGENT_SIGN_TEST_SYSTEM_CONFIG", stand_in.into_os_string())],
        &[],
    );
    assert!(
        v["reason"] == "no_trust_file" || v["reason"] == "untrusted_authority",
        "reason must be no_trust_file or untrusted_authority, not {}: {}",
        v["reason"],
        text(&out)
    );
    assert_eq!(v["verified"], false, "verified: {}", text(&out));
    assert_eq!(v["attested"], false, "attested: {}", text(&out));
    assert_eq!(out.status.code(), Some(1), "exit code: {}", text(&out));
}

/// System mode, with the SEAM ASSUMPTION that under
/// `AGENT_SIGN_TEST_SYSTEM_CONFIG` the trust file is `allowed_signers` next
/// to that file (the stand-in for `/etc/agent-sign/allowed_signers`): that
/// file holds the real authority; both the global and the repository's
/// config name the attacker's file. The good commit verifies ok, and the JSON
/// names the file next to the stand-in. If the builder's seam differs, this
/// is the one test to adapt (and say so).
///
/// Fails today: the config-named attacker file is used (untrusted_authority).
#[test]
fn system_mode_trust_file_sits_next_to_the_system_config() {
    let f = Fixture::without_trust_file();
    let attacker = f.attacker_trust();
    f.w.name_allowed_signers_file(&attacker);
    f.w.git_ok(
        &f.repo,
        &[
            "config",
            "--local",
            "gpg.ssh.allowedSignersFile",
            attacker.to_str().unwrap(),
        ],
    );
    let system_dir = f.w.home.join("etc-agent-sign");
    fs::create_dir_all(&system_dir).unwrap();
    let stand_in = system_dir.join("system.toml");
    fs::write(&stand_in, "# system mode, for the test\n").unwrap();
    let pinned = system_dir.join("allowed_signers");
    fs::write(
        &pinned,
        format!(
            "*@{DOMAIN} cert-authority {}\n",
            pub_line(&key(TRUSTED_CA_SEED))
        ),
    )
    .unwrap();
    let good = f.trusted(Some(LAUNCHER), "good.txt");
    let (out, v) = f.json_in(
        &f.repo,
        &[],
        &good,
        &[("AGENT_SIGN_TEST_SYSTEM_CONFIG", stand_in.into_os_string())],
        &[],
    );
    assert_ok_with_trust_file(
        &out,
        &v,
        &pinned,
        "system mode, trust file next to the stand-in",
    );
}

// ---------------------------------------------------------------------------
// F3: the human form's exit status.
// ---------------------------------------------------------------------------

/// The human form of `verify` for `rev`: its exit code, which must equal the
/// JSON form's, and the JSON verdict it is compared with.
fn human_and_json(f: &Fixture, rev: &str) -> (Output, Output, Value) {
    let human = f.human(rev);
    let (json_out, v) = f.json(rev);
    (human, json_out, v)
}

fn assert_human_exits_as_json(f: &Fixture, rev: &str, reason: &str, verified: bool) {
    let (human, json_out, v) = human_and_json(f, rev);
    // The JSON half is today's behaviour: the commit is what the test says.
    assert_eq!(
        v["reason"],
        reason,
        "setup: the JSON reason: {}",
        text(&json_out)
    );
    assert_eq!(
        v["verified"],
        verified,
        "setup: the JSON verified: {}",
        text(&json_out)
    );
    assert_eq!(
        json_out.status.code(),
        Some(1),
        "setup: the JSON exit: {}",
        text(&json_out)
    );
    assert_eq!(
        human.status.code(),
        Some(1),
        "the human form must exit 1 for a {reason} commit, as the JSON form does: {}",
        text(&human)
    );
}

/// A certificate from the trusted authority with no attestation extension
/// (a name only claimed): the human form exits 1.
///
/// Fails today: it prints "verified: ..." and exits 0.
#[test]
fn f3_human_form_exits_1_for_a_claimed_commit() {
    let f = Fixture::new();
    let c = f.trusted(None, "claimed.txt");
    assert_human_exits_as_json(&f, &c, "claimed", true);
}

/// A certificate whose extension says `unattested`: the human form exits 1.
///
/// Fails today: exits 0.
#[test]
fn f3_human_form_exits_1_for_an_unattested_commit() {
    let f = Fixture::new();
    let c = f.trusted(Some(UNATTESTED), "unattested.txt");
    assert_human_exits_as_json(&f, &c, "unattested", true);
}

/// A certificate whose attestation extension is junk (it doesn't decode):
/// the human form exits 1.
///
/// Fails today: exits 0.
#[test]
fn f3_human_form_exits_1_for_a_junk_attestation() {
    let f = Fixture::new();
    let c = f.trusted(
        Some("launcher session=zz uid=x isolation=nowhere"),
        "junk.txt",
    );
    assert_human_exits_as_json(&f, &c, "claimed", true);
}

/// A commit signed with a plain key that the trust file lists for the
/// principal (no certificate, so nothing established the name): the human
/// form exits 1.
///
/// Fails today: exits 0.
#[test]
fn f3_human_form_exits_1_for_a_plain_key_signature() {
    let f = Fixture::new();
    let plain = key(PLAIN_SEED);
    let mut trust = fs::read_to_string(f.real_trust()).unwrap();
    trust.push_str(&format!("{} {}\n", f.principal, pub_line(&plain)));
    fs::write(f.real_trust(), trust).unwrap();
    let tree = f.w.tree_with(&f.repo, "plain.txt", "plain\n");
    let buffer = commit_buffer_at(
        &tree,
        &[&f.head],
        &agent_ident(&f.principal),
        now_secs(),
        "plain",
    );
    let sig = sshsig(&plain_key_blob(&plain), &plain, "git", &buffer);
    let c = f.w.write_signed_commit(&f.repo, &buffer, &sig);
    assert_human_exits_as_json(&f, &c, "claimed", true);
}

/// Control: an unsigned commit: the human form exits 1.
///
/// Passes today (pins what must not change).
#[test]
fn f3_control_human_form_exits_1_for_an_unsigned_commit() {
    let f = Fixture::new();
    assert_human_exits_as_json(&f, &f.head, "unsigned", false);
}

/// Control: an untrusted authority: the human form exits 1.
///
/// Passes today (pins what must not change).
#[test]
fn f3_control_human_form_exits_1_for_an_untrusted_authority() {
    let f = Fixture::new();
    let c = f.attacker_commit("untrusted.txt");
    assert_human_exits_as_json(&f, &c, "untrusted_authority", false);
}

/// Control: a good attested commit: the human form exits 0 and says so.
///
/// Passes today (pins what must not change).
#[test]
fn f3_control_human_form_exits_0_for_a_launched_commit() {
    let f = Fixture::new();
    let c = f.trusted(Some(LAUNCHER), "launched.txt");
    let out = f.human(&c);
    assert_eq!(out.status.code(), Some(0), "exit code: {}", text(&out));
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("verified: Good signature for"),
        "{}",
        text(&out)
    );
}

// ---------------------------------------------------------------------------
// F7: ssh-keygen by absolute path; terminal escapes in human text.
// ---------------------------------------------------------------------------

/// A committer email holding an ESC byte, where the certificate is for
/// someone else: the human form's refusal names the committer, and must not
/// print the ESC raw (nor any control byte) on either stream. The JSON form
/// (already escaped by JSON) must not hold a raw ESC either.
///
/// Fails today: the refusal prints the email verbatim.
#[test]
fn f7_an_escape_in_the_committer_email_never_reaches_the_human_refusal_raw() {
    let f = Fixture::new();
    let esc_principal = format!("claude-code.{}{ESC}@{DOMAIN}", session8("esc"));
    // A certificate for the ordinary principal; the commit's committer is
    // the escape-bearing email: "the certificate isn't for the committer".
    let cert = cert(TRUSTED_CA_SEED, &f.principal, &f.subject, Some(LAUNCHER));
    let tree = f.w.tree_with(&f.repo, "esc.txt", "esc\n");
    let buffer = commit_buffer_at(
        &tree,
        &[&f.head],
        &agent_ident(&esc_principal),
        now_secs(),
        "esc",
    );
    let sig = sshsig(&cert, &f.subject, "git", &buffer);
    let c = f.w.write_signed_commit(&f.repo, &buffer, &sig);
    let human = f.human(&c);
    assert!(
        !human.stdout.is_empty() || !human.stderr.is_empty(),
        "the human form printed nothing: {}",
        text(&human)
    );
    assert!(
        !has_control_bytes(&human.stdout) && !has_control_bytes(&human.stderr),
        "a control byte reached the human output raw: {:?} / {:?}",
        String::from_utf8_lossy(&human.stdout),
        String::from_utf8_lossy(&human.stderr)
    );
    assert_eq!(human.status.code(), Some(1), "exit code: {}", text(&human));
    let (json_out, _) = f.json(&c);
    assert!(
        !has_control_bytes(&json_out.stdout),
        "a control byte reached the JSON output raw: {}",
        text(&json_out)
    );
}

/// As above where the certificate does name the escape-bearing email and the
/// authority is trusted (the verified path, and wherever ssh-keygen's
/// refusal quotes the principal): no control byte on either stream.
///
/// Fails today: the principal is printed verbatim ("verified: Good
/// signature for ..." or the refusal's detail).
#[test]
fn f7_an_escape_in_a_certified_principal_never_reaches_the_human_output_raw() {
    let f = Fixture::new();
    let esc_principal = format!("claude-code.{}{ESC}@{DOMAIN}", session8("esc2"));
    let cert = cert(TRUSTED_CA_SEED, &esc_principal, &f.subject, Some(LAUNCHER));
    let tree = f.w.tree_with(&f.repo, "esc2.txt", "esc2\n");
    let buffer = commit_buffer_at(
        &tree,
        &[&f.head],
        &agent_ident(&esc_principal),
        now_secs(),
        "esc2",
    );
    let sig = sshsig(&cert, &f.subject, "git", &buffer);
    let c = f.w.write_signed_commit(&f.repo, &buffer, &sig);
    let human = f.human(&c);
    assert!(
        !human.stdout.is_empty() || !human.stderr.is_empty(),
        "the human form printed nothing: {}",
        text(&human)
    );
    assert!(
        !has_control_bytes(&human.stdout) && !has_control_bytes(&human.stderr),
        "a control byte reached the human output raw: {:?} / {:?}",
        String::from_utf8_lossy(&human.stdout),
        String::from_utf8_lossy(&human.stderr)
    );
}

/// `ssh-keygen` is run by absolute path, as the signing program does, never
/// found through `PATH`: a fake `ssh-keygen` first on `PATH` (it records that
/// it ran, then hands over to the real one so the verdict is unaffected)
/// must not be run, and the good commit still verifies.
///
/// Fails today: `verify` runs `ssh-keygen` from `PATH`, so the fake runs.
#[test]
fn f7_ssh_keygen_is_run_by_absolute_path_not_found_on_path() {
    let f = Fixture::new();
    let good = f.trusted(Some(LAUNCHER), "good.txt");
    let real_keygen = ["/usr/bin/ssh-keygen", "/usr/local/bin/ssh-keygen"]
        .into_iter()
        .find(|p| Path::new(p).exists())
        .expect("setup: no system ssh-keygen");
    let fake_dir = f.w.home.join("fakebin");
    fs::create_dir_all(&fake_dir).unwrap();
    let marker = f.w.home.join("fake-ssh-keygen-ran");
    let fake = fake_dir.join("ssh-keygen");
    fs::write(
        &fake,
        format!(
            "#!/bin/sh\necho ran >> '{}'\nexec {real_keygen} \"$@\"\n",
            marker.display()
        ),
    )
    .unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&fake, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let mut path = OsString::from(&fake_dir);
    path.push(":");
    path.push(&f.w.path);
    let (out, v) = f.json_in(&f.repo, &[], &good, &[("PATH", path)], &[]);
    assert!(
        !marker.exists(),
        "verify ran the ssh-keygen found on PATH (the fake recorded it): {}",
        text(&out)
    );
    assert_eq!(
        v["reason"],
        "ok",
        "the good commit must still verify: {}",
        text(&out)
    );
    assert_eq!(out.status.code(), Some(0), "exit code: {}", text(&out));
}

/// A repository's own config must not make `verify` run a command. A session
/// writes `.git/config` as a partial clone whose promisor remote is reached
/// through `core.sshCommand`; asked for an object the repository lacks, git
/// would lazily fetch it by running that command as the verifier. `verify`
/// tells git not to fetch lazily (`GIT_NO_LAZY_FETCH=1`), so the object is
/// simply missing: reason `error`, exit 1, and the planted command never runs.
///
/// Fails without the setting: the marker file appears.
#[test]
fn a_partial_clone_config_cannot_make_verify_run_the_sessions_command() {
    let f = Fixture::new();
    let marker = f.w.home.join("lazy-fetch-ran");
    let script = f.w.home.join("lazy-fetch.sh");
    fs::write(
        &script,
        format!("#!/bin/sh\necho ran >> '{}'\nexit 1\n", marker.display()),
    )
    .unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    }
    for (key, value) in [
        ("core.repositoryformatversion", "1"),
        ("extensions.partialClone", "origin"),
        ("remote.origin.promisor", "true"),
        ("remote.origin.partialclonefilter", "blob:none"),
        ("remote.origin.url", "ssh://lazy-fetch.invalid/repo.git"),
        ("core.sshCommand", script.to_str().unwrap()),
    ] {
        f.w.git_ok(&f.repo, &["config", "--local", key, value]);
    }
    // The setup is real: plain git, asked for the missing object, runs the command.
    let missing = "1234567890abcdef1234567890abcdef12345678";
    let probe = f.w.git(&f.repo, &["cat-file", "-t", missing]);
    assert!(!probe.status.success(), "setup: the object exists");
    assert!(
        marker.exists(),
        "setup: plain git did not run the planted command, so this test proves nothing: {}",
        text(&probe)
    );
    fs::remove_file(&marker).unwrap();

    let real = f.w.home.join("trusted_allowed_signers");
    let (out, v) = f.json_in(
        &f.repo,
        &["--allowed-signers", real.to_str().unwrap()],
        missing,
        &[],
        &[],
    );
    assert!(
        !marker.exists(),
        "verify ran the command named by the repo's own config (lazy fetch): {}",
        text(&out)
    );
    assert_eq!(v["verified"], false, "{}", text(&out));
    assert_ne!(out.status.code(), Some(0), "exit code: {}", text(&out));
}

// ===========================================================================
// Round 3 (the last): V1, V3, V5 (and V2's faithful half), written before the
// builder's fixes, as their eval (1 Nov 2026).
//
// - V1: a relative explicit `--allowed-signers` path is refused, exit 2.
// - V2: `git_command()` also sets `GIT_ALLOW_PROTOCOL=""` (no transport at
//   all, git 2.12 and later), so a lazy fetch is blocked even on a git older
//   than 2.44, where `GIT_NO_LAZY_FETCH` is ignored. The tests simulate such
//   a git faithfully: `AGENT_SIGN_REAL_GIT` names a wrapper that unsets
//   `GIT_NO_LAZY_FETCH` (exactly what an older git does with it: nothing),
//   records the `GIT_ALLOW_PROTOCOL` it was given, and runs the real git. On
//   this machine's git (2.53) the switch works, so only the wrapper shows
//   the second defence.
// - V3: Unicode format characters never reach the human output.
// - V5: shallow and partial clones: verify fetches nothing and is not ok.
//   The system-mode-ignores-global probe is the EXISTING test
//   `f2_system_mode_pins_the_trust_file_whatever_git_config_says` (global
//   config names the real trust file, system mode is on through the
//   `AGENT_SIGN_TEST_SYSTEM_CONFIG` seam, the verdict is not ok, exit 1).
// ===========================================================================

/// Writes an executable shell script.
fn write_script(path: &Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    fs::write(path, body).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

/// The authority line a trust file holds for this machine's agents.
fn authority_line() -> String {
    format!(
        "*@{DOMAIN} cert-authority {}\n",
        pub_line(&key(TRUSTED_CA_SEED))
    )
}

// ---------------------------------------------------------------------------
// V1: a relative explicit trust-file path.
// ---------------------------------------------------------------------------

/// The trust file the session being checked could write sits in the
/// checkout; a relative `--allowed-signers` is read from the current folder,
/// which is that checkout. Every spelling of a relative path, in both output
/// forms, exits 2 with a message saying to pass an absolute path, and the
/// good commit is not reported verified.
///
/// Fails today: the relative file is read and the commit verifies (exit 0).
#[test]
fn v1_a_relative_explicit_allowed_signers_path_is_refused_with_exit_2() {
    let f = Fixture::without_trust_file();
    let good = f.trusted(Some(LAUNCHER), "good.txt");
    fs::write(f.repo.join("signers"), authority_line()).unwrap();
    let spellings: [Vec<&str>; 4] = [
        vec!["--allowed-signers", "signers"],
        vec!["--allowed-signers=signers"],
        vec!["--allowed-signers", "./signers"],
        vec!["--allowed-signers", "../repo/signers"],
    ];
    let mut failures = Vec::new();
    for flags in &spellings {
        for json in [true, false] {
            let mut args = vec!["verify"];
            if json {
                args.extend(["--format", "json"]);
            }
            args.extend(flags.iter().copied());
            args.push(&good);
            let out = f.run_in(&f.repo, &args, &[], &[]);
            let all = text(&out).to_lowercase();
            let verified_claimed = String::from_utf8_lossy(&out.stdout)
                .contains("\"verified\":true")
                || String::from_utf8_lossy(&out.stdout).contains("verified: Good signature");
            if out.status.code() != Some(2) || verified_claimed || !all.contains("absolute") {
                failures.push(format!("{args:?} (json: {json}): {}", text(&out)));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "a relative explicit path must exit 2, say \"absolute\", and not verify:\n{}",
        failures.join("\n---\n")
    );
}

/// Control: an absolute path to a file that happens to sit inside the
/// checkout is still accepted (the rule is about relative paths, the
/// caller's duty to pass a path outside the checkout is in the usage text
/// and the README), whatever the current folder is.
#[test]
fn v1_control_an_absolute_explicit_path_still_works() {
    let f = Fixture::without_trust_file();
    let good = f.trusted(Some(LAUNCHER), "good.txt");
    let inside = f.repo.join("signers");
    fs::write(&inside, authority_line()).unwrap();
    for dir in [f.repo.clone(), f.w.home.clone()] {
        let (out, v) = f.json_in(
            &dir,
            &["--allowed-signers", inside.to_str().unwrap()],
            &good,
            &[("GIT_DIR", f.repo.join(".git").into_os_string())],
            &[],
        );
        assert_ok_with_trust_file(
            &out,
            &v,
            &inside,
            &format!("absolute, cwd {}", dir.display()),
        );
    }
}

/// The usage text tells the caller to pass an absolute path.
///
/// Fails today: the usage line names the option without saying so.
#[test]
fn v1_the_usage_text_says_the_path_must_be_absolute() {
    let f = Fixture::new();
    let out = f.run_in(&f.repo, &["verify"], &[], &[]);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
    assert!(
        String::from_utf8_lossy(&out.stderr)
            .to_lowercase()
            .contains("absolute"),
        "the usage text must say --allowed-signers takes an absolute path: {}",
        text(&out)
    );
}

// ---------------------------------------------------------------------------
// V3: format characters in human output.
// ---------------------------------------------------------------------------

/// The characters that can reorder or hide text in a terminal: bidi
/// embeddings, overrides and isolates, the directional marks, zero-width
/// characters, the word joiner and the byte-order mark.
const FORMAT_CHARS: [char; 16] = [
    '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{202E}', '\u{2066}', '\u{2067}', '\u{2068}',
    '\u{2069}', '\u{200E}', '\u{200F}', '\u{200B}', '\u{200C}', '\u{200D}', '\u{2060}', '\u{FEFF}',
];

/// A commit signed by the trusted authority with a certificate naming
/// `cert_principal`, whose committer email is `email`.
fn commit_with_email(f: &Fixture, email: &str, cert_principal: &str, tag: &str) -> String {
    let cert = cert(TRUSTED_CA_SEED, cert_principal, &f.subject, Some(LAUNCHER));
    let tree =
        f.w.tree_with(&f.repo, &format!("{tag}.txt"), &format!("{tag}\n"));
    let buffer = commit_buffer_at(&tree, &[&f.head], &agent_ident(email), now_secs(), tag);
    let sig = sshsig(&cert, &f.subject, "git", &buffer);
    f.w.write_signed_commit(&f.repo, &buffer, &sig)
}

/// For each listed format character, a committer email holding it never
/// reaches the human output (either stream), on the refusal path (the
/// certificate isn't for the committer) and on the path where the
/// certificate names that very email. The output is not empty (so it isn't
/// passing by printing nothing).
///
/// Fails today: only control characters are written out; these pass raw.
#[test]
fn v3_unicode_format_characters_in_a_committer_email_never_reach_human_output() {
    let f = Fixture::new();
    let mut failures = Vec::new();
    for c in FORMAT_CHARS {
        let code = c as u32;
        let email = format!(
            "claude-code.{}{c}@{DOMAIN}",
            session8(&format!("v3-{code:x}"))
        );
        let refused = commit_with_email(&f, &email, &f.principal, &format!("v3r-{code:x}"));
        let certified = commit_with_email(&f, &email, &email, &format!("v3c-{code:x}"));
        for (path, rev) in [("refusal", refused), ("certified principal", certified)] {
            let out = f.human(&rev);
            let shown = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            if shown.is_empty() {
                failures.push(format!(
                    "U+{code:04X} via {path}: the human form printed nothing"
                ));
            } else if shown.contains(c) {
                failures.push(format!(
                    "U+{code:04X} via {path}: reached the output raw: {shown:?}"
                ));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "format characters must not reach human output:\n{}",
        failures.join("\n")
    );
}

// ---------------------------------------------------------------------------
// V5 and V2: shallow and partial clones; nothing is fetched, nothing is run.
// ---------------------------------------------------------------------------

/// Every file under the repository's object store and refs (path and size),
/// plus `shallow`, `packed-refs` and `HEAD`: if verify fetches anything, a
/// new object, pack or ref appears here.
fn store_snapshot(repo: &Path) -> Vec<String> {
    fn walk(base: &Path, dir: &Path, out: &mut Vec<String>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(base, &path, out);
            } else {
                let rel = path.strip_prefix(base).unwrap().display().to_string();
                let len = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                out.push(format!("{rel} {len}"));
            }
        }
    }
    let git = repo.join(".git");
    let mut out = Vec::new();
    walk(&git, &git.join("objects"), &mut out);
    walk(&git, &git.join("refs"), &mut out);
    for name in ["shallow", "packed-refs", "HEAD"] {
        out.push(format!("{name}: {:?}", fs::read(git.join(name)).ok()));
    }
    out.sort();
    out
}

impl Fixture {
    /// `git clone` of this fixture's repository over `file://`, with `flags`,
    /// into `<home>/<dest>`.
    fn clone_file(&self, flags: &[&str], dest: &str) -> PathBuf {
        let url = format!("file://{}", self.repo.display());
        let mut args = vec!["clone", "-q"];
        args.extend_from_slice(flags);
        args.push(&url);
        args.push(dest);
        self.w.git_ok(&self.w.home, &args);
        self.w.home.join(dest)
    }

    /// A script `remote.origin.uploadpack` can name: records that it ran,
    /// then runs the real upload-pack. If it runs, a transport ran.
    fn transport_marker(&self, name: &str) -> (PathBuf, PathBuf) {
        let script = self.w.home.join(format!("{name}.sh"));
        let marker = self.w.home.join(format!("{name}-ran"));
        write_script(
            &script,
            &format!(
                "#!/bin/sh\necho ran >> '{}'\nexec '{}' upload-pack \"$@\"\n",
                marker.display(),
                self.w.real_git.display()
            ),
        );
        (script, marker)
    }

    /// A stand-in for a git older than 2.44: it unsets `GIT_NO_LAZY_FETCH`
    /// (the one thing such a git does with it is ignore it), records the
    /// `GIT_ALLOW_PROTOCOL` it was handed (one line per run), and runs the
    /// real git. Named to agent-sign through `AGENT_SIGN_REAL_GIT`.
    fn old_git_wrapper(&self) -> (PathBuf, PathBuf) {
        let script = self.w.home.join("old-git.sh");
        let log = self.w.home.join("old-git-log");
        write_script(
            &script,
            &format!(
                "#!/bin/sh\nunset GIT_NO_LAZY_FETCH\n\
                 echo \"allow_protocol=${{GIT_ALLOW_PROTOCOL+set}}:[$GIT_ALLOW_PROTOCOL]\" >> '{}'\n\
                 exec '{}' \"$@\"\n",
                log.display(),
                self.w.real_git.display()
            ),
        );
        (script, log)
    }
}

/// Runs `verify` (JSON and human form) for `rev` in `clone` against `real`,
/// with `set` in the environment, and asserts: not ok, not verified, a
/// non-zero exit in both forms, `marker` not created (nothing was run), and
/// the object store, refs and shallow file exactly as before.
fn assert_not_ok_and_nothing_fetched(
    f: &Fixture,
    clone: &Path,
    rev: &str,
    marker: &Path,
    set: &[(&str, OsString)],
    how: &str,
) {
    let real = f.real_trust();
    let before = store_snapshot(clone);
    let (out, v) = f.json_in(
        clone,
        &["--allowed-signers", real.to_str().unwrap()],
        rev,
        set,
        &[],
    );
    let human = f.run_in(
        clone,
        &["verify", "--allowed-signers", real.to_str().unwrap(), rev],
        set,
        &[],
    );
    assert_ne!(v["reason"], "ok", "{how}: reported ok: {}", text(&out));
    assert_eq!(v["verified"], false, "{how}: verified: {}", text(&out));
    assert_eq!(v["attested"], false, "{how}: attested: {}", text(&out));
    assert_ne!(
        out.status.code(),
        Some(0),
        "{how}: json exit: {}",
        text(&out)
    );
    assert_ne!(
        human.status.code(),
        Some(0),
        "{how}: human exit: {}",
        text(&human)
    );
    assert!(
        !String::from_utf8_lossy(&human.stdout).contains("verified: Good signature"),
        "{how}: the human form said verified: {}",
        text(&human)
    );
    assert!(
        !marker.exists(),
        "{how}: a transport ran (the promisor's upload-pack was started): {}",
        text(&out)
    );
    assert_eq!(
        store_snapshot(clone),
        before,
        "{how}: verify changed the repository's objects, refs or shallow file (it fetched): {}",
        text(&out)
    );
}

/// A shallow clone (`--depth 1`) of a repository whose tip sits on top of a
/// good attested commit S: S lies beyond the shallow boundary, so it is
/// absent. Controls: in the source, S verifies ok; in the clone, S really is
/// absent. Then `verify S` in the clone is not ok, runs nothing, and
/// changes nothing in the clone.
///
/// May pass today (verify never fetches, and says "isn't a commit"): it pins
/// the property against the lazy-fetch and transport changes.
#[test]
fn v5_a_shallow_clone_missing_the_commit_is_not_ok_and_fetches_nothing() {
    let f = Fixture::new();
    let real = f.real_trust();
    let signed = f.trusted(Some(LAUNCHER), "signed.txt");
    let tree = f.w.tree_with(&f.repo, "top.txt", "top\n");
    let buffer = commit_buffer_at(
        &tree,
        &[&signed],
        &agent_ident(&f.principal),
        now_secs(),
        "top",
    );
    let top = f.w.git_stdin(
        &f.repo,
        &["hash-object", "-t", "commit", "-w", "--stdin"],
        &buffer,
    );
    f.w.git_ok(&f.repo, &["update-ref", "refs/heads/work", &top]);
    let (out, v) = f.json_in(
        &f.repo,
        &["--allowed-signers", real.to_str().unwrap()],
        &signed,
        &[],
        &[],
    );
    assert_ok_with_trust_file(&out, &v, &real, "control: S in the source repository");

    let clone = f.clone_file(&["--depth", "1", "--no-checkout"], "shallow");
    let absent = f.w.git(&clone, &["cat-file", "-e", &signed]);
    assert!(
        !absent.status.success(),
        "setup: S is present in the shallow clone: {}",
        text(&absent)
    );
    let (script, marker) = f.transport_marker("shallow-uploadpack");
    f.w.git_ok(
        &clone,
        &[
            "config",
            "remote.origin.uploadpack",
            script.to_str().unwrap(),
        ],
    );
    assert_not_ok_and_nothing_fetched(&f, &clone, &signed, &marker, &[], "shallow clone");
}

/// The state of a partial clone for the V5 probes: a partial clone of the
/// source taken BEFORE S existed, then S (good, attested) is added to the
/// source, which is the clone's promisor over `file://`. S is absent from
/// the clone but fetchable. Returns (S, the clone, the marker its
/// promisor's upload-pack leaves when it runs).
///
/// Setup checks (so the probes mean something): plain git, asked for S in a
/// copy of the clone, fetches it from the promisor and runs the marker
/// script.
fn partial_clone_with_fetchable_commit(f: &Fixture) -> (String, PathBuf, PathBuf) {
    f.w.git_ok(&f.repo, &["config", "uploadpack.allowFilter", "true"]);
    f.w.git_ok(
        &f.repo,
        &["config", "uploadpack.allowAnySHA1InWant", "true"],
    );
    let clone = f.clone_file(&["--filter=blob:none", "--no-checkout"], "partial");
    let signed = f.trusted(Some(LAUNCHER), "signed.txt");
    f.w.git_ok(&f.repo, &["update-ref", "refs/heads/work", &signed]);
    let (script, marker) = f.transport_marker("partial-uploadpack");
    f.w.git_ok(
        &clone,
        &[
            "config",
            "remote.origin.uploadpack",
            script.to_str().unwrap(),
        ],
    );
    let probe = f.w.home.join("partial-probe");
    let copied = Command::new("cp")
        .args(["-a"])
        .arg(&clone)
        .arg(&probe)
        .status()
        .unwrap();
    assert!(copied.success(), "setup: couldn't copy the clone");
    let present_before = store_snapshot(&clone);
    let fetched = f.w.git(&probe, &["cat-file", "-t", &signed]);
    assert!(
        fetched.status.success() && String::from_utf8_lossy(&fetched.stdout).trim() == "commit",
        "setup: plain git could not lazily fetch S from the promisor, so the probes prove nothing: {}",
        text(&fetched)
    );
    assert!(
        marker.exists(),
        "setup: the lazy fetch did not go through the planted upload-pack: {}",
        text(&fetched)
    );
    fs::remove_file(&marker).unwrap();
    assert_eq!(
        store_snapshot(&clone),
        present_before,
        "setup: the probe copy was not independent of the clone"
    );
    (signed, clone, marker)
}

/// A PARTIAL clone whose promisor is a local `file://` repository that holds
/// S's attested bytes: `verify S` must not fetch it (no new object, nothing
/// run) and must not report ok.
///
/// Passes today on git 2.44 or later (`GIT_NO_LAZY_FETCH` is honoured); the
/// next test shows the second defence.
#[test]
fn v5_a_partial_clone_with_a_file_promisor_is_not_ok_and_fetches_nothing() {
    let f = Fixture::new();
    let (signed, clone, marker) = partial_clone_with_fetchable_commit(&f);
    assert_not_ok_and_nothing_fetched(&f, &clone, &signed, &marker, &[], "partial clone");
}

/// V2, the faithful half: the same partial clone, but `verify` is given a git
/// that ignores `GIT_NO_LAZY_FETCH` (as one older than 2.44 does). Then only
/// `GIT_ALLOW_PROTOCOL=""` can stop the lazy fetch: no transport may run,
/// nothing may be fetched, the verdict is not ok, and every git `verify`
/// started was handed `GIT_ALLOW_PROTOCOL` set to the empty string.
///
/// Fails today: the lazy fetch runs the promisor's upload-pack over `file://`
/// and brings S into the repository.
#[test]
fn v2_a_git_that_ignores_the_lazy_fetch_switch_still_fetches_nothing() {
    let f = Fixture::new();
    let (signed, clone, marker) = partial_clone_with_fetchable_commit(&f);
    let (wrapper, log) = f.old_git_wrapper();
    assert_not_ok_and_nothing_fetched(
        &f,
        &clone,
        &signed,
        &marker,
        &[("AGENT_SIGN_REAL_GIT", wrapper.into_os_string())],
        "partial clone, git without GIT_NO_LAZY_FETCH",
    );
    let seen = fs::read_to_string(&log).unwrap_or_default();
    assert!(
        !seen.is_empty(),
        "the stand-in git was never run, so the probe proves nothing"
    );
    for line in seen.lines() {
        assert_eq!(
            line, "allow_protocol=set:[]",
            "every git verify runs must get GIT_ALLOW_PROTOCOL set to the empty string; log:\n{seen}"
        );
    }
}

/// V2 for the planted-config case of the existing test
/// (`a_partial_clone_config_cannot_make_verify_run_the_sessions_command`):
/// the session's `core.sshCommand` promisor, with a git that ignores
/// `GIT_NO_LAZY_FETCH`. The planted command must not run.
///
/// Fails today: the old-git stand-in lazily fetches and runs the command.
#[test]
fn v2_a_planted_ssh_command_does_not_run_under_a_git_without_the_switch() {
    let f = Fixture::new();
    let marker = f.w.home.join("lazy-fetch-ran");
    let script = f.w.home.join("lazy-fetch.sh");
    write_script(
        &script,
        &format!("#!/bin/sh\necho ran >> '{}'\nexit 1\n", marker.display()),
    );
    for (key, value) in [
        ("core.repositoryformatversion", "1"),
        ("extensions.partialClone", "origin"),
        ("remote.origin.promisor", "true"),
        ("remote.origin.partialclonefilter", "blob:none"),
        ("remote.origin.url", "ssh://lazy-fetch.invalid/repo.git"),
        ("core.sshCommand", script.to_str().unwrap()),
    ] {
        f.w.git_ok(&f.repo, &["config", "--local", key, value]);
    }
    let missing = "1234567890abcdef1234567890abcdef12345678";
    let probe = f.w.git(&f.repo, &["cat-file", "-t", missing]);
    assert!(!probe.status.success(), "setup: the object exists");
    assert!(
        marker.exists(),
        "setup: plain git did not run the command: {}",
        text(&probe)
    );
    fs::remove_file(&marker).unwrap();

    let (wrapper, _log) = f.old_git_wrapper();
    let real = f.real_trust();
    let (out, v) = f.json_in(
        &f.repo,
        &["--allowed-signers", real.to_str().unwrap()],
        missing,
        &[("AGENT_SIGN_REAL_GIT", wrapper.into_os_string())],
        &[],
    );
    assert!(
        !marker.exists(),
        "verify ran the command named by the repo's own config under a git without \
         GIT_NO_LAZY_FETCH: {}",
        text(&out)
    );
    assert_eq!(v["verified"], false, "{}", text(&out));
    assert_ne!(out.status.code(), Some(0), "exit code: {}", text(&out));
}
