//! Re-check low R3, the verify and docs half (a gate needs the author): written
//! before the fix, as its eval, by an agent other than the builder.
//!
//! The interface (decided by the orchestrator and accepted by the PM):
//! - `agent-sign verify --format json` gains, additively, `author` (the
//!   commit's author email, as the commit has it) and `author_matches_signer`
//!   (true only when the author email equals the verified signer's principal
//!   exactly, byte for byte, and the commit is verified; false otherwise). The
//!   existing fields and the exit code do not change: the author never changes
//!   the verdict.
//! - The human form filters the author as it does other commit text (control
//!   and format characters never reach the terminal raw). The test assumes the
//!   human form shows the author when it differs from the signer; that is what
//!   "filters the author" means to a reader of the output.
//! - The README's merge-gate section and docs/caller-identity.md each say that
//!   a gate that needs the author to be the agent requires
//!   `author_matches_signer` to be true.
//!
//! The harness is a copy of `test_verify_review2.rs`'s (certificates minted in
//! memory from fixed seeds, no key ever written to a file).
//!
//! Run on hetzner, never on the Mac:
//! `cargo test --locked --test test_rechecks_lows_verify`.

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

// ---------------------------------------------------------------------------
// R3: verify reports the author.
// ---------------------------------------------------------------------------

/// A commit signed by the trusted authority for `f.principal` (attested by the
/// launcher) whose author line is `author_ident` (the committer is the
/// principal, as the certificate needs).
fn commit_authored(f: &Fixture, author_ident: &str, tag: &str) -> String {
    let cert = cert(TRUSTED_CA_SEED, &f.principal, &f.subject, Some(LAUNCHER));
    let tree =
        f.w.tree_with(&f.repo, &format!("{tag}.txt"), &format!("{tag}\n"));
    let when = now_secs();
    let committer = agent_ident(&f.principal);
    let buffer = format!(
        "tree {tree}\nparent {}\nauthor {author_ident} {when} +0000\n\
         committer {committer} {when} +0000\n\n{tag}\n",
        f.head
    )
    .into_bytes();
    let sig = sshsig(&cert, &f.subject, "git", &buffer);
    f.w.write_signed_commit(&f.repo, &buffer, &sig)
}

/// R3. A verified commit whose author is the signer: the JSON carries the
/// author email and `author_matches_signer` true, and keeps its six existing
/// fields.
///
/// Red today: neither field is there.
#[test]
fn r3_json_reports_the_author_and_that_it_matches_the_signer() {
    let f = Fixture::new();
    let c = commit_authored(&f, &agent_ident(&f.principal), "same");
    let (out, v) = f.json(&c);
    assert_eq!(v["verified"], true, "setup: {}", text(&out));
    assert_eq!(out.status.code(), Some(0), "setup: {}", text(&out));
    for field in FIELDS {
        assert!(v.get(field).is_some(), "the existing field {field} is gone");
    }
    assert_eq!(v["signer"], f.principal.as_str(), "setup: {}", text(&out));
    assert_eq!(
        v["author"],
        f.principal.as_str(),
        "R3: verify's JSON does not carry the author email: {}",
        text(&out)
    );
    assert_eq!(
        v["author_matches_signer"],
        true,
        "R3: author_matches_signer is not true for an author equal to the signer: {}",
        text(&out)
    );
}

/// R3. A verified commit whose author is someone else (the person, with a
/// different name): the JSON carries that email as the commit has it,
/// `author_matches_signer` is false, and the verdict is unchanged (still
/// verified, exit 0): the author is information for the gate, not a verdict.
///
/// Red today: no author field.
#[test]
fn r3_json_reports_a_different_author_as_not_matching() {
    let f = Fixture::new();
    let c = commit_authored(&f, "Taylor <Taylor@Example.com>", "other");
    let (out, v) = f.json(&c);
    assert_eq!(
        v["verified"],
        true,
        "the author changed the verdict: {}",
        text(&out)
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "the author changed the exit: {}",
        text(&out)
    );
    assert_eq!(
        v["author"],
        "Taylor@Example.com",
        "R3: the author email is not reported as the commit has it: {}",
        text(&out)
    );
    assert_eq!(
        v["author_matches_signer"],
        false,
        "R3: author_matches_signer is not false for a different author: {}",
        text(&out)
    );
}

/// R3. "Exactly": the signer's principal in other letter case is not a match.
///
/// Red today: no field (and once present, a case-folding comparison fails it).
#[test]
fn r3_the_match_is_exact_not_case_folded() {
    let f = Fixture::new();
    let shouted = f.principal.to_uppercase();
    let c = commit_authored(&f, &format!("Claude Code <{shouted}>"), "shout");
    let (out, v) = f.json(&c);
    assert_eq!(v["verified"], true, "setup: {}", text(&out));
    assert_eq!(v["author"], shouted.as_str(), "R3: {}", text(&out));
    assert_eq!(
        v["author_matches_signer"],
        false,
        "R3: a case-changed author counted as the signer: {}",
        text(&out)
    );
}

/// R3. A commit that is not verified (an authority the trust file does not
/// hold) whose author equals its committer: the author is still reported, and
/// `author_matches_signer` is false, because there is no verified signer to
/// match.
///
/// Red today: no fields.
#[test]
fn r3_an_unverified_commit_never_matches_its_signer() {
    let f = Fixture::new();
    let c = f.commit(
        UNTRUSTED_CA_SEED,
        Some(LAUNCHER),
        now_secs(),
        "untrusted.txt",
    );
    let (out, v) = f.json(&c);
    assert_eq!(v["verified"], false, "setup: {}", text(&out));
    assert_eq!(
        v["author"],
        f.principal.as_str(),
        "R3: the author is not reported for an unverified commit: {}",
        text(&out)
    );
    assert_eq!(
        v["author_matches_signer"],
        false,
        "R3: an unverified commit's author counted as matching a signer: {}",
        text(&out)
    );
}

/// R3. A control character in the author email never reaches the human form
/// raw (stdout or stderr), the human form still shows the author (the visible
/// part before the escape), and the JSON form carries the author whole and
/// escaped.
///
/// Red today: the human form shows no author at all (so the visible marker is
/// missing), and the JSON has no author.
#[test]
fn r3_an_authors_control_characters_never_reach_the_human_form_raw() {
    let f = Fixture::new();
    let author = format!("author-marker-{}{ESC}z@example.com", fresh());
    let marker = author.split(ESC).next().unwrap().to_string();
    let c = commit_authored(&f, &format!("Someone <{author}>"), "esc-author");
    let human = f.human(&c);
    assert!(
        !has_control_bytes(&human.stdout) && !has_control_bytes(&human.stderr),
        "a control byte from the author reached the human output raw: {}",
        text(&human)
    );
    let shown = format!(
        "{}{}",
        String::from_utf8_lossy(&human.stdout),
        String::from_utf8_lossy(&human.stderr)
    );
    assert!(
        shown.contains(&marker),
        "R3: the human form does not show the commit's author (expected to see {marker:?}): {}",
        text(&human)
    );
    let (json_out, v) = f.json(&c);
    assert!(
        !has_control_bytes(&json_out.stdout),
        "a raw control byte in the JSON: {}",
        text(&json_out)
    );
    assert_eq!(
        v["author"],
        author.as_str(),
        "R3: the JSON author is not the whole email as the commit has it: {}",
        text(&json_out)
    );
}

/// The text of the README's merge-gate section: from its `###` heading to the
/// next heading of that depth or higher.
fn readme_merge_gate_section() -> String {
    let readme =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("README.md")).unwrap();
    let start = readme
        .find("### Merge gates")
        .expect("the README has no `### Merge gates` section");
    let rest = &readme[start + 4..];
    let end = rest
        .find("\n## ")
        .into_iter()
        .chain(rest.find("\n### "))
        .min()
        .unwrap_or(rest.len());
    rest[..end].to_string()
}

/// R3, docs. The README's merge-gate section says that a gate that needs the
/// author to be the agent requires `author_matches_signer` to be true.
///
/// Red today: the section does not mention it.
#[test]
fn r3_the_readmes_merge_gate_section_names_author_matches_signer() {
    let section = readme_merge_gate_section();
    assert!(
        section.contains("author_matches_signer"),
        "R3: the README's merge-gate section does not mention author_matches_signer:\n{section}"
    );
    assert!(
        section.to_lowercase().contains("author"),
        "R3: the README's merge-gate section does not say anything about the author"
    );
}

/// R3, docs. docs/caller-identity.md says the same.
///
/// Red today.
#[test]
fn r3_caller_identity_doc_names_author_matches_signer() {
    let doc =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/caller-identity.md"))
            .unwrap();
    assert!(
        doc.contains("author_matches_signer"),
        "R3: docs/caller-identity.md does not mention author_matches_signer"
    );
}

// ---------------------------------------------------------------------------
// Sitting review 3, Q3: more hiding format characters.
// ---------------------------------------------------------------------------

/// Q3. Each of these characters in a commit's author email never reaches the
/// human form (stdout or stderr) raw: the Arabic letter mark U+061C, the line
/// and paragraph separators U+2028/U+2029, the invisible operators
/// U+2061-U+2064, the Mongolian vowel separator U+180E, and the tag
/// characters U+E0000-U+E007F (the range's ends and a spread of its middle).
/// U+202E (already escaped) is the control: the test can see an escape.
///
/// Red today: `is_hiding_format_char` lets each of the new ones through.
#[test]
fn q3_more_hiding_format_characters_never_reach_the_human_form_raw() {
    let f = Fixture::new();
    let mut tagged: Vec<char> = vec!['\u{061C}', '\u{2028}', '\u{2029}', '\u{180E}'];
    tagged.extend('\u{2061}'..='\u{2064}');
    tagged.extend(
        [
            0xE0000u32, 0xE0001, 0xE0020, 0xE0041, 0xE0061, 0xE007E, 0xE007F,
        ]
        .iter()
        .map(|c| char::from_u32(*c).unwrap()),
    );
    let shown_for = |ch: char| {
        let author = format!("q3-marker-{}{ch}z@example.com", fresh());
        let c = commit_authored(&f, &format!("Someone <{author}>"), "q3");
        let human = f.human(&c);
        format!(
            "{}{}",
            String::from_utf8_lossy(&human.stdout),
            String::from_utf8_lossy(&human.stderr)
        )
    };
    let control = '\u{202E}';
    assert!(
        !shown_for(control).contains(control),
        "Q3 control: U+202E reached the human form raw"
    );
    let leaked: Vec<String> = tagged
        .into_iter()
        .filter(|ch| shown_for(*ch).contains(*ch))
        .map(|ch| format!("U+{:04X}", ch as u32))
        .collect();
    assert!(
        leaked.is_empty(),
        "Q3: these characters reached the human form raw: {leaked:?}"
    );
}
