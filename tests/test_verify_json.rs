//! `agent-sign verify --format json <rev>`: the machine-readable verdict a
//! merge step, or the suite's future decider, calls.
//!
//! These tests were written before the feature, as its eval (follow-up to
//! build step S6, interface agreed with the suite PM, 1 Nov 2026). They fail
//! today, because `verify` takes no `--format`; the work is done when every
//! test here passes on hetzner and on the Pi, with no assertion changed.
//!
//! **The interface.** `agent-sign verify --format json <rev>` prints exactly
//! one JSON object on stdout:
//! `{"verified": bool, "attested": bool, "attestation": "launcher" |
//! "approval" | "unattested" | "claimed" | "none", "signer": string | null,
//! "reason": string, "detail": string}`.
//! - `reason` is one of `ok`, `unsigned`, `unattested`, `claimed`,
//!   `untrusted_authority`, `outside_window`, `bad_signature`,
//!   `no_trust_file`, `error`; `detail` is the human sentence.
//! - The exit code is 0 only when the commit is verified AND attested
//!   (launcher or approval), 1 for every other verdict, and 2 when the check
//!   can't run (for example the revision doesn't exist).
//! - Without `--format json` the human output is unchanged, and the human
//!   and JSON verdicts always agree, since one function makes both.
//!
//! **What the commits are.** A decision is `agent-sign verify`'s verdict on
//! the signature and its certificate, so the commits here are signed with
//! certificates the tests mint in memory, from an authority the trust file
//! holds (so they verify) or one it doesn't. The attested ones carry the
//! `attestation@agent-sign` extension exactly as the service writes it
//! (`launcher session=<hex> uid=<n> isolation=<..>`, `approval sha256=<hex>`),
//! which `verify` reads only after the signature has verified. They are not
//! produced by running the launcher or the approval path: those are covered
//! by `test_caller_identity*.rs`, and this file is about how a verdict is
//! reported, not how an identity is established.
//!
//! No private key is ever written to a file: every key is made in memory
//! from a fixed seed, and only public material (the trust file) reaches the
//! temporary folder.
//!
//! Isolation as in `test_verify_time.rs`: an empty environment plus a
//! temporary HOME (under `TMPDIR`), a temporary global git config, no system
//! config, a PATH without agent-sign's installed `bin`. Every wait is
//! bounded.
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

/// What a verdict must be: every field of the interface, no more, and
/// `exit` per the rule (0 only when verified and attested).
struct Expect<'a> {
    verified: bool,
    attested: bool,
    attestation: &'a str,
    reason: &'a str,
    exit: i32,
}

/// Checks `value` (and the `out` exit status) against the interface and
/// against `expect`; `signer` must be the commit's principal when
/// `signer` is given.
fn assert_verdict(out: &Output, value: &Value, expect: &Expect, signer: Option<&str>) {
    let obj = value.as_object().unwrap();
    let mut names: Vec<&str> = obj.keys().map(String::as_str).collect();
    names.sort_unstable();
    // The six fields of the interface, and `trust_file`, added later (second
    // whole-branch review, I-F2, 1 Nov 2026) and named by the verdict as the
    // file it was checked against.
    // DELIBERATE EVAL CHANGE (re-check R3, fix round, 1 Nov 2026): two more
    // fields, `author` and `author_matches_signer`, added to the verdict at the
    // PM's request so a gate can check that the author is the agent. The key
    // set stays exact: this only names the two new keys, it loosens nothing.
    let mut want = FIELDS.to_vec();
    want.push("trust_file");
    want.push("author");
    want.push("author_matches_signer");
    want.sort_unstable();
    assert_eq!(
        names,
        want,
        "the JSON object must have exactly the fields {FIELDS:?}, trust_file, author and author_matches_signer: {}",
        text(out)
    );
    assert!(value["verified"].is_boolean() && value["attested"].is_boolean());
    assert!(
        value["attestation"]
            .as_str()
            .is_some_and(|a| ATTESTATIONS.contains(&a)),
        "attestation must be one of {ATTESTATIONS:?}: {}",
        text(out)
    );
    assert!(
        value["reason"]
            .as_str()
            .is_some_and(|r| REASONS.contains(&r)),
        "reason must be one of {REASONS:?}: {}",
        text(out)
    );
    assert!(
        value["signer"].is_null() || value["signer"].is_string(),
        "signer must be a string or null: {}",
        text(out)
    );
    assert!(
        value["detail"]
            .as_str()
            .is_some_and(|d| !d.trim().is_empty()),
        "detail must be the human sentence, not empty: {}",
        text(out)
    );
    assert_eq!(
        value["verified"],
        expect.verified,
        "verified: {}",
        text(out)
    );
    assert_eq!(
        value["attested"],
        expect.attested,
        "attested: {}",
        text(out)
    );
    assert_eq!(
        value["attestation"],
        expect.attestation,
        "attestation: {}",
        text(out)
    );
    assert_eq!(value["reason"], expect.reason, "reason: {}", text(out));
    if let Some(signer) = signer {
        assert_eq!(value["signer"], signer, "signer: {}", text(out));
    }
    assert_eq!(
        out.status.code(),
        Some(expect.exit),
        "exit code (0 only when verified and attested, 1 for every other verdict): {}",
        text(out)
    );
    // The rule behind the exit code, so a wrong expectation can't hide.
    assert_eq!(
        expect.exit == 0,
        expect.verified && expect.attested,
        "the test's own expectation breaks the exit-code rule"
    );
}

// ---------------------------------------------------------------------------
// The verdicts.
// ---------------------------------------------------------------------------

/// A commit signed by a trusted authority's certificate carrying a launcher
/// attestation, dated within the certificate's window: verified and
/// attested, attestation "launcher", reason "ok", the signer is the
/// committer's principal, exit 0.
///
/// Fails today: `verify` takes no `--format`.
#[test]
fn a_launched_commit_is_verified_and_attested_exit_0() {
    let f = Fixture::new();
    let commit = f.trusted(Some(LAUNCHER), "launched.txt");
    let (out, v) = f.json(&commit);
    assert_verdict(
        &out,
        &v,
        &Expect {
            verified: true,
            attested: true,
            attestation: "launcher",
            reason: "ok",
            exit: 0,
        },
        Some(&f.principal),
    );
}

/// As above for a certificate carrying an approval attestation: attestation
/// "approval", exit 0.
///
/// Fails today: `verify` takes no `--format`.
#[test]
fn an_approved_commit_is_verified_and_attested_exit_0() {
    let f = Fixture::new();
    let words = format!("approval sha256={}", "ab".repeat(32));
    let commit = f.trusted(Some(&words), "approved.txt");
    let (out, v) = f.json(&commit);
    assert_verdict(
        &out,
        &v,
        &Expect {
            verified: true,
            attested: true,
            attestation: "approval",
            reason: "ok",
            exit: 0,
        },
        Some(&f.principal),
    );
}

/// An unsigned commit claims nothing and proves nothing: not verified, not
/// attested, attestation "none", reason "unsigned", exit 1.
///
/// Fails today: `verify` takes no `--format`.
#[test]
fn an_unsigned_commit_is_unsigned_exit_1() {
    let f = Fixture::new();
    let (out, v) = f.json(&f.head);
    assert_verdict(
        &out,
        &v,
        &Expect {
            verified: false,
            attested: false,
            attestation: "none",
            reason: "unsigned",
            exit: 1,
        },
        None,
    );
}

/// A certificate from a trusted authority with no attestation extension is a
/// name that was claimed, not established: the signature verifies, so
/// `verified` is true, but `attested` is false, attestation "claimed",
/// reason "claimed", exit 1.
///
/// Fails today: `verify` takes no `--format`.
#[test]
fn a_self_asserted_certificate_with_no_extension_is_claimed_exit_1() {
    let f = Fixture::new();
    let commit = f.trusted(None, "claimed.txt");
    let (out, v) = f.json(&commit);
    assert_verdict(
        &out,
        &v,
        &Expect {
            verified: true,
            attested: false,
            attestation: "claimed",
            reason: "claimed",
            exit: 1,
        },
        Some(&f.principal),
    );
}

/// A certificate from an authority the trust file doesn't hold, even one
/// whose extension says "launcher", is not verified, and its extension is
/// not believed: attestation "none", reason "untrusted_authority", exit 1.
///
/// Fails today: `verify` takes no `--format`.
#[test]
fn an_untrusted_authority_is_untrusted_authority_exit_1() {
    let f = Fixture::new();
    let commit = f.commit(
        UNTRUSTED_CA_SEED,
        Some(LAUNCHER),
        now_secs(),
        "untrusted.txt",
    );
    let (out, v) = f.json(&commit);
    assert_verdict(
        &out,
        &v,
        &Expect {
            verified: false,
            attested: false,
            attestation: "none",
            reason: "untrusted_authority",
            exit: 1,
        },
        None,
    );
}

/// A commit dated outside its certificate's window (two days after it
/// expired) is not verified, though the authority is trusted and the
/// extension says "launcher": reason "outside_window", exit 1.
///
/// Fails today: `verify` takes no `--format`.
#[test]
fn a_commit_dated_outside_its_certificates_window_is_outside_window_exit_1() {
    let f = Fixture::new();
    let commit = f.commit(
        TRUSTED_CA_SEED,
        Some(LAUNCHER),
        now_secs() + OUTSIDE,
        "late.txt",
    );
    let (out, v) = f.json(&commit);
    assert_verdict(
        &out,
        &v,
        &Expect {
            verified: false,
            attested: false,
            attestation: "none",
            reason: "outside_window",
            exit: 1,
        },
        None,
    );
}

/// A trusted certificate whose extension says "unattested" (the service
/// issued it, and nothing established the name) is verified but not
/// attested: attestation "unattested", reason "unattested", exit 1. An
/// extra beyond the required list: it pins the fourth attestation value.
///
/// Fails today: `verify` takes no `--format`.
#[test]
fn an_unattested_certificate_is_unattested_exit_1() {
    let f = Fixture::new();
    let commit = f.trusted(Some(UNATTESTED), "unattested.txt");
    let (out, v) = f.json(&commit);
    assert_verdict(
        &out,
        &v,
        &Expect {
            verified: true,
            attested: false,
            attestation: "unattested",
            reason: "unattested",
            exit: 1,
        },
        Some(&f.principal),
    );
}

/// With no allowed-signers file named by git there is nothing to verify
/// against: not verified, reason "no_trust_file", exit 1. An extra beyond
/// the required list: it pins a reason that is a verdict, not "can't run".
///
/// Fails today: `verify` takes no `--format`.
#[test]
fn no_trust_file_is_no_trust_file_exit_1() {
    let f = Fixture::without_trust_file();
    let commit = f.trusted(Some(LAUNCHER), "no-trust.txt");
    let (out, v) = f.json(&commit);
    assert_verdict(
        &out,
        &v,
        &Expect {
            verified: false,
            attested: false,
            attestation: "none",
            reason: "no_trust_file",
            exit: 1,
        },
        None,
    );
}

/// A revision that doesn't exist can't be checked: exit 2, and (an
/// assumption of this file, from "stdout is exactly one JSON object") the
/// one JSON object still comes out, saying not verified with reason
/// "error".
///
/// Fails today: `verify` takes no `--format` (it exits 2 for the usage
/// error, so the exit code alone would pass; the JSON object is what
/// fails).
#[test]
fn a_missing_revision_cannot_run_exit_2() {
    let f = Fixture::new();
    let (out, v) = f.json("no-such-branch-anywhere");
    assert_verdict(
        &out,
        &v,
        &Expect {
            verified: false,
            attested: false,
            attestation: "none",
            reason: "error",
            exit: 2,
        },
        None,
    );
}

// ---------------------------------------------------------------------------
// The shape, and the human form.
// ---------------------------------------------------------------------------

/// Stdout is exactly one JSON object for every kind of verdict, a good one,
/// a refused one and one that can't run: nothing before it, nothing after
/// it (the human lines `verified:`, `attestation:` and `note:` go
/// nowhere near it), and the machine's words don't leak onto stdout.
///
/// Fails today: `verify` takes no `--format`.
#[test]
fn stdout_is_exactly_one_json_object() {
    let f = Fixture::new();
    let revs = [
        f.trusted(Some(LAUNCHER), "shape-good.txt"),
        f.trusted(None, "shape-claimed.txt"),
        f.commit(UNTRUSTED_CA_SEED, None, now_secs(), "shape-bad.txt"),
        f.head.clone(),
        "no-such-branch-anywhere".to_string(),
    ];
    for rev in &revs {
        let out = f.agent_sign(&["verify", "--format", "json", rev]);
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        parse_one_object(&stdout).unwrap_or_else(|why| {
            panic!(
                "stdout for {rev} isn't exactly one JSON object ({why}):\n{}",
                text(&out)
            )
        });
        for human in ["verified: Good signature", "attestation: ", "note: "] {
            assert!(
                !stdout.contains(&format!("\n{human}")) && !stdout.starts_with(human),
                "stdout for {rev} carries the human line {human:?}:\n{}",
                text(&out)
            );
        }
    }
}

/// The human form is unchanged, for the same commits the JSON form is asked
/// about: a verified, attested commit still prints
/// `verified: Good signature for <principal>` and
/// `attestation: <words>` on stdout and exits 0; a claimed one still prints
/// them plus the merge note and exits 1 (the human exit code is the JSON
/// one since F3, 1 Nov 2026; it was 0); an untrusted one still says `not verified`
/// on stderr and exits 1; an unsigned one still says `not verified` and
/// "unsigned". And for each of those the human and the JSON verdicts
/// agree on whether it verified.
///
/// Passes today for the human half (it pins what must not change); fails
/// today for the JSON half it is compared with.
#[test]
fn the_human_output_for_the_same_commit_still_has_its_words() {
    let f = Fixture::new();

    let launched = f.trusted(Some(LAUNCHER), "human-launched.txt");
    let out = f.human(&launched);
    let said = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        out.status.success()
            && said.contains(&format!("verified: Good signature for {}", f.principal))
            && said.contains("attestation: launcher"),
        "human output for a launched commit changed: {}",
        text(&out)
    );
    assert!(
        !said.contains("note:"),
        "human output for an attested commit gained a merge note: {}",
        text(&out)
    );

    let claimed = f.trusted(None, "human-claimed.txt");
    let out = f.human(&claimed);
    let said = String::from_utf8_lossy(&out.stdout).into_owned();
    // Exit 1 since F3 (the second whole-branch review, 1 Nov 2026): the human
    // form exits as the JSON form does, so a claimed commit, which is not
    // attested, is not a pass for a gate that reads only the exit status.
    assert!(
        out.status.code() == Some(1)
            && said.contains("verified: Good signature for")
            && said.contains("attestation: claimed by a process in a shared account")
            && said.contains("note: This commit can live on a branch"),
        "human output for a claimed commit changed: {}",
        text(&out)
    );

    let untrusted = f.commit(
        UNTRUSTED_CA_SEED,
        Some(LAUNCHER),
        now_secs(),
        "human-bad.txt",
    );
    let out = f.human(&untrusted);
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.status.code() == Some(1)
            && err.contains("agent-sign verify: not verified:")
            && !String::from_utf8_lossy(&out.stdout).contains("attestation:"),
        "human output for an untrusted commit changed: {}",
        text(&out)
    );

    let out = f.human(&f.head);
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.status.code() == Some(1) && err.contains("not verified:") && err.contains("unsigned"),
        "human output for an unsigned commit changed: {}",
        text(&out)
    );

    // The JSON half, after every human assertion above has been held to
    // the words it has today: the two verdicts agree on whether the commit
    // verified.
    for (rev, verified) in [
        (&launched, true),
        (&claimed, true),
        (&untrusted, false),
        (&f.head, false),
    ] {
        let (_, v) = f.json(rev);
        assert_eq!(
            v["verified"], verified,
            "JSON disagrees with the human verdict for {rev}"
        );
    }
}
