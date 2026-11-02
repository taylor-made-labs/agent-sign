//! Certificate times: what decides a signature's validity must not depend on
//! how git or the host's clock zone reads a time.
//!
//! These tests were written before the fix, as its eval (follow-up to build
//! step S6, diagnosed and approved by the suite PM, 1 Nov 2026). They fail
//! today; the fix is done when every test here passes on hetzner and on the
//! Pi, with no assertion changed.
//!
//! **The finding.** git passes `-Overify-time=YYYYMMDDHHMMSS` to
//! `ssh-keygen -Y verify` as its own local time with no zone. OpenSSH 10.0p2
//! (the Pi, Debian 13) misreads that whenever the clock zone isn't UTC: it
//! accepts only the Z-suffixed UTC form. OpenSSH 10.2p1 (hetzner) reads it
//! correctly. So on such a machine git's own check of an SSH certificate is
//! shifted by the zone offset (`p8_a_self_asserted_signature_is_reported_as_
//! claimed_never_as_proven` failed only on the Pi: its one-hour legacy
//! certificate fell outside the shifted window). `agent-sign verify` already
//! passes `YYYYMMDDHHMMSSZ` (`src/verify.rs`) and is unaffected.
//!
//! **What is held to account here.**
//! - `doctor_*`: `agent-sign doctor` says whether git on this machine reads
//!   certificate times correctly, and agrees with a truth the test works out
//!   itself on whichever machine it runs on (so it shows the warning on the
//!   Pi and none on hetzner, with the clock zone set the same way).
//! - `*_though_gits_verdict_is_good` : a decision is `agent-sign verify`'s,
//!   never git's. In a world whose git is made to lie (its signing program
//!   says Good to anything), `agent-sign verify` still refuses a certificate
//!   from an authority the trust file doesn't hold, and a commit dated
//!   outside its certificate's window, and still accepts a genuine commit.
//!   These may already pass; they pin the property against regressions.
//! - `docs_say_*`: the documentation tells whoever builds a merge gate, a
//!   server-side check or a hook to use `agent-sign verify`.
//!
//! No private key is ever written to a file: every key here is made in
//! memory from a fixed seed, and only public material (certificates,
//! signatures, authority lines) reaches the temporary folder.
//!
//! Isolation as in `test_caller_identity.rs`: an empty environment plus a
//! temporary HOME (under `TMPDIR`), a temporary global git config, no system
//! config, a PATH without agent-sign's installed `bin`. Every wait is
//! bounded.
#![cfg(unix)]

use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
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
/// A zone that is never UTC, so a zone-blind reading of a time is always off.
const ZONE: &str = "America/New_York";
/// How far outside the certificate's window a commit is dated: two days.
const OUTSIDE: u64 = 2 * 24 * 3600;

/// The seeds of the in-memory keys.
const TRUSTED_CA_SEED: [u8; 32] = [11; 32];
const UNTRUSTED_CA_SEED: [u8; 32] = [41; 32];
const SUBJECT_SEED: [u8; 32] = [12; 32];
const PROBE_CA_SEED: [u8; 32] = [51; 32];
const PROBE_SUBJECT_SEED: [u8; 32] = [52; 32];

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
/// `ca_seed`, valid from five minutes before now to an hour after: the
/// window of the one-hour certificates agent-sign issued before the fix. Built
/// here with ssh-key.
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
    ssh_keygen: PathBuf,
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

/// `s` without ANSI colour codes.
fn strip_ansi(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' && chars.peek() == Some(&'[') {
            for d in chars.by_ref() {
                if d.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

impl World {
    fn new() -> World {
        let dir = tempdir().unwrap();
        let home = dir.path().to_path_buf();
        let path = cleaned_path();
        let world = World {
            global_config: home.join("person.gitconfig"),
            real_git: find_on(&path, "git"),
            ssh_keygen: find_on(&path, "ssh-keygen"),
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
            // So that results don't depend on the host's clock zone; a test
            // that is about the zone sets its own, per command.
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

    /// Makes git's signing program (`gpg.ssh.program`) a script that says
    /// Good, for whatever principal is asked about, to anything, and exits
    /// 0 (after reading all of its input, so git never meets a closed pipe):
    /// a git that lies, so `git verify-commit` and `%G?` say Good.
    fn make_git_lie(&self) {
        let liar = self.home.join("lying-ssh-keygen.sh");
        fs::write(
            &liar,
            "#!/bin/sh\n\
             principal=anyone@example.invalid\n\
             prev=\n\
             for a in \"$@\"; do\n\
             \x20 if [ \"$prev\" = \"-I\" ]; then principal=$a; fi\n\
             \x20 prev=$a\n\
             done\n\
             case \" $* \" in\n\
             \x20 *\" find-principals \"*) echo \"$principal\"; exit 0 ;;\n\
             esac\n\
             cat > /dev/null\n\
             echo \"Good \\\"git\\\" signature for $principal with ED25519 key SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"\n\
             exit 0\n",
        )
        .unwrap();
        fs::set_permissions(&liar, fs::Permissions::from_mode(0o755)).unwrap();
        let mut config = fs::read_to_string(&self.global_config).unwrap();
        config.push_str(&format!(
            "[gpg \"ssh\"]\n\tprogram = \"{}\"\n",
            liar.display()
        ));
        fs::write(&self.global_config, config).unwrap();
    }

    /// `agent-sign verify <rev>` in `repo`: whether the signature verified,
    /// and its output and errors together.
    ///
    /// DELIBERATE EVAL CHANGE: strengthened (third round of the second
    /// whole-branch review, V4, 1 Nov 2026). "Verified" is read from the
    /// output (`verified: Good signature`), and the helper now also asserts
    /// the human form's exit status is consistent with the JSON form's: the
    /// same exit code, and 0 only when the commit is verified AND attested
    /// (these tests' commits carry no attestation, so a good signature exits
    /// 1, never 0), and the text says verified exactly when the JSON does.
    fn agent_sign_verify(&self, repo: &Path, rev: &str) -> (bool, String) {
        let mut cmd = self.cmd(Path::new(env!("CARGO_BIN_EXE_agent-sign")));
        cmd.args(["verify", rev]).current_dir(repo);
        let out = run_within(cmd, "agent-sign verify");
        let mut json_cmd = self.cmd(Path::new(env!("CARGO_BIN_EXE_agent-sign")));
        json_cmd
            .args(["verify", "--format", "json", rev])
            .current_dir(repo);
        let json_out = run_within(json_cmd, "agent-sign verify --format json");
        let json: serde_json::Value =
            serde_json::from_slice(&json_out.stdout).unwrap_or_else(|e| {
                panic!(
                    "the JSON form printed no JSON object ({e}): {}",
                    String::from_utf8_lossy(&json_out.stdout)
                )
            });
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let said = format!("{}{}", stdout, String::from_utf8_lossy(&out.stderr));
        let verified = stdout.contains("verified: Good signature for");
        assert_eq!(
            verified,
            json["verified"] == true,
            "the human text and the JSON disagree on verified: {said} / {json}"
        );
        assert_eq!(
            out.status.code(),
            json_out.status.code(),
            "the human form's exit status must equal the JSON form's: {said} / {json}"
        );
        assert_eq!(
            out.status.code() == Some(0),
            verified && json["attested"] == true,
            "the human form exits 0 only when verified AND attested: {said} / {json}"
        );
        (verified, said)
    }
}

// ---------------------------------------------------------------------------
// 1. The doctor's self-check of how git reads certificate times.
// ---------------------------------------------------------------------------

/// The local time in `ZONE` of `secs`, as git writes it into
/// `-Overify-time`: `YYYYMMDDHHMMSS`, no zone. Asked of `date`.
fn local_stamp(w: &World, secs: u64) -> String {
    for flag in [format!("@{secs}"), String::new()] {
        let mut cmd = Command::new("date");
        cmd.env_clear().env("PATH", &w.path).env("TZ", ZONE);
        if flag.is_empty() {
            cmd.args(["-r", &secs.to_string()]);
        } else {
            cmd.args(["-d", &flag]);
        }
        cmd.arg("+%Y%m%d%H%M%S");
        if let Ok(out) = cmd.output()
            && out.status.success()
        {
            return String::from_utf8_lossy(&out.stdout).trim().to_string();
        }
    }
    panic!("couldn't ask date for the local time of {secs}");
}

/// Whether `ssh-keygen -Y find-principals` finds `principal` for `sig_file`
/// in `allowed` at the verify time `stamp`, run in `ZONE` like git would be.
fn finds_principal(
    w: &World,
    allowed: &Path,
    sig_file: &Path,
    stamp: &str,
    principal: &str,
) -> bool {
    let mut cmd = Command::new(&w.ssh_keygen);
    cmd.env_clear()
        .env("PATH", &w.path)
        .env("HOME", &w.home)
        .env("TZ", ZONE)
        .args(["-Y", "find-principals", "-f"])
        .arg(allowed)
        .arg("-s")
        .arg(sig_file)
        .arg(format!("-Overify-time={stamp}"))
        .stdin(Stdio::null());
    let out = run_within(cmd, "ssh-keygen find-principals");
    out.status.success() && String::from_utf8_lossy(&out.stdout).contains(principal)
}

/// What this machine's OpenSSH does with the two forms of `-Overify-time`,
/// for a certificate valid now: `(plain local time reads right, UTC with a
/// Z reads right)`. Only public material is written to disk.
fn how_ssh_keygen_reads_times(w: &World) -> (bool, bool) {
    let principal = "doctor-probe@example.invalid";
    let subject = key(PROBE_SUBJECT_SEED);
    let cert = legacy_cert(PROBE_CA_SEED, principal, &subject);
    let sig = sshsig(&cert, &subject, "git", b"probe\n");
    let allowed = w.home.join("probe_allowed_signers");
    fs::write(
        &allowed,
        format!(
            "{principal} cert-authority {}\n",
            pub_line(&key(PROBE_CA_SEED))
        ),
    )
    .unwrap();
    let sig_file = w.home.join("probe.sig");
    fs::write(&sig_file, sig).unwrap();
    let now = now_secs();
    let plain = local_stamp(w, now);
    let z = {
        let utc = local_stamp_utc(w, now);
        format!("{utc}Z")
    };
    (
        finds_principal(w, &allowed, &sig_file, &plain, principal),
        finds_principal(w, &allowed, &sig_file, &z, principal),
    )
}

/// `secs` as `YYYYMMDDHHMMSS` in UTC.
fn local_stamp_utc(w: &World, secs: u64) -> String {
    for args in [
        vec!["-u".to_string(), "-d".into(), format!("@{secs}")],
        vec!["-u".to_string(), "-r".into(), secs.to_string()],
    ] {
        let out = Command::new("date")
            .env_clear()
            .env("PATH", &w.path)
            .args(&args)
            .arg("+%Y%m%d%H%M%S")
            .output();
        if let Ok(out) = out
            && out.status.success()
        {
            return String::from_utf8_lossy(&out.stdout).trim().to_string();
        }
    }
    panic!("couldn't ask date for the UTC time of {secs}");
}

/// The doctor line about certificate times, with the indented hint lines
/// after it, ANSI codes removed; `None` when there is no such line.
fn certificate_times_block(doctor_output: &str) -> Option<String> {
    let clean = strip_ansi(doctor_output);
    let lines: Vec<&str> = clean.lines().collect();
    let first = lines
        .iter()
        .position(|l| l.to_lowercase().contains("certificate times"))?;
    let mut block = vec![lines[first]];
    for l in &lines[first + 1..] {
        if l.starts_with("    ") {
            block.push(l);
        } else {
            break;
        }
    }
    Some(block.join("\n"))
}

/// Doctor's self-check of how git reads certificate times. `agent-sign
/// doctor` prints a line about whether git here reads certificate times
/// correctly. The test works out the truth itself, on the machine it runs
/// on: it makes a throwaway authority and certificate in memory (only public
/// material is written down), and asks `ssh-keygen -Y find-principals` once
/// with the plain local-time `-Overify-time` git uses and once with the
/// Z-suffixed UTC form, in the clock zone America/New_York.
/// - If only the Z form works (the Pi, OpenSSH 10.0p2), doctor, run in that
///   same zone, must warn: a line with a warning mark about certificate
///   times that git here misreads ("misreads certificate times"), and in
///   that line or the hint lines under it: "unaffected" (`agent-sign verify`
///   is), "agent-sign verify", "TZ=UTC" (the fix for git) and "newer
///   OpenSSH" (the other fix).
/// - If both work (hetzner, OpenSSH 10.2p1), doctor must not warn: its line
///   about certificate times is a pass ("reads certificate times
///   correctly"), and nothing says "misread".
///
/// Fails today: doctor prints no such line.
#[test]
fn doctor_says_whether_git_here_reads_certificate_times_correctly() {
    let w = World::new();
    let (plain_ok, z_ok) = how_ssh_keygen_reads_times(&w);
    assert!(
        z_ok,
        "CONTROL: ssh-keygen here doesn't accept even the Z-suffixed UTC form for a certificate \
         valid now (plain form ok: {plain_ok}); the probe is wrong, not doctor"
    );
    let expect_warning = !plain_ok;

    let mut cmd = w.cmd(Path::new(env!("CARGO_BIN_EXE_agent-sign")));
    cmd.arg("doctor").env("TZ", ZONE).current_dir(&w.home);
    let out = run_within(cmd, "agent-sign doctor");
    let said = String::from_utf8_lossy(&out.stdout).into_owned();
    let truth = format!(
        "(on this machine, in {ZONE}: plain local time reads right = {plain_ok}, Z form reads \
         right = {z_ok}, so a warning is {})",
        if expect_warning {
            "expected"
        } else {
            "not expected"
        }
    );
    let block = certificate_times_block(&said).unwrap_or_else(|| {
        panic!(
            "doctor has no line about whether git reads certificate times {truth}; it said:\n{said}"
        )
    });
    let lower = block.to_lowercase();
    if expect_warning {
        assert!(
            block.lines().next().is_some_and(|l| l.contains('⚠')),
            "doctor didn't warn {truth}; its line:\n{block}"
        );
        assert!(
            lower.contains("misread"),
            "doctor's warning doesn't say git misreads certificate times {truth}:\n{block}"
        );
        assert!(
            lower.contains("unaffected") && lower.contains("agent-sign verify"),
            "doctor's warning doesn't say `agent-sign verify` is unaffected {truth}:\n{block}"
        );
        assert!(
            block.contains("TZ=UTC"),
            "doctor's warning doesn't give TZ=UTC for git as a fix {truth}:\n{block}"
        );
        assert!(
            lower.contains("newer openssh"),
            "doctor's warning doesn't give a newer OpenSSH as a fix {truth}:\n{block}"
        );
    } else {
        assert!(
            block.contains('✓') && lower.contains("reads certificate times correctly"),
            "doctor didn't pass git's reading of certificate times {truth}; its line:\n{block}"
        );
        assert!(
            !strip_ansi(&said).to_lowercase().contains("misread") && !block.contains('⚠'),
            "doctor warned about certificate times though both forms work {truth}:\n{said}"
        );
    }
}

// ---------------------------------------------------------------------------
// 2. Decisions never consult git's verdict.
// ---------------------------------------------------------------------------

/// A world whose git lies, with a repository and an allowed-signers file
/// that trusts only the authority with [`TRUSTED_CA_SEED`] for this
/// machine's agents.
struct LyingWorld {
    w: World,
    repo: PathBuf,
    head: String,
    principal: String,
    subject: SigningKey,
}

impl LyingWorld {
    fn new() -> LyingWorld {
        let w = World::new();
        let repo = w.repo();
        let head = w.git_ok(&repo, &["rev-parse", "HEAD"]);
        let allowed = w.home.join("trusted_allowed_signers");
        fs::write(
            &allowed,
            format!(
                "*@{DOMAIN} cert-authority {}\n",
                pub_line(&key(TRUSTED_CA_SEED))
            ),
        )
        .unwrap();
        w.name_allowed_signers_file(&allowed);
        w.make_git_lie();
        LyingWorld {
            w,
            repo,
            head,
            principal: principal_for("claude-code", "verify-time-session"),
            subject: key(SUBJECT_SEED),
        }
    }

    /// A commit signed with a certificate from the authority with `ca_seed`
    /// (valid from five minutes ago to an hour from now), dated `when`.
    fn commit(&self, ca_seed: [u8; 32], when: u64, name: &str) -> String {
        let cert = legacy_cert(ca_seed, &self.principal, &self.subject);
        let tree = self.w.tree_with(&self.repo, name, &format!("{name}\n"));
        let ident = agent_ident(&self.principal);
        let buffer = commit_buffer_at(&tree, &[&self.head], &ident, when, name);
        let sig = sshsig(&cert, &self.subject, "git", &buffer);
        self.w.write_signed_commit(&self.repo, &buffer, &sig)
    }

    /// CONTROL: git here is a liar: `%G?` and `git verify-commit` say Good
    /// for `commit`, whatever it is.
    fn assert_git_says_good(&self, commit: &str, what: &str) {
        let shown = self
            .w
            .git_ok(&self.repo, &["log", "-1", "--format=%G?", commit]);
        assert_eq!(
            shown, "G",
            "CONTROL: git's %G? should be made to say Good for {what}"
        );
        let out = self.w.git(&self.repo, &["verify-commit", commit]);
        assert!(
            out.status.success(),
            "CONTROL: `git verify-commit` should be made to say Good for {what}: {}",
            text(&out)
        );
    }

    /// CONTROL: a genuinely good commit verifies.
    fn assert_genuine_commit_verifies(&self) {
        let good = self.commit(TRUSTED_CA_SEED, now_secs(), "genuine.txt");
        self.assert_git_says_good(&good, "the genuine commit");
        let (ok, said) = self.w.agent_sign_verify(&self.repo, &good);
        assert!(
            ok && said.contains("attestation:") && !said.contains("not verified"),
            "CONTROL: `agent-sign verify` should accept a genuine commit (trusted authority, \
             dated within its certificate): {said}"
        );
    }

    fn assert_not_verified(&self, commit: &str, why: &str) {
        let (ok, said) = self.w.agent_sign_verify(&self.repo, commit);
        assert!(
            !ok && said.contains("not verified") && !said.contains("attestation:"),
            "`agent-sign verify` must say \"not verified\" and exit non-zero for {why}, even \
             though git says Good (ok: {ok}); it said: {said}"
        );
    }
}

/// A decision never takes git's word. In a world whose git is made to lie
/// (its `gpg.ssh.program` says Good to any principal and exits 0), a commit
/// whose certificate comes from an authority that is NOT in the trust file is
/// reported by `agent-sign verify` as "not verified", with a non-zero exit,
/// while `%G?` and `git verify-commit` say Good. Control, in the same world:
/// a genuine commit verifies. May pass today; pins the property.
#[test]
fn an_untrusted_authority_is_not_verified_though_gits_verdict_is_good() {
    let lw = LyingWorld::new();
    lw.assert_genuine_commit_verifies();
    let bad = lw.commit(UNTRUSTED_CA_SEED, now_secs(), "untrusted.txt");
    lw.assert_git_says_good(
        &bad,
        "a certificate from an authority the trust file doesn't hold",
    );
    lw.assert_not_verified(
        &bad,
        "a certificate from an authority the trust file doesn't hold",
    );
}

/// A decision never takes git's word. In the same lying world, a commit
/// whose committer date lies before its certificate's window (two days
/// before the certificate was valid) is "not verified", non-zero exit, while
/// `%G?` and `git verify-commit` say Good. Control: a genuine commit
/// verifies. May pass today; pins the property.
#[test]
fn a_commit_dated_before_its_certificate_is_not_verified_though_gits_verdict_is_good() {
    let lw = LyingWorld::new();
    lw.assert_genuine_commit_verifies();
    let bad = lw.commit(TRUSTED_CA_SEED, now_secs() - OUTSIDE, "early.txt");
    lw.assert_git_says_good(&bad, "a commit dated before its certificate's window");
    lw.assert_not_verified(&bad, "a commit dated before its certificate's window");
}

/// A decision never takes git's word. In the same lying world, a commit
/// whose committer date lies after its certificate's window (two days after
/// the certificate expired) is "not verified", non-zero exit, while `%G?` and
/// `git verify-commit` say Good. Control: a genuine commit verifies. May
/// pass today; pins the property.
#[test]
fn a_commit_dated_after_its_certificate_is_not_verified_though_gits_verdict_is_good() {
    let lw = LyingWorld::new();
    lw.assert_genuine_commit_verifies();
    let bad = lw.commit(TRUSTED_CA_SEED, now_secs() + OUTSIDE, "late.txt");
    lw.assert_git_says_good(&bad, "a commit dated after its certificate's window");
    lw.assert_not_verified(&bad, "a commit dated after its certificate's window");
}

// ---------------------------------------------------------------------------
// 3. Documentation.
// ---------------------------------------------------------------------------

/// The documentation tells whoever builds a merge gate, a server-side check
/// or a hook to use `agent-sign verify` and never git's own verdict.
/// Checked by words, in one paragraph (blank-line separated, markdown
/// backticks and asterisks removed, line breaks folded, case ignored) of
/// `README.md` or `docs/caller-identity.md`, which must contain all of:
/// "decide" (anything that decides), "merge gate", "server-side", "hook",
/// "must use", "agent-sign verify", "never", "%G?" and "verify-commit".
/// Fails today: neither file mentions `%G?` or `verify-commit`.
#[test]
fn docs_say_that_anything_that_decides_must_use_agent_sign_verify_never_gits_verdict() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let required = [
        "decide",
        "merge gate",
        "server-side",
        "hook",
        "must use",
        "agent-sign verify",
        "never",
        "%g?",
        "verify-commit",
    ];
    let mut best: Vec<(String, usize, Vec<&str>)> = Vec::new();
    for file in ["README.md", "docs/caller-identity.md"] {
        let body = fs::read_to_string(root.join(file)).unwrap();
        for para in body.split("\n\n") {
            let flat = para
                .replace(['`', '*'], "")
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .to_lowercase();
            let missing: Vec<&str> = required
                .iter()
                .copied()
                .filter(|w| !flat.contains(w))
                .collect();
            if missing.is_empty() {
                return;
            }
            best.push((file.to_string(), required.len() - missing.len(), missing));
        }
    }
    best.sort_by_key(|(_, found, _)| std::cmp::Reverse(*found));
    let (file, found, missing) = best.first().unwrap();
    panic!(
        "no paragraph of README.md or docs/caller-identity.md says that anything that decides \
         (a merge gate, a server-side check, a hook) must use `agent-sign verify`, never git's \
         %G? or verify-commit output. It needs one paragraph with all of the words {required:?}. \
         The closest ({file}) has {found} of {} and lacks {missing:?}",
        required.len()
    );
}
