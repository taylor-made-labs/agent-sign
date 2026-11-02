//! Caller identity, decisions D2 and D3 (the suite PM, 31 Oct 2026): the
//! approval binds the whole commit, and the service's authority is trusted
//! only by an explicit `agent-sign trust install`.
//!
//! The evals for two binding decisions in `ci-decisions.md`. Like
//! `test_caller_identity.rs` and `test_caller_identity_extra.rs` they are
//! written before the build and fail today; the build is done for these when
//! they pass. Nothing in the other two files is loosened (their approval
//! helpers only gained the new field: see their "DELIBERATE EVAL CHANGE"
//! comments).
//!
//! **D3, an approval binds the whole commit.** Part 1 binds an approval to a
//! tree, parents, branch and working copy, and (since the critique) the
//! author and committer emails. It does not bind the commit message, the
//! author or committer names, or any date. Whoever captures an approval
//! (any process in the account can read the runner's socket traffic or its
//! files) can sign a commit with a message of their choosing, and the
//! signature's attestation then says the commitments check approved it. The
//! approval gains one field, `commit_sha256`: the lowercase hex SHA-256 of
//! the exact unsigned commit object agent-sign is asked to sign. That is the
//! `buffer_b64` of the `SignApproved` request, decoded: the bytes git writes
//! to the file it hands its signing program, which are the commit object
//! without its `gpgsig` header. (The control below proves it: the signature
//! over those bytes is Good on the stored commit, where git verifies it over
//! the same bytes with the `gpgsig` header taken out.) The runner builds the
//! object first, with fixed author and committer dates, hashes it, gets the
//! approval, and then presents both. agent-sign refuses a buffer whose hash
//! differs, and an approval with no hash.
//!
//! How each refusal test is made attributable. A commit that differs from
//! the approved one in a single part (its message, an author name, a date)
//! keeps every other thing part 1 checks: the same tree, parents, working
//! copy and branch, both emails the principal's, a committer date inside the
//! certificate's window. The approval is presented with that commit first
//! and must be refused. Then the same approval is presented with the exact
//! commit it was made for and must sign. So the refusal can only have been
//! about the one part that changed (a refused approval is not used up: part
//! 1's documented behaviour, kept).
//!
//! **Fails today.** `CommitApproval` refuses a field it doesn't know, so an
//! approval carrying `commit_sha256` is refused whole: the control that ends
//! (or begins) each D3 test fails first, saying so. The missing-field test
//! fails on its own assertion: an approval with no hash is signed today.
//!
//! **D2, the authority without OpenBao.** The service holds its authority in
//! memory, and only `agent-sign trust install` writes trust, so a service
//! that has just started is not yet trusted by anyone. `agent-sign doctor`
//! must say so, plainly, naming the command, and stop saying so once the
//! authority is trusted. (The lock, the in-memory authority and trust
//! staying put when another service starts are the first file's
//! `p3_starting_another_service_never_changes_what_verifiers_trust`.) Fails
//! today: the start writes the authority into the trust files itself, so
//! doctor has nothing to say.
//!
//! The harness (the isolated world, the in-memory keys, the SSHSIG writer)
//! is copied from `test_caller_identity_extra.rs`, so this file stands
//! alone; keep it in step. The same isolation applies: an empty environment,
//! a temporary HOME, a temporary global git config, no system config, a
//! socket in the temporary directory, no private key ever written to a file,
//! every wait bounded, every process stopped.

// Lint-only: the change tables below are arrays of (name, closure) pairs.
#![allow(clippy::type_complexity)]

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
/// The managed block's markers in an allowed-signers file.
const BLOCK_BEGIN: &str = "# agent-sign: agents' certificate authorities, managed; do not edit";
const BLOCK_END: &str = "# agent-sign: end of agents' certificate authorities";

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

impl World {
    /// Makes git name a new allowed-signers file holding only agent-sign's
    /// empty managed block, and returns it: what `agent-sign trust install`
    /// keeps current, and what a verifier on this machine reads.
    fn managed_allowed_signers(&self) -> PathBuf {
        let file = self.home.join("allowed_signers");
        fs::write(&file, format!("{BLOCK_BEGIN}\n{BLOCK_END}\n")).unwrap();
        let mut config = fs::read_to_string(&self.global_config).unwrap();
        config.push_str(&format!(
            "[gpg \"ssh\"]\n\tallowedSignersFile = \"{}\"\n",
            file.display()
        ));
        fs::write(&self.global_config, config).unwrap();
        file
    }

    /// `agent-sign <args>` in the isolated world, bounded.
    fn agent_sign(&self, args: &[&str]) -> Output {
        let mut cmd = self.cmd(Path::new(env!("CARGO_BIN_EXE_agent-sign")));
        cmd.args(args).current_dir(&self.home);
        run_within(cmd, &format!("agent-sign {}", args.join(" ")))
    }
}

/// The lowercase hex SHA-256 of `data`.
fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Everything a program printed, stdout then stderr, without colour codes.
fn all_output(out: &Output) -> String {
    let raw = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let mut plain = String::new();
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' && chars.peek() == Some(&'[') {
            for d in chars.by_ref() {
                if d.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            plain.push(c);
        }
    }
    plain
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
// A commit, in parts, so a test can change exactly one and rebuild the
// buffer; and the approval for it.
// ---------------------------------------------------------------------------

/// The parts of an unsigned commit object. `author_when` and
/// `committer_when` are the text after the email: `<seconds> <zone>`.
#[derive(Clone)]
struct Parts {
    tree: String,
    parent: String,
    principal: String,
    author_name: String,
    author_when: String,
    committer_name: String,
    committer_when: String,
    /// Everything after the blank line, trailing newline included.
    message: String,
}

impl Parts {
    /// The unsigned commit object: the bytes git hands its signing program.
    fn buffer(&self) -> Vec<u8> {
        format!(
            "tree {}\nparent {}\nauthor {} <{}> {}\ncommitter {} <{}> {}\n\n{}",
            self.tree,
            self.parent,
            self.author_name,
            self.principal,
            self.author_when,
            self.committer_name,
            self.principal,
            self.committer_when,
            self.message
        )
        .into_bytes()
    }
}

/// What one commit approval names. `commit_sha256` is the D3 field; `None`
/// leaves it out of the text altogether.
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
    commit_sha256: Option<String>,
}

impl Ask {
    fn text(&self) -> String {
        let mut text = json!({
            "kind": "commit",
            "principal": self.principal,
            "machine": self.machine,
            "repo": self.repo,
            "branch": self.branch,
            "tree": self.tree,
            "parents": self.parents,
            "nonce": self.nonce,
            "expires_at": self.expires_at,
        });
        if let Some(hash) = &self.commit_sha256 {
            text["commit_sha256"] = json!(hash);
        }
        text.to_string()
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
/// service started.
fn approval_world() -> World {
    let mut w = World::new(&approval_config());
    start(&mut w);
    w
}

fn approval_config() -> String {
    format!(
        "{}\n[approvals]\ncommitments_key = \"{}\"\n",
        machine_config(),
        pub_line(&key(APPROVAL_SEED))
    )
}

fn start(w: &mut World) {
    if let Err(e) = w.try_start_service() {
        panic!(
            "CONTROL: the service doesn't accept `[approvals] commitments_key`, so the approval \
             path doesn't exist and no refusal can be told apart from it. The service {e}"
        );
    }
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

fn refused(answer: &Option<Response>) -> bool {
    !matches!(answer, Some(Response::Signed { .. }))
}

/// A new commit in `repo` adding `file`, as the runner would build it: fixed
/// author and committer dates (a minute ago, so any date a test moves a
/// little stays inside the signing certificate's window), both identities
/// the principal.
fn fresh_parts(w: &World, repo: &Path, file: &str) -> Parts {
    let parent = w.rev(repo, "HEAD");
    let tree = w.tree_with(repo, "HEAD", file, &format!("{file} {}\n", fresh()));
    let principal = principal_for("claude-code", "approved-run");
    let when = format!("{} +0000", now_secs() - 60);
    Parts {
        tree,
        parent,
        author_name: "Claude Code".into(),
        committer_name: "Claude Code".into(),
        author_when: when.clone(),
        committer_when: when,
        message: format!("approved: {file}\n"),
        principal,
    }
}

/// An approval for exactly `parts`, bound to its commit's hash.
fn ask_for(w: &World, repo: &Path, parts: &Parts) -> Ask {
    Ask {
        principal: parts.principal.clone(),
        machine: MACHINE.into(),
        repo: w.canonical(repo),
        branch: "work".into(),
        tree: parts.tree.clone(),
        parents: vec![parts.parent.clone()],
        nonce: fresh(),
        expires_at: now_secs() + 600,
        commit_sha256: Some(sha256_hex(&parts.buffer())),
    }
}

/// Presents the approval `ask` with `buffer`.
fn present_ask(w: &World, ask: &Ask, buffer: &[u8]) -> Option<Response> {
    let (text, sig) = ask.signed();
    present(w, &text, &sig, buffer, &ask.repo, &ask.branch)
}

/// The control every D3 test uses: `ask`'s own exact commit is signed, and
/// the signature is Good for its principal under this machine's trust.
fn assert_signs_exactly(w: &World, ask: &Ask, parts: &Parts, context: &str) -> String {
    let buffer = parts.buffer();
    let answer = present_ask(w, ask, &buffer);
    let Some(Response::Signed { signature_pem }) = answer else {
        panic!(
            "CONTROL ({context}): an approval bound to its commit's hash \
             (commit_sha256 {:?}) wasn't signed for that exact commit ({answer:?}). Today the \
             approval's `commit_sha256` is a field the service doesn't know, so it refuses the \
             whole approval.\nservice log:\n{}",
            ask.commit_sha256,
            w.service_log()
        );
    };
    assert!(
        w.good_as(&ask.principal, &signature_pem, &buffer),
        "CONTROL ({context}): the signature isn't Good for {} under this machine's trust",
        ask.principal
    );
    signature_pem
}

/// One refusal test: an approval for `parts`, captured, is presented with a
/// commit that differs by `change` alone. It must be refused; then the same
/// approval, presented with the commit it names, must sign, which shows the
/// refusal was about the change and not about the nonce, the expiry or
/// anything else, and that it did not use the approval up.
fn changed_commit_is_refused(w: &World, repo: &Path, what: &str, change: &dyn Fn(&mut Parts)) {
    let parts = fresh_parts(w, repo, &format!("tamper-{}.txt", fresh()));
    let ask = ask_for(w, repo, &parts);
    let mut other = parts.clone();
    change(&mut other);
    assert_ne!(
        other.buffer(),
        parts.buffer(),
        "PREMISE ({what}): the changed commit is the same bytes as the approved one"
    );
    let answer = present_ask(w, &ask, &other.buffer());
    assert!(
        refused(&answer),
        "D3: an approval bound to commit {} signed a commit that differs by {what} ({answer:?}); \
         the approval must bind the whole commit.\nservice log:\n{}",
        sha256_hex(&parts.buffer()),
        w.service_log()
    );
    assert_signs_exactly(
        w,
        &ask,
        &parts,
        &format!("after refusing a commit that differs by {what}"),
    );
}

// ===========================================================================
// D3. The approval binds the whole commit.
// ===========================================================================

/// D3 control. The legitimate runner's exact commit still works end to end:
/// built with fixed dates, hashed, approved, presented, signed. The
/// signature is Good for the principal under plain ssh-keygen, the commit
/// object git would store (the buffer with the signature as its `gpgsig`)
/// is Good under git's own check, which proves the hashed bytes are what git
/// verifies, and `agent-sign verify` reports an approval attestation.
///
/// Fails today: the approval's `commit_sha256` is an unknown field, so the
/// whole approval is refused.
#[test]
fn d3_the_runners_exact_commit_still_signs_and_verifies() {
    let w = approval_world();
    let repo = w.repo();
    let parts = fresh_parts(&w, &repo, "runner.txt");
    let ask = ask_for(&w, &repo, &parts);
    let text = ask.text();
    assert!(
        text.contains(&format!(
            "\"commit_sha256\":\"{}\"",
            sha256_hex(&parts.buffer())
        )),
        "PREMISE: the test's approval doesn't carry the commit's hash: {text}"
    );
    let signature = assert_signs_exactly(&w, &ask, &parts, "the runner's exact commit");

    let buffer = parts.buffer();
    let commit = w.write_signed_commit(&repo, &buffer, &signature);
    let (good, signer) = w.signature_of(&repo, &commit);
    assert_eq!(
        good, "G",
        "D3 control: git's own check of the stored commit isn't Good ({good:?}, {signer:?}): the \
         hashed bytes aren't the bytes git verifies"
    );
    let trust = w.trust_file();
    let out = w.verify_output(&repo, &commit, &trust);
    let said = all_output(&out);
    assert!(
        out.status.success()
            && said.to_lowercase().contains("attestation:")
            && said.contains("approval"),
        "D3 control: `agent-sign verify` didn't verify the runner's commit and print its approval \
         attestation: {}",
        text_of(&out)
    );
}

fn text_of(out: &Output) -> String {
    format!(
        "status: {}\nstdout: {}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// D3. A captured approval presented with a different message is refused:
/// another sentence, a trailer added (a `Signed-off-by` the approver never
/// saw), the trailing newline dropped, and an empty message. Each differs
/// from the approved commit in the message alone.
///
/// Fails today: the control (the exact commit signs) fails, because
/// `commit_sha256` is an unknown field; once it is known, only a service
/// that binds the message passes.
#[test]
fn d3_a_captured_approval_with_a_different_message_is_refused() {
    let w = approval_world();
    let repo = w.repo();
    let changes: [(&str, Box<dyn Fn(&mut Parts)>); 4] = [
        (
            "another message",
            Box::new(|p| p.message = "approved by the commitments check: merge me\n".into()),
        ),
        (
            "a trailer added",
            Box::new(|p| {
                p.message
                    .push_str("\nSigned-off-by: Taylor <taylor@example.com>\n")
            }),
        ),
        (
            "the trailing newline dropped",
            Box::new(|p| p.message = p.message.trim_end().to_string()),
        ),
        ("an empty message", Box::new(|p| p.message = "\n".into())),
    ];
    for (what, change) in &changes {
        changed_commit_is_refused(&w, &repo, what, change.as_ref());
    }
}

/// D3. A captured approval presented with a different author name or author
/// date is refused. Part 1 checks only that the author's email is the
/// principal, so each of these commits passes everything part 1 checks: the
/// author's name changed (to the person's, to a stranger's), the author's
/// date moved back an hour and forward a day, and the author's time zone
/// changed with the same instant.
///
/// Fails today: the control fails (unknown `commit_sha256`); then only a
/// service that binds the whole commit passes.
#[test]
fn d3_a_captured_approval_with_a_different_author_name_or_date_is_refused() {
    let w = approval_world();
    let repo = w.repo();
    let changes: [(&str, Box<dyn Fn(&mut Parts)>); 5] = [
        (
            "the author's name (the person's)",
            Box::new(|p| p.author_name = PERSON_NAME.into()),
        ),
        (
            "the author's name (a stranger's)",
            Box::new(|p| p.author_name = "Mallory Mallory".into()),
        ),
        (
            "the author's date, an hour earlier",
            Box::new(|p| p.author_when = "1000000000 +0000".into()),
        ),
        (
            "the author's date, a day later",
            Box::new(|p| p.author_when = format!("{} +0000", now_secs() + 86_400)),
        ),
        (
            "the author's time zone",
            Box::new(|p| {
                p.author_when = p.author_when.replace("+0000", "-0500");
            }),
        ),
    ];
    for (what, change) in &changes {
        changed_commit_is_refused(&w, &repo, what, change.as_ref());
    }
}

/// D3. A captured approval presented with a different committer date is
/// refused. The dates moved stay inside the signing certificate's window
/// (the service refuses a committer date outside it anyway), so each commit
/// passes part 1's date check: half a minute earlier, half a minute later,
/// the same instant in another time zone, and the committer's name changed
/// (the committer's email is already bound).
///
/// Fails today: the control fails (unknown `commit_sha256`); then only a
/// service that binds the whole commit passes.
#[test]
fn d3_a_captured_approval_with_a_different_committer_date_is_refused() {
    let w = approval_world();
    let repo = w.repo();
    let shifted = |delta: i64| -> Box<dyn Fn(&mut Parts)> {
        Box::new(move |p| {
            let secs: i64 = p.committer_when.split(' ').next().unwrap().parse().unwrap();
            p.committer_when = format!("{} +0000", secs + delta);
        })
    };
    let changes: [(&str, Box<dyn Fn(&mut Parts)>); 4] = [
        ("the committer's date, 30 s earlier", shifted(-30)),
        ("the committer's date, 30 s later", shifted(30)),
        (
            "the committer's time zone",
            Box::new(|p| {
                p.committer_when = p.committer_when.replace("+0000", "+0200");
            }),
        ),
        (
            "the committer's name",
            Box::new(|p| p.committer_name = "Release Bot".into()),
        ),
    ];
    for (what, change) in &changes {
        changed_commit_is_refused(&w, &repo, what, change.as_ref());
    }
}

/// D3. A replay is refused: the same approval and the same commit presented
/// a second time, after the first signed. Then a fresh approval for another
/// commit still signs, so the refusal was the replay's and not a service
/// that stopped answering. (The nonce is checked and recorded as one step
/// under the lock, and synced before the signature: the second file's
/// `the_same_approval_presented_twice_at_once_is_signed_exactly_once`.)
///
/// Fails today: the control (the first presentation) fails, because
/// `commit_sha256` is an unknown field.
#[test]
fn d3_a_replay_of_the_same_approval_and_commit_is_refused() {
    let w = approval_world();
    let repo = w.repo();
    let parts = fresh_parts(&w, &repo, "replay.txt");
    let ask = ask_for(&w, &repo, &parts);
    assert_signs_exactly(&w, &ask, &parts, "the first presentation");

    let (text, sig) = ask.signed();
    for attempt in 1..=2 {
        let again = present(&w, &text, &sig, &parts.buffer(), &ask.repo, &ask.branch);
        assert!(
            refused(&again),
            "D3: the same approval (nonce {}) and the same commit were signed a second time \
             (replay {attempt}, {again:?})",
            ask.nonce
        );
    }

    let next = fresh_parts(&w, &repo, "after-replay.txt");
    let next_ask = ask_for(&w, &repo, &next);
    assert_signs_exactly(&w, &next_ask, &next, "a fresh approval after the replays");
}

/// D3. An approval with no `commit_sha256` is refused, however good the
/// rest. Then the same commit with a hash-bearing approval (a new nonce)
/// signs, so the missing field was the only difference. Then hashes that
/// aren't the commit's lowercase hex SHA-256 are refused too: empty, cut
/// short, in capitals, not hex at all.
///
/// Fails today on its first assertion: an approval with no hash is signed.
#[test]
fn d3_an_approval_without_commit_sha256_is_refused() {
    let w = approval_world();
    let repo = w.repo();
    let parts = fresh_parts(&w, &repo, "unbound.txt");
    let mut ask = ask_for(&w, &repo, &parts);
    ask.commit_sha256 = None;
    assert!(
        !ask.text().contains("commit_sha256"),
        "PREMISE: the approval text still names commit_sha256"
    );
    let answer = present_ask(&w, &ask, &parts.buffer());
    assert!(
        refused(&answer),
        "D3: an approval with no commit_sha256 was signed ({answer:?}): it binds nothing about \
         the commit's message, names or dates\nservice log:\n{}",
        w.service_log()
    );

    let bound = ask_for(&w, &repo, &parts);
    assert_signs_exactly(
        &w,
        &bound,
        &parts,
        "the same commit, with its hash in the approval",
    );

    let malformed: [(&str, fn(String) -> String); 4] = [
        ("an empty hash", |_| String::new()),
        ("a hash cut short", |h| h[..h.len() - 2].to_string()),
        ("a hash in capitals", |h| h.to_uppercase()),
        ("a hash that isn't hex", |h| "z".repeat(h.len())),
    ];
    for (what, spoil) in malformed {
        let next = fresh_parts(&w, &repo, &format!("malformed-{}.txt", fresh()));
        let mut ask = ask_for(&w, &repo, &next);
        ask.commit_sha256 = Some(spoil(sha256_hex(&next.buffer())));
        let answer = present_ask(&w, &ask, &next.buffer());
        assert!(
            refused(&answer),
            "D3: an approval carrying {what} ({:?}) was signed for the commit it was meant for \
             ({answer:?})",
            ask.commit_sha256
        );
    }
}

// ===========================================================================
// D2. The authority without OpenBao: trusted only by `trust install`.
// ===========================================================================

/// Whether `said` (doctor's output) tells the person plainly that the
/// service's certificate authority isn't trusted yet and names the command
/// that trusts it. The wording is the builder's; these are the words the
/// decision used ("the service's authority isn't trusted yet") and the
/// command's exact name.
fn says_authority_not_trusted_yet(said: &str) -> bool {
    let said = said.to_lowercase().replace('\u{2019}', "'");
    (said.contains("not trusted yet") || said.contains("isn't trusted yet"))
        && said.contains("authorit")
        && said.contains("agent-sign trust install")
}

/// D2. `agent-sign doctor`, with the service running and its live authority
/// not yet in any trust file, says so plainly and names `agent-sign trust
/// install`. Premises, checked after the doctor assertion so a failing build
/// is told apart by its first failing line: the file git names holds only
/// its empty managed block (the start wrote nothing into it), and an
/// approved commit signed by this service is not Good under it. Then `agent-sign trust
/// install` succeeds, the same commit is Good under that file, and doctor no
/// longer says the authority isn't trusted yet.
///
/// Fails today: the start itself writes the authority into the allowed
/// signers file, so doctor says nothing about it (and there is no `trust
/// install`).
#[test]
fn d2_doctor_says_when_the_services_authority_is_not_trusted_yet() {
    let mut w = World::new(&approval_config());
    let allowed = w.managed_allowed_signers();
    let empty_block = fs::read_to_string(&allowed).unwrap();
    start(&mut w);
    let repo = w.repo();

    let before = w.agent_sign(&["doctor"]);
    let said = all_output(&before);
    assert!(
        says_authority_not_trusted_yet(&said),
        "D2: with the service running and its authority in no trust file, `agent-sign doctor` \
         doesn't say plainly that the service's authority isn't trusted yet and name `agent-sign \
         trust install`. It said:\n{said}\nthe allowed-signers file now reads:\n{}",
        fs::read_to_string(&allowed).unwrap_or_default()
    );

    // The claim is true, not just worded: the start wrote no trust.
    assert_eq!(
        fs::read_to_string(&allowed).unwrap(),
        empty_block,
        "D2: the service's start wrote into the allowed-signers file git names; only `agent-sign \
         trust install` may"
    );
    let parts = fresh_parts(&w, &repo, "doctor.txt");
    let ask = ask_for(&w, &repo, &parts);
    let signature =
        assert_signs_exactly(&w, &ask, &parts, "an approved commit, before trust install");
    assert!(
        !w.good_under(&allowed, &ask.principal, &signature, &parts.buffer()),
        "D2: doctor says the authority isn't trusted yet, but the allowed-signers file git names \
         already trusts the service's signatures"
    );

    let install = w.agent_sign(&["trust", "install"]);
    assert!(
        install.status.success(),
        "D2: `agent-sign trust install` failed: {}",
        text_of(&install)
    );
    assert!(
        w.good_under(&allowed, &ask.principal, &signature, &parts.buffer()),
        "D2: after `agent-sign trust install` the allowed-signers file git names doesn't trust \
         the service's signatures; it reads:\n{}\n{}",
        fs::read_to_string(&allowed).unwrap_or_default(),
        text_of(&install)
    );
    let after = all_output(&w.agent_sign(&["doctor"]));
    assert!(
        !after.to_lowercase().contains("trusted yet"),
        "D2: after `agent-sign trust install`, doctor still says the authority isn't trusted \
         yet:\n{after}"
    );
}
