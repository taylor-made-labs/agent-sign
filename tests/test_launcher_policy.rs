//! The launcher's policy: what a launched session can and can't do, and what
//! an agent nobody launched gets.
//!
//! Written before the build, as its eval, from the suite PM's decisions D4
//! and D1 (31 Oct 2026, `docs/caller-identity.md`, build plan steps S6 to
//! S8, and the critique of that plan). Each test names its decision in its
//! doc comment. They fail today because there is no launcher
//! (`agent-sign launch`) and the plain path still signs. A test that needs
//! the launcher starts by saying "NO TRUSTED LAUNCHER" until it exists, so a
//! refusal or a block is never the launcher's absence.
//!
//! **D4, the launcher in one account.** bwrap gets `/` read-only; only the
//! session's own working copy and a private tmp are writable, and
//! `~/.agent-sign` and agent-sign's installed programs are read-only. So a
//! launched session can't plant a hook in another session's `.git/hooks`,
//! write into its tree, or change agent-sign's config, keys or programs
//! (the critique's first finding: `--dev-bind / /` left all of it writable
//! to every session). `agent-sign verify` says what the isolation is and
//! isn't. A one-account launch is refused once a system config exists. The
//! tests can't write `/etc`, so they use a seam that only the debug test
//! build honours, `AGENT_SIGN_TEST_SYSTEM_CONFIG`, set to a path of the
//! test's own, like `AGENT_SIGN_TEST_ACCOUNTS`. The pidfd_getfd gap, where a
//! plain process of the same uid takes a session's channel, is a known
//! failure: its test asserts the gap is closed and is `#[ignore]`d, so it is
//! listed and fails under `--ignored` until system mode.
//!
//! **D1, an agent nobody launched.** A plain process with Claude Code's
//! marks gets an unsigned commit under the agent's own names and a one-line
//! note. The wrapper's refusals (protected branch, forbidden paths, the diff
//! limit, the rate limit) still apply, one test for each, with a control
//! that an ordinary commit goes through unsigned. `agent-sign verify` says an
//! unsigned or unattested commit can live on a branch, but merging to main
//! will require an attested signature (launcher or approval). The merge
//! gate itself is not built here.
//!
//! **Harness.** Copied from `test_caller_identity.rs`: an empty environment
//! plus a temporary HOME, a temporary global git config, no system config,
//! and a socket in the temporary directory; no private key is written to a
//! file; every wait is bounded and every process started is stopped at the
//! end. One difference, forced by D4: a live session signals "ready" and
//! "stop" through files in its own working copy, because it can write
//! nowhere else. Several tests collect every failed assertion
//! ([`Problems`]) so one run reports them all.
//!
//! Run on a server, never on the Mac: `cargo test --test test_launcher_policy`,
//! and `-- --ignored` for the known gap.

use std::cell::Cell;
use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256, Sha512};
use ssh_key::certificate::{Builder, CertType};
use ssh_key::private::{Ed25519Keypair, PrivateKey};
use ssh_key::public::{Ed25519PublicKey, KeyData};
use tempfile::{TempDir, tempdir};

use agent_sign::crypto::openssh_ed25519_line;

/// The machine every test service is named for.
const MACHINE: &str = "hetzner";
/// Its agents' domain.
const DOMAIN: &str = "hetzner.agents.local";
const PERSON_NAME: &str = "Human Developer";
const PERSON_EMAIL: &str = "dev@example.com";
/// Every program run gets at most this long.
const RUN_LIMIT: Duration = Duration::from_secs(30);
/// What the launcher probe prints when `agent-sign launch` ran its program.
const LAUNCH_PROBE: &str = "caller-identity-launch-probe";
/// In every attacker program's command line, so a search for a victim's
/// marker never finds the attacker itself.
const ATTACKER_TAG: &str = "caller-identity-attacker";

/// The seeds of the in-memory keys.
const PERSON_SEED: [u8; 32] = [3; 32];
const CA_SEED: [u8; 32] = [11; 32];
const SUBJECT_SEED: [u8; 32] = [12; 32];

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
    /// Whether `agent-sign launch` works, once probed.
    launcher: Cell<Option<bool>>,
    /// Where the test-only seam `AGENT_SIGN_TEST_SYSTEM_CONFIG` points
    /// agent-sign for `/etc/agent-sign/system.toml`, when it is set: the
    /// tests can't write `/etc`. Only the debug test build honours it (the
    /// `test-authenticator` feature), like `AGENT_SIGN_TEST_ACCOUNTS`.
    system_config: Option<PathBuf>,
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
            system_config: None,
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
        if let Some(system) = &self.system_config {
            env.push(("AGENT_SIGN_TEST_SYSTEM_CONFIG".into(), s(system)));
        }
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

/// A certificate from the authority with [`CA_SEED`] for `subject`, naming
/// `principal`, in the shape agent-sign issues now, carrying the extension
/// `attestation@agent-sign` = `unattested`: a signature a verifier trusts
/// that neither the launcher nor an approval established. Built here with
/// ssh-key, so the test doesn't trust agent-sign's own issuing code.
fn unattested_cert(principal: &str, subject: &SigningKey) -> Vec<u8> {
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
        .unwrap()
        .extension("attestation@agent-sign", "unattested")
        .unwrap();
    let ca = PrivateKey::from(Ed25519Keypair::from_seed(&CA_SEED));
    b.sign(&ca).unwrap().to_bytes().unwrap()
}

/// Every failed assertion of a test, collected, so one run reports them
/// all: these tests fail today for several separate reasons, and the first
/// one would otherwise hide the others.
#[derive(Default)]
struct Problems(Vec<String>);

impl Problems {
    fn check(&mut self, ok: bool, what: impl FnOnce() -> String) {
        if !ok {
            self.0.push(what());
        }
    }

    fn finish(self) {
        assert!(
            self.0.is_empty(),
            "{} assertion(s) failed:\n- {}",
            self.0.len(),
            self.0.join("\n- ")
        );
    }
}

// ---------------------------------------------------------------------------
// Live sessions, and what a plain process of the account does.
// ---------------------------------------------------------------------------

/// A session that stays alive until the test ends (at most a minute), so
/// its process and its filesystem can be looked at.
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

/// Arguments of a live session's script: `$0` its marker, `$1` its working
/// copy, `$2` agent-git, `$3` the file it creates when ready, `$4` the file
/// whose appearance ends it.
const COMMIT_AND_STAY: &str = r#"cd "$1" && "$2" commit -q -m live-session && : > "$3"; i=0; while [ $i -lt 600 ] && [ ! -e "$4" ]; do sleep 0.1; i=$((i+1)); done"#;

/// A live session that makes a temporary file of its own and records where.
const TMP_AND_STAY: &str = r#"cd "$1" && f=$(mktemp) && echo secret > "$f" && printf '%s' "$f" > "$1/.victim-tmp-path" && : > "$3"; i=0; while [ $i -lt 600 ] && [ ! -e "$4" ]; do sleep 0.1; i=$((i+1)); done"#;

impl World {
    /// Starts a [`LiveSession`] of `slug` in `repo` running `script` (one of
    /// the constants above) and waits until it is ready.
    ///
    /// Unlike `test_caller_identity.rs`, the ready and stop files live in
    /// `repo`, the session's own working copy: D4 makes the rest of the
    /// filesystem read-only to a session, so a session can't make a file in
    /// the test's home to say it is ready. The test, a plain process,
    /// writes the stop file from outside.
    fn live_session(&self, repo: &Path, slug: &str, script: &str) -> LiveSession {
        let marker = format!("launcher-policy-victim-{}", fresh());
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
                script,
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
                "CONTROL: the {slug} session didn't get ready; its output:\n{}\nservice log:\n{}",
                fs::read_to_string(&log).unwrap_or_default(),
                self.service_log()
            );
        }
        session
    }

    /// `agent-sign launch --agent slug -- program args` in `dir`, whether or
    /// not the probe found a launcher.
    fn launch(&self, dir: &Path, slug: &str, program: &Path, args: &[&str]) -> Command {
        let mut cmd = self.cmd(Path::new(env!("CARGO_BIN_EXE_agent-sign")));
        cmd.args(["launch", "--agent", slug, "--"])
            .arg(program)
            .args(args)
            .current_dir(dir);
        cmd
    }

    /// A commit of `file` (with `content`) staged and made by a plain
    /// process with `marks`: no launcher.
    fn plain_commit(
        &self,
        repo: &Path,
        marks: &[(&str, &str)],
        file: &str,
        content: &str,
    ) -> Output {
        if let Some(parent) = Path::new(file).parent() {
            fs::create_dir_all(repo.join(parent)).unwrap();
        }
        self.stage(repo, file, content);
        self.plain_agent(repo, marks, &["commit", "-q", "-m", &format!("add {file}")])
    }

    /// Whether commit `rev` carries no signature at all.
    fn is_unsigned(&self, repo: &Path, rev: &str) -> bool {
        !self
            .git_ok(repo, &["cat-file", "commit", rev])
            .contains("gpgsig")
    }
}

/// Claude Code's marks in a plain process: what an agent run in a terminal
/// carries today.
fn claude_marks(session: &str) -> [(&str, &str); 2] {
    [("CLAUDECODE", "1"), ("CLAUDE_CODE_SESSION_ID", session)]
}

/// What a launched session tries on the filesystem: for each place it prints
/// "reached <place>" if the write (for a program, the write permission)
/// got through, and "blocked <place>" if not. Its two first places are the
/// ones it is meant to write. Arguments: `$1` another session's working
/// copy, `$2` HOME, `$3` to `$6` agent-sign's four built programs.
const ATTACK_SCRIPT: &str = r##"
victim=$1; home=$2
try() { label=$1; shift; if "$@" 2>/dev/null; then echo "reached $label"; else echo "blocked $label"; fi; }
try own-working-copy sh -c 'printf x > "$1"' _ ./own-file.txt
try private-tmp sh -c 'd=$(mktemp -d) && printf x > "$d/f"' _
try other-hook sh -c 'printf "#!/bin/sh\n" > "$1"' _ "$victim/.git/hooks/pre-commit"
try other-tree-new-file sh -c 'printf x > "$1"' _ "$victim/planted.txt"
try other-tree-edit sh -c 'printf x >> "$1"' _ "$victim/base.txt"
try config sh -c 'printf "x\n" >> "$1"' _ "$home/.agent-sign/config.toml"
try keys sh -c 'printf x > "$1"' _ "$home/.agent-sign/keys/planted"
try state sh -c 'printf x > "$1"' _ "$home/.agent-sign/planted"
try installed-program sh -c 'printf x > "$1"' _ "$home/.agent-sign/bin/agent-git"
try home sh -c 'printf x > "$1"' _ "$home/planted"
try built-agent-git test -w "$3"
try built-agent-sign test -w "$4"
try built-agent-signd test -w "$5"
try built-agent-ssh-sign test -w "$6"
"##;

/// What a plain process of the account tries on a live session: for every
/// process whose command line holds the session's marker, take each of its
/// descriptors with `pidfd_getfd` and report the sockets (the session's
/// signing channel is one). `$1` tags the attacker itself, `$2` the marker.
const TAKE_CHANNEL_SCRIPT: &str = r#"
import ctypes, json, os, stat, sys
tag, marker = sys.argv[1], sys.argv[2]
me = os.getpid()
libc = ctypes.CDLL(None, use_errno=True)
out = {"found": [], "sockets": []}
for d in os.listdir('/proc'):
    if not d.isdigit() or int(d) == me:
        continue
    try:
        with open('/proc/%s/cmdline' % d, 'rb') as f:
            cl = f.read()
    except Exception:
        continue
    if marker.encode() not in cl or tag.encode() in cl:
        continue
    pid = int(d)
    out["found"].append(pid)
    try:
        pfd = os.pidfd_open(pid)
    except Exception:
        continue
    for t in range(256):
        r = libc.syscall(438, pfd, t, 0)
        if r >= 0:
            try:
                if stat.S_ISSOCK(os.fstat(r).st_mode):
                    out["sockets"].append([pid, t])
            finally:
                os.close(r)
    os.close(pfd)
print(json.dumps(out))
"#;

// ===========================================================================
// D4. The one-account launcher keeps sessions apart, and says how far.
// ===========================================================================

/// D4, the filesystem. Two launched sessions: a victim that stays alive in
/// its own working copy, and an attacker that tries to write into the
/// victim's working copy (a hook in `.git/hooks`, a new file, an edit to a
/// tracked file), into `~/.agent-sign` (the config, the keys, anything
/// new), over agent-sign's installed programs, over the programs the
/// tests built, and into the home folder itself. Every attempt must be
/// blocked: the session's filesystem is read-only apart from its own working
/// copy and a private tmp. The two controls, writing in its own working
/// copy and making a temporary file with `mktemp` (so the launcher must give
/// the session a usable `TMPDIR`), must get through. Fails today: there is
/// no launcher.
#[cfg(target_os = "linux")]
#[test]
fn d4_a_launched_session_writes_only_to_its_own_working_copy_and_a_private_tmp() {
    let mut w = World::new(&machine_config());
    w.start_service();
    w.require_launcher("D4 (a launched session's filesystem)");
    let victim = w.repo_named("victim");
    fs::create_dir_all(victim.join(".git/hooks")).unwrap();
    w.stage(&victim, "v.txt", "victim\n");
    let _victim_session = w.live_session(&victim, "claude-code", COMMIT_AND_STAY);

    let state = w.home.join(".agent-sign");
    fs::create_dir_all(state.join("keys")).unwrap();
    fs::create_dir_all(state.join("bin")).unwrap();
    let installed = state.join("bin/agent-git");
    fs::write(&installed, "installed\n").unwrap();
    let config_before = fs::read_to_string(w.config_path()).unwrap();
    let base_before = fs::read_to_string(victim.join("base.txt")).unwrap();

    let attacker = w.repo_named("attacker");
    let victim_s = victim.to_string_lossy().into_owned();
    let home_s = w.home.to_string_lossy().into_owned();
    let out = w.run_session(
        &attacker,
        "codex",
        &[],
        Path::new("/bin/sh"),
        &[
            "-c",
            ATTACK_SCRIPT,
            ATTACKER_TAG,
            &victim_s,
            &home_s,
            env!("CARGO_BIN_EXE_agent-git"),
            env!("CARGO_BIN_EXE_agent-sign"),
            env!("CARGO_BIN_EXE_agent-signd"),
            env!("CARGO_BIN_EXE_agent-ssh-sign"),
        ],
    );
    let said = String::from_utf8_lossy(&out.stdout).into_owned();
    let result = |label: &str| {
        said.lines()
            .find_map(|l| l.strip_suffix(label).map(|s| s.trim().to_string()))
    };

    let mut p = Problems::default();
    for (label, what) in [
        ("own-working-copy", "its own working copy"),
        ("private-tmp", "a temporary file made with mktemp"),
    ] {
        p.check(result(label).as_deref() == Some("reached"), || {
            format!(
                "CONTROL: the session couldn't write {what}; it printed:\n{}",
                text(&out)
            )
        });
    }
    for (label, what) in [
        ("other-hook", "a hook in another session's .git/hooks"),
        (
            "other-tree-new-file",
            "a new file in another session's tree",
        ),
        (
            "other-tree-edit",
            "a tracked file in another session's tree",
        ),
        ("config", "~/.agent-sign/config.toml"),
        ("keys", "a file in ~/.agent-sign/keys"),
        ("state", "a file in ~/.agent-sign"),
        (
            "installed-program",
            "agent-sign's installed programs (~/.agent-sign/bin)",
        ),
        ("home", "the home folder outside any working copy"),
        ("built-agent-git", "the agent-git program"),
        ("built-agent-sign", "the agent-sign program"),
        ("built-agent-signd", "the agent-signd program"),
        ("built-agent-ssh-sign", "the agent-ssh-sign program"),
    ] {
        p.check(result(label).as_deref() == Some("blocked"), || {
            format!(
                "D4: a launched session could write {what} ({label}: {:?})",
                result(label)
            )
        });
    }
    // What the filesystem itself says, whatever the session printed.
    p.check(!victim.join(".git/hooks/pre-commit").exists(), || {
        "D4: a hook is now in another session's .git/hooks".into()
    });
    p.check(!victim.join("planted.txt").exists(), || {
        "D4: a file is now in another session's working copy".into()
    });
    p.check(
        fs::read_to_string(victim.join("base.txt")).unwrap() == base_before,
        || "D4: another session's tracked file was changed".into(),
    );
    p.check(
        fs::read_to_string(w.config_path()).unwrap() == config_before,
        || "D4: ~/.agent-sign/config.toml was changed".into(),
    );
    p.check(
        !state.join("keys/planted").exists() && !state.join("planted").exists(),
        || "D4: a file is now in ~/.agent-sign".into(),
    );
    p.check(
        fs::read_to_string(&installed).unwrap() == "installed\n",
        || "D4: agent-sign's installed program was replaced".into(),
    );
    p.check(!w.home.join("planted").exists(), || {
        "D4: a file is now in the home folder".into()
    });
    p.finish();
}

/// D4, the private tmp. A launched session makes a temporary file and
/// records its path in its own working copy; another launched session is
/// handed that path and must not see the file. Fails today: there is no
/// launcher.
#[cfg(target_os = "linux")]
#[test]
fn d4_a_launched_sessions_tmp_is_private() {
    let mut w = World::new(&machine_config());
    w.start_service();
    w.require_launcher("D4 (a launched session's private tmp)");
    let victim = w.repo_named("tmp-victim");
    let _session = w.live_session(&victim, "claude-code", TMP_AND_STAY);
    let tmp_path = fs::read_to_string(victim.join(".victim-tmp-path")).unwrap();
    let attacker = w.repo_named("tmp-attacker");
    let out = w.run_session(
        &attacker,
        "codex",
        &[],
        Path::new("/bin/sh"),
        &[
            "-c",
            r#"if [ -e "$1" ]; then echo "visible: $(cat "$1" 2>&1)"; else echo hidden; fi"#,
            ATTACKER_TAG,
            tmp_path.trim(),
        ],
    );
    let said = String::from_utf8_lossy(&out.stdout);
    assert!(
        said.trim() == "hidden",
        "D4: a launched session saw another session's temporary file {} ({}):\n{}",
        tmp_path.trim(),
        said.trim(),
        text(&out)
    );
}

/// D4, what verify says. A one-account launched session's commit is Good as
/// its principal, and `agent-sign verify` says exactly how far that goes:
/// "launcher, same account: isolated from other launched sessions, not from
/// other processes of this account". It never says "proven", "claimed" or
/// "unattested", and (D1) none of the unsigned-or-unattested merge warning.
/// Fails today: there is no launcher.
#[cfg(target_os = "linux")]
#[test]
fn d4_verify_on_a_one_account_launched_commit_says_what_the_isolation_is() {
    let mut w = World::new(&machine_config());
    w.start_service();
    w.require_launcher("D4 (control: a launched session signs as itself)");
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
    let lower = said.to_lowercase();
    let mut p = Problems::default();
    p.check(
        said.contains("launcher, same account: isolated from other launched sessions, not from other processes of this account"),
        || format!("D4: verify didn't say \"launcher, same account: isolated from other launched sessions, not from other processes of this account\"; it said: {said}"),
    );
    for word in ["proven", "claimed", "unattested"] {
        p.check(!lower.contains(word), || {
            format!("D4: verify said \"{word}\" of a one-account launched session: {said}")
        });
    }
    p.check(!lower.contains("merging to main will require"), || {
        format!("D1: verify warned about merging an attested launcher commit to main: {said}")
    });
    p.finish();
}

/// D4, system mode. Once a system config exists (the tests can't write
/// `/etc/agent-sign/system.toml`, so the test-only seam
/// `AGENT_SIGN_TEST_SYSTEM_CONFIG` points agent-sign at a path of the test's
/// own; honoured only by a build with the `test-authenticator` feature, like
/// `AGENT_SIGN_TEST_ACCOUNTS`), a launch with no account of its own for the
/// session is refused: it exits non-zero, says why (the system config), and
/// never runs its program. The control is the same launch before the file
/// exists, which must work. The check is made at each launch, not once at
/// start. Fails today: there is no launcher.
#[test]
fn d4_one_account_launch_is_refused_once_a_system_config_exists() {
    let mut w = World::new(&machine_config());
    let system = w.home.join("system.toml");
    w.system_config = Some(system.clone());
    w.start_service();
    w.require_launcher("D4 (control: one-account launch works while no system config exists)");
    assert!(!system.exists(), "setup: the system config exists already");
    fs::write(
        &system,
        "# system mode: this file existing is what counts\n",
    )
    .unwrap();
    let cmd = w.launch(
        &w.home,
        "claude-code",
        Path::new("/bin/sh"),
        &["-c", &format!("echo {LAUNCH_PROBE}")],
    );
    let out = run_within(cmd, "a one-account launch with a system config");
    let mut p = Problems::default();
    p.check(!out.status.success(), || {
        format!(
            "D4: one-account launch succeeded although a system config exists:\n{}",
            text(&out)
        )
    });
    p.check(
        !String::from_utf8_lossy(&out.stdout).contains(LAUNCH_PROBE),
        || {
            format!(
                "D4: the program ran although a system config exists:\n{}",
                text(&out)
            )
        },
    );
    p.check(
        String::from_utf8_lossy(&out.stderr)
            .to_lowercase()
            .contains("system"),
        || {
            format!(
                "D4: the refusal didn't say the system config is why:\n{}",
                text(&out)
            )
        },
    );
    p.finish();
}

/// D4, a known gap, recorded honestly. A plain process of the same account,
/// outside any session, takes a launched session's signing channel with
/// `pidfd_getfd`: bwrap's user namespace is owned by the same uid, so Yama
/// lets the owner in, and an executed program is dumpable again. The test
/// asserts the gap is CLOSED: that the plain process gets no socket out of
/// the session's processes. It is ignored (listed, runnable with
/// `--ignored`) and fails there until system mode gives each session a uid
/// of its own. Until then `agent-sign verify` says so in its words (see
/// `d4_verify_on_a_one_account_launched_commit_says_what_the_isolation_is`).
/// If a sandbox's own internal socket ever shows here, narrow the check to
/// the channel then.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "known gap in one-account mode: a plain process of the same uid can take a session's channel with pidfd_getfd; closed only by a uid per session (system mode)"]
fn d4_a_plain_process_of_the_account_cant_take_a_sessions_channel() {
    let mut w = World::new(&machine_config());
    w.start_service();
    w.require_launcher("D4 (a plain process taking a session's channel)");
    let python = find_on(&w.path, "python3");
    let victim = w.repo_named("victim");
    w.stage(&victim, "v.txt", "victim\n");
    let session = w.live_session(&victim, "claude-code", COMMIT_AND_STAY);
    let mut cmd = w.cmd(&python);
    cmd.args([
        "-I",
        "-c",
        TAKE_CHANNEL_SCRIPT,
        ATTACKER_TAG,
        &session.marker,
    ])
    .current_dir(&w.home);
    let out = run_within(cmd, "the plain process taking a channel");
    let report: serde_json::Value = serde_json::from_str(
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .last()
            .unwrap_or(""),
    )
    .unwrap_or_else(|e| {
        panic!(
            "CONTROL: the plain process printed no report ({e}):\n{}",
            text(&out)
        )
    });
    assert!(
        report["found"].as_array().is_some_and(|a| !a.is_empty()),
        "CONTROL: the plain process found none of the session's processes in /proc:\n{}",
        text(&out)
    );
    assert!(
        report["sockets"].as_array().is_some_and(|a| a.is_empty()),
        "D4 (known gap): a plain process of the same account took socket descriptors out of a \
         launched session with pidfd_getfd (pid, fd): {}",
        report["sockets"]
    );
}

// ===========================================================================
// D1. An agent nobody launched gets an unsigned commit, and the rules apply.
// ===========================================================================

/// A world with the service running and `extra` appended to the config.
fn plain_world(extra: &str) -> World {
    let mut w = World::new(&format!("{}\n{extra}", machine_config()));
    w.start_service();
    w
}

/// The one thing every D1 refusal test also checks, so each fails today for
/// the same stated reason: an ordinary commit by a plain process with agent
/// marks (no launcher) is made, and carries no signature at all.
fn plain_commit_is_unsigned(p: &mut Problems, w: &World, repo: &Path, before: &str, out: &Output) {
    let head = w.rev(repo, "HEAD");
    p.check(out.status.success() && head != before, || {
        format!(
            "CONTROL (D1): an ordinary plain commit wasn't made:\n{}",
            text(out)
        )
    });
    p.check(head != before && w.is_unsigned(repo, "HEAD"), || {
        "D1: the plain path signed an ordinary commit (it has a gpgsig); with no launcher it \
         must go through unsigned"
            .into()
    });
}

/// One refusal, checked: non-zero, no commit made, and the reason said.
fn refused_plainly(
    p: &mut Problems,
    w: &World,
    repo: &Path,
    before: &str,
    out: &Output,
    why: &str,
) {
    p.check(!out.status.success(), || {
        format!(
            "D1: the plain path didn't refuse ({why}); exit status was a success:\n{}",
            text(out)
        )
    });
    p.check(w.rev(repo, "HEAD") == before, || {
        format!("D1: the plain path made a commit that should have been refused ({why})")
    });
    p.check(
        String::from_utf8_lossy(&out.stderr)
            .to_lowercase()
            .contains(&why.to_lowercase()),
        || format!("D1: the refusal didn't say {why:?}:\n{}", text(out)),
    );
}

/// D1, the plain path. A process with Claude Code's marks and no launcher
/// commits. The commit goes through UNSIGNED (no `gpgsig` at all, not "Good",
/// not signed under any domain), under the agent's own names (not the
/// person's global ones), and stderr holds one line saying why: no launcher
/// started it. Fails today: the plain path signs it as
/// `claude-code.<session>@hetzner.agents.local`.
#[test]
fn d1_a_plain_process_with_agent_marks_commits_unsigned_under_the_agents_names_with_a_note() {
    let w = plain_world("");
    let repo = w.repo();
    let before = w.rev(&repo, "HEAD");
    w.stage(&repo, "plain.txt", "plain\n");
    let session = fresh();
    let out = w.plain_agent(
        &repo,
        &claude_marks(&session),
        &["commit", "-q", "-m", "plain shell"],
    );
    let mut p = Problems::default();
    p.check(out.status.success(), || {
        format!(
            "D1: the plain path refused an ordinary commit:\n{}",
            text(&out)
        )
    });
    let head = w.rev(&repo, "HEAD");
    p.check(head != before, || "D1: no commit was made".into());
    if head != before {
        p.check(w.is_unsigned(&repo, "HEAD"), || {
            let (g, signer) = w.signature_of(&repo, "HEAD");
            format!("D1: the plain commit carries a signature (%G? {g}, signer {signer:?}); it must carry none")
        });
        let names = w.git_ok(
            &repo,
            &["log", "-1", "--format=%an%x1f%ae%x1f%cn%x1f%ce", "HEAD"],
        );
        let fields: Vec<&str> = names.split('\x1f').collect();
        p.check(
            fields.len() == 4
                && fields[0] == "Claude Code"
                && fields[2] == "Claude Code"
                && fields[1].starts_with("claude-code.")
                && fields[3].starts_with("claude-code.")
                && fields[1].contains("agents.local")
                && fields[3].contains("agents.local"),
            || format!("D1: the plain commit isn't under the agent's own names (author name, email, committer name, email): {fields:?}"),
        );
    }
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let lines: Vec<&str> = stderr.lines().filter(|l| !l.trim().is_empty()).collect();
    p.check(
        lines.len() == 1
            && lines[0].to_lowercase().contains("unsigned")
            && lines[0].to_lowercase().contains("launcher"),
        || format!("D1: stderr isn't one line saying the commit is unsigned because no launcher started it:\n{stderr}"),
    );
    p.finish();
}

/// D1, a protected branch. The plain path still refuses a commit on `main`
/// (default protected branches), makes none, and says "protected". As
/// `test_edge_cases.rs::a_protected_branch_is_refused_without_asking`. The
/// control, the same process then committing on a branch that isn't
/// protected, must go through unsigned (D1), which is what fails today.
#[test]
fn d1_the_plain_path_still_refuses_a_protected_branch() {
    let w = plain_world("");
    let repo = w.repo();
    w.git_ok(&repo, &["checkout", "-q", "-b", "main"]);
    let session = fresh();
    let marks = claude_marks(&session);
    let before = w.rev(&repo, "HEAD");
    let out = w.plain_commit(&repo, &marks, "a.txt", "a\n");
    let mut p = Problems::default();
    refused_plainly(&mut p, &w, &repo, &before, &out, "protected");
    w.git_ok(&repo, &["checkout", "-q", "work"]);
    let before = w.rev(&repo, "HEAD");
    let out = w.plain_commit(&repo, &marks, "b.txt", "b\n");
    plain_commit_is_unsigned(&mut p, &w, &repo, &before, &out);
    p.finish();
}

/// D1, forbidden paths. The plain path still refuses a commit changing a CI
/// workflow or a key file, and says "forbidden path". As
/// `test_edge_cases.rs::ci_workflows_and_key_files_are_refused`.
#[test]
fn d1_the_plain_path_still_refuses_forbidden_paths() {
    let w = plain_world("");
    let repo = w.repo();
    let session = fresh();
    let marks = claude_marks(&session);
    let before = w.rev(&repo, "HEAD");
    let mut p = Problems::default();
    let out = w.plain_commit(&repo, &marks, ".github/workflows/ci.yml", "on: push\n");
    refused_plainly(&mut p, &w, &repo, &before, &out, "forbidden path");
    w.git_ok(&repo, &["reset", "-q"]);
    let out = w.plain_commit(&repo, &marks, "deploy.pem", "key\n");
    refused_plainly(&mut p, &w, &repo, &before, &out, "forbidden path");
    w.git_ok(&repo, &["reset", "-q"]);
    let out = w.plain_commit(&repo, &marks, "ok.txt", "ok\n");
    plain_commit_is_unsigned(&mut p, &w, &repo, &before, &out);
    p.finish();
}

/// D1, the diff limit. With `max_diff_lines = 5`, the plain path still
/// refuses a 50-line commit and says "more than the limit you set". As
/// `test_edge_cases.rs::a_diff_over_a_limit_the_person_set_is_refused`.
#[test]
fn d1_the_plain_path_still_refuses_an_oversized_diff() {
    let w = plain_world("[security]\nmax_diff_lines = 5\n");
    let repo = w.repo();
    let session = fresh();
    let marks = claude_marks(&session);
    let before = w.rev(&repo, "HEAD");
    let out = w.plain_commit(&repo, &marks, "big.txt", &"x\n".repeat(50));
    let mut p = Problems::default();
    refused_plainly(
        &mut p,
        &w,
        &repo,
        &before,
        &out,
        "more than the limit you set",
    );
    w.git_ok(&repo, &["reset", "-q"]);
    let out = w.plain_commit(&repo, &marks, "small.txt", "x\n");
    plain_commit_is_unsigned(&mut p, &w, &repo, &before, &out);
    p.finish();
}

/// D1, the rate limit. With `max_commits_per_minute = 2`, a plain process's
/// first two commits go through and the third is refused, saying "rate
/// limit". As `test_edge_cases.rs::commits_over_the_rate_limit_are_refused`.
/// The first commit must also be unsigned (D1), which is what fails today.
#[test]
fn d1_the_plain_path_still_refuses_commits_over_the_rate_limit() {
    let w = plain_world("[security]\nmax_commits_per_minute = 2\n");
    let repo = w.repo();
    let session = fresh();
    let marks = claude_marks(&session);
    let start = w.rev(&repo, "HEAD");
    let first = w.plain_commit(&repo, &marks, "a.txt", "a\n");
    let after_first = w.rev(&repo, "HEAD");
    let second = w.plain_commit(&repo, &marks, "b.txt", "b\n");
    let after_second = w.rev(&repo, "HEAD");
    let third = w.plain_commit(&repo, &marks, "c.txt", "c\n");
    let mut p = Problems::default();
    p.check(first.status.success() && second.status.success(), || {
        format!(
            "CONTROL: the first two plain commits weren't both made:\n{}\n{}",
            text(&first),
            text(&second)
        )
    });
    refused_plainly(&mut p, &w, &repo, &after_second, &third, "rate limit");
    p.check(
        after_first != start && w.is_unsigned(&repo, &after_first),
        || "D1: the first plain commit is signed".into(),
    );
    p.finish();
}

// ---------------------------------------------------------------------------
// What verify says of a commit that can't be merged to main.
// ---------------------------------------------------------------------------

/// The warning D1 wants on an unsigned or unattested commit, checked in
/// `said` (verify's output and errors together), case aside.
fn merge_warning_problems(p: &mut Problems, said: &str, what: &str) {
    let lower = said.to_lowercase();
    for part in [
        "can live on a branch",
        "merging to main will require an attested signature",
        "(launcher or approval)",
    ] {
        p.check(lower.contains(part), || {
            format!("D1: `agent-sign verify` on {what} didn't say \"{part}\"; it said: {said}")
        });
    }
}

/// D1, an unsigned commit. `agent-sign verify` says it can live on a
/// branch, but merging to main will require an attested signature (launcher
/// or approval). Fails today: it says only that the commit carries no
/// signature.
#[test]
fn d1_verify_says_an_unsigned_commit_cant_reach_main_without_an_attested_signature() {
    let w = World::new(&machine_config());
    let repo = w.repo();
    assert!(
        w.is_unsigned(&repo, "HEAD"),
        "CONTROL: the commit should be unsigned"
    );
    let said = w.verify_text(&repo, "HEAD");
    let mut p = Problems::default();
    merge_warning_problems(&mut p, &said, "an unsigned commit");
    p.finish();
}

/// D1, an unattested signature. A commit signed under a certificate from a
/// trusted authority whose attestation is `unattested` is Good, and `agent-sign
/// verify` says it is unattested (as it does today) and also that it can live
/// on a branch, but merging to main will require an attested signature
/// (launcher or approval). Fails today: it says "unattested" and nothing
/// about main.
#[test]
fn d1_verify_says_an_unattested_commit_cant_reach_main_without_an_attested_signature() {
    let w = World::new(&machine_config());
    let repo = w.repo();
    let principal = principal_for("claude-code", "unattested-session");
    let subject = key(SUBJECT_SEED);
    let cert = unattested_cert(&principal, &subject);
    let head = w.rev(&repo, "HEAD");
    let tree = w.tree_with(&repo, "HEAD", "unattested.txt", "unattested\n");
    let ident = agent_ident(&principal);
    let buffer = commit_buffer(&tree, &[&head], &ident, &ident, "unattested");
    let sig = sshsig(&cert, &subject, "git", &buffer);
    let commit = w.write_signed_commit(&repo, &buffer, &sig);
    let allowed = w.home.join("authority_allowed_signers");
    fs::write(
        &allowed,
        format!("*@{DOMAIN} cert-authority {}\n", pub_line(&key(CA_SEED))),
    )
    .unwrap();
    w.name_allowed_signers_file(&allowed);
    assert_eq!(
        w.signature_of(&repo, &commit),
        ("G".to_string(), principal.clone()),
        "CONTROL: the commit should be Good for {principal} under its authority"
    );
    let said = w.verify_text(&repo, &commit);
    let mut p = Problems::default();
    p.check(said.to_lowercase().contains("unattested"), || {
        format!("CONTROL: `agent-sign verify` didn't call the signature unattested: {said}")
    });
    merge_warning_problems(&mut p, &said, "an unattested commit");
    p.finish();
}
