//! The eval for the follow-up to the person-name refusal (63a51aa, 1c502f7),
//! agreed with the suite PM. Written before the fix, by someone other than
//! its builder; each test names the item it holds the code to, and says in
//! its doc comment whether it fails today (and why) or is a guard that
//! passes today.
//!
//! | Item | Test(s) | Today |
//! |---|---|---|
//! | (1) an agent's display name is printable ASCII only | `ascii_*` | the Cyrillic, fullwidth, daemon and accented-name tests fail; the guards pass |
//! | (2) names compared case-insensitively after NFKC, both sides | `nfkc_*` | the fullwidth people and [human] tests fail; the TAYLOR test is a guard |
//! | (3) an unreadable account database stops the service | `accounts_*` | the refusal test and the source-gating test fail; the control passes |
//!
//! **The seam for item (3)**, for the builder: the environment variable
//! `AGENT_SIGN_TEST_ACCOUNTS`. When it is `fail`, the service's read of the
//! account database (`accounts::persons_accounts` at start) must fail, and
//! the service must stop with a non-zero status and a message on its
//! standard error that mentions the accounts. The variable is honoured only
//! when the crate is built with the `test-authenticator` feature (debug test
//! builds; `src/lib.rs`'s `compile_error!` makes that feature impossible in a
//! release build), so an installed build has no such code at all. The test
//! `accounts_the_seam_is_compiled_only_with_the_test_authenticator_feature`
//! holds the source to that (a heuristic scan: a `cfg` on the feature must
//! sit just above every code line that names the variable). The stronger
//! proof is that the variable's name is absent from a release binary, which a
//! script can check after a `cargo build --release` on a server; a test run
//! can't build one.
//!
//! Isolation follows `test_review_fixes.rs`, whose harness is copied here:
//! every process starts from an empty environment plus a temporary HOME, a
//! temporary global git config, no system config, a PATH without
//! agent-sign's installed `bin`, and a socket inside the temporary
//! directory. The person's signer is a fake that logs one line per call and
//! exits 1. Nothing here touches a real `~/.agent-sign`, a real signing key
//! or a running service.
//!
//! The look-alike names are written as `\u{..}` escapes so no editor or
//! normaliser can quietly turn them into plain letters.

#![allow(dead_code)]
// DELIBERATE EVAL CHANGE: these tests start their agent with `agent-sign launch`, and the launcher exists only on
// Linux (no launcher on macOS yet, listed in the README's gaps), so they run only where the launcher exists.
#![cfg(target_os = "linux")]

#[path = "support/die_with_parent.rs"]
mod die_with_parent;

#[path = "support/memory_keys.rs"]
mod memory_keys;

#[path = "support/no_plain_keys.rs"]
mod no_plain_keys;
use die_with_parent::DieWithParent;
#[path = "support/launch.rs"]
mod launch;

use base64::Engine;
use std::ffi::OsString;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use tempfile::{TempDir, tempdir};

use agent_sign::protocol::Response;

const PERSON_NAME: &str = "Human Developer";
const PERSON_EMAIL: &str = "dev@example.com";

/// The git user name on the machines this round is about: the work runner's
/// agents set `user.name` to a name of their own, so git says nothing about
/// who the person is.
const AGENT_GIT_NAME: &str = "work-loop agent on hetzner";

/// Every wrapper run gets at most this long.
const RUN_LIMIT: Duration = Duration::from_secs(30);

const SESSION: &str = "review-fixes-session";
const NAMED_SESSION: &str = "review-fixes-named";

// ---------------------------------------------------------------------------
// Expected identities, computed independently of agent-sign.
// ---------------------------------------------------------------------------

fn session8(session: &str) -> String {
    Sha256::digest(session.as_bytes())[..4]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn principal_of(slug: &str, session: &str, domain: &str) -> String {
    format!("{slug}.{}@{domain}", session8(session))
}

/// The marks of a Claude Code agent with session id `session`.
fn marks_of(session: &str) -> Vec<(&'static str, String)> {
    vec![
        ("CLAUDECODE", "1".to_string()),
        ("CLAUDE_CODE_SESSION_ID", session.to_string()),
    ]
}

/// The environment of an agent that names itself (`AGENT_SIGN_AGENT_NAME`).
fn named(name: &str) -> Vec<(&'static str, String)> {
    vec![
        ("AGENT_SIGN_AGENT_NAME", name.to_string()),
        ("AGENT_SIGN_SESSION_ID", NAMED_SESSION.to_string()),
    ]
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A config that lifts the rate limit (some tests make several commits),
/// plus `extra`.
fn config_with(extra: &str) -> String {
    format!("[security]\nmax_commits_per_minute = 1000\n\n{extra}")
}

// ---------------------------------------------------------------------------
// The isolated agent-side world (copied from test_allowed_agents.rs, with the
// git user name made a parameter).
// ---------------------------------------------------------------------------

struct World {
    _dir: TempDir,
    home: PathBuf,
    global_config: PathBuf,
    path: OsString,
    real_git: PathBuf,
    ssh_keygen: PathBuf,
    socket: PathBuf,
    signer_log: PathBuf,
    service: Option<Child>,
    /// Extra environment for the next service start (the debug-test seam).
    service_env: Vec<(&'static str, &'static str)>,
}

impl Drop for World {
    fn drop(&mut self) {
        self.stop_service();
        // The runtime half of the no-unprotected-test-keys guard: nothing a
        // test did may leave an unencrypted private key under its home.
        if !std::thread::panicking() {
            no_plain_keys::assert_no_plain_private_keys(&self.home);
        }
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

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn all_output(out: &Output) -> String {
    format!("{}{}", stdout(out), stderr(out))
}

/// Runs `cmd`, killing it and failing the test after `limit`.
fn run_within_for(mut cmd: Command, what: &str, limit: Duration) -> Output {
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let start = Instant::now();
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if start.elapsed() > limit {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{what} didn't finish within {limit:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn run_within(cmd: Command, what: &str) -> Output {
    run_within_for(cmd, what, RUN_LIMIT)
}

/// How the service's start went.
enum Start {
    Running,
    Refused(ExitStatus),
}

impl World {
    /// A world whose `~/.agent-sign/config.toml` is `config` and whose git
    /// `user.name` is the usual test person's.
    fn new(config: &str) -> World {
        World::with_git_name(config, PERSON_NAME)
    }

    /// A world whose `~/.agent-sign/config.toml` is `config` and whose git
    /// `user.name` is `git_name`. The service is not started.
    fn with_git_name(config: &str, git_name: &str) -> World {
        let dir = tempdir().unwrap();
        let home = dir.path().to_path_buf();
        let path = cleaned_path();
        let real_git = find_on(&path, "git");
        let ssh_keygen = find_on(&path, "ssh-keygen");
        let world = World {
            global_config: home.join("person.gitconfig"),
            socket: home.join("agent-sign-test.sock"),
            signer_log: home.join("person-signer.log"),
            home,
            path,
            real_git,
            ssh_keygen,
            service: None,
            service_env: Vec::new(),
            _dir: dir,
        };
        world.write_person_setup(config, git_name);
        world
    }

    fn cmd(&self, program: &Path) -> Command {
        let mut cmd = Command::new(program);
        cmd.env_clear();
        for keep in ["TMPDIR", "USER", "LOGNAME", "LANG", "LC_ALL"] {
            if let Some(v) = std::env::var_os(keep) {
                cmd.env(keep, v);
            }
        }
        cmd.env("HOME", &self.home)
            .env("PATH", &self.path)
            .env("GIT_CONFIG_GLOBAL", &self.global_config)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_EDITOR", "true")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("AGENT_SIGN_SOCKET", &self.socket)
            .env("AGENT_SIGN_REAL_GIT", &self.real_git)
            .env("AGENT_SIGN_BIN", env!("CARGO_BIN_EXE_agent-ssh-sign"))
            .env("AGENT_SIGN_CONNECT_WAIT_MS", "200")
            .stdin(Stdio::null());
        cmd
    }

    fn config_path(&self) -> PathBuf {
        self.home.join(".agent-sign/config.toml")
    }

    fn config_text(&self) -> String {
        fs::read_to_string(self.config_path()).unwrap()
    }

    /// The throwaway person key, the fake signer, the person's global git
    /// config (with `user.name = git_name`), and agent-sign's config.toml.
    fn write_person_setup(&self, config: &str, git_name: &str) {
        // Only the public half is ever needed (git's `user.signingkey` names the
        // `.pub` file; the signer is the fake below). The key is made in memory and
        // never written, so no private key exists on disk.
        let key = self.home.join("person_key");
        memory_keys::write_public_only(&key, "person");

        let fake = self.home.join("person-signer.sh");
        fs::write(
            &fake,
            format!(
                "#!/bin/sh\necho \"called: $*\" >> '{}'\nexit 1\n",
                self.signer_log.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&fake, fs::Permissions::from_mode(0o755)).unwrap();

        fs::create_dir_all(self.home.join(".agent-sign")).unwrap();
        fs::write(self.config_path(), config).unwrap();

        fs::write(
            &self.global_config,
            format!(
                "[user]\n\tname = {git_name}\n\temail = {PERSON_EMAIL}\n\tsigningkey = \"{}.pub\"\n\
                 [commit]\n\tgpgsign = true\n[gpg]\n\tformat = ssh\n[gpg \"ssh\"]\n\tprogram = \"{}\"\n",
                key.display(),
                fake.display()
            ),
        )
        .unwrap();
    }

    fn service_log(&self) -> String {
        fs::read_to_string(self.home.join("service.log")).unwrap_or_default()
    }

    fn service_command(&self) -> Command {
        let log = fs::File::create(self.home.join("service.log")).unwrap();
        let mut cmd = self.cmd(Path::new(env!("CARGO_BIN_EXE_agent-signd")));
        cmd.die_with_parent();
        cmd.arg("--socket")
            .arg(&self.socket)
            .arg("--auto-approve")
            .env("AGENT_SIGN_TEST_AUTH", "fail")
            .env("AGENT_SIGN_REFUSAL_BACKOFF", "none")
            .envs(self.service_env.iter().copied())
            .stdout(Stdio::null())
            .stderr(Stdio::from(log));
        cmd
    }

    /// Starts the service and waits for its socket; fails the test, with the
    /// service's own log, if it stops instead.
    fn start_service(&mut self) {
        match self.start_or_refusal() {
            Start::Running => {}
            Start::Refused(status) => panic!(
                "the test service stopped at start ({status}) instead of opening its socket; its log:\n{}",
                self.service_log()
            ),
        }
    }

    /// Starts the service and waits for it either to stop (`Refused`) or to
    /// open its socket (`Running`; it is then kept in `self.service`).
    fn start_or_refusal(&mut self) -> Start {
        let mut child = self.service_command().spawn().unwrap();
        let start = Instant::now();
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                return Start::Refused(status);
            }
            if self.socket.exists() {
                self.service = Some(child);
                return Start::Running;
            }
            if start.elapsed() > Duration::from_secs(10) {
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "test service neither started nor stopped: {}",
                    self.service_log()
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn stop_service(&mut self) {
        if let Some(mut child) = self.service.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    fn signer_calls(&self) -> usize {
        fs::read_to_string(&self.signer_log)
            .map(|s| s.lines().count())
            .unwrap_or(0)
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

    /// The wrapper, as an agent runs it (no terminal), with `marks` set.
    fn agent(&self, repo: &Path, marks: &[(&str, String)], args: &[&str]) -> Output {
        let mut cmd = self.cmd(Path::new(env!("CARGO_BIN_EXE_agent-git")));
        for (k, v) in marks {
            cmd.env(k, v);
        }
        cmd.args(args).current_dir(repo);
        run_within(cmd, &format!("agent git {args:?} with {marks:?}"))
    }

    /// An unsigned setup commit adding `file`.
    fn commit(&self, repo: &Path, file: &str) {
        fs::write(repo.join(file), format!("{file}\n")).unwrap();
        self.git_ok(repo, &["add", file]);
        self.git_ok(
            repo,
            &["-c", "commit.gpgsign=false", "commit", "-q", "-m", file],
        );
    }

    /// A repository on branch `work` (base, w1), with `feature` branched
    /// from base.
    fn repo(&self) -> PathBuf {
        let repo = self.home.join("repo");
        fs::create_dir_all(&repo).unwrap();
        self.git_ok(&repo, &["init", "-q", "-b", "work"]);
        self.commit(&repo, "base.txt");
        self.git_ok(&repo, &["checkout", "-q", "-b", "feature"]);
        self.commit(&repo, "f1.txt");
        self.git_ok(&repo, &["checkout", "-q", "work"]);
        self.commit(&repo, "w1.txt");
        repo
    }

    fn stage(&self, repo: &Path, path: &str, content: &str) {
        let file = repo.join(path);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(&file, content).unwrap();
        self.git_ok(repo, &["add", path]);
    }

    fn agent_commit(&self, repo: &Path, marks: &[(&str, String)], file: &str) -> Output {
        self.stage(repo, file, &format!("{file}\n"));
        self.agent(repo, marks, &["commit", "-m", &format!("feat: {file}")])
    }

    fn named_commit(&self, repo: &Path, name: &str, file: &str) -> Output {
        self.agent_commit(repo, &named(name), file)
    }

    /// Stages `file` and commits it as a launched session of `agent` (a slug
    /// or a display name: `agent-sign launch --agent <agent>`).
    ///
    /// DELIBERATE EVAL CHANGE (P7/D1, 1 Nov 2026): agents sign only when
    /// launched. These controls ran a plain process whose marks or
    /// `AGENT_SIGN_AGENT_NAME` named the agent; the service now makes the
    /// session's id, so the principal is read back ([`World::launched_principal`]).
    fn launched_commit(&self, repo: &Path, agent: &str, file: &str) -> Output {
        self.stage(repo, file, &format!("{file}\n"));
        let mut cmd = self.cmd(Path::new(env!("CARGO_BIN_EXE_agent-sign")));
        cmd.args(["launch", "--agent", agent, "--"])
            .arg(env!("CARGO_BIN_EXE_agent-git"))
            .args(["commit", "-m", &format!("feat: {file}")])
            .current_dir(repo);
        run_within(cmd, &format!("launched {agent} commit of {file}"))
    }

    /// The principal of the launched session that made `rev` (its committer
    /// email), checked to be `<slug>.<8 hex>@agents.local`.
    fn launched_principal(&self, repo: &Path, rev: &str, slug: &str) -> String {
        let email = self.git_ok(repo, &["log", "-1", "--format=%ce", rev]);
        let session = email
            .strip_prefix(&format!("{slug}."))
            .and_then(|rest| rest.strip_suffix("@agents.local"))
            .unwrap_or("");
        assert!(
            session.len() == 8 && session.bytes().all(|b| b.is_ascii_hexdigit()),
            "{rev}'s committer {email:?} isn't a launched {slug} session's principal"
        );
        email
    }

    /// A launched Claude Code session's commit, which must succeed.
    fn claude_commit_ok(&self, repo: &Path, file: &str) {
        let out = self.launched_commit(repo, "claude-code", file);
        assert!(
            out.status.success(),
            "agent commit {file} failed:\n{}\nservice log:\n{}",
            text(&out),
            self.service_log()
        );
    }

    fn rev(&self, repo: &Path, rev: &str) -> String {
        self.git_ok(repo, &["rev-parse", rev])
    }

    /// Whether `rev`'s commit object carries a signature at all.
    fn has_signature(&self, repo: &Path, rev: &str) -> bool {
        self.git_ok(repo, &["cat-file", "commit", rev])
            .contains("\ngpgsig ")
    }

    /// `agent-sign trust-line` (run as the user whose service this is).
    fn trust_lines(&self) -> String {
        let out = self
            .cmd(Path::new(env!("CARGO_BIN_EXE_agent-sign")))
            .arg("trust-line")
            .output()
            .unwrap();
        assert!(out.status.success(), "trust-line: {}", text(&out));
        stdout(&out)
    }

    /// `(%G?, %GS)` for `rev`, checked by plain ssh-keygen against the
    /// allowed-signers content `allowed`.
    fn signature_under(&self, repo: &Path, rev: &str, allowed: &str) -> (String, String) {
        let file = self.home.join("verify_allowed_signers");
        fs::write(&file, allowed).unwrap();
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

    fn canonical(&self, repo: &Path) -> String {
        fs::canonicalize(repo)
            .unwrap()
            .to_string_lossy()
            .into_owned()
    }

    /// Sends one raw JSON request line to the test service and reads the
    /// answer.
    fn ask_raw(&self, json: serde_json::Value) -> Response {
        let mut stream = UnixStream::connect(&self.socket).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(20)))
            .unwrap();
        writeln!(stream, "{json}").unwrap();
        let mut line = String::new();
        BufReader::new(&stream).read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap_or_else(|e| panic!("bad answer {line:?}: {e}"))
    }

    fn lease(&self, repo: &str, branch: &str) {
        let granted = self.ask_raw(serde_json::json!({
            "type": "RequestLease",
            "payload": {"repo": repo, "branch": branch, "intent": "test", "duration_secs": null}
        }));
        assert!(
            matches!(granted, Response::LeaseGranted { .. }),
            "lease for {repo} {branch}: {granted:?}"
        );
    }

    /// A token request (`kind` is `IssueIdentifiedToken` or `IssueRunToken`)
    /// for `slug`, with a well-formed principal in the default domain.
    fn slug_token_request(&self, kind: &str, repo: &str, slug: &str) -> Response {
        self.ask_raw(serde_json::json!({
            "type": kind,
            "payload": {
                "repo": repo,
                "branch": "work",
                "identity": {
                    "slug": slug,
                    "name": slug,
                    "principal": principal_of(slug, NAMED_SESSION, "agents.local"),
                }
            }
        }))
    }

    /// A token request for the Claude Code identity with session `session`.
    fn claude_token_request(&self, kind: &str, repo: &str, session: &str) -> Response {
        self.ask_raw(serde_json::json!({
            "type": kind,
            "payload": {
                "repo": repo,
                "branch": "work",
                "identity": {
                    "slug": "claude-code",
                    "name": "Claude Code",
                    "principal": principal_of("claude-code", session, "agents.local"),
                }
            }
        }))
    }

    /// `SignCommit` for a buffer whose committer timestamp is `committer_ts`.
    /// The tree and parent are the repository's own `HEAD`, so the buffer
    /// passes the service's candidate checks and only the date can differ.
    fn sign_dated(&self, token: &str, repo: &str, committer_ts: u64) -> Response {
        let tree = self.git_ok(Path::new(repo), &["rev-parse", "HEAD^{tree}"]);
        let parent = self.git_ok(Path::new(repo), &["rev-parse", "HEAD"]);
        let t = now();
        let buffer = format!(
            "tree {tree}\nparent {parent}\nauthor Fixture <fixture@example.invalid> {t} +0000\ncommitter Fixture <fixture@example.invalid> {committer_ts} +0000\n\ntest: dated fixture\n"
        );
        self.ask_raw(serde_json::json!({
            "type": "SignCommit",
            "payload": {
                "token": token,
                "buffer_b64": base64::engine::general_purpose::STANDARD.encode(buffer.as_bytes()),
                "repo": repo,
                "branch": "work",
            }
        }))
    }

    /// The `commit_count` of the lease for `repo` on `branch`, as the
    /// service lists it.
    fn lease_commit_count(&self, repo: &str, branch: &str) -> u64 {
        match self.ask_raw(serde_json::json!({"type": "ListLeases"})) {
            Response::LeaseList { leases } => {
                leases
                    .iter()
                    .find(|l| l.repo == repo && l.branch == branch)
                    .unwrap_or_else(|| panic!("no lease for {repo} {branch} in {leases:?}"))
                    .commit_count
            }
            other => panic!("ListLeases: {other:?}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Copied from test_review_fixes.rs: a name that must be refused one way or the other.
// ---------------------------------------------------------------------------

/// Asserts that the attempt `out` (an agent commit under the name `what`)
/// got no certificate and no signature: if a commit was made, it carries no
/// signature and does not verify Good; the person's signer was never
/// called; and the message on standard error names `allowed_agents`.
fn assert_no_certificate(w: &World, repo: &Path, before: &str, out: &Output, what: &str) {
    let after = w.rev(repo, "HEAD");
    if after != before {
        assert!(
            !w.has_signature(repo, "HEAD"),
            "{what}: a signed commit was made:\n{}",
            text(out)
        );
        let trust = w.trust_lines();
        assert_ne!(
            w.signature_under(repo, "HEAD", &trust).0,
            "G",
            "{what}: the commit verifies Good"
        );
    }
    assert_eq!(
        w.signer_calls(),
        0,
        "{what}: the person's signer was called"
    );
    assert!(
        stderr(out).contains("allowed_agents"),
        "{what}: the message should name `allowed_agents`:\n{}\nservice log:\n{}",
        text(out),
        w.service_log()
    );
}

/// Asserts that `name` (listed in `allowed_agents` in `w`'s config) is
/// refused one way or the other: either the service refuses to start, with a
/// log that names `allowed_agents` and the name, or the service runs and the
/// agent's commit under that name gets no certificate and no signature, with
/// a message on standard error that names `allowed_agents` and the name.
fn assert_name_refused(w: &mut World, name: &str, what: &str) {
    match w.start_or_refusal() {
        Start::Refused(status) => {
            let log = w.service_log();
            assert!(
                !status.success(),
                "{what}: the service stopped with {status}"
            );
            assert!(
                log.contains("allowed_agents") && log.contains(name),
                "{what}: the service's refusal should name `allowed_agents` and {name:?}:\n{log}"
            );
        }
        Start::Running => {
            let repo = w.repo();
            let before = w.rev(&repo, "HEAD");
            let out = w.named_commit(&repo, name, "refused.txt");
            assert_no_certificate(w, &repo, &before, &out, what);
            assert!(
                stderr(&out).contains(name),
                "{what}: the message should name {name:?}:\n{}",
                text(&out)
            );
        }
    }
}

// ---------------------------------------------------------------------------
// The names under test.
// ---------------------------------------------------------------------------

/// "Tаylor" with a Cyrillic small a (U+0430) for the second letter. NFKC
/// leaves it alone, so only the ASCII rule can catch it. Its slug is
/// `t-ylor`.
const CYRILLIC_TAYLOR: &str = "T\u{0430}ylor";
const CYRILLIC_TAYLOR_SLUG: &str = "t-ylor";

/// "Ｔａｙｌｏｒ" in fullwidth letters. NFKC turns it into "Taylor". Its slug
/// today is `agent` (no ASCII letter in it).
const FULLWIDTH_TAYLOR: &str = "\u{FF34}\u{FF41}\u{FF59}\u{FF4C}\u{FF4F}\u{FF52}";
/// "ＴＡＹＬＯＲ" in fullwidth capitals.
const FULLWIDTH_TAYLOR_CAPS: &str = "\u{FF34}\u{FF21}\u{FF39}\u{FF2C}\u{FF2F}\u{FF32}";

/// "Agént", with an accented e (U+00E9). Its slug today is `ag-nt`.
const ACCENTED_AGENT: &str = "Ag\u{00E9}nt";
const ACCENTED_AGENT_SLUG: &str = "ag-nt";

/// The world of the attack: `people` lists Taylor, git names someone else
/// (the usual test person; a git name that is an agent's would make the
/// config check refuse slugs such as `agent` as words of it), and the operator
/// allowed the slug the look-alike name turns into (so it is
/// the new rule alone that stands in the way), plus `extra` lines of
/// `[identity]`.
fn world_people_taylor(allowed: &[&str], extra: &str) -> World {
    let allowed_list = allowed
        .iter()
        .map(|a| format!("\"{a}\""))
        .collect::<Vec<_>>()
        .join(", ");
    World::with_git_name(
        &config_with(&format!(
            "[identity]\nallowed_agents = [{allowed_list}]\npeople = [\"Taylor\"]\n{extra}"
        )),
        PERSON_NAME,
    )
}

/// Asserts the agent commit `out` (made under a refused name) got no
/// signature at all: if a commit was made it carries none and does not
/// verify Good, and the person's signer was never called. Unlike
/// `test_review_fixes.rs`'s helper it asks for no particular setting's name
/// in the message; callers check the message themselves.
fn assert_unsigned(w: &World, repo: &Path, before: &str, out: &Output, what: &str) {
    let after = w.rev(repo, "HEAD");
    if after != before {
        assert!(
            !w.has_signature(repo, "HEAD"),
            "{what}: a signed commit was made:\n{}\nservice log:\n{}",
            text(out),
            w.service_log()
        );
        let trust = w.trust_lines();
        assert_ne!(
            w.signature_under(repo, "HEAD", &trust).0,
            "G",
            "{what}: the commit verifies Good"
        );
    }
    assert_eq!(
        w.signer_calls(),
        0,
        "{what}: the person's signer was called"
    );
}

/// Starts `w`'s service (it must start: the config is valid) and commits as
/// the agent named `name`; returns the attempt's output after checking it got
/// no signature.
fn refused_commit(w: &mut World, name: &str, what: &str) -> Output {
    w.start_service();
    let repo = w.repo();
    let before = w.rev(&repo, "HEAD");
    let out = w.named_commit(&repo, name, "refused.txt");
    assert_unsigned(w, &repo, &before, &out, what);
    out
}

// ---------------------------------------------------------------------------
// Item (1): an agent's display name is printable ASCII only.
// ---------------------------------------------------------------------------

/// The shared body of the two look-alike tests: with `people = ["Taylor"]`
/// and the slug the look-alike turns into on the operator's list (so it is
/// the new rule alone that stands in the way), an agent named `name` gets no
/// signature, and the message says the name must be printable ASCII (or
/// names `AGENT_SIGN_AGENT_NAME`).
fn lookalike_gets_no_signature(name: &str, slug: &str) {
    let mut w = world_people_taylor(&[slug], "");
    let out = refused_commit(&mut w, name, &format!("agent name {name:?}"));
    let said = stderr(&out).to_lowercase();
    assert!(
        said.contains("ascii") || said.contains("agent_sign_agent_name"),
        "{name:?}: the message should say the name must be printable ASCII (or name \
         AGENT_SIGN_AGENT_NAME):\n{}\nservice log:\n{}",
        text(&out),
        w.service_log()
    );
}

/// Item (1) and (2). With `people = ["Taylor"]`, an agent that names itself
/// with a Cyrillic look-alike "Tаylor" (small Cyrillic a, U+0430) gets no
/// signature, even where the operator allowed the slug the name turns into
/// (`t-ylor`). The display name becomes the commit's author name, and NFKC
/// can't catch the Cyrillic letter, so the rule is "printable ASCII only".
///
/// Fails today: the name is slugged to `t-ylor`, which is on the operator's
/// list and is no person's name, so the commit is signed with the look-alike
/// as its author name.
#[test]
fn ascii_a_cyrillic_lookalike_taylor_gets_no_signature_when_people_lists_taylor() {
    lookalike_gets_no_signature(CYRILLIC_TAYLOR, CYRILLIC_TAYLOR_SLUG);
}

/// Item (1) and (2). Same world, with the fullwidth "Ｔａｙｌｏｒ" (NFKC turns
/// it into "Taylor"): no signature, with the same message.
///
/// Fails today: the name is slugged to `agent` (no ASCII letter in it),
/// which is on the operator's list and is no person's name.
#[test]
fn ascii_a_fullwidth_taylor_gets_no_signature_when_people_lists_taylor() {
    lookalike_gets_no_signature(FULLWIDTH_TAYLOR, "agent");
}

/// Item (1), at the daemon (the authority, whatever the wrapper does). A
/// token request, commit token or run token, whose identity carries the
/// display name "Tаylor" (Cyrillic) or "Ｔａｙｌｏｒ" (fullwidth) is refused
/// with an error that says the display name must be ASCII, while the same
/// request with the plain name "My Bot 2" is granted (so the refusal is not
/// "everything fails").
///
/// Fails today: `AgentIdentity::check_in` accepts any printable characters
/// in the display name, so the daemon grants a token and the certificate's
/// holder commits under the look-alike author name.
#[test]
fn ascii_the_service_refuses_a_non_ascii_display_name_in_any_token_request() {
    let mut w = world_people_taylor(
        &[
            "my-bot-2",
            CYRILLIC_TAYLOR_SLUG,
            "agent",
            ACCENTED_AGENT_SLUG,
        ],
        "",
    );
    w.start_service();
    let repo = w.canonical(&w.repo());
    w.lease(&repo, "work");
    let request = |kind: &str, slug: &str, name: &str| {
        w.ask_raw(serde_json::json!({
            "type": kind,
            "payload": {
                "repo": repo,
                "branch": "work",
                "identity": {
                    "slug": slug,
                    "name": name,
                    "principal": principal_of(slug, NAMED_SESSION, "agents.local"),
                }
            }
        }))
    };
    let mut failures = Vec::new();
    // DELIBERATE EVAL CHANGE (P7/D1, 1 Nov 2026): agents sign only when
    // launched. The control, a token for My Bot 2, is granted to a launched
    // session on its channel; the non-ASCII refusals are asked on the
    // service's own socket, where the name rules run first and say ASCII.
    let bot = launch::start_session(&w.socket, "my-bot-2");
    for kind in ["IssueIdentifiedToken", "IssueRunToken"] {
        let control: agent_sign::protocol::Request = serde_json::from_value(serde_json::json!({
            "type": kind,
            "payload": {
                "repo": repo,
                "branch": "work",
                "identity": {
                    "slug": bot.identity.slug,
                    "name": bot.identity.name,
                    "principal": bot.principal,
                }
            }
        }))
        .unwrap();
        let granted = bot.ask(&control);
        assert!(
            matches!(granted, Response::TokenIssued { .. }),
            "{kind} for My Bot 2 (control): {granted:?}"
        );
        for (slug, name) in [
            (CYRILLIC_TAYLOR_SLUG, CYRILLIC_TAYLOR),
            ("agent", FULLWIDTH_TAYLOR),
            (ACCENTED_AGENT_SLUG, ACCENTED_AGENT),
        ] {
            match request(kind, slug, name) {
                Response::Error { message } => {
                    if !message.to_lowercase().contains("ascii") {
                        failures.push(format!(
                            "{kind} for display name {name:?}: refused, but the message should \
                             say the display name must be ASCII: {message:?}"
                        ));
                    }
                }
                other => failures.push(format!(
                    "{kind} for display name {name:?} was not refused: {other:?}"
                )),
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Item (1). Any non-ASCII display name, such as "Agént", is refused even
/// with no people configured and no look-alike in sight: it gets no
/// signature, and the message says why (the name must be printable ASCII)
/// and names the name or `AGENT_SIGN_AGENT_NAME`. The operator allowed the
/// name's slug (`ag-nt`) so that nothing but the new rule can refuse it.
///
/// Fails today: the commit is signed as `ag-nt`, author name "Agént".
#[test]
fn ascii_any_non_ascii_display_name_is_refused_even_with_no_people_configured() {
    let mut w = World::with_git_name(
        &config_with(&format!(
            "[identity]\nallowed_agents = [\"{ACCENTED_AGENT_SLUG}\"]\n"
        )),
        PERSON_NAME,
    );
    assert!(!w.config_text().contains("people"), "{}", w.config_text());
    let out = refused_commit(&mut w, ACCENTED_AGENT, "agent name with an accented e");
    let said = stderr(&out);
    assert!(
        said.to_lowercase().contains("ascii"),
        "the message should say the name must be printable ASCII:\n{}\nservice log:\n{}",
        text(&out),
        w.service_log()
    );
    assert!(
        said.contains(ACCENTED_AGENT) || said.contains("AGENT_SIGN_AGENT_NAME"),
        "the message should name the display name or AGENT_SIGN_AGENT_NAME:\n{}",
        text(&out)
    );
}

/// Item (1), GUARD (passes today; it must keep passing). The ASCII rule is
/// not "refuse anything unusual": every printable ASCII name an operator
/// listed still signs, including spaces, digits and punctuation ("My Bot 2",
/// "My Bot (beta) #2"), as the agent's slug, and the commit's author name is
/// the display name as given.
#[test]
fn ascii_guard_printable_ascii_names_listed_in_allowed_agents_still_sign() {
    for (name, slug) in [
        ("My Bot 2", "my-bot-2"),
        ("My Bot (beta) #2", "my-bot-beta-2"),
    ] {
        let mut w = World::with_git_name(
            &config_with(&format!("[identity]\nallowed_agents = [\"{slug}\"]\n")),
            PERSON_NAME,
        );
        w.start_service();
        let repo = w.repo();
        // DELIBERATE EVAL CHANGE (P7/D1, 1 Nov 2026): agents sign only when
        // launched (`--agent "My Bot (beta) #2"`).
        let out = w.launched_commit(&repo, name, "listed.txt");
        assert!(
            out.status.success(),
            "{name:?}: {}\n{}",
            text(&out),
            w.service_log()
        );
        let want = w.launched_principal(&repo, "HEAD", slug);
        let trust = w.trust_lines();
        assert_eq!(
            w.signature_under(&repo, "HEAD", &trust),
            ("G".into(), want),
            "{name:?}"
        );
        assert_eq!(
            w.git_ok(&repo, &["log", "-1", "--format=%an"]),
            name,
            "{name:?}: the author name should be the display name as given"
        );
    }
}

/// Item (1), GUARD (passes today). The built-in agents need no setting and
/// still sign: Claude Code by its marks, and Codex.
#[test]
fn ascii_guard_built_in_agents_still_sign() {
    let mut w = World::with_git_name(
        &config_with("[identity]\npeople = [\"Taylor\"]\n"),
        PERSON_NAME,
    );
    w.start_service();
    let repo = w.repo();
    w.claude_commit_ok(&repo, "claude.txt");
    let trust = w.trust_lines();
    assert_eq!(
        w.signature_under(&repo, "HEAD", &trust),
        (
            "G".into(),
            w.launched_principal(&repo, "HEAD", "claude-code")
        )
    );
    // DELIBERATE EVAL CHANGE (P7/D1, 1 Nov 2026): agents sign only when
    // launched: Codex too.
    let out = w.launched_commit(&repo, "codex", "codex.txt");
    assert!(out.status.success(), "{}\n{}", text(&out), w.service_log());
    let trust = w.trust_lines();
    assert_eq!(
        w.signature_under(&repo, "HEAD", &trust),
        ("G".into(), w.launched_principal(&repo, "HEAD", "codex"))
    );
}

// ---------------------------------------------------------------------------
// Item (2): names compared case-insensitively after NFKC, both sides.
// ---------------------------------------------------------------------------

/// Item (2), GUARD (passes today; it must keep passing). "TAYLOR" as the
/// agent's name is refused when `people = ["Taylor"]` and the operator also
/// listed `taylor` in allowed_agents: either the service refuses to start,
/// naming `allowed_agents` and the name, or the commit gets no signature (a
/// message naming both). With `taylor` not listed, the same name is refused
/// too, and the message says a person's name is never allowed.
#[test]
fn nfkc_guard_taylor_in_capitals_is_refused_when_people_lists_taylor() {
    let mut w = world_people_taylor(&["taylor"], "");
    assert_name_refused(
        &mut w,
        "taylor",
        "allowed_agents = [\"taylor\"], people = [\"Taylor\"]",
    );

    let mut w = world_people_taylor(&[], "");
    let out = refused_commit(&mut w, "TAYLOR", "agent name \"TAYLOR\"");
    assert!(
        stderr(&out).to_lowercase().contains("person"),
        "the message should say a person's name is never allowed:\n{}",
        text(&out)
    );
}

/// Item (2). A `people` entry written in fullwidth capitals ("ＴＡＹＬＯＲ",
/// here as escapes) is the name Taylor, on the people's side of the
/// comparison. Two worlds:
/// - The entry is valid: with it in `people` and a harmless name in
///   allowed_agents the service starts, and that agent still signs. (A
///   `people` entry is also refused today when it has no ASCII letter or
///   digit, so that rule must look at the normalised name.)
/// - The entry protects: with `taylor` also in allowed_agents, the name is
///   refused one way or the other (the service refuses to start, naming
///   `allowed_agents` and `taylor`, or the commit gets no signature).
///
/// Fails today: the config check rejects the entry ("isn't a person's name
/// agent-sign can use"), so the first world's service never starts, and the
/// second world's refusal doesn't name `allowed_agents` or `taylor`.
#[test]
fn nfkc_a_fullwidth_people_entry_refuses_the_agent_name_taylor() {
    // The entry is accepted, and nothing harmless is refused.
    let mut w = World::with_git_name(
        &config_with(&format!(
            "[identity]\nallowed_agents = [\"totally-real-tool\"]\n\
             people = [\"{FULLWIDTH_TAYLOR_CAPS}\"]\n"
        )),
        PERSON_NAME,
    );
    match w.start_or_refusal() {
        Start::Running => {}
        Start::Refused(status) => panic!(
            "the service stopped at start ({status}) instead of accepting a fullwidth \
             `people` entry as the name Taylor; its log:\n{}",
            w.service_log()
        ),
    }
    let repo = w.repo();
    // DELIBERATE EVAL CHANGE (P7/D1, 1 Nov 2026): agents sign only when
    // launched.
    let out = w.launched_commit(&repo, "Totally Real Tool", "listed.txt");
    assert!(out.status.success(), "{}\n{}", text(&out), w.service_log());
    let trust = w.trust_lines();
    assert_eq!(
        w.signature_under(&repo, "HEAD", &trust),
        (
            "G".into(),
            w.launched_principal(&repo, "HEAD", "totally-real-tool")
        )
    );

    // The entry protects the name.
    let mut w = World::with_git_name(
        &config_with(&format!(
            "[identity]\nallowed_agents = [\"taylor\"]\n\
             people = [\"{FULLWIDTH_TAYLOR_CAPS}\"]\n"
        )),
        PERSON_NAME,
    );
    assert_name_refused(
        &mut w,
        "taylor",
        "people = [fullwidth TAYLOR], allowed_agents = [\"taylor\"]",
    );
}

/// Item (2). The `[human]` name is compared the same way: with `[human] name
/// = "Ｄａｎａ Example"` (a fullwidth first name, here as escapes) and no
/// `[human] email`, an agent named "dana" listed in allowed_agents is
/// refused one way or the other (the service refuses to start, naming
/// `allowed_agents` and `dana`, or the commit gets no signature).
///
/// Fails today: `slug_of` drops the fullwidth letters, so the human's name
/// gives only `example` and `dana` is certified.
#[test]
fn nfkc_a_fullwidth_human_name_refuses_the_agent_name_dana() {
    let fullwidth_dana = "\u{FF24}\u{FF41}\u{FF4E}\u{FF41}";
    let mut w = World::with_git_name(
        &config_with(&format!(
            "[human]\nname = \"{fullwidth_dana} Example\"\n\n\
             [identity]\nallowed_agents = [\"dana\"]\n"
        )),
        PERSON_NAME,
    );
    assert_name_refused(&mut w, "dana", "[human] name = fullwidth Dana Example");
}

// ---------------------------------------------------------------------------
// Item (3): an unreadable account database stops the service.
// ---------------------------------------------------------------------------

/// The debug-test-only seam: see this file's header.
const ACCOUNTS_SEAM: &str = "AGENT_SIGN_TEST_ACCOUNTS";

/// Item (3), GUARD (passes today). With the seam unset, the same config
/// starts and serves, so the refusal in the next test is the seam's doing and
/// not a config the service dislikes.
#[test]
fn accounts_guard_without_the_seam_the_service_starts() {
    let mut w = world_people_taylor(&[], "");
    w.start_service();
}

/// Item (3). If reading the account database fails at the service's start,
/// the service refuses to start: it stops with a non-zero status and a
/// message that mentions the accounts, and never opens its socket, rather
/// than running with an empty list of people (which would let an agent be
/// certified under any account holder's name). The failure is forced through
/// `AGENT_SIGN_TEST_ACCOUNTS=fail`, which only a debug test build honours.
///
/// Fails today: the seam does not exist, `persons_accounts` cannot fail, and
/// the service starts.
#[test]
fn accounts_the_service_refuses_to_start_when_the_account_read_fails() {
    let mut w = world_people_taylor(&[], "");
    w.service_env = vec![(ACCOUNTS_SEAM, "fail")];
    match w.start_or_refusal() {
        Start::Refused(status) => {
            let log = w.service_log();
            assert!(
                !status.success(),
                "the service stopped with {status}:\n{log}"
            );
            assert!(
                log.to_lowercase().contains("account"),
                "the service's refusal should mention the accounts:\n{log}"
            );
            assert!(
                !w.socket.exists(),
                "the service opened its socket before refusing:\n{log}"
            );
        }
        Start::Running => panic!(
            "the service started although {ACCOUNTS_SEAM}=fail forced the account read to \
             fail (or the seam does not exist yet); its log:\n{}",
            w.service_log()
        ),
    }
}

/// Item (3), at the source: the seam exists only in debug test builds, so
/// an installed build has no way to make the account read "fail" (or, worse,
/// to make a service ignore the accounts). A heuristic scan of `src/`: the
/// seam's name must appear in the code (not only in comments), and each line
/// of code that names it must have a `cfg` on the `test-authenticator`
/// feature within the 20 lines above it, the feature `src/lib.rs` makes
/// impossible to compile into a release build. The stronger proof, that the
/// name is absent from a release binary, is not something a test run can
/// build; see this file's header.
///
/// Fails today: the seam isn't in the source.
#[test]
fn accounts_the_seam_is_compiled_only_with_the_test_authenticator_feature() {
    fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                rust_files(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    let mut files = Vec::new();
    rust_files(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut files,
    );
    let mut mentions = 0;
    for file in files {
        let source = fs::read_to_string(&file).unwrap();
        let lines: Vec<&str> = source.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let code = line.trim_start();
            if !line.contains(ACCOUNTS_SEAM) || code.starts_with("//") {
                continue;
            }
            mentions += 1;
            let from = i.saturating_sub(20);
            let gated = lines[from..i].iter().any(|l| {
                l.contains("feature = \"test-authenticator\"") && !l.contains("not(feature")
            });
            assert!(
                gated,
                "{}:{}: `{ACCOUNTS_SEAM}` is named in code with no `cfg(feature = \
                 \"test-authenticator\")` in the 20 lines above it:\n{line}",
                file.display(),
                i + 1
            );
        }
    }
    assert!(
        mentions > 0,
        "no code in src/ names {ACCOUNTS_SEAM}: the seam for item (3) doesn't exist yet"
    );
}
