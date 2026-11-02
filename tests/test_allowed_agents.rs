//! Which agent names get a certificate, and which commit dates get a
//! signature. These are the name and date refusals of plan check 6 ("0 of
//! these 4 attempts succeed": a pass for a made-up agent name, such as one
//! named after the user; a commit dated outside its pass's lifetime that
//! still checks out), plus the controls that show the refusals are not
//! simply "everything fails".
//!
//! These tests were written before the change, as its eval. The interface
//! they hold the code to:
//!
//! - An identity's slug must be one of the built-in tool slugs that
//!   `identify_agent` produces (`claude-code`, `codex`, `gemini-cli`) or be
//!   listed in `[identity] allowed_agents = [...]` in the user's own
//!   `~/.agent-sign/config.toml`. A repository's `.agent-sign.toml` can't
//!   add to the list.
//! - `AGENT_SIGN_AGENT_NAME` naming any other slug (`taylor`, `root`, the
//!   configured human's name) gets no certificate and no signature, with a
//!   message that says how to allow it (it names `allowed_agents`). The
//!   daemon refuses the token; the wrapper shows the daemon's message on
//!   standard error. Whether the wrapper then fails the commit or lets it
//!   through unsigned is not fixed by the interface: these tests accept
//!   either, and require only that no signature of the agent's exists.
//! - `agent-signd` refuses to sign a commit whose committer timestamp lies
//!   outside the signing certificate's validity window (from 5 minutes
//!   before the certificate was issued to 12 hours after). The author date
//!   is not looked at: a rebase or cherry-pick keeps old author dates.
//!
//! Tests marked REGRESSION GUARD pass today and must keep passing. Every
//! other test fails today: for the name tests because today any slug gets a
//! certificate (a `taylor` commit verifies Good), for the `allowed_agents`
//! tests because the `[identity]` table doesn't exist yet (the service stops
//! at start: "an unknown table [identity]"), and for the date tests because
//! today a commit dated 2020 or 2099 verifies Good.
//!
//! NOTE for the builder: existing tests sign fixtures whose committer date is
//! the fixed 1700000000 (`test_identity_review_fixes.rs`, `test_edge_cases.rs`,
//! `test_security_boundary.rs`) and some name agents with
//! `AGENT_SIGN_AGENT_NAME` values outside the allowed list (`My Bot 2`, in
//! `test_per_agent_identity.rs` and others). Both are exactly what
//! this change refuses, so those tests must be updated as part of it; that
//! is a deliberate change to them, made for this reason, not a way to make
//! them pass.
//!
//! Isolation is the same as `test_identity_review_fixes.rs`, whose harness
//! this follows: every process starts from an empty environment plus a
//! temporary HOME, a temporary global git config, no system config, a PATH
//! without agent-sign's installed `bin`, and a socket inside the temporary
//! directory. The person's signer is a fake that logs one line per call and
//! exits 1. Nothing here touches a real `~/.agent-sign`, a real signing key
//! or a running service.
//!
//! The expected principals are computed here from the session ids the tests
//! set, with `sha2`, so the tests don't trust the code under test.

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
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use tempfile::{TempDir, tempdir};

use agent_sign::protocol::Response;

const PERSON_NAME: &str = "Human Developer";
const PERSON_EMAIL: &str = "dev@example.com";

/// The marker lines of the managed block in an allowed-signers file.
const BLOCK_BEGIN: &str = "# agent-sign: agents' certificate authorities, managed; do not edit";
const BLOCK_END: &str = "# agent-sign: end of agents' certificate authorities";

/// Every wrapper run gets at most this long.
const RUN_LIMIT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// Expected identities, computed independently of agent-sign.
// ---------------------------------------------------------------------------

fn session8(session: &str) -> String {
    Sha256::digest(session.as_bytes())[..4]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

const SESSION: &str = "machine-names-session";

/// `claude-code.<session8>@<domain>` for `session`.
fn principal(session: &str, domain: &str) -> String {
    format!("claude-code.{}@{domain}", session8(session))
}

/// The marks of a Claude Code agent with session id `session`.
fn marks_of(session: &str) -> Vec<(&'static str, String)> {
    vec![
        ("CLAUDECODE", "1".to_string()),
        ("CLAUDE_CODE_SESSION_ID", session.to_string()),
    ]
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
    signer_log: PathBuf,
    service: Option<Child>,
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

/// Runs `cmd`, killing it and failing the test after [`RUN_LIMIT`].
fn run_within(mut cmd: Command, what: &str) -> Output {
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
        if start.elapsed() > RUN_LIMIT {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{what} didn't finish within {RUN_LIMIT:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

impl World {
    /// A world whose `~/.agent-sign/config.toml` is `config`. The service is
    /// not started.
    fn new(config: &str) -> World {
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
            _dir: dir,
        };
        world.write_person_setup(config);
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

    /// Replaces the person's `config.toml` (the service reads it at start;
    /// the wrapper reads it at every run).
    fn set_config(&self, config: &str) {
        fs::write(self.config_path(), config).unwrap();
    }

    /// The throwaway person key, the fake signer, the person's global git
    /// config, and agent-sign's config.toml.
    fn write_person_setup(&self, config: &str) {
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
        self.set_config(config);

        fs::write(
            &self.global_config,
            format!(
                "[user]\n\tname = {PERSON_NAME}\n\temail = {PERSON_EMAIL}\n\tsigningkey = \"{}.pub\"\n\
                 [commit]\n\tgpgsign = true\n[gpg]\n\tformat = ssh\n[gpg \"ssh\"]\n\tprogram = \"{}\"\n",
                key.display(),
                fake.display()
            ),
        )
        .unwrap();
    }

    /// Makes git name `file` as `gpg.ssh.allowedSignersFile`, so the service
    /// keeps its managed block there.
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

    fn service_command(&self) -> Command {
        let log = fs::File::create(self.home.join("service.log")).unwrap();
        let mut cmd = self.cmd(Path::new(env!("CARGO_BIN_EXE_agent-signd")));
        cmd.die_with_parent();
        cmd.arg("--socket")
            .arg(&self.socket)
            .arg("--auto-approve")
            .env("AGENT_SIGN_TEST_AUTH", "fail")
            .env("AGENT_SIGN_REFUSAL_BACKOFF", "none")
            .stdout(Stdio::null())
            .stderr(Stdio::from(log));
        cmd
    }

    /// Starts the service and waits for its socket; fails the test, with the
    /// service's own log, if it stops instead.
    fn start_service(&mut self) {
        let mut child = self.service_command().spawn().unwrap();
        let start = Instant::now();
        while !self.socket.exists() {
            if let Some(status) = child.try_wait().unwrap() {
                panic!(
                    "the test service stopped at start ({status}) instead of opening its socket; its log:\n{}",
                    self.service_log()
                );
            }
            if start.elapsed() > Duration::from_secs(10) {
                let _ = child.kill();
                let _ = child.wait();
                panic!("test service didn't start: {}", self.service_log());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        self.service = Some(child);
    }

    fn stop_service(&mut self) {
        if let Some(mut child) = self.service.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    /// Starts the service and waits up to 10 seconds for it either to stop
    /// (`Some(status)`) or to open its socket (`None`, and it is stopped).
    fn service_stops_at_start(&self) -> Option<std::process::ExitStatus> {
        let mut child = self.service_command().spawn().unwrap();
        let start = Instant::now();
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                return Some(status);
            }
            if self.socket.exists() || start.elapsed() > Duration::from_secs(10) {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            std::thread::sleep(Duration::from_millis(20));
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

    /// A repository called `name` on `branch` (base, w1), with `feature`
    /// branched from base, `branch` checked out.
    fn repo_named(&self, name: &str, branch: &str) -> PathBuf {
        let repo = self.home.join(name);
        fs::create_dir_all(&repo).unwrap();
        self.git_ok(&repo, &["init", "-q", "-b", branch]);
        self.commit(&repo, "base.txt");
        self.git_ok(&repo, &["checkout", "-q", "-b", "feature"]);
        self.commit(&repo, "f1.txt");
        self.git_ok(&repo, &["checkout", "-q", branch]);
        self.commit(&repo, "w1.txt");
        repo
    }

    fn repo(&self) -> PathBuf {
        self.repo_named("repo", "work")
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

    /// Stages `file` and commits it as a launched session of `agent` (a slug
    /// or a display name: `agent-sign launch --agent <agent>`), with `extra`
    /// environment variables too.
    ///
    /// DELIBERATE EVAL CHANGE (P7/D1, 1 Nov 2026): agents sign only when
    /// launched. These tests ran a plain process whose marks or
    /// `AGENT_SIGN_AGENT_NAME` named the agent. The service now makes the
    /// session's id, so the principal is read back from the commit
    /// ([`World::launched_principal`]).
    fn launched_commit(
        &self,
        repo: &Path,
        agent: &str,
        file: &str,
        extra: &[(&str, &str)],
    ) -> Output {
        self.stage(repo, file, &format!("{file}\n"));
        let mut cmd = self.cmd(Path::new(env!("CARGO_BIN_EXE_agent-sign")));
        cmd.args(["launch", "--agent", agent, "--"])
            .arg(env!("CARGO_BIN_EXE_agent-git"))
            .args(["commit", "-m", &format!("feat: {file}")])
            .current_dir(repo);
        for (k, v) in extra {
            cmd.env(k, v);
        }
        run_within(cmd, &format!("launched {agent} commit of {file}"))
    }

    /// The principal of the launched session that made `rev` (its committer
    /// email, which must also be its author email), checked to be
    /// `<slug>.<8 hex>@agents.local`.
    fn launched_principal(&self, repo: &Path, rev: &str, slug: &str) -> String {
        let (author, committer) = self.emails(repo, rev);
        assert_eq!(author, committer, "author and committer email of {rev}");
        let session = committer
            .strip_prefix(&format!("{slug}."))
            .and_then(|rest| rest.strip_suffix("@agents.local"))
            .unwrap_or("");
        assert!(
            session.len() == 8 && session.bytes().all(|b| b.is_ascii_hexdigit()),
            "{rev}'s committer {committer:?} isn't a launched {slug} session's principal"
        );
        committer
    }

    /// `launched_commit` as Claude Code, which must succeed.
    fn claude_commit_ok(&self, repo: &Path, file: &str) {
        let out = self.launched_commit(repo, "claude-code", file, &[]);
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

    /// `(author email, committer email)` of `rev`.
    fn emails(&self, repo: &Path, rev: &str) -> (String, String) {
        let both = self.git_ok(repo, &["log", "-1", "--format=%ae%x1f%ce", rev]);
        let (a, c) = both.split_once('\x1f').unwrap();
        (a.to_string(), c.to_string())
    }

    /// `agent-sign trust-line` (run as the user whose service this is).
    fn trust_line_output(&self) -> Output {
        self.cmd(Path::new(env!("CARGO_BIN_EXE_agent-sign")))
            .arg("trust-line")
            .output()
            .unwrap()
    }

    /// The lines `agent-sign trust-line` prints; the command must succeed.
    fn trust_lines(&self) -> String {
        let out = self.trust_line_output();
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
    /// answer. Raw, so these tests don't depend on the Rust types of the
    /// identity the change may extend.
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
    /// for a Claude Code identity with `principal`.
    fn token_request(&self, kind: &str, repo: &str, branch: &str, principal: &str) -> Response {
        self.ask_raw(serde_json::json!({
            "type": kind,
            "payload": {
                "repo": repo,
                "branch": branch,
                "identity": {"slug": "claude-code", "name": "Claude Code", "principal": principal}
            }
        }))
    }
}

fn assert_commit_ok(w: &World, out: &Output, what: &str) {
    assert!(
        out.status.success(),
        "{what} failed (person's signer calls: {}):\n{}\nservice log:\n{}",
        w.signer_calls(),
        text(out),
        w.service_log()
    );
}

// ---------------------------------------------------------------------------
// Names.
// ---------------------------------------------------------------------------

const NAMED_SESSION: &str = "allowed-agents-session";

/// The environment of an agent that names itself (`AGENT_SIGN_AGENT_NAME`),
/// with a session id, as an agent without a mark of its own is started.
fn named(name: &str) -> Vec<(&'static str, String)> {
    vec![
        ("AGENT_SIGN_AGENT_NAME", name.to_string()),
        ("AGENT_SIGN_SESSION_ID", NAMED_SESSION.to_string()),
    ]
}

/// The principal of the agent `named(...)` starts, for its slug.
fn named_principal(slug: &str) -> String {
    principal_of(slug, NAMED_SESSION, "agents.local")
}

fn principal_of(slug: &str, session: &str, domain: &str) -> String {
    format!("{slug}.{}@{domain}", session8(session))
}

/// A config that lifts the rate limit (these tests make several commits),
/// plus `extra`.
fn config_with(extra: &str) -> String {
    format!("[security]\nmax_commits_per_minute = 1000\n\n{extra}")
}

impl World {
    /// `agent_commit` for an agent started with `named(name)`, with `extra`
    /// environment variables too.
    fn named_commit(&self, repo: &Path, name: &str, file: &str) -> Output {
        self.agent_commit(repo, &named(name), file)
    }

    /// Whether `rev`'s commit object carries a signature at all.
    fn has_signature(&self, repo: &Path, rev: &str) -> bool {
        self.git_ok(repo, &["cat-file", "commit", rev])
            .contains("\ngpgsig ")
    }
}

/// Asserts that the attempt `out` (an agent commit under the name `what`)
/// got no certificate and no signature: if a commit was made, it carries no
/// signature and does not verify Good; the person's signer was never
/// called; and the message on standard error says how to allow the name
/// (it names `allowed_agents`).
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
        "{what}: the message should say how to allow the name (name `allowed_agents`):\n{}\nservice log:\n{}",
        text(out),
        w.service_log()
    );
}

/// REGRESSION GUARD (passes today). The built-in tool slugs keep getting
/// certificates under their own names: Claude Code, Codex and Gemini CLI,
/// started by slug and by display name.
///
/// DELIBERATE EVAL CHANGE (P7/D1, 1 Nov 2026): agents sign only when
/// launched. The agents are started with `agent-sign launch --agent ...`;
/// the tools' own marks (`CLAUDECODE`, `CODEX_THREAD_ID`, `GEMINI_CLI`) no
/// longer name anyone for a signature, so they are not what starts the
/// agent here. The principal is `<slug>.<8 hex>@agents.local`, the 8 hex
/// the service's.
#[test]
fn regression_guard_the_built_in_tool_slugs_are_accepted() {
    let mut w = World::new(&config_with(""));
    w.start_service();
    let repo = w.repo();
    // (what, the --agent argument, the slug it must get)
    let cases: Vec<(&str, &str, &str)> = vec![
        ("claude-code", "claude-code", "claude-code"),
        ("codex", "codex", "codex"),
        ("gemini-cli", "gemini-cli", "gemini-cli"),
        ("Claude Code (named)", "Claude Code", "claude-code"),
        ("Codex (named)", "Codex", "codex"),
        ("Gemini CLI (named)", "Gemini CLI", "gemini-cli"),
    ];
    for (i, (what, agent, slug)) in cases.iter().enumerate() {
        let out = w.launched_commit(&repo, agent, &format!("f{i}.txt"), &[]);
        assert_commit_ok(&w, &out, what);
        let want = w.launched_principal(&repo, "HEAD", slug);
        let trust = w.trust_lines();
        assert_eq!(
            w.signature_under(&repo, "HEAD", &trust),
            ("G".into(), want.clone()),
            "{what}"
        );
    }
}

/// Plan check 6a (a pass for a made-up agent name). With no `allowed_agents`
/// at all, agents that name themselves `taylor`, `root`, `admin` or `Totally
/// Real Tool` (neither built in nor a widely used tool) get no certificate and no signature, and the message
/// names `allowed_agents`. A built-in agent's commit in the same world
/// first shows the service works. Fails today because every slug gets a
/// certificate: a `taylor` commit is signed and verifies Good.
#[test]
fn a_made_up_agent_name_gets_no_certificate_and_no_signature() {
    let mut w = World::new(&config_with(""));
    w.start_service();
    let repo = w.repo();
    w.claude_commit_ok(&repo, "control.txt");
    for (i, name) in ["taylor", "Taylor", "root", "admin", "Totally Real Tool"]
        .iter()
        .enumerate()
    {
        let before = w.rev(&repo, "HEAD");
        let out = w.named_commit(&repo, name, &format!("made-up-{i}.txt"));
        assert_no_certificate(&w, &repo, &before, &out, &format!("agent named {name:?}"));
    }
}

/// Plan check 6a (a name after the user). The configured human is "Dana
/// Example" (`[human] name`); an agent that names itself `Dana Example`, or
/// `dana-example`, or `Human Developer` (the git user name of this world's
/// person) gets no certificate and no signature. Fails today because every
/// slug gets a certificate.
#[test]
fn an_agent_named_after_the_configured_human_gets_no_certificate() {
    let mut w = World::new(&config_with(
        "[human]\nname = \"Dana Example\"\nemail = \"dana@example.com\"\n",
    ));
    w.start_service();
    let repo = w.repo();
    w.claude_commit_ok(&repo, "control.txt");
    for (i, name) in ["Dana Example", "dana-example", "Human Developer"]
        .iter()
        .enumerate()
    {
        let before = w.rev(&repo, "HEAD");
        let out = w.named_commit(&repo, name, &format!("human-{i}.txt"));
        assert_no_certificate(&w, &repo, &before, &out, &format!("agent named {name:?}"));
    }
}

/// Plan check 6a, at the daemon (the authority, whatever the wrapper does).
/// A token request, commit token or run token, for an identity whose slug is
/// `taylor` or `root` (well-formed in every other way) is refused with an
/// error that names `allowed_agents` and the slug; the same request for
/// `claude-code` is granted. Fails today because the daemon grants any
/// well-formed slug.
#[test]
fn the_service_refuses_a_token_for_a_slug_that_is_not_allowed() {
    let mut w = World::new(&config_with(""));
    w.start_service();
    let repo = w.canonical(&w.repo());
    w.lease(&repo, "work");
    // DELIBERATE EVAL CHANGE (P7/D1, 1 Nov 2026): agents sign only when
    // launched. The control, a token for claude-code, is granted to a launched
    // session on its channel; the refusals for `taylor` and `root` are asked
    // on the service's own socket, where the name rules run first (a
    // launched session's channel would refuse any identity but its own for
    // that reason instead).
    let session = launch::start_session(&w.socket, "claude-code");
    for kind in ["IssueIdentifiedToken", "IssueRunToken"] {
        let request: agent_sign::protocol::Request = serde_json::from_value(serde_json::json!({
            "type": kind,
            "payload": {
                "repo": repo,
                "branch": "work",
                "identity": {
                    "slug": "claude-code",
                    "name": "Claude Code",
                    "principal": session.principal,
                }
            }
        }))
        .unwrap();
        let ok = session.ask(&request);
        assert!(
            matches!(ok, Response::TokenIssued { .. }),
            "{kind} for claude-code: {ok:?}"
        );
        for slug in ["taylor", "root"] {
            match w.slug_token_request(kind, &repo, slug) {
                Response::Error { message } => {
                    assert!(
                        message.contains("allowed_agents") && message.contains(slug),
                        "{kind} for {slug}: the message should name allowed_agents and the slug: {message:?}"
                    );
                }
                other => panic!("{kind} for slug {slug} was not refused: {other:?}"),
            }
        }
    }
}

impl World {
    /// A token request for `slug` with a well-formed principal.
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
}

/// Plan check 6a (the way in). A slug listed in `[identity] allowed_agents`
/// gets a certificate and a Good signature under its own principal, as
/// `Totally Real Tool` (slug `totally-real-tool`) and `My Bot 2` (`my-bot-2`) do here, at the
/// daemon too; a built-in agent still works; a name not listed (`taylor`)
/// is still refused, with the message. Fails today because the service
/// stops at start on the unknown `[identity]` table.
#[test]
fn a_slug_listed_in_allowed_agents_is_accepted_and_others_are_still_refused() {
    let mut w = World::new(&config_with(
        "[identity]\nallowed_agents = [\"totally-real-tool\", \"my-bot-2\"]\n",
    ));
    w.start_service();
    let repo = w.repo();
    w.claude_commit_ok(&repo, "control.txt");
    // DELIBERATE EVAL CHANGE (P7/D1, 1 Nov 2026): agents sign only when
    // launched (`--agent "My Bot 2"`), with the principal the service made.
    for (i, (name, slug)) in [
        ("Totally Real Tool", "totally-real-tool"),
        ("My Bot 2", "my-bot-2"),
    ]
    .iter()
    .enumerate()
    {
        let out = w.launched_commit(&repo, name, &format!("listed-{i}.txt"), &[]);
        assert_commit_ok(&w, &out, &format!("agent named {name:?}"));
        let want = w.launched_principal(&repo, "HEAD", slug);
        let trust = w.trust_lines();
        assert_eq!(
            w.signature_under(&repo, "HEAD", &trust),
            ("G".into(), want),
            "agent named {name:?}"
        );
    }

    let canonical = w.canonical(&repo);
    w.lease(&canonical, "work");
    let listed = launch::start_session(&w.socket, "totally-real-tool");
    let granted = listed.ask(&agent_sign::protocol::Request::IssueIdentifiedToken {
        repo: canonical.clone(),
        branch: "work".into(),
        identity: listed.identity.clone(),
    });
    assert!(
        matches!(granted, Response::TokenIssued { .. }),
        "daemon token for a listed slug: {granted:?}"
    );

    let before = w.rev(&repo, "HEAD");
    let out = w.named_commit(&repo, "taylor", "not-listed.txt");
    assert_no_certificate(&w, &repo, &before, &out, "agent named \"taylor\"");
}

/// Plan check 6a (a repository can't allow a name). The user's config lists
/// nothing; a cloned repository's `.agent-sign.toml` says
/// `[identity] allowed_agents = ["taylor"]`. An agent named `taylor` in that
/// repository still gets no certificate and no signature. Fails today
/// because every slug gets a certificate.
#[test]
fn a_repository_file_cant_add_to_allowed_agents() {
    let mut w = World::new(&config_with(""));
    w.start_service();
    let repo = w.repo();
    w.claude_commit_ok(&repo, "control.txt");
    fs::write(
        repo.join(".agent-sign.toml"),
        "[identity]\nallowed_agents = [\"taylor\"]\n",
    )
    .unwrap();
    let before = w.rev(&repo, "HEAD");
    let out = w.named_commit(&repo, "taylor", "hostile.txt");
    assert_no_certificate(&w, &repo, &before, &out, "agent named \"taylor\"");
}

// ---------------------------------------------------------------------------
// Dates.
// ---------------------------------------------------------------------------

impl World {
    /// `SignCommit` for a buffer whose committer timestamp is `committer_ts`
    /// (author timestamp `author_ts`), with `token`, for `repo` on `branch`.
    /// The tree and parent are the repository's own `HEAD`, so the buffer
    /// passes the service's candidate checks and only the date can differ.
    ///
    /// DELIBERATE EVAL CHANGE (caller identity, P2, 31 Oct 2026): the service signs only a
    /// commit whose one committer is the token's principal, so the committer
    /// is `principal`, the token's (it was "Fixture <fixture@example.invalid>").
    fn sign_dated(
        &self,
        session: &launch::Session,
        token: &str,
        repo: &str,
        branch: &str,
        author_ts: u64,
        committer_ts: u64,
    ) -> Response {
        let tree = self.git_ok(Path::new(repo), &["rev-parse", "HEAD^{tree}"]);
        let parent = self.git_ok(Path::new(repo), &["rev-parse", "HEAD"]);
        let buffer = format!(
            "tree {tree}\nparent {parent}\nauthor Fixture <fixture@example.invalid> {author_ts} +0000\ncommitter Claude Code <{}> {committer_ts} +0000\n\ntest: dated fixture\n",
            session.principal
        );
        // DELIBERATE EVAL CHANGE (P7/D1, 1 Nov 2026): agents sign only when
        // launched: asked on the session's channel.
        session.ask(&agent_sign::protocol::Request::SignCommit {
            token: token.to_string(),
            buffer_b64: base64::engine::general_purpose::STANDARD.encode(buffer.as_bytes()),
            repo: Some(repo.to_string()),
            branch: Some(branch.to_string()),
        })
    }

    /// A fresh commit token for the launched `session`, asked on its channel.
    fn fresh_token(&self, session: &launch::Session, repo: &str) -> String {
        let request = agent_sign::protocol::Request::IssueIdentifiedToken {
            repo: repo.to_string(),
            branch: "work".into(),
            identity: session.identity.clone(),
        };
        match session.ask(&request) {
            Response::TokenIssued { token } => token,
            other => panic!("no token for {}: {other:?}", session.principal),
        }
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Plan check 6c at the daemon (a commit dated outside its certificate's
/// lifetime). The certificate is valid from 5 minutes before it was issued
/// until 12 hours after. Committer dates of now and an hour ahead are
/// signed (controls, and an old author date is fine); two days ago, an hour
/// ago, 13 hours ahead and a year ahead are refused. Fails today because the
/// daemon signs any committer date.
#[test]
fn the_service_refuses_to_sign_a_commit_dated_outside_the_certificates_window() {
    let mut w = World::new(&config_with(""));
    w.start_service();
    let repo = w.canonical(&w.repo());
    w.lease(&repo, "work");
    let session = launch::start_session(&w.socket, "claude-code");
    let t = now();
    const HOUR: u64 = 3600;
    let cases: [(&str, u64, u64, bool); 7] = [
        ("committer date now", 1_700_000_000, t, true),
        ("committer date an hour ahead", t, t + HOUR, true),
        (
            "old author date, committer date now",
            1_600_000_000,
            t,
            true,
        ),
        ("committer date two days ago", t, t - 48 * HOUR, false),
        ("committer date an hour ago", t, t - HOUR, false),
        ("committer date 13 hours ahead", t, t + 13 * HOUR, false),
        ("committer date a year ahead", t, t + 365 * 24 * HOUR, false),
    ];
    for (what, author_ts, committer_ts, signed) in cases {
        let token = w.fresh_token(&session, &repo);
        let answer = w.sign_dated(&session, &token, &repo, "work", author_ts, committer_ts);
        match (signed, &answer) {
            (true, Response::Signed { .. }) | (false, Response::Error { .. }) => {}
            _ => panic!(
                "{what}: expected {}, got {answer:?}",
                if signed { "a signature" } else { "a refusal" }
            ),
        }
    }
}

/// Plan check 6c end to end (a backdated commit that still checks out).
/// Through the wrapper, git signs the commit with the committer date
/// `GIT_COMMITTER_DATE` gives. With dates 2020 and 2099, either the commit
/// is refused or it carries no signature at all; a date a minute ago and an
/// old author date with the committer date now are signed and verify Good
/// (controls).
///
/// Note why this checks for no signature at all, and not just "does not
/// verify Good": git verifies an SSH certificate at the commit's own time,
/// so a commit dated outside the certificate's window already fails to
/// verify today. What is missing today is that the service signs it anyway.
/// Fails today because the 2020 and 2099 commits carry a signature.
#[test]
fn an_agent_commit_with_a_committer_date_outside_the_window_is_not_signed() {
    let mut w = World::new(&config_with(""));
    w.start_service();
    let repo = w.repo();

    let controls = [
        (
            "a committer date a minute ago",
            "GIT_COMMITTER_DATE",
            format!("{} +0000", now() - 60),
        ),
        (
            "an old author date",
            "GIT_AUTHOR_DATE",
            "2020-01-01T00:00:00Z".to_string(),
        ),
    ];
    for (i, (what, var, value)) in controls.iter().enumerate() {
        w.stage(&repo, &format!("control{i}.txt"), "c\n");
        // DELIBERATE EVAL CHANGE (P7/D1, 1 Nov 2026): agents sign only when
        // launched; the principal is read back from the commit.
        let out = w.agent_with_env(&repo, &[(var, value)], &["commit", "-m", "feat: c"]);
        assert_commit_ok(&w, &out, what);
        let who = w.launched_principal(&repo, "HEAD", "claude-code");
        let trust = w.trust_lines();
        assert_eq!(
            w.signature_under(&repo, "HEAD", &trust),
            ("G".into(), who.clone()),
            "{what}"
        );
    }

    for (i, date) in ["2020-01-01T00:00:00Z", "2099-01-01T00:00:00Z"]
        .iter()
        .enumerate()
    {
        let before = w.rev(&repo, "HEAD");
        w.stage(&repo, &format!("dated{i}.txt"), "d\n");
        let out = w.agent_with_env(
            &repo,
            &[("GIT_COMMITTER_DATE", date)],
            &["commit", "-m", "feat: dated"],
        );
        if w.rev(&repo, "HEAD") != before {
            assert!(
                !w.has_signature(&repo, "HEAD"),
                "a commit with committer date {date} was signed:\n{}",
                text(&out)
            );
        }
        assert_eq!(w.signer_calls(), 0, "the person's signer was called");
    }
}

impl World {
    /// The wrapper as a launched Claude Code session runs it, with `extra`
    /// set.
    fn agent_with_env(&self, repo: &Path, extra: &[(&str, &str)], args: &[&str]) -> Output {
        let mut cmd = self.cmd(Path::new(env!("CARGO_BIN_EXE_agent-sign")));
        cmd.args(["launch", "--agent", "claude-code", "--"])
            .arg(env!("CARGO_BIN_EXE_agent-git"))
            .args(args)
            .current_dir(repo);
        for (k, v) in extra {
            cmd.env(k, v);
        }
        run_within(cmd, &format!("launched agent git {args:?} with {extra:?}"))
    }
}
