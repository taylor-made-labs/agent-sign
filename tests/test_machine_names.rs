//! The optional machine name: agent names say where an agent ran, and each
//! machine signs only for its own agents.
//!
//! These tests were written before the change, as its eval (plan "next:
//! real use on servers", checks 1 and 2, and the cross-machine refusal in
//! check 6). The interface they hold the code to:
//!
//! - The user's own `~/.agent-sign/config.toml` may set
//!   `[identity] machine = "<label>"`. A repository's `.agent-sign.toml` can
//!   never set or change it (ignored or refused).
//! - A valid label matches `^[a-z0-9]+(-[a-z0-9]+)*$` and is at most 63
//!   characters. An invalid one makes `agent-signd` refuse to start and
//!   `agent-git` refuse to commit, each with a message that names the
//!   machine setting.
//! - With a machine set, an agent's principal (the commit's author and
//!   committer email, and the certificate's principal) is
//!   `<slug>.<session8>@<machine>.agents.local`; the allowed-signers lines
//!   (`agent-sign trust-line`, and the managed block the service keeps) become
//!   `*@<machine>.agents.local cert-authority ...`; and `agent-signd`
//!   refuses any token request whose identity is in another domain: another
//!   machine's, or plain `@agents.local`.
//! - With no machine set, everything stays exactly as before
//!   (`@agents.local`). The tests marked REGRESSION GUARD pass today and
//!   must keep passing.
//!
//! Every other test here fails today. The reason is the same for most: the
//! `[identity]` table does not exist yet, so the service refuses a config
//! that holds it ("an unknown table [identity]"), and the first thing each
//! test asserts is that the service came up. The tests that must not pass
//! for that reason alone (a repository's file cannot set the machine; an
//! invalid label is refused) first prove with a valid label that the
//! setting works, so a refusal can't be the unknown-table refusal.
//!
//! Isolation is the same as `test_identity_review_fixes.rs`, whose harness
//! this follows: every process starts from an empty environment plus a
//! temporary HOME, a temporary global git config, no system config, a PATH
//! without agent-sign's installed `bin`, and a socket inside the temporary
//! directory. The person's signer is a fake that logs one line per call and
//! exits 1. Nothing here touches a real `~/.agent-sign`, a real signing key
//! or a running service. Loops are bounded and sequential: each started
//! service is stopped before the next, so no test leaves processes behind.
//!
//! The expected principals are computed here from the session ids the tests
//! set, with `sha2`, so the tests don't trust the code under test.

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

use agent_sign::agents_ca::{AgentsCa, CertificateIssuer, SessionSigner, now_secs};
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
        let key = self.home.join("person_key");
        let out = self
            .cmd(&self.ssh_keygen)
            .args(["-q", "-t", "ed25519", "-N", "", "-C", "person", "-f"])
            .arg(&key)
            .output()
            .unwrap();
        assert!(out.status.success(), "ssh-keygen: {}", text(&out));

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

    /// `agent_commit` as Claude Code with the fixed session, which must succeed.
    fn claude_commit_ok(&self, repo: &Path, file: &str) {
        let marks = marks_of(SESSION);
        let out = self.agent_commit(repo, &marks, file);
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

fn machine_config(label: &str) -> String {
    format!("[identity]\nmachine = \"{label}\"\n")
}

// ---------------------------------------------------------------------------
// 1. With a machine set, the principal says where the agent ran.
// ---------------------------------------------------------------------------

/// Plan check 1 (the name names the machine). With `machine = "hetzner"` an
/// agent's commit carries author and committer email
/// `claude-code.<session8>@hetzner.agents.local`, and the signature is Good
/// for exactly that principal under the lines `agent-sign trust-line` prints
/// (so the certificate's principal is the machine's one too). Fails today
/// because the config's `[identity]` table is unknown, so the service stops
/// at start.
#[test]
fn a_machine_set_gives_agent_commits_and_certificates_the_machine_principal() {
    let mut w = World::new(&machine_config("hetzner"));
    w.start_service();
    let repo = w.repo();
    let out = w.agent_commit(&repo, &marks_of(SESSION), "a.txt");
    assert_commit_ok(&w, &out, "agent commit with a machine set");
    let want = principal(SESSION, "hetzner.agents.local");
    assert_eq!(
        w.emails(&repo, "HEAD"),
        (want.clone(), want.clone()),
        "author and committer email should be the machine's principal"
    );
    let trust = w.trust_lines();
    assert_eq!(
        w.signature_under(&repo, "HEAD", &trust),
        ("G".into(), want),
        "the signature should be Good for the machine's principal, under trust-line's lines"
    );
}

/// REGRESSION GUARD (passes today): with no machine set, the principal, the
/// trust line and the signature are exactly what they were before the
/// change: `@agents.local`, `*@agents.local cert-authority,namespaces="git"`.
#[test]
fn regression_guard_no_machine_set_keeps_agents_local_everywhere() {
    let mut w = World::new("");
    w.start_service();
    let repo = w.repo();
    let out = w.agent_commit(&repo, &marks_of(SESSION), "a.txt");
    assert_commit_ok(&w, &out, "agent commit with no machine set");
    let want = principal(SESSION, "agents.local");
    assert_eq!(w.emails(&repo, "HEAD"), (want.clone(), want.clone()));
    let trust = w.trust_lines();
    assert!(!trust.trim().is_empty(), "trust-line printed nothing");
    for line in trust.lines() {
        assert!(
            line.starts_with("*@agents.local cert-authority,namespaces=\"git\" ssh-ed25519 "),
            "trust-line changed with no machine set: {line:?}"
        );
    }
    assert_eq!(w.signature_under(&repo, "HEAD", &trust), ("G".into(), want));
}

// ---------------------------------------------------------------------------
// 2. The trust line and the managed block are scoped to the machine.
// ---------------------------------------------------------------------------

/// Plan check 1 / 6b (a machine's trust is only for its own domain). With
/// `machine = "hetzner"`, every line `agent-sign trust-line` prints begins
/// `*@hetzner.agents.local cert-authority`, none trusts the bare
/// `*@agents.local`, and the managed block the service writes into the
/// user's allowed-signers file holds exactly those lines. Fails today
/// because the service stops at start on the unknown `[identity]` table.
#[test]
fn the_trust_line_and_the_managed_block_are_scoped_to_the_machine() {
    let mut w = World::new(&machine_config("hetzner"));
    let allowed = w.home.join("allowed_signers");
    let before =
        "dev@example.com namespaces=\"git\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIUserKeyLine\n";
    fs::write(&allowed, format!("{before}{BLOCK_BEGIN}\n{BLOCK_END}\n")).unwrap();
    w.name_allowed_signers_file(&allowed);
    w.start_service();

    let trust = w.trust_lines();
    assert!(!trust.trim().is_empty(), "trust-line printed nothing");
    for line in trust.lines() {
        assert!(
            line.starts_with("*@hetzner.agents.local cert-authority"),
            "trust-line should be scoped to the machine: {line:?}"
        );
        assert!(
            !line.starts_with("*@agents.local"),
            "trust-line still trusts the bare domain: {line:?}"
        );
    }

    let content = fs::read_to_string(&allowed).unwrap();
    assert!(
        content.starts_with(before),
        "the user's lines changed:\n{content}"
    );
    let begin = content.find(BLOCK_BEGIN).expect("block begin") + BLOCK_BEGIN.len() + 1;
    let end = content.find(BLOCK_END).expect("block end");
    assert_eq!(
        &content[begin..end],
        trust,
        "the managed block should hold exactly trust-line's lines:\n{content}"
    );
}

// ---------------------------------------------------------------------------
// 3. Valid and invalid labels.
// ---------------------------------------------------------------------------

/// Plan check 1 (what a machine may be called). Labels matching
/// `^[a-z0-9]+(-[a-z0-9]+)*$`, up to 63 characters, start the service and
/// give an agent commit the principal `...@<label>.agents.local`, Good under
/// trust-line. Fails today because the service stops at start on the
/// unknown `[identity]` table.
#[test]
fn valid_machine_labels_are_accepted() {
    let longest = "a".repeat(63);
    for label in [
        "a",
        "pi",
        "hetzner",
        "my-box-2",
        "9lives",
        "ubuntu-16gb-hel1-1",
        longest.as_str(),
    ] {
        let mut w = World::new(&machine_config(label));
        w.start_service();
        let repo = w.repo();
        let out = w.agent_commit(&repo, &marks_of(SESSION), "a.txt");
        assert_commit_ok(&w, &out, &format!("agent commit with machine {label:?}"));
        let want = principal(SESSION, &format!("{label}.agents.local"));
        assert_eq!(w.emails(&repo, "HEAD"), (want.clone(), want.clone()));
        let trust = w.trust_lines();
        assert_eq!(
            w.signature_under(&repo, "HEAD", &trust),
            ("G".into(), want),
            "machine {label:?}"
        );
    }
}

/// The labels that must be refused: an `@` or a `.` (either would let a
/// label reach into another domain: OpenSSH's `*` also matches `@`), empty,
/// upper case, 64 characters, a leading, trailing or doubled `-`, and other
/// characters.
fn invalid_labels() -> Vec<String> {
    let mut labels: Vec<String> = [
        "a@b", "x.y", "", "Hetzner", "HETZNER", "-a", "a-", "a--b", "a b", "a_b", "é", "a/b",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    labels.push("a".repeat(64));
    labels
}

/// Plan check 1 (invalid labels). For each invalid label the service stops
/// at start with a failure exit and a log line naming the machine setting.
/// The test first starts the service with a valid label, so a refusal here
/// can't be the unknown-table refusal of today. Fails today at that
/// control.
#[test]
fn the_service_refuses_to_start_on_an_invalid_machine_label() {
    // Control: the setting works when valid.
    let mut ok = World::new(&machine_config("hetzner"));
    ok.start_service();
    ok.stop_service();

    for label in invalid_labels() {
        let w = World::new(&machine_config(&label));
        let stopped = w.service_stops_at_start();
        assert!(
            stopped.is_some_and(|s| !s.success()),
            "the service started (or didn't fail) with machine {label:?}: {stopped:?}\n{}",
            w.service_log()
        );
        let log = w.service_log().to_lowercase();
        assert!(
            log.contains("machine"),
            "the message for machine {label:?} should name the machine setting:\n{log}"
        );
    }
}

/// Plan check 1 (invalid labels, the wrapper's side). A running service was
/// started with a valid label; the config is then changed to each invalid
/// label, and an agent commit is refused: non-zero exit, nothing committed,
/// a message that names the machine setting. Changing the config back to a
/// valid label lets the same commit through. Fails today at the first
/// control commit (unknown `[identity]` table).
#[test]
fn the_wrapper_refuses_to_commit_on_an_invalid_machine_label() {
    let mut w = World::new(&machine_config("hetzner"));
    w.start_service();
    let repo = w.repo();
    w.claude_commit_ok(&repo, "control.txt");
    let head = w.rev(&repo, "HEAD");

    w.stage(&repo, "next.txt", "next\n");
    let marks = marks_of(SESSION);
    for label in invalid_labels() {
        w.set_config(&machine_config(&label));
        let out = w.agent(&repo, &marks, &["commit", "-m", "feat: next"]);
        assert!(
            !out.status.success(),
            "the wrapper committed with machine {label:?}:\n{}",
            text(&out)
        );
        assert_eq!(
            w.rev(&repo, "HEAD"),
            head,
            "a commit was made with machine {label:?}"
        );
        assert!(
            stderr(&out).to_lowercase().contains("machine"),
            "the message for machine {label:?} should name the machine setting:\n{}",
            text(&out)
        );
    }

    w.set_config(&machine_config("hetzner"));
    let out = w.agent(&repo, &marks, &["commit", "-m", "feat: next"]);
    assert_commit_ok(&w, &out, "the same commit once the label is valid again");
}

// ---------------------------------------------------------------------------
// 4. A repository's file can't set the machine.
// ---------------------------------------------------------------------------

/// Plan check 1 / 6 (a repository can't choose the agent's domain). The
/// user's config says `hetzner`; a cloned repository's `.agent-sign.toml`
/// says `[identity] machine = "evil"`. Either the commit is refused or it
/// carries the user's own machine; in no case does `evil` appear in a
/// commit or a certificate. A control commit in the same world, before the
/// hostile file, proves the setting works (so "refused" can't be the
/// unknown-table refusal of today). Fails today at that control.
#[test]
fn a_repository_file_cant_change_the_machine_the_user_set() {
    let mut w = World::new(&machine_config("hetzner"));
    w.start_service();
    let repo = w.repo();
    w.claude_commit_ok(&repo, "control.txt");
    let mine = principal(SESSION, "hetzner.agents.local");
    assert_eq!(w.emails(&repo, "HEAD"), (mine.clone(), mine.clone()));

    fs::write(
        repo.join(".agent-sign.toml"),
        "[identity]\nmachine = \"evil\"\n",
    )
    .unwrap();
    let before = w.rev(&repo, "HEAD");
    let out = w.agent_commit(&repo, &marks_of(SESSION), "hostile.txt");
    let trust = w.trust_lines();
    if out.status.success() {
        assert_eq!(
            w.emails(&repo, "HEAD"),
            (mine.clone(), mine.clone()),
            "a repository's file changed the machine of an agent commit"
        );
        assert_eq!(w.signature_under(&repo, "HEAD", &trust), ("G".into(), mine));
    } else {
        assert_eq!(
            w.rev(&repo, "HEAD"),
            before,
            "a refused commit left a commit behind"
        );
    }
    let log = w.git_ok(&repo, &["log", "--format=%ae %ce %an"]);
    assert!(
        !log.contains("evil"),
        "a commit names the repository's machine:\n{log}"
    );
    assert!(
        !trust.contains("evil"),
        "the trust line names the repository's machine:\n{trust}"
    );
}

/// REGRESSION GUARD (passes today): with no machine in the user's config, a
/// repository's `[identity] machine = "evil"` doesn't give the user a
/// machine. The commit is either refused or stays `@agents.local`; and a
/// control commit before the file shows the plain name works.
#[test]
fn regression_guard_a_repository_file_cant_give_a_machine_to_a_user_with_none() {
    let mut w = World::new("");
    w.start_service();
    let repo = w.repo();
    w.claude_commit_ok(&repo, "control.txt");
    let plain = principal(SESSION, "agents.local");
    assert_eq!(w.emails(&repo, "HEAD"), (plain.clone(), plain.clone()));

    fs::write(
        repo.join(".agent-sign.toml"),
        "[identity]\nmachine = \"evil\"\n",
    )
    .unwrap();
    let out = w.agent_commit(&repo, &marks_of(SESSION), "hostile.txt");
    if out.status.success() {
        assert_eq!(w.emails(&repo, "HEAD"), (plain.clone(), plain));
    }
    let log = w.git_ok(&repo, &["log", "--format=%ae %ce %an"]);
    assert!(!log.contains("evil"), "a commit names `evil`:\n{log}");
}

// ---------------------------------------------------------------------------
// 5. The service refuses another machine's domain.
// ---------------------------------------------------------------------------

/// Plan check 6b (one machine's agent-sign signing for the other machine's
/// agents). With `machine = "hetzner"`, a token request (commit token or
/// run token) for an identity in the machine's own domain is granted, and
/// the same request for `@pi.agents.local`, for plain `@agents.local`, or
/// for a sub-domain `@x.hetzner.agents.local` is refused with an error.
/// Fails today because the service stops at start on the unknown
/// `[identity]` table.
#[test]
fn the_service_refuses_token_requests_in_another_domain() {
    let mut w = World::new(&machine_config("hetzner"));
    w.start_service();
    let repo = w.canonical(&w.repo());
    w.lease(&repo, "work");
    for kind in ["IssueIdentifiedToken", "IssueRunToken"] {
        let own = principal(SESSION, "hetzner.agents.local");
        let granted = w.token_request(kind, &repo, "work", &own);
        assert!(
            matches!(granted, Response::TokenIssued { .. }),
            "{kind} for the machine's own domain: {granted:?}"
        );
        for foreign in ["pi.agents.local", "agents.local", "x.hetzner.agents.local"] {
            let p = principal(SESSION, foreign);
            let refused = w.token_request(kind, &repo, "work", &p);
            assert!(
                matches!(refused, Response::Error { .. }),
                "{kind} for {p} was not refused on machine hetzner: {refused:?}"
            );
        }
    }
}

/// REGRESSION GUARD (passes today): with no machine set, plain
/// `@agents.local` is granted and a machine domain is refused.
#[test]
fn regression_guard_with_no_machine_only_the_plain_domain_is_served() {
    let mut w = World::new("");
    w.start_service();
    let repo = w.canonical(&w.repo());
    w.lease(&repo, "work");
    for kind in ["IssueIdentifiedToken", "IssueRunToken"] {
        let plain = principal(SESSION, "agents.local");
        let granted = w.token_request(kind, &repo, "work", &plain);
        assert!(
            matches!(granted, Response::TokenIssued { .. }),
            "{kind} for the plain domain: {granted:?}"
        );
        let p = principal(SESSION, "hetzner.agents.local");
        let refused = w.token_request(kind, &repo, "work", &p);
        assert!(
            matches!(refused, Response::Error { .. }),
            "{kind} for {p} was not refused with no machine set: {refused:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// 6. A combined trust file keeps the machines apart.
// ---------------------------------------------------------------------------

/// Runs `ssh-keygen -Y verify` for `principal` over `data` with signature
/// `sig`, against the allowed-signers file `allowed`.
fn ssh_verify(w: &World, allowed: &Path, principal: &str, sig: &str, data: &[u8]) -> Output {
    let sig_file = w.home.join("check.sig");
    fs::write(&sig_file, sig).unwrap();
    let mut child = Command::new(&w.ssh_keygen)
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
    child.wait_with_output().unwrap()
}

/// Plan check 6b (one machine can't vouch for another's agents), with the
/// real thing and with a hostile authority.
///
/// Real: two services, one `hetzner` and one `pi`, each with its own
/// authority. One combined allowed-signers file holds both machines' real
/// `trust-line` lines. Each machine's agent commit is Good under the
/// combined file for its own principal; the hetzner commit is not Good under
/// the pi line alone.
///
/// Hostile: the combined file's hetzner line keeps its real scope but trusts
/// a key this test holds (a hetzner authority that has gone bad). A
/// certificate from that key for a hetzner principal verifies (control), but
/// one for a pi principal does not, because the hetzner line is scoped to
/// `*@hetzner.agents.local` and the pi line trusts another key. This is the
/// check that fails if the lines are not scoped by machine. Fails today
/// because the services stop at start on the unknown `[identity]` table.
#[test]
fn a_combined_trust_file_rejects_one_machines_signature_for_the_others_principal() {
    let mut hetzner = World::new(&machine_config("hetzner"));
    let mut pi = World::new(&machine_config("pi"));
    hetzner.start_service();
    pi.start_service();
    let h_repo = hetzner.repo();
    let p_repo = pi.repo();
    hetzner.claude_commit_ok(&h_repo, "h.txt");
    pi.claude_commit_ok(&p_repo, "p.txt");
    let (h_lines, p_lines) = (hetzner.trust_lines(), pi.trust_lines());
    let combined = format!("{h_lines}{p_lines}");
    let h_principal = principal(SESSION, "hetzner.agents.local");
    let p_principal = principal(SESSION, "pi.agents.local");

    assert_eq!(
        hetzner.signature_under(&h_repo, "HEAD", &combined),
        ("G".into(), h_principal.clone()),
        "hetzner's commit under the combined file"
    );
    assert_eq!(
        pi.signature_under(&p_repo, "HEAD", &combined),
        ("G".into(), p_principal.clone()),
        "pi's commit under the combined file"
    );
    assert_ne!(
        hetzner.signature_under(&h_repo, "HEAD", &p_lines).0,
        "G",
        "hetzner's commit is Good under the pi line alone"
    );
    assert_ne!(
        pi.signature_under(&p_repo, "HEAD", &h_lines).0,
        "G",
        "pi's commit is Good under the hetzner line alone"
    );

    // Hostile: a bad hetzner authority, scoped as the real hetzner line is.
    let h_line = h_lines.lines().next().expect("a hetzner line");
    let scope = h_line
        .split(" ssh-")
        .next()
        .expect("the line's scope and options");
    assert!(
        scope.starts_with("*@hetzner.agents.local cert-authority"),
        "the hetzner line: {h_line:?}"
    );
    let rogue = AgentsCa::from_seed([7u8; 32], "rogue-hetzner");
    let rogue_h_line = format!("{scope} {}\n", rogue.public_key_openssh());
    let allowed = hetzner.home.join("combined_allowed_signers");
    fs::write(&allowed, format!("{rogue_h_line}{p_lines}")).unwrap();

    let buffer = b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\nauthor A <a@x> 1 +0000\ncommitter A <a@x> 1 +0000\n\nrogue\n";
    let now = now_secs();
    let for_hetzner = SessionSigner::new(&rogue, &h_principal, now)
        .unwrap()
        .sign_git_buffer(buffer);
    let ok = ssh_verify(&hetzner, &allowed, &h_principal, &for_hetzner, buffer);
    assert!(
        ok.status.success(),
        "control: the hetzner authority's certificate for a hetzner principal should verify:\n{}",
        text(&ok)
    );
    let for_pi = SessionSigner::new(&rogue, &p_principal, now)
        .unwrap()
        .sign_git_buffer(buffer);
    let bad = ssh_verify(&hetzner, &allowed, &p_principal, &for_pi, buffer);
    assert!(
        !bad.status.success(),
        "a hetzner-certified signature for the pi principal {p_principal} verified under the combined file:\n{}",
        text(&bad)
    );
}

// ---------------------------------------------------------------------------
// 7. Separate agents, separate names.
// ---------------------------------------------------------------------------

/// Plan check 2 (two agents at once sign under two different names). Two
/// agents with different session ids commit at the same time on one machine
/// (`machine = "hetzner"`): each commit is Good under trust-line for its own
/// principal, and the two principals differ. Fails today because the
/// service stops at start on the unknown `[identity]` table.
#[test]
fn two_agents_with_different_sessions_sign_under_two_principals() {
    let mut w = World::new(&machine_config("hetzner"));
    w.start_service();
    let (repo1, repo2) = (w.repo_named("repo1", "work"), w.repo_named("repo2", "work"));
    let (m1, m2) = (marks_of("session-one"), marks_of("session-two"));
    let (out1, out2) = std::thread::scope(|s| {
        let a = s.spawn(|| w.agent_commit(&repo1, &m1, "one.txt"));
        let b = s.spawn(|| w.agent_commit(&repo2, &m2, "two.txt"));
        (a.join().unwrap(), b.join().unwrap())
    });
    assert_commit_ok(&w, &out1, "first agent's commit");
    assert_commit_ok(&w, &out2, "second agent's commit");
    let (p1, p2) = (
        principal("session-one", "hetzner.agents.local"),
        principal("session-two", "hetzner.agents.local"),
    );
    assert_ne!(p1, p2);
    let trust = w.trust_lines();
    assert_eq!(w.emails(&repo1, "HEAD"), (p1.clone(), p1.clone()));
    assert_eq!(w.emails(&repo2, "HEAD"), (p2.clone(), p2.clone()));
    assert_eq!(
        w.signature_under(&repo1, "HEAD", &trust),
        ("G".into(), p1),
        "first agent"
    );
    assert_eq!(
        w.signature_under(&repo2, "HEAD", &trust),
        ("G".into(), p2),
        "second agent"
    );
}
