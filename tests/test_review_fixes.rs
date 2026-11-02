//! The eval for the fix round after the security review of the `feat/servers`
//! branch. Written before the fixes, by someone other than their builder;
//! each test names the finding it holds the code to, and says in its doc
//! comment whether it fails today (and why) or is a guard or pin that passes
//! today.
//!
//! | Finding | Test(s) | Today |
//! |---|---|---|
//! | M2: "never a person's name" must not depend on git | `m2_*` | fail, except the Dana and harmless-name guards |
//! | L4: executing install.sh with the functions-only variable | `l4_*` | one fails, one guard |
//! | L5: `--launcher-unit` and `EnvironmentFile=` | `l5_*` | one fails, two guards (Linux only) |
//! | L8: a date-refused signature in run mode | `l8_*` | one fails, one passes (see its comment) |
//! | L9: the default agent names | `l9_*` | pin, passes |
//! | Claimed, not proven | `claimed_*` | fail |
//!
//! (L6, the daemons that outlive a killed test run, is checked by
//! `scripts/check-test-daemons-die.sh`, not here: it has to kill a test
//! process, which a test can't do to itself.)
//!
//! Isolation follows `test_allowed_agents.rs` (agent-side tests) and
//! `test_install_servers.rs` (installer tests), whose harnesses are copied
//! here: every process starts from an empty environment plus a temporary
//! HOME, a temporary global git config, no system config, a PATH without
//! agent-sign's installed `bin`, and a socket inside the temporary
//! directory. The person's signer is a fake that logs one line per call and
//! exits 1. The installer runs against stand-ins for `systemctl`,
//! `launchctl` and friends, so no real service manager is reached. Nothing
//! here touches a real `~/.agent-sign`, a real signing key or a running
//! service.

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

use agent_sign::protocol::{Request, Response};

#[path = "support/launch.rs"]
mod launch;

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
    ///
    /// DELIBERATE EVAL CHANGE (caller identity, P2, 31 Oct 2026): the service signs only a
    /// commit whose one committer is the token's principal, so the committer
    /// is [`SESSION`]'s Claude Code, the identity every token used here is
    /// issued for (it was "Fixture <fixture@example.invalid>").
    ///
    /// DELIBERATE EVAL CHANGE (P7/D1, 1 Nov 2026): agents sign only when
    /// launched: the committer is the launched `session`'s principal and the
    /// request is asked on its channel.
    fn sign_dated(
        &self,
        session: &launch::Session,
        token: &str,
        repo: &str,
        committer_ts: u64,
    ) -> Response {
        let tree = self.git_ok(Path::new(repo), &["rev-parse", "HEAD^{tree}"]);
        let parent = self.git_ok(Path::new(repo), &["rev-parse", "HEAD"]);
        let t = now();
        let principal = &session.principal;
        let buffer = format!(
            "tree {tree}\nparent {parent}\nauthor Fixture <fixture@example.invalid> {t} +0000\ncommitter Claude Code <{principal}> {committer_ts} +0000\n\ntest: dated fixture\n"
        );
        session.ask(&Request::SignCommit {
            token: token.to_string(),
            buffer_b64: base64::engine::general_purpose::STANDARD.encode(buffer.as_bytes()),
            repo: Some(repo.to_string()),
            branch: Some("work".to_string()),
        })
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

// ---------------------------------------------------------------------------
// M2: "never a person's name" must not depend on git.
// ---------------------------------------------------------------------------

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

/// M2. On a machine whose git `user.name` is an agent's ("work-loop agent on
/// hetzner") and whose config has no `[human]` section, listing `taylor`,
/// `root` or `admin` in `[identity] allowed_agents` must still be refused:
/// the deny-list is fixed in `IdentityPolicy::check`, not derived from what
/// git says the person is called. The service refuses to start, or the
/// agent's commit under that name gets no certificate and no signature, with
/// a message naming `allowed_agents` and the name.
///
/// Fails today because the person's name is taken from git, which here names
/// no person: the service starts and a `taylor` commit is signed and
/// verifies Good.
#[test]
fn m2_a_person_s_name_in_allowed_agents_is_refused_without_git_naming_the_person() {
    for name in ["taylor", "root", "admin"] {
        // DELIBERATE EVAL CHANGE (fix round 1, 31 Oct 2026): a product for
        // anyone can't know that "taylor" is a person's name with nothing
        // configured (CI machines have no taylor account), so the taylor
        // case lists Taylor in `[identity] people`. root and admin are still
        // refused with nothing configured.
        let people = if name == "taylor" {
            "people = [\"Taylor\"]\n"
        } else {
            ""
        };
        let mut w = World::with_git_name(
            &config_with(&format!(
                "[identity]\nallowed_agents = [\"{name}\"]\n{people}"
            )),
            AGENT_GIT_NAME,
        );
        // The world is what the finding describes.
        assert!(!w.config_text().contains("[human]"), "{}", w.config_text());
        assert_eq!(
            w.git_ok(&w.home.clone(), &["config", "--global", "user.name"]),
            AGENT_GIT_NAME
        );
        assert_name_refused(&mut w, name, &format!("allowed_agents = [{name:?}]"));
    }
}

/// M2, at the daemon (the authority, whatever the wrapper does). Same world:
/// git names an agent, no `[human]` section, and `allowed_agents` lists
/// `taylor`, `root` and `admin` besides a harmless `totally-real-tool`. The
/// service refuses to start (naming `allowed_agents` and a name), or it runs
/// and every token request, commit token or run token, for `taylor`, `root`
/// or `admin` is refused with an error that names `allowed_agents` and the
/// slug, while the same requests for `totally-real-tool` and `claude-code`
/// are granted (so the refusal is not "everything fails").
///
/// Fails today because the daemon grants a token for any slug on the list.
#[test]
fn m2_the_service_never_certifies_taylor_root_or_admin_whatever_allowed_agents_says() {
    // DELIBERATE EVAL CHANGE (fix round 1, 31 Oct 2026): Taylor is listed
    // in `[identity] people`, since a product for anyone can't know that
    // "taylor" is a person's name with nothing configured (CI machines have
    // no taylor account). root and admin with nothing configured are the
    // test above.
    let mut w = World::with_git_name(
        &config_with(
            "[identity]\nallowed_agents = [\"taylor\", \"root\", \"admin\", \"totally-real-tool\"]\npeople = [\"Taylor\"]\n",
        ),
        AGENT_GIT_NAME,
    );
    assert!(!w.config_text().contains("[human]"));
    match w.start_or_refusal() {
        Start::Refused(status) => {
            let log = w.service_log();
            assert!(!status.success(), "the service stopped with {status}");
            assert!(
                log.contains("allowed_agents")
                    && ["taylor", "root", "admin"].iter().any(|n| log.contains(n)),
                "the service's refusal should name `allowed_agents` and the name:\n{log}"
            );
        }
        Start::Running => {
            let repo = w.canonical(&w.repo());
            w.lease(&repo, "work");
            for kind in ["IssueIdentifiedToken", "IssueRunToken"] {
                for ok in ["totally-real-tool", "claude-code"] {
                    let granted = w.slug_token_request(kind, &repo, ok);
                    assert!(
                        matches!(granted, Response::TokenIssued { .. }),
                        "{kind} for {ok} (control): {granted:?}"
                    );
                }
                for slug in ["taylor", "root", "admin"] {
                    match w.slug_token_request(kind, &repo, slug) {
                        Response::Error { message } => assert!(
                            message.contains("allowed_agents") && message.contains(slug),
                            "{kind} for {slug}: the message should name allowed_agents and the slug: {message:?}"
                        ),
                        other => panic!("{kind} for slug {slug} was not refused: {other:?}"),
                    }
                }
            }
        }
    }
}

/// M2, REGRESSION GUARD (passes today; it must keep passing when the
/// deny-list moves into `IdentityPolicy::check`). With `[human] name = "Dana
/// Example"` configured, `dana` and `dana-example` in `allowed_agents` are
/// refused too, even though git's `user.name` is an agent's.
#[test]
fn m2_guard_the_configured_humans_name_is_refused_too() {
    for name in ["dana", "dana-example"] {
        let mut w = World::with_git_name(
            &config_with(&format!(
                "[human]\nname = \"Dana Example\"\nemail = \"dana@example.com\"\n\n\
                 [identity]\nallowed_agents = [\"{name}\"]\n"
            )),
            AGENT_GIT_NAME,
        );
        assert_name_refused(&mut w, name, &format!("allowed_agents = [{name:?}]"));
    }
}

/// M2, REGRESSION GUARD (passes today). On the same agent-named-git machine
/// a harmless name in `allowed_agents` still works end to end: the deny-list
/// must not turn into "this machine refuses everything".
#[test]
fn m2_guard_a_harmless_listed_name_still_signs_where_git_names_an_agent() {
    let mut w = World::with_git_name(
        &config_with("[identity]\nallowed_agents = [\"totally-real-tool\"]\n"),
        AGENT_GIT_NAME,
    );
    w.start_service();
    let repo = w.repo();
    // DELIBERATE EVAL CHANGE (P7/D1, 1 Nov 2026): agents sign only when
    // launched.
    let out = w.launched_commit(&repo, "Totally Real Tool", "listed.txt");
    assert!(out.status.success(), "{}\n{}", text(&out), w.service_log());
    let want = w.launched_principal(&repo, "HEAD", "totally-real-tool");
    let trust = w.trust_lines();
    assert_eq!(w.signature_under(&repo, "HEAD", &trust), ("G".into(), want));
}

// ---------------------------------------------------------------------------
// L9: the default agent names are pinned.
// ---------------------------------------------------------------------------

/// L9, a PIN, not a failing test (passes today). The agent names that get a
/// certificate with no setting are exactly these. Changing either list
/// changes who the service certifies, so it must be a deliberate edit of
/// this test as well, in the same change and with a reason.
#[test]
fn l9_pin_the_default_agent_names() {
    assert_eq!(
        agent_sign::attribution::WIDELY_USED_AGENT_SLUGS,
        [
            "aider",
            "antigravity",
            "cline",
            "copilot",
            "cursor",
            "opencode",
            "windsurf"
        ]
    );
    assert_eq!(
        agent_sign::attribution::BUILT_IN_AGENT_SLUGS,
        ["claude-code", "codex", "gemini-cli"]
    );
}

// ---------------------------------------------------------------------------
// L8: a signature refused for its committer date is not used up.
// ---------------------------------------------------------------------------

/// A world with a service, a lease on `work`, and a run token for a launched
/// Claude Code session (one the test starts itself, playing the launcher:
/// DELIBERATE EVAL CHANGE (P7/D1, 1 Nov 2026), agents sign only when
/// launched); returns `(world, session, canonical repo, run token)`.
fn run_mode_world(config: &str) -> (World, launch::Session, String, String) {
    let mut w = World::new(config);
    w.start_service();
    let repo = w.canonical(&w.repo());
    w.lease(&repo, "work");
    let session = launch::start_session(&w.socket, "claude-code");
    let token = match session.ask(&Request::IssueRunToken {
        repo: repo.clone(),
        branch: "work".into(),
        identity: session.identity.clone(),
    }) {
        Response::TokenIssued { token } => token,
        other => panic!("no run token: {other:?}"),
    };
    (w, session, repo, token)
}

const HOUR: u64 = 3600;

/// L8, as the brief states it. In run mode, with `max_commits_per_minute`
/// low (3), six commits refused for their committer dates (two days ago, 13
/// hours ahead) leave an in-window commit signable on the same run token.
///
/// This one PASSES TODAY: a signature made with a run token never counted
/// against the rate limit (the run counted once, when its token was issued),
/// so the date refusals could not use it up. The behaviour that does fail
/// today is the usage record, in the next test; this test stays as a guard
/// so the fix can't make refusals count against the rate.
#[test]
fn l8_guard_date_refusals_in_run_mode_do_not_use_up_the_rate_limit() {
    let (w, session, repo, token) = run_mode_world("[security]\nmax_commits_per_minute = 3\n");
    let t = now();
    for i in 0..6u64 {
        let committer = if i % 2 == 0 {
            t - 48 * HOUR
        } else {
            t + 13 * HOUR
        };
        match w.sign_dated(&session, &token, &repo, committer) {
            Response::Error { message } => assert!(
                message.contains("committer date"),
                "refusal {i} should be the committer-date one: {message:?}"
            ),
            other => panic!("refusal {i}: a commit dated outside the window was signed: {other:?}"),
        }
    }
    let ok = w.sign_dated(&session, &token, &repo, t);
    assert!(
        matches!(ok, Response::Signed { .. }),
        "an in-window commit after six date refusals: {ok:?}"
    );
}

/// L8. In run mode a signature refused for its committer date must leave the
/// lease's usage record alone: `record_signature` runs before the date check
/// in `sign_candidate`, so each refusal raises the lease's `commit_count`
/// (the number `agent-sign leases` shows) and its last-used time (which the
/// idle limit measures), as if the refused commit had been made. After six
/// refusals the count must be what it was before them; an in-window commit
/// afterwards still signs.
///
/// Fails today: the count goes up by six.
#[test]
fn l8_a_date_refused_signature_in_run_mode_is_not_recorded_as_a_commit() {
    let (w, session, repo, token) = run_mode_world(&config_with(""));
    let before = w.lease_commit_count(&repo, "work");
    let t = now();
    for i in 0..6u64 {
        let committer = if i % 2 == 0 {
            t - 48 * HOUR
        } else {
            t + 13 * HOUR
        };
        let answer = w.sign_dated(&session, &token, &repo, committer);
        assert!(
            matches!(answer, Response::Error { .. }),
            "refusal {i}: {answer:?}"
        );
    }
    let after = w.lease_commit_count(&repo, "work");
    assert_eq!(
        after, before,
        "six signatures refused for their committer dates changed the lease's commit_count \
         from {before} to {after}"
    );
    let ok = w.sign_dated(&session, &token, &repo, t);
    assert!(
        matches!(ok, Response::Signed { .. }),
        "an in-window commit after the refusals: {ok:?}"
    );
}

// ---------------------------------------------------------------------------
// Claimed, not proven: what a certificate and `doctor` say about how the
// identity was established.
// ---------------------------------------------------------------------------

/// The armored SSHSIG in a commit object's `gpgsig` header.
fn gpgsig_of(commit: &str) -> String {
    let mut out = String::new();
    let mut inside = false;
    for line in commit.lines() {
        if let Some(rest) = line.strip_prefix("gpgsig ") {
            inside = true;
            out.push_str(rest);
            out.push('\n');
        } else if inside {
            match line.strip_prefix(' ') {
                Some(rest) => {
                    out.push_str(rest);
                    out.push('\n');
                }
                None => break,
            }
        }
    }
    out
}

/// The certificate inside an armored SSHSIG, as `ssh-keygen -L` reads it
/// (`<key type> <base64 blob>`).
fn certificate_line(armored: &str) -> String {
    let body: String = armored
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect();
    let raw = base64::engine::general_purpose::STANDARD
        .decode(body)
        .unwrap();
    assert_eq!(&raw[..6], b"SSHSIG");
    let len = u32::from_be_bytes(raw[10..14].try_into().unwrap()) as usize;
    let blob = &raw[14..14 + len];
    let type_len = u32::from_be_bytes(blob[..4].try_into().unwrap()) as usize;
    let key_type = std::str::from_utf8(&blob[4..4 + type_len]).unwrap();
    format!(
        "{key_type} {}",
        base64::engine::general_purpose::STANDARD.encode(blob)
    )
}

/// Claimed, not proven (certificates), after the switch (P7/D1, 1 Nov 2026).
/// A certificate can no longer say "claimed": a process in the account
/// can't get one by claiming a session. A launched session's certificate
/// (read with `ssh-keygen -L` from the signature in the signed commit)
/// has the key id `<principal> on <host>`, which says nothing about the
/// name being claimed, and carries the `attestation@agent-sign` extension
/// that says the launcher established it. The old assertion (a key id ending
/// "claimed by a process in a shared account") is now only true of
/// certificates from before the switch, which `agent-sign verify` reads
/// (`p8_a_self_asserted_signature_is_reported_as_claimed_never_as_proven`).
///
/// DELIBERATE EVAL CHANGE (P7/D1, 1 Nov 2026): agents sign only when
/// launched; plan step S8, group B.
#[test]
fn claimed_the_certificates_key_id_says_the_identity_was_claimed() {
    let mut w = World::new(&config_with(""));
    w.start_service();
    let repo = w.repo();
    w.claude_commit_ok(&repo, "claimed.txt");
    let commit = w.git_ok(&repo, &["cat-file", "commit", "HEAD"]);
    let armored = gpgsig_of(&commit);
    assert!(!armored.is_empty(), "no signature in:\n{commit}");

    let cert_file = w.home.join("agent-cert.pub");
    fs::write(&cert_file, format!("{}\n", certificate_line(&armored))).unwrap();
    let listing = w
        .cmd(&w.ssh_keygen)
        .args(["-L", "-f"])
        .arg(&cert_file)
        .output()
        .unwrap();
    assert!(
        listing.status.success(),
        "ssh-keygen -L: {}",
        text(&listing)
    );
    let listing = stdout(&listing);
    let key_id = listing
        .lines()
        .find_map(|l| l.trim().strip_prefix("Key ID:"))
        .unwrap_or_else(|| panic!("no Key ID in:\n{listing}"))
        .trim()
        .trim_matches('"')
        .to_string();
    let principal = w.launched_principal(&repo, "HEAD", "claude-code");
    let want = format!("{principal} on {}", agent_sign::agents_ca::hostname());
    assert_eq!(key_id, want, "the certificate:\n{listing}");
    assert!(
        !key_id.contains("claimed"),
        "a launched session's certificate says it was claimed: {key_id}"
    );
    assert!(
        listing.contains("attestation@agent-sign"),
        "the certificate should carry the attestation extension:\n{listing}"
    );
}

/// The other half of the claimed-key-id property, after the switch (P7/D1,
/// 1 Nov 2026): a process in the account that nobody launched, claiming an
/// agent by its marks, gets no certificate at all. Its commit is made under
/// the claimed names with no signature, so nothing says a name was proven.
#[test]
fn claimed_a_process_nobody_launched_gets_no_certificate_at_all() {
    let mut w = World::new(&config_with(""));
    w.start_service();
    let repo = w.repo();
    let out = w.agent_commit(&repo, &marks_of(SESSION), "claimed.txt");
    assert!(out.status.success(), "{}\n{}", text(&out), w.service_log());
    assert!(
        !w.has_signature(&repo, "HEAD"),
        "a process nobody launched got a certificate"
    );
}

/// Claimed, not proven (`doctor`), after the switch (P7/D1, 1 Nov 2026).
/// `agent-sign doctor` says, in plain words, what an agent's signature
/// means now: only an agent a launcher started (or an approval named) is
/// signed, in one account the launcher keeps sessions apart from each other
/// and not from other processes of the account, and an agent nobody launched
/// commits unsigned. It no longer says every name is "claimed by a process
/// in a shared account" (a process can't claim its way to a signature).
///
/// DELIBERATE EVAL CHANGE (P7/D1, 1 Nov 2026): plan step S8, group B.
#[test]
fn claimed_doctor_says_agents_names_are_claimed() {
    let mut w = World::new(&config_with(""));
    w.start_service();
    let mut cmd = w.cmd(Path::new(env!("CARGO_BIN_EXE_agent-sign")));
    cmd.arg("doctor");
    let out = run_within(cmd, "agent-sign doctor");
    let shown = all_output(&out);
    assert!(
        shown.contains("no launcher started it") && shown.contains("unsigned"),
        "doctor's output should say an agent no launcher started commits unsigned:\n{}",
        text(&out)
    );
    assert!(
        shown.contains("not from other processes of this account"),
        "doctor's output should say what the one-account launcher does not keep apart:\n{}",
        text(&out)
    );
    assert!(
        !shown.contains("claimed by a process in a shared account"),
        "doctor still says every agent name is claimed:\n{}",
        text(&out)
    );
}

// ---------------------------------------------------------------------------
// L4: install.sh run, not sourced, with the functions-only variable.
// ---------------------------------------------------------------------------

fn scripts_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts")
}

/// A command that runs with an empty environment plus `HOME` and the cleaned
/// PATH, and `AGENT_SIGN_INSTALL_FUNCTIONS_ONLY=1`.
fn functions_only_cmd(program: &str, home: &Path) -> Command {
    let mut cmd = Command::new(program);
    cmd.env_clear()
        .env("HOME", home)
        .env("PATH", cleaned_path())
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("AGENT_SIGN_INSTALL_FUNCTIONS_ONLY", "1")
        .stdin(Stdio::null());
    cmd
}

/// L4. The variable that makes the installer stop after its helper functions
/// is for sourcing them in tests. Executing the installer with it set is a
/// mistake (or a way to make an installer quietly do nothing and report
/// success): it must exit non-zero and say why on standard error, and
/// install nothing. Both ways of executing it: through `bash`, and directly
/// (when the script is executable).
///
/// Fails today because the script exits 0, silently.
#[test]
fn l4_executing_the_installer_with_the_functions_only_variable_is_an_error() {
    let installer = scripts_dir().join("install.sh");
    let mut ways = vec![("bash install.sh", false)];
    if fs::metadata(&installer).unwrap().permissions().mode() & 0o111 != 0 {
        ways.push(("./install.sh", true));
    }
    for (what, direct) in ways {
        let home = tempdir().unwrap();
        let cmd = if direct {
            functions_only_cmd(installer.to_str().unwrap(), home.path())
        } else {
            let mut cmd = functions_only_cmd("/bin/bash", home.path());
            cmd.arg(&installer);
            cmd
        };
        let out = run_within(cmd, what);
        assert!(
            !out.status.success(),
            "{what} with AGENT_SIGN_INSTALL_FUNCTIONS_ONLY=1 exited 0:\n{}",
            text(&out)
        );
        assert!(
            !stderr(&out).trim().is_empty(),
            "{what} with AGENT_SIGN_INSTALL_FUNCTIONS_ONLY=1 should say why on standard error:\n{}",
            text(&out)
        );
        assert!(
            !home.path().join(".agent-sign").exists(),
            "{what} installed something"
        );
    }
}

/// L4, REGRESSION GUARD (passes today; `test_launch_agent_real_git.rs`
/// relies on it). Sourcing the installer with the variable still stops
/// quietly before installing: the sourcing shell goes on, with status 0, no
/// message on standard error, and nothing created in HOME.
#[test]
fn l4_guard_sourcing_the_installer_with_the_functions_only_variable_stops_quietly() {
    let home = tempdir().unwrap();
    let mut cmd = functions_only_cmd("/bin/bash", home.path());
    cmd.arg("-c")
        .arg("source \"$1\"; echo AFTER-SOURCE")
        .arg("bash")
        .arg(scripts_dir().join("install.sh"));
    let out = run_within(cmd, "source install.sh");
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(stdout(&out).trim(), "AFTER-SOURCE", "{}", text(&out));
    assert_eq!(stderr(&out).trim(), "", "{}", text(&out));
    assert!(!home.path().join(".agent-sign").exists());
}

// ---------------------------------------------------------------------------
// L5: --launcher-unit warns about a PATH set through EnvironmentFile=.
// (Linux only, like the launcher-unit tests in test_install_servers.rs.)
// ---------------------------------------------------------------------------

/// The user manager's PATH as the `systemctl show-environment` stand-in
/// reports it. Deliberately unlike the PATH of the test itself.
const MANAGER_PATH: &str = "/opt/manager-bin:/usr/local/bin:/usr/bin:/bin";

fn write_executable(path: &Path, body: &str) {
    fs::write(path, body).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

/// The `systemctl` stand-in: logs every call, answers `show-environment`,
/// and answers questions about a unit from files in `~/stand-in-unit/`, as
/// the real command does:
///
/// - `Environment` holds the value of the unit's `Environment=` property
///   (space-separated `NAME=value`), empty when the unit sets none;
/// - `EnvironmentFiles` holds the value of its `EnvironmentFiles=` property
///   (`<file> (ignore_errors=no)`), one per line;
/// - `cat` holds what `systemctl --user cat <unit>` prints.
///
/// `show -p Environment` answers only the first, `show -p EnvironmentFiles`
/// only the second, `--value` gives the bare values, and without `-p` both.
/// So however the installer asks, it sees one consistent unit.
const SYSTEMCTL_STAND_IN: &str = r#"#!/bin/sh
d="$HOME/stand-in-calls"
mkdir -p "$d"
n=$(ls "$d" | grep -c '\.call$')
echo "systemctl $*" >> "$HOME/stand-ins.log"
echo "systemctl $*" > "$d/$n.call"
cp "$HOME/.agent-sign/config.toml" "$d/$n.config" 2>/dev/null
u="$HOME/stand-in-unit"
value=0
case " $* " in *" --value "*) value=1;; esac
case " $* " in
  *" show-environment "*) echo 'LANG=C'; echo 'PATH=@MANAGER_PATH@'; exit 0;;
  *" cat "*) [ -f "$u/cat" ] && cat "$u/cat"; exit 0;;
esac
case " $* " in
  *" show "*)
    rest=$(printf '%s' "$*" | sed 's/EnvironmentFiles//g')
    want_files=0; want_env=0
    case "$*" in *EnvironmentFiles*) want_files=1;; esac
    case "$rest" in *Environment*) want_env=1;; esac
    case "$*" in *" -p "*|*--property*|*-pEnvironment*) ;; *) want_files=1; want_env=1;; esac
    if [ "$want_env" = 1 ]; then
      v=$(cat "$u/Environment" 2>/dev/null)
      if [ "$value" = 1 ]; then echo "$v"; else echo "Environment=$v"; fi
    fi
    if [ "$want_files" = 1 ]; then
      if [ "$value" = 1 ]; then cat "$u/EnvironmentFiles" 2>/dev/null
      else sed 's/^/EnvironmentFiles=/' "$u/EnvironmentFiles" 2>/dev/null; fi
    fi
    exit 0;;
esac
exit 0
"#;

/// The installer's lab (copied from test_install_servers.rs): a fresh home,
/// a copy of `scripts/` with the test's own builds as its programs, and a
/// folder of stand-ins first on PATH.
struct Lab {
    _dir: TempDir,
    home: PathBuf,
    src: PathBuf,
    path: OsString,
    global_config: PathBuf,
}

impl Lab {
    fn new() -> Lab {
        let dir = tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let home = root.join("home");
        fs::create_dir_all(&home).unwrap();
        let global_config = home.join("user.gitconfig");
        fs::write(
            &global_config,
            "[user]\n\tname = Human Developer\n\temail = dev@example.com\n",
        )
        .unwrap();

        let src = root.join("installer/src");
        let scripts = src.join("scripts");
        fs::create_dir_all(&scripts).unwrap();
        for entry in fs::read_dir(scripts_dir()).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_file() {
                fs::copy(entry.path(), scripts.join(entry.file_name())).unwrap();
            }
        }
        // The test builds carry the test authenticator, which the real check
        // rightly refuses to install.
        fs::write(scripts.join("check-binary-clean.sh"), "#!/bin/sh\nexit 0\n").unwrap();
        fs::write(
            src.join("Cargo.toml"),
            "[package]\nname = \"installer-fixture\"\nversion = \"0.0.0\"\n",
        )
        .unwrap();
        let release = src.join("target/release");
        fs::create_dir_all(&release).unwrap();
        for (name, built) in [
            ("agent-signd", env!("CARGO_BIN_EXE_agent-signd")),
            ("agent-sign", env!("CARGO_BIN_EXE_agent-sign")),
            ("agent-ssh-sign", env!("CARGO_BIN_EXE_agent-ssh-sign")),
            ("agent-git", env!("CARGO_BIN_EXE_agent-git")),
        ] {
            fs::copy(built, release.join(name)).unwrap();
        }

        let fakebin = root.join("installer/fakebin");
        fs::create_dir_all(&fakebin).unwrap();
        for (name, status) in [
            ("loginctl", 0),
            ("codesign", 0),
            ("pkill", 1),
            ("pgrep", 1),
            ("curl", 1),
            ("cargo", 0),
        ] {
            write_executable(
                &fakebin.join(name),
                &format!(
                    "#!/bin/sh\necho \"{name} $*\" >> \"$HOME/stand-ins.log\"\nexit {status}\n"
                ),
            );
        }
        write_executable(
            &fakebin.join("systemctl"),
            &SYSTEMCTL_STAND_IN.replace("@MANAGER_PATH@", MANAGER_PATH),
        );
        write_executable(
            &fakebin.join("launchctl"),
            "#!/bin/sh\necho \"launchctl $*\" >> \"$HOME/stand-ins.log\"\nexit 0\n",
        );

        let mut path_dirs = vec![fakebin.clone()];
        path_dirs.extend(std::env::split_paths(&cleaned_path()));
        let path = std::env::join_paths(path_dirs).unwrap();

        // The real user systemd manager must be unreachable: systemctl is the
        // stand-in, and there is no runtime directory or bus in the env.
        let resolved = std::env::split_paths(&path)
            .map(|d| d.join("systemctl"))
            .find(|p| p.is_file())
            .unwrap();
        assert_eq!(resolved, fakebin.join("systemctl"));
        Lab {
            _dir: dir,
            home,
            src,
            path,
            global_config,
        }
    }

    fn cmd(&self, program: &str) -> Command {
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
            .env("TERM", "dumb")
            .current_dir(&self.src)
            .stdin(Stdio::null());
        cmd
    }

    fn install(&self, args: &[&str]) -> Output {
        let mut cmd = self.cmd("/bin/bash");
        cmd.arg(self.src.join("scripts/install.sh"))
            .arg("--yes")
            .args(args);
        run_within_for(cmd, "install.sh", Duration::from_secs(60))
    }

    /// Describes `unit` to the `systemctl` stand-in: its `Environment=`
    /// property value, and the environment files it names. Also writes the
    /// unit file where an installer that reads it from disk would look.
    fn describe_unit(&self, unit: &str, environment: &str, env_files: &[&Path]) {
        let d = self.home.join("stand-in-unit");
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join("Environment"), environment).unwrap();
        let files: String = env_files
            .iter()
            .map(|f| format!("{} (ignore_errors=no)\n", f.display()))
            .collect();
        fs::write(d.join("EnvironmentFiles"), &files).unwrap();
        let mut body = String::from("[Service]\nExecStart=/bin/true\n");
        for f in env_files {
            body.push_str(&format!("EnvironmentFile={}\n", f.display()));
        }
        if !environment.is_empty() {
            body.push_str(&format!("Environment={environment}\n"));
        }
        let unit_dir = self.home.join(".config/systemd/user");
        fs::create_dir_all(&unit_dir).unwrap();
        fs::write(unit_dir.join(unit), &body).unwrap();
        fs::write(
            d.join("cat"),
            format!("# {}\n{body}", unit_dir.join(unit).display()),
        )
        .unwrap();
    }

    fn drop_in(&self, unit: &str) -> PathBuf {
        self.home
            .join(".config/systemd/user")
            .join(format!("{unit}.d"))
            .join("agent-sign.conf")
    }

    /// The non-blank, non-comment lines of the drop-in for `unit`.
    fn drop_in_lines(&self, unit: &str) -> Vec<String> {
        let path = self.drop_in(unit);
        fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{} should exist: {e}", path.display()))
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with(';'))
            .map(str::to_string)
            .collect()
    }

    fn expected_drop_in(&self) -> Vec<String> {
        vec![
            "[Service]".to_string(),
            format!(
                "Environment=PATH={}/.agent-sign/bin:{MANAGER_PATH}",
                self.home.display()
            ),
        ]
    }
}

/// The lines of the installer's output that mention `unit` and `PATH` and
/// also one of `needles` (the unit's own PATH value, or its environment
/// file).
fn warning_lines<'a>(shown: &'a str, unit: &str, needles: &[&str]) -> Vec<&'a str> {
    shown
        .lines()
        .filter(|l| l.contains(unit) && l.contains("PATH") && needles.iter().any(|n| l.contains(n)))
        .collect()
}

/// L5. A launcher unit that sets its own PATH through `EnvironmentFile=` (not
/// only through `Environment=`) loses it to the drop-in just the same, so
/// `--launcher-unit` must warn before anyone restarts it: a line naming the
/// unit, PATH, and the file or the PATH value the file sets. The drop-in is
/// still written, exactly as before.
///
/// Fails today because the installer asks only for the unit's `Environment=`.
#[cfg(target_os = "linux")]
#[test]
fn l5_a_path_set_through_an_environment_file_is_warned_about() {
    let lab = Lab::new();
    let env_file = lab.home.join("foo-env");
    fs::write(&env_file, "OTHER=1\nPATH=/opt/own-bin:/usr/bin\n").unwrap();
    lab.describe_unit("foo.service", "", &[&env_file]);
    let out = lab.install(&["--launcher-unit", "foo.service"]);
    assert!(out.status.success(), "install: {}", text(&out));
    let shown = all_output(&out);
    let file = env_file.to_string_lossy().into_owned();
    assert!(
        !warning_lines(&shown, "foo.service", &[file.as_str(), "/opt/own-bin"]).is_empty(),
        "no warning that foo.service sets PATH through its EnvironmentFile (a line naming the \
         unit, PATH, and {file} or /opt/own-bin):\n{shown}"
    );
    assert_eq!(
        lab.drop_in_lines("foo.service"),
        lab.expected_drop_in(),
        "the drop-in should be written as before"
    );
}

/// L5, a control (passes today). A unit whose environment file sets nothing
/// to do with PATH gets no warning about it, and the same drop-in.
#[cfg(target_os = "linux")]
#[test]
fn l5_guard_an_environment_file_without_path_is_not_warned_about() {
    let lab = Lab::new();
    let env_file = lab.home.join("foo-env");
    fs::write(&env_file, "OTHER=1\n# PATH is not set here\n").unwrap();
    lab.describe_unit("foo.service", "", &[&env_file]);
    let out = lab.install(&["--launcher-unit", "foo.service"]);
    assert!(out.status.success(), "install: {}", text(&out));
    let shown = all_output(&out);
    let file = env_file.to_string_lossy().into_owned();
    assert!(
        !shown.contains(&file),
        "the unit's environment file sets no PATH, so it shouldn't be mentioned:\n{shown}"
    );
    assert_eq!(lab.drop_in_lines("foo.service"), lab.expected_drop_in());
}

/// L5, REGRESSION GUARD (passes today). The warning for a PATH set through
/// `Environment=` stays.
#[cfg(target_os = "linux")]
#[test]
fn l5_guard_a_path_set_through_environment_is_still_warned_about() {
    let lab = Lab::new();
    lab.describe_unit("foo.service", "LANG=C PATH=/opt/own-env-bin:/bin", &[]);
    let out = lab.install(&["--launcher-unit", "foo.service"]);
    assert!(out.status.success(), "install: {}", text(&out));
    let shown = all_output(&out);
    assert!(
        !warning_lines(&shown, "foo.service", &["/opt/own-env-bin"]).is_empty(),
        "no warning that foo.service sets its own PATH:\n{shown}"
    );
    assert_eq!(lab.drop_in_lines("foo.service"), lab.expected_drop_in());
}
