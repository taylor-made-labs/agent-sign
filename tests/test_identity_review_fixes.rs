//! Regression tests for the review of the per-agent identity change (28 Oct
//! 2026). Two independent reviewers confirmed nine findings with isolated
//! reproductions; each test below reproduces one of them and was run against
//! the code before its fix, where it failed (the record of which failed, and
//! how, is in `docs/ADVERSARIAL_REVIEW.md`). Each group is one finding:
//!
//! 1. A repository's `.agent-sign.toml` could set any table, and so put the
//!    person's (or anyone's) name on agent commits that carry a Good agent
//!    signature. It may now only tighten `[security]` rules; and an
//!    identified agent's signed commit is always authored (new commits) and
//!    committed by its identity, whatever the attribution mode.
//! 2. An identified agent's commit that declines signing carried the
//!    person's global name and email.
//! 3. Run tokens signed anything for ten minutes: `rebase feature main`,
//!    and `rebase --exec 'cd /other && git commit'`, made agent-signed
//!    commits on `main` and in other repositories.
//! 4. A `config.toml` that can't be read, or a misspelt or misplaced key,
//!    silently became the defaults.
//! 5. An unmarked commit with no terminal was signed as an "unidentified
//!    agent"; now it is unsigned, under git's own names, and never fails for
//!    want of the service.
//! 6. The certificate authority signed any principal `check()` let through
//!    (`codex.admin@agents.local`, `---.a@agents.local`).
//! 7. Run tokens skipped the rate limit; session keys were never evicted;
//!    a repository named by a link had its own lease and rate window.
//! 8. A leaked `AGENT_EVENT_TOKEN` made the person's terminal commit sign as
//!    the agent.
//! 9. A branch named `MAIN` slipped past main protection.
//!
//! Isolation is the same as `test_per_agent_identity.rs`, whose harness this
//! file follows: every process starts from an empty environment plus a
//! temporary HOME, a temporary global git config, no system config, a PATH
//! without agent-sign's installed `bin`, and a socket inside the temporary
//! directory. The person's signer is a fake that logs one line per call and
//! exits 1. Every wrapper run, and every service start, is bounded in time.

use std::ffi::OsString;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use base64::Engine;
use sha2::{Digest, Sha256};
use tempfile::{TempDir, tempdir};

use agent_sign::attribution::{AgentIdentity, identify_agent_with};
use agent_sign::lease::{LeaseEngine, LeasePolicy};
use agent_sign::protocol::{Request, Response, send_request};

const PERSON_NAME: &str = "Human Developer";
const PERSON_EMAIL: &str = "dev@example.com";

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

const SESSION: &str = "review-fixes-session";
const CLAUDE: &[(&str, &str)] = &[("CLAUDECODE", "1"), ("CLAUDE_CODE_SESSION_ID", SESSION)];

/// `Claude Code <claude-code.<session8>@agents.local>`, as git shows it.
fn claude_ident() -> String {
    format!(
        "Claude Code <claude-code.{}@agents.local>",
        session8(SESSION)
    )
}

fn claude_principal() -> String {
    format!("claude-code.{}@agents.local", session8(SESSION))
}

fn claude_identity() -> AgentIdentity {
    AgentIdentity {
        slug: "claude-code".into(),
        name: "Claude Code".into(),
        principal: claude_principal(),
    }
}

type Marks<'a> = &'a [(&'a str, &'a str)];
const UNMARKED: Marks = &[];

// ---------------------------------------------------------------------------
// The isolated world.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq)]
enum PersonSigner {
    /// `gpg.ssh.program` is the fake signer.
    Fake,
    /// `gpg.ssh.program` is agent-sign's signing program, whose
    /// `fallback_program` is the fake signer.
    ThroughAgentSshSign,
}

struct World {
    _dir: TempDir,
    home: PathBuf,
    global_config: PathBuf,
    path: OsString,
    real_git: PathBuf,
    ssh_keygen: PathBuf,
    socket: PathBuf,
    signer_log: PathBuf,
    auth_log: PathBuf,
    service: Option<Child>,
}

impl Drop for World {
    fn drop(&mut self) {
        if let Some(mut child) = self.service.take() {
            let _ = child.kill();
            let _ = child.wait();
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
    /// A world whose `~/.agent-sign/config.toml` is `config` (plus the
    /// fallback program for [`PersonSigner::ThroughAgentSshSign`]), with the
    /// test service started with `--auto-approve` when `service` is true.
    fn new(signer: PersonSigner, config: &str, service: bool) -> World {
        let dir = tempdir().unwrap();
        let home = dir.path().to_path_buf();
        let path = cleaned_path();
        let real_git = find_on(&path, "git");
        let ssh_keygen = find_on(&path, "ssh-keygen");
        let mut world = World {
            global_config: home.join("person.gitconfig"),
            socket: home.join("agent-sign-test.sock"),
            signer_log: home.join("person-signer.log"),
            auth_log: home.join("owner-prompts.log"),
            home,
            path,
            real_git,
            ssh_keygen,
            service: None,
            _dir: dir,
        };
        world.write_person_setup(signer, config);
        if service {
            world.start_service(&["--auto-approve"]);
        }
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

    fn fake_signer(&self) -> PathBuf {
        self.home.join("person-signer.sh")
    }

    fn config_path(&self) -> PathBuf {
        self.home.join(".agent-sign/config.toml")
    }

    fn write_person_setup(&self, signer: PersonSigner, config: &str) {
        let key = self.home.join("person_key");
        let out = self
            .cmd(&self.ssh_keygen)
            .args(["-q", "-t", "ed25519", "-N", "", "-C", "person", "-f"])
            .arg(&key)
            .output()
            .unwrap();
        assert!(out.status.success(), "ssh-keygen: {}", text(&out));

        let fake = self.fake_signer();
        fs::write(
            &fake,
            format!(
                "#!/bin/sh\necho \"called: $*\" >> '{}'\nexit 1\n",
                self.signer_log.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&fake, fs::Permissions::from_mode(0o755)).unwrap();

        let mut agent_sign_config = config.to_string();
        let program = match signer {
            PersonSigner::Fake => fake.clone(),
            PersonSigner::ThroughAgentSshSign => {
                agent_sign_config.push_str(&format!(
                    "\n[ssh]\nfallback_program = \"{}\"\n",
                    fake.display()
                ));
                PathBuf::from(env!("CARGO_BIN_EXE_agent-ssh-sign"))
            }
        };
        let state = self.home.join(".agent-sign");
        fs::create_dir_all(&state).unwrap();
        fs::write(self.config_path(), agent_sign_config).unwrap();

        fs::write(
            &self.global_config,
            format!(
                "[user]\n\tname = {PERSON_NAME}\n\temail = {PERSON_EMAIL}\n\tsigningkey = \"{}.pub\"\n\
                 [commit]\n\tgpgsign = true\n[gpg]\n\tformat = ssh\n[gpg \"ssh\"]\n\tprogram = \"{}\"\n",
                key.display(),
                program.display()
            ),
        )
        .unwrap();
    }

    fn service_log(&self) -> String {
        fs::read_to_string(self.home.join("service.log")).unwrap_or_default()
    }

    fn service_command(&self, args: &[&str]) -> Command {
        let log = fs::File::create(self.home.join("service.log")).unwrap();
        let mut cmd = self.cmd(Path::new(env!("CARGO_BIN_EXE_agent-signd")));
        cmd.arg("--socket")
            .arg(&self.socket)
            .args(args)
            .env("AGENT_SIGN_TEST_AUTH", "fail")
            .env("AGENT_SIGN_TEST_AUTH_LOG", &self.auth_log)
            .env("AGENT_SIGN_REFUSAL_BACKOFF", "none")
            .stdout(Stdio::null())
            .stderr(Stdio::from(log));
        cmd
    }

    fn start_service(&mut self, args: &[&str]) {
        self.service = Some(self.service_command(args).spawn().unwrap());
        let start = Instant::now();
        while !self.socket.exists() {
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "test service didn't start: {}",
                self.service_log()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Starts the service and waits up to 10 seconds for it either to stop
    /// (`Some(status)`) or to open its socket (`None`, and it is stopped).
    fn service_stops_at_start(&self) -> Option<std::process::ExitStatus> {
        let mut child = self.service_command(&[]).spawn().unwrap();
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
    fn agent(&self, repo: &Path, marks: Marks, args: &[&str]) -> Output {
        let mut cmd = self.cmd(Path::new(env!("CARGO_BIN_EXE_agent-git")));
        for (k, v) in marks {
            cmd.env(k, v);
        }
        cmd.args(args).current_dir(repo);
        run_within(cmd, &format!("agent git {args:?} with {marks:?}"))
    }

    /// The wrapper in a real terminal (`script`), unmarked: the person.
    #[cfg(target_os = "macos")]
    fn person_in_terminal(&self, repo: &Path, env: Marks, args: &[&str]) -> Output {
        let mut cmd = self.cmd(Path::new("/usr/bin/script"));
        cmd.args(["-q", "/dev/null", env!("CARGO_BIN_EXE_agent-git")])
            .args(args)
            .env("TERM", "dumb")
            .current_dir(repo);
        for (k, v) in env {
            cmd.env(k, v);
        }
        run_within(cmd, &format!("person's git {args:?} in a terminal"))
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
    /// branched from base (f1), `branch` checked out.
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

    /// Writes `path` (relative to the repository) and stages it.
    fn stage(&self, repo: &Path, path: &str, content: &str) {
        let file = repo.join(path);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(&file, content).unwrap();
        self.git_ok(repo, &["add", path]);
    }

    fn agent_commit(&self, repo: &Path, marks: Marks, file: &str) -> Output {
        self.stage(repo, file, &format!("{file}\n"));
        self.agent(repo, marks, &["commit", "-m", &format!("feat: {file}")])
    }

    fn rev(&self, repo: &Path, rev: &str) -> String {
        self.git_ok(repo, &["rev-parse", rev])
    }

    fn author_and_committer(&self, repo: &Path, rev: &str) -> (String, String) {
        let both = self.git_ok(repo, &["log", "-1", "--format=%an <%ae>%x1f%cn <%ce>", rev]);
        let (a, c) = both.split_once('\x1f').unwrap();
        (a.to_string(), c.to_string())
    }

    /// `(%G?, %GS)` for `rev`, checked by plain ssh-keygen against the
    /// agents' trust line (or against nobody, before the authority exists).
    fn signature(&self, repo: &Path, rev: &str) -> (String, String) {
        let ca = self.home.join(".agent-sign/keys/agents_ca_ed25519.pub");
        let line = fs::read_to_string(&ca)
            .map(|k| {
                format!(
                    "*@agents.local cert-authority,namespaces=\"git\" {}\n",
                    k.trim()
                )
            })
            .unwrap_or_default();
        let allowed = self.home.join("agents_allowed_signers");
        fs::write(&allowed, line).unwrap();
        let program = format!("gpg.ssh.program={}", self.ssh_keygen.display());
        let file = format!("gpg.ssh.allowedSignersFile={}", allowed.display());
        let out = self.git(
            repo,
            &[
                "-c",
                &program,
                "-c",
                &file,
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

    /// The canonical path of `repo`, as the wrapper and the service name it.
    fn canonical(&self, repo: &Path) -> String {
        fs::canonicalize(repo)
            .unwrap()
            .to_string_lossy()
            .into_owned()
    }

    /// Sends `request` to the test service.
    fn ask(&self, request: &Request) -> Response {
        send_request(&self.socket, request).expect("the test service answers")
    }

    /// Sends one raw JSON request line to the test service and reads the
    /// answer, for requests whose shape this change extends (a `SignCommit`
    /// that names its repository and branch).
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
        let granted = self.ask(&Request::RequestLease {
            repo: repo.to_string(),
            branch: branch.to_string(),
            intent: "test".into(),
            duration_secs: None,
        });
        assert!(
            matches!(granted, Response::LeaseGranted { .. }),
            "lease for {repo} {branch}: {granted:?}"
        );
    }

    fn token(&self, request: Request) -> String {
        match self.ask(&request) {
            Response::TokenIssued { token } => token,
            other => panic!("no token for {request:?}: {other:?}"),
        }
    }

    /// `SignCommit` with the repository and branch the signing program
    /// reports.
    fn sign(&self, token: &str, repo: &str, branch: &str) -> Response {
        // Real object/header fixture independent of the candidate validator:
        // it changes no paths, retaining this test's original token assertions.
        let tree = self.git_ok(Path::new(repo), &["rev-parse", "HEAD^{tree}"]);
        let parent = self.git_ok(Path::new(repo), &["rev-parse", "HEAD"]);
        let buffer = format!(
            "tree {}\nparent {}\nauthor Fixture <fixture@example.invalid> 1700000000 +0000\ncommitter Fixture <fixture@example.invalid> 1700000000 +0000\n\ntest: token fixture\n",
            tree.trim(),
            parent.trim()
        );
        self.ask_raw(serde_json::json!({
            "type": "SignCommit",
            "payload": {
                "token": token,
                "buffer_b64": base64::engine::general_purpose::STANDARD.encode(buffer.as_bytes()),
                "repo": repo,
                "branch": branch,
            }
        }))
    }
}

fn assert_ok(w: &World, out: &Output, what: &str) {
    assert!(
        out.status.success(),
        "{what} failed (person's signer calls: {}):\n{}\nservice log:\n{}",
        w.signer_calls(),
        text(out),
        w.service_log()
    );
}

fn assert_no_person_signer(w: &World, what: &str) {
    assert_eq!(
        w.signer_calls(),
        0,
        "{what}: the person's signer was called (log: {:?})",
        fs::read_to_string(&w.signer_log).unwrap_or_default()
    );
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

// ---------------------------------------------------------------------------
// 1. A repository's file only tightens [security]; agent commits are always
//    the agent's.
// ---------------------------------------------------------------------------

#[test]
fn f1_a_repository_file_cant_put_another_name_on_agent_commits() {
    let w = World::new(PersonSigner::Fake, "", true);
    let repo = w.repo();
    fs::write(
        repo.join(".agent-sign.toml"),
        "[attribution]\nmode = \"split\"\n\n[human]\nname = \"Repo Person\"\nemail = \"repo.person@example.com\"\n\n\
         [agent]\nname = \"Repo Agent\"\nemail = \"repo.agent@example.com\"\n",
    )
    .unwrap();
    let out = w.agent_commit(&repo, CLAUDE, "agent.txt");
    assert_ok(&w, &out, "agent commit in a repository with a hostile file");
    assert_eq!(
        w.author_and_committer(&repo, "HEAD"),
        (claude_ident(), claude_ident()),
        "a repository's file changed who an agent commit is attributed to"
    );
    assert_eq!(w.signature(&repo, "HEAD"), ("G".into(), claude_principal()));
    let err = stderr(&out);
    let warnings: Vec<&str> = err.lines().filter(|l| l.contains("ignored")).collect();
    assert_eq!(
        warnings.len(),
        1,
        "one warning line should name what was ignored:\n{}",
        text(&out)
    );
    for named in ["attribution", "human", "agent"] {
        assert!(
            warnings[0].contains(named),
            "the warning should name [{named}]: {}",
            warnings[0]
        );
    }
}

#[test]
fn f1_every_attribution_mode_commits_as_the_agent() {
    for mode in ["split", "trailers", "alias"] {
        let w = World::new(
            PersonSigner::Fake,
            &format!("[attribution]\nmode = \"{mode}\"\n"),
            true,
        );
        let repo = w.repo();
        let out = w.agent_commit(&repo, CLAUDE, "agent.txt");
        assert_ok(&w, &out, mode);
        assert_eq!(
            w.author_and_committer(&repo, "HEAD"),
            (claude_ident(), claude_ident()),
            "mode = {mode:?} put another name on an agent's signed commit"
        );
    }
}

#[test]
fn f1_a_repository_file_adds_forbidden_paths_but_cant_remove_them() {
    let w = World::new(PersonSigner::Fake, "", true);
    let repo = w.repo();
    fs::write(
        repo.join(".agent-sign.toml"),
        "[security]\nforbidden_paths = [\"secret/*\"]\n",
    )
    .unwrap();
    let before = w.rev(&repo, "HEAD");
    w.stage(&repo, ".github/workflows/ci.yml", "on: push\n");
    let out = w.agent(&repo, CLAUDE, &["commit", "-m", "ci: change"]);
    assert!(
        !out.status.success(),
        "the repository's forbidden_paths replaced the person's, so a CI workflow change went in:\n{}",
        text(&out)
    );
    w.git_ok(&repo, &["reset", "-q"]);
    fs::remove_dir_all(repo.join(".github")).unwrap();
    w.stage(&repo, "secret/x.txt", "x\n");
    let out = w.agent(&repo, CLAUDE, &["commit", "-m", "feat: secret"]);
    assert!(
        !out.status.success(),
        "the repository's own forbidden path wasn't applied:\n{}",
        text(&out)
    );
    assert_eq!(w.rev(&repo, "HEAD"), before);
}

#[test]
fn f1_a_repository_file_cant_raise_max_diff_lines() {
    let w = World::new(PersonSigner::Fake, "[security]\nmax_diff_lines = 5\n", true);
    let repo = w.repo();
    fs::write(
        repo.join(".agent-sign.toml"),
        "[security]\nmax_diff_lines = 100000\n",
    )
    .unwrap();
    let before = w.rev(&repo, "HEAD");
    w.stage(&repo, "big.txt", &"line\n".repeat(20));
    let out = w.agent(&repo, CLAUDE, &["commit", "-m", "feat: big"]);
    assert!(
        !out.status.success(),
        "a repository's file raised the person's max_diff_lines:\n{}",
        text(&out)
    );
    assert_eq!(w.rev(&repo, "HEAD"), before);
}

#[test]
fn f1_a_repository_file_can_block_more_branches() {
    let w = World::new(PersonSigner::Fake, "", true);
    let repo = w.repo();
    fs::write(
        repo.join(".agent-sign.toml"),
        "[security]\nblock_branches = [\"work\"]\n",
    )
    .unwrap();
    let before = w.rev(&repo, "HEAD");
    let out = w.agent_commit(&repo, CLAUDE, "agent.txt");
    assert!(
        !out.status.success(),
        "a branch the repository's file protects took an agent commit:\n{}",
        text(&out)
    );
    assert_eq!(w.rev(&repo, "HEAD"), before);
}

// ---------------------------------------------------------------------------
// 2. An identified agent's unsigned commit carries its identity, unless the
//    repository sets its own user.
// ---------------------------------------------------------------------------

#[test]
fn f2_an_identified_agents_unsigned_commit_is_attributed_to_it() {
    let w = World::new(PersonSigner::Fake, "", true);
    let repo = w.repo();
    w.stage(&repo, "a.txt", "a\n");
    let out = w.agent(&repo, CLAUDE, &["commit", "--no-gpg-sign", "-m", "a"]);
    assert_ok(&w, &out, "commit --no-gpg-sign");
    assert_eq!(
        w.author_and_committer(&repo, "HEAD"),
        (claude_ident(), claude_ident()),
        "an identified agent's unsigned commit carried the person's global name"
    );
    assert_eq!(w.signature(&repo, "HEAD").0, "N");

    // commit.gpgsign = false in the repository: the same.
    w.git_ok(&repo, &["config", "commit.gpgsign", "false"]);
    w.stage(&repo, "b.txt", "b\n");
    let out = w.agent(&repo, CLAUDE, &["commit", "-m", "b"]);
    assert_ok(
        &w,
        &out,
        "commit in a repository with commit.gpgsign = false",
    );
    assert_eq!(
        w.author_and_committer(&repo, "HEAD"),
        (claude_ident(), claude_ident())
    );
    assert_no_person_signer(&w, "unsigned agent commits");
}

#[test]
fn f2_a_fixture_with_its_own_user_keeps_its_names() {
    let w = World::new(PersonSigner::Fake, "", true);
    let repo = w.repo();
    w.git_ok(&repo, &["config", "user.name", "Fixture"]);
    w.git_ok(&repo, &["config", "user.email", "fixture@example.com"]);
    w.stage(&repo, "a.txt", "a\n");
    let out = w.agent(&repo, CLAUDE, &["commit", "--no-gpg-sign", "-m", "a"]);
    assert_ok(&w, &out, "fixture commit");
    let fixture = "Fixture <fixture@example.com>".to_string();
    assert_eq!(
        w.author_and_committer(&repo, "HEAD"),
        (fixture.clone(), fixture)
    );
}

// ---------------------------------------------------------------------------
// 3. A token signs only for its own repository and branch.
// ---------------------------------------------------------------------------

#[test]
fn f3_rebasing_main_from_another_branch_makes_no_agent_commit_on_main() {
    let w = World::new(PersonSigner::Fake, "", true);
    let repo = w.repo_named("repo", "main");
    w.git_ok(&repo, &["checkout", "-q", "feature"]);
    let main_before = w.rev(&repo, "main");
    // From `feature`, rebase `main` onto it: git checks out main and replays
    // its commits there.
    let _ = w.agent(&repo, CLAUDE, &["rebase", "feature", "main"]);
    assert_eq!(
        w.rev(&repo, "main"),
        main_before,
        "an agent's rebase rewrote main with commits signed as the agent: {:?}",
        w.signature(&repo, "main")
    );
    assert_no_person_signer(&w, "rebase onto main");
}

#[test]
fn f3_a_run_token_signs_nothing_in_another_repository() {
    let w = World::new(PersonSigner::Fake, "", true);
    let repo = w.repo();
    let other = w.repo_named("other", "side");
    let other_before = w.rev(&other, "HEAD");
    let exec = format!(
        "cd '{}' && git commit -q --allow-empty -m injected",
        other.display()
    );
    let _ = w.agent(&repo, CLAUDE, &["rebase", "--exec", &exec, "HEAD~1"]);
    assert_eq!(
        w.rev(&other, "HEAD"),
        other_before,
        "a run token signed a commit in another repository: {:?}",
        w.signature(&other, "HEAD")
    );
}

#[test]
fn f3_a_commit_token_signs_only_for_its_repository_and_branch() {
    let w = World::new(PersonSigner::Fake, "", true);
    let repo = w.repo();
    let other = w.repo_named("other", "side");
    let (repo, other) = (w.canonical(&repo), w.canonical(&other));
    w.lease(&repo, "work");
    for (to_repo, to_branch) in [(&other, "work"), (&repo, "feature")] {
        let token = w.token(Request::IssueIdentifiedToken {
            repo: repo.clone(),
            branch: "work".into(),
            identity: claude_identity(),
        });
        let answer = w.sign(&token, to_repo, to_branch);
        assert!(
            matches!(answer, Response::Error { .. }),
            "a token for {repo} on work signed for {to_repo} on {to_branch}: {answer:?}"
        );
    }
    let token = w.token(Request::IssueIdentifiedToken {
        repo: repo.clone(),
        branch: "work".into(),
        identity: claude_identity(),
    });
    let answer = w.sign(&token, &repo, "work");
    assert!(
        matches!(answer, Response::Signed { .. }),
        "the token's own repository and branch: {answer:?}"
    );
}

// ---------------------------------------------------------------------------
// 4. A config that can't be read stops the service.
// ---------------------------------------------------------------------------

fn assert_service_refuses(w: &World, what: &str, names: &[&str]) {
    let stopped = w.service_stops_at_start();
    assert!(
        stopped.is_some_and(|s| !s.success()),
        "{what}: the service started (or didn't fail): {stopped:?}\n{}",
        w.service_log()
    );
    let log = w.service_log();
    for name in names {
        assert!(
            log.contains(name),
            "{what}: the message should name {name:?}:\n{log}"
        );
    }
}

#[test]
fn f4_an_unreadable_config_stops_the_service() {
    let w = World::new(
        PersonSigner::Fake,
        "[security]\napproval = \"device-owner\"\n",
        false,
    );
    fs::set_permissions(w.config_path(), fs::Permissions::from_mode(0o000)).unwrap();
    // Running as root would read it anyway; then there is nothing to test.
    if fs::read_to_string(w.config_path()).is_ok() {
        return;
    }
    assert_service_refuses(
        &w,
        "a config.toml without read permission",
        &["config.toml"],
    );
}

#[test]
fn f4_a_config_that_is_a_directory_or_a_dangling_link_stops_the_service() {
    let w = World::new(PersonSigner::Fake, "", false);
    fs::remove_file(w.config_path()).unwrap();
    fs::create_dir(w.config_path()).unwrap();
    assert_service_refuses(&w, "a config.toml that is a directory", &["config.toml"]);
    fs::remove_dir(w.config_path()).unwrap();
    std::os::unix::fs::symlink(w.home.join("nowhere.toml"), w.config_path()).unwrap();
    assert_service_refuses(
        &w,
        "a config.toml that is a dangling link",
        &["config.toml"],
    );
}

#[test]
fn f4_an_unknown_or_misplaced_key_stops_the_service() {
    for (config, key) in [
        ("[security]\napprovl = \"device-owner\"\n", "approvl"),
        ("approval = \"device-owner\"\n", "approval"),
        ("[attribution]\napproval = \"device-owner\"\n", "approval"),
        ("[securty]\napproval = \"device-owner\"\n", "securty"),
    ] {
        let w = World::new(PersonSigner::Fake, config, false);
        assert_service_refuses(&w, &format!("config {config:?}"), &["config.toml", key]);
    }
}

/// Every key any version of `scripts/install.sh` has written (read from
/// `git log -p -- scripts/install.sh`), with the values it wrote, so an
/// existing install keeps starting.
const EVERY_INSTALLER_KEY: &str = r#"
[security]
approval = "none"
lease_mode = "identity"
lease_scope = "branch"
allow_branch_switching = false
default_lease_duration = "2h"
max_lease_ceiling = "24h"
end_after_idle = "7d"
auto_revoke_on_branch_delete = true
allow_main_branch = false
block_branches = ["main", "master"]
max_commits_per_minute = 10
auto_approve = false

[attribution]
mode = "split"

[agent]
name = "Agent"
email = "agent@local.internal"

[human]
name = "Human Developer"
email = "dev@example.com"

[ssh]
fallback_program = "/usr/bin/ssh-keygen"
"#;

#[test]
fn f4_a_config_any_installer_wrote_still_starts_the_service() {
    let w = World::new(PersonSigner::Fake, EVERY_INSTALLER_KEY, false);
    assert_eq!(
        w.service_stops_at_start(),
        None,
        "a config an installer wrote stopped the service:\n{}",
        w.service_log()
    );
}

#[test]
fn f4_the_service_logs_its_approval_mode_at_start() {
    let mut w = World::new(PersonSigner::Fake, "", false);
    w.start_service(&[]);
    assert!(
        w.service_log().contains("approval = \"none\""),
        "the start-up log should say the approval mode:\n{}",
        w.service_log()
    );
    let mut w = World::new(
        PersonSigner::Fake,
        "[security]\napproval = \"device-owner\"\n",
        false,
    );
    w.start_service(&[]);
    assert!(
        w.service_log().contains("approval = \"device-owner\""),
        "the start-up log should say the approval mode:\n{}",
        w.service_log()
    );
}

// ---------------------------------------------------------------------------
// 5. An unmarked commit with no terminal is git's own, and never fails.
// ---------------------------------------------------------------------------

#[test]
fn f5_an_unmarked_commit_needs_no_service_and_is_gits_own() {
    // No service at all: the person's editor commits anyway.
    let w = World::new(PersonSigner::Fake, "", false);
    let repo = w.repo();
    let out = w.agent_commit(&repo, UNMARKED, "editor.txt");
    assert_ok(&w, &out, "unmarked commit with no service running");
    let gits_own = format!("{PERSON_NAME} <{PERSON_EMAIL}>");
    assert_eq!(
        w.author_and_committer(&repo, "HEAD"),
        (gits_own.clone(), gits_own)
    );
    assert_eq!(w.signature(&repo, "HEAD").0, "N");
    assert_no_person_signer(&w, "unmarked commit");
}

// ---------------------------------------------------------------------------
// 6. Only well-formed principals.
// ---------------------------------------------------------------------------

fn ident(slug: &str, principal: &str) -> AgentIdentity {
    AgentIdentity {
        slug: slug.into(),
        name: "Some Agent".into(),
        principal: principal.into(),
    }
}

#[test]
fn f6_check_refuses_principals_that_dont_look_like_sessions() {
    for (slug, principal) in [
        ("codex", "codex.admin@agents.local"),
        ("---", "---.a@agents.local"),
        ("codex", "codex.1A2B3C4D@agents.local"),
        ("codex", "codex.1a2b3c4@agents.local"),
        ("codex", "codex.1a2b3c4d5@agents.local"),
        ("codex", "codex.unidentified@agents.local"),
        ("-codex", "-codex.1a2b3c4d@agents.local"),
        ("codex-", "codex-.1a2b3c4d@agents.local"),
        ("my--bot", "my--bot.1a2b3c4d@agents.local"),
    ] {
        assert!(
            ident(slug, principal).check().is_err(),
            "check() let {principal:?} (slug {slug:?}) through"
        );
    }
    for (slug, principal) in [
        ("codex", "codex.1a2b3c4d@agents.local"),
        ("gemini-cli", "gemini-cli.nosession@agents.local"),
        ("my-bot-2", "my-bot-2.00000000@agents.local"),
    ] {
        assert!(
            ident(slug, principal).check().is_ok(),
            "check() refused the well-formed {principal:?}"
        );
    }
}

#[test]
fn f6_an_explicit_name_gets_a_slug_check_accepts() {
    let id = identify_agent_with(|k| {
        (k == "AGENT_SIGN_AGENT_NAME").then(|| "  My  Bot! (beta) ".to_string())
    })
    .unwrap();
    assert_eq!(id.slug, "my-bot-beta");
    assert!(id.check().is_ok(), "{id:?}: {:?}", id.check());
}

// ---------------------------------------------------------------------------
// 7. Rate limits for runs, a bounded set of session keys, canonical paths.
// ---------------------------------------------------------------------------

// Changed 28 Oct, after the live check on the server: counting every
// signature a git run made let a rebase of more commits than the limit fail
// halfway (the server's check hit it at 10). A git run counts once, however
// many commits it signs; separate runs still hit the limit.
#[test]
fn f7_a_git_run_counts_once_against_the_rate_limit_however_many_commits_it_signs() {
    let w = World::new(
        PersonSigner::Fake,
        "[security]\nmax_commits_per_minute = 3\n",
        true,
    );
    let repo = w.canonical(&w.repo());
    w.lease(&repo, "work");
    let run = || {
        w.token(Request::IssueRunToken {
            repo: repo.clone(),
            branch: "work".into(),
            identity: claude_identity(),
        })
    };
    // One run (a rebase, say) signs 4 commits: all go through.
    let token = run();
    for i in 0..4 {
        let answer = w.sign(&token, &repo, "work");
        assert!(
            matches!(answer, Response::Signed { .. }),
            "signature {i} of one run: {answer:?}"
        );
    }
    // That run counted once, so two more runs fit in the minute...
    run();
    run();
    // ...and a fourth separate run doesn't.
    let fourth = w.ask(&Request::IssueRunToken {
        repo: repo.clone(),
        branch: "work".into(),
        identity: claude_identity(),
    });
    match fourth {
        Response::Error { message } => assert!(
            message.to_lowercase().contains("rate") || message.contains("per minute"),
            "the refusal should say it's the rate limit: {message}"
        ),
        other => panic!("a fourth run in the minute went past max_commits_per_minute: {other:?}"),
    }
}

/// The public key blob inside an armored SSHSIG: the session's certificate.
fn sshsig_public_key(armored: &str) -> Vec<u8> {
    let body: String = armored
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect();
    let raw = base64::engine::general_purpose::STANDARD
        .decode(body)
        .unwrap();
    assert_eq!(&raw[..6], b"SSHSIG");
    let len = u32::from_be_bytes(raw[10..14].try_into().unwrap()) as usize;
    raw[14..14 + len].to_vec()
}

#[test]
fn f7_session_keys_are_capped_least_recently_used_first() {
    let w = World::new(
        PersonSigner::Fake,
        "[security]\nmax_commits_per_minute = 1000000\n",
        true,
    );
    let repo = w.canonical(&w.repo());
    w.lease(&repo, "work");
    let sign_as = |identity: AgentIdentity| -> Vec<u8> {
        let token = w.token(Request::IssueIdentifiedToken {
            repo: repo.clone(),
            branch: "work".into(),
            identity,
        });
        match w.sign(&token, &repo, "work") {
            Response::Signed { signature_pem } => sshsig_public_key(&signature_pem),
            other => panic!("not signed: {other:?}"),
        }
    };
    let first = sign_as(AgentIdentity::new("codex", "Codex", Some("first")));
    assert_eq!(
        first,
        sign_as(AgentIdentity::new("codex", "Codex", Some("first"))),
        "the same session should keep its key while it's in use"
    );
    for i in 0..1024 {
        sign_as(AgentIdentity::new("codex", "Codex", Some(&format!("s{i}"))));
    }
    assert_ne!(
        first,
        sign_as(AgentIdentity::new("codex", "Codex", Some("first"))),
        "1024 newer sessions should have evicted the least recently used key"
    );
}

#[test]
fn f7_a_repository_named_by_a_link_shares_its_lease_and_rate_window() {
    let w = World::new(
        PersonSigner::Fake,
        "[security]\nmax_commits_per_minute = 2\n",
        true,
    );
    let repo = w.repo();
    let link = w.home.join("repo-link");
    std::os::unix::fs::symlink(&repo, &link).unwrap();
    let (real, link) = (w.canonical(&repo), link.to_string_lossy().into_owned());
    w.lease(&real, "work");
    let issue = |r: &str| {
        w.ask(&Request::IssueIdentifiedToken {
            repo: r.to_string(),
            branch: "work".into(),
            identity: claude_identity(),
        })
    };
    let via_link = issue(&link);
    assert!(
        matches!(via_link, Response::TokenIssued { .. }),
        "the lease didn't cover its own repository named by a link: {via_link:?}"
    );
    assert!(matches!(issue(&real), Response::TokenIssued { .. }));
    assert!(
        matches!(issue(&link), Response::Error { .. }),
        "a link gave the repository a second rate window"
    );
}

// ---------------------------------------------------------------------------
// 8. A leaked token never signs the person's commit.
// ---------------------------------------------------------------------------

/// A valid single-use commit token for `repo` on `work`, as one could leak
/// from an agent's environment.
fn leaked_token(w: &World, repo: &Path) -> String {
    let repo = w.canonical(repo);
    w.lease(&repo, "work");
    w.token(Request::IssueIdentifiedToken {
        repo,
        branch: "work".into(),
        identity: claude_identity(),
    })
}

#[cfg(target_os = "macos")]
#[test]
fn f8_a_leaked_token_doesnt_sign_the_persons_terminal_commit() {
    let w = World::new(PersonSigner::ThroughAgentSshSign, "", true);
    let repo = w.repo();
    let token = leaked_token(&w, &repo);
    w.stage(&repo, "mine.txt", "mine\n");
    let _ = w.person_in_terminal(
        &repo,
        &[("AGENT_EVENT_TOKEN", token.as_str())],
        &["commit", "-q", "-m", "mine"],
    );
    assert_ne!(
        w.signature(&repo, "HEAD"),
        ("G".into(), claude_principal()),
        "the person's commit was signed as the agent"
    );
    assert!(
        w.signer_calls() >= 1,
        "the person's commit should have gone to their own signer"
    );
}

#[test]
fn f8_the_signing_program_ignores_a_token_without_the_wrappers_mark() {
    let w = World::new(PersonSigner::ThroughAgentSshSign, "", true);
    let repo = w.repo();
    let token = leaked_token(&w, &repo);
    w.stage(&repo, "mine.txt", "mine\n");
    // The real git, directly, with the person's own config: their
    // gpg.ssh.program is agent-ssh-sign, and a token leaked into the
    // environment.
    let out = w
        .cmd(&w.real_git)
        .args(["commit", "-q", "-m", "mine"])
        .env("AGENT_EVENT_TOKEN", &token)
        .current_dir(&repo)
        .output()
        .unwrap();
    assert_ne!(
        w.signature(&repo, "HEAD"),
        ("G".into(), claude_principal()),
        "a leaked token signed the person's commit as the agent:\n{}",
        text(&out)
    );
    assert!(
        w.signer_calls() >= 1,
        "the person's commit should have gone to their own signer"
    );
}

// ---------------------------------------------------------------------------
// 9. Branch protection ignores case.
// ---------------------------------------------------------------------------

#[test]
fn f9_protected_branches_are_compared_without_case() {
    let mut policy = LeasePolicy::default();
    policy.block_branches.push("release/*".into());
    let engine = LeaseEngine::new(policy);
    for branch in ["MAIN", "Main", "MASTER", "Release/1.0", "RELEASE/x"] {
        assert!(
            engine.is_branch_blocked(branch),
            "{branch} slipped past branch protection"
        );
    }
    assert!(!engine.is_branch_blocked("feature"));
}

#[test]
fn f9_an_agent_commit_on_upper_case_main_is_refused() {
    let w = World::new(PersonSigner::Fake, "", true);
    let repo = w.repo_named("repo", "MAIN");
    let before = w.rev(&repo, "HEAD");
    let out = w.agent_commit(&repo, CLAUDE, "agent.txt");
    assert!(
        !out.status.success(),
        "an agent commit on MAIN went in:\n{}",
        text(&out)
    );
    assert_eq!(w.rev(&repo, "HEAD"), before);
}
