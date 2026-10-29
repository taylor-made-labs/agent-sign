//! Per-agent identity: every agent signs as itself, never as the person.
//!
//! Before this change every agent signed with one shared key whose trust
//! entry is the person's own email, so agent commits looked like the
//! person's, and the first commit on each branch asked for the person's
//! Touch ID. These tests were written before the change, as its eval. Each
//! group is one numbered point of the change:
//!
//! 1. The identity comes from what the agent already sets (positive evidence
//!    only): Claude Code, Codex, Gemini CLI, or `AGENT_SIGN_AGENT_NAME` /
//!    `AGENT_SIGN_SESSION_ID`. Its principal is
//!    `<slug>.<session8>@agents.local`, session8 being the first 8 hex
//!    characters of the SHA-256 of the session id (`nosession` for a marked
//!    agent without one). An unmarked commit with no terminal is no agent's:
//!    since the identity review (28 Oct 2026) it is git's own, unsigned,
//!    under git's own names, with nothing asked (it was `agent.unidentified`).
//! 2. No approval by default; `[security] approval = "device-owner"` opts
//!    back in.
//! 3. Each agent commit is signed with an OpenSSH certificate for its
//!    principal, issued by an agents' certificate authority the service
//!    creates; `agent-sign trust-line` prints the allowed-signers line.
//! 4. Author and committer are the agent, never the person.
//! 5. Sessions are distinct principals; agents never share one.
//! 6. Other git commands by an identified agent sign as the agent.
//! 7. Unmarked non-commit commands are unchanged (unsigned, git's own names).
//! 8. Rules are unchanged: no agent commits on main or master, forbidden
//!    paths refused.
//! 9. The person's own commands in a terminal still reach their signer.
//! 10. The two ignored attribution tests of
//!     `test_agent_ops_never_persons_key.rs` belong here; their scenarios are
//!     repeated in group 10 below.
//!
//! The expected principals are computed here from the session ids the tests
//! set, with `sha2`, so the tests don't trust the code under test.
//!
//! Isolation (as in `test_agent_ops_never_persons_key.rs`): every process
//! starts from an empty environment plus a temporary HOME, a temporary global
//! git config, no system config, a PATH without agent-sign's installed `bin`,
//! and a socket inside the temporary directory. The person's signer is a
//! fake that logs one line per call and exits 1. The test service never uses
//! the real Touch ID: test builds have a stand-in (`AGENT_SIGN_TEST_AUTH`)
//! whose prompts are logged, so "no approval was asked" is "the log is
//! empty".

use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use tempfile::{TempDir, tempdir};

const PERSON_NAME: &str = "Human Developer";
const PERSON_EMAIL: &str = "dev@example.com";
const ORIGINAL_AUTHOR: &str = "Original Author";
const ORIGINAL_AUTHOR_EMAIL: &str = "orig@example.com";

/// Every wrapper run gets at most this long: a wrapper that loops or waits
/// on a prompt fails the test instead of hanging it.
const RUN_LIMIT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// Expected identities, computed independently of agent-sign.
// ---------------------------------------------------------------------------

/// The first 8 lowercase hex characters of the SHA-256 of `session`.
fn session8(session: &str) -> String {
    Sha256::digest(session.as_bytes())[..4]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// What an agent's commits must say: its display name and its principal.
#[derive(Debug, Clone)]
struct Identity {
    name: String,
    principal: String,
}

/// The identity for display name `name`, tool slug `slug` and session id
/// `session` (`None`: a marked agent with no session id).
fn identity(name: &str, slug: &str, session: Option<&str>) -> Identity {
    let s8 = session
        .map(session8)
        .unwrap_or_else(|| "nosession".to_string());
    Identity {
        name: name.to_string(),
        principal: format!("{slug}.{s8}@agents.local"),
    }
}

/// The environment an agent sets, as (variable, value) pairs.
type Marks<'a> = &'a [(&'a str, &'a str)];

const UNMARKED: Marks = &[];

// ---------------------------------------------------------------------------
// The isolated world.
// ---------------------------------------------------------------------------

/// What the person's global git config uses to sign.
#[derive(Clone, Copy, PartialEq)]
enum PersonSigner {
    /// `gpg.ssh.program` is the fake signer.
    Fake,
    /// `gpg.ssh.program` is agent-sign's signing program, whose
    /// `fallback_program` is the fake signer. Only the macOS-only terminal
    /// tests use it, so it's unused on Linux.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    ThroughAgentSshSign,
}

/// How the test service is started.
#[derive(Clone, Copy)]
struct ServiceSetup {
    /// `--auto-approve`.
    auto_approve: bool,
    /// The stand-in owner's answer (`AGENT_SIGN_TEST_AUTH`): `allow`, or
    /// anything else to refuse.
    auth: &'static str,
    /// `[security] approval = "<this>"` in the config, when set.
    approval: Option<&'static str>,
}

/// The new default: no `--auto-approve`, and a stand-in owner who refuses
/// every prompt. An agent commit can succeed here only if nobody is asked.
const NO_APPROVAL: ServiceSetup = ServiceSetup {
    auto_approve: false,
    auth: "fail",
    approval: None,
};

/// `--auto-approve`: used where a test is about identity, not approval, so
/// that on the code before the change it fails for the reason under test.
const AUTO: ServiceSetup = ServiceSetup {
    auto_approve: true,
    auth: "fail",
    approval: None,
};

struct World {
    dir: TempDir,
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

/// `PATH` with every entry containing `.agent-sign` removed.
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
    fn new(signer: PersonSigner, service: Option<ServiceSetup>) -> World {
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
            dir,
        };
        world.write_person_setup(signer, service.and_then(|s| s.approval));
        if let Some(setup) = service {
            world.start_service(setup);
        }
        world
    }

    /// Every process the tests start is built here.
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

    /// The throwaway person key, the fake signer, the person's global git
    /// config, and agent-sign's config.toml.
    fn write_person_setup(&self, signer: PersonSigner, approval: Option<&str>) {
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

        let mut agent_sign_config = String::new();
        if let Some(a) = approval {
            agent_sign_config.push_str(&format!("[security]\napproval = \"{a}\"\n"));
        }
        let program = match signer {
            PersonSigner::Fake => fake.clone(),
            PersonSigner::ThroughAgentSshSign => {
                agent_sign_config.push_str(&format!(
                    "[ssh]\nfallback_program = \"{}\"\n",
                    fake.display()
                ));
                PathBuf::from(env!("CARGO_BIN_EXE_agent-ssh-sign"))
            }
        };
        let state = self.home.join(".agent-sign");
        fs::create_dir_all(&state).unwrap();
        fs::write(state.join("config.toml"), agent_sign_config).unwrap();

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

    fn start_service(&mut self, setup: ServiceSetup) {
        let log = fs::File::create(self.home.join("service.log")).unwrap();
        let mut cmd = self.cmd(Path::new(env!("CARGO_BIN_EXE_agent-signd")));
        cmd.arg("--socket")
            .arg(&self.socket)
            .env("AGENT_SIGN_TEST_AUTH", setup.auth)
            .env("AGENT_SIGN_TEST_AUTH_LOG", &self.auth_log)
            .env("AGENT_SIGN_REFUSAL_BACKOFF", "none")
            .stdout(Stdio::null())
            .stderr(Stdio::from(log));
        if setup.auto_approve {
            cmd.arg("--auto-approve");
        }
        self.service = Some(cmd.spawn().unwrap());
        let start = Instant::now();
        while !self.socket.exists() {
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "test service didn't start: {}",
                fs::read_to_string(self.home.join("service.log")).unwrap_or_default()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn signer_calls(&self) -> usize {
        fs::read_to_string(&self.signer_log)
            .map(|s| s.lines().count())
            .unwrap_or(0)
    }

    /// The prompts the stand-in owner was shown, one per line.
    fn approvals_asked(&self) -> String {
        fs::read_to_string(&self.auth_log).unwrap_or_default()
    }

    /// The real git, directly, unmarked (setup and inspection).
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
    fn person_in_terminal(&self, repo: &Path, args: &[&str]) -> Output {
        let mut cmd = self.cmd(Path::new("/usr/bin/script"));
        cmd.args(["-q", "/dev/null", env!("CARGO_BIN_EXE_agent-git")])
            .args(args)
            .env("TERM", "dumb")
            .current_dir(repo);
        run_within(cmd, &format!("person's git {args:?} in a terminal"))
    }

    /// An unsigned setup commit adding `file`.
    fn commit(&self, repo: &Path, file: &str, author: Option<(&str, &str)>) {
        fs::write(repo.join(file), format!("{file}\n")).unwrap();
        self.git_ok(repo, &["add", file]);
        let mut args = vec!["-c", "commit.gpgsign=false", "commit", "-q", "-m", file];
        let author_arg;
        if let Some((name, email)) = author {
            author_arg = format!("--author={name} <{email}>");
            args.push(&author_arg);
        }
        self.git_ok(repo, &args);
    }

    /// A repository on `branch` (base, w1), with `feature` branched from base
    /// (f1, f2, both by the original author), `branch` checked out.
    fn repo_on(&self, branch: &str) -> PathBuf {
        let repo = self.home.join("repo");
        fs::create_dir_all(&repo).unwrap();
        self.git_ok(&repo, &["init", "-q", "-b", branch]);
        self.commit(&repo, "base.txt", None);
        self.git_ok(&repo, &["checkout", "-q", "-b", "feature"]);
        let orig = Some((ORIGINAL_AUTHOR, ORIGINAL_AUTHOR_EMAIL));
        self.commit(&repo, "f1.txt", orig);
        self.commit(&repo, "f2.txt", orig);
        self.git_ok(&repo, &["checkout", "-q", branch]);
        self.commit(&repo, "w1.txt", None);
        repo
    }

    fn repo(&self) -> PathBuf {
        self.repo_on("work")
    }

    /// The temporary directory everything lives in.
    fn path(&self) -> &Path {
        self.dir.path()
    }

    /// Stages a new file and commits it through the wrapper as `marks`.
    fn agent_commit(&self, repo: &Path, marks: Marks, file: &str) -> Output {
        fs::write(repo.join(file), format!("{file}\n")).unwrap();
        self.git_ok(repo, &["add", file]);
        self.agent(repo, marks, &["commit", "-m", &format!("feat: {file}")])
    }

    fn rev(&self, repo: &Path, rev: &str) -> String {
        self.git_ok(repo, &["rev-parse", rev])
    }

    /// `%an <%ae>` and `%cn <%ce>` of `rev`.
    fn author_and_committer(&self, repo: &Path, rev: &str) -> (String, String) {
        let both = self.git_ok(repo, &["log", "-1", "--format=%an <%ae>%x1f%cn <%ce>", rev]);
        let (a, c) = both.split_once('\x1f').unwrap();
        (a.to_string(), c.to_string())
    }

    fn agents_ca_pub_path(&self) -> PathBuf {
        self.home.join(".agent-sign/keys/agents_ca_ed25519.pub")
    }

    fn legacy_agent_pub_path(&self) -> PathBuf {
        self.home.join(".agent-sign/keys/agent_ed25519.pub")
    }

    /// The agents' certificate authority's public key line.
    fn agents_ca_pub(&self) -> String {
        let path = self.agents_ca_pub_path();
        fs::read_to_string(&path)
            .unwrap_or_else(|e| {
                panic!(
                    "no agents' certificate authority key at {} ({e}): the service didn't create one",
                    path.display()
                )
            })
            .trim()
            .to_string()
    }

    /// The allowed-signers line `agent-sign trust-line` must print.
    fn expected_trust_line(&self) -> String {
        format!(
            "*@agents.local cert-authority,namespaces=\"git\" {}",
            self.agents_ca_pub()
        )
    }

    /// An allowed-signers file holding `lines`.
    fn allowed_signers(&self, name: &str, lines: &[String]) -> PathBuf {
        let file = self.home.join(name);
        fs::write(&file, format!("{}\n", lines.join("\n"))).unwrap();
        file
    }

    /// An allowed-signers file with exactly the agents' trust line.
    fn agents_trust_file(&self) -> PathBuf {
        let line = self.expected_trust_line();
        self.allowed_signers("agents_allowed_signers", &[line])
    }

    /// `(%G?, %GS, --show-signature output)` for `rev`, checked by plain
    /// ssh-keygen (never the fake signer) against `allowed`.
    fn signature(&self, repo: &Path, rev: &str, allowed: &Path) -> (String, String, String) {
        let program = format!("gpg.ssh.program={}", self.ssh_keygen.display());
        let file = format!("gpg.ssh.allowedSignersFile={}", allowed.display());
        let base = ["-c", program.as_str(), "-c", file.as_str(), "log", "-1"];
        let fmt = self.git(repo, &[&base[..], &["--format=%G?%x1f%GS", rev]].concat());
        let fmt = String::from_utf8_lossy(&fmt.stdout).trim().to_string();
        let (g, signer) = fmt.split_once('\x1f').unwrap_or((fmt.as_str(), ""));
        let shown = self.git(repo, &[&base[..], &["--show-signature", rev]].concat());
        (g.to_string(), signer.to_string(), text(&shown))
    }
}

// ---------------------------------------------------------------------------
// Assertions.
// ---------------------------------------------------------------------------

fn assert_ok(w: &World, out: &Output, what: &str) {
    assert!(
        out.status.success(),
        "{what} failed (person's signer calls: {}; approvals asked: {:?}):\n{}",
        w.signer_calls(),
        w.approvals_asked(),
        text(out)
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

fn as_git_ident(id: &Identity) -> String {
    format!("{} <{}>", id.name, id.principal)
}

fn assert_authored_as(w: &World, repo: &Path, rev: &str, id: &Identity, what: &str) {
    let (author, _) = w.author_and_committer(repo, rev);
    assert_eq!(author, as_git_ident(id), "{what}: author of {rev}");
}

fn assert_committed_as(w: &World, repo: &Path, rev: &str, id: &Identity, what: &str) {
    let (_, committer) = w.author_and_committer(repo, rev);
    assert_eq!(committer, as_git_ident(id), "{what}: committer of {rev}");
}

/// Author and committer are both the agent.
fn assert_attributed_to(w: &World, repo: &Path, rev: &str, id: &Identity, what: &str) {
    assert_authored_as(w, repo, rev, id, what);
    assert_committed_as(w, repo, rev, id, what);
}

/// `rev` has a Good "git" signature for `id`'s principal, checked against
/// exactly the agents' trust line.
fn assert_signed_as(w: &World, repo: &Path, rev: &str, id: &Identity, what: &str) {
    let good = format!("Good \"git\" signature for {}", id.principal);
    // Without the CA key there is no trust line; the signature is still
    // checked (against no one) so the failure says what the commit has.
    let (allowed, ca_note) = if w.agents_ca_pub_path().exists() {
        (w.agents_trust_file(), String::new())
    } else {
        (
            w.allowed_signers("no_signers", &[]),
            format!(
                "; no agents' certificate authority key at {}",
                w.agents_ca_pub_path().display()
            ),
        )
    };
    let (g, signer, shown) = w.signature(repo, rev, &allowed);
    assert!(
        g == "G" && signer == id.principal && shown.contains(&good),
        "{what}: {rev} should have a {good} (got %G?={g:?}, %GS={signer:?}{ca_note}):\n{shown}"
    );
}

// ---------------------------------------------------------------------------
// 1. Identity from what the agent already sets.
// ---------------------------------------------------------------------------

/// Commits once as `marks` on a fresh world and checks author and
/// committer are `expected`.
fn commit_attributed_as(marks: Marks, expected: &Identity, what: &str) {
    let w = World::new(PersonSigner::Fake, Some(AUTO));
    let repo = w.repo();
    let out = w.agent_commit(&repo, marks, "agent.txt");
    assert_ok(&w, &out, what);
    assert_no_person_signer(&w, what);
    assert_attributed_to(&w, &repo, "HEAD", expected, what);
}

#[test]
fn claude_code_is_named_by_its_session() {
    let session = "cc-session-0001";
    commit_attributed_as(
        &[("CLAUDECODE", "1"), ("CLAUDE_CODE_SESSION_ID", session)],
        &identity("Claude Code", "claude-code", Some(session)),
        "Claude Code commit",
    );
}

#[test]
fn codex_is_named_by_its_session_id() {
    let session = "codex-session-0001";
    commit_attributed_as(
        &[("CODEX_SESSION_ID", session)],
        &identity("Codex", "codex", Some(session)),
        "Codex commit (CODEX_SESSION_ID)",
    );
}

#[test]
fn codex_falls_back_to_its_thread_id() {
    let thread = "codex-thread-0001";
    commit_attributed_as(
        &[("CODEX_THREAD_ID", thread)],
        &identity("Codex", "codex", Some(thread)),
        "Codex commit (CODEX_THREAD_ID only)",
    );
}

#[test]
fn codex_session_id_wins_over_its_thread_id() {
    let session = "codex-session-0002";
    commit_attributed_as(
        &[
            ("CODEX_SESSION_ID", session),
            ("CODEX_THREAD_ID", "codex-thread-0002"),
        ],
        &identity("Codex", "codex", Some(session)),
        "Codex commit (both ids)",
    );
}

#[test]
fn gemini_cli_without_a_session_id_is_nosession() {
    commit_attributed_as(
        &[("GEMINI_CLI", "1")],
        &identity("Gemini CLI", "gemini-cli", None),
        "Gemini CLI commit",
    );
}

#[test]
fn marked_claude_code_without_a_session_id_is_nosession() {
    commit_attributed_as(
        &[("CLAUDECODE", "1")],
        &identity("Claude Code", "claude-code", None),
        "Claude Code commit without a session id",
    );
}

#[test]
fn explicit_name_and_session_override_the_agents_own_mark() {
    let session = "explicit-session-0001";
    commit_attributed_as(
        &[
            ("CLAUDECODE", "1"),
            ("CLAUDE_CODE_SESSION_ID", "cc-session-ignored"),
            ("AGENT_SIGN_AGENT_NAME", "My Bot 2"),
            ("AGENT_SIGN_SESSION_ID", session),
        ],
        // slug: lowercase, non-alphanumerics to '-'.
        &identity("My Bot 2", "my-bot-2", Some(session)),
        "explicitly named agent",
    );
}

#[test]
fn explicit_session_id_names_a_gemini_session() {
    let session = "gemini-session-0001";
    commit_attributed_as(
        &[("GEMINI_CLI", "1"), ("AGENT_SIGN_SESSION_ID", session)],
        &identity("Gemini CLI", "gemini-cli", Some(session)),
        "Gemini CLI commit with AGENT_SIGN_SESSION_ID",
    );
}

/// Identity review (28 Oct 2026), finding 5: a commit with no terminal and
/// no agent mark may be the person's own editor or GUI, so it's git's own:
/// it succeeds unsigned (`%G?` is N) under git's own author and committer,
/// the person's signer is never called, and no approval is asked even with
/// `approval = "device-owner"` and an owner who refuses every prompt.
fn commit_is_gits_own(marks: Marks, what: &str) {
    let w = World::new(
        PersonSigner::Fake,
        Some(ServiceSetup {
            auto_approve: false,
            auth: "fail",
            approval: Some("device-owner"),
        }),
    );
    let repo = w.repo();
    let before = w.rev(&repo, "HEAD");
    let out = w.agent_commit(&repo, marks, "agent.txt");
    assert_eq!(
        w.approvals_asked(),
        "",
        "{what}: approval was asked:\n{}",
        text(&out)
    );
    assert_ok(&w, &out, what);
    assert_ne!(w.rev(&repo, "HEAD"), before, "{what}: no commit was made");
    assert_no_person_signer(&w, what);
    let any = w.allowed_signers("any", &[]);
    let (g, _, shown) = w.signature(&repo, "HEAD", &any);
    assert_eq!(g, "N", "{what}: the commit should be unsigned:\n{shown}");
    let gits_own = format!("{PERSON_NAME} <{PERSON_EMAIL}>");
    assert_eq!(
        w.author_and_committer(&repo, "HEAD"),
        (gits_own.clone(), gits_own),
        "{what}: author and committer should be git's own"
    );
}

#[test]
fn claudecode_set_to_zero_is_no_mark_so_the_commit_is_gits_own() {
    // Positive evidence only: CLAUDECODE=0 is not Claude Code.
    commit_is_gits_own(
        &[
            ("CLAUDECODE", "0"),
            ("CLAUDE_CODE_SESSION_ID", "cc-session-zero"),
        ],
        "commit with CLAUDECODE=0",
    );
}

#[test]
fn an_unmarked_commit_with_no_terminal_is_gits_own_unsigned_commit() {
    commit_is_gits_own(UNMARKED, "unmarked commit");
}

// ---------------------------------------------------------------------------
// 2. No approval by default; approval is an opt-in.
// ---------------------------------------------------------------------------

fn commit_without_approval(marks: Marks, what: &str) {
    let w = World::new(PersonSigner::Fake, Some(NO_APPROVAL));
    let repo = w.repo();
    let before = w.rev(&repo, "HEAD");
    let out = w.agent_commit(&repo, marks, "agent.txt");
    assert_eq!(
        w.approvals_asked(),
        "",
        "{what}: approval was asked (the stand-in owner refuses), but none should be:\n{}",
        text(&out)
    );
    assert_ok(&w, &out, what);
    assert_ne!(w.rev(&repo, "HEAD"), before, "{what}: no commit was made");
    assert_no_person_signer(&w, what);
}

#[test]
fn an_identified_agent_commit_needs_no_approval() {
    commit_without_approval(
        &[
            ("CLAUDECODE", "1"),
            ("CLAUDE_CODE_SESSION_ID", "cc-session-0002"),
        ],
        "Claude Code commit with no approval",
    );
}

#[test]
fn an_unmarked_commit_with_no_terminal_asks_no_approval() {
    commit_is_gits_own(UNMARKED, "unmarked commit, approval = \"device-owner\"");
}

#[test]
fn approval_device_owner_restores_asking_and_a_refusal_stops_the_commit() {
    let w = World::new(
        PersonSigner::Fake,
        Some(ServiceSetup {
            auto_approve: false,
            auth: "fail",
            approval: Some("device-owner"),
        }),
    );
    let repo = w.repo();
    let before = w.rev(&repo, "HEAD");
    let out = w.agent_commit(
        &repo,
        &[
            ("CLAUDECODE", "1"),
            ("CLAUDE_CODE_SESSION_ID", "cc-session-0003"),
        ],
        "agent.txt",
    );
    assert!(
        !out.status.success(),
        "with approval = \"device-owner\" and the owner refusing, the commit must fail:\n{}",
        text(&out)
    );
    assert_ne!(w.approvals_asked(), "", "the owner should have been asked");
    assert_eq!(
        w.rev(&repo, "HEAD"),
        before,
        "a refused commit made a commit"
    );
    assert_no_person_signer(&w, "refused opt-in approval");
}

#[test]
fn approval_device_owner_when_allowed_still_signs_as_the_agent() {
    let w = World::new(
        PersonSigner::Fake,
        Some(ServiceSetup {
            auto_approve: false,
            auth: "allow",
            approval: Some("device-owner"),
        }),
    );
    let repo = w.repo();
    let session = "cc-session-0004";
    let out = w.agent_commit(
        &repo,
        &[("CLAUDECODE", "1"), ("CLAUDE_CODE_SESSION_ID", session)],
        "agent.txt",
    );
    assert_ok(&w, &out, "approved opt-in commit");
    assert_ne!(w.approvals_asked(), "", "the owner should have been asked");
    let id = identity("Claude Code", "claude-code", Some(session));
    assert_signed_as(&w, &repo, "HEAD", &id, "approved opt-in commit");
}

// ---------------------------------------------------------------------------
// 3. Signed with a certificate for the agent's own principal.
// ---------------------------------------------------------------------------

#[test]
fn the_service_creates_the_agents_certificate_authority_on_first_start() {
    let w = World::new(PersonSigner::Fake, Some(NO_APPROVAL));
    let ca = w.agents_ca_pub();
    assert!(
        ca.starts_with("ssh-ed25519 "),
        "the CA public key should be an OpenSSH ed25519 line: {ca:?}"
    );
    let out = w
        .cmd(&w.ssh_keygen)
        .arg("-l")
        .arg("-f")
        .arg(w.agents_ca_pub_path())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "ssh-keygen can't read it:\n{}",
        text(&out)
    );
}

#[test]
fn trust_line_prints_the_agents_allowed_signers_line() {
    let w = World::new(PersonSigner::Fake, Some(NO_APPROVAL));
    let mut cmd = w.cmd(Path::new(env!("CARGO_BIN_EXE_agent-sign")));
    cmd.arg("trust-line");
    let out = run_within(cmd, "agent-sign trust-line");
    assert!(
        out.status.success(),
        "agent-sign trust-line failed:\n{}",
        text(&out)
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        w.expected_trust_line(),
        "trust-line output"
    );
}

#[test]
fn an_agent_commit_is_good_for_its_principal_under_the_trust_line() {
    let w = World::new(PersonSigner::Fake, Some(AUTO));
    let repo = w.repo();
    let session = "cc-session-0005";
    let out = w.agent_commit(
        &repo,
        &[("CLAUDECODE", "1"), ("CLAUDE_CODE_SESSION_ID", session)],
        "agent.txt",
    );
    assert_ok(&w, &out, "Claude Code commit");
    let id = identity("Claude Code", "claude-code", Some(session));
    assert_signed_as(&w, &repo, "HEAD", &id, "Claude Code commit");
}

#[test]
fn an_unmarked_commit_with_no_terminal_is_unsigned_and_never_reaches_the_persons_signer() {
    commit_is_gits_own(UNMARKED, "unmarked commit, checked for a signature");
}

#[test]
fn the_legacy_shared_agent_key_is_not_used_for_new_signatures() {
    let w = World::new(PersonSigner::Fake, Some(AUTO));
    let repo = w.repo();
    let out = w.agent_commit(
        &repo,
        &[
            ("CLAUDECODE", "1"),
            ("CLAUDE_CODE_SESSION_ID", "cc-session-0006"),
        ],
        "agent.txt",
    );
    assert_ok(&w, &out, "Claude Code commit");
    let Ok(legacy) = fs::read_to_string(w.legacy_agent_pub_path()) else {
        // No shared key at all: it certainly didn't sign.
        return;
    };
    let allowed = w.allowed_signers(
        "legacy_allowed_signers",
        &[format!("legacy@test namespaces=\"git\" {}", legacy.trim())],
    );
    let (g, signer, shown) = w.signature(&repo, "HEAD", &allowed);
    assert_ne!(
        g, "G",
        "the commit verifies against the legacy shared agent key (signer {signer:?}):\n{shown}"
    );
}

/// Guards the eval itself: a commit signed by hand with an OpenSSH
/// certificate from a throwaway CA, for an agents.local principal, is Good
/// under a trust line of the same shape, through the same check the tests
/// above use. If this fails, the checks above can't pass whatever the code
/// does.
#[test]
fn the_signature_check_accepts_a_hand_made_agent_certificate() {
    let w = World::new(PersonSigner::Fake, None);
    let keys = w.home.join("handmade");
    fs::create_dir_all(&keys).unwrap();
    let principal = identity("Claude Code", "claude-code", Some("hand-made")).principal;
    for (name, comment) in [("ca", "ca"), ("user", "user")] {
        let out = w
            .cmd(&w.ssh_keygen)
            .args(["-q", "-t", "ed25519", "-N", "", "-C", comment, "-f"])
            .arg(keys.join(name))
            .output()
            .unwrap();
        assert!(out.status.success(), "ssh-keygen: {}", text(&out));
    }
    let out = w
        .cmd(&w.ssh_keygen)
        .args(["-q", "-s"])
        .arg(keys.join("ca"))
        .args(["-I", "hand-made", "-n", &principal])
        .arg(keys.join("user.pub"))
        .output()
        .unwrap();
    assert!(out.status.success(), "ssh-keygen -s: {}", text(&out));

    let repo = w.repo();
    fs::write(repo.join("x.txt"), "x\n").unwrap();
    w.git_ok(&repo, &["add", "x.txt"]);
    let program = format!("gpg.ssh.program={}", w.ssh_keygen.display());
    let key = format!("user.signingkey={}", keys.join("user-cert.pub").display());
    w.git_ok(
        &repo,
        &["-c", &program, "-c", &key, "commit", "-q", "-m", "x"],
    );

    let ca = fs::read_to_string(keys.join("ca.pub")).unwrap();
    let allowed = w.allowed_signers(
        "handmade_allowed_signers",
        &[format!(
            "*@agents.local cert-authority,namespaces=\"git\" {}",
            ca.trim()
        )],
    );
    let (g, signer, shown) = w.signature(&repo, "HEAD", &allowed);
    assert_eq!(
        (g.as_str(), signer.as_str()),
        ("G", principal.as_str()),
        "{shown}"
    );
    assert!(
        shown.contains(&format!("Good \"git\" signature for {principal}")),
        "{shown}"
    );
}

// ---------------------------------------------------------------------------
// 4. Attribution: the agent, never the person.
// ---------------------------------------------------------------------------

#[test]
fn an_identified_agent_commit_is_authored_and_committed_as_the_agent() {
    let w = World::new(PersonSigner::Fake, Some(AUTO));
    let repo = w.repo();
    let session = "cc-session-0007";
    let out = w.agent_commit(
        &repo,
        &[("CLAUDECODE", "1"), ("CLAUDE_CODE_SESSION_ID", session)],
        "agent.txt",
    );
    assert_ok(&w, &out, "Claude Code commit");
    let (author, committer) = w.author_and_committer(&repo, "HEAD");
    for (role, who) in [("author", &author), ("committer", &committer)] {
        assert!(
            !who.contains(PERSON_NAME) && !who.contains(PERSON_EMAIL),
            "{role} is the person: {who}"
        );
    }
    let id = identity("Claude Code", "claude-code", Some(session));
    assert_eq!(author, as_git_ident(&id), "author");
    assert_eq!(committer, as_git_ident(&id), "committer");
}

// ---------------------------------------------------------------------------
// 5. Sessions are distinct; agents never share a principal.
// ---------------------------------------------------------------------------

#[test]
fn the_same_session_keeps_one_principal() {
    let w = World::new(PersonSigner::Fake, Some(AUTO));
    let repo = w.repo();
    let session = "cc-session-0008";
    let marks: Marks = &[("CLAUDECODE", "1"), ("CLAUDE_CODE_SESSION_ID", session)];
    let id = identity("Claude Code", "claude-code", Some(session));
    for file in ["one.txt", "two.txt"] {
        let out = w.agent_commit(&repo, marks, file);
        assert_ok(&w, &out, file);
    }
    for rev in ["HEAD", "HEAD~1"] {
        assert_attributed_to(&w, &repo, rev, &id, "same session");
        assert_signed_as(&w, &repo, rev, &id, "same session");
    }
}

#[test]
fn two_sessions_get_two_principals() {
    let w = World::new(PersonSigner::Fake, Some(AUTO));
    let repo = w.repo();
    let (s1, s2) = ("cc-session-0009", "cc-session-0010");
    for (session, file) in [(s1, "one.txt"), (s2, "two.txt")] {
        let out = w.agent_commit(
            &repo,
            &[("CLAUDECODE", "1"), ("CLAUDE_CODE_SESSION_ID", session)],
            file,
        );
        assert_ok(&w, &out, file);
    }
    let (first, _) = w.author_and_committer(&repo, "HEAD~1");
    let (second, _) = w.author_and_committer(&repo, "HEAD");
    assert_ne!(first, second, "two sessions share one identity");
    assert_attributed_to(
        &w,
        &repo,
        "HEAD~1",
        &identity("Claude Code", "claude-code", Some(s1)),
        "session 1",
    );
    assert_attributed_to(
        &w,
        &repo,
        "HEAD",
        &identity("Claude Code", "claude-code", Some(s2)),
        "session 2",
    );
}

#[test]
fn codex_and_claude_code_never_share_a_principal() {
    let w = World::new(PersonSigner::Fake, Some(AUTO));
    let repo = w.repo();
    let same = "shared-session-id";
    let claude: Marks = &[("CLAUDECODE", "1"), ("CLAUDE_CODE_SESSION_ID", same)];
    let codex: Marks = &[("CODEX_SESSION_ID", same)];
    assert_ok(
        &w,
        &w.agent_commit(&repo, claude, "claude.txt"),
        "Claude Code",
    );
    assert_ok(&w, &w.agent_commit(&repo, codex, "codex.txt"), "Codex");
    let (claude_author, _) = w.author_and_committer(&repo, "HEAD~1");
    let (codex_author, _) = w.author_and_committer(&repo, "HEAD");
    assert_ne!(
        claude_author, codex_author,
        "Codex and Claude Code share one identity"
    );
    assert_attributed_to(
        &w,
        &repo,
        "HEAD~1",
        &identity("Claude Code", "claude-code", Some(same)),
        "Claude Code",
    );
    assert_attributed_to(
        &w,
        &repo,
        "HEAD",
        &identity("Codex", "codex", Some(same)),
        "Codex",
    );
}

// ---------------------------------------------------------------------------
// 6. Other git commands by an identified agent sign as the agent.
// ---------------------------------------------------------------------------

const SIX_SESSION: &str = "cc-session-0006-ops";
const SIX: Marks = &[("CLAUDECODE", "1"), ("CLAUDE_CODE_SESSION_ID", SIX_SESSION)];

fn six() -> Identity {
    identity("Claude Code", "claude-code", Some(SIX_SESSION))
}

/// A new commit (merge, revert): signed, authored and committed as the agent.
fn assert_new_commit_by_agent(w: &World, repo: &Path, out: &Output, what: &str) {
    assert_no_person_signer(w, what);
    assert_ok(w, out, what);
    assert_signed_as(w, repo, "HEAD", &six(), what);
    assert_attributed_to(w, repo, "HEAD", &six(), what);
}

/// A replayed commit (rebase, cherry-pick, am): signed as the agent, the
/// original author kept, the agent as committer.
fn assert_replayed_by_agent(w: &World, repo: &Path, rev: &str, what: &str) {
    assert_signed_as(w, repo, rev, &six(), what);
    let (author, _) = w.author_and_committer(repo, rev);
    assert_eq!(
        author,
        format!("{ORIGINAL_AUTHOR} <{ORIGINAL_AUTHOR_EMAIL}>"),
        "{what}: {rev} should keep its original author"
    );
    assert_committed_as(w, repo, rev, &six(), what);
}

#[test]
fn an_agents_merge_is_signed_and_made_by_the_agent() {
    let w = World::new(PersonSigner::Fake, Some(AUTO));
    let repo = w.repo();
    let out = w.agent(
        &repo,
        SIX,
        &["merge", "--no-ff", "-m", "merge feature", "feature"],
    );
    assert_new_commit_by_agent(&w, &repo, &out, "merge --no-ff");
}

#[test]
fn an_agents_revert_is_signed_and_made_by_the_agent() {
    let w = World::new(PersonSigner::Fake, Some(AUTO));
    let repo = w.repo();
    let out = w.agent(&repo, SIX, &["revert", "--no-edit", "HEAD"]);
    assert_new_commit_by_agent(&w, &repo, &out, "revert");
}

#[test]
fn an_agents_pull_merge_is_signed_and_made_by_the_agent() {
    let w = World::new(PersonSigner::Fake, Some(AUTO));
    let upstream = w.repo();
    let down = w.path().join("down");
    w.git_ok(
        w.path(),
        &[
            "clone",
            "-q",
            "-b",
            "work",
            upstream.to_str().unwrap(),
            "down",
        ],
    );
    w.commit(&down, "d1.txt", None);
    let out = w.agent(
        &down,
        SIX,
        &[
            "pull",
            "--no-rebase",
            "--no-edit",
            upstream.to_str().unwrap(),
            "feature",
        ],
    );
    assert_new_commit_by_agent(&w, &down, &out, "pull --no-rebase");
}

#[test]
fn an_agents_shell_alias_merge_is_signed_and_made_by_the_agent() {
    let w = World::new(PersonSigner::Fake, Some(AUTO));
    let repo = w.repo();
    w.git_ok(
        &repo,
        &["config", "alias.mm", "!git merge --no-ff -m msg feature"],
    );
    let out = w.agent(&repo, SIX, &["mm"]);
    assert_new_commit_by_agent(&w, &repo, &out, "shell alias merge");
}

#[test]
fn an_agents_rebase_signs_replayed_commits_as_the_agent() {
    let w = World::new(PersonSigner::Fake, Some(AUTO));
    let repo = w.repo();
    w.git_ok(&repo, &["checkout", "-q", "feature"]);
    let out = w.agent(&repo, SIX, &["rebase", "work"]);
    assert_no_person_signer(&w, "rebase");
    assert_ok(&w, &out, "rebase");
    assert_eq!(
        w.rev(&repo, "HEAD~2"),
        w.rev(&repo, "work"),
        "rebase didn't replay both"
    );
    assert_replayed_by_agent(&w, &repo, "HEAD", "rebase");
    assert_replayed_by_agent(&w, &repo, "HEAD~1", "rebase");
}

#[test]
fn an_agents_cherry_pick_is_signed_as_the_agent() {
    let w = World::new(PersonSigner::Fake, Some(AUTO));
    let repo = w.repo();
    let out = w.agent(&repo, SIX, &["cherry-pick", "feature~1"]);
    assert_no_person_signer(&w, "cherry-pick");
    assert_ok(&w, &out, "cherry-pick");
    assert_replayed_by_agent(&w, &repo, "HEAD", "cherry-pick");
}

#[test]
fn an_agents_am_is_signed_as_the_agent() {
    let w = World::new(PersonSigner::Fake, Some(AUTO));
    let repo = w.repo();
    let patches = w.path().join("patches");
    let made = w.git_ok(
        &repo,
        &[
            "format-patch",
            "-1",
            "feature",
            "-o",
            patches.to_str().unwrap(),
        ],
    );
    let patch = made
        .lines()
        .next()
        .expect("format-patch wrote a patch")
        .to_string();
    let out = w.agent(&repo, SIX, &["am", &patch]);
    assert_no_person_signer(&w, "am");
    assert_ok(&w, &out, "am");
    assert_replayed_by_agent(&w, &repo, "HEAD", "am");
}

// ---------------------------------------------------------------------------
// 7. Unmarked non-commit commands: unchanged.
// ---------------------------------------------------------------------------

fn unmarked_op_unchanged(args: &[&str], what: &str) {
    let w = World::new(PersonSigner::Fake, Some(NO_APPROVAL));
    let repo = w.repo();
    let before = w.rev(&repo, "HEAD");
    let out = w.agent(&repo, UNMARKED, args);
    assert_no_person_signer(&w, what);
    assert_ok(&w, &out, what);
    assert_ne!(w.rev(&repo, "HEAD"), before, "{what} made no commit");
    let any = w.allowed_signers("any", &[]);
    let (g, _, shown) = w.signature(&repo, "HEAD", &any);
    assert_eq!(g, "N", "{what}: the commit should be unsigned:\n{shown}");
    let gits_own = format!("{PERSON_NAME} <{PERSON_EMAIL}>");
    assert_eq!(
        w.author_and_committer(&repo, "HEAD"),
        (gits_own.clone(), gits_own),
        "{what}: author and committer should be git's own"
    );
}

#[test]
fn an_unmarked_merge_is_unsigned_with_gits_own_names() {
    unmarked_op_unchanged(
        &["merge", "--no-ff", "-m", "merge feature", "feature"],
        "unmarked merge --no-ff",
    );
}

#[test]
fn an_unmarked_revert_is_unsigned_with_gits_own_names() {
    unmarked_op_unchanged(&["revert", "--no-edit", "HEAD"], "unmarked revert");
}

// ---------------------------------------------------------------------------
// 8. Rules unchanged.
// ---------------------------------------------------------------------------

fn agent_commit_refused_on(branch: &str) {
    let w = World::new(PersonSigner::Fake, Some(AUTO));
    let repo = w.repo_on(branch);
    let before = w.rev(&repo, "HEAD");
    let out = w.agent_commit(&repo, SIX, "agent.txt");
    assert!(
        !out.status.success(),
        "an agent commit on {branch} should be refused:\n{}",
        text(&out)
    );
    assert_eq!(
        w.rev(&repo, "HEAD"),
        before,
        "a commit was made on {branch}"
    );
    assert_no_person_signer(&w, branch);
}

#[test]
fn an_agent_commit_on_main_is_refused() {
    agent_commit_refused_on("main");
}

#[test]
fn an_agent_commit_on_master_is_refused() {
    agent_commit_refused_on("master");
}

#[test]
fn an_identified_agents_merge_on_main_creates_no_commit() {
    let w = World::new(PersonSigner::Fake, Some(AUTO));
    let repo = w.repo_on("main");
    let before = w.rev(&repo, "HEAD");
    let out = w.agent(
        &repo,
        SIX,
        &["merge", "--no-ff", "-m", "merge feature", "feature"],
    );
    assert_eq!(
        w.rev(&repo, "HEAD"),
        before,
        "an agent's merge created a commit on main:\n{}",
        text(&out)
    );
    assert_no_person_signer(&w, "merge on main");
}

#[test]
fn a_forbidden_path_is_still_refused() {
    let w = World::new(PersonSigner::Fake, Some(AUTO));
    let repo = w.repo();
    let before = w.rev(&repo, "HEAD");
    let out = w.agent_commit(&repo, SIX, "server.pem");
    assert!(
        !out.status.success(),
        "a commit touching *.pem should be refused:\n{}",
        text(&out)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("forbidden path"),
        "{}",
        text(&out)
    );
    assert_eq!(w.rev(&repo, "HEAD"), before, "a forbidden commit was made");
}

// ---------------------------------------------------------------------------
// 9. The person's own commands in a terminal still reach their signer.
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
#[test]
fn the_persons_commit_in_a_terminal_reaches_their_signer() {
    let w = World::new(PersonSigner::Fake, Some(NO_APPROVAL));
    let repo = w.repo();
    fs::write(repo.join("mine.txt"), "mine\n").unwrap();
    w.git_ok(&repo, &["add", "mine.txt"]);
    let out = w.person_in_terminal(&repo, &["commit", "-m", "my own work"]);
    assert!(
        w.signer_calls() >= 1,
        "the person's commit in a terminal should reach their signer:\n{}",
        text(&out)
    );
    assert_eq!(
        w.approvals_asked(),
        "",
        "the person's own commit asked an approval"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn the_persons_merge_in_a_terminal_reaches_their_signer() {
    let w = World::new(PersonSigner::Fake, Some(NO_APPROVAL));
    let repo = w.repo();
    let out = w.person_in_terminal(
        &repo,
        &["merge", "--no-ff", "-m", "merge feature", "feature"],
    );
    assert!(
        w.signer_calls() >= 1,
        "the person's merge in a terminal should reach their signer:\n{}",
        text(&out)
    );
}

#[cfg(target_os = "macos")]
#[test]
fn the_persons_routed_commit_in_a_terminal_reaches_their_signer() {
    // With the person's signing routed through agent-ssh-sign (as an install
    // sets it), their own commit still reaches their signer.
    let w = World::new(PersonSigner::ThroughAgentSshSign, Some(NO_APPROVAL));
    let repo = w.repo();
    fs::write(repo.join("mine.txt"), "mine\n").unwrap();
    w.git_ok(&repo, &["add", "mine.txt"]);
    let out = w.person_in_terminal(&repo, &["commit", "-m", "my own work"]);
    assert!(
        w.signer_calls() >= 1,
        "the person's routed commit in a terminal should reach their signer:\n{}",
        text(&out)
    );
}

// ---------------------------------------------------------------------------
// 10. The two attribution tests ignored in test_agent_ops_never_persons_key.rs
//     (CLAUDECODE=1 only, as there): merge and revert commits are authored as
//     "Claude Code". Here with the full identity (nosession).
// ---------------------------------------------------------------------------

const CLAUDE_ONLY: Marks = &[("CLAUDECODE", "1")];

fn claude_nosession() -> Identity {
    identity("Claude Code", "claude-code", None)
}

#[test]
fn claude_codes_merge_commit_is_authored_as_claude_code() {
    let w = World::new(PersonSigner::Fake, Some(AUTO));
    let repo = w.repo();
    let out = w.agent(
        &repo,
        CLAUDE_ONLY,
        &["merge", "--no-ff", "-m", "merge feature", "feature"],
    );
    assert_ok(&w, &out, "merge");
    assert_no_person_signer(&w, "merge");
    assert_attributed_to(&w, &repo, "HEAD", &claude_nosession(), "merge");
}

#[test]
fn claude_codes_revert_commit_is_authored_as_claude_code() {
    let w = World::new(PersonSigner::Fake, Some(AUTO));
    let repo = w.repo();
    let out = w.agent(&repo, CLAUDE_ONLY, &["revert", "--no-edit", "HEAD"]);
    assert_ok(&w, &out, "revert");
    assert_no_person_signer(&w, "revert");
    assert_attributed_to(&w, &repo, "HEAD", &claude_nosession(), "revert");
}
