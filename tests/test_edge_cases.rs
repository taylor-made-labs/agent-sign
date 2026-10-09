//! Release checks F4 (fails closed), F5 (the rules refuse with a reason) and
//! F8 (edge cases), end to end: a real service, the git wrapper, the signing
//! program, and git, in a temporary home.
//!
//! No real dialog can appear: the service's `PATH` holds only git and
//! stand-in dialogs, which answer from a file and log each time they're
//! shown. "Never signed some other way" is checked by the commit not
//! existing at all after a refusal: the wrapper never falls through to the
//! person's own git and signing.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use agent_sign::attribution::KNOWN_AGENTS;
use agent_sign::protocol::{Request, Response, send_request};
use tempfile::{TempDir, tempdir};

const THIS_REPOSITORY: &str = "This repository only";
const DENY: &str = "DENY";

struct Setup {
    _dir: TempDir,
    home: PathBuf,
    socket: PathBuf,
    fakebin: PathBuf,
    service: Option<Child>,
}

impl Drop for Setup {
    fn drop(&mut self) {
        self.stop_service();
    }
}

fn write_script(path: &Path, body: &str) {
    fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

fn real_git() -> &'static str {
    [
        "/usr/bin/git",
        "/usr/local/bin/git",
        "/opt/homebrew/bin/git",
    ]
    .into_iter()
    .find(|p| Path::new(p).exists())
    .expect("git is needed for these tests")
}

/// Runs the real git as the person, isolated from the machine's own git
/// config: no global or system config, so the person's real signing (a
/// password manager or hardware key) is never asked to sign test commits.
fn git(repo: &Path, args: &[&str]) -> Output {
    Command::new(real_git())
        .args(args)
        .current_dir(repo)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("HOME", repo)
        .output()
        .unwrap()
}

fn git_ok(repo: &Path, args: &[&str]) {
    let out = git(repo, args);
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

impl Setup {
    /// A home with `config` as its config file and a running service.
    /// `auto_approve` grants without asking; otherwise the stand-in dialogs
    /// answer with whatever `answer` holds ([`THIS_REPOSITORY`] to start).
    fn new(config: &str, auto_approve: bool) -> Setup {
        let dir = tempdir().unwrap();
        let home = dir.path().to_path_buf();
        let state = home.join(".agent-sign");
        fs::create_dir_all(&state).unwrap();
        fs::write(state.join("config.toml"), config).unwrap();

        let fakebin = home.join("fakebin");
        fs::create_dir_all(&fakebin).unwrap();
        std::os::unix::fs::symlink(real_git(), fakebin.join("git")).unwrap();
        let answer = home.join("answer");
        let log = home.join("dialog.log");
        fs::write(&answer, THIS_REPOSITORY).unwrap();
        let (a, l) = (answer.display(), log.display());
        // macOS's list dialog prints "false" for Deny; zenity exits 1.
        write_script(
            &fakebin.join("osascript"),
            &format!(
                "echo shown >> '{l}'\nread -r A < '{a}'\n[ \"$A\" = {DENY} ] && echo false || echo \"$A\""
            ),
        );
        write_script(
            &fakebin.join("zenity"),
            &format!(
                "echo shown >> '{l}'\nread -r A < '{a}'\n[ \"$A\" = {DENY} ] && exit 1\necho \"$A\""
            ),
        );

        let mut setup = Setup {
            socket: home.join("s.sock"),
            _dir: dir,
            home,
            fakebin,
            service: None,
        };
        setup.start_service(auto_approve);
        setup
    }

    fn start_service(&mut self, auto_approve: bool) {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_agent-signd"));
        cmd.arg("--socket")
            .arg(&self.socket)
            .env("HOME", &self.home)
            .env("PATH", &self.fakebin)
            .env("DISPLAY", ":99")
            .env_remove("WAYLAND_DISPLAY")
            .env_remove("AGENT_SIGN_AUTO_APPROVE")
            .env_remove("AGENT_SIGN_AUTO_APPROVE")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if auto_approve {
            cmd.arg("--auto-approve");
        }
        self.service = Some(cmd.spawn().unwrap());
        let start = Instant::now();
        while !matches!(
            send_request(&self.socket, &Request::Ping),
            Ok(Response::Pong)
        ) {
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "service didn't start"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn stop_service(&mut self) {
        if let Some(mut child) = self.service.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    fn answer(&self, answer: &str) {
        fs::write(self.home.join("answer"), answer).unwrap();
    }

    fn times_asked(&self) -> usize {
        fs::read_to_string(self.home.join("dialog.log"))
            .map(|s| s.lines().count())
            .unwrap_or(0)
    }

    /// A new repository at `rel` under the home, on `branch`, with a first
    /// commit made by the person (agents can't commit on main).
    fn repo(&self, rel: &str, branch: &str) -> PathBuf {
        let repo = self.home.join(rel);
        fs::create_dir_all(&repo).unwrap();
        git_ok(&repo, &["init", "-q", "-b", "main"]);
        git_ok(&repo, &["config", "user.name", "Person"]);
        git_ok(&repo, &["config", "user.email", "person@example.com"]);
        git_ok(&repo, &["commit", "-q", "--allow-empty", "-m", "first"]);
        if branch != "main" {
            git_ok(&repo, &["checkout", "-q", "-b", branch]);
        }
        repo
    }

    /// Runs the wrapper as an agent would (no terminal, no agent marks).
    fn agent_git(&self, repo: &Path, args: &[&str], extra_env: &[(&str, &str)]) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_agent-git"));
        cmd.args(args)
            .current_dir(repo)
            .env("HOME", &self.home)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("AGENT_SIGN_SOCKET", &self.socket)
            .env("AGENT_SIGN_BIN", env!("CARGO_BIN_EXE_agent-ssh-sign"))
            .stdin(Stdio::null());
        for (var, _) in KNOWN_AGENTS {
            cmd.env_remove(var);
        }
        for (k, v) in extra_env {
            cmd.env(k, v);
        }
        cmd.output().unwrap()
    }

    /// Writes `file`, stages it, and commits it as the agent.
    fn agent_commit(&self, repo: &Path, file: &str) -> Output {
        if let Some(parent) = Path::new(file).parent() {
            fs::create_dir_all(repo.join(parent)).unwrap();
        }
        fs::write(repo.join(file), format!("{file}\n")).unwrap();
        git_ok(repo, &["add", file]);
        self.agent_git(repo, &["commit", "-q", "-m", &format!("add {file}")], &[])
    }

    /// Whether HEAD's signature verifies with the agent key.
    fn head_verifies(&self, repo: &Path) -> bool {
        let key = fs::read_to_string(self.home.join(".agent-sign/keys/agent_ed25519.pub")).unwrap();
        let signers = self.home.join("allowed_signers");
        fs::write(&signers, format!("person@example.com {}\n", key.trim())).unwrap();
        let out = git(
            repo,
            &[
                "-c",
                &format!("gpg.ssh.allowedSignersFile={}", signers.display()),
                "log",
                "-1",
                "--format=%G?",
            ],
        );
        String::from_utf8_lossy(&out.stdout).trim() == "G"
    }
}

fn commits(repo: &Path) -> usize {
    String::from_utf8_lossy(&git(repo, &["rev-list", "--count", "HEAD"]).stdout)
        .trim()
        .parse()
        .unwrap()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).to_string()
}

fn assert_refused(out: &Output, repo: &Path, before: usize, why: &str) {
    assert!(!out.status.success(), "expected a refusal ({why})");
    assert_eq!(
        commits(repo),
        before,
        "a refused commit must not exist ({why})"
    );
    assert!(
        stderr(out).to_lowercase().contains(&why.to_lowercase()),
        "refusal should say {why:?}: {}",
        stderr(out)
    );
}

// --- F4: fails closed ---------------------------------------------------

#[test]
fn denied_refuses_and_makes_no_commit() {
    let s = Setup::new("", false);
    s.answer(DENY);
    let repo = s.repo("r", "feat/a");
    let out = s.agent_commit(&repo, "a.txt");
    assert_refused(&out, &repo, 1, "denied");
}

#[test]
fn a_revoked_lease_asks_again_and_a_denial_then_refuses() {
    let s = Setup::new("", false);
    let repo = s.repo("r", "feat/a");
    assert!(s.agent_commit(&repo, "a.txt").status.success());

    let key = fs::canonicalize(&repo).unwrap().display().to_string();
    let revoked = send_request(
        &s.socket,
        &Request::RevokeLease {
            repo: key,
            branch: None,
            all: false,
        },
    )
    .unwrap();
    assert!(matches!(revoked, Response::Success));

    s.answer(DENY);
    let out = s.agent_commit(&repo, "b.txt");
    assert_refused(&out, &repo, 2, "denied");
    assert_eq!(s.times_asked(), 2);
}

#[test]
fn an_ended_lease_asks_again() {
    let s = Setup::new(
        "[security]\nlease_mode = \"timed\"\ndefault_lease_duration = \"2s\"\n",
        false,
    );
    let repo = s.repo("r", "feat/a");
    assert!(s.agent_commit(&repo, "a.txt").status.success());
    assert!(s.agent_commit(&repo, "b.txt").status.success());
    assert_eq!(s.times_asked(), 1);

    std::thread::sleep(Duration::from_millis(3100));
    s.answer(DENY);
    let out = s.agent_commit(&repo, "c.txt");
    assert_refused(&out, &repo, 3, "denied");
    assert_eq!(s.times_asked(), 2);
}

#[test]
fn a_forged_or_reused_token_signs_nothing() {
    let s = Setup::new("", true);
    let buffer = "dHJlZQ==".to_string(); // "tree", base64
    let forged = send_request(
        &s.socket,
        &Request::SignCommit {
            token: "ev_00000000-0000-0000-0000-000000000000".into(),
            buffer_b64: buffer.clone(),
        },
    )
    .unwrap();
    assert!(matches!(forged, Response::Error { .. }), "{forged:?}");

    let granted = send_request(
        &s.socket,
        &Request::RequestLease {
            repo: "/w/r".into(),
            branch: "feat/a".into(),
            intent: "t".into(),
            duration_secs: None,
        },
    )
    .unwrap();
    assert!(matches!(granted, Response::LeaseGranted { .. }));
    let Response::TokenIssued { token } = send_request(
        &s.socket,
        &Request::IssueToken {
            repo: "/w/r".into(),
            branch: "feat/a".into(),
        },
    )
    .unwrap() else {
        panic!("no token");
    };
    let first = send_request(
        &s.socket,
        &Request::SignCommit {
            token: token.clone(),
            buffer_b64: buffer.clone(),
        },
    )
    .unwrap();
    assert!(matches!(first, Response::Signed { .. }), "{first:?}");
    let again = send_request(
        &s.socket,
        &Request::SignCommit {
            token,
            buffer_b64: buffer,
        },
    )
    .unwrap();
    assert!(matches!(again, Response::Error { .. }), "{again:?}");
}

#[test]
fn a_stopped_service_refuses_after_a_short_wait_and_makes_no_commit() {
    let mut s = Setup::new("", true);
    let repo = s.repo("r", "feat/a");
    assert!(s.agent_commit(&repo, "a.txt").status.success());
    s.stop_service();

    fs::write(repo.join("b.txt"), "b\n").unwrap();
    git_ok(&repo, &["add", "b.txt"]);
    let start = Instant::now();
    let out = s.agent_git(
        &repo,
        &["commit", "-q", "-m", "b"],
        &[("AGENT_SIGN_CONNECT_WAIT_MS", "300")],
    );
    assert!(start.elapsed() < Duration::from_secs(5));
    assert!(!out.status.success());
    assert_eq!(commits(&repo), 2);
}

// --- F5: the rules refuse with a reason ------------------------------------

#[test]
fn a_protected_branch_is_refused_without_asking() {
    let s = Setup::new("", false);
    let repo = s.repo("r", "main");
    let out = s.agent_commit(&repo, "a.txt");
    assert_refused(&out, &repo, 1, "protected");
    assert_eq!(s.times_asked(), 0);
}

#[test]
fn ci_workflows_and_key_files_are_refused() {
    let s = Setup::new("", true);
    let repo = s.repo("r", "feat/a");
    let out = s.agent_commit(&repo, ".github/workflows/ci.yml");
    assert_refused(&out, &repo, 1, "forbidden path");
    git_ok(&repo, &["reset", "-q"]);
    let out = s.agent_commit(&repo, "deploy.pem");
    assert_refused(&out, &repo, 1, "forbidden path");
}

#[test]
fn a_diff_over_a_limit_the_person_set_is_refused() {
    let s = Setup::new("[security]\nmax_diff_lines = 5\n", true);
    let repo = s.repo("r", "feat/a");
    fs::write(repo.join("big.txt"), "x\n".repeat(50)).unwrap();
    git_ok(&repo, &["add", "big.txt"]);
    let out = s.agent_git(&repo, &["commit", "-q", "-m", "big"], &[]);
    assert_refused(&out, &repo, 1, "more than the limit you set");
}

#[test]
fn commits_over_the_rate_limit_are_refused() {
    let s = Setup::new("[security]\nmax_commits_per_minute = 2\n", true);
    let repo = s.repo("r", "feat/a");
    assert!(s.agent_commit(&repo, "a.txt").status.success());
    assert!(s.agent_commit(&repo, "b.txt").status.success());
    let out = s.agent_commit(&repo, "c.txt");
    assert_refused(&out, &repo, 3, "rate limit");
}

// --- F8: edge cases ---------------------------------------------------------

#[test]
fn a_path_with_spaces_and_accents_signs_and_verifies() {
    let s = Setup::new("", true);
    let repo = s.repo("my projects/naïve café", "feat/a");
    let out = s.agent_commit(&repo, "notes and ideas.txt");
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(s.head_verifies(&repo));
}

#[test]
fn a_repository_reached_through_a_symlink_is_one_repository() {
    let s = Setup::new("", false);
    let repo = s.repo("real", "feat/a");
    let link = s.home.join("link");
    std::os::unix::fs::symlink(&repo, &link).unwrap();
    assert!(s.agent_commit(&repo, "a.txt").status.success());
    assert!(s.agent_commit(&link, "b.txt").status.success());
    assert_eq!(s.times_asked(), 1, "the link must use the same lease");
}

#[test]
fn a_worktree_commit_signs_and_verifies() {
    let s = Setup::new("", true);
    let repo = s.repo("r", "feat/a");
    let wt = s.home.join("r-wt");
    git_ok(
        &repo,
        &[
            "worktree",
            "add",
            "-q",
            wt.to_str().unwrap(),
            "-b",
            "feat/wt",
        ],
    );
    let out = s.agent_commit(&wt, "w.txt");
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(s.head_verifies(&wt));
}

#[test]
fn a_detached_head_commit_signs_and_verifies() {
    let s = Setup::new("", true);
    let repo = s.repo("r", "feat/a");
    git_ok(&repo, &["checkout", "-q", "--detach"]);
    let out = s.agent_commit(&repo, "d.txt");
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(s.head_verifies(&repo));
}

#[test]
fn an_amended_commit_is_signed_again() {
    let s = Setup::new("", true);
    let repo = s.repo("r", "feat/a");
    assert!(s.agent_commit(&repo, "a.txt").status.success());
    let out = s.agent_git(&repo, &["commit", "-q", "--amend", "-m", "amended"], &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(s.head_verifies(&repo));
}

#[test]
fn two_hundred_commits_in_a_row_all_sign() {
    let s = Setup::new("[security]\nmax_commits_per_minute = 1000\n", true);
    let repo = s.repo("r", "feat/a");
    for i in 0..200 {
        let out = s.agent_commit(&repo, &format!("f{i}.txt"));
        assert!(out.status.success(), "commit {i}: {}", stderr(&out));
    }
    assert_eq!(commits(&repo), 201);
    assert!(s.head_verifies(&repo));
}

#[test]
fn two_agents_committing_at_once_in_two_repositories_all_sign() {
    let s = Setup::new("[security]\nmax_commits_per_minute = 1000\n", true);
    let a = s.repo("a", "feat/a");
    let b = s.repo("b", "feat/b");
    std::thread::scope(|scope| {
        for repo in [&a, &b] {
            let s = &s;
            scope.spawn(move || {
                for i in 0..25 {
                    let out = s.agent_commit(repo, &format!("f{i}.txt"));
                    assert!(out.status.success(), "{}", stderr(&out));
                }
            });
        }
    });
    assert_eq!(commits(&a), 26);
    assert_eq!(commits(&b), 26);
    assert!(s.head_verifies(&a) && s.head_verifies(&b));
}

#[test]
fn a_restart_between_commits_keeps_the_lease() {
    let mut s = Setup::new("", false);
    let repo = s.repo("r", "feat/a");
    let first = s.agent_commit(&repo, "a.txt");
    assert!(first.status.success(), "{}", stderr(&first));
    s.stop_service();
    s.start_service(false);
    assert!(s.agent_commit(&repo, "b.txt").status.success());
    assert_eq!(s.times_asked(), 1);
}

// --- Who is committing, in a real terminal ---------------------------------

impl Setup {
    /// Runs the wrapper's `commit` inside a real terminal (via `script`), as
    /// a person typing it, or an agent running in a terminal pane, would.
    fn commit_in_a_terminal(&self, repo: &Path, file: &str, marks: &[(&str, &str)]) -> Output {
        fs::write(repo.join(file), format!("{file}\n")).unwrap();
        git_ok(repo, &["add", file]);
        let wrapper = env!("CARGO_BIN_EXE_agent-git");
        let mut cmd = Command::new("script");
        if cfg!(target_os = "macos") {
            cmd.args(["-q", "/dev/null", wrapper, "commit", "-q", "-m", file]);
        } else {
            cmd.args([
                "-qec",
                &format!("{wrapper} commit -q -m {file}"),
                "/dev/null",
            ]);
        }
        cmd.current_dir(repo)
            .env("HOME", &self.home)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("AGENT_SIGN_SOCKET", &self.socket)
            .env("AGENT_SIGN_BIN", env!("CARGO_BIN_EXE_agent-ssh-sign"))
            .stdin(Stdio::null());
        for (var, _) in KNOWN_AGENTS {
            cmd.env_remove(var);
        }
        for (k, v) in marks {
            cmd.env(k, v);
        }
        cmd.output().unwrap()
    }
}

fn head_signature_status(repo: &Path) -> String {
    String::from_utf8_lossy(&git(repo, &["log", "-1", "--format=%G?"]).stdout)
        .trim()
        .to_string()
}

#[test]
fn a_terminal_commit_with_no_agent_mark_is_left_to_the_person() {
    let s = Setup::new("", true);
    let repo = s.repo("r", "feat/a");
    let out = s.commit_in_a_terminal(&repo, "mine.txt", &[]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert_eq!(commits(&repo), 2);
    // The person's own git, with this test's empty config: not signed, and
    // certainly not with the agent key.
    assert_eq!(head_signature_status(&repo), "N");
}

#[test]
fn an_agent_in_a_terminal_pane_is_still_treated_as_an_agent() {
    let s = Setup::new("", true);
    let repo = s.repo("r", "feat/a");
    let out = s.commit_in_a_terminal(&repo, "agents.txt", &[("CLAUDECODE", "1")]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert_eq!(commits(&repo), 2);
    assert!(s.head_verifies(&repo), "signed with the agent key");
}

// --- Every lease ends --------------------------------------------------------

#[test]
fn unfinished_work_keeps_its_approval() {
    let s = Setup::new("", false);
    let repo = s.repo("r", "feat/a");
    for f in ["a.txt", "b.txt", "c.txt"] {
        assert!(s.agent_commit(&repo, f).status.success());
    }
    assert_eq!(s.times_asked(), 1);
}

#[test]
fn merging_the_work_ends_its_approval() {
    let s = Setup::new("", false);
    let repo = s.repo("r", "feat/a");
    assert!(s.agent_commit(&repo, "a.txt").status.success());
    // The person merges the agent's branch into main.
    git_ok(&repo, &["checkout", "-q", "main"]);
    git_ok(
        &repo,
        &["merge", "-q", "--no-ff", "-m", "merge feat/a", "feat/a"],
    );
    git_ok(&repo, &["checkout", "-q", "feat/a"]);
    // The next agent commit asks again.
    assert!(s.agent_commit(&repo, "b.txt").status.success());
    assert_eq!(s.times_asked(), 2);
}

#[test]
fn deleting_the_branch_ends_its_approval() {
    let s = Setup::new("", false);
    let repo = s.repo("r", "feat/a");
    assert!(s.agent_commit(&repo, "a.txt").status.success());
    git_ok(&repo, &["checkout", "-q", "-b", "feat/b"]);
    git_ok(&repo, &["branch", "-q", "-D", "feat/a"]);
    assert!(s.agent_commit(&repo, "b.txt").status.success());
    assert_eq!(s.times_asked(), 2);
}

#[test]
fn an_approval_unused_past_the_backstop_asks_again() {
    let s = Setup::new("[security]\nend_after_idle = \"2s\"\n", false);
    let repo = s.repo("r", "feat/a");
    assert!(s.agent_commit(&repo, "a.txt").status.success());
    std::thread::sleep(Duration::from_millis(3100));
    assert!(s.agent_commit(&repo, "b.txt").status.success());
    assert_eq!(s.times_asked(), 2);
}

#[test]
fn an_unreadable_backstop_stops_the_service_instead_of_dropping_it() {
    let dir = tempdir().unwrap();
    let state = dir.path().join(".agent-sign");
    fs::create_dir_all(&state).unwrap();
    fs::write(
        state.join("config.toml"),
        "[security]\nend_after_idle = \"soon\"\n",
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_agent-signd"))
        .arg("--socket")
        .arg(dir.path().join("s.sock"))
        .env("HOME", dir.path())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("end_after_idle"));
}

// --- No size limit unless the person sets one ------------------------------

#[test]
fn by_default_a_commit_of_any_size_is_signed() {
    // A generated lockfile is often thousands of lines; nothing about signing
    // limits a commit's size, so by default nothing here does either.
    let s = Setup::new("", true);
    let repo = s.repo("r", "feat/a");
    fs::write(
        repo.join("package-lock.json"),
        "  \"x\": 1,\n".repeat(20_000),
    )
    .unwrap();
    git_ok(&repo, &["add", "package-lock.json"]);
    let out = s.agent_git(&repo, &["commit", "-q", "-m", "lockfile"], &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(s.head_verifies(&repo));
}
