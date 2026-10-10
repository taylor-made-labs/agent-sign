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
                "echo shown >> '{l}'\necho \"$@\" >> '{l}.text'\nread -r A < '{a}'\n[ \"$A\" = {DENY} ] && echo false || echo \"$A\""
            ),
        );
        write_script(
            &fakebin.join("zenity"),
            &format!(
                "echo shown >> '{l}'\necho \"$@\" >> '{l}.text'\nread -r A < '{a}'\n[ \"$A\" = {DENY} ] && exit 1\necho \"$A\""
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
                start.elapsed() < Duration::from_secs(20),
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
    // (A second commit inside the 2 seconds isn't checked here: on a busy
    // machine it can land after them. Commits inside a lease asking nothing
    // is covered by the approval-scope tests.)
    assert!(s.agent_commit(&repo, "a.txt").status.success());
    assert_eq!(s.times_asked(), 1);

    std::thread::sleep(Duration::from_millis(3100));
    s.answer(DENY);
    let out = s.agent_commit(&repo, "c.txt");
    assert_refused(&out, &repo, 2, "denied");
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

#[test]
fn the_lease_list_says_how_each_lease_ends() {
    let s = Setup::new("", true);
    let repo = s.repo("r", "feat/a");
    assert!(s.agent_commit(&repo, "a.txt").status.success());
    let out = Command::new(env!("CARGO_BIN_EXE_agent-sign"))
        .arg("leases")
        .env("HOME", &s.home)
        .env("AGENT_SIGN_SOCKET", &s.socket)
        .output()
        .unwrap();
    let listed = String::from_utf8_lossy(&out.stdout);
    assert!(!listed.contains("when revoked"), "{listed}");
    assert!(
        listed.contains(
            "when branch 'feat/a' is merged or deleted, after 7 days with no agent commits, \
             or when you turn it off (agent-sign revoke)"
        ),
        "{listed}"
    );
}

// --- Commits that ask not to be signed never ask the person -----------------

#[test]
fn a_commit_with_signing_off_on_the_command_line_never_asks() {
    let s = Setup::new("", false);
    let repo = s.repo("r", "feat/a");
    fs::write(repo.join("t.txt"), "t\n").unwrap();
    git_ok(&repo, &["add", "t.txt"]);
    let out = s.agent_git(
        &repo,
        &["-c", "commit.gpgsign=false", "commit", "-q", "-m", "t"],
        &[],
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(head_signature_status(&repo), "N");
    assert_eq!(s.times_asked(), 0);
}

#[test]
fn a_commit_with_no_gpg_sign_never_asks() {
    let s = Setup::new("", false);
    let repo = s.repo("r", "feat/a");
    fs::write(repo.join("t.txt"), "t\n").unwrap();
    git_ok(&repo, &["add", "t.txt"]);
    let out = s.agent_git(&repo, &["commit", "-q", "--no-gpg-sign", "-m", "t"], &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(s.times_asked(), 0);
}

#[test]
fn a_test_fixture_repository_with_signing_off_never_asks_even_on_main() {
    // What cas's tests do: a throwaway repository with signing turned off,
    // committing on main, many times.
    let s = Setup::new("", false);
    let repo = s.repo("fixture", "main");
    git_ok(&repo, &["config", "commit.gpgsign", "false"]);
    for i in 0..5 {
        fs::write(repo.join(format!("f{i}.txt")), "x\n").unwrap();
        git_ok(&repo, &["add", "."]);
        let out = s.agent_git(&repo, &["commit", "-q", "-m", "fixture"], &[]);
        assert!(out.status.success(), "{}", stderr(&out));
    }
    assert_eq!(s.times_asked(), 0);
}

#[test]
fn signing_off_in_the_persons_global_config_still_signs_agent_commits() {
    let s = Setup::new("", false);
    let repo = s.repo("r", "feat/a");
    let global = s.home.join("global.gitconfig");
    fs::write(&global, "[commit]\n\tgpgsign = false\n").unwrap();
    fs::write(repo.join("t.txt"), "t\n").unwrap();
    git_ok(&repo, &["add", "t.txt"]);
    let out = s.agent_git(
        &repo,
        &["commit", "-q", "-m", "t"],
        &[("GIT_CONFIG_GLOBAL", global.to_str().unwrap())],
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(s.times_asked(), 1);
    assert!(s.head_verifies(&repo));
}

// --- The repository a commit is for, however git is pointed at it -----------

impl Setup {
    /// Everything the dialogs were shown, as one string.
    fn dialog_text(&self) -> String {
        fs::read_to_string(self.home.join("dialog.log.text")).unwrap_or_default()
    }

    /// The wrapper's `commit` run from `cwd` with `args` before `commit`.
    fn agent_commit_from(&self, cwd: &Path, global: &[&str], extra_env: &[(&str, &str)]) -> Output {
        let mut args: Vec<&str> = global.to_vec();
        args.extend(["commit", "-q", "-m", "from elsewhere"]);
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_agent-git"));
        cmd.args(&args)
            .current_dir(cwd)
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

    fn lease_repos(&self) -> Vec<String> {
        match send_request(&self.socket, &Request::ListLeases).unwrap() {
            Response::LeaseList { leases } => leases.into_iter().map(|l| l.repo).collect(),
            other => panic!("unexpected {other:?}"),
        }
    }
}

fn stage(repo: &Path, file: &str) {
    fs::write(repo.join(file), "x\n").unwrap();
    git_ok(repo, &["add", file]);
}

#[test]
fn a_commit_pointed_at_a_repository_with_dash_c_names_that_repository() {
    let s = Setup::new("", false);
    let repo = s.repo("r", "feat/a");
    stage(&repo, "a.txt");
    let elsewhere = s.home.join("not-a-repo");
    fs::create_dir_all(&elsewhere).unwrap();
    let out = s.agent_commit_from(&elsewhere, &["-C", repo.to_str().unwrap()], &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    let canonical = fs::canonicalize(&repo).unwrap().display().to_string();
    assert_eq!(s.lease_repos(), vec![canonical.clone()]);
    let shown = s.dialog_text();
    assert!(shown.contains(&canonical), "{shown}");
    assert!(shown.contains("feat/a"), "{shown}");
    assert!(!shown.contains("default-repo"), "{shown}");
    assert!(s.head_verifies(&repo));
}

#[test]
fn a_commit_pointed_at_a_repository_with_git_dir_names_that_repository() {
    let s = Setup::new("", false);
    let repo = s.repo("r", "feat/a");
    stage(&repo, "a.txt");
    let elsewhere = s.home.join("not-a-repo");
    fs::create_dir_all(&elsewhere).unwrap();
    let git_dir = repo.join(".git");
    let out = s.agent_commit_from(
        &elsewhere,
        &[],
        &[
            ("GIT_DIR", git_dir.to_str().unwrap()),
            ("GIT_WORK_TREE", repo.to_str().unwrap()),
        ],
    );
    assert!(out.status.success(), "{}", stderr(&out));
    let canonical = fs::canonicalize(&repo).unwrap().display().to_string();
    assert_eq!(s.lease_repos(), vec![canonical]);
}

#[test]
fn a_commit_whose_repository_cant_be_identified_is_refused_without_asking() {
    let s = Setup::new("", false);
    let elsewhere = s.home.join("not-a-repo");
    fs::create_dir_all(&elsewhere).unwrap();
    let out = s.agent_commit_from(&elsewhere, &[], &[]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("couldn't identify the repository"),
        "{}",
        stderr(&out)
    );
    assert_eq!(s.times_asked(), 0);
    assert!(s.lease_repos().is_empty());
}

#[test]
fn the_service_refuses_a_request_without_a_real_repository_path() {
    let s = Setup::new("", false);
    for repo in ["default-repo", "", "relative/path"] {
        let resp = send_request(
            &s.socket,
            &Request::RequestLease {
                repo: repo.into(),
                branch: "feat/a".into(),
                intent: "t".into(),
                duration_secs: None,
            },
        )
        .unwrap();
        match resp {
            Response::Error { message } => assert!(message.contains("repository"), "{message}"),
            other => panic!("{repo:?} should be refused, got {other:?}"),
        }
    }
    assert_eq!(s.times_asked(), 0);
}

#[test]
fn the_dialog_shows_no_placeholder_reason() {
    let s = Setup::new("", false);
    let repo = s.repo("r", "feat/a");
    assert!(s.agent_commit(&repo, "a.txt").status.success());
    let shown = s.dialog_text();
    assert!(!shown.contains("Autonomous coding agent commit"), "{shown}");
    assert!(!shown.contains("Reason given by the agent"), "{shown}");
}

// --- The person's own key is never used for an agent's commit ---------------
//
// From the 10 Oct security review: commits the wrapper took for "signing
// off" could still be signed by git with the person's own signer, through
// option forms the wrapper parsed differently from git.

impl Setup {
    /// A global git config for "the person": signs every commit by default,
    /// with a stand-in signer that records each call. Returns (config, log).
    fn persons_signing(&self) -> (PathBuf, PathBuf) {
        let log = self.home.join("persons-signer.log");
        let signer = self.home.join("persons-signer");
        fs::write(
            &signer,
            format!("#!/bin/sh\necho called >> '{}'\nexit 1\n", log.display()),
        )
        .unwrap();
        fs::set_permissions(&signer, fs::Permissions::from_mode(0o755)).unwrap();
        let config = self.home.join("persons.gitconfig");
        fs::write(
            &config,
            format!(
                "[user]\n\tsigningkey = ~/.ssh/persons_key.pub\n[gpg]\n\tformat = ssh\n[gpg \"ssh\"]\n\tprogram = {}\n[commit]\n\tgpgsign = true\n",
                signer.display()
            ),
        )
        .unwrap();
        (config, log)
    }
}

#[test]
fn no_option_form_reaches_the_persons_signer() {
    let s = Setup::new("", false);
    s.answer(DENY);
    let (persons, log) = s.persons_signing();
    let repo = s.repo("r", "feat/a");
    let off_file = s.home.join("off.gitconfig");
    fs::write(&off_file, "[commit]\n\tgpgsign = false\n").unwrap();
    let persons = persons.to_str().unwrap();

    // (args, set commit.gpgsign=false in the repository first, extra env)
    type Case<'a> = (Vec<&'a str>, bool, Vec<(&'a str, &'a str)>);
    let cases: Vec<Case> = vec![
        (
            vec!["commit", "-a", "--no-gpg-sign", "-qS", "-m", "x"],
            false,
            vec![],
        ),
        (vec!["commit", "-aS", "-m", "x"], true, vec![]),
        (vec!["commit", "-a", "--gpg", "-m", "x"], true, vec![]),
        (
            vec!["commit", "-a", "-m", "x"],
            false,
            vec![("GIT_CONFIG", off_file.to_str().unwrap())],
        ),
        (vec!["commit", "-a", "-m", "--no-gpg-sign"], false, vec![]),
        (
            vec![
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-a",
                "-S",
                "-m",
                "x",
            ],
            false,
            vec![],
        ),
    ];
    for (i, (args, local_off, env)) in cases.into_iter().enumerate() {
        let _ = git(&repo, &["config", "--unset-all", "commit.gpgsign"]);
        if local_off {
            git_ok(&repo, &["config", "commit.gpgsign", "false"]);
        }
        fs::write(repo.join("t.txt"), format!("{i}\n")).unwrap();
        git_ok(&repo, &["add", "t.txt"]);
        let mut extra: Vec<(&str, &str)> = vec![("GIT_CONFIG_GLOBAL", persons)];
        extra.extend(env);
        let _ = s.agent_git(&repo, &args, &extra);
        assert_eq!(
            fs::read_to_string(&log).unwrap_or_default(),
            "",
            "case {i} {args:?} called the person's signer"
        );
    }
}

#[test]
fn a_lease_for_one_repository_never_signs_a_dash_c_commit_to_anothers_main() {
    // An agent approved in repository A commits with -C into repository B,
    // which is on main. Before 10 Oct the wrapper read the branch from A
    // (the working folder) and signed B's main with A's lease.
    let s = Setup::new("", true);
    let a = s.repo("a", "feat/a");
    assert!(s.agent_commit(&a, "a.txt").status.success());
    let b = s.repo("b", "main");
    stage(&b, "b.txt");
    let out = s.agent_commit_from(&a, &["-C", b.to_str().unwrap()], &[]);
    assert!(
        !out.status.success(),
        "a -C commit to another repository's main was signed"
    );
    assert!(stderr(&out).contains("protected"), "{}", stderr(&out));
    assert_eq!(commits(&b), 1);
}

#[test]
fn a_dash_c_commit_asks_for_the_other_repository_not_the_working_one() {
    let s = Setup::new("", false);
    let a = s.repo("a", "feat/a");
    assert!(s.agent_commit(&a, "a.txt").status.success());
    assert_eq!(s.times_asked(), 1);
    let b = s.repo("b", "feat/b");
    stage(&b, "b.txt");
    let out = s.agent_commit_from(&a, &["-C", b.to_str().unwrap()], &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(s.times_asked(), 2, "B needs its own approval");
}

// --- The rules see what the commit will actually contain --------------------

#[test]
fn a_ci_workflow_changed_and_committed_with_dash_a_is_refused() {
    let s = Setup::new("", true);
    let repo = s.repo("r", "main");
    fs::create_dir_all(repo.join(".github/workflows")).unwrap();
    fs::write(repo.join(".github/workflows/ci.yml"), "on: push\n").unwrap();
    git_ok(&repo, &["add", "."]);
    git_ok(&repo, &["commit", "-q", "-m", "the person adds CI"]);
    git_ok(&repo, &["checkout", "-q", "-b", "feat/a"]);
    // The agent changes the workflow but doesn't stage it; -a commits it.
    fs::write(
        repo.join(".github/workflows/ci.yml"),
        "on: [push, pull_request]\n",
    )
    .unwrap();
    let out = s.agent_git(&repo, &["commit", "-q", "-a", "-m", "tweak"], &[]);
    assert!(
        !out.status.success(),
        "a workflow change committed with -a got through"
    );
    assert!(stderr(&out).contains("forbidden path"), "{}", stderr(&out));
}

#[test]
fn the_rules_apply_with_a_separate_git_dir_and_work_tree() {
    let s = Setup::new("", true);
    let repo = s.repo("r", "feat/a");
    // The repository's git folder kept apart from its files, as with
    // GIT_DIR setups: the work tree has no .git at all.
    let git_dir_path = s.home.join("r.git");
    fs::rename(repo.join(".git"), &git_dir_path).unwrap();
    let git_dir = format!("--git-dir={}", git_dir_path.display());
    let work_tree = format!("--work-tree={}", repo.display());
    fs::write(repo.join("deploy.pem"), "key\n").unwrap();
    let staged = Command::new(real_git())
        .args([&git_dir, &work_tree, "add", "deploy.pem"])
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .status()
        .unwrap();
    assert!(staged.success());
    let elsewhere = s.home.join("not-a-repo");
    fs::create_dir_all(&elsewhere).unwrap();
    let out = s.agent_commit_from(&elsewhere, &[&git_dir, &work_tree], &[]);
    assert!(
        !out.status.success(),
        "a key file got through with --git-dir"
    );
    assert!(stderr(&out).contains("forbidden path"), "{}", stderr(&out));
}

// --- Every way of running `commit` goes through the wrapper -----------------

#[test]
fn a_commit_after_global_options_with_values_is_still_an_agent_commit() {
    let s = Setup::new("", true);
    let (persons, log) = s.persons_signing();
    let repo = s.repo("r", "feat/a");
    let persons = persons.to_str().unwrap();
    for (i, global) in [
        vec!["--namespace", "ns"],
        vec!["--config-env", "user.name=HOME"],
        vec!["--attr-source", "HEAD"],
    ]
    .into_iter()
    .enumerate()
    {
        stage(&repo, &format!("g{i}.txt"));
        let mut args: Vec<&str> = global.clone();
        args.extend(["commit", "-q", "-m", "x"]);
        let out = s.agent_git(&repo, &args, &[("GIT_CONFIG_GLOBAL", persons)]);
        assert!(out.status.success(), "{global:?}: {}", stderr(&out));
        assert_eq!(
            fs::read_to_string(&log).unwrap_or_default(),
            "",
            "{global:?} used the person's signer"
        );
        assert!(
            s.head_verifies(&repo),
            "{global:?} wasn't signed with the agent key"
        );
    }
}

#[test]
fn a_commit_through_an_alias_is_still_an_agent_commit() {
    let s = Setup::new("", true);
    let (persons, log) = s.persons_signing();
    let repo = s.repo("r", "feat/a");
    git_ok(&repo, &["config", "alias.ci", "commit -q"]);
    stage(&repo, "a.txt");
    let out = s.agent_git(
        &repo,
        &["ci", "-m", "via alias"],
        &[("GIT_CONFIG_GLOBAL", persons.to_str().unwrap())],
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(fs::read_to_string(&log).unwrap_or_default(), "");
    assert!(s.head_verifies(&repo));
}

#[test]
fn a_path_with_markup_characters_is_shown_as_written() {
    // zenity (Linux) reads its text as markup; an unescaped "&" blanks it.
    let s = Setup::new("", false);
    let repo = s.repo("R&D <lab>", "feat/a");
    assert!(s.agent_commit(&repo, "a.txt").status.success());
    let shown = s.dialog_text();
    if cfg!(target_os = "linux") {
        assert!(shown.contains("R&amp;D &lt;lab&gt;"), "{shown}");
    } else {
        assert!(shown.contains("R&D <lab>"), "{shown}");
    }
}
