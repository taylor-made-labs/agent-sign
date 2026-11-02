//! The speed check (plan check 7, backlog d37fd952): an agent commit must not
//! cost more git runs as leases pile up.
//!
//! Before each token and each signature the service used to look over every
//! open lease to see whether its work was finished, about 10 git runs per
//! lease. On a Mac each git run through launchd's `PATH` costs about 0.14 s,
//! so 11 leases made a commit wait 8 to 15 seconds. The count of git runs is
//! the same on every OS, so it is what these tests measure: they put a
//! counting shim in the place of git for the service, one log line per run,
//! and count the lines one agent commit adds.
//!
//! The setup is a real service, a real git wrapper (`agent-git`) and real
//! throwaway repositories in a temporary home, like `test_e2e_git_commit.rs`.
//! Nothing here touches the real `~/.agent-sign` or any running service.
//!
//! Two counting shims, so the service's git runs can be told apart from the
//! git wrapper's own:
//!
//! - the service gets `AGENT_SIGN_REAL_GIT` pointing at shim D (log D), and
//!   a `git` shim first on its `PATH` that writes log P. The rule in the plan
//!   is that the service runs *every* git through `paths::real_git()`, which
//!   honours `AGENT_SIGN_REAL_GIT`, so after the fix log P stays empty.
//!   Today `work.rs` runs `Command::new("git")` (through `PATH`), so its
//!   runs land in P: the service's count is D + P.
//! - the git wrapper and the programs git starts for it get shim C.
//!
//! The agent is Claude Code (`CLAUDECODE=1`), a built-in tool slug, so these
//! tests keep working when only listed agent names are allowed (plan check 6).

// DELIBERATE EVAL CHANGE: these tests start their agent with `agent-sign launch`, and the launcher exists only on
// Linux (no launcher on macOS yet, listed in the README's gaps), so they run only where the launcher exists.
#![cfg(target_os = "linux")]

#[path = "support/die_with_parent.rs"]
mod die_with_parent;
use die_with_parent::DieWithParent;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use agent_sign::protocol::{Request, Response, send_request};
use tempfile::{TempDir, tempdir};

/// The real git, never a wrapper earlier on PATH.
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

/// Runs the real git in `repo`, isolated from the machine's own config.
fn git(repo: &Path, args: &[&str]) -> String {
    let out = Command::new(real_git())
        .args(args)
        .current_dir(repo)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", "P")
        .env("GIT_AUTHOR_EMAIL", "p@example.com")
        .env("GIT_COMMITTER_NAME", "P")
        .env("GIT_COMMITTER_EMAIL", "p@example.com")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// A shell script that appends one line per run to `log`, then runs the real
/// git with the same arguments.
fn write_shim(path: &Path, log: &Path) {
    fs::write(
        path,
        format!(
            "#!/bin/sh\necho \"$$ $*\" >> '{}'\nexec '{}' \"$@\"\n",
            log.display(),
            real_git()
        ),
    )
    .unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

/// A shell script that appends one line per run to the file named by the
/// environment variable `var`, then runs the real git with the same
/// arguments. For a git run inside a launched session, which may write only
/// its own working copy: the log is a file in the repository's git folder,
/// named by the test for each commit.
fn write_shim_logging_to_env(path: &Path, var: &str) {
    fs::write(
        path,
        format!(
            "#!/bin/sh\necho \"$$ $*\" >> \"${var}\"\nexec '{}' \"$@\"\n",
            real_git()
        ),
    )
    .unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

/// How many runs a shim's log holds.
fn runs(log: &Path) -> usize {
    fs::read_to_string(log)
        .map(|s| s.lines().count())
        .unwrap_or(0)
}

/// A repository on `main` (with a first commit) and a checked-out branch
/// `feat/work-<n>`. Also `master`, `origin/main` and `origin/master` refs at
/// the first commit, so a finished-work check has all four merge targets to
/// look at (the costliest case, about 10 git runs for one lease).
fn make_repo(home: &Path, n: usize) -> PathBuf {
    let repo = home.join(format!("repo{n}"));
    fs::create_dir_all(&repo).unwrap();
    git(&repo, &["init", "-q", "-b", "main"]);
    git(&repo, &["commit", "-q", "--allow-empty", "-m", "first"]);
    let first = git(&repo, &["rev-parse", "HEAD"]);
    git(&repo, &["update-ref", "refs/heads/master", &first]);
    git(&repo, &["update-ref", "refs/remotes/origin/main", &first]);
    git(&repo, &["update-ref", "refs/remotes/origin/master", &first]);
    git(&repo, &["checkout", "-q", "-b", &format!("feat/work-{n}")]);
    repo
}

/// A service in a temporary home, with the counting shims in place.
struct Service {
    dir: TempDir,
    child: Child,
    socket: PathBuf,
    log_d: PathBuf,
    log_p: PathBuf,
    shim_c: PathBuf,
}

impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Service {
    fn start() -> Service {
        let dir = tempdir().unwrap();
        let shims = dir.path().join("shims");
        fs::create_dir_all(&shims).unwrap();
        let (log_d, log_p) = (
            dir.path().join("git-runs-d.log"),
            dir.path().join("git-runs-p.log"),
        );
        let shim_d = shims.join("real-git-d");
        let shim_c = shims.join("real-git-c");
        write_shim(&shim_d, &log_d);
        // DELIBERATE EVAL CHANGE (P7/D1, 1 Nov 2026): agents sign only when
        // launched, and a launched session may write only its own working
        // copy, so the wrapper's shim logs to a file in the repository's git
        // folder that the test names for each commit (`HOT_PATH_LOG_C`), not
        // to a file in the home folder. The count means the same.
        write_shim_logging_to_env(&shim_c, "HOT_PATH_LOG_C");
        // A `git` first on the service's PATH, for any git it runs by name.
        let path_dir = shims.join("path");
        fs::create_dir_all(&path_dir).unwrap();
        write_shim(&path_dir.join("git"), &log_p);

        let socket = dir.path().join("test_daemon.sock");
        // No --auto-approve: approval = "none" is the default and grants
        // leases without asking, which is the case that matters here.
        let child = Command::new(env!("CARGO_BIN_EXE_agent-signd"))
            .die_with_parent()
            .arg("--socket")
            .arg(&socket)
            .env("HOME", dir.path())
            .env("PATH", format!("{}:/usr/bin:/bin", path_dir.display()))
            .env("AGENT_SIGN_REAL_GIT", &shim_d)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to start agent-signd");
        let start = Instant::now();
        while !socket.exists() {
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "the service didn't create its socket in time"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        Service {
            dir,
            child,
            socket,
            log_d,
            log_p,
            shim_c,
        }
    }

    fn home(&self) -> &Path {
        self.dir.path()
    }

    /// Asks the service for a lease on `repo`'s current branch, as the git
    /// wrapper does (approval = "none" grants it without asking).
    fn lease(&self, repo: &Path, branch: &str) {
        let resp = send_request(
            &self.socket,
            &Request::RequestLease {
                repo: repo.to_string_lossy().into_owned(),
                branch: branch.to_string(),
                intent: "test".to_string(),
                duration_secs: None,
            },
        )
        .unwrap();
        assert!(
            matches!(resp, Response::LeaseGranted { .. }),
            "lease for {} {branch}: {resp:?}",
            repo.display()
        );
    }

    /// The (repo, branch) of every open lease, as the service lists them.
    fn listed(&self) -> Vec<(String, String)> {
        match send_request(&self.socket, &Request::ListLeases).unwrap() {
            Response::LeaseList { leases } => {
                leases.into_iter().map(|l| (l.repo, l.branch)).collect()
            }
            other => panic!("unexpected response to ListLeases: {other:?}"),
        }
    }

    /// Opens `open_leases` leases in as many repositories. The first is the
    /// one the agent commits in (fresh: its branch is still where the lease
    /// found it). Every other one has work on its branch since its lease
    /// was granted, so none of them is "nothing new yet" and the finished-work
    /// check has to look at the merge targets.
    fn open_leases(&self, open_leases: usize) -> PathBuf {
        let mut in_use = None;
        for n in 0..open_leases {
            let repo = make_repo(self.home(), n);
            let branch = format!("feat/work-{n}");
            self.lease(&repo, &branch);
            if n == 0 {
                in_use = Some(repo);
            } else {
                git(&repo, &["commit", "-q", "--allow-empty", "-m", "work"]);
            }
        }
        assert_eq!(
            self.listed().len(),
            open_leases,
            "leases open before the commit"
        );
        in_use.expect("at least one lease")
    }

    /// One agent commit in `repo` through the real git wrapper, as Claude
    /// Code. Returns how many git runs the service made through
    /// `AGENT_SIGN_REAL_GIT` and by name (through `PATH`), and how many the
    /// wrapper and the programs git started made: `(service_real_git,
    /// service_by_name, wrapper)`.
    fn agent_commit(&self, repo: &Path) -> (usize, usize, usize) {
        fs::write(repo.join("hello.txt"), "hello from an agent\n").unwrap();
        git(repo, &["add", "hello.txt"]);

        let log_c = repo.join(".git/hot-path-runs-c.log");
        let before = (runs(&self.log_d), runs(&self.log_p), runs(&log_c));
        // DELIBERATE EVAL CHANGE (P7/D1, 1 Nov 2026): agents sign only when
        // launched: a launched Claude Code session (the launcher's own one
        // git run, to find the working copy, is counted with the wrapper's).
        let out = Command::new(env!("CARGO_BIN_EXE_agent-sign"))
            .args(["launch", "--agent", "claude-code", "--"])
            .arg(env!("CARGO_BIN_EXE_agent-git"))
            .args(["commit", "-m", "feat: an agent commit"])
            .current_dir(repo)
            .env_remove("GEMINI_CLI")
            .env_remove("CODEX_THREAD_ID")
            .env_remove("CODEX_SESSION_ID")
            .env_remove("AGENT_SIGN_AGENT_NAME")
            .env("HOT_PATH_LOG_C", &log_c)
            .env("HOME", self.home())
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("AGENT_SIGN_SOCKET", &self.socket)
            .env("AGENT_SIGN_BIN", env!("CARGO_BIN_EXE_agent-ssh-sign"))
            .env("AGENT_SIGN_REAL_GIT", &self.shim_c)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "agent-git commit failed.\nSTDOUT: {}\nSTDERR: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let after = (runs(&self.log_d), runs(&self.log_p), runs(&log_c));

        // The counts mean something only if the commit was really signed.
        let commit = git(repo, &["cat-file", "-p", "HEAD"]);
        assert!(
            commit.contains("gpgsig"),
            "the agent commit wasn't signed:\n{commit}"
        );
        (after.0 - before.0, after.1 - before.1, after.2 - before.2)
    }
}

/// Plan check 7 ("with 20 pieces of work open, an agent commit runs git at
/// most 10 times before it signs"). Fails today because the service looks
/// over every open lease before it issues the token and again before it
/// signs, about 10 git runs per lease, so one commit at 20 leases makes a few
/// hundred runs, not 10 (the number is in the failure message).
#[test]
fn one_agent_commit_at_20_open_leases_runs_git_at_most_10_times_in_the_service() {
    let svc = Service::start();
    let repo = svc.open_leases(20);
    let (by_real_git, by_name, _wrapper) = svc.agent_commit(&repo);
    let service_total = by_real_git + by_name;
    eprintln!(
        "[measured] service git runs for one agent commit at 20 open leases: {service_total} \
         ({by_real_git} through AGENT_SIGN_REAL_GIT, {by_name} by name through PATH)"
    );
    assert!(
        service_total <= 10,
        "one agent commit at 20 open leases made {service_total} git runs in the service \
         ({by_real_git} through AGENT_SIGN_REAL_GIT, {by_name} by name through PATH); \
         the limit is 10"
    );
}

/// Interface item 5 ("runs every git through `paths::real_git()`, which
/// honours `AGENT_SIGN_REAL_GIT`"). Fails today because `work.rs` starts
/// `Command::new("git")`, found through `PATH`, which on a machine with
/// agent-sign installed can be the wrapper (and on a Mac is a slow `xcrun`
/// shim), instead of the real git.
#[test]
fn the_service_runs_every_git_through_the_real_git_path_never_by_name() {
    let svc = Service::start();
    let repo = svc.open_leases(3);
    let (by_real_git, by_name, _wrapper) = svc.agent_commit(&repo);
    // A commit always makes the service run git through the real path (the
    // candidate check does), so the counting shim is known to be wired up.
    assert!(
        by_real_git > 0,
        "the counting shim saw no git run from the service through AGENT_SIGN_REAL_GIT"
    );
    assert_eq!(
        by_name, 0,
        "the service ran git by name {by_name} time(s) through PATH instead of paths::real_git()"
    );
}

/// Plan check 7, second part ("cost must not grow with leases"): one agent
/// commit at 20 open leases makes at most 2 more git runs in total (service,
/// wrapper and the programs git starts) than the same commit at 1 open lease.
/// Fails today because the service's finished-work checks run per open lease,
/// so the 19 extra leases add a couple of hundred runs.
#[test]
fn git_runs_for_one_agent_commit_do_not_grow_with_the_number_of_open_leases() {
    let total = |open: usize| {
        let svc = Service::start();
        let repo = svc.open_leases(open);
        let (d, p, c) = svc.agent_commit(&repo);
        eprintln!(
            "[measured] git runs for one agent commit at {open} open lease(s): service {} ({d} real-git path + {p} by name), wrapper {c}",
            d + p
        );
        d + p + c
    };
    let at_one = total(1);
    let at_twenty = total(20);
    assert!(
        at_twenty <= at_one + 2,
        "git runs for one agent commit: {at_one} at 1 open lease, {at_twenty} at 20 \
         (more than 2 extra means the cost grows with the number of leases)"
    );
}

/// Interface item 5, last sentence ("finished work still ends"). This guards
/// the other side of the speed fix: moving the checks off the commit's path
/// must not stop them. A lease whose branch was merged into `main`, and one
/// whose branch was deleted, are ended once the leases are listed (`agent-sign
/// leases`, which is the service's ListLeases); one still going stays. The
/// service may do the ending in the listing or a moment later in a background
/// sweep, so the lease may go within 15 seconds of the listing.
///
/// Passes today (the check runs in the listing); it must keep passing.
#[test]
fn finished_work_still_ends_once_the_leases_are_listed() {
    let svc = Service::start();
    // Three repositories, each with a lease and work since the lease.
    let mut repos = Vec::new();
    for n in 0..3 {
        let repo = make_repo(svc.home(), n);
        svc.lease(&repo, &format!("feat/work-{n}"));
        git(&repo, &["commit", "-q", "--allow-empty", "-m", "work"]);
        repos.push(repo);
    }
    let canon = |r: &Path| fs::canonicalize(r).unwrap().to_string_lossy().into_owned();
    assert_eq!(svc.listed().len(), 3, "three leases open to start with");

    // Work 0 is merged into main; work 1's branch is deleted; work 2 goes on.
    git(&repos[0], &["checkout", "-q", "main"]);
    git(
        &repos[0],
        &["merge", "-q", "--no-ff", "-m", "merge", "feat/work-0"],
    );
    git(&repos[1], &["checkout", "-q", "main"]);
    git(&repos[1], &["branch", "-q", "-D", "feat/work-1"]);

    // The listing, as a person asks for it.
    let listing = Command::new(env!("CARGO_BIN_EXE_agent-sign"))
        .arg("leases")
        .env("HOME", svc.home())
        .env("AGENT_SIGN_SOCKET", &svc.socket)
        .output()
        .unwrap();
    assert!(
        listing.status.success(),
        "agent-sign leases failed: {}",
        String::from_utf8_lossy(&listing.stderr)
    );

    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let open = svc.listed();
        let gone = |r: &Path| !open.iter().any(|(repo, _)| *repo == canon(r));
        if gone(&repos[0]) && gone(&repos[1]) {
            assert!(
                !gone(&repos[2]),
                "the lease for the work still going was ended too: {open:?}"
            );
            return;
        }
        assert!(
            Instant::now() < deadline,
            "after 15 s the leases for finished work are still open: {open:?}"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}
