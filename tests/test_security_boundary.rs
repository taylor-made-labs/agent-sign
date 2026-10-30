//! Implementation-owner real-object regressions for the 29 October security review.
//! Every process uses a temporary home, empty inherited environment and test
//! identities; no installed signer, real key or user service is contacted.
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use agent_sign::attribution::AgentIdentity;
use agent_sign::config::Config;
use agent_sign::guardrails::validate_candidate;
use agent_sign::lease::{LeaseEngine, LeasePolicy};
use agent_sign::protocol::{Request, Response, send_request};
use base64::Engine;
use sha2::{Digest, Sha256};
use tempfile::{TempDir, tempdir};

fn git_bin() -> &'static str {
    ["/usr/bin/git", "/usr/local/bin/git"]
        .into_iter()
        .find(|p| Path::new(p).is_file())
        .unwrap()
}
fn isolated(program: &Path, home: &Path) -> Command {
    let mut cmd = Command::new(program);
    cmd.env_clear()
        .env("HOME", home)
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("AGENT_SIGN_REAL_GIT", git_bin())
        .stdin(Stdio::null());
    cmd
}
fn git(repo: &Path, args: &[&str]) -> String {
    let out = isolated(Path::new(git_bin()), repo)
        .current_dir(repo)
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}
fn write_exec(path: &Path, text: &str) {
    fs::write(path, text).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}
struct World {
    _dir: TempDir,
    home: PathBuf,
    repo: PathBuf,
    socket: PathBuf,
    service: Child,
}
impl Drop for World {
    fn drop(&mut self) {
        let _ = self.service.kill();
        let _ = self.service.wait();
    }
}
impl World {
    fn new(settings: &str) -> Self {
        let dir = tempdir().unwrap();
        let home = dir.path().to_path_buf();
        let repo = home.join("repo");
        fs::create_dir(&repo).unwrap();
        git(&repo, &["init", "-q", "-b", "work"]);
        git(&repo, &["config", "user.name", "Fixture"]);
        git(&repo, &["config", "user.email", "fixture@example.invalid"]);
        git(
            &repo,
            &[
                "-c",
                "commit.gpgsign=false",
                "commit",
                "--allow-empty",
                "-qm",
                "test: baseline",
            ],
        );
        fs::create_dir(home.join(".agent-sign")).unwrap();
        fs::write(home.join(".agent-sign/config.toml"), settings).unwrap();
        let socket = home.join("service.sock");
        let service = isolated(Path::new(env!("CARGO_BIN_EXE_agent-signd")), &home)
            .arg("--socket")
            .arg(&socket)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let start = Instant::now();
        while !socket.exists() {
            assert!(start.elapsed() < Duration::from_secs(10));
            std::thread::sleep(Duration::from_millis(10));
        }
        Self {
            _dir: dir,
            home,
            repo,
            socket,
            service,
        }
    }
    fn ask(&self, request: Request) -> Response {
        send_request(&self.socket, &request).unwrap()
    }
    fn lease(&self) {
        assert!(matches!(
            self.ask(Request::RequestLease {
                repo: self.repo.display().to_string(),
                branch: "work".into(),
                intent: "isolated boundary regression".into(),
                duration_secs: None
            }),
            Response::LeaseGranted { .. }
        ));
    }
    fn token(&self, run: bool) -> String {
        let repo = self.repo.display().to_string();
        let identity = AgentIdentity::new("fixture", "Fixture Agent", Some("security-boundary"));
        let request = if run {
            Request::IssueRunToken {
                repo,
                branch: "work".into(),
                identity,
            }
        } else {
            Request::IssueIdentifiedToken {
                repo,
                branch: "work".into(),
                identity,
            }
        };
        match self.ask(request) {
            Response::TokenIssued { token } => token,
            answer => panic!("{answer:?}"),
        }
    }
    fn candidate(&self, message: &str) -> Vec<u8> {
        let tree = git(&self.repo, &["write-tree"]);
        let parent = git(&self.repo, &["rev-parse", "HEAD"]);
        format!("tree {tree}\nparent {parent}\nauthor Original Author <original@example.invalid> 1700000000 +0000\ncommitter Fixture <fixture@example.invalid> 1700000000 +0000\n\n{message}\n").into_bytes()
    }
    fn sign(&self, token: &str, candidate: &[u8]) -> Response {
        self.ask(Request::SignCommit {
            token: token.into(),
            buffer_b64: base64::engine::general_purpose::STANDARD.encode(candidate),
            repo: Some(self.repo.display().to_string()),
            branch: Some("work".into()),
        })
    }
    fn wrapper(&self, args: &[&str]) -> Output {
        isolated(Path::new(env!("CARGO_BIN_EXE_agent-git")), &self.home)
            .current_dir(&self.repo)
            .env("AGENT_SIGN_SOCKET", &self.socket)
            .env("AGENT_SIGN_AGENT_NAME", "Fixture Agent")
            .env("AGENT_SIGN_SESSION_ID", "security-boundary")
            .args(args)
            .output()
            .unwrap()
    }
}

#[test]
fn both_token_types_check_the_actual_tree_not_the_current_index() {
    for run in [false, true] {
        let w = World::new("");
        w.lease();
        let token = w.token(run);
        assert!(matches!(
            w.sign(&token, &w.candidate("test: allowed")),
            Response::Signed { .. }
        ));
        fs::create_dir_all(w.repo.join(".github/workflows")).unwrap();
        fs::write(
            w.repo.join(".github/workflows/blocked.yml"),
            "fixture only\n",
        )
        .unwrap();
        git(&w.repo, &["add", ".github/workflows/blocked.yml"]);
        let candidate = w.candidate("test: forbidden candidate");
        git(
            &w.repo,
            &["reset", "-q", "HEAD", "--", ".github/workflows/blocked.yml"],
        );
        let token = w.token(run);
        let answer = w.sign(&token, &candidate);
        assert!(
            matches!(answer, Response::Error { ref message } if message.contains("forbidden path")),
            "{answer:?}"
        );
        if !run {
            assert!(matches!(
                w.sign(&token, &w.candidate("test: consumed")),
                Response::Error { .. }
            ));
        }
    }
}

#[test]
fn both_token_types_check_the_actual_message_and_changed_line_count() {
    for run in [false, true] {
        let w = World::new("[security]\nmax_diff_lines = 2\nenforce_conventional_commits = true\n");
        w.lease();
        assert!(matches!(
            w.sign(&w.token(run), &w.candidate("test: allowed empty delta")),
            Response::Signed { .. }
        ));
        let answer = w.sign(&w.token(run), &w.candidate("unstructured final message"));
        assert!(
            matches!(answer, Response::Error { ref message } if message.contains("conventional commits")),
            "{answer:?}"
        );
        fs::write(w.repo.join("safe.txt"), "one\ntwo\nthree\n").unwrap();
        git(&w.repo, &["add", "safe.txt"]);
        let too_large = w.candidate("test: independently counted three-line delta");
        git(&w.repo, &["reset", "-q", "HEAD", "--", "safe.txt"]);
        let answer = w.sign(&w.token(run), &too_large);
        assert!(
            matches!(answer, Response::Error { ref message } if message.contains("changes 3 lines") && message.contains("max_diff_lines = 2")),
            "{answer:?}"
        );
        fs::write(w.repo.join("safe.txt"), "one\ntwo\n").unwrap();
        git(&w.repo, &["add", "safe.txt"]);
        assert!(matches!(
            w.sign(
                &w.token(run),
                &w.candidate("test: exactly two lines allowed")
            ),
            Response::Signed { .. }
        ));
    }
}

#[test]
fn hooks_and_cherry_picks_cannot_add_forbidden_paths_after_preflight() {
    let w = World::new("");
    fs::write(w.repo.join("safe.txt"), "safe\n").unwrap();
    git(&w.repo, &["add", "safe.txt"]);
    fs::create_dir_all(w.repo.join(".github/workflows")).unwrap();
    fs::write(w.repo.join(".github/workflows/late.yml"), "fixture\n").unwrap();
    write_exec(
        &w.repo.join(".git/hooks/pre-commit"),
        &format!(
            "#!/bin/sh\n{} add -- .github/workflows/late.yml\n",
            git_bin()
        ),
    );
    let before = git(&w.repo, &["rev-parse", "HEAD"]);
    let result = w.wrapper(&["commit", "-m", "test: hook stages forbidden file"]);
    assert!(!result.status.success());
    assert_eq!(git(&w.repo, &["rev-parse", "HEAD"]), before);
    fs::remove_file(w.repo.join(".git/hooks/pre-commit")).unwrap();
    git(&w.repo, &["reset", "--hard", "HEAD"]);
    git(&w.repo, &["checkout", "-qb", "source"]);
    fs::create_dir_all(w.repo.join(".github/workflows")).unwrap();
    fs::write(
        w.repo.join(".github/workflows/from-source.yml"),
        "fixture\n",
    )
    .unwrap();
    git(&w.repo, &["add", "."]);
    git(
        &w.repo,
        &[
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-qm",
            "test: source workflow",
        ],
    );
    let source = git(&w.repo, &["rev-parse", "HEAD"]);
    git(&w.repo, &["checkout", "-q", "work"]);
    let result = w.wrapper(&["cherry-pick", &source]);
    assert!(!result.status.success());
    assert_eq!(git(&w.repo, &["rev-parse", "HEAD"]), before);
}

#[test]
fn normal_merge_and_replayed_author_still_work() {
    let w = World::new("");
    git(&w.repo, &["checkout", "-qb", "source"]);
    fs::write(w.repo.join("source.txt"), "normal fixture\n").unwrap();
    git(&w.repo, &["add", "."]);
    git(
        &w.repo,
        &[
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--author",
            "Original Author <original@example.invalid>",
            "-qm",
            "test: allowed source",
        ],
    );
    let source = git(&w.repo, &["rev-parse", "HEAD"]);
    git(&w.repo, &["checkout", "-q", "work"]);
    let result = w.wrapper(&["cherry-pick", &source]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        git(&w.repo, &["log", "-1", "--format=%an <%ae>"]),
        "Original Author <original@example.invalid>"
    );
    git(&w.repo, &["checkout", "-qb", "other"]);
    fs::write(w.repo.join("merge.txt"), "merge fixture\n").unwrap();
    git(&w.repo, &["add", "."]);
    git(
        &w.repo,
        &[
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-qm",
            "test: merge source",
        ],
    );
    git(&w.repo, &["checkout", "-q", "work"]);
    let result = w.wrapper(&["merge", "--no-ff", "other", "-m", "test: allowed merge"]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        git(&w.repo, &["rev-list", "--parents", "-n1", "HEAD"])
            .split_whitespace()
            .count(),
        3
    );
}

#[test]
fn revoked_replaced_and_expired_leases_cannot_sign_with_old_tokens() {
    for run in [false, true] {
        let w = World::new("");
        w.lease();
        let token = w.token(run);
        let candidate = w.candidate("test: revoke");
        assert!(matches!(
            w.ask(Request::RevokeLease {
                repo: w.repo.display().to_string(),
                branch: None,
                all: false
            }),
            Response::Success
        ));
        assert!(matches!(w.sign(&token, &candidate), Response::Error { .. }));
        w.lease();
        let old = w.token(run);
        assert!(matches!(
            w.ask(Request::RevokeLease {
                repo: String::new(),
                branch: None,
                all: true
            }),
            Response::Success
        ));
        w.lease();
        assert!(matches!(w.sign(&old, &candidate), Response::Error { .. }));
        assert!(matches!(
            w.sign(&w.token(run), &candidate),
            Response::Signed { .. }
        ));
    }
    let w = World::new("[security]\nlease_mode = \"timed\"\ndefault_lease_duration = \"2s\"\n");
    w.lease();
    let tokens = [w.token(false), w.token(true)];
    let candidate = w.candidate("test: expired");
    std::thread::sleep(Duration::from_millis(2100));
    for token in tokens {
        assert!(matches!(w.sign(&token, &candidate), Response::Error { .. }));
    }
}

#[test]
fn finished_work_is_checked_at_signature_dispatch() {
    let w = World::new("");
    w.lease();
    let tokens = [w.token(false), w.token(true)];
    fs::write(w.repo.join("done.txt"), "finished fixture\n").unwrap();
    git(&w.repo, &["add", "."]);
    git(
        &w.repo,
        &[
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-qm",
            "test: completed work",
        ],
    );
    let tip = git(&w.repo, &["rev-parse", "HEAD"]);
    git(&w.repo, &["update-ref", "refs/heads/main", &tip]);
    for token in tokens {
        assert!(matches!(
            w.sign(&token, &w.candidate("test: after merge")),
            Response::Error { .. }
        ));
    }
}

#[test]
fn malformed_candidate_or_selected_policy_refuses_and_normal_root_tree_is_allowed() {
    let w = World::new("");
    w.lease();
    assert!(matches!(
        w.sign(&w.token(false), b"tree x\n"),
        Response::Error { .. }
    ));
    let empty_tree = git(&w.repo, &["rev-parse", "HEAD^{tree}"]);
    let malformed = format!("tree {empty_tree}\nauthor \ncommitter \n\ntest: malformed identity\n");
    assert!(matches!(
        w.sign(&w.token(false), malformed.as_bytes()),
        Response::Error { .. }
    ));
    for invalid in [
        "[security]\nforbidden_paths = 123\n",
        "[security]\nblock_branches = [\"main\", 1]\n",
        "[security]\nmax_diff_lines = \"small\"\n",
        "[security\n",
    ] {
        fs::write(w.repo.join(".agent-sign.toml"), invalid).unwrap();
        assert!(Config::try_load_in_home(&w.home, Some(&w.repo)).is_err());
        assert!(matches!(
            w.sign(&w.token(false), &w.candidate("test: bad policy")),
            Response::Error { .. }
        ));
    }
    fs::remove_file(w.repo.join(".agent-sign.toml")).unwrap();
    let empty = git(&w.repo, &["hash-object", "-t", "tree", "/dev/null"]);
    let root = format!(
        "tree {empty}\nauthor Fixture <fixture@example.invalid> 1700000000 +0000\ncommitter Fixture <fixture@example.invalid> 1700000000 +0000\n\ntest: root\n"
    );
    assert!(validate_candidate(&w.repo, &Config::default(), root.as_bytes()).is_ok());
    for encoding in ["ISO-8859-1", "UTF-16", "UTF-8\nencoding UTF-8"] {
        let declared = root.replace(
            "\n\ntest: root",
            &format!("\nencoding {encoding}\n\ntest: root"),
        );
        assert!(validate_candidate(&w.repo, &Config::default(), declared.as_bytes()).is_err());
    }
    let utf8 = root.replace("\n\ntest: root", "\nencoding UTF-8\n\ntest: root");
    assert!(validate_candidate(&w.repo, &Config::default(), utf8.as_bytes()).is_ok());
    let token = w.token(false);
    fs::write(
        w.home.join(".agent-sign/config.toml"),
        "[security]\napproval = [\n",
    )
    .unwrap();
    assert!(matches!(
        w.sign(&token, &w.candidate("test: bad global config")),
        Response::Error { .. }
    ));
}

#[test]
fn failed_durable_revocation_reports_error_and_recovery_can_flush_it() {
    let dir = tempdir().unwrap();
    let store = dir.path().join("store");
    fs::create_dir(&store).unwrap();
    let path = store.join("leases.json");
    let mut engine = LeaseEngine::new_with_storage(LeasePolicy::default(), Some(path.clone()));
    engine.grant_lease("fixture/repo", "work", "test only");
    let saved = dir.path().join("saved");
    fs::rename(&store, &saved).unwrap();
    fs::write(&store, "blocked directory path").unwrap();
    let error = engine.revoke_lease_durable("fixture/repo").unwrap_err();
    assert!(error.contains("NOT confirmed"));
    assert!(!engine.has_active_lease("fixture/repo"));
    fs::remove_file(&store).unwrap();
    fs::rename(&saved, &store).unwrap();
    // The error is truthful: without a durable write the old grant can return.
    let old = LeaseEngine::new_with_storage(LeasePolicy::default(), Some(path.clone()));
    assert!(old.has_active_lease("fixture/repo"));
    engine.revoke_all_durable().unwrap();
    let recovered = LeaseEngine::new_with_storage(LeasePolicy::default(), Some(path));
    assert!(!recovered.has_active_lease("fixture/repo"));
}

#[cfg(target_os = "linux")]
#[test]
fn daemon_disables_both_core_limits_before_holding_keys() {
    let w = World::new("");
    let limits = fs::read_to_string(format!("/proc/{}/limits", w.service.id())).unwrap();
    let core = limits
        .lines()
        .find(|line| line.starts_with("Max core file size"))
        .unwrap();
    let fields: Vec<_> = core.split_whitespace().collect();
    assert_eq!(&fields[4..6], ["0", "0"]);
}

#[test]
fn source_install_requires_a_build_and_bad_archive_digest_is_refused_before_effects() {
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    let source = dir.path().join("source");
    fs::create_dir(&home).unwrap();
    fs::create_dir_all(source.join("scripts")).unwrap();
    fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/install.sh"),
        source.join("scripts/install.sh"),
    )
    .unwrap();
    fs::write(source.join("Cargo.toml"), "selected-source-fixture").unwrap();
    let fakebin = dir.path().join("fakebin");
    fs::create_dir(&fakebin).unwrap();
    write_exec(
        &fakebin.join("cargo"),
        "#!/bin/sh\necho selected-source-build > \"$HOME/build-called\"\nexit 42\n",
    );
    write_exec(
        &fakebin.join("curl"),
        "#!/bin/sh\necho unexpected-download > \"$HOME/download-called\"\nexit 99\n",
    );
    fs::create_dir_all(source.join("target/release")).unwrap();
    for name in ["agent-signd", "agent-sign", "agent-ssh-sign", "agent-git"] {
        write_exec(
            &source.join("target/release").join(name),
            "#!/bin/sh\necho stale-binary > \"$HOME/stale-ran\"\nexit 0\n",
        );
    }
    let mut cmd = isolated(Path::new("/bin/bash"), &home);
    let out = cmd
        .env("PATH", format!("{}:/usr/bin:/bin", fakebin.display()))
        .arg(source.join("scripts/install.sh"))
        .arg("--yes")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(42));
    assert!(home.join("build-called").is_file());
    assert!(!home.join("download-called").exists());
    assert!(!home.join("stale-ran").exists());
    assert!(!home.join(".agent-sign/bin/agent-signd").exists());
    let clean_home = dir.path().join("clean-home");
    fs::create_dir(&clean_home).unwrap();
    let archive = dir.path().join("archive.tar.gz");
    fs::write(&archive, "not an archive").unwrap();
    let out = isolated(Path::new("/bin/bash"), &clean_home)
        .arg(source.join("scripts/install.sh"))
        .args(["--yes", "--archive"])
        .arg(&archive)
        .arg("--sha256")
        .arg("0".repeat(64))
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(!clean_home.join(".agent-sign").exists());
    let actual = format!("{:x}", Sha256::digest(fs::read(&archive).unwrap()));
    assert_ne!(actual, "0".repeat(64));
}

#[test]
fn a_pristine_repository_root_commit_is_checked_without_an_existing_empty_tree() {
    let dir = tempdir().unwrap();
    git(dir.path(), &["init", "-q", "-b", "work"]);
    fs::write(dir.path().join("ordinary.txt"), "first commit fixture\n").unwrap();
    git(dir.path(), &["add", "ordinary.txt"]);
    let tree = git(dir.path(), &["write-tree"]);
    let candidate = format!(
        "tree {tree}\nauthor Fixture <fixture@example.invalid> 1700000000 +0000\ncommitter Fixture <fixture@example.invalid> 1700000000 +0000\n\ntest: first commit\n"
    );
    let config = Config::try_load_in_home(dir.path(), None).unwrap();
    assert!(validate_candidate(dir.path(), &config, candidate.as_bytes()).is_ok());
}

#[test]
fn local_submodule_ignore_settings_cannot_hide_a_forbidden_gitlink_change() {
    let w = World::new("");
    let commit = git(&w.repo, &["rev-parse", "HEAD"]);
    git(
        &w.repo,
        &[
            "update-index",
            "--add",
            "--cacheinfo",
            "160000",
            &commit,
            "protected-module",
        ],
    );
    git(&w.repo, &["config", "diff.ignoreSubmodules", "all"]);
    let mut config = Config::try_load_in_home(&w.home, None).unwrap();
    config
        .security
        .forbidden_paths
        .push("protected-module".into());
    assert!(validate_candidate(&w.repo, &config, &w.candidate("test: gitlink")).is_err());
}
