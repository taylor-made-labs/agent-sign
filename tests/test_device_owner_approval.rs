//! A click is not an approval: a lease is granted only if the device's owner
//! authenticates (on macOS, Touch ID or the login password) in one prompt
//! whose reason says what is being approved, and anything short of success
//! denies.
//!
//! The decision tests use a stand-in [`Authenticator`] so every outcome can be
//! forced. The service tests run the real `agent-signd` with a stand-in owner
//! chosen by `AGENT_SIGN_TEST_AUTH`; that variable exists only in test builds
//! (feature `test-authenticator`). The one thing no test can do is press a
//! real finger on the sensor, or see the wording the system puts around the
//! reason: that is the manual check in the release checklist (and the ignored
//! test below).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use agent_sign::approval::{
    Approval, Asked, AuthOutcome, Authenticator, BranchReach, MAX_PENDING_REQUESTS,
    MAX_REASON_CHARS, NO_WAY_TO_ASK, RefusalBackoff, auth_reason, confirm, display_text,
    has_unsafe_display_chars, short_path,
};
use agent_sign::lease::Coverage;
use agent_sign::protocol::{Request, Response, send_request};
use tempfile::tempdir;

// --- The decision, with a stand-in owner -----------------------------------

/// Answers with a fixed outcome and records every reason it was asked with.
struct Fake {
    outcome: AuthOutcome,
    asked: Mutex<Vec<String>>,
}

impl Fake {
    fn new(outcome: AuthOutcome) -> Self {
        Fake {
            outcome,
            asked: Mutex::new(Vec::new()),
        }
    }
    fn times_asked(&self) -> usize {
        self.asked.lock().unwrap().len()
    }
}

impl Authenticator for Fake {
    fn authenticate(&self, reason: &str, _cancel: &AtomicBool) -> AuthOutcome {
        self.asked.lock().unwrap().push(reason.to_string());
        self.outcome.clone()
    }
}

fn decide(outcome: AuthOutcome) -> (Approval, usize) {
    let fake = Fake::new(outcome);
    let approval = confirm(
        Coverage::Repository,
        &fake,
        "reason",
        &AtomicBool::new(false),
    );
    (approval, fake.times_asked())
}

#[test]
fn without_authentication_nothing_is_approved() {
    // Every way authentication can fail to happen refuses.
    let failures = [
        AuthOutcome::Failed("cancelled".to_string()),
        AuthOutcome::TimedOut,
        AuthOutcome::Unavailable("no authenticator".to_string()),
    ];
    for failure in failures {
        let (approval, _) = decide(failure.clone());
        assert!(
            matches!(
                approval,
                Approval::NotAuthenticated(_) | Approval::NoWayToAsk
            ),
            "{failure:?} gave {approval:?}"
        );
        assert!(approval.refusal().is_some(), "{failure:?} must refuse");
    }
}

#[test]
fn authentication_failure_denies_and_says_why_it_was_not_the_persons_no() {
    let (approval, _) = decide(AuthOutcome::Failed("Authentication failed".to_string()));
    let refusal = approval.refusal().unwrap();
    assert!(
        refusal.contains("could not confirm it was you"),
        "{refusal}"
    );
    assert!(refusal.contains("Authentication failed"), "{refusal}");
    assert!(!refusal.contains("the person denied"), "{refusal}");
}

#[test]
fn a_mac_that_cannot_ask_says_so_instead_of_blaming_the_person() {
    let (approval, _) = decide(AuthOutcome::Unavailable("no password set".to_string()));
    assert_eq!(approval, Approval::NoWayToAsk);
    assert_eq!(approval.refusal().as_deref(), Some(NO_WAY_TO_ASK));
}

#[test]
fn success_approves_once_with_the_narrowest_coverage_asked_for() {
    let (approval, asked) = decide(AuthOutcome::Authenticated);
    assert_eq!(approval, Approval::Approved(Coverage::Repository));
    assert_eq!(asked, 1);
}

#[test]
fn withdrawing_during_authentication_is_not_an_approval() {
    let (approval, _) = decide(AuthOutcome::Withdrawn);
    assert_eq!(approval, Approval::Withdrawn);
}

/// The reason for a lease on one branch, asked from `repo`.
fn reason_for(repo: &str, home: Option<&str>, branch: &str, ends: &str) -> String {
    let reach = BranchReach::This(branch.to_string());
    auth_reason(&Asked {
        repo,
        worktree: None,
        unrecognized_worktree: false,
        home,
        reach: &reach,
        ends,
    })
}

#[test]
fn the_prompt_says_the_branch_the_repository_where_it_is_and_how_long() {
    let reason = reason_for(
        "/Users/me/dev/suite",
        Some("/Users/me"),
        "feat/parser",
        "until merged",
    );
    assert_eq!(
        reason,
        "let an agent sign commits on branch \u{201C}feat/parser\u{201D} in suite (~/dev/suite), until merged"
    );
    // The system writes "<name> is trying to <reason>.", so the reason is a
    // lowercase phrase with no full stop of its own.
    assert!(!reason.ends_with('.'));
    assert!(reason.starts_with(char::is_lowercase));

    // When the config lets the lease follow the agent, the reason says so.
    let wide = auth_reason(&Asked {
        repo: "/Users/me/dev/suite",
        worktree: None,
        unrecognized_worktree: false,
        home: Some("/Users/me"),
        reach: &BranchReach::AnyUnprotected,
        ends: "until merged, at most 7 days",
    });
    assert_eq!(
        wide,
        "let an agent sign commits on any unprotected branch in suite (~/dev/suite), until merged, at most 7 days"
    );
    let all = auth_reason(&Asked {
        repo: "/w/app",
        worktree: None,
        unrecognized_worktree: false,
        home: None,
        reach: &BranchReach::Any,
        ends: "until merged",
    });
    assert_eq!(
        all,
        "let an agent sign commits on any branch in app (/w/app), until merged"
    );
}

#[test]
fn a_linked_worktree_names_the_repository_it_commits_into() {
    let reach = BranchReach::This("feat/x".to_string());
    let reason = auth_reason(&Asked {
        repo: "/Users/me/dev/suite",
        worktree: Some("/Users/me/tmp/scratch-notes"),
        unrecognized_worktree: false,
        home: Some("/Users/me"),
        reach: &reach,
        ends: "until merged",
    });
    assert_eq!(
        reason,
        "let an agent sign commits on branch \u{201C}feat/x\u{201D} in suite (~/dev/suite, worktree \u{201C}scratch-notes\u{201D}), until merged"
    );
}

#[test]
fn the_lease_policy_says_how_long_it_lasts() {
    use agent_sign::config::LeaseMode;
    use agent_sign::lease::LeasePolicy;
    let p = LeasePolicy::default();
    assert_eq!(p.end_phrase(), "until merged");
    let idle = LeasePolicy {
        idle_limit: Some(Duration::from_secs(7 * 86400)),
        ..LeasePolicy::default()
    };
    assert_eq!(idle.end_phrase(), "until merged or 7 days idle");
    let ceiling = LeasePolicy {
        max_ceiling: Some(Duration::from_secs(86400)),
        idle_limit: Some(Duration::from_secs(7 * 86400)),
        ..LeasePolicy::default()
    };
    assert_eq!(ceiling.end_phrase(), "until merged, at most 1 day");
    let timed = LeasePolicy {
        mode: LeaseMode::Timed,
        default_ttl: Duration::from_secs(7200),
        ..LeasePolicy::default()
    };
    assert_eq!(timed.end_phrase(), "until merged, at most 2 hours");
}

#[test]
fn only_a_whole_leading_folder_is_shown_as_the_home_folder() {
    assert_eq!(short_path("/Users/me/dev/x", Some("/Users/me")), "~/dev/x");
    assert_eq!(short_path("/Users/me", Some("/Users/me")), "~");
    assert_eq!(short_path("/Users/me/", Some("/Users/me/")), "~/");
    // A different folder that starts the same way is not under home.
    assert_eq!(
        short_path("/Users/me2/dev/x", Some("/Users/me")),
        "/Users/me2/dev/x"
    );
    assert_eq!(short_path("/opt/x", Some("/Users/me")), "/opt/x");
    assert_eq!(short_path("/opt/x", None), "/opt/x");
    // A home of "/" or empty would turn every path into "~...".
    assert_eq!(short_path("/opt/x", Some("/")), "/opt/x");
    assert_eq!(short_path("/opt/x", Some("")), "/opt/x");
}

#[test]
fn a_long_reason_is_cut_but_keeps_the_branch_and_the_repository_name() {
    // Ordinary names are never cut, however deep the folder is.
    let deep = "/Users/me/a/very/long/way/down/through/many/folders/to/the/project";
    let reason = reason_for(deep, Some("/Users/me"), "feat/parser", "until merged");
    assert!(reason.chars().count() <= MAX_REASON_CHARS, "{reason}");
    assert!(
        reason.contains("branch \u{201C}feat/parser\u{201D} in project ("),
        "{reason}"
    );
    // The path gave way, in the middle, so its start and end still show.
    assert!(reason.contains("(~/a/very"), "{reason}");
    assert!(reason.contains("to/the/project)"), "{reason}");

    // The worst case: huge names everywhere stays within the limit, and the
    // start and end of the branch and of the name still show.
    let long_branch = format!("feat/{}/the-end", "b".repeat(300));
    let long_repo = format!("/w/{}/proj-end", "r".repeat(300));
    let reach = BranchReach::This(long_branch);
    let worst = auth_reason(&Asked {
        repo: &long_repo,
        worktree: Some(&format!("/t/{}/wt-end", "w".repeat(300))),
        unrecognized_worktree: false,
        home: None,
        reach: &reach,
        ends: &"until merged, at most 100 days ".repeat(10),
    });
    assert!(worst.chars().count() <= MAX_REASON_CHARS, "{worst}");
    assert!(worst.contains("branch \u{201C}feat/"), "{worst}");
    assert!(worst.contains("/the-end\u{201D} in "), "{worst}");
    assert!(worst.contains("proj-end ("), "{worst}");
    assert!(worst.contains("wt-end\u{201D})"), "{worst}");
}

#[test]
fn text_the_agent_supplies_cannot_reshape_the_prompt() {
    // Newlines, direction overrides and zero-width characters are removed...
    let evil = "/w/app (and everything else)\n\n\n\u{202e}\u{200b}x";
    assert!(has_unsafe_display_chars(evil));
    let reason = reason_for(evil, None, "feat/\u{2028}a", "until merged");
    assert!(!has_unsafe_display_chars(&reason), "{reason:?}");
    assert!(!reason.contains('\n'));
    // ...a folder named like a second place can't close or open the
    // sentence's own brackets...
    assert_eq!(
        reason.matches('(').count(),
        1,
        "a folder name added a bracket: {reason}"
    );
    assert_eq!(reason.matches(')').count(), 1, "{reason}");
    // ...and what is approved still leads, in the service's own words.
    assert!(
        reason.starts_with("let an agent sign commits on branch \u{201C}feat/a\u{201D} in "),
        "{reason}"
    );

    // Blank fillers that pass for spaces, and right-to-left letters next to
    // the prompt's punctuation, are removed or replaced in names too.
    let tricky = "/w/\u{3164}\u{2800}x\u{5d0}\u{5d1}y\u{0627}";
    assert!(has_unsafe_display_chars("\u{3164}"));
    assert!(has_unsafe_display_chars("\u{2800}"));
    let shown = reason_for(tricky, None, "feat/a", "until merged");
    assert!(shown.contains("in x??y? (/w/x??y?)"), "{shown}");

    // Long text is cut in the middle, so the start and the end both show.
    let long = format!("/start/{}/the-real-end", "x".repeat(500));
    let shown = display_text(&long, 60);
    assert!(shown.chars().count() <= 60, "{shown}");
    assert!(
        shown.starts_with("/start/") && shown.ends_with("/the-real-end"),
        "{shown}"
    );

    // Ordinary text is untouched.
    assert_eq!(
        display_text("/Users/me/dev/R&D <lab>", 100),
        "/Users/me/dev/R&D <lab>"
    );
    assert!(!has_unsafe_display_chars(
        "/Users/me/Documents/projet-\u{e9}t\u{e9}"
    ));
}

#[test]
fn the_no_way_to_ask_message_says_linux_has_no_way_to_approve() {
    assert!(NO_WAY_TO_ASK.contains("Linux has no way to approve yet"));
    assert!(NO_WAY_TO_ASK.contains("auto_approve"));
    assert!(!NO_WAY_TO_ASK.to_lowercase().contains("terminal"));
}

// --- Holding back repeated prompts ------------------------------------------

#[test]
fn a_refusal_holds_the_next_request_back_and_each_one_in_a_row_doubles_it() {
    let t0 = Instant::now();
    let mut b = RefusalBackoff::new(Duration::from_secs(60));
    assert_eq!(b.remaining(t0), None, "nothing is held back at first");

    b.record_refusal(t0);
    assert_eq!(b.remaining(t0), Some(Duration::from_secs(60)));
    assert_eq!(b.remaining(t0 + Duration::from_secs(61)), None);

    b.record_refusal(t0);
    assert_eq!(b.remaining(t0), Some(Duration::from_secs(120)));
    b.record_refusal(t0);
    assert_eq!(b.remaining(t0), Some(Duration::from_secs(240)));

    // It never grows past an hour, however many refusals.
    for _ in 0..40 {
        b.record_refusal(t0);
    }
    assert_eq!(b.remaining(t0), Some(Duration::from_secs(3600)));

    // An approval clears it, and the next refusal starts from the base again.
    b.record_approval();
    assert_eq!(b.remaining(t0), None);
    b.record_refusal(t0);
    assert_eq!(b.remaining(t0), Some(Duration::from_secs(60)));
}

#[test]
fn a_zero_backoff_never_holds_anything_back() {
    let t0 = Instant::now();
    let mut b = RefusalBackoff::new(Duration::ZERO);
    b.record_refusal(t0);
    assert_eq!(b.remaining(t0), None);
}

/// Needs a Mac whose owner can authenticate in this session. Shows nothing.
#[cfg(target_os = "macos")]
#[test]
#[ignore = "needs a desktop session with Touch ID or a login password; run by hand"]
fn this_mac_can_authenticate_its_owner() {
    agent_sign::device_owner::DeviceOwner::is_available().unwrap();
}

// --- The running service, with a stand-in owner -------------------------------

struct Service {
    child: Child,
    socket: PathBuf,
}

impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// How a test service is set up.
#[derive(Default)]
struct Setup<'a> {
    /// `AGENT_SIGN_TEST_AUTH`; `None` leaves it unset.
    auth: Option<&'a str>,
    /// `refusal_backoff` (`AGENT_SIGN_REFUSAL_BACKOFF`); empty means "none".
    backoff: &'a str,
    /// Each prompt stays open this long (`AGENT_SIGN_TEST_AUTH_DELAY_MS`).
    delay_ms: Option<u64>,
    /// Each prompt stays open until this file exists
    /// (`AGENT_SIGN_TEST_AUTH_ANSWER`).
    answer_file: Option<PathBuf>,
    /// Added under `[security]` in the config.
    config: &'a str,
}

fn start(dir: &Path, setup: Setup) -> Service {
    let socket = dir.join("svc.sock");
    let state = dir.join(".agent-sign");
    fs::create_dir_all(&state).unwrap();
    fs::write(
        state.join("config.toml"),
        format!("[security]\n{}", setup.config),
    )
    .unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_agent-signd"));
    cmd.arg("--socket")
        .arg(&socket)
        .env("HOME", dir)
        .env("PATH", "/usr/bin:/bin")
        .env_remove("AGENT_SIGN_AUTO_APPROVE")
        .env_remove("AGENT_SIGN_TEST_AUTH")
        .env_remove("AGENT_SIGN_TEST_AUTH_ANSWER")
        .env_remove("AGENT_SIGN_TEST_AUTH_DELAY_MS")
        .env(
            "AGENT_SIGN_REFUSAL_BACKOFF",
            if setup.backoff.is_empty() {
                "none"
            } else {
                setup.backoff
            },
        )
        .env("AGENT_SIGN_TEST_AUTH_LOG", dir.join("auth.log"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(auth) = setup.auth {
        cmd.env("AGENT_SIGN_TEST_AUTH", auth);
    }
    if let Some(ms) = setup.delay_ms {
        cmd.env("AGENT_SIGN_TEST_AUTH_DELAY_MS", ms.to_string());
    }
    if let Some(file) = &setup.answer_file {
        cmd.env("AGENT_SIGN_TEST_AUTH_ANSWER", file);
    }
    let child = cmd.spawn().expect("Failed to start agent-signd");
    let start = Instant::now();
    while !matches!(send_request(&socket, &Request::Ping), Ok(Response::Pong)) {
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "agent-signd did not start answering"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    Service { child, socket }
}

/// A service whose stand-in owner answers `auth`.
fn start_service(dir: &Path, auth: Option<&str>) -> Service {
    start(
        dir,
        Setup {
            auth,
            ..Setup::default()
        },
    )
}

/// A directory that looks like a git working tree. Returns its path.
fn fake_repo(root: &Path, rel: &str) -> String {
    let repo = root.join(rel);
    fs::create_dir_all(repo.join(".git")).unwrap();
    let repo = repo.display().to_string();
    set_head(&repo, "feat/a");
    repo
}

/// Makes the repository's `HEAD` name `branch`: the service checks that the
/// branch it is asked about is the one checked out.
fn set_head(repo: &str, branch: &str) {
    let git = Path::new(repo).join(".git");
    if git.is_dir() {
        let _ = fs::write(git.join("HEAD"), format!("ref: refs/heads/{branch}\n"));
    }
}

/// How many prompts the owner was shown.
fn times_shown(dir: &Path) -> usize {
    fs::read_to_string(dir.join("auth.log"))
        .map(|s| s.lines().count())
        .unwrap_or(0)
}

fn ask_about(svc: &Service, repo: &str, branch: &str) -> Response {
    set_head(repo, branch);
    send_request(
        &svc.socket,
        &Request::RequestLease {
            repo: repo.to_string(),
            branch: branch.to_string(),
            intent: "test".to_string(),
            duration_secs: None,
        },
    )
    .unwrap()
}

fn message_of(response: Response) -> String {
    match response {
        Response::Error { message } => message,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

fn lease_count(svc: &Service) -> usize {
    match send_request(&svc.socket, &Request::ListLeases).unwrap() {
        Response::LeaseList { leases } => leases.len(),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn without_the_owner_authenticating_nothing_is_granted() {
    // A stand-in owner that fails, one that times out, and one that was never
    // configured: none approves, and each says it couldn't confirm it was you.
    for auth in [Some("fail"), Some("timeout"), None] {
        let dir = tempdir().unwrap();
        let svc = start_service(dir.path(), auth);
        let app = fake_repo(dir.path(), "w/app");
        let message = message_of(ask_about(&svc, &app, "feat/a"));
        assert!(
            message.contains("could not confirm it was you"),
            "{auth:?}: {message}"
        );
        assert_eq!(lease_count(&svc), 0, "{auth:?} left a lease");
    }
    // One that can't be used here (no password set, no desktop session)
    // says nobody could be asked.
    let dir = tempdir().unwrap();
    let svc = start_service(dir.path(), Some("unavailable"));
    let app = fake_repo(dir.path(), "w/app");
    let message = message_of(ask_about(&svc, &app, "feat/a"));
    assert!(message.contains("couldn't ask you"), "{message}");
    assert_eq!(lease_count(&svc), 0);
}

#[test]
fn the_owner_authenticating_approves_this_branch_of_this_repository_only() {
    let dir = tempdir().unwrap();
    let svc = start_service(dir.path(), Some("allow"));
    let app = fake_repo(dir.path(), "w/app");
    let elsewhere = fake_repo(dir.path(), "elsewhere/repo");
    assert!(matches!(
        ask_about(&svc, &app, "feat/a"),
        Response::LeaseGranted { .. }
    ));
    assert_eq!(times_shown(dir.path()), 1);
    // The same branch again is covered...
    assert!(matches!(
        ask_about(&svc, &app, "feat/a"),
        Response::LeaseGranted { .. }
    ));
    assert_eq!(times_shown(dir.path()), 1);
    // ...but another branch, and another repository, are asked about.
    assert!(matches!(
        ask_about(&svc, &app, "feat/z"),
        Response::LeaseGranted { .. }
    ));
    assert_eq!(times_shown(dir.path()), 2);
    assert!(matches!(
        ask_about(&svc, &elsewhere, "feat/a"),
        Response::LeaseGranted { .. }
    ));
    assert_eq!(times_shown(dir.path()), 3);
    // A repository holds one lease at a time, so the new branch's approval
    // took the place of the old one.
    assert_eq!(lease_count(&svc), 2);
}

#[test]
fn agent_sign_deny_while_the_prompt_is_open_is_a_denial_even_if_the_owner_then_authenticates() {
    let dir = tempdir().unwrap();
    let answer = dir.path().join("answer");
    let svc = start(
        dir.path(),
        Setup {
            answer_file: Some(answer.clone()),
            ..Setup::default()
        },
    );
    let app = fake_repo(dir.path(), "w/app");
    let socket = svc.socket.clone();
    let waiting = std::thread::spawn({
        let app = app.clone();
        move || {
            send_request(
                &socket,
                &Request::RequestLease {
                    repo: app,
                    branch: "feat/a".to_string(),
                    intent: "test".to_string(),
                    duration_secs: None,
                },
            )
            .unwrap()
        }
    });
    let start = Instant::now();
    while times_shown(dir.path()) == 0 {
        assert!(start.elapsed() < Duration::from_secs(10), "no prompt");
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(matches!(
        send_request(
            &svc.socket,
            &Request::DenyPending {
                id: None,
                all: true
            }
        )
        .unwrap(),
        Response::Success
    ));
    // A late "yes" changes nothing.
    fs::write(&answer, "allow").unwrap();
    let message = message_of(waiting.join().unwrap());
    assert!(message.contains("the person denied"), "{message}");
    assert_eq!(lease_count(&svc), 0);
}

// --- The service holds prompts back after a refusal --------------------------

#[test]
fn after_a_refused_prompt_the_service_does_not_ask_again_straight_away() {
    let dir = tempdir().unwrap();
    // A Touch ID that fails (cancelled, say).
    let svc = start(
        dir.path(),
        Setup {
            auth: Some("fail"),
            backoff: "60s",
            ..Setup::default()
        },
    );
    let app = fake_repo(dir.path(), "w/app");
    let first = message_of(ask_about(&svc, &app, "feat/a"));
    assert!(!first.contains("not asking again"), "{first}");
    assert_eq!(times_shown(dir.path()), 1);

    // Another branch, another repository: still held back, and no prompt.
    let other = fake_repo(dir.path(), "w/other");
    for (repo, branch) in [(&app, "feat/b"), (&other, "feat/a")] {
        let held = message_of(ask_about(&svc, repo, branch));
        assert!(held.contains("not asking again"), "{held}");
    }
    assert_eq!(
        times_shown(dir.path()),
        1,
        "a held-back request opened a prompt"
    );
}

#[test]
fn only_one_approval_prompt_is_shown_at_a_time() {
    let dir = tempdir().unwrap();
    // Each prompt takes a moment, and the stand-in records when it starts and
    // ends.
    let svc = start(
        dir.path(),
        Setup {
            auth: Some("fail"),
            delay_ms: Some(400),
            ..Setup::default()
        },
    );
    let repos: Vec<String> = (0..3)
        .map(|i| fake_repo(dir.path(), &format!("w/r{i}")))
        .collect();
    let socket = svc.socket.clone();
    let handles: Vec<_> = repos
        .into_iter()
        .map(|repo| {
            let socket = socket.clone();
            std::thread::spawn(move || {
                send_request(
                    &socket,
                    &Request::RequestLease {
                        repo,
                        branch: "feat/a".to_string(),
                        intent: "t".to_string(),
                        duration_secs: None,
                    },
                )
                .unwrap()
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    let lines: Vec<String> = fs::read_to_string(dir.path().join("auth.log.events"))
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    let expected: Vec<&str> = ["start", "end"].repeat(3);
    assert_eq!(lines, expected, "prompts overlapped: {lines:?}");
}

#[test]
fn requests_waiting_for_an_answer_are_capped() {
    let dir = tempdir().unwrap();
    // A prompt that stays open: the answer file is never written.
    let svc = start(
        dir.path(),
        Setup {
            answer_file: Some(dir.path().join("never")),
            ..Setup::default()
        },
    );
    let _waiting: Vec<_> = (0..MAX_PENDING_REQUESTS)
        .map(|i| {
            // One repository each: a repository has one branch checked out.
            let repo = fake_repo(dir.path(), &format!("w/app{i}"));
            set_head(&repo, &format!("feat/{i}"));
            let socket = svc.socket.clone();
            std::thread::spawn(move || {
                send_request(
                    &socket,
                    &Request::RequestLease {
                        repo,
                        branch: format!("feat/{i}"),
                        intent: "t".to_string(),
                        duration_secs: None,
                    },
                )
                .map_err(|e| e.to_string())
            })
        })
        .collect();
    let start = Instant::now();
    loop {
        match send_request(&svc.socket, &Request::ListPending).unwrap() {
            Response::PendingList { pending } if pending.len() == MAX_PENDING_REQUESTS => break,
            _ => {}
        }
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "requests never queued"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let repo = fake_repo(dir.path(), "w/one-too-many");
    let message = message_of(ask_about(&svc, &repo, "feat/one-too-many"));
    assert!(message.contains("approval requests waiting"), "{message}");
}

// --- What the person is shown is what was asked about -------------------------

#[test]
fn a_repository_that_does_not_exist_is_refused_before_anyone_is_asked() {
    let dir = tempdir().unwrap();
    let svc = start_service(dir.path(), Some("allow"));
    let message = message_of(ask_about(&svc, "/this/path/does/not/exist", "feat/a"));
    assert!(
        message.contains("isn't an existing git working tree"),
        "{message}"
    );
    // A directory that is not a git working tree is refused too.
    let plain = dir.path().join("plain");
    fs::create_dir_all(&plain).unwrap();
    let message = message_of(ask_about(&svc, &plain.display().to_string(), "feat/a"));
    assert!(
        message.contains("isn't an existing git working tree"),
        "{message}"
    );
    assert_eq!(times_shown(dir.path()), 0);
    assert_eq!(lease_count(&svc), 0);
}

#[test]
fn control_and_invisible_characters_in_the_path_or_branch_are_refused() {
    let dir = tempdir().unwrap();
    let svc = start_service(dir.path(), Some("allow"));
    let app = fake_repo(dir.path(), "w/app");
    let bad_paths = [
        format!("{app}\n(This repository only)"),
        format!("{app}\u{202e}evil"),
        format!("{app}\u{200b}"),
        format!("{app}\u{2028}x"),
    ];
    for repo in &bad_paths {
        let message = message_of(ask_about(&svc, repo, "feat/a"));
        assert!(
            message.contains("control or invisible characters"),
            "{message}"
        );
    }
    for branch in ["feat/\u{202e}a", "feat/\nmain", "feat/\u{feff}a"] {
        let message = message_of(ask_about(&svc, &app, branch));
        assert!(
            message.contains("control or invisible characters"),
            "{message}"
        );
    }
    assert_eq!(
        times_shown(dir.path()),
        0,
        "someone was asked about a spoofed request"
    );
}

#[test]
fn the_owner_is_shown_the_branch_the_repository_and_where_it_is() {
    let dir = tempdir().unwrap();
    let svc = start_service(dir.path(), Some("allow"));
    let app = fake_repo(dir.path(), "w/app");
    assert!(matches!(
        ask_about(&svc, &app, "feat/shown"),
        Response::LeaseGranted { .. }
    ));
    let shown = fs::read_to_string(dir.path().join("auth.log")).unwrap();
    // The home folder (this test's) is shown as "~", and the path is the
    // real one, not the spelling the agent used.
    assert_eq!(
        shown.trim_end(),
        "let an agent sign commits on branch \u{201C}feat/shown\u{201D} in app (~/w/app), until merged or 7 days idle"
    );
}

#[test]
fn the_owner_is_told_when_a_lease_will_follow_the_agent_between_branches() {
    let dir = tempdir().unwrap();
    let svc = start(
        dir.path(),
        Setup {
            auth: Some("allow"),
            config: "allow_branch_switching = true\n",
            ..Setup::default()
        },
    );
    let app = fake_repo(dir.path(), "w/app");
    assert!(matches!(
        ask_about(&svc, &app, "feat/shown"),
        Response::LeaseGranted { .. }
    ));
    let shown = fs::read_to_string(dir.path().join("auth.log")).unwrap();
    assert_eq!(
        shown.trim_end(),
        "let an agent sign commits on any unprotected branch in app (~/w/app), until merged or 7 days idle"
    );
}

#[test]
fn a_branch_that_could_pose_as_prompt_text_is_refused_before_anyone_is_asked() {
    let dir = tempdir().unwrap();
    let svc = start_service(dir.path(), Some("allow"));
    let app = fake_repo(dir.path(), "w/app");
    let spoofs = [
        "typo fix in scratch (~/tmp/scratch)",
        "feat/\u{3164}scratch",
        "feat/\u{115f}x",
        "feat/\u{2800}x",
        "feat/\u{5d0}\u{5d1}\u{5d2}",
        "feat/\u{627}\u{644}",
        "feat/\u{201c}x\u{201d}",
        "a..b",
        "-x",
        "x.lock",
    ];
    for branch in spoofs {
        let message = message_of(ask_about(&svc, &app, branch));
        assert!(
            message.contains("no approval was asked for"),
            "{branch:?}: {message}"
        );
    }
    assert_eq!(
        times_shown(dir.path()),
        0,
        "someone was asked about a spoof"
    );
    assert_eq!(lease_count(&svc), 0);
}

#[test]
fn a_branch_the_repository_is_not_on_is_refused_before_anyone_is_asked() {
    let dir = tempdir().unwrap();
    let svc = start_service(dir.path(), Some("allow"));
    let app = fake_repo(dir.path(), "w/app");
    // The agent asks about a plain, valid name, but the repository is on
    // another branch: ask_about would set HEAD, so send the request directly.
    set_head(&app, "feat/real");
    let response = send_request(
        &svc.socket,
        &Request::RequestLease {
            repo: app.clone(),
            branch: "feat/other".to_string(),
            intent: "t".to_string(),
            duration_secs: None,
        },
    )
    .unwrap();
    let message = message_of(response);
    assert!(
        message.contains("isn't the branch checked out"),
        "{message}"
    );
    // A repository whose HEAD can't be read is refused too.
    fs::remove_file(Path::new(&app).join(".git/HEAD")).unwrap();
    let response = send_request(
        &svc.socket,
        &Request::RequestLease {
            repo: app.clone(),
            branch: "feat/real".to_string(),
            intent: "t".to_string(),
            duration_secs: None,
        },
    )
    .unwrap();
    assert!(message_of(response).contains("isn't the branch checked out"));
    assert_eq!(times_shown(dir.path()), 0);
    // The branch it is on is asked about, and a detached HEAD is asked as HEAD.
    set_head(&app, "feat/real");
    assert!(matches!(
        ask_about(&svc, &app, "feat/real"),
        Response::LeaseGranted { .. }
    ));
    let detached = fake_repo(dir.path(), "w/detached");
    fs::write(
        Path::new(&detached).join(".git/HEAD"),
        "0123456789abcdef0123456789abcdef01234567\n",
    )
    .unwrap();
    let response = send_request(
        &svc.socket,
        &Request::RequestLease {
            repo: detached,
            branch: "HEAD".to_string(),
            intent: "t".to_string(),
            duration_secs: None,
        },
    )
    .unwrap();
    assert!(
        matches!(response, Response::LeaseGranted { .. }),
        "{response:?}"
    );
}

#[test]
fn a_linked_worktree_is_shown_as_the_repository_it_commits_into() {
    let dir = tempdir().unwrap();
    let svc = start_service(dir.path(), Some("allow"));
    // The layout git makes: <main>/.git/worktrees/<name>/{HEAD,commondir},
    // and a `.git` file in the worktree pointing at that folder.
    let main = fake_repo(dir.path(), "dev/suite");
    let wt_meta = Path::new(&main).join(".git/worktrees/scratch-notes");
    fs::create_dir_all(&wt_meta).unwrap();
    fs::write(wt_meta.join("HEAD"), "ref: refs/heads/feat/x\n").unwrap();
    fs::write(wt_meta.join("commondir"), "../..\n").unwrap();
    let wt = dir.path().join("tmp/scratch-notes");
    fs::create_dir_all(&wt).unwrap();
    fs::write(wt.join(".git"), format!("gitdir: {}\n", wt_meta.display())).unwrap();
    // git also records where the worktree lives; the service checks it.
    fs::write(
        wt_meta.join("gitdir"),
        format!("{}\n", wt.join(".git").display()),
    )
    .unwrap();

    let response = send_request(
        &svc.socket,
        &Request::RequestLease {
            repo: wt.display().to_string(),
            branch: "feat/x".to_string(),
            intent: "t".to_string(),
            duration_secs: None,
        },
    )
    .unwrap();
    assert!(
        matches!(response, Response::LeaseGranted { .. }),
        "{response:?}"
    );
    let shown = fs::read_to_string(dir.path().join("auth.log")).unwrap();
    assert_eq!(
        shown.trim_end(),
        "let an agent sign commits on branch \u{201C}feat/x\u{201D} in suite (~/dev/suite, worktree \u{201C}scratch-notes\u{201D}), until merged or 7 days idle"
    );
}

#[test]
fn a_folder_forging_a_worktree_of_a_real_repository_is_shown_as_itself() {
    let dir = tempdir().unwrap();
    let svc = start_service(dir.path(), Some("allow"));
    let main = fake_repo(dir.path(), "dev/suite");
    // The agent's own folder, with a fake gitdir whose commondir names the
    // real repository; nothing in the real repository mentions it.
    let fake = dir.path().join("tmp/fake-gitdir");
    fs::create_dir_all(&fake).unwrap();
    fs::write(fake.join("HEAD"), "ref: refs/heads/feat/x\n").unwrap();
    fs::write(fake.join("commondir"), format!("{main}/.git\n")).unwrap();
    let evil = dir.path().join("tmp/evil");
    fs::create_dir_all(&evil).unwrap();
    fs::write(evil.join(".git"), format!("gitdir: {}\n", fake.display())).unwrap();
    fs::write(
        fake.join("gitdir"),
        format!("{}\n", evil.join(".git").display()),
    )
    .unwrap();

    let response = send_request(
        &svc.socket,
        &Request::RequestLease {
            repo: evil.display().to_string(),
            branch: "feat/x".to_string(),
            intent: "t".to_string(),
            duration_secs: None,
        },
    )
    .unwrap();
    assert!(
        matches!(response, Response::LeaseGranted { .. }),
        "{response:?}"
    );
    let shown = fs::read_to_string(dir.path().join("auth.log")).unwrap();
    assert_eq!(
        shown.trim_end(),
        "let an agent sign commits on branch \u{201C}feat/x\u{201D} in evil (~/tmp/evil, not a recognized worktree), until merged or 7 days idle"
    );
    assert!(!shown.contains("suite"), "{shown}");
}

// --- The stand-in owner cannot be in an installable program -------------------

#[test]
fn an_optimized_build_cannot_include_the_test_stand_in() {
    // `cargo test --release` would otherwise unify the test feature into
    // target/release/agent-signd, which the installer installs as it is.
    let out = Command::new(env!("CARGO"))
        .args([
            "check",
            "--release",
            "--locked",
            "--bins",
            "--features",
            "test-authenticator",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env_remove("CARGO_TARGET_DIR")
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "an optimized build with the stand-in compiled"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("debug test builds only"), "{stderr}");
}

#[test]
fn the_installer_refuses_programs_that_contain_a_test_stand_in() {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/check-binary-clean.sh");
    let check = |dir: &Path| Command::new("sh").arg(script).arg(dir).output().unwrap();
    let dir = tempdir().unwrap();
    fs::write(
        dir.path().join("agent-signd"),
        b"\x7fELF ordinary program text",
    )
    .unwrap();
    assert!(check(dir.path()).status.success());

    for marker in ["AGENT_SIGN_TEST_AUTH", "AGENT_SIGN_TEST_AUTH_ANSWER"] {
        let dirty = tempdir().unwrap();
        fs::write(
            dirty.path().join("agent-signd"),
            format!("\x00binary\x00{marker}\x00more").as_bytes(),
        )
        .unwrap();
        let out = check(dirty.path());
        assert!(!out.status.success(), "{marker} was accepted");
        assert!(String::from_utf8_lossy(&out.stderr).contains("test build"));
    }
    // And the installer calls it for every way it installs programs.
    let installer =
        fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/install.sh")).unwrap();
    assert_eq!(installer.matches("check-binary-clean.sh").count(), 2);
}

// --- No clickable or terminal fallback ------------------------------------------

#[test]
fn there_is_no_dialog_of_our_own_no_terminal_prompt_and_no_linux_dialog() {
    let root = env!("CARGO_MANIFEST_DIR");
    let daemon = fs::read_to_string(format!("{root}/src/bin/agent_signd.rs")).unwrap();
    // The service shows no dialog: not AppleScript, not a list, not a button.
    for forbidden in [
        "osascript",
        "choose from list",
        "display dialog",
        "OK button name",
        "Command::new",
        "AGENT_SIGN_TEST_DIALOG",
    ] {
        assert!(
            !daemon.contains(forbidden),
            "agent_signd.rs still mentions {forbidden}"
        );
    }
    // Linux: no zenity or kdialog, and nothing reads a terminal.
    for forbidden in ["zenity", "kdialog", "is_terminal", "IsTerminal"] {
        assert!(
            !daemon.contains(forbidden),
            "agent_signd.rs still mentions {forbidden}"
        );
    }
    for file in [
        "test_approval_scope.rs",
        "test_pending.rs",
        "test_edge_cases.rs",
        "test_refusals_and_revoke.rs",
    ] {
        let text = fs::read_to_string(format!("{root}/tests/{file}")).unwrap();
        assert!(
            !text.contains("zenity") && !text.contains("kdialog"),
            "{file} has a fake Linux dialog"
        );
    }
    // The README example doesn't show a reason the prompt doesn't show.
    let readme = fs::read_to_string(format!("{root}/README.md")).unwrap();
    assert!(!readme.contains("Reason given by the agent"));
}
