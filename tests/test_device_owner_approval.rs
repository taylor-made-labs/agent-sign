//! A click is not an approval: choosing what a lease covers only counts if the
//! device's owner then authenticates (on macOS, Touch ID or the login
//! password), and anything short of success denies.
//!
//! The decision tests use a stand-in [`Authenticator`] so every outcome can be
//! forced. The service tests run the real `agent-signd` with a stand-in
//! dialog that always picks the widest coverage (as a program clicking
//! through it would) and a stand-in owner chosen by `AGENT_SIGN_TEST_AUTH`;
//! that variable exists only in test builds (feature `test-authenticator`).
//! The one thing no test can do is press a real finger on the sensor: that is
//! the manual check in the release checklist (and the ignored test below).

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use agent_sign::approval::{
    Approval, AuthOutcome, Authenticator, MAX_PENDING_REQUESTS, NO_WAY_TO_ASK, RefusalBackoff,
    auth_reason, confirm, display_text, has_unsafe_display_chars,
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

fn decide(selection: Option<Coverage>, outcome: AuthOutcome) -> (Approval, usize) {
    let fake = Fake::new(outcome);
    let approval = confirm(selection, &fake, "reason", &AtomicBool::new(false));
    (approval, fake.times_asked())
}

#[test]
fn a_selection_without_authentication_is_denied() {
    // Every way authentication can fail to happen denies the selection.
    let failures = [
        AuthOutcome::Failed("cancelled".to_string()),
        AuthOutcome::TimedOut,
        AuthOutcome::Unavailable("no authenticator".to_string()),
    ];
    for failure in failures {
        let (approval, _) = decide(Some(Coverage::Everywhere), failure.clone());
        assert!(
            matches!(approval, Approval::NotAuthenticated(_)),
            "{failure:?} gave {approval:?}"
        );
        assert!(approval.refusal().is_some(), "{failure:?} must refuse");
    }
}

#[test]
fn authentication_failure_denies_and_says_why_it_was_not_the_persons_no() {
    let (approval, _) = decide(
        Some(Coverage::Repository),
        AuthOutcome::Failed("Authentication failed".to_string()),
    );
    let refusal = approval.refusal().unwrap();
    assert!(
        refusal.contains("could not confirm it was you"),
        "{refusal}"
    );
    assert!(refusal.contains("Authentication failed"), "{refusal}");
    assert!(!refusal.contains("the person denied"), "{refusal}");
}

#[test]
fn success_approves_with_the_chosen_coverage() {
    for coverage in [
        Coverage::Repository,
        Coverage::Folder("/w/dev".to_string()),
        Coverage::Everywhere,
    ] {
        let (approval, asked) = decide(Some(coverage.clone()), AuthOutcome::Authenticated);
        assert_eq!(approval, Approval::Approved(coverage));
        assert_eq!(asked, 1);
    }
}

#[test]
fn deny_never_asks_for_authentication() {
    // Nothing selected (Deny, closed, nothing picked): denied, and the owner
    // isn't bothered, and a stand-in that would succeed changes nothing.
    let (approval, asked) = decide(None, AuthOutcome::Authenticated);
    assert_eq!(approval, Approval::Denied);
    assert_eq!(asked, 0);
}

#[test]
fn an_answer_matching_no_choice_selects_nothing() {
    let choices = vec![
        (Coverage::Repository, "This repository only".to_string()),
        (
            Coverage::Everywhere,
            "Every repository on this computer".to_string(),
        ),
    ];
    assert_eq!(Approval::selection_from_answer("false", &choices), None);
    assert_eq!(Approval::selection_from_answer("", &choices), None);
    assert_eq!(
        Approval::selection_from_answer("Every repository under /elsewhere", &choices),
        None
    );
    assert_eq!(
        Approval::selection_from_answer("  Every repository on this computer\n", &choices),
        Some(Coverage::Everywhere)
    );
}

#[test]
fn withdrawing_during_authentication_is_not_an_approval() {
    let (approval, _) = decide(Some(Coverage::Repository), AuthOutcome::Withdrawn);
    assert_eq!(approval, Approval::Withdrawn);
}

#[test]
fn the_prompt_leads_with_the_coverage_then_names_the_repository_and_branch() {
    let reason = auth_reason("/w/dev/app", "feat/a", "Every repository on this computer");
    assert!(
        reason
            .starts_with("allow AI agents to sign git commits: Every repository on this computer"),
        "{reason}"
    );
    assert!(
        reason.contains("/w/dev/app") && reason.contains("feat/a"),
        "{reason}"
    );
}

#[test]
fn text_the_agent_supplies_cannot_reshape_the_prompt() {
    // Newlines, direction overrides and zero-width characters are removed...
    let evil = "/w/app (This repository only)\n\n\n\u{202e}\u{200b}x";
    assert!(has_unsafe_display_chars(evil));
    let reason = auth_reason(evil, "feat/\u{2028}a", "Every repository on this computer");
    assert!(!has_unsafe_display_chars(&reason), "{reason:?}");
    assert!(!reason.contains('\n'));
    // ...and the coverage the person chose still comes first, so nothing the
    // agent wrote can push it out of view.
    assert!(
        reason.contains("sign git commits: Every repository on this computer ("),
        "{reason}"
    );

    // Long text is cut in the middle, so the start and the end both show.
    let long = format!("/start/{}/the-real-end", "x".repeat(500));
    let shown = display_text(&long, 60);
    assert!(shown.chars().count() <= 60, "{shown}");
    assert!(
        shown.starts_with("/start/") && shown.ends_with("/the-real-end"),
        "{shown}"
    );
    assert!(auth_reason(&long, &long, "Everywhere").chars().count() < 400);

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

// --- The running service, with a stand-in dialog and a stand-in owner -----

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

fn write_script(path: &Path, body: &str) {
    fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

/// The widest coverage, picked by a stand-in dialog: what a program clicking
/// through the real one could do.
const WIDEST: &str = "Every repository on this computer";

/// How a test service is set up.
struct Setup<'a> {
    /// What the stand-in dialog does (a shell snippet); `None` for no dialog.
    dialog: Option<String>,
    /// `AGENT_SIGN_TEST_AUTH`; `None` leaves it unset.
    auth: Option<&'a str>,
    /// `refusal_backoff` (`AGENT_SIGN_REFUSAL_BACKOFF`).
    backoff: &'a str,
}

fn picks(label: &str) -> Option<String> {
    Some(format!("echo '{label}'"))
}

fn start(dir: &Path, setup: Setup) -> Service {
    let socket = dir.join("svc.sock");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_agent-signd"));
    cmd.arg("--socket")
        .arg(&socket)
        .env("HOME", dir)
        .env("PATH", "/usr/bin:/bin")
        .env_remove("AGENT_SIGN_AUTO_APPROVE")
        .env_remove("AGENT_SIGN_TEST_AUTH")
        .env_remove("AGENT_SIGN_TEST_DIALOG")
        .env("AGENT_SIGN_REFUSAL_BACKOFF", setup.backoff)
        .env("AGENT_SIGN_TEST_AUTH_LOG", dir.join("auth.log"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(body) = &setup.dialog {
        let dialog = dir.join("dialog");
        write_script(
            &dialog,
            &format!("echo shown >> '{}'\n{body}", dir.join("shown").display()),
        );
        cmd.env("AGENT_SIGN_TEST_DIALOG", &dialog);
    }
    if let Some(auth) = setup.auth {
        cmd.env("AGENT_SIGN_TEST_AUTH", auth);
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

/// A service whose dialog always picks the widest coverage.
fn start_service(dir: &Path, auth: Option<&str>) -> Service {
    start(
        dir,
        Setup {
            dialog: picks(WIDEST),
            auth,
            backoff: "none",
        },
    )
}

/// A directory that looks like a git working tree. Returns its path.
fn fake_repo(root: &Path, rel: &str) -> String {
    let repo = root.join(rel);
    fs::create_dir_all(repo.join(".git")).unwrap();
    repo.display().to_string()
}

fn times_shown(dir: &Path) -> usize {
    fs::read_to_string(dir.join("shown"))
        .map(|s| s.lines().count())
        .unwrap_or(0)
}

fn ask_about(svc: &Service, repo: &str, branch: &str) -> Response {
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
fn a_click_through_the_dialog_without_the_owner_grants_nothing() {
    // A stand-in owner that fails, one that times out, one that is
    // unavailable, and one that was never configured: none approves.
    for auth in [Some("fail"), Some("timeout"), Some("unavailable"), None] {
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
}

#[test]
fn the_owner_authenticating_approves_the_coverage_that_was_chosen() {
    let dir = tempdir().unwrap();
    let svc = start_service(dir.path(), Some("allow"));
    let app = fake_repo(dir.path(), "w/app");
    let elsewhere = fake_repo(dir.path(), "elsewhere/repo");
    assert!(matches!(
        ask_about(&svc, &app, "feat/a"),
        Response::LeaseGranted { .. }
    ));
    // The widest coverage was chosen, so another repository is covered too.
    let other = ask_about(&svc, &elsewhere, "feat/z");
    assert!(matches!(other, Response::LeaseGranted { .. }), "{other:?}");
    assert_eq!(lease_count(&svc), 1);
}

#[test]
fn deny_in_the_dialog_is_a_denial_even_if_the_owner_would_authenticate() {
    let dir = tempdir().unwrap();
    let svc = start(
        dir.path(),
        Setup {
            dialog: Some("echo false".to_string()),
            auth: Some("allow"),
            backoff: "none",
        },
    );
    let app = fake_repo(dir.path(), "w/app");
    let message = message_of(ask_about(&svc, &app, "feat/a"));
    assert!(message.contains("the person denied"), "{message}");
    assert_eq!(lease_count(&svc), 0);
}

// --- The service holds prompts back after a refusal --------------------------

#[test]
fn after_a_refused_prompt_the_service_does_not_ask_again_straight_away() {
    // Once for a Deny, once for a Touch ID that fails.
    for (dialog, auth) in [
        ("echo false", "allow"),
        (&format!("echo '{WIDEST}'")[..], "fail"),
    ] {
        let dir = tempdir().unwrap();
        let svc = start(
            dir.path(),
            Setup {
                dialog: Some(dialog.to_string()),
                auth: Some(auth),
                backoff: "60s",
            },
        );
        let app = fake_repo(dir.path(), "w/app");
        let first = message_of(ask_about(&svc, &app, "feat/a"));
        assert!(!first.contains("not asking again"), "{first}");
        assert_eq!(times_shown(dir.path()), 1);

        // Another branch, another repository: still held back, and no dialog.
        let other = fake_repo(dir.path(), "w/other");
        for (repo, branch) in [(&app, "feat/b"), (&other, "feat/a")] {
            let held = message_of(ask_about(&svc, repo, branch));
            assert!(held.contains("not asking again"), "{held}");
        }
        assert_eq!(
            times_shown(dir.path()),
            1,
            "a held-back request opened a dialog"
        );
    }
}

#[test]
fn only_one_approval_prompt_is_shown_at_a_time() {
    let dir = tempdir().unwrap();
    let log = dir.path().join("overlap.log");
    // Each stand-in dialog records when it starts and ends, and takes a moment.
    let body = format!(
        "echo start >> '{log}'\n/bin/sleep 0.4\necho end >> '{log}'\necho '{WIDEST}'",
        log = log.display()
    );
    let svc = start(
        dir.path(),
        Setup {
            dialog: Some(body),
            auth: Some("fail"),
            backoff: "none",
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
    let lines: Vec<String> = fs::read_to_string(&log)
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
    // A dialog that stays open until the test's home is gone.
    let body = format!(
        "while [ -d '{}' ]; do /bin/sleep 0.1 || exit 1; done",
        dir.path().display()
    );
    let svc = start(
        dir.path(),
        Setup {
            dialog: Some(body),
            auth: Some("allow"),
            backoff: "none",
        },
    );
    let repo = fake_repo(dir.path(), "w/app");
    let _waiting: Vec<_> = (0..MAX_PENDING_REQUESTS)
        .map(|i| {
            let (socket, repo) = (svc.socket.clone(), repo.clone());
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
fn the_owner_is_shown_the_chosen_coverage_the_real_path_and_the_branch() {
    let dir = tempdir().unwrap();
    let svc = start_service(dir.path(), Some("allow"));
    let app = fake_repo(dir.path(), "w/app");
    assert!(matches!(
        ask_about(&svc, &app, "feat/shown"),
        Response::LeaseGranted { .. }
    ));
    let shown = fs::read_to_string(dir.path().join("auth.log")).unwrap();
    assert!(
        shown.starts_with("allow AI agents to sign git commits: Every repository on this computer"),
        "{shown}"
    );
    assert!(
        shown.contains("w/app") && shown.contains("feat/shown"),
        "{shown}"
    );
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

    for marker in ["AGENT_SIGN_TEST_AUTH", "AGENT_SIGN_TEST_DIALOG"] {
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

// --- No clickable or terminal fallback, no Approve default --------------------

#[test]
fn there_is_no_approve_button_no_preselection_no_terminal_prompt_and_no_linux_dialog() {
    let root = env!("CARGO_MANIFEST_DIR");
    let daemon = fs::read_to_string(format!("{root}/src/bin/agent_signd.rs")).unwrap();
    assert!(!daemon.contains("OK button name \\\"Approve\\\""));
    assert!(!daemon.contains("default items"));
    assert!(daemon.contains("OK button name \\\"Continue\\\""));
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
    // The README example doesn't show a reason the dialog doesn't show.
    let readme = fs::read_to_string(format!("{root}/README.md")).unwrap();
    assert!(!readme.contains("Reason given by the agent"));
}
