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
    Approval, AuthOutcome, Authenticator, NO_WAY_TO_ASK, auth_reason, confirm,
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
fn the_prompt_names_the_repository_and_coverage_and_stays_short() {
    let reason = auth_reason("/w/dev/app", "This repository only");
    assert!(reason.contains("/w/dev/app") && reason.contains("This repository only"));
    let long = format!("/{}", "x".repeat(400));
    assert!(auth_reason(&long, "Everywhere").len() < 260);
}

#[test]
fn the_no_way_to_ask_message_says_there_is_no_clickable_fallback_on_linux() {
    assert!(NO_WAY_TO_ASK.contains("Linux"));
    assert!(NO_WAY_TO_ASK.contains("no platform authenticator"));
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

/// Starts the service with a dialog that picks `choice`, and the stand-in
/// owner set to `auth` (`None` leaves `AGENT_SIGN_TEST_AUTH` unset).
fn start_service(dir: &Path, choice: Option<&str>, auth: Option<&str>) -> Service {
    let fakebin = dir.join("fakebin");
    fs::create_dir_all(&fakebin).unwrap();
    let answer = match choice {
        Some(label) => format!("echo '{label}'"),
        None => "echo false; exit 1".to_string(),
    };
    write_script(&fakebin.join("osascript"), &answer);
    write_script(&fakebin.join("zenity"), &answer);

    let socket = dir.join("svc.sock");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_agent-signd"));
    cmd.arg("--socket")
        .arg(&socket)
        .env("HOME", dir)
        .env("PATH", &fakebin)
        .env("DISPLAY", ":99")
        .env_remove("WAYLAND_DISPLAY")
        .env_remove("AGENT_SIGN_AUTO_APPROVE")
        .env_remove("AGENT_SIGN_TEST_AUTH")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(auth) = auth {
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

fn ask(svc: &Service) -> Response {
    send_request(
        &svc.socket,
        &Request::RequestLease {
            repo: "/w/dev/app".to_string(),
            branch: "feat/a".to_string(),
            intent: "test".to_string(),
            duration_secs: None,
        },
    )
    .unwrap()
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
        let svc = start_service(dir.path(), Some(WIDEST), auth);
        match ask(&svc) {
            Response::Error { message } => {
                assert!(
                    message.contains("could not confirm it was you"),
                    "{auth:?}: {message}"
                );
            }
            other => panic!("{auth:?}: approved without the owner: {other:?}"),
        }
        assert_eq!(lease_count(&svc), 0, "{auth:?} left a lease");
    }
}

#[test]
fn the_owner_authenticating_approves_the_coverage_that_was_chosen() {
    let dir = tempdir().unwrap();
    let svc = start_service(dir.path(), Some(WIDEST), Some("allow"));
    assert!(matches!(ask(&svc), Response::LeaseGranted { .. }));
    // The widest coverage was chosen, so another repository is covered too.
    let other = send_request(
        &svc.socket,
        &Request::RequestLease {
            repo: "/somewhere/else/repo".to_string(),
            branch: "feat/z".to_string(),
            intent: "test".to_string(),
            duration_secs: None,
        },
    )
    .unwrap();
    assert!(matches!(other, Response::LeaseGranted { .. }), "{other:?}");
    assert_eq!(lease_count(&svc), 1);
}

#[test]
fn deny_in_the_dialog_is_a_denial_even_if_the_owner_would_authenticate() {
    let dir = tempdir().unwrap();
    let svc = start_service(dir.path(), None, Some("allow"));
    match ask(&svc) {
        Response::Error { message } => assert!(message.contains("the person denied"), "{message}"),
        other => panic!("{other:?}"),
    }
    assert_eq!(lease_count(&svc), 0);
}

#[test]
fn the_dialog_has_no_approve_button_and_preselects_nothing() {
    // The source is the check: the macOS dialog's buttons are Continue and
    // Deny, no choice is preselected, and the terminal has no "y" shortcut.
    let src = fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bin/agent_signd.rs"
    ))
    .unwrap();
    assert!(!src.contains("OK button name \\\"Approve\\\""));
    assert!(!src.contains("default items"));
    assert!(!src.contains("\"y\" | \"yes\""));
    assert!(src.contains("OK button name \\\"Continue\\\""));
}
