//! What it takes to approve a signing lease: the person's choice, then proof
//! that the device's owner made it.
//!
//! A dialog alone proves nothing. Any program allowed to control the screen
//! (a computer-use agent, a System Events script) can click its button, so an
//! agent could approve its own lease. So the service never grants a lease on
//! a click: after the person picks what the lease covers, the choice only
//! counts if the platform's own authentication succeeds too (on macOS,
//! Touch ID or the login password, through LocalAuthentication; see
//! [`crate::device_owner`]). A program can't produce either.
//!
//! This module is the decision, kept apart from any dialog or platform call
//! so it can be tested with a stand-in [`Authenticator`]:
//!
//! - no selection (Deny, closed, nothing picked) is a denial, and the
//!   authenticator isn't even asked;
//! - a selection is approved only if the authenticator says
//!   [`AuthOutcome::Authenticated`]; failure, cancellation, timeout and
//!   unavailability all deny;
//! - when the request is withdrawn while the authenticator waits, the
//!   authentication is cancelled and the result is `Withdrawn`.
//!
//! Nothing here grants anything on its own: the caller turns an
//! [`Approval::Approved`] into a lease.

use std::sync::atomic::AtomicBool;
use std::time::Duration;

use crate::lease::Coverage;

/// How an authentication ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthOutcome {
    /// The device's owner proved it was them.
    Authenticated,
    /// Wrong or cancelled authentication, a lockout, or any other refusal by
    /// the system. The text says why, for the person.
    Failed(String),
    /// No answer within the time allowed.
    TimedOut,
    /// This machine can't authenticate its owner (no platform
    /// authenticator, or no way to use it in this session).
    Unavailable(String),
    /// The request was withdrawn while waiting (every commit asking had
    /// gone), so the authentication was cancelled.
    Withdrawn,
}

/// Proof that the person at the device is its owner. Implementations must not
/// be satisfiable by a program that merely controls the screen or the input.
pub trait Authenticator: Send + Sync {
    /// Asks the owner to authenticate, showing `reason`, and waits. It must
    /// stop waiting and return [`AuthOutcome::Withdrawn`] once `cancel` is
    /// set, and must never wait forever.
    fn authenticate(&self, reason: &str, cancel: &AtomicBool) -> AuthOutcome;
}

/// The person's answer to a lease request, or that there was no way to ask.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Approval {
    /// Approved, covering what the person chose, and authenticated.
    Approved(Coverage),
    /// The person said no, or chose nothing.
    Denied,
    /// The person chose a coverage but authentication didn't succeed: the
    /// lease is refused. The text says why.
    NotAuthenticated(String),
    /// Nobody could be asked: the lease is refused (failing closed).
    NoWayToAsk,
    /// The request was closed because every commit waiting on it had gone.
    Withdrawn,
}

/// Sent back when the service couldn't ask the person, so the agent (and the
/// person reading its output) learns why and what to do.
pub const NO_WAY_TO_ASK: &str = "agent-sign couldn't ask you to approve a lease: there is no way to confirm it is you on this machine (on macOS, a desktop session for Touch ID or your password; on Linux there is no platform authenticator yet, so the service only asks at its own terminal). On a machine without a screen, see \"Headless machines\" in docs/INSTALL.md";

impl Approval {
    /// The error to send back for a refusal, or `None` if approved. The
    /// refusals are worded differently so that a headless machine or a
    /// failed fingerprint doesn't report that the person said no.
    pub fn refusal(&self) -> Option<String> {
        match self {
            Approval::Approved(_) => None,
            Approval::Denied => Some("the person denied the signing lease".to_string()),
            Approval::NotAuthenticated(why) => Some(format!(
                "the signing lease was not approved: agent-sign could not confirm it was you ({why}), so it was denied"
            )),
            Approval::NoWayToAsk => Some(NO_WAY_TO_ASK.to_string()),
            Approval::Withdrawn => Some(
                "the approval request was withdrawn: every commit waiting on it had gone"
                    .to_string(),
            ),
        }
    }

    /// Reads a dialog's answer: the label of one of the choices offered is a
    /// choice of that coverage; anything else is a denial, so an answer that
    /// can't be matched never approves more than was shown. This is only the
    /// person's choice: it still needs [`confirm`].
    pub fn selection_from_answer(answer: &str, choices: &[(Coverage, String)]) -> Option<Coverage> {
        let answer = answer.trim();
        choices
            .iter()
            .find(|(_, label)| label == answer)
            .map(|(coverage, _)| coverage.clone())
    }
}

/// Turns the person's choice into a decision. `selection` is what they
/// picked (`None` for Deny, a closed dialog, or nothing picked). It is
/// approved only if `authenticator` succeeds; the authenticator isn't asked
/// at all when there's nothing to approve.
pub fn confirm(
    selection: Option<Coverage>,
    authenticator: &dyn Authenticator,
    reason: &str,
    cancel: &AtomicBool,
) -> Approval {
    let Some(coverage) = selection else {
        return Approval::Denied;
    };
    match authenticator.authenticate(reason, cancel) {
        AuthOutcome::Authenticated => Approval::Approved(coverage),
        AuthOutcome::Failed(why) => Approval::NotAuthenticated(why),
        AuthOutcome::TimedOut => Approval::NotAuthenticated("timed out".to_string()),
        AuthOutcome::Unavailable(why) => Approval::NotAuthenticated(why),
        AuthOutcome::Withdrawn => Approval::Withdrawn,
    }
}

/// The text the system shows with its authentication prompt: short, and
/// naming what is being approved.
pub fn auth_reason(repo: &str, coverage_label: &str) -> String {
    let repo: String = if repo.chars().count() > 120 {
        let tail: String = repo
            .chars()
            .rev()
            .take(117)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        format!("...{tail}")
    } else {
        repo.to_string()
    };
    format!("approve an AI agent's git signing lease for {repo} ({coverage_label})")
}

/// How long to wait for the owner to authenticate before denying. Generous,
/// because a person may be away from the desk; the commit that asked is
/// refused when it ends.
pub const AUTH_TIMEOUT: Duration = Duration::from_secs(300);

/// The authenticator this build uses, or `None` where the platform has none.
///
/// - macOS: LocalAuthentication, policy "device owner authentication"
///   ([`crate::device_owner::DeviceOwner`]).
/// - Test builds (feature `test-authenticator`, switched on only for
///   `cargo test`): a stand-in chosen by `AGENT_SIGN_TEST_AUTH`.
/// - Anything else: `None`. There is deliberately no clickable stand-in.
pub fn platform_authenticator() -> Option<Box<dyn Authenticator>> {
    #[cfg(feature = "test-authenticator")]
    {
        Some(Box::new(TestAuthenticator))
    }
    #[cfg(all(not(feature = "test-authenticator"), target_os = "macos"))]
    {
        Some(Box::new(crate::device_owner::DeviceOwner::new(
            AUTH_TIMEOUT,
        )))
    }
    #[cfg(all(not(feature = "test-authenticator"), not(target_os = "macos")))]
    {
        None
    }
}

/// Stand-in for the owner in end-to-end tests of the service, chosen by
/// `AGENT_SIGN_TEST_AUTH`: `allow` succeeds; `timeout`, `unavailable` and
/// anything else (including unset) deny, `fail` with a reason. It exists
/// only when the feature `test-authenticator` is on, which `cargo build` and
/// `cargo build --release` never do.
#[cfg(feature = "test-authenticator")]
pub struct TestAuthenticator;

#[cfg(feature = "test-authenticator")]
impl Authenticator for TestAuthenticator {
    fn authenticate(&self, _reason: &str, _cancel: &AtomicBool) -> AuthOutcome {
        match std::env::var("AGENT_SIGN_TEST_AUTH").as_deref() {
            Ok("allow") => AuthOutcome::Authenticated,
            Ok("timeout") => AuthOutcome::TimedOut,
            Ok("unavailable") => AuthOutcome::Unavailable("no authenticator".to_string()),
            _ => AuthOutcome::Failed("authentication failed".to_string()),
        }
    }
}
