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
pub const NO_WAY_TO_ASK: &str = "agent-sign couldn't ask you to approve a lease: there is no way to confirm it is you here. On macOS that needs a desktop session (Touch ID or your login password). Linux has no way to approve yet, so every request there is refused unless auto_approve is on. On a machine without a screen, see \"Headless machines\" in docs/INSTALL.md";

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

/// Whether `c` is invisible or can reshape text around it: a control
/// character (Unicode Cc), a format character such as the bidirectional
/// overrides and isolates and the zero-width characters (Cf), or a line or
/// paragraph separator (Zl, Zp). Text with any of these must not reach a
/// prompt the person relies on.
pub fn is_unsafe_display_char(c: char) -> bool {
    c.is_control()
        || matches!(c,
            '\u{00AD}' | '\u{0600}'..='\u{0605}' | '\u{061C}' | '\u{06DD}' | '\u{070F}'
            | '\u{0890}'..='\u{0891}' | '\u{08E2}' | '\u{180E}' | '\u{200B}'..='\u{200F}'
            | '\u{2028}'..='\u{202E}' | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{206F}'
            | '\u{FEFF}' | '\u{FFF9}'..='\u{FFFB}' | '\u{110BD}' | '\u{110CD}'
            | '\u{13430}'..='\u{1343F}' | '\u{1BCA0}'..='\u{1BCA3}' | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0001}' | '\u{E0020}'..='\u{E007F}')
}

/// Whether `text` contains anything [`is_unsafe_display_char`] names. A
/// request whose repository or branch does, is refused before anyone is asked.
pub fn has_unsafe_display_chars(text: &str) -> bool {
    text.chars().any(is_unsafe_display_char)
}

/// `text` for display: unsafe characters removed, and cut to at most `max`
/// characters by dropping the middle (so both the start and the end, which
/// is where a path says what it is, stay visible).
pub fn display_text(text: &str, max: usize) -> String {
    let clean: Vec<char> = text
        .chars()
        .filter(|c| !is_unsafe_display_char(*c))
        .collect();
    if clean.len() <= max {
        return clean.into_iter().collect();
    }
    let keep = max.saturating_sub(3);
    let head = keep / 2;
    let tail = keep - head;
    let mut out: String = clean[..head].iter().collect();
    out.push_str("...");
    out.extend(clean[clean.len() - tail..].iter());
    out
}

/// The text the system shows with its authentication prompt. It is the one
/// statement of what is being approved that the agent can't alter after the
/// fact, so it leads with the coverage the person chose, in fixed wording
/// (the label comes from the service, not the agent), then says where the
/// request came from: the repository (the verified path) and the branch,
/// cleaned and shortened by [`display_text`].
pub fn auth_reason(repo: &str, branch: &str, coverage_label: &str) -> String {
    format!(
        "allow AI agents to sign git commits: {} (asked from {}, branch {})",
        display_text(coverage_label, 120),
        display_text(repo, 100),
        display_text(branch, 60)
    )
}

/// The most approval requests that may be open at once. A request holds a
/// thread and may hold a dialog, so an agent can't pile them up by asking
/// from many branches.
pub const MAX_PENDING_REQUESTS: usize = 4;

/// The longest the service ever holds back after refusals.
const BACKOFF_CAP: Duration = Duration::from_secs(3600);

/// Holds back new approval requests after the person (or the system) refused
/// one, so an agent can't keep a Touch ID prompt coming until a reflexive
/// touch gives in. After each refusal in a row the wait doubles, up to an
/// hour; an approval resets it. A zero `base` turns it off.
#[derive(Debug, Clone)]
pub struct RefusalBackoff {
    base: Duration,
    in_a_row: u32,
    until: Option<std::time::Instant>,
}

impl RefusalBackoff {
    /// One that waits `base` after the first refusal, then double that, and so on.
    pub fn new(base: Duration) -> Self {
        RefusalBackoff {
            base,
            in_a_row: 0,
            until: None,
        }
    }

    /// How much longer new requests are held back at `now`, if at all.
    pub fn remaining(&self, now: std::time::Instant) -> Option<Duration> {
        self.until
            .and_then(|t| t.checked_duration_since(now))
            .filter(|d| !d.is_zero())
    }

    /// A prompt was refused (Deny, cancelled, failed, or timed out).
    pub fn record_refusal(&mut self, now: std::time::Instant) {
        if self.base.is_zero() {
            return;
        }
        let doublings = self.in_a_row.min(16);
        let wait = self
            .base
            .checked_mul(1u32 << doublings)
            .unwrap_or(BACKOFF_CAP)
            .min(BACKOFF_CAP);
        self.in_a_row = self.in_a_row.saturating_add(1);
        self.until = Some(now + wait);
    }

    /// A lease was approved: the next refusal starts from the base again.
    pub fn record_approval(&mut self) {
        self.in_a_row = 0;
        self.until = None;
    }
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
/// `AGENT_SIGN_TEST_AUTH` (and, if `AGENT_SIGN_TEST_AUTH_LOG` names a file,
/// recording each reason it was shown): `allow` succeeds; `timeout`, `unavailable` and
/// anything else (including unset) deny, `fail` with a reason. It exists
/// only when the feature `test-authenticator` is on, which `cargo build` and
/// `cargo build --release` never do.
#[cfg(feature = "test-authenticator")]
pub struct TestAuthenticator;

#[cfg(feature = "test-authenticator")]
impl Authenticator for TestAuthenticator {
    fn authenticate(&self, reason: &str, _cancel: &AtomicBool) -> AuthOutcome {
        // Where a test wants to see what the owner would have been shown.
        if let Some(path) = std::env::var_os("AGENT_SIGN_TEST_AUTH_LOG") {
            use std::io::Write;
            if let Ok(mut file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
            {
                let _ = writeln!(file, "{reason}");
            }
        }
        match std::env::var("AGENT_SIGN_TEST_AUTH").as_deref() {
            Ok("allow") => AuthOutcome::Authenticated,
            Ok("timeout") => AuthOutcome::TimedOut,
            Ok("unavailable") => AuthOutcome::Unavailable("no authenticator".to_string()),
            _ => AuthOutcome::Failed("authentication failed".to_string()),
        }
    }
}
