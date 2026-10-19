//! What it takes to approve a signing lease: the platform's own
//! authentication, with a reason that says what is being approved.
//!
//! A dialog alone proves nothing. Any program allowed to control the screen
//! (a computer-use agent, a System Events script) can click its button, so an
//! agent could approve its own lease. So the service shows no dialog of its
//! own: the approval is one prompt from the platform's authentication (on
//! macOS, Touch ID or the login password, through LocalAuthentication; see
//! [`crate::device_owner`]), whose reason text ([`auth_reason`]) says plainly
//! which branch of which repository is being approved. A program can't answer
//! that prompt for the owner.
//!
//! This module is the decision, kept apart from any platform call so it can
//! be tested with a stand-in [`Authenticator`]:
//!
//! - an approval is granted only if the authenticator says
//!   [`AuthOutcome::Authenticated`]; failure, cancellation, timeout and
//!   unavailability all deny;
//! - when the request is withdrawn while the authenticator waits, the
//!   authentication is cancelled and the result is `Withdrawn`.
//!
//! What a lease covers is not chosen at the prompt: it is the narrowest
//! coverage (this branch of this repository) unless the config widens it
//! (`allow_branch_switching`, `lease_scope`). That keeps the prompt to one
//! question the person can read in full.
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
    /// Approved, covering what the prompt said, and authenticated.
    Approved(Coverage),
    /// Refused with `agent-sign deny` while the prompt was open.
    Denied,
    /// Authentication didn't succeed (cancelled, failed, timed out): the
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
}

/// Turns the authentication into a decision: `coverage` is approved only if
/// `authenticator` succeeds, showing `reason`. Failure, cancellation and
/// timeout refuse, and so does an authenticator that can't be used here
/// ([`Approval::NoWayToAsk`]).
pub fn confirm(
    coverage: Coverage,
    authenticator: &dyn Authenticator,
    reason: &str,
    cancel: &AtomicBool,
) -> Approval {
    match authenticator.authenticate(reason, cancel) {
        AuthOutcome::Authenticated => Approval::Approved(coverage),
        AuthOutcome::Failed(why) => Approval::NotAuthenticated(why),
        AuthOutcome::TimedOut => Approval::NotAuthenticated("timed out".to_string()),
        // Nobody could be asked at all (no password set, no desktop
        // session): that is not a refusal, so it is worded as one that
        // couldn't ask, and doesn't hold back the next request.
        AuthOutcome::Unavailable(_) => Approval::NoWayToAsk,
        AuthOutcome::Withdrawn => Approval::Withdrawn,
    }
}

/// Whether `c` is invisible or can reshape text around it: a control
/// character (Unicode Cc), a format character such as the bidirectional
/// overrides and isolates and the zero-width characters (Cf), a line or
/// paragraph separator (Zl, Zp), or a blank filler that passes for a space.
/// Text with any of these must not reach a prompt the person relies on.
pub fn is_unsafe_display_char(c: char) -> bool {
    c.is_control()
        || matches!(c,
            '\u{00AD}' | '\u{0600}'..='\u{0605}' | '\u{061C}' | '\u{06DD}' | '\u{070F}'
            | '\u{0890}'..='\u{0891}' | '\u{08E2}' | '\u{180E}' | '\u{200B}'..='\u{200F}'
            | '\u{2028}'..='\u{202E}' | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{206F}'
            | '\u{FEFF}' | '\u{FFF9}'..='\u{FFFB}' | '\u{110BD}' | '\u{110CD}'
            | '\u{13430}'..='\u{1343F}' | '\u{1BCA0}'..='\u{1BCA3}' | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0001}' | '\u{E0020}'..='\u{E007F}'
            // Characters that draw nothing but aren't format characters:
            // the Hangul fillers, Khmer inherent vowels and the blank braille
            // pattern, which pass for spaces.
            | '\u{115F}' | '\u{1160}' | '\u{17B4}' | '\u{17B5}' | '\u{2800}'
            | '\u{3164}' | '\u{FFA0}')
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

/// Which branches a new lease reaches, as the prompt says it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BranchReach {
    /// This branch only (the default, and the narrowest).
    This(String),
    /// Every branch except the protected ones (`allow_branch_switching`, or
    /// `lease_scope = "repo"`).
    AnyUnprotected,
    /// Every branch, protected ones included (`allow_main_branch`, or no
    /// protected branches).
    Any,
}

/// The most characters of each part of the reason text. The whole reason is
/// at most [`MAX_REASON_CHARS`].
///
/// macOS documents no maximum for LocalAuthentication's reason. The system
/// puts it in the sentence "<name> is trying to <reason>." and wraps it in
/// the prompt, but the Touch Bar form ("Touch ID to <reason>") has to fit in
/// one line. So the reason is kept short and ordered by importance: the
/// branch and the repository's name come first and are only shortened when
/// they are unusually long, and the path, which comes later, gives way first.
const MAX_BRANCH_CHARS: usize = 32;
const MAX_NAME_CHARS: usize = 20;
const MAX_PATH_CHARS: usize = 32;
const MAX_WORKTREE_CHARS: usize = 16;
const MAX_ENDS_CHARS: usize = 32;

/// The longest reason [`auth_reason`] ever produces.
pub const MAX_REASON_CHARS: usize = 200;

/// `path` with the start of `home` replaced by `~`, the way a person writes
/// it. Only a whole leading folder is replaced: `/Users/me2/x` is not under
/// `/Users/me`.
pub fn short_path(path: &str, home: Option<&str>) -> String {
    if let Some(home) = home
        .map(|h| h.trim_end_matches('/'))
        .filter(|h| !h.is_empty())
    {
        if path == home {
            return "~".to_string();
        }
        if let Some(rest) = path.strip_prefix(home)
            && rest.starts_with('/')
        {
            return format!("~{rest}");
        }
    }
    path.to_string()
}

/// The last folder of `path`: the repository's name as the person knows it.
fn repo_name(path: &str) -> &str {
    let trimmed = path.trim_end_matches('/');
    match trimmed.rsplit('/').next() {
        Some(name) if !name.is_empty() => name,
        _ => trimmed,
    }
}

/// Whether `c` is a right-to-left letter (Hebrew, Arabic, Syriac, Thaana,
/// N'Ko and their presentation forms). Next to the prompt's own punctuation
/// these can make the bidirectional algorithm reorder it.
fn is_rtl_letter(c: char) -> bool {
    matches!(c,
        '\u{0590}'..='\u{08FF}' | '\u{FB1D}'..='\u{FDFF}' | '\u{FE70}'..='\u{FEFF}'
        | '\u{10800}'..='\u{10FFF}' | '\u{1E800}'..='\u{1EFFF}')
}

/// A folder name or path made to sit inside the prompt's sentence: unsafe
/// characters removed and the text shortened by [`display_text`], then the
/// characters that could close or open the sentence's own brackets and quotes
/// ( `(` `)` `"` and the curly quotes), and right-to-left letters, shown as
/// `?`. Folder names are the agent's to choose, and a repository named
/// `x (~/dev/suite)` must not read as two places.
fn plain(text: &str, max: usize) -> String {
    display_text(text, max)
        .chars()
        .map(|c| {
            if matches!(c, '(' | ')' | '"' | '\u{201C}' | '\u{201D}') || is_rtl_letter(c) {
                '?'
            } else {
                c
            }
        })
        .collect()
}

/// What the approval prompt is about, all of it verified by the service
/// before it asks.
#[derive(Debug, Clone)]
pub struct Asked<'a> {
    /// The repository whose object store the commits go into: the canonical
    /// path, or, for a linked worktree, the main repository's.
    pub repo: &'a str,
    /// For a linked worktree, the worktree's own canonical path.
    pub worktree: Option<&'a str>,
    /// The person's home folder, shown as `~`.
    pub home: Option<&'a str>,
    /// Which branches the lease will cover.
    pub reach: &'a BranchReach,
    /// How long it lasts, in a few words ("until merged"); see
    /// `LeasePolicy::end_phrase`.
    pub ends: &'a str,
}

/// The text the system shows as the reason in its authentication prompt. It
/// is the one statement of what is being approved that the agent can't alter
/// after the fact, so it says it plainly, in fixed wording from the service:
/// `let an agent sign commits on branch “<branch>” in <repo name> (<path>),
/// until merged`. On macOS the prompt reads "agent-sign is trying to
/// <reason>.", so the reason starts lowercase and has no full stop.
///
/// The branch is checked before this (valid, plain characters, the one the
/// repository has checked out: see [`crate::repo_info`]) and set in curly
/// quotes so it reads as a name. The names and paths are the agent's to
/// choose, so they are cleaned by [`plain`]. For a linked worktree the
/// parentheses also say `worktree “<name>”`. The result is at most
/// [`MAX_REASON_CHARS`] characters.
pub fn auth_reason(asked: &Asked) -> String {
    let name = plain(repo_name(asked.repo), MAX_NAME_CHARS);
    let path = plain(&short_path(asked.repo, asked.home), MAX_PATH_CHARS);
    let on = match asked.reach {
        BranchReach::This(branch) => {
            format!("branch \u{201C}{}\u{201D}", plain(branch, MAX_BRANCH_CHARS))
        }
        BranchReach::AnyUnprotected => "any unprotected branch".to_string(),
        BranchReach::Any => "any branch".to_string(),
    };
    let place = match asked.worktree {
        Some(worktree) => format!(
            "{path}, worktree \u{201C}{}\u{201D}",
            plain(repo_name(worktree), MAX_WORKTREE_CHARS)
        ),
        None => path,
    };
    let ends = plain(asked.ends, MAX_ENDS_CHARS);
    format!("let an agent sign commits on {on} in {name} ({place}), {ends}")
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

/// Stand-in for the owner in end-to-end tests of the service. It exists only
/// when the feature `test-authenticator` is on, which `cargo build` and
/// `cargo build --release` never do.
///
/// `AGENT_SIGN_TEST_AUTH` chooses the outcome: `allow` succeeds; `timeout`,
/// `unavailable` and anything else (including unset) deny, `fail` with a
/// reason. Three more variables let a test watch and steer the prompt:
///
/// - `AGENT_SIGN_TEST_AUTH_LOG`: a file that gets each reason the owner would
///   have been shown, one line per prompt; `<file>.events` gets `start` and
///   `end` around each prompt (to see prompts overlap), and
///   `<file>.withdrawn` gets a line when a prompt is cancelled while open.
/// - `AGENT_SIGN_TEST_AUTH_DELAY_MS`: the prompt stays open this long first.
/// - `AGENT_SIGN_TEST_AUTH_ANSWER`: a file; the prompt stays open until it
///   exists, and what it holds (`allow`, `timeout`, anything else denies)
///   replaces `AGENT_SIGN_TEST_AUTH`. This is how a test plays the person
///   taking their time.
///
/// Like the real thing, it stops waiting when `cancel` is set and gives up,
/// denying, after [`AUTH_TIMEOUT`].
#[cfg(feature = "test-authenticator")]
pub struct TestAuthenticator;

#[cfg(feature = "test-authenticator")]
fn append_line(path: &std::path::Path, line: &str) {
    use std::io::Write;
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = writeln!(file, "{line}");
    }
}

#[cfg(feature = "test-authenticator")]
impl Authenticator for TestAuthenticator {
    fn authenticate(&self, reason: &str, cancel: &AtomicBool) -> AuthOutcome {
        use std::sync::atomic::Ordering;
        let log = std::env::var_os("AGENT_SIGN_TEST_AUTH_LOG").map(std::path::PathBuf::from);
        let side_file = |suffix: &str| {
            log.as_ref().map(|p| {
                let mut name = p.clone().into_os_string();
                name.push(suffix);
                std::path::PathBuf::from(name)
            })
        };
        let event = |line: &str| {
            if let Some(path) = side_file(".events") {
                append_line(&path, line);
            }
        };
        if let Some(path) = &log {
            append_line(path, reason);
        }
        event("start");

        let answer = std::env::var_os("AGENT_SIGN_TEST_AUTH_ANSWER").map(std::path::PathBuf::from);
        let delay = std::env::var("AGENT_SIGN_TEST_AUTH_DELAY_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .map(Duration::from_millis);
        let started = std::time::Instant::now();
        loop {
            let waiting = match (&answer, delay) {
                (Some(path), _) => !path.exists(),
                (None, Some(d)) => started.elapsed() < d,
                (None, None) => false,
            };
            if !waiting {
                break;
            }
            if cancel.load(Ordering::SeqCst) {
                if let Some(path) = side_file(".withdrawn") {
                    append_line(&path, "withdrawn");
                }
                event("end");
                return AuthOutcome::Withdrawn;
            }
            if started.elapsed() >= AUTH_TIMEOUT {
                event("end");
                return AuthOutcome::TimedOut;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        event("end");

        let chosen = match &answer {
            Some(path) => std::fs::read_to_string(path)
                .map(|t| t.trim().to_string())
                .unwrap_or_default(),
            None => std::env::var("AGENT_SIGN_TEST_AUTH").unwrap_or_default(),
        };
        match chosen.as_str() {
            "allow" => AuthOutcome::Authenticated,
            "timeout" => AuthOutcome::TimedOut,
            "unavailable" => AuthOutcome::Unavailable("no authenticator".to_string()),
            _ => AuthOutcome::Failed("authentication failed".to_string()),
        }
    }
}
