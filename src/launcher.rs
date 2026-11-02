//! The launcher's shared pieces: the launch socket's protocol, the session
//! spec, the slot folders' names and the rules for what a request may hold
//! (docs/system-mode.md, sections 2 and 3, "D6", "How working copies are
//! shared"; build step 3). The program is `src/bin/agent_launchd.rs`; the
//! session's own side is [`crate::session_runner`]; the caller's side is
//! [`crate::launch_client`].
//!
//! **The launch socket** (`[launcher] socket`, `/run/agent-launch/launch.sock`)
//! speaks one JSON object per line, `{"type":..,"payload":..}`, as the
//! service's socket does. A caller sends one [`LaunchRequest`]. For a
//! `Launch`, the launcher answers `Launched` once the session's unit has
//! started, then `Output` with whatever the session writes, then `Ended`
//! once the session is over and its folder is in the slot's Trash, with
//! the bundles of its new commits; a refusal at any point is `Error`. The
//! caller stays connected for the session's life: when it goes, the session
//! is stopped.
//!
//! **Git crosses only as bundles.** A repository comes in as a git bundle
//! the caller made in its own account, and goes out as a bundle the end step
//! made in the slot's account. The launcher writes and reads bytes; it never
//! runs git, so no repository's config or hooks ever run as the launcher.
//!
//! **Why each check on a request.** Every name in a request becomes a file
//! name in a slot folder ([`is_repo_name`]: one plain name, so it can't
//! reach outside `in/` or `work/`); a base is a git object id; a bundle must
//! start with git's bundle signature (anything else would be refused by git
//! later anyway, but not before the session had started); and the
//! environment is an allow-list, not a filter ([`check_env`]): only `LANG`
//! and `TERM`, each once, with plain values, from every caller. A launch
//! approval signs the agent, program and repositories but never the
//! environment, so whatever environment a relayer adds would otherwise run
//! inside an attested session (`ANTHROPIC_BASE_URL`, `LD_PRELOAD`, git's
//! `GIT_CONFIG_*`); a name outside the list is refused by name, not
//! silently dropped, so nobody believes it took effect.
//!
//! **Bundles after the check.** A request may carry its bundles inline
//! (`bundle_b64`, a person's way and the only way `agent-sign launch` uses), or,
//! with `bundles_follow`, send the head first (no bundle bytes in it) and the
//! bundles on a second line ([`LaunchBundles`]). The launcher reads at most
//! 64 KiB from a caller it has not verified, checks the launch approval on
//! the head, and only then reads the second line, so an account that holds
//! no approval can never make it take bundle bytes.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::time::Duration;

use serde::de::{Error as _, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use crate::launch_approval::ApprovedRepo;

/// The launcher's state folder in production (`StateDirectory=` of
/// `agent-launchd.service`).
pub const STATE_DIR: &str = "/var/lib/agent-launch";

/// The launcher's state folder: [`STATE_DIR`], or in a debug test build
/// only, `AGENT_SIGN_TEST_LAUNCH_STATE`.
pub fn state_dir() -> PathBuf {
    #[cfg(feature = "test-authenticator")]
    if let Some(dir) = std::env::var_os("AGENT_SIGN_TEST_LAUNCH_STATE") {
        return PathBuf::from(dir);
    }
    PathBuf::from(STATE_DIR)
}

/// The launcher's I/O folder in production: the one place every file a slot
/// unit's systemd opens *as root* lives (A-2 of the sitting review, interface
/// I-A2). systemd v259 opens `LoadCredential=spec:...` and
/// `StandardOutput=append:...` as root, before it drops privilege, with no
/// `O_NOFOLLOW`; so those paths must have only root-owned folders on the way.
/// The folder, `specs/` and `logs/` in it are root:agent-launch 0750: the
/// launcher can read the listing and open entries, but no account except root
/// can make, rename or remove one, so nothing a compromised launcher (whose
/// socket is 0666) could plant is ever there for root to follow. The sitting
/// pre-makes `specs/<n>.json` and `logs/<n>.out` for every slot as regular
/// files owned by `agent-launch`, mode 0600; the launcher only opens those
/// (see [`crate::slot_fs::open_existing_file_at`]) and never creates,
/// renames, links or removes an entry here.
pub const IO_DIR: &str = "/var/lib/agent-launch-io";

/// The launcher's I/O folder: [`IO_DIR`], or in a debug test build only,
/// `AGENT_SIGN_TEST_LAUNCH_IO` (a production build ignores the variable: it is
/// not compiled in).
pub fn io_dir() -> PathBuf {
    #[cfg(feature = "test-authenticator")]
    if let Some(dir) = std::env::var_os("AGENT_SIGN_TEST_LAUNCH_IO") {
        return PathBuf::from(dir);
    }
    PathBuf::from(IO_DIR)
}

/// A slot's running session's folder, in `<slots root>/<n>/`.
pub const CURRENT: &str = "current";
/// A slot's Trash, in `<slots root>/<n>/`: owned by the launcher, 0700.
pub const TRASH: &str = "trash";
/// In `current/`: the input bundles the launcher writes.
pub const IN: &str = "in";
/// In `current/`: what the end step leaves for the launcher.
pub const OUT: &str = "out";
/// In `current/out/`: the end step's report, one entry per working copy.
pub const STATUS_FILE: &str = "status.json";
/// In `current/`: the session's working copies.
pub const WORK: &str = "work";
/// In `current/`: the session's home folder.
pub const HOME: &str = "home";
/// In `current/`: the session's private temporary folder.
pub const TMP: &str = "tmp";
/// In the state folder: one line per session that ended, and every move to
/// a Trash.
pub const SESSIONS_LOG: &str = "sessions.log";
/// In the I/O folder ([`IO_DIR`]), not the state folder: `<n>.json`, the spec
/// of slot n's session, a file the sitting made and the launcher only opens.
pub const SPECS: &str = "specs";
/// In the I/O folder ([`IO_DIR`]), not the state folder: `<n>.out`, slot n's
/// output (appended by systemd as root, read and truncated by the launcher).
pub const LOGS: &str = "logs";
/// In the state folder: `<session>/`, bundles kept for `launch --collect`.
pub const RETURNED: &str = "out";

/// The longest request line the launcher reads: bundles travel in it, as
/// base64. A memory guard for the launcher, not a policy: large enough for
/// the suite's repositories' whole histories.
pub const MAX_REQUEST_BYTES: u64 = 512 * 1024 * 1024;

/// The biggest file read back from a session's `out/` (a bundle).
pub const MAX_BUNDLE_BYTES: u64 = 256 * 1024 * 1024;

/// The biggest `status.json` read back.
pub const MAX_STATUS_BYTES: u64 = 1024 * 1024;

/// One repository a caller sends: its name in the session, the commit the
/// session starts from, and a git bundle holding it. With
/// [`LaunchRequest::Launch`]'s `bundles_follow` the bundle isn't here
/// (`bundle_b64` is empty or left out) and comes on the next line.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoIn {
    pub name: String,
    pub base: String,
    #[serde(default)]
    pub bundle_b64: String,
}

/// The second line of a `bundles_follow` launch: each repository's bundle,
/// base64, in the order of the head's `repos`. The launcher reads it only
/// after the head (and, for an account that isn't a person's, the launch
/// approval) has been checked.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchBundles {
    pub bundles_b64: Vec<String>,
}

/// The environment variables a session may be given: the only two names
/// ([`check_env`]).
pub const ALLOWED_ENV: [&str; 2] = ["LANG", "TERM"];

/// The longest value of an allowed variable, in bytes.
pub const MAX_ENV_VALUE_BYTES: usize = 64;

/// A name as shown in a message: quoted, cut at 64 characters (it came from
/// the caller and may be any length).
fn shown(name: &str) -> String {
    let cut: String = name.chars().take(64).collect();
    if cut.len() < name.len() {
        format!("{cut:?}...")
    } else {
        format!("{cut:?}")
    }
}

/// Whether `value` may be an allowed variable's value: 1 to
/// [`MAX_ENV_VALUE_BYTES`] bytes of `A-Za-z0-9._@+-`. Nothing a shell, a
/// path list or a loader would read as more than a word (no space, `/`, `:`,
/// `;`, `=`, `$`, quote or control character).
pub fn is_env_value(value: &str) -> bool {
    (1..=MAX_ENV_VALUE_BYTES).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._@+-".contains(&b))
}

/// The one rule for a session's environment (interface I-M1), applied by the
/// launcher to every request, from a person's account or an approval's
/// holder alike, and again by `session-exec` to the spec it is handed: only
/// [`ALLOWED_ENV`], with values [`is_env_value`] accepts. The first fault
/// refuses the whole request, in plain words naming the variable (never its
/// value). A name sent twice never reaches here: the request's reader
/// refuses it ([`LaunchRequest::Launch`]).
///
/// Widening the list would be a root-owned `system.toml` setting; it is not
/// built, and the list is not the caller's to widen.
pub fn check_env(env: &BTreeMap<String, String>) -> Result<(), String> {
    for (name, value) in env {
        if !ALLOWED_ENV.contains(&name.as_str()) {
            return Err(format!(
                "the environment variable {} isn't allowed: a session is given only LANG and \
                 TERM, so nothing was started",
                shown(name)
            ));
        }
        if !is_env_value(value) {
            return Err(format!(
                "the value of {name} must be 1 to {MAX_ENV_VALUE_BYTES} bytes of letters, \
                 digits, '.', '_', '@', '+' or '-', so nothing was started"
            ));
        }
    }
    Ok(())
}

/// Reads the `env` object refusing a name that appears twice (JSON allows
/// it, and a map would silently keep the last, so a repeat could hide a
/// value from a reader that kept the first).
fn env_without_repeats<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<BTreeMap<String, String>, D::Error> {
    struct Names;
    impl<'de> Visitor<'de> for Names {
        type Value = BTreeMap<String, String>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("an object of environment variables")
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            let mut out = BTreeMap::new();
            while let Some((name, value)) = map.next_entry::<String, String>()? {
                if out.contains_key(&name) {
                    return Err(A::Error::custom(format!(
                        "the environment variable {} is sent more than once",
                        shown(&name)
                    )));
                }
                out.insert(name, value);
            }
            Ok(out)
        }
    }
    d.deserialize_map(Names)
}

/// A launch approval as presented: its exact text and its armored SSHSIG.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalIn {
    pub text: String,
    pub signature: String,
}

/// What a caller asks the launcher.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum LaunchRequest {
    /// Start `command` as a session of `agent`, with `repos` cloned into
    /// it. `approval` is needed unless the caller is a person's account.
    /// `env` is only [`ALLOWED_ENV`] ([`check_env`]); a name sent twice
    /// refuses the request. With `bundles_follow`, the repositories carry no
    /// bundle and one more line follows, a [`LaunchBundles`].
    Launch {
        agent: String,
        command: Vec<String>,
        #[serde(default, deserialize_with = "env_without_repeats")]
        env: BTreeMap<String, String>,
        #[serde(default)]
        repos: Vec<RepoIn>,
        #[serde(default)]
        approval: Option<ApprovalIn>,
        #[serde(default)]
        bundles_follow: bool,
    },
    /// The bundles of a session whose caller went away before its end,
    /// for the account that launched it only.
    Collect { session: String },
}

/// One bundle returned at a session's end.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleOut {
    pub name: String,
    pub bundle_b64: String,
}

/// What the launcher answers.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum LaunchResponse {
    /// The session's unit started.
    Launched {
        session: String,
        slot: u32,
        principal: String,
    },
    /// Bytes the session (or its end step) wrote to its output.
    Output {
        data_b64: String,
    },
    /// The session ended and its folder is in the Trash. `status` is the end
    /// step's report (an object), or a sentence when there was none.
    Ended {
        status: serde_json::Value,
        bundles: Vec<BundleOut>,
    },
    Error {
        message: String,
    },
}

/// What `agent-sign session-exec` runs, written by the launcher into the
/// existing file `<I/O folder>/specs/<n>.json` ([`io_dir`]) and handed to the
/// unit by systemd (`LoadCredential=spec:`), so the slot never reads the
/// launcher's state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionSpec {
    pub session: String,
    pub principal: String,
    pub agent: String,
    pub slot: u32,
    pub command: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub repos: Vec<ApprovedRepo>,
}

/// Whether `name` may name a repository in a session: 1 to 64 letters,
/// digits, `.`, `_` or `-`, not starting with `.` or `-`. It becomes
/// `in/<name>.bundle`, `work/<name>` and `out/<name>.bundle`.
pub fn is_repo_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && !name.starts_with('.')
        && !name.starts_with('-')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
}

/// Whether `bytes` starts like a git bundle (version 2 or 3).
pub fn looks_like_bundle(bytes: &[u8]) -> bool {
    bytes.starts_with(b"# v2 git bundle\n") || bytes.starts_with(b"# v3 git bundle\n")
}

/// Whether `name` may be an environment variable's name in a session.
pub fn is_env_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
        && name.len() <= 128
}

/// Whether `id` may be a session id in a file name: 8 to 64 letters,
/// digits or `-` (the service makes them as hex).
pub fn is_session_id(id: &str) -> bool {
    (8..=64).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// `<root>/<n>/`'s Trash entry name for a session: its UTC end time and the
/// first 8 characters of its id (`20261101T120000Z-1a2b3c4d`), or `leftover`
/// for a folder no live session owned.
pub fn trash_name(now: u64, session: Option<&str>) -> String {
    let time: String = crate::agents_ca::utc_timestamp(now)
        .chars()
        .filter(|c| *c != '-' && *c != ':')
        .collect();
    let tag = session
        .filter(|s| is_session_id(s))
        .map_or_else(|| "leftover".to_string(), |s| s.chars().take(8).collect());
    format!("{time}-{tag}")
}

/// Parses `[slots] max_duration` (`12h`, `90m`, `3600s`, `1d`, or seconds).
pub fn parse_duration(text: &str) -> Result<Duration, String> {
    let t = text.trim();
    let (num, unit) = match t.char_indices().find(|(_, c)| !c.is_ascii_digit()) {
        Some((i, _)) => (&t[..i], &t[i..]),
        None => (t, "s"),
    };
    let n: u64 = num
        .parse()
        .map_err(|_| format!("{text:?} isn't a duration such as 12h"))?;
    let secs = match unit {
        "s" => n,
        "m" => n.saturating_mul(60),
        "h" => n.saturating_mul(3600),
        "d" => n.saturating_mul(86_400),
        _ => return Err(format!("{text:?} isn't a duration such as 12h")),
    };
    if secs == 0 {
        return Err(format!("{text:?} is no time at all"));
    }
    Ok(Duration::from_secs(secs))
}

/// The uid a slot's files must belong to for the launcher to read them:
/// the slot account's. Under the test stand-in for the kernel only, tests
/// can't give files to another account, so a slot's files are the test's
/// own ([`crate::kernel_facts::is_stand_in`]).
pub fn slot_file_owner(slot_uid: u32) -> u32 {
    if crate::kernel_facts::is_stand_in() {
        // SAFETY: geteuid takes no arguments and can't fail.
        return unsafe { libc::geteuid() };
    }
    slot_uid
}

/// Appends one line to `<state>/sessions.log`, synced. Never follows a link
/// at the log's name.
pub fn log_session(state: &std::path::Path, entry: &serde_json::Value) -> std::io::Result<()> {
    let mut f = fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(state.join(SESSIONS_LOG))?;
    f.write_all(format!("{entry}\n").as_bytes())?;
    f.sync_all()
}

/// The span a caller's launches are counted over, one hour. The setting that
/// limits them is `[launcher] launches_per_hour`
/// ([`crate::system_config::LauncherSection::launches_per_hour`]).
pub const LAUNCH_WINDOW_SECS: u64 = 60 * 60;

/// The launches each caller account has made in the last hour (F7 of the
/// review of 1 Nov 2026, round 2): what stops one caller from filling
/// `sessions.log`, the nonce record and the slots by launching in a loop.
///
/// Callers are told apart by the uid the kernel reports, as everywhere in the
/// launcher. The record is memory only and starts empty with the launcher: a
/// restart forgets the hour, which can let a looping caller through once more
/// but loses nothing the audit log keeps (`sessions.log` has every launch).
/// It is bounded: a caller holds at most `limit` timestamps (the check comes
/// before every record), a timestamp leaves an hour after it was made, and a
/// caller with none left leaves the map.
#[derive(Debug, Default)]
pub struct LaunchRate {
    by_uid: std::collections::HashMap<u32, std::collections::VecDeque<u64>>,
}

impl LaunchRate {
    /// Forgets launches older than the window (and callers with none left).
    fn prune(&mut self, now: u64) {
        let from = now.saturating_sub(LAUNCH_WINDOW_SECS);
        self.by_uid.retain(|_, times| {
            while times.front().is_some_and(|t| *t <= from) {
                times.pop_front();
            }
            !times.is_empty()
        });
    }

    /// Whether `uid` may launch now under `limit` launches an hour. Records
    /// nothing: a launch that is refused for another reason must cost no
    /// part of the allowance. The refusal says, in plain words, that
    /// launching too often is what stopped it, and when to try again.
    pub fn check(&mut self, uid: u32, now: u64, limit: u32) -> Result<(), String> {
        self.prune(now);
        let times = self.by_uid.get(&uid);
        let made = times.map_or(0, |t| t.len());
        if made < limit as usize {
            return Ok(());
        }
        let wait = times
            .and_then(|t| t.front())
            .map_or(LAUNCH_WINDOW_SECS, |first| {
                (first + LAUNCH_WINDOW_SECS).saturating_sub(now)
            });
        Err(format!(
            "uid {uid} has made {made} launches in the last hour, the most [launcher] \
             launches_per_hour ({limit}) allows, so launching too often is refused; try again \
             in about {} minutes. Nothing was started and no approval was used up",
            wait.div_ceil(60).max(1)
        ))
    }

    /// Counts a launch by `uid` made at `now`. Call it only after a
    /// successful [`LaunchRate::check`], under the same lock.
    pub fn record(&mut self, uid: u32, now: u64) {
        self.by_uid.entry(uid).or_default().push_back(now);
    }
}

/// Seconds since the epoch.
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_launch_rate_counts_per_caller_over_an_hour() {
        let mut r = LaunchRate::default();
        for t in [100, 200] {
            r.check(7, t, 2).unwrap();
            r.record(7, t);
        }
        let e = r.check(7, 300, 2).unwrap_err();
        assert!(e.contains("launching too often"), "{e}");
        // Another caller is not held back, and a check records nothing.
        r.check(8, 300, 2).unwrap();
        assert!(r.check(7, 300, 2).is_err());
        // The first launch leaves the window an hour after it was made.
        r.check(7, 100 + LAUNCH_WINDOW_SECS, 2).unwrap();
        r.record(7, 100 + LAUNCH_WINDOW_SECS);
        assert!(r.check(7, 101 + LAUNCH_WINDOW_SECS, 2).is_err());
        // Once everything has aged out the caller leaves the map.
        r.check(9, 200 + 2 * LAUNCH_WINDOW_SECS, 2).unwrap();
        assert!(r.by_uid.is_empty());
        // A limit of 0 refuses every launch.
        assert!(LaunchRate::default().check(1, 0, 0).is_err());
    }

    #[test]
    fn repo_names_are_one_plain_name() {
        for good in ["r", "agent-sign", "a.b_c-1"] {
            assert!(is_repo_name(good), "{good}");
        }
        for bad in [
            "",
            ".",
            "..",
            ".git",
            "-x",
            "a/b",
            "a b",
            "a\0",
            &"x".repeat(65),
        ] {
            assert!(!is_repo_name(bad), "{bad:?}");
        }
    }

    #[test]
    fn durations_read() {
        assert_eq!(parse_duration("12h").unwrap(), Duration::from_secs(43_200));
        assert_eq!(parse_duration("90").unwrap(), Duration::from_secs(90));
        assert!(parse_duration("0h").is_err());
        assert!(parse_duration("12 hours").is_err());
    }

    #[test]
    fn trash_names_carry_the_time_and_the_session() {
        let n = trash_name(1_793_000_000, Some("1a2b3c4d5e6f"));
        assert!(n.ends_with("-1a2b3c4d") && !n.contains(':'), "{n}");
        assert!(trash_name(0, Some("../x")).ends_with("-leftover"));
    }

    #[test]
    fn a_name_sent_twice_in_the_environment_refuses_the_request() {
        let dup = r#"{"type":"Launch","payload":{"agent":"a","command":["x"],"env":{"LANG":"C","LANG":"D"}}}"#;
        let e = serde_json::from_str::<LaunchRequest>(dup)
            .unwrap_err()
            .to_string();
        assert!(e.contains("LANG") && e.contains("more than once"), "{e}");
        let ok = r#"{"type":"Launch","payload":{"agent":"a","command":["x"],"env":{"LANG":"C","TERM":"D"}}}"#;
        assert!(serde_json::from_str::<LaunchRequest>(ok).is_ok());
    }

    #[test]
    fn bundles_may_follow_the_head() {
        let head = r#"{"type":"Launch","payload":{"agent":"a","command":["x"],"repos":[{"name":"r","base":"b"}],"bundles_follow":true}}"#;
        let LaunchRequest::Launch {
            repos,
            bundles_follow,
            ..
        } = serde_json::from_str(head).unwrap()
        else {
            panic!("not a launch")
        };
        assert!(bundles_follow && repos[0].bundle_b64.is_empty());
        assert!(
            serde_json::from_str::<LaunchBundles>(r#"{"bundles_b64":["x"],"more":1}"#).is_err()
        );
    }

    #[test]
    fn the_protocol_reads_what_the_tests_send() {
        let r: LaunchRequest = serde_json::from_str(
            r#"{"type":"Launch","payload":{"agent":"a","command":["sleep","1"],"env":{},"repos":[],"approval":null}}"#,
        )
        .unwrap();
        assert!(matches!(r, LaunchRequest::Launch { .. }));
    }
}
