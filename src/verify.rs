//! `agent-sign verify <rev>`: checks a commit's signature, then says how the
//! signer's identity was established (P8, docs/caller-identity.md).
//!
//! It also reports the commit's author email and whether it is exactly the
//! verified signer ([`Verdict::author`], [`Verdict::author_matches_signer`],
//! re-check R3): the signature covers the whole commit, but the certificate
//! names only the committer, so a gate that needs the *author* to be the agent
//! must require `author_matches_signer`. The author never changes the
//! verdict or the exit code.
//!
//! Why: `git log --show-signature` says a signature is Good for an agent's
//! principal, and nothing about whether that name was established or merely
//! claimed by a process in a shared account. agent-sign's certificates now
//! record that ([`crate::attestation`]), and this command reads it out.
//!
//! The order is the point (the critique of the build plan, 31 Oct 2026):
//! anybody can mint a certificate whose attestation extension says
//! "launcher" or "approval", so the extension means something only for a
//! certificate from an authority the verifier trusts. So nothing is read
//! from the certificate until `ssh-keygen -Y verify` has accepted the
//! signature, and when it hasn't, the command prints "not verified: <why>"
//! and no attestation, and exits non-zero. The check is the one git itself
//! makes, done here so that neither the repository nor the session being
//! checked can redirect it (the second whole-branch review, 1 Nov 2026):
//! - against a trust file the verifier chooses, never the repository
//!   ([`trust_file`]): `--allowed-signers <file>` when the caller names it
//!   (what a gate should pass); else, in system mode, always
//!   `/etc/agent-sign/allowed_signers`; else the file git's *system* and
//!   *global* configuration name. The repository's own config (and its
//!   worktree config, `includeIf`, `GIT_CONFIG_COUNT` and
//!   `GIT_CONFIG_PARAMETERS`) is a session's to write, so it is never read
//!   for this: a session that could point the trust file at its own
//!   authority could mint its own "launcher" attestation (F2);
//! - on the commit's own bytes: every git run here ignores `refs/replace/*`
//!   (a pushed replace ref could make an unsigned commit read as an attested
//!   one, F1), and the bytes read are hashed again and must hash to the
//!   commit's name, so an object that is not what its name says is refused
//!   even where git's own read would let it through;
//! - with the system's `ssh-keygen` by absolute path, never one found on
//!   `PATH` and never git's `gpg.ssh.program`, which can name any program
//!   (on an agent machine, agent-sign's own signer);
//! - for the commit's committer email as the principal, which the
//!   certificate must name;
//! - at the committer's date (`-Overify-time`), as git does, so a
//!   certificate that has since expired still verifies for commits made
//!   while it was valid.

use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use base64::Engine;
use ssh_key::Certificate;

use crate::attestation::{Attestation, EXTENSION, describe_missing, describe_unreadable};
use crate::ssh_sign::system_ssh_keygen;

// About the `#[allow(clippy::result_large_err)]` on `trust_file`, `check` and
// `check_signature` below: a `Verdict` is the answer itself, made once per run of `agent-sign verify`
// (never in a loop), so the size of the `Err` it travels in costs nothing
// that boxing it would repay; boxing it would also change `trust_file`'s
// public type. The author field (re-check R3) took it past clippy's 128 bytes.

/// What a verified commit's signature says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    /// The principal the signature is Good for (the committer's email).
    pub principal: String,
    /// How that identity was established, in plain words.
    pub attestation: String,
    /// Whether a launcher or an approval established it. When not, the
    /// commit can live on a branch but not reach main ([`MERGE_NOTE`]).
    pub attested: bool,
}

/// What `agent-sign verify` adds to a commit that is unsigned or whose
/// signature isn't attested (D1, 1 Nov 2026): such a commit is allowed on a
/// branch, since unsigned claims nothing. The merge gate that enforces this
/// is not built yet; this says what it will require.
pub const MERGE_NOTE: &str = "This commit can live on a branch, but merging to main will \
require an attested signature (launcher or approval).";

/// A commit object split into what was signed and its `gpgsig` signature,
/// or `None` when it carries no signature (or more than one).
pub fn split_signature(raw: &str) -> Option<(String, String)> {
    let (headers, message) = raw.split_once("\n\n")?;
    let mut payload = String::with_capacity(raw.len());
    let mut signature: Option<Vec<&str>> = None;
    let mut in_signature = false;
    for line in headers.split('\n') {
        if let Some(first) = line.strip_prefix("gpgsig ") {
            if signature.is_some() {
                return None;
            }
            signature = Some(vec![first]);
            in_signature = true;
            continue;
        }
        if in_signature {
            if let Some(more) = line.strip_prefix(' ') {
                signature.as_mut()?.push(more);
                continue;
            }
            in_signature = false;
        }
        payload.push_str(line);
        payload.push('\n');
    }
    payload.push('\n');
    payload.push_str(message);
    let mut signature = signature?.join("\n");
    signature.push('\n');
    Some((payload, signature))
}

/// Reads one SSH wire string from `bytes` at `at`, advancing it.
fn read_string<'a>(bytes: &'a [u8], at: &mut usize) -> Option<&'a [u8]> {
    let len = u32::from_be_bytes(bytes.get(*at..*at + 4)?.try_into().ok()?) as usize;
    let start = *at + 4;
    let out = bytes.get(start..start.checked_add(len)?)?;
    *at = start + len;
    Some(out)
}

/// The public key blob an armored SSHSIG carries (a certificate's, for an
/// agent's signature), or `None` when it isn't one.
pub fn sshsig_public_key(armored: &str) -> Option<Vec<u8>> {
    let body: String = armored
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("-----"))
        .collect();
    let raw = base64::engine::general_purpose::STANDARD
        .decode(body)
        .ok()?;
    let rest = raw.strip_prefix(b"SSHSIG")?;
    let mut at = 4; // the version
    rest.get(..4)?;
    read_string(rest, &mut at).map(<[u8]>::to_vec)
}

/// The email between `<` and `>` in an ident line (`Name <email> time zone`,
/// without its `author `/`committer ` word): the first `<` to the next `>`,
/// as git reads it. One reading for the committer and the author, so the two
/// are compared as they are written.
fn ident_email(line: &str) -> Option<&str> {
    let (_, rest) = line.split_once('<')?;
    let (email, _) = rest.split_once('>')?;
    Some(email)
}

/// The email of the commit's one `author` line, as the commit has it
/// (nothing folded or trimmed), or `None` when the commit does not have
/// exactly one author line with an email. Read from the commit's headers
/// only (the text before the first blank line): a signature's lines and the
/// message cannot supply an author, because a header's continuation lines
/// begin with a space.
fn author_of(raw: &str) -> Option<String> {
    let headers = raw.split_once("\n\n").map_or(raw, |(h, _)| h);
    let mut authors = headers
        .split('\n')
        .filter_map(|l| l.strip_prefix("author "));
    let line = authors.next()?;
    if authors.next().is_some() {
        return None;
    }
    ident_email(line).map(str::to_string)
}

/// The email of the commit's one `committer` line, and its time.
fn committer_of(payload: &str) -> Option<(String, u64)> {
    let headers = payload.split_once("\n\n").map_or(payload, |(h, _)| h);
    let mut committers = headers
        .split('\n')
        .filter_map(|l| l.strip_prefix("committer "));
    let line = committers.next()?;
    if committers.next().is_some() {
        return None;
    }
    let email = ident_email(line)?;
    let when = crate::agents_ca::committer_time(payload.as_bytes())?;
    Some((email.to_string(), when))
}

/// `secs` as ssh-keygen's `verify-time` (`YYYYMMDDHHMMSSZ`, UTC).
pub(crate) fn verify_time(secs: u64) -> String {
    crate::agents_ca::utc_timestamp(secs)
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == 'Z')
        .collect()
}

/// `text`'s first non-empty line, printable ASCII only and at most 200
/// characters: ssh-keygen's own words about a failure, safe to print.
fn first_line(text: &[u8]) -> String {
    String::from_utf8_lossy(text)
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or_default()
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(200)
        .collect()
}

/// A file holding a signature for ssh-keygen to read, removed when dropped.
struct SignatureFile(PathBuf);

impl SignatureFile {
    fn new(signature: &str) -> Result<Self, String> {
        let path = std::env::temp_dir().join(format!(
            "agent-sign-verify-{}.sig",
            uuid::Uuid::new_v4().simple()
        ));
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| format!("couldn't write the signature for ssh-keygen ({e})"))?;
        let made = Self(path);
        file.write_all(signature.as_bytes())
            .map_err(|e| format!("couldn't write the signature for ssh-keygen ({e})"))?;
        Ok(made)
    }
}

impl Drop for SignatureFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

/// The real git, set to ignore replace refs both ways git can be told
/// (`--no-replace-objects` and `GIT_NO_REPLACE_OBJECTS=1`): a replace ref is
/// pushed like any ref, and with one git serves another object's bytes under
/// a commit's name (F1). It is also told never to fetch a missing object
/// lazily (`GIT_NO_LAZY_FETCH=1`, git 2.44 and later): a repository's own
/// config can make itself a partial clone whose promisor remote is reached
/// through `core.sshCommand`, and a lazy fetch would then run that command as
/// the verifier. That switch does nothing on an older git, so no transport is
/// allowed at all either (`GIT_ALLOW_PROTOCOL=` empty, git 2.12 and later):
/// even a git that ignores the first switch can't start `ssh`, `file` or any
/// other transport, so nothing the repository's config names runs. Every git
/// `verify` runs starts here.
fn git_command() -> Command {
    let mut cmd = Command::new(crate::paths::real_git());
    cmd.arg("--no-replace-objects")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_ALLOW_PROTOCOL", "");
    cmd
}

/// Runs the real git in `dir` with `args`, giving it `input` on its standard
/// input: its output, or why it failed.
fn git_with_input(dir: &Path, args: &[&str], input: &[u8]) -> Result<Vec<u8>, String> {
    let mut child = git_command()
        .args(args)
        .current_dir(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("couldn't run git ({e})"))?;
    // git may stop reading early; its answer is what counts.
    let _ = child.stdin.take().map(|mut stdin| stdin.write_all(input));
    let out = child
        .wait_with_output()
        .map_err(|e| format!("git didn't finish ({e})"))?;
    if !out.status.success() {
        return Err(first_line(&out.stderr));
    }
    Ok(out.stdout)
}

/// Runs the real git in `dir` with `args`: its output, or why it failed.
fn git(dir: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    git_with_input(dir, args, &[])
}

/// The value of `gpg.ssh.allowedSignersFile` in git's `scope` (`--system` or
/// `--global`) configuration alone, or `None`. Asked of the real git from `/`
/// and outside any repository, with every other way of handing git a setting
/// taken out of its environment (`GIT_DIR`, `GIT_WORK_TREE`,
/// `GIT_CONFIG_COUNT` and its `KEY_*`/`VALUE_*`, `GIT_CONFIG_PARAMETERS`,
/// `GIT_CONFIG`), so what comes back is what the machine's and the person's
/// own files say. `GIT_CONFIG_GLOBAL`, `GIT_CONFIG_SYSTEM`,
/// `GIT_CONFIG_NOSYSTEM` and `HOME` are the verifier's own environment, and
/// are honoured. `--includes` is explicit because git leaves includes off
/// when one scope is asked for, and a person's global config may include.
fn git_scope_trust_file(scope: &str) -> Option<String> {
    let mut cmd = git_command();
    for (name, _) in std::env::vars_os() {
        let name = name.to_string_lossy().into_owned();
        if name.starts_with("GIT_CONFIG_KEY_") || name.starts_with("GIT_CONFIG_VALUE_") {
            cmd.env_remove(name);
        }
    }
    for name in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_COMMON_DIR",
        "GIT_CONFIG",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_PARAMETERS",
    ] {
        cmd.env_remove(name);
    }
    let out = cmd
        .args([
            "config",
            scope,
            "--includes",
            "--path",
            "--get",
            "gpg.ssh.allowedSignersFile",
        ])
        .current_dir("/")
        .stdin(Stdio::null())
        .output()
        .ok()?;
    let value = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (out.status.success() && !value.is_empty()).then_some(value)
}

/// Where the allowed signers come from (F2, the second whole-branch review).
///
/// Why not the repository's git config, which `git config --get` reads and
/// which wins over the global one: the session being checked can write the
/// repository's config (`.git/config`, a linked worktree's `config.worktree`,
/// an `includeIf` it adds), and with it name an allowed-signers file holding
/// an authority it made itself, so its own commit, carrying a
/// "launcher" attestation it minted, would verify as attested. The trust
/// file is a decision for the verifier's side, so, in order:
/// 1. `explicit`, the `--allowed-signers` a gate passes;
/// 2. in system mode (`/etc/agent-sign/system.toml` exists), the root-owned
///    `/etc/agent-sign/allowed_signers`, whatever any git config says (in a
///    debug test build the file beside the stand-in `system.toml` that
///    `AGENT_SIGN_TEST_SYSTEM_CONFIG` names, see [`crate::launch`]);
/// 3. the file git's global configuration names, else the one its system
///    configuration names ([`git_scope_trust_file`]), global winning as in
///    git.
///
/// `Err` is the verdict when there is none, or it can't be used: the file
/// must be an absolute path to a readable file (a relative one would be read
/// from the repository being checked, which the session controls).
#[allow(clippy::result_large_err)]
pub fn trust_file(explicit: Option<&Path>) -> Result<PathBuf, Verdict> {
    let (path, how) = if let Some(path) = explicit {
        (path.to_path_buf(), "named with --allowed-signers")
    } else if let Some(config) = crate::launch::system_config() {
        let beside = config.parent().map(|dir| dir.join("allowed_signers"));
        (
            beside.unwrap_or_else(|| PathBuf::from("/etc/agent-sign/allowed_signers")),
            "pinned by system mode",
        )
    } else {
        let named = git_scope_trust_file("--global").or_else(|| git_scope_trust_file("--system"));
        match named {
            Some(file) => (
                PathBuf::from(file),
                "named by git's global or system config",
            ),
            None => {
                return Err(Verdict::refused(
                    Reason::NoTrustFile,
                    "git's global and system configuration name no allowed-signers file \
                     (gpg.ssh.allowedSignersFile), and none was given with --allowed-signers, \
                     so there is nothing to verify against",
                ));
            }
        }
    };
    let shown = plain_text(&path.display().to_string());
    if explicit.is_none() && !path.is_absolute() {
        return Err(Verdict::refused(
            Reason::NoTrustFile,
            format!(
                "the trust file {shown} is a relative path, which would be read from the \
                 repository being checked; name an absolute path"
            ),
        ));
    }
    if !fs::metadata(&path).is_ok_and(|m| m.is_file()) {
        return Err(Verdict::refused(
            Reason::NoTrustFile,
            format!("the trust file {shown} ({how}) isn't a readable file"),
        ));
    }
    Ok(path)
}

/// Format characters that can reorder or hide text in a terminal: bidi
/// embeddings and overrides (U+202A-202E), isolates (U+2066-2069), the
/// directional marks (U+200E, U+200F), zero-width characters (U+200B-200D),
/// the word joiner (U+2060) and the byte-order mark (U+FEFF); and (re-check
/// Q3) the Arabic letter mark (U+061C), the Mongolian vowel separator
/// (U+180E), the line and paragraph separators (U+2028, U+2029), the invisible
/// operators (U+2061-2064) and the tag characters (U+E0000-E007F), which
/// render as nothing but travel with the text.
fn is_hiding_format_char(c: char) -> bool {
    matches!(
        c,
        '\u{202A}'..='\u{202E}'
            | '\u{2066}'..='\u{2069}'
            | '\u{061C}'
            | '\u{180E}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{2061}'..='\u{2064}'
            | '\u{E0000}'..='\u{E007F}'
            | '\u{200E}'
            | '\u{200F}'
            | '\u{200B}'..='\u{200D}'
            | '\u{2060}'
            | '\u{FEFF}'
    )
}

/// `text` with every control character (terminal escapes included) and every
/// format character that can reorder or hide text ([`is_hiding_format_char`])
/// written out as `\u{..}`: for printing text a commit or a certificate controls
/// (the committer's email, a certified principal, a certificate's words) in
/// the human form, where a raw ESC could rewrite what the reader sees (F7).
/// The JSON form needs no such step: JSON escapes control characters.
pub fn plain_text(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_control() || is_hiding_format_char(c) {
                c.escape_unicode().to_string()
            } else {
                c.to_string()
            }
        })
        .collect()
}

/// Why a commit got the verdict it did: the `reason` of the JSON form
/// (`agent-sign verify --format json`), and the single place that decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// Verified and attested (launcher or approval).
    Ok,
    /// The commit carries no signature.
    Unsigned,
    /// Verified, and the certificate says nothing established the name.
    Unattested,
    /// Verified, but the name is only claimed (no attestation recorded).
    Claimed,
    /// The certificate (or key) is from an authority the trust file lacks.
    UntrustedAuthority,
    /// The commit is dated outside its certificate's validity window.
    OutsideWindow,
    /// The signature is malformed, doesn't match, or names someone else.
    BadSignature,
    /// Git names no allowed-signers file, so there is nothing to check against.
    NoTrustFile,
    /// The check couldn't run (for example, the revision doesn't exist).
    Error,
}

impl Reason {
    /// The word the JSON form uses.
    pub fn as_str(self) -> &'static str {
        match self {
            Reason::Ok => "ok",
            Reason::Unsigned => "unsigned",
            Reason::Unattested => "unattested",
            Reason::Claimed => "claimed",
            Reason::UntrustedAuthority => "untrusted_authority",
            Reason::OutsideWindow => "outside_window",
            Reason::BadSignature => "bad_signature",
            Reason::NoTrustFile => "no_trust_file",
            Reason::Error => "error",
        }
    }
}

/// The one verdict on a commit; the human output and the JSON form are both
/// printed from it, so they cannot disagree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// The signature checked out against the trust file.
    pub verified: bool,
    /// Verified, and a launcher or an approval established the name.
    pub attested: bool,
    /// `launcher`, `approval`, `unattested`, `claimed` or `none`. Only a
    /// verified signature's certificate is ever read, so anything else is `none`.
    pub attestation: &'static str,
    /// The principal the signature is Good for; only when verified.
    pub signer: Option<String>,
    /// Why.
    pub reason: Reason,
    /// The human sentence: the failure's words, or the Good-signature line.
    pub detail: String,
    /// When verified, the words after `attestation:` in the human output.
    pub attestation_words: Option<String>,
    /// The trust file the verdict was (or, for a commit that never got that
    /// far, would have been) checked against; `None` when there was none.
    /// The JSON form's `trust_file` (additive, 1 Nov 2026).
    pub trust_file: Option<String>,
    /// The email of the commit's author line, exactly as the commit has it,
    /// whatever the verdict (it is information, never part of the verdict:
    /// the exit code does not depend on it). `None` when the commit could not
    /// be read as far as its headers, or does not have exactly one author
    /// line with an email. The JSON form's `author` (additive, re-check R3).
    pub author: Option<String>,
    /// Whether the check ran as far as a verdict on the commit. `false` only
    /// for [`Verdict::cant_run`] (exit 2); a commit refused for what it is,
    /// as one whose bytes don't hash to its name, is `true` with
    /// [`Reason::Error`] (exit 1, so a gate refuses it as it does any
    /// verdict that isn't ok).
    pub ran: bool,
}

impl Verdict {
    /// The exit code of the JSON form: 0 only when verified and attested, 2
    /// when the check couldn't run, 1 for every other verdict. The human
    /// form exits the same way (F3): "verified" in words alone is not a
    /// reason to let a gate pass a commit that isn't attested.
    pub fn json_exit_code(&self) -> u8 {
        if self.verified && self.attested {
            0
        } else if self.reason == Reason::Error && !self.ran {
            2
        } else {
            1
        }
    }

    /// Whether the commit is verified and its author's email is exactly its
    /// verified signer's principal: byte for byte, no case folding, no
    /// trimming (re-check R3). `false` for a commit that is not verified, and
    /// when there is no single author. A merge gate that needs the author to
    /// be the agent (the signature covers the committer, not the author)
    /// requires this to be true.
    pub fn author_matches_signer(&self) -> bool {
        self.verified && matches!((&self.author, &self.signer), (Some(a), Some(s)) if a == s)
    }

    /// This verdict with the commit's `author` ([`Verdict::author`]) set.
    fn with_author(mut self, author: Option<String>) -> Self {
        self.author = author;
        self
    }

    /// The JSON object: the six fields of the interface, `trust_file`, and
    /// (additively, re-check R3) `author` and `author_matches_signer`.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "verified": self.verified,
            "attested": self.attested,
            "attestation": self.attestation,
            "signer": self.signer,
            "reason": self.reason.as_str(),
            "detail": self.detail,
            "trust_file": self.trust_file,
            "author": self.author,
            "author_matches_signer": self.author_matches_signer(),
        })
    }

    /// A check that couldn't run.
    pub fn cant_run(why: String) -> Self {
        Verdict {
            ran: false,
            ..Self::refused(Reason::Error, why)
        }
    }

    fn refused(reason: Reason, detail: impl Into<String>) -> Self {
        Verdict {
            verified: false,
            attested: false,
            attestation: "none",
            signer: None,
            reason,
            detail: detail.into(),
            attestation_words: None,
            trust_file: None,
            author: None,
            ran: true,
        }
    }
}

/// Whether the allowed-signers file `allowed` lists `blob` (as a
/// certificate authority when `authority`).
fn key_listed(allowed: &Path, blob: &[u8], authority: bool) -> bool {
    let want = base64::engine::general_purpose::STANDARD.encode(blob);
    fs::read_to_string(allowed).is_ok_and(|text| {
        text.lines().any(|l| {
            !l.trim_start().starts_with('#')
                && l.split_whitespace().any(|tok| tok == want)
                && (!authority || l.contains("cert-authority"))
        })
    })
}

/// Why ssh-keygen refused a signature, told apart from what we can see:
/// an authority the trust file lacks, a commit dated outside the
/// certificate's window, or anything else.
fn classify_refusal(
    allowed: &Path,
    key_blob: &[u8],
    cert: Option<&Certificate>,
    when: u64,
) -> Reason {
    let signing_blob = match cert {
        Some(cert) => ssh_key::PublicKey::from(cert.signature_key().clone())
            .to_bytes()
            .ok(),
        None => Some(key_blob.to_vec()),
    };
    let listed = signing_blob.is_some_and(|b| key_listed(allowed, &b, cert.is_some()));
    if !listed {
        return Reason::UntrustedAuthority;
    }
    match cert {
        Some(c) if when < c.valid_after() || when >= c.valid_before() => Reason::OutsideWindow,
        _ => Reason::BadSignature,
    }
}

/// Verifies the signature of commit `rev` in the repository at `dir`, and
/// only then reads how its identity was established (see the module
/// documentation). `Err` is the reason it isn't verified.
pub fn verify_commit(dir: &Path, rev: &str) -> Result<Verified, String> {
    let v = verdict(dir, rev);
    if v.verified {
        Ok(Verified {
            principal: v.signer.unwrap_or_default(),
            attestation: v.attestation_words.unwrap_or_default(),
            attested: v.attested,
        })
    } else {
        Err(v.detail)
    }
}

/// The verdict on commit `rev` in the repository at `dir`, against the trust
/// file [`trust_file`] finds with no `--allowed-signers`.
pub fn verdict(dir: &Path, rev: &str) -> Verdict {
    verdict_with(dir, rev, None)
}

/// The verdict on commit `rev` in the repository at `dir` against the trust
/// file `allowed_signers` names, or, when `None`, the one [`trust_file`]
/// chooses: the one function both outputs of `agent-sign verify` come from.
pub fn verdict_with(dir: &Path, rev: &str, allowed_signers: Option<&Path>) -> Verdict {
    let trust = trust_file(allowed_signers);
    let mut verdict = match check(dir, rev, &trust) {
        Ok(v) | Err(v) => v,
    };
    if let Ok(file) = &trust {
        verdict.trust_file = Some(file.display().to_string());
    }
    verdict
}

/// The commit's full object id for `rev`: its commit (a tag peeled), or,
/// when git can't peel it (for example because git itself finds the object
/// isn't what its name says), the name alone, so the object's bytes are
/// still read and re-hashed by [`check`] and refused with the reason.
fn resolve_oid(dir: &Path, rev: &str) -> Result<String, String> {
    let peeled = format!("{rev}^{{commit}}");
    let out = git(dir, &["rev-parse", "--verify", "--quiet", &peeled])
        .or_else(|_| git(dir, &["rev-parse", "--verify", "--quiet", rev]))?;
    let oid = String::from_utf8_lossy(&out).trim().to_string();
    let hex = oid.chars().all(|c| c.is_ascii_hexdigit());
    if hex && (oid.len() == 40 || oid.len() == 64) {
        Ok(oid.to_ascii_lowercase())
    } else {
        Err(format!("{oid:?} isn't an object id"))
    }
}

#[allow(clippy::result_large_err)]
fn check(dir: &Path, rev: &str, trust: &Result<PathBuf, Verdict>) -> Result<Verdict, Verdict> {
    let cant = Verdict::cant_run;
    if rev.starts_with('-') {
        return Err(cant(format!("{rev:?} isn't a revision")));
    }
    let oid = resolve_oid(dir, rev)
        .map_err(|_| cant(format!("{rev:?} isn't a commit in this repository")))?;
    let raw = git(dir, &["cat-file", "commit", &oid])
        .map_err(|_| cant(format!("{rev:?} isn't a commit in this repository")))?;
    // The bytes must be the object they are filed under (F1, defence in
    // depth: replace refs are off, and this also catches an object planted
    // under another's name, which git's own read may let through). The hash
    // is git's own, in the repository's object format; `--literally` so an
    // unusual but real commit is hashed, not judged.
    let hashed = git_with_input(
        dir,
        &["hash-object", "--literally", "-t", "commit", "--stdin"],
        &raw,
    )
    .map_err(cant)?;
    let hashed = String::from_utf8_lossy(&hashed).trim().to_ascii_lowercase();
    if hashed != oid {
        return Err(Verdict::refused(
            Reason::Error,
            format!(
                "the commit object {oid} doesn't hash to its name: the bytes git served for it \
                 hash to {}, so they aren't that commit (a planted or replaced object?)",
                plain_text(&hashed)
            ),
        ));
    }
    let raw = String::from_utf8(raw).map_err(|_| cant("the commit isn't UTF-8".to_string()))?;
    // The author is read from the bytes just hashed, and attached to every
    // verdict from here on, whatever it is: it is information for a gate
    // (`author_matches_signer`), never part of the verdict.
    let author = author_of(&raw);
    check_signature(&raw, trust)
        .map(|v| v.with_author(author.clone()))
        .map_err(|v| v.with_author(author))
}

/// The signature half of [`check`], on the commit's bytes (already hashed to
/// the name they are filed under): the verdict on its signature, then, only
/// when ssh-keygen has accepted it, its attestation.
#[allow(clippy::result_large_err)]
fn check_signature(raw: &str, trust: &Result<PathBuf, Verdict>) -> Result<Verdict, Verdict> {
    let cant = Verdict::cant_run;
    let bad = |why: String| Verdict::refused(Reason::BadSignature, why);
    let (payload, signature) = match split_signature(raw) {
        Some(parts) => parts,
        None if has_signature_header(raw) => {
            return Err(bad("the commit carries more than one signature".to_string()));
        }
        None => {
            return Err(Verdict::refused(
                Reason::Unsigned,
                format!("the commit is unsigned: it carries no signature. {MERGE_NOTE}"),
            ));
        }
    };
    if !signature.starts_with("-----BEGIN SSH SIGNATURE-----") {
        return Err(bad(
            "the commit's signature isn't an SSH signature".to_string()
        ));
    }
    let (principal, when) = committer_of(&payload)
        .ok_or_else(|| bad("the commit has no single committer with a date".to_string()))?;

    // The verifier's trust file, never the repository's (see [`trust_file`]).
    let allowed: &Path = trust.as_ref().map_err(Clone::clone)?;

    // The certificate is only parsed here to refuse one for someone other
    // than the committer; nothing from it is printed before ssh-keygen
    // accepts the signature.
    let key_blob =
        sshsig_public_key(&signature).ok_or_else(|| bad("the signature can't be read".into()))?;
    let cert = Certificate::from_bytes(&key_blob).ok();
    if let Some(cert) = &cert
        && !cert.valid_principals().iter().any(|p| p == &principal)
    {
        return Err(bad(format!(
            "the signature's certificate isn't for the commit's committer {principal}"
        )));
    }

    let sig_file = SignatureFile::new(&signature).map_err(cant)?;
    // The system's ssh-keygen by absolute path, as the signing program finds
    // it: a program first on `PATH` is the session's to put there (F7).
    let keygen = system_ssh_keygen().ok_or_else(|| {
        cant("no ssh-keygen at /usr/bin/ssh-keygen or /usr/local/bin/ssh-keygen".to_string())
    })?;
    let mut child = Command::new(keygen)
        .args(["-Y", "verify", "-n", "git", "-I", &principal, "-f"])
        .arg(allowed)
        .arg("-s")
        .arg(&sig_file.0)
        .arg(format!("-Overify-time={}", verify_time(when)))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| cant(format!("couldn't run ssh-keygen ({e})")))?;
    // ssh-keygen may stop reading early; its answer is what counts.
    let _ = child
        .stdin
        .take()
        .map(|mut stdin| stdin.write_all(payload.as_bytes()));
    let out = child
        .wait_with_output()
        .map_err(|e| cant(format!("ssh-keygen didn't finish ({e})")))?;
    if !out.status.success() {
        let said = first_line(&out.stderr);
        return Err(Verdict::refused(
            classify_refusal(allowed, &key_blob, cert.as_ref(), when),
            format!(
                "ssh-keygen didn't accept the signature for {principal} under {}{}",
                allowed.display(),
                if said.is_empty() {
                    String::new()
                } else {
                    format!(" ({said})")
                }
            ),
        ));
    }

    // Verified: now, and only now, the attestation.
    let (words, attested, kind, reason) = match &cert {
        None => (
            "none: signed with a plain key, not an agents' certificate, so agent-sign \
             records nothing about how the name was established"
                .to_string(),
            false,
            "none",
            Reason::Claimed,
        ),
        Some(cert) => match cert.extensions().get(EXTENSION) {
            None => (
                describe_missing().to_string(),
                false,
                "claimed",
                Reason::Claimed,
            ),
            Some(value) => match Attestation::decode(value) {
                Some(a) => {
                    let (kind, attested, reason) = match a {
                        Attestation::Launcher { .. } => ("launcher", true, Reason::Ok),
                        Attestation::Approval { .. } => ("approval", true, Reason::Ok),
                        Attestation::Unattested => ("unattested", false, Reason::Unattested),
                    };
                    (a.describe(), attested, kind, reason)
                }
                None => (describe_unreadable(), false, "claimed", Reason::Claimed),
            },
        },
    };
    Ok(Verdict {
        verified: true,
        attested,
        attestation: kind,
        signer: Some(principal.clone()),
        reason,
        detail: format!("Good signature for {principal}; attestation: {words}"),
        attestation_words: Some(words),
        trust_file: None,
        author: None,
        ran: true,
    })
}

/// Whether the commit object `raw` has a `gpgsig` header at all.
fn has_signature_header(raw: &str) -> bool {
    raw.split_once("\n\n")
        .map_or(raw, |(headers, _)| headers)
        .split('\n')
        .any(|l| l.starts_with("gpgsig "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_signature_is_cut_out_of_the_commit_exactly() {
        let unsigned =
            "tree t\nparent p\nauthor A <a@x> 1 +0000\ncommitter A <a@x> 1 +0000\n\nmsg\n";
        let signed = "tree t\nparent p\nauthor A <a@x> 1 +0000\ncommitter A <a@x> 1 +0000\ngpgsig -----BEGIN SSH SIGNATURE-----\n AAAA\n -----END SSH SIGNATURE-----\n\nmsg\n";
        let (payload, sig) = split_signature(signed).unwrap();
        assert_eq!(payload, unsigned);
        assert_eq!(
            sig,
            "-----BEGIN SSH SIGNATURE-----\nAAAA\n-----END SSH SIGNATURE-----\n"
        );
        assert_eq!(split_signature(unsigned), None);
        let twice = signed.replace("\n\nmsg", "\ngpgsig x\n\nmsg");
        assert_eq!(split_signature(&twice), None);
    }

    #[test]
    fn the_author_is_the_one_author_lines_email_as_written() {
        let one = "tree t\nauthor A <Mixed@Case.X> 1 +0000\ncommitter C <c@y> 1 +0000\n\nm\n";
        assert_eq!(author_of(one).as_deref(), Some("Mixed@Case.X"));
        // Two author lines, none, or none with an email: no author.
        let two = "tree t\nauthor A <a@x> 1 +0000\nauthor B <b@x> 1 +0000\n\nm\n";
        assert_eq!(author_of(two), None);
        assert_eq!(author_of("tree t\ncommitter C <c@y> 1 +0000\n\nm\n"), None);
        assert_eq!(author_of("tree t\nauthor nobody 1 +0000\n\nm\n"), None);
        // An author line in the message, or in a signature's continuation
        // lines, is not a header.
        let hidden = "tree t\ngpgsig -----BEGIN\n author fake <f@x> 1 +0000\n -----END\n\nauthor B <b@x> 1\n";
        assert_eq!(author_of(hidden), None);
    }

    #[test]
    fn the_author_matches_only_a_verified_signer_exactly() {
        let verified = |author: Option<&str>, signer: &str| Verdict {
            verified: true,
            signer: Some(signer.to_string()),
            author: author.map(str::to_string),
            ..Verdict::refused(Reason::Ok, "")
        };
        assert!(verified(Some("a@x"), "a@x").author_matches_signer());
        assert!(!verified(Some("A@x"), "a@x").author_matches_signer());
        assert!(!verified(Some("a@x "), "a@x").author_matches_signer());
        assert!(!verified(None, "a@x").author_matches_signer());
        let unverified = Verdict {
            author: Some("a@x".into()),
            signer: Some("a@x".into()),
            ..Verdict::refused(Reason::UntrustedAuthority, "")
        };
        assert!(!unverified.author_matches_signer());
    }

    #[test]
    fn the_committer_and_its_time_are_read() {
        let p = "tree t\nauthor A <a@x> 1 +0000\ncommitter C <c@y> 1700000000 +0000\n\nm\n";
        assert_eq!(committer_of(p), Some(("c@y".to_string(), 1_700_000_000)));
        assert_eq!(verify_time(1_793_196_192), "20261028140312Z");
    }
}
