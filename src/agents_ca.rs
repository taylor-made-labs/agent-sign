//! The agents' certificate authority, and the per-session keys it vouches for.
//!
//! Why: before per-agent identities every agent signed with one shared key,
//! whose trust entry was the person's own email, so agent commits looked like
//! the person's. Now the service holds a certificate authority for agents and
//! gives each agent session its own signing key, which lives only in the
//! service's memory and is never written to disk. Each session key gets a
//! short-lived OpenSSH certificate whose principal is the agent's principal
//! (`claude-code.1a2b3c4d@agents.local`, see [`crate::attribution`]). The
//! allowed-signers lines from [`trust_lines`] then make git and `ssh-keygen`
//! report every agent commit as a Good signature *for that agent*, and
//! nothing else: each line only trusts an authority for `*@agents.local`.
//!
//! Keys are never stored unprotected (Taylor, 28 Oct 2026: "never create
//! keys unprotected, they must be protected from the start"). A private key
//! lives in OpenBao, a hardware or OS keystore, or only in a running
//! process's memory, never in a plain file. So the authority is made in
//! memory each time the service starts ([`AgentsCa::generate`]) and its
//! private half is never written anywhere; only its public half is kept, in
//! the append-only `keys/agents_cas.pub` ([`record_authority`]), so commits
//! certified by an earlier run keep verifying. Issuing goes through the
//! [`CertificateIssuer`] port, whose one adapter today is that in-memory
//! authority; OpenBao's SSH secrets engine is the intended second.
//!
//! The user's allowed-signers file can carry a managed block between
//! [`BLOCK_BEGIN`] and [`BLOCK_END`] (the installer writes it); at each start
//! the service rewrites that block, and only that block, with the current
//! trust lines ([`update_allowed_signers`]), so a new authority is trusted
//! with no step of the user's.
//!
//! Signatures are SSHSIG (namespace "git", sha512) with the certificate as
//! the public key, which is what `ssh-keygen -Y sign` makes with a
//! certificate, so `ssh-keygen -Y verify` and git accept them unchanged.
//!
//! Certificates are encoded with RustCrypto's `ssh-key` crate; the SSHSIG
//! wrapper is the same few lines [`crate::crypto`] has always used.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::RngCore;
use rand::rngs::OsRng;
use ssh_key::certificate::{Builder, CertType};
use ssh_key::private::Ed25519Keypair;
use ssh_key::public::{Ed25519PublicKey, KeyData};
use ssh_key::{Certificate, PrivateKey};

use crate::crypto::sshsig_armored;

/// Where earlier development builds of this change kept the authority's
/// private key, a raw seed in a plain file. Its presence stops the service
/// ([`refuse_unprotected_key`]); the installer deletes it, after asking.
pub const CA_KEY_FILE: &str = "agents_ca_ed25519";

/// The current run's authority, one OpenSSH public key line, in the keys
/// folder: rewritten at each start. Programs that need a public key file to
/// name (git's `user.signingkey` for an agent commit) use it.
pub const CA_PUB_FILE: &str = "agents_ca_ed25519.pub";

/// Every authority the service has started with, one per line, oldest
/// first, each an OpenSSH public key line with the time it started as its
/// comment (`ssh-ed25519 AAAA... 2026-10-28T14:03:12Z`). Append-only.
pub const CAS_HISTORY_FILE: &str = "agents_cas.pub";

/// What comes before an authority's key on an allowed-signers line: trust
/// it to vouch for `*@agents.local` principals, for git signatures only.
pub const TRUST_LINE_PREFIX: &str = "*@agents.local cert-authority,namespaces=\"git\"";

/// The line that opens the managed block in the user's allowed-signers
/// file. The service rewrites what lies between it and [`BLOCK_END`].
pub const BLOCK_BEGIN: &str = "# agent-sign: agents' certificate authorities, managed; do not edit";

/// The line that closes the managed block.
pub const BLOCK_END: &str = "# agent-sign: end of agents' certificate authorities";

/// How long before now a certificate is already valid, so a clock that's a
/// little behind elsewhere still accepts it.
pub const CERT_BACKDATE_SECS: u64 = 5 * 60;

/// How long a certificate lasts. git checks it at the commit's own time, so
/// commits stay verifiable after it ends; a session longer than this gets a
/// new certificate.
pub const CERT_LIFETIME_SECS: u64 = 12 * 60 * 60;

/// A certificate is replaced this long before it ends, so a signature never
/// carries one that's about to stop being valid.
const RENEW_MARGIN_SECS: u64 = 60;

/// The keys folder in a state directory (`~/.agent-sign/keys`).
pub fn keys_dir_in(state_dir: &Path) -> PathBuf {
    state_dir.join("keys")
}

/// The current authority's public key file in a state directory.
pub fn ca_pub_path_in(state_dir: &Path) -> PathBuf {
    keys_dir_in(state_dir).join(CA_PUB_FILE)
}

/// The allowed-signers line that trusts the authority whose public key line
/// is `ca_pub_line`: its key type and key only, without any comment (such
/// as the date in [`CAS_HISTORY_FILE`]).
pub fn trust_line(ca_pub_line: &str) -> String {
    let key: Vec<&str> = ca_pub_line.split_whitespace().take(2).collect();
    format!("{TRUST_LINE_PREFIX} {}", key.join(" "))
}

/// One allowed-signers line per authority the service has started with, in
/// the order they started, without repeats, from [`CAS_HISTORY_FILE`]. Empty
/// before the first start. An authority an earlier development build kept
/// in [`CA_PUB_FILE`] is never trusted: its private key sat in a plain file,
/// so it counts as exposed.
pub fn trust_lines(keys_dir: &Path) -> Vec<String> {
    let text = fs::read_to_string(keys_dir.join(CAS_HISTORY_FILE)).unwrap_or_default();
    let mut lines: Vec<String> = Vec::new();
    for line in text.lines().filter(|l| l.split_whitespace().count() >= 2) {
        let trust = trust_line(line);
        if !lines.contains(&trust) {
            lines.push(trust);
        }
    }
    lines
}

/// Stops the service when an earlier development build left the
/// authority's private key in a plain file ([`CA_KEY_FILE`]): a key stored
/// unprotected counts as exposed, and is never used again. The message
/// names the file; the service doesn't delete it itself (the installer
/// does, after asking), so nothing of the user's goes without a word.
pub fn refuse_unprotected_key(keys_dir: &Path) -> Result<(), String> {
    let path = keys_dir.join(CA_KEY_FILE);
    if fs::symlink_metadata(&path).is_ok() {
        return Err(format!(
            "{} holds an agents' certificate authority private key, stored unprotected by an \
             earlier development build. agent-sign now keeps that key only in the service's \
             memory and never uses one from a file. Delete the file (run the installer again, \
             which asks first, or `rm '{}'`), then start the service again.",
            path.display(),
            path.display()
        ));
    }
    Ok(())
}

/// Records a newly started authority: makes the keys folder private (0700),
/// appends `ca_pub_line` with the time `now` (seconds) to
/// [`CAS_HISTORY_FILE`], and writes it as the current [`CA_PUB_FILE`]. An
/// authority an earlier development build left in [`CA_PUB_FILE`] is not
/// carried over (see [`trust_lines`]). Returns the trust lines now in force
/// ([`trust_lines`]).
pub fn record_authority(
    keys_dir: &Path,
    ca_pub_line: &str,
    now: u64,
) -> std::io::Result<Vec<String>> {
    fs::create_dir_all(keys_dir)?;
    fs::set_permissions(keys_dir, fs::Permissions::from_mode(0o700))?;
    let history = keys_dir.join(CAS_HISTORY_FILE);
    let current = keys_dir.join(CA_PUB_FILE);
    let mut file = fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o644)
        .open(&history)?;
    let text = format!("{} {}\n", ca_pub_line.trim(), utc_timestamp(now));
    file.write_all(text.as_bytes())?;
    file.sync_all()?;
    let tmp = keys_dir.join(format!(".{CA_PUB_FILE}.new"));
    fs::write(&tmp, format!("{}\n", ca_pub_line.trim()))?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o644))?;
    fs::rename(&tmp, &current)?;
    Ok(trust_lines(keys_dir))
}

/// `content` with its managed block's lines replaced by `lines`, or `None`
/// when it has no block (no [`BLOCK_BEGIN`] line followed by a
/// [`BLOCK_END`] line). Everything outside the block, the marker lines
/// included, is kept byte for byte.
pub fn rewrite_managed_block(content: &str, lines: &[String]) -> Option<String> {
    let mut offset = 0;
    let mut body_start = None;
    for line in content.split_inclusive('\n') {
        let bare = line.trim_end_matches(['\n', '\r']);
        match body_start {
            None if bare == BLOCK_BEGIN && line.ends_with('\n') => {
                body_start = Some(offset + line.len());
            }
            Some(start) if bare == BLOCK_END => {
                let mut out = String::with_capacity(content.len());
                out.push_str(&content[..start]);
                for l in lines {
                    out.push_str(l);
                    out.push('\n');
                }
                out.push_str(&content[offset..]);
                return Some(out);
            }
            _ => {}
        }
        offset += line.len();
    }
    None
}

/// What [`update_allowed_signers`] did.
#[derive(Debug, PartialEq, Eq)]
pub enum BlockUpdate {
    /// The block already held these lines.
    Unchanged,
    /// The block was rewritten.
    Rewritten,
    /// The file has no managed block, so nothing was touched.
    NoBlock,
}

/// Rewrites the managed block of the allowed-signers file at `path` with
/// `lines` ([`rewrite_managed_block`]), leaving everything outside it as it
/// was. The new content is written beside the file's real location (a link
/// is followed, not replaced) with the file's permissions, and renamed into
/// place, so a crash never leaves it half-written.
pub fn update_allowed_signers(path: &Path, lines: &[String]) -> std::io::Result<BlockUpdate> {
    let real = fs::canonicalize(path)?;
    let content = fs::read_to_string(&real)?;
    let Some(updated) = rewrite_managed_block(&content, lines) else {
        return Ok(BlockUpdate::NoBlock);
    };
    if updated == content {
        return Ok(BlockUpdate::Unchanged);
    }
    let name = real
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = real.with_file_name(format!(".{name}.agent-sign.new"));
    let perms = fs::metadata(&real)?.permissions();
    fs::write(&tmp, updated)?;
    fs::set_permissions(&tmp, perms)?;
    fs::rename(&tmp, &real)?;
    Ok(BlockUpdate::Rewritten)
}

/// The file the user's global git config names as
/// `gpg.ssh.allowedSignersFile` (with `~` expanded), if any: asked of the
/// real git (never the wrapper, see [`crate::paths::real_git`]), as
/// `git config --global --path`. It lives here, not in the service's own
/// source, which runs no other program (a guard against dialogs checks it).
pub fn global_allowed_signers_file() -> Option<PathBuf> {
    let out = std::process::Command::new(crate::paths::real_git())
        .args([
            "config",
            "--global",
            "--path",
            "--get",
            "gpg.ssh.allowedSignersFile",
        ])
        .stdin(std::process::Stdio::null())
        .output()
        .ok()?;
    let value = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (out.status.success() && !value.is_empty()).then(|| PathBuf::from(value))
}

/// `secs` since the epoch as an ISO 8601 UTC time (`2026-10-28T14:03:12Z`),
/// for the authority history. (Days to civil date: Howard Hinnant's
/// algorithm, which needs no date library.)
pub fn utc_timestamp(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3_600,
        rem % 3_600 / 60,
        rem % 60
    )
}

/// This machine's name, for certificates' key ids ("<principal> on <host>"):
/// `hostname`'s answer, kept to plain printable characters, or `localhost`.
pub fn hostname() -> String {
    let found = ["/bin/hostname", "/usr/bin/hostname"]
        .into_iter()
        .find(|p| Path::new(p).exists())
        .and_then(|p| std::process::Command::new(p).output().ok())
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    let clean: String = found
        .chars()
        .filter(|c| c.is_ascii_graphic())
        .take(253)
        .collect();
    if clean.is_empty() {
        "localhost".to_string()
    } else {
        clean
    }
}

/// Now, in seconds since the epoch.
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn ssh_err(e: ssh_key::Error) -> String {
    format!("certificate error: {e}")
}

/// The port through which the service gets certificates for agents'
/// session keys: whatever holds the authority's private key implements it,
/// and nothing else ever sees that key.
///
/// Today's one adapter is [`AgentsCa`], an authority made in memory at each
/// start. The intended second is OpenBao's SSH secrets engine (its
/// `ssh/sign/<role>` endpoint signs a public key into a user certificate,
/// with the key held in OpenBao), which would keep one authority across
/// restarts without the key ever being in a file. An adapter must issue
/// user certificates for exactly the one principal asked, with the lifetime
/// and fields [`AgentsCa::issue`] documents.
pub trait CertificateIssuer: Send {
    /// The authority's public key as one OpenSSH line (`ssh-ed25519 AAAA...`).
    fn public_key_openssh(&self) -> String;

    /// A user certificate for `subject`, naming `principal` only, valid
    /// from a little before `now` (seconds) for [`CERT_LIFETIME_SECS`].
    fn issue(
        &self,
        principal: &str,
        subject: &VerifyingKey,
        now: u64,
    ) -> Result<Certificate, String>;
}

/// The agents' certificate authority, held in memory only: the in-memory
/// adapter of [`CertificateIssuer`]. Its seed is zeroed when it's dropped.
pub struct AgentsCa {
    seed: zeroize::Zeroizing<[u8; 32]>,
    host: String,
}

impl AgentsCa {
    /// An authority from a 32-byte seed (tests).
    pub fn from_seed(seed: [u8; 32], host: &str) -> Self {
        Self {
            seed: zeroize::Zeroizing::new(seed),
            host: host.to_string(),
        }
    }

    /// A new authority with a random key, made in memory and never written
    /// anywhere: what the service does at each start.
    pub fn generate(host: &str) -> Self {
        let mut seed = zeroize::Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(seed.as_mut());
        Self {
            seed,
            host: host.to_string(),
        }
    }

    fn private_key(&self) -> PrivateKey {
        PrivateKey::from(Ed25519Keypair::from_seed(&self.seed))
    }
}

impl CertificateIssuer for AgentsCa {
    fn public_key_openssh(&self) -> String {
        let signing = SigningKey::from_bytes(&self.seed);
        crate::crypto::openssh_ed25519_line(&signing.verifying_key())
    }

    /// A user certificate for `subject`, naming `principal` only: key id
    /// "<principal> on <host>", valid from [`CERT_BACKDATE_SECS`] before `now`
    /// for [`CERT_LIFETIME_SECS`] after it, no critical options, no
    /// extensions, a random serial and nonce.
    fn issue(
        &self,
        principal: &str,
        subject: &VerifyingKey,
        now: u64,
    ) -> Result<Certificate, String> {
        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);
        let key = KeyData::Ed25519(Ed25519PublicKey(subject.to_bytes()));
        let mut builder = Builder::new(
            nonce.to_vec(),
            key,
            now.saturating_sub(CERT_BACKDATE_SECS),
            now + CERT_LIFETIME_SECS,
        )
        .map_err(ssh_err)?;
        builder
            .serial(OsRng.next_u64())
            .map_err(ssh_err)?
            .key_id(format!("{principal} on {}", self.host))
            .map_err(ssh_err)?
            .cert_type(CertType::User)
            .map_err(ssh_err)?
            .valid_principal(principal)
            .map_err(ssh_err)?;
        builder.sign(&self.private_key()).map_err(ssh_err)
    }
}

/// One agent session's signing key and its current certificate.
pub struct SessionSigner {
    key: SigningKey,
    cert_blob: Vec<u8>,
    valid_before: u64,
}

impl SessionSigner {
    /// A new key for `principal`, with a certificate from `ca`.
    pub fn new(ca: &dyn CertificateIssuer, principal: &str, now: u64) -> Result<Self, String> {
        let key = SigningKey::generate(&mut OsRng);
        let cert = ca.issue(principal, &key.verifying_key(), now)?;
        Ok(Self {
            valid_before: cert.valid_before(),
            cert_blob: cert.to_bytes().map_err(ssh_err)?,
            key,
        })
    }

    /// Whether the certificate is still good for a while yet.
    pub fn is_fresh(&self, now: u64) -> bool {
        now + RENEW_MARGIN_SECS < self.valid_before
    }

    /// The certificate's OpenSSH wire encoding.
    pub fn certificate_blob(&self) -> &[u8] {
        &self.cert_blob
    }

    /// An armored SSHSIG over `buffer` for namespace "git", with the
    /// certificate as its public key.
    pub fn sign_git_buffer(&self, buffer: &[u8]) -> String {
        sshsig_armored(&self.cert_blob, &self.key, buffer)
    }
}

/// A session signer not used for this long is dropped: its session has
/// most likely ended (an agent session that comes back gets a new key, which
/// verifies the same way). The same as [`CERT_LIFETIME_SECS`], the longest a
/// key's certificate lasts anyway.
pub const SIGNER_IDLE_SECS: u64 = 12 * 60 * 60;

/// The most session signers kept at once; past it, the least recently used
/// goes. Principals are chosen by whoever asks (any session id), so without
/// a cap a program could make the service keep keys without end.
pub const MAX_SIGNERS: usize = 1024;

/// The service's session signers, one per principal, made and renewed as
/// needed. They exist only in memory: a restart gives every session a new
/// key and certificate, which verify the same way under the trust line.
/// Signers idle for [`SIGNER_IDLE_SECS`] are evicted, and at most
/// [`MAX_SIGNERS`] are kept (identity review, 28 Oct 2026: before, every
/// principal ever seen kept its key until the service stopped).
#[derive(Default)]
pub struct SessionSigners {
    /// Each principal's signer, when it was last used (seconds, for the idle
    /// limit), and the order of that use (for least recently used: many
    /// uses fall in the same second).
    by_principal: HashMap<String, (SessionSigner, u64, u64)>,
    /// Counts uses, giving each one its order.
    uses: u64,
}

impl SessionSigners {
    /// The signer for `principal`, with a certificate valid now: a new one
    /// the first time, or when the last certificate is about to end.
    pub fn signer_for(
        &mut self,
        ca: &dyn CertificateIssuer,
        principal: &str,
    ) -> Result<&SessionSigner, String> {
        self.signer_for_at(ca, principal, now_secs())
    }

    /// [`SessionSigners::signer_for`] at time `now` (seconds), so eviction
    /// can be tested without waiting.
    pub fn signer_for_at(
        &mut self,
        ca: &dyn CertificateIssuer,
        principal: &str,
        now: u64,
    ) -> Result<&SessionSigner, String> {
        // Idle ones first, so the cap only ever removes a signer in use when
        // that many are.
        self.by_principal
            .retain(|_, (_, used, _)| now.saturating_sub(*used) <= SIGNER_IDLE_SECS);
        let stale = self
            .by_principal
            .get(principal)
            .is_none_or(|(s, _, _)| !s.is_fresh(now));
        if stale {
            let signer = SessionSigner::new(ca, principal, now)?;
            if !self.by_principal.contains_key(principal)
                && self.by_principal.len() >= MAX_SIGNERS
                && let Some(oldest) = self
                    .by_principal
                    .iter()
                    .min_by_key(|(_, (_, _, order))| *order)
                    .map(|(p, _)| p.clone())
            {
                self.by_principal.remove(&oldest);
            }
            self.by_principal
                .insert(principal.to_string(), (signer, now, 0));
        }
        self.uses += 1;
        let entry = self
            .by_principal
            .get_mut(principal)
            .expect("inserted above");
        entry.1 = now;
        entry.2 = self.uses;
        Ok(&entry.0)
    }

    /// How many session signers are held.
    pub fn len(&self) -> usize {
        self.by_principal.len()
    }

    /// Whether no session signer is held.
    pub fn is_empty(&self) -> bool {
        self.by_principal.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_certificate_names_only_the_principal_and_lasts_twelve_hours() {
        let ca = AgentsCa::from_seed([9u8; 32], "test-host");
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let cert = ca
            .issue(
                "codex.12345678@agents.local",
                &key.verifying_key(),
                1_000_000,
            )
            .unwrap();
        assert_eq!(cert.valid_principals(), ["codex.12345678@agents.local"]);
        assert_eq!(cert.key_id(), "codex.12345678@agents.local on test-host");
        assert_eq!(cert.valid_after(), 1_000_000 - CERT_BACKDATE_SECS);
        assert_eq!(cert.valid_before(), 1_000_000 + CERT_LIFETIME_SECS);
        assert_eq!(cert.cert_type(), CertType::User);
        assert!(cert.critical_options().is_empty());
        assert!(cert.extensions().is_empty());
    }

    #[test]
    fn the_trust_line_trusts_agents_local_for_git_only() {
        assert_eq!(
            trust_line("ssh-ed25519 AAAA\n"),
            "*@agents.local cert-authority,namespaces=\"git\" ssh-ed25519 AAAA"
        );
    }

    /// The certificate blob of `principal`'s signer at `now`.
    fn cert_at(
        signers: &mut SessionSigners,
        ca: &dyn CertificateIssuer,
        principal: &str,
        now: u64,
    ) -> Vec<u8> {
        signers
            .signer_for_at(ca, principal, now)
            .unwrap()
            .certificate_blob()
            .to_vec()
    }

    #[test]
    fn an_idle_session_key_is_evicted_after_twelve_hours() {
        let ca = AgentsCa::from_seed([9u8; 32], "test-host");
        let mut signers = SessionSigners::default();
        let (a, b) = ("codex.1a2b3c4d@agents.local", "codex.5e6f7a8b@agents.local");
        let t0 = 1_000_000;
        let first = cert_at(&mut signers, &ca, a, t0);
        assert_eq!(
            first,
            cert_at(&mut signers, &ca, a, t0 + 60),
            "kept while in use"
        );
        // Another session's use, past a's idle limit, drops a.
        cert_at(&mut signers, &ca, b, t0 + 60 + SIGNER_IDLE_SECS + 1);
        assert_eq!(signers.len(), 1, "the idle signer should be gone");
        assert_ne!(
            first,
            cert_at(&mut signers, &ca, a, t0 + 60 + SIGNER_IDLE_SECS + 2),
            "an evicted session gets a new key and certificate"
        );
    }

    #[test]
    fn at_most_max_signers_are_kept() {
        let ca = AgentsCa::from_seed([9u8; 32], "test-host");
        let mut signers = SessionSigners::default();
        for i in 0..MAX_SIGNERS + 5 {
            cert_at(
                &mut signers,
                &ca,
                &format!("codex.{i:08x}@agents.local"),
                1_000 + i as u64,
            );
        }
        assert_eq!(signers.len(), MAX_SIGNERS);
    }

    #[test]
    fn each_generated_authority_is_new_and_nothing_is_written() {
        let dir = tempfile::tempdir().unwrap();
        let before: Vec<_> = fs::read_dir(dir.path()).unwrap().collect();
        let a = AgentsCa::generate("h");
        let b = AgentsCa::generate("h");
        assert_ne!(a.public_key_openssh(), b.public_key_openssh());
        assert_eq!(before.len(), fs::read_dir(dir.path()).unwrap().count());
    }

    #[test]
    fn the_history_is_appended_and_an_earlier_builds_authority_is_never_trusted() {
        // An earlier development build kept its authority's private key in a
        // plain file, so that authority counts as exposed: its public half
        // must not be carried into the trust.
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("keys");
        fs::create_dir_all(&keys).unwrap();
        fs::write(keys.join(CA_PUB_FILE), "ssh-ed25519 AAAAold\n").unwrap();
        assert!(trust_lines(&keys).is_empty());
        let lines = record_authority(&keys, "ssh-ed25519 AAAAnew", 86_400).unwrap();
        assert_eq!(lines, [trust_line("ssh-ed25519 AAAAnew")]);
        assert_eq!(
            fs::read_to_string(keys.join(CAS_HISTORY_FILE)).unwrap(),
            "ssh-ed25519 AAAAnew 1970-01-02T00:00:00Z\n"
        );
        let lines = record_authority(&keys, "ssh-ed25519 AAAAthird", 86_401).unwrap();
        assert_eq!(lines.len(), 2);
        assert_eq!(
            fs::read_to_string(keys.join(CA_PUB_FILE)).unwrap(),
            "ssh-ed25519 AAAAthird\n"
        );
        let mode = fs::metadata(&keys).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn only_the_managed_block_is_rewritten() {
        let lines = vec!["one".to_string(), "two".to_string()];
        let content = format!("a\r\n{BLOCK_BEGIN}\nold\n{BLOCK_END}\nb");
        assert_eq!(
            rewrite_managed_block(&content, &lines).unwrap(),
            format!("a\r\n{BLOCK_BEGIN}\none\ntwo\n{BLOCK_END}\nb")
        );
        assert_eq!(rewrite_managed_block("a\nb\n", &lines), None);
        assert_eq!(
            rewrite_managed_block(&format!("{BLOCK_END}\n{BLOCK_BEGIN}\n"), &lines),
            None,
            "an end before the beginning isn't a block"
        );
    }

    #[test]
    fn timestamps_are_iso_utc() {
        assert_eq!(utc_timestamp(0), "1970-01-01T00:00:00Z");
        assert_eq!(utc_timestamp(1_793_196_192), "2026-10-28T14:03:12Z");
        assert_eq!(utc_timestamp(951_782_400), "2000-02-29T00:00:00Z");
    }
}
