//! Whether git on this machine reads an SSH certificate's times correctly,
//! for `agent-sign doctor`.
//!
//! Why: git checks a commit's SSH signature by running `ssh-keygen -Y verify`
//! with `-Overify-time=YYYYMMDDHHMMSS`, the commit's date in the machine's
//! *local* time with no zone. OpenSSH 10.0p2 (Debian 13, the Raspberry Pi)
//! reads that string as UTC whenever the clock zone isn't UTC: it accepts
//! only the form with a `Z` after it. OpenSSH 10.2p1 reads it as local time.
//! So on the first kind of machine git's own check of a certificate is
//! shifted by the zone's offset, and a commit made just now can show as
//! unverified (or an old one as verified) in git's `%G?` and
//! `git verify-commit`. `agent-sign verify` always passes the `Z` form
//! ([`crate::verify`]), so it is unaffected, which is why anything that
//! decides must use it and never git's verdict.
//!
//! How: this module asks the machine's own `ssh-keygen`, in the zone this
//! process runs in, the same question in both forms about a throwaway
//! certificate that is valid for only a few minutes around now. A shift by
//! any real zone offset puts the time outside that window. If both forms say
//! yes, git reads times correctly here; if only the `Z` form does, git
//! misreads them. Everything secret stays in memory (the throwaway authority
//! and key are random seeds in zeroizing buffers); only public material (the
//! certificate's signature, the authority's public line) is written, to a
//! private folder that is removed afterwards.
//!
//! It is a warning, never a refusal: signing isn't affected, only how git
//! reads the result. The comparison ([`judge`], [`read_with`]) is pure and
//! unit-tested; [`check`] is the thin shell around the real `ssh-keygen`.

use std::fs;
use std::io::Read;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use rand::RngCore;
use rand::rngs::OsRng;
use ssh_key::certificate::{Builder, CertType};
use ssh_key::private::{Ed25519Keypair, PrivateKey};
use ssh_key::public::{Ed25519PublicKey, KeyData};
use zeroize::Zeroizing;

/// The probe certificate is valid this long before and after now. Short, so
/// that a shift by any real clock zone's offset (an hour at the least) falls
/// outside it; long enough to cover the time the check itself takes.
const PROBE_WINDOW_SECS: u64 = 300;

/// The most time one `ssh-keygen` question gets.
const ASK_LIMIT: Duration = Duration::from_secs(10);

/// The name the probe certificate carries.
const PROBE_PRINCIPAL: &str = "doctor-probe@example.invalid";

/// What the check found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reading {
    /// Both forms of the time work: git reads certificate times correctly
    /// here (the clock zone is UTC, or this OpenSSH reads local time).
    Correct,
    /// Only the `Z`-suffixed UTC form works: git's own check is shifted by
    /// the zone offset. `agent-sign verify` is unaffected.
    Misread,
    /// The check couldn't be made; the text says why.
    Unknown(String),
}

/// The finding from what `ssh-keygen` did with the two forms for a
/// certificate that is valid now. `plain_ok`: the local time with no zone
/// (git's form) found the certificate's principal; `z_ok`: the UTC form
/// with a `Z` did.
pub fn judge(plain_ok: bool, z_ok: bool) -> Reading {
    match (plain_ok, z_ok) {
        (true, true) => Reading::Correct,
        (false, true) => Reading::Misread,
        // The control failed: this ssh-keygen doesn't take the form
        // `agent-sign verify` uses (or isn't there), so nothing can be said
        // about git's. (Plain working while Z doesn't is the same: unknown.)
        _ => Reading::Unknown(
            "ssh-keygen here didn't accept a certificate valid now, even with the UTC time \
             written with a Z"
                .to_string(),
        ),
    }
}

/// Runs the comparison: `finds(stamp)` says whether `ssh-keygen` found the
/// probe certificate's principal with `-Overify-time=<stamp>`. Asked with
/// git's form of `now` (local time) and the `Z` form.
pub fn read_with(finds: impl Fn(&str) -> bool, now: u64) -> Reading {
    let Some(plain) = git_form(now) else {
        return Reading::Unknown("couldn't work out the local time".to_string());
    };
    let z = z_form(now);
    // Ask the Z form first: if it fails, the plain answer means nothing.
    let z_ok = finds(&z);
    let plain_ok = finds(&plain);
    judge(plain_ok, z_ok)
}

/// `YYYYMMDDHHMMSS` from its parts.
fn compact(year: i64, month: i64, day: i64, hour: i64, minute: i64, second: i64) -> String {
    format!("{year:04}{month:02}{day:02}{hour:02}{minute:02}{second:02}")
}

unsafe extern "C" {
    /// POSIX `tzset`: re-reads the `TZ` variable. (The `libc` crate doesn't
    /// export it on every platform; it is in every libc agent-sign runs on.)
    safe fn tzset();
}

/// `secs` as git writes `-Overify-time`: `YYYYMMDDHHMMSS` in this process's
/// local time, with no zone. `None` if the system can't convert it.
pub fn git_form(secs: u64) -> Option<String> {
    let t = libc::time_t::try_from(secs).ok()?;
    // SAFETY: `tm` is plain data that localtime_r fills in completely on
    // success; `t` outlives the call. tzset first, as localtime_r need not
    // read the TZ variable by itself.
    let tm = unsafe {
        tzset();
        let mut tm: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&t, &mut tm).is_null() {
            return None;
        }
        tm
    };
    Some(compact(
        i64::from(tm.tm_year) + 1900,
        i64::from(tm.tm_mon) + 1,
        i64::from(tm.tm_mday),
        i64::from(tm.tm_hour),
        i64::from(tm.tm_min),
        i64::from(tm.tm_sec),
    ))
}

/// `secs` as `agent-sign verify` writes it: `YYYYMMDDHHMMSSZ`, UTC.
pub fn z_form(secs: u64) -> String {
    crate::verify::verify_time(secs)
}

/// A private folder for the public files of the probe, removed when dropped.
struct ProbeDir(PathBuf);

impl ProbeDir {
    fn new() -> Result<Self, String> {
        let path = std::env::temp_dir().join(format!(
            "agent-sign-doctor-{}",
            uuid::Uuid::new_v4().simple()
        ));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|e| format!("couldn't make a private temporary folder ({e})"))?;
        Ok(Self(path))
    }
}

impl Drop for ProbeDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A fresh random ed25519 seed, zeroed when dropped.
fn random_seed() -> Zeroizing<[u8; 32]> {
    let mut seed = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(seed.as_mut());
    seed
}

/// Whether `program -Y find-principals` finds [`PROBE_PRINCIPAL`] for
/// `sig_file` in `allowed` with `-Overify-time=stamp`. Bounded by
/// [`ASK_LIMIT`]; any trouble counts as "no".
fn ssh_keygen_finds(program: &str, allowed: &Path, sig_file: &Path, stamp: &str) -> bool {
    let Ok(mut child) = Command::new(program)
        .args(["-Y", "find-principals", "-f"])
        .arg(allowed)
        .arg("-s")
        .arg(sig_file)
        .arg(format!("-Overify-time={stamp}"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    else {
        return false;
    };
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if start.elapsed() < ASK_LIMIT => {
                std::thread::sleep(Duration::from_millis(10));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
        }
    };
    let mut said = String::new();
    if let Some(mut out) = child.stdout.take() {
        // A few lines at most; the child has exited, so this can't block.
        let _ = out.by_ref().take(64 * 1024).read_to_string(&mut said);
    }
    status.success() && said.contains(PROBE_PRINCIPAL)
}

/// Makes the throwaway authority, certificate and signature in memory,
/// writes the public parts to `dir`, and returns the paths of the
/// allowed-signers file and the signature.
fn write_probe(dir: &Path, now: u64) -> Result<(PathBuf, PathBuf), String> {
    let err = |e: ssh_key::Error| format!("couldn't make the probe certificate ({e})");
    let ca_seed = random_seed();
    let subject_seed = random_seed();
    let ca = SigningKey::from_bytes(&ca_seed);
    let subject = SigningKey::from_bytes(&subject_seed);

    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    let mut builder = Builder::new(
        nonce.to_vec(),
        KeyData::Ed25519(Ed25519PublicKey(subject.verifying_key().to_bytes())),
        now.saturating_sub(PROBE_WINDOW_SECS),
        now + PROBE_WINDOW_SECS,
    )
    .map_err(err)?;
    builder
        .serial(OsRng.next_u64())
        .map_err(err)?
        .key_id("agent-sign doctor probe")
        .map_err(err)?
        .cert_type(CertType::User)
        .map_err(err)?
        .valid_principal(PROBE_PRINCIPAL)
        .map_err(err)?;
    let cert = builder
        .sign(&PrivateKey::from(Ed25519Keypair::from_seed(&ca_seed)))
        .map_err(err)?
        .to_bytes()
        .map_err(err)?;

    let allowed = dir.join("allowed_signers");
    fs::write(
        &allowed,
        format!(
            "{PROBE_PRINCIPAL} cert-authority {}\n",
            crate::crypto::openssh_ed25519_line(&ca.verifying_key())
        ),
    )
    .map_err(|e| format!("couldn't write the probe's public files ({e})"))?;
    let sig_file = dir.join("probe.sig");
    fs::write(
        &sig_file,
        crate::crypto::sshsig_armored(&cert, &subject, b"agent-sign doctor probe\n"),
    )
    .map_err(|e| format!("couldn't write the probe's public files ({e})"))?;
    Ok((allowed, sig_file))
}

/// Asks the `ssh-keygen` on `PATH` (the one `agent-sign verify` and git's
/// default use), in this process's clock zone, whether git's form of the
/// time reads right. See the module documentation.
pub fn check() -> Reading {
    let now = crate::agents_ca::now_secs();
    let dir = match ProbeDir::new() {
        Ok(dir) => dir,
        Err(e) => return Reading::Unknown(e),
    };
    let (allowed, sig_file) = match write_probe(&dir.0, now) {
        Ok(files) => files,
        Err(e) => return Reading::Unknown(e),
    };
    read_with(
        |stamp| ssh_keygen_finds("ssh-keygen", &allowed, &sig_file, stamp),
        now,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_forms_working_means_git_reads_times_correctly() {
        assert_eq!(judge(true, true), Reading::Correct);
    }

    #[test]
    fn only_the_z_form_working_means_git_misreads_times() {
        assert_eq!(judge(false, true), Reading::Misread);
    }

    #[test]
    fn a_failing_control_is_unknown_never_a_verdict() {
        assert!(matches!(judge(false, false), Reading::Unknown(_)));
        assert!(matches!(judge(true, false), Reading::Unknown(_)));
    }

    /// An OpenSSH that, like 10.0p2, reads only the Z form as UTC.
    #[test]
    fn a_machine_that_takes_only_the_z_form_is_found_to_misread() {
        let asked = std::cell::RefCell::new(Vec::new());
        let got = read_with(
            |stamp| {
                asked.borrow_mut().push(stamp.to_string());
                stamp.ends_with('Z')
            },
            1_793_196_192,
        );
        assert_eq!(got, Reading::Misread);
        let asked = asked.into_inner();
        assert_eq!(asked.len(), 2, "one question per form: {asked:?}");
        assert!(asked.contains(&"20261028140312Z".to_string()));
        assert!(asked.iter().any(|s| s.len() == 14 && !s.ends_with('Z')));
    }

    /// An OpenSSH that, like 10.2p1, reads either form.
    #[test]
    fn a_machine_that_takes_both_forms_is_found_to_read_correctly() {
        assert_eq!(read_with(|_| true, 1_793_196_192), Reading::Correct);
    }

    /// No answer at all (no ssh-keygen, say) is unknown, not a warning
    /// about git.
    #[test]
    fn a_machine_that_takes_neither_form_is_unknown() {
        assert!(matches!(
            read_with(|_| false, 1_793_196_192),
            Reading::Unknown(_)
        ));
    }

    #[test]
    fn the_stamps_have_the_shapes_ssh_keygen_reads() {
        assert_eq!(compact(2026, 1, 2, 3, 4, 5), "20260102030405");
        let local = git_form(1_793_196_192).unwrap();
        assert!(local.len() == 14 && local.bytes().all(|b| b.is_ascii_digit()));
        assert_eq!(z_form(1_793_196_192), "20261028140312Z");
    }

    #[test]
    fn the_probe_writes_public_files_only() {
        let dir = ProbeDir::new().unwrap();
        let (allowed, sig) = write_probe(&dir.0, crate::agents_ca::now_secs()).unwrap();
        for file in [&allowed, &sig] {
            let text = fs::read_to_string(file).unwrap();
            assert!(
                !text.contains("PRIVATE KEY"),
                "{} holds private key material",
                file.display()
            );
        }
        assert!(
            fs::read_to_string(&allowed)
                .unwrap()
                .contains("cert-authority")
        );
        let folder = dir.0.clone();
        drop(dir);
        assert!(!folder.exists(), "the probe folder is removed afterwards");
    }
}
