//! The service's state lock, and the live authority it records.
//!
//! Why (decision D2, the suite PM, 31 Oct 2026; build plan step S5): any
//! process of the account could start its own `agent-signd` on the same
//! state folder. Each start used to make a new certificate authority and
//! write it into the trust files itself, so a second service's signatures
//! were trusted the moment it started (P3), and two services wrote the same
//! state (leases, approval nonces) at once.
//!
//! Now a service takes an exclusive `flock` on
//! `~/.agent-sign/agent-signd.lock` ([`StateLock::acquire`]) before it
//! writes anything in the state folder, removing a stale socket included.
//! A second service for the same state can't get it and stops with a
//! message. The lock is held for the service's whole life and released by
//! the kernel when it exits, however it exits.
//!
//! The service writes its live authority's public key line into the lock
//! file ([`StateLock::record_live_authority`]). That line is not a trust
//! entry: only `agent-sign trust install` writes trust. It lets the command
//! line tell whether a live service wrote it this run ([`live_authority`]):
//! the line counts only while the lock is held, so a key a stopped service
//! left behind, or one in a file some other program wrote, is never
//! printed as live. (The file is emptied right after the lock is taken, so
//! the only stale line ever seen is the previous run's for an instant, and
//! that key's private half ended with its process.)
//!
//! In one account this is a guard against accidents and against a second
//! service changing what verifiers trust, not a security boundary: the
//! account can edit its allowed-signers file directly. The boundary is the
//! service in its own account with a root-owned trust file
//! (docs/caller-identity.md).

use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// The lock file's name in the state folder.
pub const LOCK_FILE: &str = "agent-signd.lock";

/// How long a starting service keeps trying for the lock. A command-line
/// check ([`live_authority`]) holds a shared lock for an instant, which
/// must not stop a service starting at the same moment; a running service
/// holds it for good, so a second one stops after this.
pub const ACQUIRE_PATIENCE: Duration = Duration::from_millis(1500);

/// The lock file in `state_dir`.
pub fn lock_path_in(state_dir: &Path) -> PathBuf {
    state_dir.join(LOCK_FILE)
}

/// The exclusive lock on one state folder, held by the running service.
/// Dropping it (or the process ending) releases it.
#[derive(Debug)]
pub struct StateLock {
    file: File,
    path: PathBuf,
}

/// Opens the lock file without following a link at its name, so a link
/// planted there can't point the lock (or the live key) elsewhere.
fn open_lock_file(path: &Path, create: bool) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    if create {
        options.write(true).create(true).mode(0o600);
    }
    options.custom_flags(libc::O_NOFOLLOW).open(path)
}

impl StateLock {
    /// Takes the exclusive lock on `state_dir` (made, private, if it doesn't
    /// exist yet), trying for up to [`ACQUIRE_PATIENCE`]. Refuses, with a
    /// message saying why and what to do, when another service holds it.
    /// Nothing else in the state folder is touched first.
    pub fn acquire(state_dir: &Path) -> Result<Self, String> {
        if !state_dir.exists() {
            fs::create_dir_all(state_dir)
                .map_err(|e| format!("{}: can't be made ({e})", state_dir.display()))?;
            fs::set_permissions(state_dir, fs::Permissions::from_mode(0o700))
                .map_err(|e| format!("{}: can't be made private ({e})", state_dir.display()))?;
        }
        let path = lock_path_in(state_dir);
        let file = open_lock_file(&path, true)
            .map_err(|e| format!("{}: the state lock can't be opened ({e})", path.display()))?;
        let start = Instant::now();
        loop {
            match file.try_lock() {
                Ok(()) => break,
                Err(TryLockError::WouldBlock) if start.elapsed() < ACQUIRE_PATIENCE => {
                    std::thread::sleep(Duration::from_millis(25));
                }
                Err(TryLockError::WouldBlock) => {
                    return Err(format!(
                        "another agent-signd is already running for {} (it holds {}), so this \
                         one stops without touching its state. One service per state folder: \
                         use the running one (`agent-sign status`), or stop it first",
                        state_dir.display(),
                        path.display()
                    ));
                }
                Err(TryLockError::Error(e)) => {
                    return Err(format!(
                        "{}: the state lock can't be taken ({e})",
                        path.display()
                    ));
                }
            }
        }
        // Ours now: what a previous run wrote in it is not this run's.
        file.set_len(0)
            .map_err(|e| format!("{}: can't be emptied ({e})", path.display()))?;
        Ok(Self { file, path })
    }

    /// Records `ca_pub_line` (one OpenSSH public key line) as this run's
    /// live authority, synced to disk, for [`live_authority`] to read.
    pub fn record_live_authority(&mut self, ca_pub_line: &str) -> Result<(), String> {
        let fail = |e: std::io::Error| {
            format!(
                "{}: the live authority can't be recorded ({e})",
                self.path.display()
            )
        };
        self.file.set_len(0).map_err(fail)?;
        self.file.seek(SeekFrom::Start(0)).map_err(fail)?;
        self.file
            .write_all(format!("{}\n", ca_pub_line.trim()).as_bytes())
            .map_err(fail)?;
        self.file.sync_all().map_err(fail)
    }
}

/// Whether `line` is one plain `ssh-ed25519` public key line, which is all
/// the lock file ever holds.
fn is_public_key_line(line: &str) -> bool {
    let mut parts = line.split_whitespace();
    parts.next() == Some("ssh-ed25519")
        && parts.next().is_some_and(|key| {
            !key.is_empty()
                && key
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
        })
        && parts.next().is_none()
}

/// Whether a service holds `state_dir`'s lock right now.
pub fn is_held(state_dir: &Path) -> bool {
    let Ok(file) = open_lock_file(&lock_path_in(state_dir), false) else {
        return false;
    };
    matches!(file.try_lock_shared(), Err(TryLockError::WouldBlock))
}

/// The public key line of the authority a live service for `state_dir`
/// made this run: `Some` only while a service holds the lock and has
/// recorded its key there. Never a trust entry by itself (see the module
/// documentation).
pub fn live_authority(state_dir: &Path) -> Option<String> {
    let file = open_lock_file(&lock_path_in(state_dir), false).ok()?;
    if !matches!(file.try_lock_shared(), Err(TryLockError::WouldBlock)) {
        // Not held: no live service (the shared lock just taken is released
        // when the file closes).
        return None;
    }
    let mut text = String::new();
    file.take(4096).read_to_string(&mut text).ok()?;
    let line = text.trim();
    is_public_key_line(line).then(|| line.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGb+/=";

    #[test]
    fn a_second_lock_on_the_same_state_is_refused_until_the_first_ends() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        let mut first = StateLock::acquire(&state).unwrap();
        assert!(is_held(&state));
        assert_eq!(live_authority(&state), None, "nothing recorded yet");
        first.record_live_authority(KEY).unwrap();
        assert_eq!(live_authority(&state).as_deref(), Some(KEY));
        let second = StateLock::acquire(&state);
        assert!(second.is_err(), "a second lock was granted");
        assert!(second.unwrap_err().contains("already running"));
        drop(first);
        assert!(!is_held(&state));
        assert_eq!(live_authority(&state), None, "a stopped service isn't live");
        let again = StateLock::acquire(&state).unwrap();
        assert_eq!(
            live_authority(&state),
            None,
            "the previous run's key isn't this run's"
        );
        drop(again);
        let mode = fs::metadata(lock_path_in(&state))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn only_a_single_public_key_line_counts_as_live() {
        assert!(is_public_key_line(KEY));
        for bad in [
            "",
            "ssh-rsa AAAA",
            "ssh-ed25519",
            "ssh-ed25519 AAAA comment",
            "ssh-ed25519 AAAA\nssh-ed25519 BBBB",
            "*@agents.local cert-authority ssh-ed25519 AAAA",
            "ssh-ed25519 AA\"AA",
        ] {
            assert!(!is_public_key_line(bad), "{bad:?}");
        }
    }

    #[test]
    fn a_link_at_the_lock_files_name_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        fs::create_dir_all(&state).unwrap();
        let elsewhere = dir.path().join("elsewhere");
        fs::write(&elsewhere, format!("{KEY}\n")).unwrap();
        std::os::unix::fs::symlink(&elsewhere, lock_path_in(&state)).unwrap();
        assert!(StateLock::acquire(&state).is_err());
        assert_eq!(live_authority(&state), None);
    }
}
