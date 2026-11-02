#![allow(dead_code)]
//! Test keys that exist only in the test process's memory.
//!
//! The rule (Taylor, 28 Oct 2026; a breach found 1 Nov 2026): every private
//! key is protected from the moment it exists, with no throwaway exception
//! for tests. So no test makes a key with `ssh-keygen` (that writes a private
//! key file, and `-N` with an empty passphrase is exactly what the rule bans),
//! and none writes a private key file of its own. A test key is made here with
//! the `ssh-key` crate, from a seed read from the operating system's random
//! source into memory that is wiped when it is dropped; it is never written
//! anywhere. What a test needs from it goes out by a protected path:
//!
//! * its public half, as a file: [`write_public_file`] (public keys may be
//!   files; this is all the fixtures that only need git's `user.signingkey`
//!   to name a public key file ever needed);
//! * its signature, through a per-test ssh agent: `support/key_agent.rs`.
//!
//! `tests/test_no_unprotected_test_keys.rs` fails the build if a test goes back
//! to `ssh-keygen` generation, and `support/no_plain_keys.rs` checks what a
//! test left on disk.
//!
//! Included, like the other support files, with
//! `#[path = "support/memory_keys.rs"] mod memory_keys;`.

use rand::RngCore;
use rand::rngs::OsRng;
use ssh_key::PublicKey;
use ssh_key::private::{Ed25519Keypair, KeypairData, PrivateKey};
use std::fs;
use std::path::Path;
use zeroize::Zeroizing;

/// A new random ed25519 key with `comment`, held in memory only.
pub fn new_ed25519(comment: &str) -> PrivateKey {
    let mut seed = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(seed.as_mut());
    PrivateKey::new(
        KeypairData::Ed25519(Ed25519Keypair::from_seed(&seed)),
        comment,
    )
    .expect("an ed25519 keypair makes a private key")
}

/// A fresh random passphrase held only in memory and wiped when dropped: the
/// one passphrase source the guard (`tests/test_no_unprotected_test_keys.rs`)
/// accepts for a key tool's `-N`. For the rare test that must have an
/// ENCRYPTED key file; a literal, an empty or an environment-supplied value is
/// never protection. 48 hex characters, so far above the key tool's minimum
/// length of five.
pub fn random_passphrase() -> Zeroizing<String> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut raw = Zeroizing::new([0u8; 24]);
    OsRng.fill_bytes(raw.as_mut());
    let mut out = Zeroizing::new(String::with_capacity(48));
    for byte in raw.iter() {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 15) as usize] as char);
    }
    out
}

/// The key's public half as one OpenSSH line, `ssh-ed25519 <data> <comment>`
/// (no newline), the same shape `ssh-keygen` writes to a `.pub` file.
pub fn public_line(key: &PrivateKey) -> String {
    PublicKey::new(key.public_key().key_data().clone(), key.comment())
        .to_openssh()
        .expect("a public key encodes")
}

/// Writes only the public half of `key` to `path` (with a newline). The
/// private half goes nowhere.
pub fn write_public_file(path: &Path, key: &PrivateKey) {
    fs::write(path, format!("{}\n", public_line(key))).unwrap();
}

/// A new key made only to have a public half on disk: writes `<path>.pub` and
/// drops the key, whose private half never existed anywhere else. Returns the
/// public line (no newline).
pub fn write_public_only(path_without_pub: &Path, comment: &str) -> String {
    let key = new_ed25519(comment);
    let mut with_pub = path_without_pub.as_os_str().to_owned();
    with_pub.push(".pub");
    write_public_file(Path::new(&with_pub), &key);
    public_line(&key)
}

/// What stands in for the old shared agent key's private half in the
/// installer tests. The installer deletes that file by its path, whatever it
/// holds, so the tests need a file there, not a key; this is plainly not one
/// (it does not parse as any key format), so no private key is ever on disk.
pub const LEGACY_PRIVATE_HALF_STAND_IN: &str =
    "stand-in for the old shared agent key's private half; this is not a key\n";
