#![allow(dead_code)]
//! Runtime check: after a test, no unencrypted private key is left on disk.
//!
//! The rule (Taylor, 28 Oct 2026; a breach found 1 Nov 2026): every private
//! key is protected from the moment it exists, with no throwaway exception for
//! tests. `tests/test_no_unprotected_test_keys.rs` reads the test source for
//! the ways of making an unprotected key; this is the other half, which looks
//! at what a test actually left behind. A converted fixture calls
//! [`assert_no_plain_private_keys`] on its temp folders (its `home`, its
//! socket folder) after the test has run, and the test fails, naming the file,
//! if anything under them parses as an unencrypted OpenSSH private key (or is
//! an armored private key that does not say it is encrypted). Public keys and
//! certificates are not private keys and pass; an encrypted private key passes.
//!
//! A frame that does not parse counts as a hit (G2, 1 Nov 2026, the suite PM's
//! review): only an OpenSSH frame that parses AND is encrypted passes. A
//! truncated or hand-damaged key file used to be read as "not a key" and slip
//! by.
//!
//! This file holds the ONE run-time-built (`concat!`) private-key frame that
//! the source guard allows, in [`openssh_armor`], and it is keyed on this file's
//! name there. Every other piece of armor text here is a separate constant, so
//! no second frame is ever spelled out in this source.
//!
//! Included, like the other support files, with
//! `#[path = "support/no_plain_keys.rs"] mod no_plain_keys;`.

use ssh_key::PrivateKey;
use std::fs;
use std::path::{Path, PathBuf};

/// Larger files are not keys; skipping them keeps the walk cheap.
const MAX_KEY_FILE_BYTES: u64 = 64 * 1024;

/// The armor line is assembled here, so that the repository's own history scan
/// for private key blocks never matches this source.
fn openssh_armor() -> String {
    concat!("-----BEGIN OPENSSH ", "PRIVATE KEY-----").to_string()
}

/// The start of any armored block, and the end of the armor line of a private
/// one: kept apart (never one frame) so the source guard sees only the frame
/// above.
const ARMOR_OPEN: &str = "-----BEGIN ";
const ARMOR_PRIVATE_TAIL: &str = "PRIVATE KEY-----";

/// Whether `text` holds a private key that is not encrypted: an OpenSSH
/// private key whose cipher is none, or any other armored private key (PEM
/// PKCS#8, RSA, EC) that does not say ENCRYPTED. An OpenSSH frame that does not
/// parse (cut short, damaged, not base64) is a hit as well: only a frame that
/// parses AND is encrypted passes. Text that is not a key, public keys and
/// certificates are false.
pub fn is_plain_private_key(text: &str) -> bool {
    let armor = openssh_armor();
    if let Some(start) = text.find(&armor) {
        return match PrivateKey::from_openssh(&text[start..]) {
            Ok(key) => !key.is_encrypted(),
            Err(_) => true,
        };
    }
    text.contains(ARMOR_OPEN) && text.contains(ARMOR_PRIVATE_TAIL) && !text.contains("ENCRYPTED")
}

/// Every regular file under `root` (symlinks not followed) that is an
/// unencrypted private key.
pub fn find_plain_private_keys(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    walk(root, &mut found);
    found.sort();
    found
}

fn walk(dir: &Path, found: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.is_dir() {
            walk(&path, found);
        } else if meta.is_file()
            && meta.len() <= MAX_KEY_FILE_BYTES
            && let Ok(text) = fs::read_to_string(&path)
            && is_plain_private_key(&text)
        {
            found.push(path);
        }
    }
}

/// Fails the test, naming each file, if anything under `root` is an
/// unencrypted private key.
pub fn assert_no_plain_private_keys(root: &Path) {
    let found = find_plain_private_keys(root);
    assert!(
        found.is_empty(),
        "unencrypted private key(s) left on disk under {}: {:?}. A test key lives only in the \
         test's memory (make it with the ssh-key crate) and reaches ssh-keygen or git through a \
         per-test ssh agent (see tests/test_no_unprotected_test_keys.rs).",
        root.display(),
        found
    );
}
