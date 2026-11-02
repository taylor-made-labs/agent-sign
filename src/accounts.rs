//! The people's accounts on this machine, whose names agents never get.
//!
//! Security review fix round (31 Oct 2026, finding M2): the service must never
//! certify an agent under a person's name, and before this it knew a person's
//! name only from git's `user.name`, which on a server whose agents set
//! `user.name` themselves names no person at all. A machine's account
//! database does name its people, with no setting: the service reads it once
//! at start ([`persons_accounts`]) and refuses, at token issue, any agent name
//! that is the login name of a person's account or a word of its full name
//! (see [`crate::attribution::IdentityPolicy`]). Nothing here reads git.
//!
//! **Which accounts are a person's.** Those with a login shell that lets
//! someone log in (not `nologin`, `false` or `true`) and a user id in the
//! range the system gives to people:
//! - **Linux:** uid 1000 and up, the default first uid of `useradd` and
//!   `adduser` (`UID_MIN` in /etc/login.defs) on Debian, Ubuntu, Fedora,
//!   Arch and Raspberry Pi OS. Service accounts below it, and accounts with
//!   `nologin` (such as `nobody`), are left out.
//! - **macOS:** uid 501 and up, where macOS numbers the accounts made in
//!   System Settings (the first is 501). Below 1000 there, so the Linux rule
//!   would cover no one; system accounts (`_www`, `daemon`, `nobody`) have
//!   uids below 500 or `false` as their shell.
//!
//! The account agent-sign itself runs as is left out: that is the account the
//! agents share, and on Taylor's servers it is called `agents`.
//!
//! **What it reads.** `getpwent`, the system's own account database: on Linux
//! /etc/passwd plus whatever the name service lists (an LDAP or SSSD
//! directory lists its accounts only when set to enumerate them); on macOS
//! Directory Services' local accounts. A person with no account on the
//! machine is listed in `[identity] people` instead (`install.sh --person`).
//!
//! The full name is the account's GECOS field up to its first comma (Linux
//! puts room and phone numbers after it).
//!
//! **A failed read stops the service** (31 Oct 2026 follow-up, item 3). Run
//! with an empty list, the service would certify an agent under any account
//! holder's name, so [`persons_accounts`] returns an error instead and the
//! service refuses to start. A read has failed when `getpwent` stops with an
//! error (`EIO`, `EMFILE`, `ENFILE`, `ENOMEM` or `ERANGE`, the errors it
//! documents) or when the walk never lists root, which every Unix account
//! database has.
//!
//! Tests force a failure with `AGENT_SIGN_TEST_ACCOUNTS=fail`. Like the
//! stand-in for the device owner, it is read only in builds with the
//! `test-authenticator` feature, which `src/lib.rs` refuses to compile
//! outside debug test builds, so an installed program has no such code.

use crate::attribution::PersonName;
use std::ffi::CStr;
use std::sync::Mutex;

/// One entry of the account database, as far as agent-sign reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    /// The login name, such as `taylor`.
    pub login: String,
    /// The full name (GECOS up to its first comma), possibly empty.
    pub full_name: String,
    pub uid: u32,
    /// The login shell, possibly empty (which means `/bin/sh`).
    pub shell: String,
}

/// The first user id the system gives to a person (see the module header).
#[cfg(target_os = "macos")]
pub const FIRST_PERSON_UID: u32 = 501;
/// The first user id the system gives to a person (see the module header).
#[cfg(not(target_os = "macos"))]
pub const FIRST_PERSON_UID: u32 = 1000;

/// Whether `shell` lets someone log in: not `nologin`, `false` or `true`
/// (wherever they live). An empty shell means `/bin/sh`, so it does.
fn is_login_shell(shell: &str) -> bool {
    let name = shell.rsplit('/').next().unwrap_or(shell);
    !matches!(name, "nologin" | "false" | "true")
}

/// The accounts of `all` that are people's: a uid from `first_uid` up, a
/// login shell, and not `own_uid` (the account agent-sign runs as).
pub fn persons_of(all: &[Account], own_uid: u32, first_uid: u32) -> Vec<Account> {
    all.iter()
        .filter(|a| a.uid >= first_uid && a.uid != own_uid && is_login_shell(&a.shell))
        .cloned()
        .collect()
}

/// The names [`persons_of`]'s accounts give: each login name's slugs and
/// each full name's, said as coming from that account.
pub fn names_of(accounts: &[Account]) -> Vec<PersonName> {
    let mut out = Vec::new();
    for account in accounts {
        out.extend(PersonName::all_of(
            &account.login,
            &format!(
                "the login name of the account {} on this machine",
                account.login
            ),
        ));
        out.extend(PersonName::all_of(
            &account.full_name,
            &format!(
                "a person's name (the account {} on this machine is {:?})",
                account.login, account.full_name
            ),
        ));
    }
    out
}

/// Sets this thread's `errno` to 0, so an error `getpwent` reports can be
/// told from the end of the list (both return null).
fn clear_errno() {
    // SAFETY: the errno location is this thread's own, always valid.
    #[cfg(target_os = "linux")]
    unsafe {
        *libc::__errno_location() = 0;
    }
    // SAFETY: as above.
    #[cfg(target_os = "macos")]
    unsafe {
        *libc::__error() = 0;
    }
}

/// Whether `errno` after a null `getpwent` is one of the errors it documents
/// (not the end of the list, which leaves 0, or `ENOENT` on glibc).
fn is_read_error(errno: i32) -> bool {
    cfg!(any(target_os = "linux", target_os = "macos"))
        && [
            libc::EIO,
            libc::EMFILE,
            libc::ENFILE,
            libc::ENOMEM,
            libc::ERANGE,
        ]
        .contains(&errno)
}

/// Every account the system's account database lists (`getpwent`), or why
/// the list can't be trusted to be whole (see the module header).
pub fn all_accounts() -> Result<Vec<Account>, String> {
    // getpwent walks one cursor shared by the whole process: one walk at a
    // time.
    static WALK: Mutex<()> = Mutex::new(());
    let _walk = WALK.lock().unwrap_or_else(|e| e.into_inner());
    let text = |p: *const libc::c_char| {
        if p.is_null() {
            String::new()
        } else {
            // SAFETY: a non-null field of a passwd entry is a NUL-terminated
            // string that stays valid until the next getpwent/endpwent call,
            // and it is copied out before then.
            unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
        }
    };
    let mut out = Vec::new();
    let mut error = None;
    // SAFETY: setpwent, getpwent and endpwent take no arguments; the entry
    // getpwent returns is read only before the next call, under WALK.
    unsafe { libc::setpwent() };
    loop {
        clear_errno();
        // SAFETY: as above.
        let entry = unsafe { libc::getpwent() };
        if entry.is_null() {
            let errno = std::io::Error::last_os_error();
            if errno.raw_os_error().is_some_and(is_read_error) {
                error = Some(errno);
            }
            break;
        }
        // SAFETY: getpwent returned a non-null pointer to a passwd entry,
        // valid until the next call.
        let pw = unsafe { &*entry };
        let gecos = text(pw.pw_gecos);
        out.push(Account {
            login: text(pw.pw_name),
            full_name: gecos.split(',').next().unwrap_or("").trim().to_string(),
            uid: pw.pw_uid,
            shell: text(pw.pw_shell),
        });
    }
    // SAFETY: as above.
    unsafe { libc::endpwent() };
    if let Some(e) = error {
        return Err(format!(
            "reading the machine's account database failed after {} accounts ({e})",
            out.len()
        ));
    }
    if !out.iter().any(|a| a.uid == 0) {
        return Err(format!(
            "the machine's account database listed {} accounts and no root account, so the \
             list isn't whole",
            out.len()
        ));
    }
    Ok(out)
}

/// The test seam (see the module header): whether this start must fail its
/// account read. Compiled only with the `test-authenticator` feature.
#[cfg(feature = "test-authenticator")]
fn read_forced_to_fail() -> bool {
    std::env::var("AGENT_SIGN_TEST_ACCOUNTS").is_ok_and(|v| v == "fail")
}

/// Without the `test-authenticator` feature nothing can force a failure.
#[cfg(not(feature = "test-authenticator"))]
fn read_forced_to_fail() -> bool {
    false
}

/// The people's accounts on this machine (see the module header), read now,
/// or why they couldn't be read: the service then refuses to start rather
/// than run with no one's names. The service calls this once, at start.
pub fn persons_accounts() -> Result<Vec<Account>, String> {
    if read_forced_to_fail() {
        return Err("reading the machine's account database failed (forced by a test)".into());
    }
    // SAFETY: getuid takes no arguments and can't fail.
    let own = unsafe { libc::getuid() };
    Ok(persons_of(&all_accounts()?, own, FIRST_PERSON_UID))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(login: &str, full: &str, uid: u32, shell: &str) -> Account {
        Account {
            login: login.into(),
            full_name: full.into(),
            uid,
            shell: shell.into(),
        }
    }

    #[test]
    fn people_are_accounts_with_a_persons_uid_and_a_login_shell_other_than_ours() {
        let all = [
            account("root", "root", 0, "/bin/bash"),
            account("sshd", "", 983, "/usr/sbin/nologin"),
            account("taylor", "Taylor Example", 1000, "/bin/bash"),
            account("agents", "", 1001, "/bin/bash"),
            account("claw", "", 1002, "/usr/sbin/nologin"),
            account("ollama", "", 1003, "/bin/false"),
            account("plain", "", 1004, ""),
            account("nobody", "nobody", 65534, "/usr/sbin/nologin"),
        ];
        let people: Vec<String> = persons_of(&all, 1001, 1000)
            .into_iter()
            .map(|a| a.login)
            .collect();
        assert_eq!(people, ["taylor", "plain"]);
        let names: Vec<String> = names_of(&persons_of(&all, 1001, 1000))
            .into_iter()
            .map(|p| p.slug)
            .collect();
        assert_eq!(
            names,
            ["taylor", "taylor", "example", "taylor-example", "plain"]
        );
    }

    #[test]
    fn the_account_database_can_be_read() {
        // Every Unix system lists root.
        assert!(all_accounts().unwrap().iter().any(|a| a.uid == 0));
        assert!(persons_accounts().is_ok());
    }

    #[test]
    fn only_the_errors_getpwent_documents_are_a_failed_read() {
        for errno in [
            libc::EIO,
            libc::EMFILE,
            libc::ENFILE,
            libc::ENOMEM,
            libc::ERANGE,
        ] {
            assert!(is_read_error(errno), "{errno}");
        }
        for end in [0, libc::ENOENT] {
            assert!(!is_read_error(end), "{end}");
        }
    }
}
