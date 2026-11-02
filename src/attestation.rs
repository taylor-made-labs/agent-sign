//! How an agent's identity was established, as its certificate records it.
//!
//! Why: until caller identity (docs/caller-identity.md, 31 Oct 2026) every
//! agent certificate named a principal that some process in a shared account
//! had claimed, and nothing in the certificate said so. A verifier couldn't
//! tell a name the kernel or a signed approval vouched for from one anybody
//! in the account could have asked for. So each certificate the service
//! issues for an established identity now carries how it was established,
//! as the OpenSSH certificate *extension* [`EXTENSION`]. It is an extension,
//! never a critical option: verifiers that don't know it (plain `git log
//! --show-signature`, `ssh-keygen -Y verify`) ignore it and keep working.
//!
//! The values ([`Attestation::encode`]):
//! - `launcher session=<id> uid=<n> isolation=<pid-namespace|slot-account>`:
//!   a session agent-sign's launcher started, with how it was kept apart
//!   (`slot-account` replaced `dynamic-user` with decision D6, 1 Nov 2026:
//!   sessions on a server run in static per-slot accounts, not systemd's
//!   DynamicUser, and nothing had shipped with the old word);
//! - `approval sha256=<hex>`: signed on a commit approval from the
//!   commitments approval key, with the approval text's hash;
//! - `unattested`: nothing established the name.
//!
//! A certificate without the extension records no attestation: every
//! certificate made before this change, and those today's plain path still
//! makes. [`describe_missing`] says what that means.
//!
//! The words [`Attestation::describe`] gives are what `agent-sign verify`
//! prints, and only after the signature has verified against the trust the
//! machine has (see [`crate::verify`]): anybody can mint a certificate whose
//! extension says anything, so the words mean something only for a
//! certificate from a trusted authority. None of them says "proven": the
//! strongest of these still rests on the launcher's or the approval key's
//! own integrity, and the launcher on one account can't keep other
//! processes of that account out (the critique of the build plan, 31 Oct
//! 2026), so its words say exactly that.

use std::fmt;

/// The certificate extension that carries an [`Attestation`].
pub const EXTENSION: &str = "attestation@agent-sign";

/// What `agent-sign verify` says about a trusted certificate with no
/// [`EXTENSION`]: the name in it was claimed, not established (P8).
pub const CLAIMED_WORDS: &str = "claimed by a process in a shared account: the certificate \
records no attestation, so any process of the account the service ran in could have asked \
for this name";

/// What `agent-sign verify` says first about a session the one-account
/// launcher started (decision D4, 31 Oct 2026): exactly how far its
/// isolation goes, never "proven". A plain process of the same account can
/// still reach into such a session (`pidfd_getfd`), which only a uid per
/// session closes.
pub const LAUNCHER_SAME_ACCOUNT_WORDS: &str = "launcher, same account: isolated from other \
launched sessions, not from other processes of this account";

/// What `agent-sign verify` says first about a session that ran in a slot
/// account of its own (system mode, docs/system-mode.md section 4): no other
/// account could reach into it. Still not "proven": it rests on the launcher
/// and the service.
pub const LAUNCHER_OWN_ACCOUNT_WORDS: &str = "launcher, own account: the session ran in an \
account of its own, so no other account could reach it";

/// How a launched session was kept apart from other processes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Isolation {
    /// One account, a PID namespace per session (bwrap): sessions can't see
    /// each other, but other processes of the same account aren't kept out.
    PidNamespace,
    /// An account of its own for the session: one of the machine's static
    /// slot accounts (`agent-slot-<n>`, decision D6), in its own systemd
    /// unit. The kernel's uid checks keep every other account out, and the
    /// service counted a caller as the session only when its uid, its unit
    /// and its live process all matched (`crate::kernel_facts`).
    SlotAccount,
}

impl Isolation {
    fn as_str(self) -> &'static str {
        match self {
            Isolation::PidNamespace => "pid-namespace",
            Isolation::SlotAccount => "slot-account",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "pid-namespace" => Some(Isolation::PidNamespace),
            "slot-account" => Some(Isolation::SlotAccount),
            _ => None,
        }
    }
}

/// How the identity in a certificate was established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attestation {
    /// A session agent-sign's launcher started: the session's id (made by
    /// the service, lowercase hex), the uid it ran as, and its isolation.
    Launcher {
        session: String,
        uid: u32,
        isolation: Isolation,
    },
    /// Signed on a commit approval: the SHA-256 of the approval's exact
    /// text, lowercase hex, so the approval can be found and checked again.
    Approval { sha256: String },
    /// Nothing established the name.
    Unattested,
}

/// Whether `s` is `len_min..=len_max` lowercase hex digits.
fn is_lower_hex(s: &str, len_min: usize, len_max: usize) -> bool {
    (len_min..=len_max).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl Attestation {
    /// The extension's value, as the module documentation lists them.
    pub fn encode(&self) -> String {
        match self {
            Attestation::Launcher {
                session,
                uid,
                isolation,
            } => format!(
                "launcher session={session} uid={uid} isolation={}",
                isolation.as_str()
            ),
            Attestation::Approval { sha256 } => format!("approval sha256={sha256}"),
            Attestation::Unattested => "unattested".to_string(),
        }
    }

    /// The attestation an extension value encodes, or `None` for anything
    /// [`Attestation::encode`] can't have written: the fields in order, each
    /// once, nothing else. Strict, because the value is read back by
    /// `agent-sign verify`, and anything it can't read must not be mistaken
    /// for an attestation.
    pub fn decode(value: &str) -> Option<Self> {
        let words: Vec<&str> = value.split(' ').collect();
        match words.as_slice() {
            ["unattested"] => Some(Attestation::Unattested),
            ["approval", hash] => {
                let sha256 = hash.strip_prefix("sha256=")?;
                is_lower_hex(sha256, 64, 64).then(|| Attestation::Approval {
                    sha256: sha256.to_string(),
                })
            }
            ["launcher", session, uid, isolation] => {
                let session = session.strip_prefix("session=")?;
                let uid = uid.strip_prefix("uid=")?;
                let isolation = Isolation::parse(isolation.strip_prefix("isolation=")?)?;
                if !is_lower_hex(session, 8, 64)
                    || uid.is_empty()
                    || !uid.bytes().all(|b| b.is_ascii_digit())
                {
                    return None;
                }
                Some(Attestation::Launcher {
                    session: session.to_string(),
                    uid: uid.parse().ok()?,
                    isolation,
                })
            }
            _ => None,
        }
    }

    /// What `agent-sign verify` says about a trusted certificate carrying
    /// this attestation. Never "proven"; a launcher's words never say
    /// "claimed" or "unattested" (see the module documentation).
    pub fn describe(&self) -> String {
        match self {
            Attestation::Launcher {
                session,
                uid,
                isolation: Isolation::PidNamespace,
            } => format!(
                "{LAUNCHER_SAME_ACCOUNT_WORDS} (agent-sign's launcher started this session, \
                 {session}, as uid {uid}, and chose its name)"
            ),
            Attestation::Launcher {
                session,
                uid,
                isolation: Isolation::SlotAccount,
            } => format!(
                "{LAUNCHER_OWN_ACCOUNT_WORDS} (agent-sign's launcher started this session, \
                 {session}, as uid {uid}, and chose its name)"
            ),
            Attestation::Approval { sha256 } => format!(
                "approval: signed on a commit approval from the commitments approval key, which \
                 named this agent, this commit's tree and parents (approval sha256 {sha256})"
            ),
            Attestation::Unattested => {
                "unattested: neither agent-sign's launcher nor an approval established this name"
                    .to_string()
            }
        }
    }
}

impl fmt::Display for Attestation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.encode())
    }
}

/// What `agent-sign verify` says about a trusted certificate without the
/// [`EXTENSION`] (P8): [`CLAIMED_WORDS`].
pub fn describe_missing() -> &'static str {
    CLAIMED_WORDS
}

/// What `agent-sign verify` says about a trusted certificate whose
/// [`EXTENSION`] this version can't read: no stronger than a missing one.
pub fn describe_unreadable() -> String {
    format!("not one this version of agent-sign can read, so treat it as {CLAIMED_WORDS}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all() -> Vec<Attestation> {
        vec![
            Attestation::Launcher {
                session: "0123456789abcdef0123456789abcdef".into(),
                uid: 61184,
                isolation: Isolation::SlotAccount,
            },
            Attestation::Launcher {
                session: "0123456789abcdef".into(),
                uid: 1000,
                isolation: Isolation::PidNamespace,
            },
            Attestation::Approval {
                sha256: "ab".repeat(32),
            },
            Attestation::Unattested,
        ]
    }

    #[test]
    fn every_attestation_reads_back_as_itself() {
        for a in all() {
            assert_eq!(Attestation::decode(&a.encode()), Some(a.clone()), "{a}");
        }
    }

    #[test]
    fn anything_else_is_not_an_attestation() {
        for bad in [
            "",
            "launcher",
            "approval",
            "approval sha256=",
            &format!("approval sha256={}", "AB".repeat(32)),
            &format!("approval sha256={} extra", "ab".repeat(32)),
            "launcher session=xyz uid=1 isolation=pid-namespace",
            "launcher session=0123456789abcdef uid=-1 isolation=pid-namespace",
            "launcher session=0123456789abcdef uid=1 isolation=none",
            "launcher session=0123456789abcdef uid=1 isolation=dynamic-user",
            "launcher uid=1 session=0123456789abcdef isolation=pid-namespace",
            "unattested ",
            " unattested",
            "Unattested",
        ] {
            assert_eq!(Attestation::decode(bad), None, "{bad:?}");
        }
    }

    /// The guard the build plan asks for (P8): no words say "proven", a
    /// launcher's say neither "claimed" nor "unattested", the approval's say
    /// "approval", and a certificate without the extension reads "claimed by
    /// a process in a shared account".
    #[test]
    fn the_words_never_overstate() {
        let mut words: Vec<String> = all().iter().map(Attestation::describe).collect();
        words.push(describe_missing().to_string());
        words.push(describe_unreadable());
        for w in &words {
            assert!(!w.to_lowercase().contains("proven"), "{w}");
        }
        for a in all() {
            let w = a.describe();
            match a {
                Attestation::Launcher {
                    isolation: Isolation::PidNamespace,
                    ..
                } => {
                    assert!(!w.contains("claimed") && !w.contains("unattested"), "{w}");
                    assert!(w.contains(LAUNCHER_SAME_ACCOUNT_WORDS), "{w}");
                }
                Attestation::Launcher { .. } => {
                    assert!(!w.contains("claimed") && !w.contains("unattested"), "{w}");
                    assert!(w.contains(LAUNCHER_OWN_ACCOUNT_WORDS), "{w}");
                }
                Attestation::Approval { .. } => assert!(w.contains("approval"), "{w}"),
                Attestation::Unattested => assert!(w.contains("unattested"), "{w}"),
            }
        }
        assert!(describe_missing().contains("claimed by a process in a shared account"));
        assert!(describe_unreadable().contains("claimed by a process in a shared account"));
    }
}
