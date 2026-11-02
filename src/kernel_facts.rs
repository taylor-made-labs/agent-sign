//! Who is asking, in system mode: the kernel's facts about a caller, behind a
//! small port (docs/system-mode.md, section 4; build step 2).
//!
//! **Why.** On a server every launched session runs in a static account of
//! its own (`agent-slot-<n>`, decision D6) inside its own systemd unit
//! (`agent-session@<n>.service`). The service must tell a session's processes
//! from everything else without trusting anything a caller says, so it asks
//! the kernel three things about the process on the other end of each
//! connection, and a caller is that session only when **all three** match:
//!
//! 1. **its uid** (`SO_PEERCRED`, recorded by the kernel when the process
//!    connected): the slot account the launcher registered;
//! 2. **its cgroup** (`/proc/<pid>/cgroup`, the cgroup v2 line `0::/...`):
//!    exactly that slot's session unit. Only root (systemd) places a process
//!    in a system unit's cgroup, and the session unit has no `Delegate=`, so a
//!    slot process outside its unit (a cron job, say, or the account used
//!    through another unit) can't move itself in;
//! 3. **that the process is still the same one** (`SO_PEERPIDFD`): a pidfd is
//!    a handle on one process that can't come to name a later process given
//!    the same number.
//!
//! Anything else is a plain caller: it gets the plain-path answers and never
//! a signature (decision D1).
//!
//! **Races and pid reuse, and why the order matters.** The cgroup is read
//! through the process's *number* (`/proc/<pid>/...`), and a number is
//! reused once its process has ended and been reaped. So the facts are read
//! in this order: the pidfd first (it pins the process the kernel recorded
//! at `connect`), then the cgroup through the number, then the pidfd is
//! asked whether its process still exists. A process holds its number until
//! it is reaped, so if the pidfd's process still exists *after* the cgroup
//! was read, the number named that same process when it was read, and the
//! cgroup is its own. If the pidfd says the process is gone, the number may
//! already name another process, the cgroup read proves nothing, and the
//! connection is refused outright, not even answered as plain. A process
//! that has exited but not been reaped (a zombie) still holds its number, so
//! counting it as present is sound: the facts read are still its own.
//!
//! What can change after the read doesn't matter: a process can't change its
//! uid (the session unit has `NoNewPrivileges=yes` and no capabilities) or
//! leave its unit's cgroup (it can't write `cgroup.procs` above it), and a
//! connection handed to another process (`SCM_RIGHTS`) is the session's own
//! choice to relay for it, which it could do anyway. No other account can
//! take a session's connection from it: `pidfd_getfd` needs ptrace rights
//! over the session's uid, which only that uid and root have. That is the
//! gap one-account mode has (D4) and slot accounts close.
//!
//! **The fallback rule.** `SO_PEERPIDFD` is in Linux 6.5 and later. On an
//! older kernel there is no way to tell a reused number from the process
//! that connected, so a caller there is **never a session**: it is answered
//! as plain (its uid, recorded at `connect`, is still reliable). The service
//! says so in its log once, at the first such caller. Nothing falls back to
//! trusting the number.
//!
//! **Where the unit's cgroup is.** systemd puts an instance of a template
//! unit under the template's slice, `system-agent\x2dsession.slice`, unless
//! the unit names `Slice=system.slice`. Both places are root's, and only the
//! unit's own processes are ever in either, so both are accepted, and
//! nothing else ([`unit_cgroups`]).
//!
//! **Not used: the unit's invocation id.** systemd 259 writes it on the
//! unit's cgroup as the `user.invocation_id` extended attribute, readable by
//! anyone (checked on hetzner, 1 Nov 2026). The launcher registers a session
//! before it starts the unit, so there is no invocation id to register yet,
//! and it isn't needed: the launcher registers a slot only after the slot's
//! previous unit is inactive, which means every process of the previous run
//! has ended (`KillMode=control-group`).
//!
//! **The test stand-in.** Tests can't make slot accounts or put a process in
//! a system unit, so in builds with the `test-authenticator` feature (never
//! installed; `src/lib.rs` refuses it outside debug builds), a file named by
//! `AGENT_SIGN_TEST_KERNEL_FACTS` stands in for the kernel, read again on
//! every call (see `tests/test_caller_registration.rs`).

use std::io;
use std::os::unix::net::UnixStream;
use std::sync::Arc;

/// Whether the process on the other end of a connection is still the one
/// that connected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Liveness {
    /// The pidfd's process still exists (it may have exited and not yet been
    /// reaped): the facts read through its number are its own.
    Alive,
    /// The pidfd's process is gone, or the pidfd couldn't be had because it
    /// was: its number may name another process now. Refused outright.
    Gone,
    /// No pidfd on this kernel (before Linux 6.5): never a session (the
    /// fallback rule in the module documentation).
    Unknown,
}

/// What the kernel reports about the process on the other end of one
/// connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerFacts {
    /// Its uid, as the kernel recorded it at `connect`.
    pub uid: u32,
    /// Its cgroup v2 line, `0::/...`, read before [`PeerFacts::process`] was
    /// checked; `None` when it couldn't be read.
    pub cgroup: Option<String>,
    /// Whether it is still the process that connected, checked after the
    /// cgroup was read.
    pub process: Liveness,
}

/// The kernel's facts the service decides callers by: the port. The real
/// adapter is [`RealKernel`]; tests use a file (see the module
/// documentation).
pub trait KernelFacts: Send + Sync {
    /// The uid of the account called `name`, `Ok(None)` when there is no
    /// such account, or an error when the account database couldn't be read
    /// (the caller then refuses: it never guesses).
    fn account_uid(&self, name: &str) -> Result<Option<u32>, String>;

    /// The facts about the process on the other end of `conn`. An error when
    /// the kernel wouldn't say: the caller then refuses the connection.
    fn peer(&self, conn: &UnixStream) -> io::Result<PeerFacts>;
}

/// The name of slot `n`'s session unit.
pub fn session_unit(slot: u32) -> String {
    format!("agent-session@{slot}.service")
}

/// The cgroup v2 lines a process of `unit` (an `agent-session@<n>.service`)
/// has: directly under `system.slice`, or under the template's own slice,
/// where systemd puts template instances by default. Only the unit's own
/// processes are ever in either (see the module documentation).
pub fn unit_cgroups(unit: &str) -> [String; 2] {
    [
        format!("0::/system.slice/{unit}"),
        format!("0::/system.slice/system-agent\\x2dsession.slice/{unit}"),
    ]
}

/// A live registration, as the judgement needs it.
#[derive(Debug, Clone, Copy)]
pub struct LiveSlot<'a> {
    /// The session's id.
    pub session: &'a str,
    /// The slot account's uid.
    pub uid: u32,
    /// The slot's session unit.
    pub unit: &'a str,
}

/// What a connection on the service's ordinary socket is, in system mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Judgement {
    /// The session with this id: uid, unit and live process all match.
    Session(String),
    /// Anyone else: plain-path answers only, never a signature.
    Plain,
    /// The process that connected is gone: not answered at all, why given.
    Refused(String),
}

/// Judges `facts` against the live registrations (see the module
/// documentation): a session only when the process is [`Liveness::Alive`],
/// its uid is a registered slot's and its cgroup is exactly that slot's
/// unit's. Pure, so every case is tested without a kernel.
pub fn judge<'a>(facts: &PeerFacts, live: impl IntoIterator<Item = LiveSlot<'a>>) -> Judgement {
    match facts.process {
        Liveness::Gone => {
            return Judgement::Refused(
                "the process that connected has already ended, so its number may name another \
                 process now: refused"
                    .into(),
            );
        }
        Liveness::Unknown => return Judgement::Plain,
        Liveness::Alive => {}
    }
    let Some(cgroup) = facts.cgroup.as_deref() else {
        return Judgement::Plain;
    };
    for slot in live {
        if slot.uid == facts.uid && unit_cgroups(slot.unit).iter().any(|c| c == cgroup) {
            return Judgement::Session(slot.session.to_string());
        }
    }
    Judgement::Plain
}

/// The settings registration is checked against (`system.toml`'s
/// `[launcher] account` and `[slots]`).
#[derive(Debug, Clone)]
pub struct SlotPolicy {
    /// The only account that registers sessions.
    pub launcher_account: String,
    /// Slot `n`'s account is `<prefix><n>`.
    pub account_prefix: String,
    /// Slots are 1 to `count`.
    pub count: u32,
}

/// What the launcher asks for, as the service read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationAsked {
    pub slot: u32,
    pub uid: u32,
    pub unit: String,
}

/// A registration that passed [`check_registration`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotBinding {
    pub slot: u32,
    /// The slot account's uid.
    pub uid: u32,
    /// `agent-session@<slot>.service`.
    pub unit: String,
}

/// Whether the registration `asked` stands (docs/system-mode.md, section 4):
/// the slot is one of the configured ones, its account (looked up by name,
/// `<prefix><n>`) has exactly the uid asked, the unit is exactly that slot's
/// session unit, and the uid is none of the accounts a session must never be
/// (root, `never`: the service's and the launcher's own, people's). Whether
/// the slot is free is checked by the caller, under its lock, where the
/// session is recorded.
pub fn check_registration(
    asked: &RegistrationAsked,
    policy: &SlotPolicy,
    kernel: &dyn KernelFacts,
    never: &[u32],
) -> Result<SlotBinding, String> {
    if asked.slot == 0 || asked.slot > policy.count {
        return Err(format!(
            "slot {} isn't one of this machine's slots (1 to {})",
            asked.slot, policy.count
        ));
    }
    let account = format!("{}{}", policy.account_prefix, asked.slot);
    let uid = kernel
        .account_uid(&account)?
        .ok_or_else(|| format!("slot {}'s account, {account}, doesn't exist", asked.slot))?;
    if uid != asked.uid {
        return Err(format!(
            "uid {} isn't slot {}'s account ({account} is uid {uid})",
            asked.uid, asked.slot
        ));
    }
    if uid == 0 || never.contains(&uid) {
        return Err(format!(
            "{account} has uid {uid}, which is root's, the service's, the launcher's or a \
             person's: a session never runs as it"
        ));
    }
    let unit = session_unit(asked.slot);
    if asked.unit != unit {
        return Err(format!(
            "slot {}'s session unit is {unit}, and the registration named {:?}",
            asked.slot, asked.unit
        ));
    }
    Ok(SlotBinding {
        slot: asked.slot,
        uid,
        unit,
    })
}

/// The kernel itself: `SO_PEERCRED`, `SO_PEERPIDFD`, `/proc/<pid>/cgroup`,
/// `pidfd_send_signal` and the account database (`getpwnam_r`).
#[derive(Debug, Default)]
pub struct RealKernel;

impl KernelFacts for RealKernel {
    fn account_uid(&self, name: &str) -> Result<Option<u32>, String> {
        uid_by_name(name)
    }

    #[cfg(target_os = "linux")]
    fn peer(&self, conn: &UnixStream) -> io::Result<PeerFacts> {
        linux::peer(conn)
    }

    /// No slot sessions off Linux: every caller is plain.
    #[cfg(not(target_os = "linux"))]
    fn peer(&self, conn: &UnixStream) -> io::Result<PeerFacts> {
        use std::os::fd::AsRawFd;
        Ok(PeerFacts {
            uid: crate::session::peer_uid(conn.as_raw_fd())?,
            cgroup: None,
            process: Liveness::Unknown,
        })
    }
}

/// The uid of the account `name` in the system's account database.
fn uid_by_name(name: &str) -> Result<Option<u32>, String> {
    let cname = std::ffi::CString::new(name)
        .map_err(|_| format!("the account name {name:?} has a NUL in it"))?;
    let mut buf: Vec<libc::c_char> = vec![0; 16 * 1024];
    loop {
        // SAFETY: an all-zero passwd is a valid buffer for getpwnam_r to
        // fill; its strings point into `buf`, which outlives this read.
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut found: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: every pointer is valid for the lengths given.
        let rc = unsafe {
            libc::getpwnam_r(
                cname.as_ptr(),
                &mut pwd,
                buf.as_mut_ptr(),
                buf.len(),
                &mut found,
            )
        };
        if rc == libc::ERANGE && buf.len() < 1 << 20 {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        if found.is_null() {
            // POSIX lets "no such account" come back as 0 or as one of these.
            return if [0, libc::ENOENT, libc::ESRCH, libc::EBADF, libc::EPERM].contains(&rc) {
                Ok(None)
            } else {
                Err(format!(
                    "couldn't read the account database for {name} ({})",
                    io::Error::from_raw_os_error(rc)
                ))
            };
        }
        return Ok(Some(pwd.pw_uid));
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{Liveness, PeerFacts};
    use std::io::{self, Read};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::os::unix::net::UnixStream;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// The most of `/proc/<pid>/cgroup` read: one line on cgroup v2.
    const MAX_CGROUP_FILE: u64 = 64 * 1024;

    /// The facts, in the order the module documentation explains.
    pub(super) fn peer(conn: &UnixStream) -> io::Result<PeerFacts> {
        let fd = conn.as_raw_fd();
        let (uid, pid) = peer_cred(fd)?;
        // 1. The pidfd, pinning the process that connected.
        let pidfd = match peer_pidfd(fd) {
            Ok(pidfd) => Some(pidfd),
            // Gone (and reaped) before we could ask: the number is free.
            Err(e) if e.raw_os_error() == Some(libc::ESRCH) => {
                return Ok(PeerFacts {
                    uid,
                    cgroup: None,
                    process: Liveness::Gone,
                });
            }
            // This kernel has no SO_PEERPIDFD: the fallback rule.
            Err(e)
                if matches!(
                    e.raw_os_error(),
                    Some(libc::ENOPROTOOPT) | Some(libc::EINVAL) | Some(libc::EOPNOTSUPP)
                ) =>
            {
                say_no_pidfd_once();
                None
            }
            Err(e) => return Err(e),
        };
        // 2. The cgroup, through the number.
        let cgroup = if pid > 0 { read_cgroup(pid) } else { None };
        // 3. Whether the pinned process still exists, after the read.
        let process = match &pidfd {
            None => Liveness::Unknown,
            Some(pidfd) if still_exists(pidfd) => Liveness::Alive,
            Some(_) => Liveness::Gone,
        };
        Ok(PeerFacts {
            uid,
            cgroup,
            process,
        })
    }

    fn say_no_pidfd_once() {
        static SAID: AtomicBool = AtomicBool::new(false);
        if !SAID.swap(true, Ordering::SeqCst) {
            eprintln!(
                "[agent-signd] this kernel has no SO_PEERPIDFD (Linux 6.5 and later), so no \
                 caller can be told apart from a later process given the same number: every \
                 caller is answered as plain, and no session signs"
            );
        }
    }

    fn peer_cred(fd: RawFd) -> io::Result<(u32, i32)> {
        let mut cred = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: getsockopt writes at most `len` bytes into `cred`.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut cred as *mut libc::ucred as *mut libc::c_void,
                &mut len,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((cred.uid, cred.pid))
    }

    fn peer_pidfd(fd: RawFd) -> io::Result<OwnedFd> {
        let mut pidfd: libc::c_int = -1;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: getsockopt writes at most `len` bytes into `pidfd`.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERPIDFD,
                &mut pidfd as *mut libc::c_int as *mut libc::c_void,
                &mut len,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        if pidfd < 0 {
            return Err(io::Error::other("the kernel gave no pidfd"));
        }
        // SAFETY: the kernel just made this descriptor for us (close-on-exec).
        Ok(unsafe { OwnedFd::from_raw_fd(pidfd) })
    }

    /// The cgroup v2 line (`0::/...`) of process `pid`, if it can be read.
    fn read_cgroup(pid: i32) -> Option<String> {
        let file = std::fs::File::open(format!("/proc/{pid}/cgroup")).ok()?;
        let mut text = String::new();
        file.take(MAX_CGROUP_FILE).read_to_string(&mut text).ok()?;
        text.lines()
            .find(|l| l.starts_with("0::"))
            .map(str::to_string)
    }

    /// Whether the pidfd's process still exists: signal 0 checks without
    /// sending anything. `EPERM` means it exists and belongs to an account
    /// this one can't signal (every slot's); `ESRCH`, or any other error,
    /// counts as gone (fail closed).
    fn still_exists(pidfd: &OwnedFd) -> bool {
        // SAFETY: pidfd_send_signal with signal 0 and no info sends nothing.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                pidfd.as_raw_fd(),
                0,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
        rc == 0 || io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
}

/// The kernel facts the service uses: the kernel itself, or, in test builds
/// only, the stand-in file `AGENT_SIGN_TEST_KERNEL_FACTS` names.
pub fn kernel() -> Arc<dyn KernelFacts> {
    #[cfg(feature = "test-authenticator")]
    if let Some(path) = std::env::var_os("AGENT_SIGN_TEST_KERNEL_FACTS") {
        return Arc::new(test_seam::FileFacts {
            path: std::path::PathBuf::from(path),
        });
    }
    Arc::new(RealKernel)
}

/// Whether the kernel's facts come from the test stand-in file: never in an
/// installed program (the stand-in exists only in debug test builds). The
/// launcher uses it for the one fact the stand-in can't fake, a file's
/// owner: tests can't give a file to a slot account, so under the stand-in
/// a slot's files are the test's own (see `crate::launcher`).
pub fn is_stand_in() -> bool {
    #[cfg(feature = "test-authenticator")]
    if std::env::var_os("AGENT_SIGN_TEST_KERNEL_FACTS").is_some() {
        return true;
    }
    false
}

/// The test stand-in (see the module documentation). The file is JSON:
/// `{"accounts": {"<name>": <uid>, ...}, "peer": {"uid": <uid>, "cgroup":
/// "<line>", "process": "alive" | "gone"}}`, read on every call.
#[cfg(feature = "test-authenticator")]
mod test_seam {
    use super::{KernelFacts, Liveness, PeerFacts};
    use std::io;
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;

    pub(super) struct FileFacts {
        pub(super) path: PathBuf,
    }

    impl FileFacts {
        fn read(&self) -> io::Result<serde_json::Value> {
            let text = std::fs::read_to_string(&self.path)?;
            serde_json::from_str(&text).map_err(io::Error::other)
        }
    }

    impl KernelFacts for FileFacts {
        fn account_uid(&self, name: &str) -> Result<Option<u32>, String> {
            let facts = self.read().map_err(|e| e.to_string())?;
            Ok(facts["accounts"][name]
                .as_u64()
                .and_then(|u| u32::try_from(u).ok()))
        }

        fn peer(&self, _conn: &UnixStream) -> io::Result<PeerFacts> {
            let facts = self.read()?;
            let peer = &facts["peer"];
            let uid = peer["uid"]
                .as_u64()
                .and_then(|u| u32::try_from(u).ok())
                .ok_or_else(|| io::Error::other("the stand-in names no peer uid"))?;
            Ok(PeerFacts {
                uid,
                cgroup: peer["cgroup"].as_str().map(str::to_string),
                process: match peer["process"].as_str() {
                    Some("alive") => Liveness::Alive,
                    Some("gone") => Liveness::Gone,
                    _ => Liveness::Unknown,
                },
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn facts(uid: u32, cgroup: &str, process: Liveness) -> PeerFacts {
        PeerFacts {
            uid,
            cgroup: Some(cgroup.to_string()),
            process,
        }
    }

    fn live() -> Vec<LiveSlot<'static>> {
        vec![
            LiveSlot {
                session: "s1",
                uid: 61001,
                unit: "agent-session@1.service",
            },
            LiveSlot {
                session: "s2",
                uid: 61002,
                unit: "agent-session@2.service",
            },
        ]
    }

    #[test]
    fn a_session_needs_its_uid_its_unit_and_a_live_process() {
        let unit1 = "0::/system.slice/agent-session@1.service";
        let templ1 = "0::/system.slice/system-agent\\x2dsession.slice/agent-session@1.service";
        for cg in [unit1, templ1] {
            assert_eq!(
                judge(&facts(61001, cg, Liveness::Alive), live()),
                Judgement::Session("s1".into())
            );
        }
        for (uid, cg) in [
            (61002, unit1),
            (1000, unit1),
            (61001, "0::/system.slice/agent-session@2.service"),
            (61001, "0::/system.slice/agent-session@1.service/child"),
            (61001, "0::/system.slice/agent-signd.service"),
            (61001, "0::/user.slice/user-61001.slice/session-3.scope"),
            (61001, "0::/system.slice/agent-session@10.service"),
            (61001, " 0::/system.slice/agent-session@1.service"),
        ] {
            assert_eq!(
                judge(&facts(uid, cg, Liveness::Alive), live()),
                Judgement::Plain,
                "{uid} {cg}"
            );
        }
        // No pidfd on this kernel: never a session.
        assert_eq!(
            judge(&facts(61001, unit1, Liveness::Unknown), live()),
            Judgement::Plain
        );
        // A gone process: refused, whoever it was.
        for uid in [61001, 1000] {
            assert!(matches!(
                judge(&facts(uid, unit1, Liveness::Gone), live()),
                Judgement::Refused(_)
            ));
        }
        // No cgroup read: plain.
        let mut f = facts(61001, unit1, Liveness::Alive);
        f.cgroup = None;
        assert_eq!(judge(&f, live()), Judgement::Plain);
    }

    struct Accounts(HashMap<&'static str, u32>);
    impl KernelFacts for Accounts {
        fn account_uid(&self, name: &str) -> Result<Option<u32>, String> {
            Ok(self.0.get(name).copied())
        }
        fn peer(&self, _conn: &UnixStream) -> io::Result<PeerFacts> {
            Err(io::Error::other("unused"))
        }
    }

    #[test]
    fn a_registration_names_a_configured_slot_its_own_uid_and_its_own_unit() {
        let policy = SlotPolicy {
            launcher_account: "agent-launch".into(),
            account_prefix: "agent-slot-".into(),
            count: 2,
        };
        let k = Accounts(HashMap::from([
            ("agent-slot-1", 61001),
            ("agent-slot-2", 61002),
            ("agent-slot-3", 61003),
            ("agent-launch", 61900),
        ]));
        let ask = |slot, uid, unit: &str| RegistrationAsked {
            slot,
            uid,
            unit: unit.into(),
        };
        let ok = check_registration(&ask(1, 61001, "agent-session@1.service"), &policy, &k, &[])
            .unwrap();
        assert_eq!(ok.uid, 61001);
        for bad in [
            ask(0, 61001, "agent-session@0.service"),
            ask(3, 61003, "agent-session@3.service"),
            ask(1, 61002, "agent-session@1.service"),
            ask(1, 61001, "agent-session@2.service"),
            ask(1, 61001, "agent-signd.service"),
        ] {
            assert!(
                check_registration(&bad, &policy, &k, &[]).is_err(),
                "{bad:?}"
            );
        }
        // The slot account's uid is a forbidden one.
        assert!(
            check_registration(
                &ask(1, 61001, "agent-session@1.service"),
                &policy,
                &k,
                &[61001]
            )
            .is_err()
        );
        // A slot whose account doesn't exist.
        let none = Accounts(HashMap::new());
        assert!(
            check_registration(
                &ask(1, 61001, "agent-session@1.service"),
                &policy,
                &none,
                &[]
            )
            .is_err()
        );
    }

    #[test]
    fn root_is_found_by_name_and_a_made_up_account_is_not() {
        assert_eq!(uid_by_name("root").unwrap(), Some(0));
        assert_eq!(uid_by_name("no-such-account-agent-sign-x").unwrap(), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn this_process_is_alive_and_in_its_own_cgroup() {
        let (a, _b) = UnixStream::pair().unwrap();
        let f = RealKernel.peer(&a).unwrap();
        // SAFETY: getuid takes no arguments and can't fail.
        assert_eq!(f.uid, unsafe { libc::getuid() });
        assert_eq!(f.process, Liveness::Alive);
        let own = std::fs::read_to_string("/proc/self/cgroup").unwrap();
        assert!(own.lines().any(|l| Some(l) == f.cgroup.as_deref()), "{f:?}");
    }

    /// Not a test: the process `a_peer_that_ended_is_gone` starts, which
    /// connects to the socket it names and ends.
    #[test]
    #[ignore = "a helper process for a_peer_that_ended_is_gone"]
    fn helper_connects_and_ends() {
        if let Some(path) = std::env::var_os("AGENT_SIGN_TEST_CONNECT_TO") {
            std::mem::forget(UnixStream::connect(path).unwrap());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_peer_that_ended_is_gone() {
        use std::os::unix::net::UnixListener;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s");
        let listener = UnixListener::bind(&path).unwrap();
        // Another process connects and ends, and is reaped, before the facts
        // are read: this test program itself, running only the helper below.
        // (Spawned, not forked: a forked copy of this multithreaded test
        // program would hold other tests' descriptors open while it lived.)
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "kernel_facts::tests::helper_connects_and_ends",
                "--ignored",
                "--quiet",
            ])
            .env("AGENT_SIGN_TEST_CONNECT_TO", &path)
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());
        let (conn, _) = listener.accept().unwrap();
        let f = RealKernel.peer(&conn).unwrap();
        assert_eq!(f.process, Liveness::Gone, "{f:?}");
    }
}
