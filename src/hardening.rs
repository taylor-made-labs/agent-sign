//! Keeping agent-signd's memory to itself.
//!
//! agent-signd holds the agents' certificate authority and every agent
//! session's signing key in its memory, and nowhere else: no private key is
//! ever written to a file. So its memory is the one place those keys can be
//! taken from, and [`protect_process_memory`] closes the ordinary ways in. It
//! runs before any private key exists (before the service makes its
//! authority) and fails closed: if a step can't be done, the service doesn't
//! start, rather than run with keys that other programs can read.
//!
//! **Core dumps (every OS).** A crash would otherwise write the whole memory,
//! keys included, to a core file (the Pi's `core_pattern` is plain `core`, a
//! file in the working directory). [`disable_core_dumps`] sets both core
//! limits to 0, so no core file is written and the process can't raise the
//! limit again. A host dump handler that ignores the limit (a piped
//! `core_pattern`) is covered on Linux by the next step: the kernel doesn't
//! dump a non-dumpable process at all while `fs.suid_dumpable` is 0, its
//! default.
//!
//! **Other programs of the same account (Linux).** Every agent runs as the
//! same user as agent-signd. On Linux, a process of the same user can read
//! another's memory through `/proc/<pid>/mem`, or attach to it with `ptrace`
//! (and so with a debugger), unless something stands in the way:
//! - Yama's `ptrace_scope = 1` (hetzner's setting) still lets a process read
//!   its descendants, so whatever started agent-signd can read it;
//! - a kernel without Yama (the Pi's) lets any process of the user read it.
//!
//! [`deny_memory_reads`] marks the process non-dumpable
//! (`prctl(PR_SET_DUMPABLE, 0)`). For a non-dumpable process the kernel
//! refuses `ptrace` and `/proc/<pid>/mem` (and makes the files in
//! `/proc/<pid>` belong to root) to every process without `CAP_SYS_PTRACE`,
//! parents included, whatever the Yama setting. The flag is read back with
//! `PR_GET_DUMPABLE`, so "set" is never assumed. `tests/test_memory_guard.rs`
//! checks it from outside, with an unprotected program as the control.
//!
//! **What this doesn't stop.** root, or anything with `CAP_SYS_PTRACE`; swap
//! (neither of Taylor's servers has swap today; the Pi's zram is memory); and
//! anything that can replace the agent-signd program or its service
//! environment before it starts, which in an account shared with agents any
//! agent can do (the README's accepted gap, closed by running agent-sign as
//! its own account).
//!
//! **macOS.** agent-sign adds nothing of its own there yet beyond the core
//! limits. What stands in the way today is the system's own rule: reading
//! another process's memory needs its task port (`task_for_pid`), which the
//! system gives only to root, or to a program signed with the debugger
//! entitlement once an administrator has approved it (or the user has
//! Developer Tools access turned on). The service runs from an ad hoc signed
//! bundle without the hardened runtime, so such a debugger can attach. None
//! of this is checked by agent-sign's tests, and nothing here relies on a
//! macOS mechanism that isn't (such as `PT_DENY_ATTACH`), so
//! [`deny_memory_reads`] does nothing on macOS rather than claim protection
//! it can't show.

use std::io;

/// Sets both core file limits to 0: a crash writes no core file holding keys.
pub fn disable_core_dumps() -> io::Result<()> {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: setrlimit reads a correctly initialized rlimit for this process.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Linux: makes this process non-dumpable, so no other program of the same
/// user (its parent included) can read its memory or attach to it, and checks
/// that the flag took. See the module header for why.
#[cfg(target_os = "linux")]
pub fn deny_memory_reads() -> io::Result<()> {
    let off: libc::c_ulong = 0;
    let unused: libc::c_ulong = 0;
    // SAFETY: PR_SET_DUMPABLE takes one integer argument and changes only
    // this process's own dumpable flag; the other arguments are ignored.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, off, unused, unused, unused) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: PR_GET_DUMPABLE reads this process's flag and takes no pointer.
    let now = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, unused, unused, unused, unused) };
    if now != 0 {
        return Err(io::Error::other(format!(
            "the process is still dumpable after PR_SET_DUMPABLE 0 (PR_GET_DUMPABLE says {now})"
        )));
    }
    Ok(())
}

/// Not Linux: nothing of agent-sign's own yet (see "macOS" in the module
/// header for what protects the memory there).
#[cfg(not(target_os = "linux"))]
pub fn deny_memory_reads() -> io::Result<()> {
    Ok(())
}

/// Both steps above, before any private key exists. An error means the
/// memory isn't protected, and the service must not start.
pub fn protect_process_memory() -> io::Result<()> {
    disable_core_dumps()
        .map_err(|e| io::Error::new(e.kind(), format!("couldn't turn off core dumps: {e}")))?;
    deny_memory_reads().map_err(|e| {
        io::Error::new(
            e.kind(),
            format!(
                "couldn't keep other programs from reading agent-signd's memory \
                 (PR_SET_DUMPABLE 0): {e}; not starting, so no key is made"
            ),
        )
    })?;
    Ok(())
}
