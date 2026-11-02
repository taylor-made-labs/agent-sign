//! A test's agent-signd dies with the test that started it.
//!
//! Most tests start a real agent-signd and stop it when the test ends. A
//! test run that is killed (a timeout, an agent's session ending, SIGKILL)
//! never runs that cleanup, and the daemons were left running, each holding a
//! socket and a folder in the temporary directory; they piled up on the
//! shared server (security review fix round, 31 Oct 2026, L6).
//! `scripts/check-test-daemons-die.sh` is the check.
//!
//! On Linux, [`DieWithParent::die_with_parent`] asks the kernel to send the
//! child SIGKILL when its parent dies (`PR_SET_PDEATHSIG`), set in the child
//! between fork and exec, and then checks that the parent is still the one
//! that forked it: a parent that died before the request was made would never
//! signal it, so the child exits instead of running on.
//!
//! The kernel sends the signal when the *thread* that spawned the child ends,
//! not the process. Every test here spawns its daemon on the test's own thread
//! (the harness runs each test on one thread, which lives as long as the
//! test), and none shares a daemon across tests, so a daemon never dies
//! before its test is done. A daemon shared across tests must not be spawned
//! from a short-lived thread.
//!
//! This is for tests only: the service itself never sets it (an installed
//! service outlives whatever started it).
//!
//! Elsewhere (macOS) there is no such request, and this does nothing. (The
//! per-test ssh agent in `support/key_agent.rs` has a parent-pid watchdog
//! instead, because its leftovers held a key in memory.)
//!
//! Included by each test file that starts agent-signd, with
//! `#[path = "support/die_with_parent.rs"] mod die_with_parent;`.

use std::process::Command;

/// See the module header.
pub trait DieWithParent {
    /// On Linux, makes the child this command spawns die with SIGKILL when
    /// the spawning thread ends; does nothing elsewhere.
    fn die_with_parent(&mut self) -> &mut Self;
}

impl DieWithParent for Command {
    #[cfg(target_os = "linux")]
    fn die_with_parent(&mut self) -> &mut Self {
        use std::os::unix::process::CommandExt;
        // SAFETY: getpid takes no arguments and can't fail.
        let parent = unsafe { libc::getpid() };
        // SAFETY: the closure runs in the child between fork and exec and
        // calls only async-signal-safe functions (prctl, getppid, _exit).
        unsafe {
            self.pre_exec(move || {
                let signal = libc::SIGKILL as libc::c_ulong;
                let unused: libc::c_ulong = 0;
                if libc::prctl(libc::PR_SET_PDEATHSIG, signal, unused, unused, unused) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                // The parent may have died before the request was made.
                if libc::getppid() != parent {
                    libc::_exit(1);
                }
                Ok(())
            })
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn die_with_parent(&mut self) -> &mut Self {
        self
    }
}
