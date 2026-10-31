//! Memory guard (Linux): another program of the same user can't read the
//! memory of agent-signd, where the agents' certificate authority and every
//! agent's signing key live.
//!
//! Serves plan check 5 ("Memory: on both machines (2 of 2), another program in
//! the account can't read agent-sign's memory. The same read must work against
//! an unprotected test program, so the check can fail") and interface item 4:
//! agent-signd makes itself non-dumpable (`PR_SET_DUMPABLE` 0) before any
//! private key exists. For a non-dumpable process the kernel refuses
//! `/proc/<pid>/mem` (and `/proc/<pid>/maps`) to everything without
//! `CAP_SYS_PTRACE`, with EACCES, even to a process of the same user and even
//! to the process's parent.
//!
//! Why the two machines differ, and why this test must pass on both: hetzner
//! has Yama `ptrace_scope=1` (only a descendant may read, which still lets a
//! parent read its child), the Pi has no Yama (any process of the user may).
//! Today neither machine protects agent-signd from its own parent, which is
//! what this test is: the test process is the daemon's parent.
//!
//! The probe: [`read_some_memory`] opens `/proc/<pid>/maps`, picks a mapped,
//! readable address and reads 16 bytes of it through `/proc/<pid>/mem`. A
//! non-dumpable process blocks either step, so either failure with EACCES or
//! EPERM counts as protected. Anything else (ENOENT, ESRCH, a process that
//! already exited) is not protection and fails the test, so a daemon that
//! crashed can't pass it.
//!
//! The control in the same test starts an ordinary `sleep` the same way and
//! requires the same probe to succeed on it, so the probe is shown to be able
//! to fail (check 5's "same read must work against an unprotected test
//! program"). If the control can't be read (a machine with
//! `ptrace_scope=2`, say) the test fails with a message saying so rather than
//! passing without having tested anything.
//!
//! Isolation: the daemon runs from an empty environment, a temporary HOME and
//! a temporary socket. Nothing here touches a real `~/.agent-sign`, a real
//! service or real signing, and nothing is spawned in a loop.

#![cfg(target_os = "linux")]

use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use tempfile::{TempDir, tempdir};

const EPERM: i32 = 1;
const EACCES: i32 = 13;

/// Kills and reaps the child when dropped, so a failed assertion leaves no
/// process behind.
struct Guard(Child);

impl Guard {
    fn pid(&self) -> u32 {
        self.0.id()
    }

    fn running(&mut self) -> bool {
        self.0.try_wait().unwrap().is_none()
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A running agent-signd in a temporary HOME.
struct Daemon {
    _dir: TempDir,
    log: PathBuf,
    child: Guard,
}

fn start_daemon() -> Daemon {
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    fs::create_dir_all(&home).unwrap();
    let socket = dir.path().join("agent-sign-test.sock");
    let log = dir.path().join("service.log");
    let global_config = home.join("user.gitconfig");
    fs::write(&global_config, "").unwrap();

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_agent-signd"));
    cmd.env_clear();
    for keep in ["TMPDIR", "USER", "LOGNAME", "LANG", "LC_ALL", "PATH"] {
        if let Some(v) = std::env::var_os(keep) {
            cmd.env(keep, v);
        }
    }
    cmd.env("HOME", &home)
        .env("GIT_CONFIG_GLOBAL", &global_config)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("AGENT_SIGN_SOCKET", &socket)
        .env("AGENT_SIGN_TEST_AUTH", "fail")
        .env("AGENT_SIGN_REFUSAL_BACKOFF", "none")
        .arg("--socket")
        .arg(&socket)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(fs::File::create(&log).unwrap()));
    let mut child = Guard(cmd.spawn().unwrap());

    let start = Instant::now();
    while !socket.exists() {
        if !child.running() {
            panic!(
                "agent-signd stopped at start:\n{}",
                fs::read_to_string(&log).unwrap_or_default()
            );
        }
        assert!(
            start.elapsed() < Duration::from_secs(15),
            "agent-signd didn't open its socket in 15 s:\n{}",
            fs::read_to_string(&log).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    Daemon {
        _dir: dir,
        log,
        child,
    }
}

/// An ordinary program that nothing protects: the control.
fn start_unprotected_program() -> Guard {
    let child = Command::new("sleep")
        .arg("120")
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("the control program `sleep` should start");
    Guard(child)
}

/// The address of a mapping the process can be asked to read: the first one
/// that is readable and is not one of the kernel's special areas.
fn readable_address(maps: &str) -> u64 {
    for line in maps.lines() {
        let mut fields = line.split_whitespace();
        let range = fields.next().unwrap_or("");
        let perms = fields.next().unwrap_or("");
        let name = line.split_whitespace().nth(5).unwrap_or("");
        if !perms.starts_with('r') || name == "[vvar]" || name == "[vsyscall]" || name == "[vvar_vclock]" {
            continue;
        }
        if let Some((start, _)) = range.split_once('-') {
            if let Ok(addr) = u64::from_str_radix(start, 16) {
                return addr;
            }
        }
    }
    panic!("no readable mapping in:\n{maps}");
}

/// Tries to read 16 bytes of `pid`'s memory the way a program of the same user
/// would. `Ok(bytes)` means the memory was readable. `Err` carries the error
/// of whichever step was refused.
fn read_some_memory(pid: u32) -> io::Result<usize> {
    let proc = PathBuf::from(format!("/proc/{pid}"));
    let mut maps = String::new();
    fs::File::open(proc.join("maps"))?.read_to_string(&mut maps)?;
    let address = readable_address(&maps);
    let mem = fs::File::open(proc.join("mem"))?;
    let mut buf = [0u8; 16];
    let n = mem.read_at(&mut buf, address)?;
    if n == 0 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "read 0 bytes"));
    }
    Ok(n)
}

fn is_blocked(err: &io::Error) -> bool {
    matches!(err.raw_os_error(), Some(EPERM) | Some(EACCES))
}

fn kernel_setting(path: &str) -> String {
    fs::read_to_string(Path::new(path))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "not present".to_string())
}

/// Plan check 5: the daemon's memory can't be read by its parent (the test),
/// while an unprotected program's can.
///
/// Fails today because nothing makes agent-signd non-dumpable: the probe reads
/// 16 bytes of its memory, so the final assertion reports that the memory was
/// readable (on hetzner despite Yama, since a parent may read its child; on
/// the Pi because it has no Yama).
#[test]
fn another_program_of_the_same_user_cant_read_agent_signds_memory() {
    // The control first, so a machine where the probe can't work at all is
    // reported as such.
    let control = start_unprotected_program();
    let control_read = read_some_memory(control.pid());
    assert!(
        control_read.is_ok(),
        "CONTROL FAILED: the probe can't read an unprotected `sleep` that the test started \
         ({control_read:?}; Yama ptrace_scope = {}). The check can't tell protected from \
         unprotected on this machine, so it proves nothing here.",
        kernel_setting("/proc/sys/kernel/yama/ptrace_scope")
    );

    let mut daemon = start_daemon();
    let pid = daemon.child.pid();
    assert!(
        daemon.child.running(),
        "agent-signd isn't running:\n{}",
        fs::read_to_string(&daemon.log).unwrap_or_default()
    );

    match read_some_memory(pid) {
        Ok(n) => panic!(
            "agent-signd (pid {pid}) is not protected: its parent read {n} bytes of its memory \
             through /proc/{pid}/mem (Yama ptrace_scope = {}). It should have made itself \
             non-dumpable (PR_SET_DUMPABLE 0) before making any key. The control read worked \
             too, so the probe is valid.",
            kernel_setting("/proc/sys/kernel/yama/ptrace_scope")
        ),
        Err(e) => assert!(
            is_blocked(&e),
            "reading agent-signd's memory failed, but not with EACCES or EPERM (so it isn't \
             protection, and the daemon may have died): {e:?}\nlog:\n{}",
            fs::read_to_string(&daemon.log).unwrap_or_default()
        ),
    }
}

/// Plan check 5, second observable: the files inside a non-dumpable process's
/// `/proc/<pid>` (`mem`, `maps`, ...) are owned by root, not by the user,
/// which is how the kernel denies the user those files. (The directory itself
/// stays the user's.) An unprotected program's files belong to the user, so
/// the observation can differ between protected and unprotected.
///
/// Fails today because agent-signd's `/proc/<pid>/mem` is owned by the user
/// (its dumpable flag is still 1).
#[test]
fn agent_signds_proc_files_are_not_owned_by_the_user() {
    let control = start_unprotected_program();
    let me = current_uid();
    let control_owner = fs::metadata(format!("/proc/{}/mem", control.pid()))
        .unwrap()
        .uid();
    assert_eq!(
        control_owner, me,
        "CONTROL FAILED: an unprotected program's /proc/<pid>/mem should belong to the user"
    );

    let daemon = start_daemon();
    let pid = daemon.child.pid();
    let owner = fs::metadata(format!("/proc/{pid}/mem")).unwrap().uid();
    assert_ne!(
        owner, me,
        "/proc/{pid}/mem (agent-signd) belongs to the user (uid {me}): the process is still \
         dumpable, so other programs of the user can read its memory"
    );
}

/// The user's uid, taken from the owner of this test process's own `/proc`
/// entry (no `unsafe` or libc call needed).
fn current_uid() -> u32 {
    fs::metadata("/proc/self").unwrap().uid()
}
