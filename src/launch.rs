//! `agent-sign launch --agent <name> -- <program> [args...]`: the trusted
//! launcher, in one account (decision D4, 31 Oct 2026).
//!
//! Why: an agent's identity must come from whoever started it, never from
//! what the agent's process says (docs/caller-identity.md, path 2). The
//! launcher asks the service for a new session (`LaunchSession`); the service
//! makes the session's id and principal from the name it was given, refuses
//! a reserved or person's name or one that isn't allowed, and hands back the
//! session's channel ([`crate::session`]). The launcher then runs the
//! program with that channel and nothing else that names an identity.
//!
//! What the program gets, on Linux, inside bubblewrap (`bwrap`):
//! - its own PID namespace (and IPC namespace), so it can't see another
//!   session's processes, their environment, descriptors or memory (P4);
//! - `/` read-only. Writable are only its own working copy (the git work
//!   tree of the folder it starts in, and that repository's git folders) and
//!   a private `/tmp`, with `TMPDIR` pointing there; `~/.agent-sign` and
//!   agent-sign's programs stay read-only even inside a working copy. So a
//!   session can't plant a hook in another session's `.git/hooks`, change
//!   another's files, or change agent-sign's config, keys or programs (the
//!   critique's first finding: `--dev-bind / /` left all of it writable);
//! - a private `/dev` and an empty `/run/user/<uid>`, so it can't reach this
//!   account's user services (systemd, D-Bus), which would run programs
//!   outside the sandbox;
//! - the caller's environment without any identity claim
//!   ([`is_identity_claim`]) and without any ssh-agent or gpg-agent variable
//!   ([`is_agent_variable`]), plus `AGENT_SIGN_CHANNEL_FD`;
//! - no way to reach an agent that belongs to a person (fix round 1, F1: a
//!   session once signed as Taylor through his ssh-agent). Four layers, each
//!   enough against the one before it failing: no `SSH_AUTH_SOCK`; the
//!   usual homes of agent sockets (`~/.ssh`, `~/.1password`, `~/.gnupg`)
//!   hidden behind empty folders, as `/run/user/<uid>` is; a seccomp filter
//!   ([`seccomp_filter`]) that refuses creating any Unix-domain socket (so
//!   no path, abstract name or custom location can be connected to; the
//!   session's own channel is a descriptor it already has and needs no new
//!   socket) and `io_uring` (which can create sockets past the filter); and
//!   no inherited descriptor but the channel (everything else the launcher
//!   was given is closed on exec). The cost, said plainly: a program in a
//!   session can't talk over Unix sockets of its own (a local database
//!   socket, a language server on a socket); pipes, TCP and `socketpair`
//!   work;
//!
//! The launcher closes its own copy of the channel once the program has it,
//! makes itself non-dumpable, passes standard input, output, error and the
//! exit status through, and holds its registration with the service open:
//! when the launcher ends, the session ends, and its channel is refused from
//! then on (a program that left a child behind keeps a dead channel).
//!
//! What it can't do in one account, said plainly (D4): a plain process of
//! the same account, outside any sandbox, can still reach into a session
//! (`pidfd_getfd` on its channel, because bwrap's user namespace belongs to
//! the same uid). So `agent-sign verify` calls these signatures "launcher,
//! same account: isolated from other launched sessions, not from other
//! processes of this account". A uid per session (system mode) closes that.
//! Once a system config exists (`/etc/agent-sign/system.toml`), one-account
//! launch is refused, here and by the service, at every launch.
//!
//! On macOS there are no PID namespaces, so there is no launched session to
//! attest: `launch` says so and runs nothing. Agents there get attested
//! commits through approvals (path 1).
//!
//! In system mode (`/etc/agent-sign/system.toml` exists) none of the above
//! runs: `launch` becomes the launcher's client ([`crate::launch_client`]),
//! and the session runs in a slot account of its own, started by
//! `agent-launchd`.
//!
//! Not yet: launching is open to any process of the account, with any
//! allowed name (risk 7 in the build plan); a working copy has no
//! per-agent writable state of its own (an agent's own settings folder in
//! the home folder is read-only in a session).

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::attribution::KNOWN_AGENTS;

/// Where the system config lives. Its existence alone means system mode.
pub const SYSTEM_CONFIG: &str = "/etc/agent-sign/system.toml";

/// The system config's path: [`SYSTEM_CONFIG`], or, in a debug test build
/// only (the `test-authenticator` feature, like `AGENT_SIGN_TEST_ACCOUNTS`),
/// `AGENT_SIGN_TEST_SYSTEM_CONFIG`, because tests can't write `/etc`.
/// `scripts/check-binary-clean.sh` refuses to install a program that
/// contains that name.
#[cfg(feature = "test-authenticator")]
pub fn system_config_path() -> PathBuf {
    std::env::var_os("AGENT_SIGN_TEST_SYSTEM_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(SYSTEM_CONFIG))
}

/// The system config's path: [`SYSTEM_CONFIG`].
#[cfg(not(feature = "test-authenticator"))]
pub fn system_config_path() -> PathBuf {
    PathBuf::from(SYSTEM_CONFIG)
}

/// The system config, if one exists (anything at its path counts, a link
/// or an unreadable file included): then this machine is in system mode,
/// and one-account launch is refused.
pub fn system_config() -> Option<PathBuf> {
    let path = system_config_path();
    path.symlink_metadata().is_ok().then_some(path)
}

/// Why one-account launch is refused when `path` exists.
pub fn system_mode_refusal(path: &Path) -> String {
    format!(
        "one-account launch is refused: a system config exists at {}, so this machine is in \
         system mode, where each session must run under an account of its own; nothing was run",
        path.display()
    )
}

/// The `AGENT_SIGN_*` settings a session keeps: where the service is, the
/// real git, the signing program, and how long to wait for the service.
pub const KEPT_SETTINGS: [&str; 4] = ["SOCKET", "REAL_GIT", "BIN", "CONNECT_WAIT_MS"];

/// Whether the variable `name` claims an identity, so the launcher strips
/// it: every `AGENT_SIGN_*` but [`KEPT_SETTINGS`] (an agent's name or
/// session, `FORCE`, `SESSION`, the wrapper's own mark, an inherited
/// channel), every agent's mark ([`KNOWN_AGENTS`]), Claude Code's session
/// id, and the wrapper's token. Nothing stripped could change who signs
/// anyway (the channel decides), but none of it should reach a session
/// that would be misled by it.
pub fn is_identity_claim(name: &str) -> bool {
    if let Some(setting) = name.strip_prefix(crate::paths::ENV_PREFIX) {
        return !KEPT_SETTINGS.contains(&setting);
    }
    KNOWN_AGENTS.iter().any(|(mark, _)| *mark == name)
        || name == "CLAUDE_CODE_SESSION_ID"
        || name == crate::ssh_sign::EVENT_TOKEN_VAR
}

/// Whether the variable `name` points at an agent that holds someone's
/// keys: an ssh-agent or a gpg-agent. A session never gets one.
pub fn is_agent_variable(name: &str) -> bool {
    matches!(name, "SSH_AUTH_SOCK" | "SSH_AGENT_PID" | "GPG_AGENT_INFO")
}

/// `vars` without the identity claims ([`is_identity_claim`]) and the agent
/// variables ([`is_agent_variable`]).
pub fn scrubbed_env(
    vars: impl IntoIterator<Item = (OsString, OsString)>,
) -> Vec<(OsString, OsString)> {
    vars.into_iter()
        .filter(|(k, _)| {
            k.to_str()
                .is_some_and(|k| !is_identity_claim(k) && !is_agent_variable(k))
        })
        .collect()
}

/// One classic-BPF instruction (`struct sock_filter`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BpfInsn {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

/// The seccomp filter every session runs under (the module documentation,
/// third layer): `socket(AF_UNIX, ...)` fails with `EAFNOSUPPORT`, the
/// `io_uring` calls and the x32 system-call range fail with `EPERM`, a call
/// from another architecture than this build's fails with `EPERM`; all else
/// is allowed. `socketpair` is allowed: it makes two already-connected ends
/// and connects to nothing outside. None of this reads a path, which a
/// filter can't safely do. Empty on an architecture this isn't written for,
/// and the launcher then refuses to start a session.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub fn seccomp_filter() -> Vec<BpfInsn> {
    #[cfg(target_arch = "x86_64")]
    const ARCH: u32 = 0xC000_003E; // AUDIT_ARCH_X86_64
    #[cfg(target_arch = "aarch64")]
    const ARCH: u32 = 0xC000_00B7; // AUDIT_ARCH_AARCH64
    const LD_W_ABS: u16 = 0x20;
    const JEQ_K: u16 = 0x15;
    const JGE_K: u16 = 0x35;
    const RET_K: u16 = 0x06;
    const ALLOW: u32 = 0x7fff_0000;
    const ERRNO: u32 = 0x0005_0000;
    let i = |code, jt, jf, k| BpfInsn { code, jt, jf, k };
    vec![
        i(LD_W_ABS, 0, 0, 4),                               // 0 architecture
        i(JEQ_K, 1, 0, ARCH),                               // 1
        i(RET_K, 0, 0, ERRNO | libc::EPERM as u32),         // 2 another architecture
        i(LD_W_ABS, 0, 0, 0),                               // 3 system call number
        i(JGE_K, 5, 0, 0x4000_0000),                        // 4 x32 range -> 10
        i(JEQ_K, 4, 0, libc::SYS_io_uring_setup as u32),    // 5 -> 10
        i(JEQ_K, 3, 0, libc::SYS_io_uring_enter as u32),    // 6 -> 10
        i(JEQ_K, 2, 0, libc::SYS_io_uring_register as u32), // 7 -> 10
        i(JEQ_K, 2, 0, libc::SYS_socket as u32),            // 8 -> 11
        i(RET_K, 0, 0, ALLOW),                              // 9
        i(RET_K, 0, 0, ERRNO | libc::EPERM as u32),         // 10 refused
        i(LD_W_ABS, 0, 0, 16),                              // 11 socket's domain
        i(JEQ_K, 1, 0, libc::AF_UNIX as u32),               // 12 -> 14
        i(RET_K, 0, 0, ALLOW),                              // 13
        i(RET_K, 0, 0, ERRNO | libc::EAFNOSUPPORT as u32),  // 14
    ]
}

/// See the other [`seccomp_filter`]: no filter is written for this
/// architecture.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub fn seccomp_filter() -> Vec<BpfInsn> {
    Vec::new()
}

/// The filter as the bytes bubblewrap's `--seccomp` reads (the kernel's
/// `struct sock_filter` array, native byte order).
pub fn seccomp_bytes(filter: &[BpfInsn]) -> Vec<u8> {
    let mut out = Vec::with_capacity(filter.len() * 8);
    for f in filter {
        out.extend_from_slice(&f.code.to_ne_bytes());
        out.push(f.jt);
        out.push(f.jf);
        out.extend_from_slice(&f.k.to_ne_bytes());
    }
    out
}

/// The places agent sockets and agent-held keys usually live inside a home
/// folder: hidden from a session behind empty folders.
pub const AGENT_HOMES: [&str; 3] = [".ssh", ".1password", ".gnupg"];

/// What the sandbox gives a session (see the module documentation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sandbox {
    /// Where the program starts.
    pub cwd: PathBuf,
    /// The session's own working copy: read-write.
    pub writable: Vec<PathBuf>,
    /// Inside a writable path, kept read-only anyway: agent-sign's state
    /// and programs.
    pub read_only: Vec<PathBuf>,
    /// Hidden behind an empty folder: this account's user services.
    pub masked: Vec<PathBuf>,
    /// Whether the program gets a session of its own (no controlling
    /// terminal): when standard input isn't a terminal. With a terminal it
    /// keeps the terminal, so an interactive agent works as it would.
    pub new_session: bool,
}

/// bwrap's arguments for `sandbox`, then `--` and the program and its
/// arguments. Later mounts win, so `/` read-only comes first, then the
/// private `/dev`, `/proc` and `/tmp`, then the writable working copy, then
/// what stays read-only inside it.
pub fn bwrap_args(sandbox: &Sandbox, program: &OsStr, args: &[OsString]) -> Vec<OsString> {
    bwrap_args_with(sandbox, None, program, args)
}

/// [`bwrap_args`], and when `seccomp_fd` is given, bubblewrap loads the
/// filter read from that descriptor ([`seccomp_filter`]) before it starts
/// the program.
pub fn bwrap_args_with(
    sandbox: &Sandbox,
    seccomp_fd: Option<i32>,
    program: &OsStr,
    args: &[OsString],
) -> Vec<OsString> {
    let mut out: Vec<OsString> = Vec::new();
    if let Some(fd) = seccomp_fd {
        out.push("--seccomp".into());
        out.push(fd.to_string().into());
    }
    let mut push = |items: &[&OsStr]| out.extend(items.iter().map(|s| s.to_os_string()));
    push(&[
        OsStr::new("--die-with-parent"),
        OsStr::new("--unshare-pid"),
        OsStr::new("--unshare-ipc"),
    ]);
    if sandbox.new_session {
        push(&[OsStr::new("--new-session")]);
    }
    push(&[
        OsStr::new("--ro-bind"),
        OsStr::new("/"),
        OsStr::new("/"),
        OsStr::new("--dev"),
        OsStr::new("/dev"),
        OsStr::new("--proc"),
        OsStr::new("/proc"),
        OsStr::new("--tmpfs"),
        OsStr::new("/tmp"),
    ]);
    for masked in &sandbox.masked {
        push(&[OsStr::new("--tmpfs"), masked.as_os_str()]);
    }
    for w in &sandbox.writable {
        push(&[OsStr::new("--bind"), w.as_os_str(), w.as_os_str()]);
    }
    for r in &sandbox.read_only {
        push(&[OsStr::new("--ro-bind"), r.as_os_str(), r.as_os_str()]);
    }
    push(&[
        OsStr::new("--chdir"),
        sandbox.cwd.as_os_str(),
        OsStr::new("--"),
        program,
    ]);
    out.extend(args.iter().cloned());
    out
}

/// Paths in `candidates` that lie inside one of `writable`: the ones that
/// need re-binding read-only (anything outside is read-only already).
pub fn protected_inside(writable: &[PathBuf], candidates: &[PathBuf]) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    for c in candidates {
        if writable.iter().any(|w| c.starts_with(w)) && !out.contains(c) {
            out.push(c.clone());
        }
    }
    out
}

/// Why a working copy can't be made writable, if it can't: when it is the
/// home folder or holds it, or holds agent-sign's state, a session could
/// write everything there (other sessions' working copies included).
pub fn working_copy_refusal(writable: &[PathBuf], home: &Path, state: &Path) -> Option<String> {
    writable.iter().find_map(|w| {
        (home.starts_with(w) || state.starts_with(w)).then(|| {
            format!(
                "the working copy {} holds the home folder or agent-sign's state, so a session \
                 there could write into every other session's working copy; launch from a \
                 repository of its own instead. Nothing was run",
                w.display()
            )
        })
    })
}

/// Runs the launcher (see the module documentation) and returns its exit
/// status: the program's, or 1 when no session was started.
///
/// In system mode (a system config exists) the session never runs in this
/// account: the request goes to the launcher, which runs it in a slot
/// account of its own ([`crate::launch_client`]).
#[cfg(target_os = "linux")]
pub fn run(agent: &str, program: &OsStr, args: &[OsString]) -> ExitCode {
    run_with_identity(agent, None, program, args)
}

/// [`run`], and when `identity` is given (`agent:<name>`), the session also
/// signs acts as that identity ([`crate::acts`]). The identity is checked
/// here before anything starts, and again by the service. System mode takes
/// none: there the launcher, not the caller, would have to decide it, and
/// that is not built.
#[cfg(target_os = "linux")]
pub fn run_with_identity(
    agent: &str,
    identity: Option<&str>,
    program: &OsStr,
    args: &[OsString],
) -> ExitCode {
    if let Some(identity) = identity
        && let Err(why) = crate::acts::check_agent_identity(identity)
    {
        eprintln!("agent-sign launch: {why}; nothing was run");
        return ExitCode::from(1);
    }
    if let Some(path) = system_config() {
        if identity.is_some() {
            eprintln!(
                "agent-sign launch: --identity is not available in system mode ({} exists): the \
                 launcher, not the caller, must decide a session's act identity, and that is not \
                 built; nothing was run",
                path.display()
            );
            return ExitCode::from(1);
        }
        return crate::launch_client::run(&path, agent, program, args);
    }
    match linux::run(agent, identity, program, args) {
        Ok(code) => code,
        Err(why) => {
            eprintln!("agent-sign launch: {why}");
            ExitCode::from(1)
        }
    }
}

/// Off Linux there are no PID namespaces, so no session could be kept apart
/// from other processes: nothing is run, and nothing pretends otherwise.
#[cfg(not(target_os = "linux"))]
pub fn run(agent: &str, program: &OsStr, args: &[OsString]) -> ExitCode {
    run_with_identity(agent, None, program, args)
}

/// See the Linux [`run_with_identity`]: off Linux nothing is run.
#[cfg(not(target_os = "linux"))]
pub fn run_with_identity(
    _agent: &str,
    _identity: Option<&str>,
    _program: &OsStr,
    _args: &[OsString],
) -> ExitCode {
    eprintln!(
        "agent-sign launch: no attested session on this system: it has no PID namespaces, so \
         agent-sign can't keep a launched session apart from other processes. Nothing was run. \
         Agents here get attested commits through approvals (docs/caller-identity.md, path 1)"
    );
    ExitCode::from(1)
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::io::{IsTerminal, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::process::ExitStatusExt;
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

    use crate::protocol::{Request, Response};

    /// The child signals are forwarded to, once it runs.
    static CHILD: AtomicI32 = AtomicI32::new(0);
    /// Whether interrupt and quit are forwarded too: only when the child has
    /// no terminal (a terminal sends them to the child itself).
    static FORWARD_INTERRUPT: AtomicBool = AtomicBool::new(false);

    extern "C" fn forward(sig: libc::c_int) {
        if (sig == libc::SIGINT || sig == libc::SIGQUIT)
            && !FORWARD_INTERRUPT.load(Ordering::SeqCst)
        {
            return;
        }
        let pid = CHILD.load(Ordering::SeqCst);
        if pid > 0 {
            // SAFETY: kill is async-signal-safe.
            unsafe {
                libc::kill(pid, sig);
            }
        }
    }

    fn find_bwrap() -> Option<PathBuf> {
        ["/usr/bin/bwrap", "/usr/local/bin/bwrap", "/bin/bwrap"]
            .into_iter()
            .map(PathBuf::from)
            .find(|p| p.is_file())
            .or_else(|| crate::paths::find_on_path_outside_agent_sign("bwrap"))
    }

    /// The working copy of `cwd`: its git work tree, its git folder and the
    /// repository's common git folder (a worktree's lives elsewhere), as
    /// absolute, resolved paths, without any inside another. Empty when
    /// `cwd` isn't in a work tree.
    fn working_copy(cwd: &Path) -> Vec<PathBuf> {
        let out = Command::new(crate::paths::real_git())
            .args([
                "rev-parse",
                "--show-toplevel",
                "--absolute-git-dir",
                "--git-common-dir",
            ])
            .current_dir(cwd)
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output();
        let Ok(out) = out else {
            return Vec::new();
        };
        if !out.status.success() {
            return Vec::new();
        }
        let mut paths: Vec<PathBuf> = Vec::new();
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            let path = cwd.join(line.trim());
            if let Ok(path) = path.canonicalize()
                && !paths.contains(&path)
            {
                paths.push(path);
            }
        }
        let all = paths.clone();
        paths.retain(|p| !all.iter().any(|q| q != p && p.starts_with(q)));
        paths
    }

    /// Asks the service for a session for `agent`: its principal, and the
    /// channel, attached to the answer; plus the registration connection,
    /// which must stay open for the session's life.
    fn start_session(
        agent: &str,
        identity: Option<&str>,
    ) -> Result<(String, std::os::fd::OwnedFd, std::os::unix::net::UnixStream), String> {
        let socket = crate::protocol::client_socket_path();
        let mut reg = crate::protocol::connect_waiting(&socket, crate::protocol::connect_wait())
            .map_err(|e| {
                format!(
                    "the agent-sign service at {} didn't answer ({e}); nothing was run",
                    socket.display()
                )
            })?;
        let req = match identity {
            Some(identity) => serde_json::to_string(&Request::LaunchActSession {
                agent: agent.to_string(),
                identity: identity.to_string(),
            }),
            None => serde_json::to_string(&Request::LaunchSession {
                agent: agent.to_string(),
            }),
        }
        .map_err(|e| e.to_string())?;
        reg.write_all(format!("{req}\n").as_bytes())
            .map_err(|e| format!("couldn't ask the service for a session ({e})"))?;
        let (line, fd) = crate::session::read_line_with_fd(&reg)
            .map_err(|e| format!("the service's answer didn't arrive ({e})"))?;
        match serde_json::from_str::<Response>(&line) {
            Ok(Response::SessionStarted { principal, .. }) => {
                let fd = fd.ok_or("the service started a session but sent no channel")?;
                Ok((principal, fd, reg))
            }
            Ok(Response::Error { message }) => Err(format!(
                "the agent-sign service refused the session: {message}. Nothing was run"
            )),
            Ok(other) => Err(format!("unexpected answer from the service: {other:?}")),
            Err(e) => Err(format!("unreadable answer from the service ({e}): {line}")),
        }
    }

    /// Marks every descriptor from 3 up that this process has open as
    /// close-on-exec, so nothing the caller inherited reaches a program
    /// started from here. (Standard input, output and error are the
    /// session's own and pass through.)
    fn close_inherited_on_exec() {
        let Ok(dir) = std::fs::read_dir("/proc/self/fd") else {
            return;
        };
        let fds: Vec<i32> = dir
            .flatten()
            .filter_map(|e| e.file_name().to_str().and_then(|n| n.parse().ok()))
            .filter(|fd| *fd >= 3)
            .collect();
        for fd in fds {
            // SAFETY: fcntl on a number that may or may not be open (the
            // directory's own descriptor is gone by now); failure is fine.
            unsafe {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags >= 0 {
                    libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC);
                }
            }
        }
    }

    /// A pipe already holding `bytes`, closed for writing, whose read end
    /// is inheritable: bubblewrap reads its seccomp program from it.
    fn filter_pipe(bytes: &[u8]) -> std::io::Result<std::os::fd::OwnedFd> {
        use std::os::fd::FromRawFd;
        let mut fds = [0i32; 2];
        // SAFETY: pipe2 writes two descriptors into the array.
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: both are fresh descriptors this function owns.
        let (read, write) = unsafe {
            (
                std::os::fd::OwnedFd::from_raw_fd(fds[0]),
                std::fs::File::from_raw_fd(fds[1]),
            )
        };
        let mut write = write;
        write.write_all(bytes)?;
        drop(write);
        crate::session::clear_cloexec(read.as_raw_fd())?;
        Ok(read)
    }

    pub(super) fn run(
        agent: &str,
        identity: Option<&str>,
        program: &OsStr,
        args: &[OsString],
    ) -> Result<ExitCode, String> {
        // Before anything is held: nothing of this account outside a session
        // may take the registration or the channel out of this process.
        // SAFETY: prctl with these arguments only changes this process's
        // dumpable flag.
        unsafe {
            libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        }
        // Whatever descriptors the caller left open (an ssh-agent
        // connection, say) stay out of the session: only the channel and
        // the sandbox's own filter, both opened below, are passed on.
        close_inherited_on_exec();
        if let Some(path) = system_config() {
            return Err(system_mode_refusal(&path));
        }
        let bwrap = find_bwrap().ok_or(
            "bubblewrap (bwrap) isn't installed, and a session never runs without its sandbox; \
             install bubblewrap. Nothing was run",
        )?;
        let cwd = std::env::current_dir().map_err(|e| format!("no current folder ({e})"))?;
        let cwd = cwd.canonicalize().unwrap_or(cwd);
        let writable = working_copy(&cwd);
        let home = crate::paths::home_dir();
        let home = home.canonicalize().unwrap_or(home);
        let state = crate::paths::state_dir_in(&home);
        if let Some(why) = working_copy_refusal(&writable, &home, &state) {
            return Err(why);
        }
        let mut keep_read_only = vec![state.clone(), state.join("bin")];
        for exe in [
            std::env::current_exe().ok(),
            crate::paths::env_var("BIN").map(PathBuf::from),
        ]
        .into_iter()
        .flatten()
        {
            if let Some(dir) = exe
                .canonicalize()
                .ok()
                .and_then(|e| e.parent().map(Path::to_path_buf))
            {
                keep_read_only.push(dir);
            }
        }
        keep_read_only.retain(|p| p.exists());
        // SAFETY: getuid takes no arguments and can't fail.
        let uid = unsafe { libc::getuid() };
        let mut masked: Vec<PathBuf> = [PathBuf::from(format!("/run/user/{uid}"))]
            .into_iter()
            .filter(|p| p.is_dir())
            .collect();
        for name in AGENT_HOMES {
            let p = home.join(name);
            if p.is_dir() && !writable.iter().any(|w| w.starts_with(&p)) {
                masked.push(p);
            }
        }
        let interactive = std::io::stdin().is_terminal();
        let sandbox = Sandbox {
            cwd: cwd.clone(),
            read_only: protected_inside(&writable, &keep_read_only),
            writable,
            masked,
            new_session: !interactive,
        };

        let (principal, channel, _registration) = start_session(agent, identity)?;
        crate::session::clear_cloexec(channel.as_raw_fd())
            .map_err(|e| format!("couldn't hand the session its channel ({e})"))?;
        let mut env = scrubbed_env(std::env::vars_os());
        env.retain(|(k, _)| k != "TMPDIR");
        env.push(("TMPDIR".into(), "/tmp".into()));
        env.push((
            crate::session::channel_fd_var().into(),
            channel.as_raw_fd().to_string().into(),
        ));
        eprintln!(
            "[agent-sign launch] session {principal}: launcher, same account: isolated from other \
             launched sessions, not from other processes of this account"
        );
        FORWARD_INTERRUPT.store(!interactive, Ordering::SeqCst);
        for sig in [libc::SIGTERM, libc::SIGHUP, libc::SIGINT, libc::SIGQUIT] {
            // SAFETY: `forward` only reads atomics and calls kill, which are
            // async-signal-safe. A handler (unlike "ignore") is reset to the
            // default in the child when it starts.
            unsafe {
                libc::signal(sig, forward as *const () as libc::sighandler_t);
            }
        }
        let filter = seccomp_filter();
        if filter.is_empty() {
            return Err(
                "no seccomp filter is written for this architecture, and a session never runs \
                 without one. Nothing was run"
                    .into(),
            );
        }
        let filter_fd = filter_pipe(&seccomp_bytes(&filter))
            .map_err(|e| format!("couldn't hand the sandbox its filter ({e})"))?;
        let mut child = Command::new(&bwrap)
            .args(bwrap_args_with(
                &sandbox,
                Some(filter_fd.as_raw_fd()),
                program,
                args,
            ))
            .env_clear()
            .envs(env)
            .spawn()
            .map_err(|e| format!("couldn't start bwrap at {} ({e})", bwrap.display()))?;
        CHILD.store(child.id() as i32, Ordering::SeqCst);
        // The session has its copy; this one closes now.
        drop(channel);
        drop(filter_fd);
        let status = child
            .wait()
            .map_err(|e| format!("lost the session's program ({e})"))?;
        let code = status
            .code()
            .or_else(|| status.signal().map(|s| 128 + s))
            .unwrap_or(1);
        Ok(ExitCode::from(code.clamp(0, 255) as u8))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_claims_are_stripped_and_the_settings_kept() {
        for claim in [
            "AGENT_SIGN_AGENT_NAME",
            "AGENT_SIGN_SESSION_ID",
            "AGENT_SIGN_SESSION",
            "AGENT_SIGN_FORCE",
            "AGENT_SIGN_CHANNEL_FD",
            "AGENT_SIGN_AGENT_RUN",
            "AGENT_SIGN_TEST_AUTH",
            "CLAUDECODE",
            "CLAUDE_CODE_SESSION_ID",
            "CODEX_SESSION_ID",
            "CODEX_THREAD_ID",
            "GEMINI_CLI",
            "AGENT_EVENT_TOKEN",
        ] {
            assert!(is_identity_claim(claim), "{claim}");
        }
        for kept in [
            "AGENT_SIGN_SOCKET",
            "AGENT_SIGN_REAL_GIT",
            "AGENT_SIGN_BIN",
            "AGENT_SIGN_CONNECT_WAIT_MS",
            "HOME",
            "PATH",
            "TMPDIR",
        ] {
            assert!(!is_identity_claim(kept), "{kept}");
        }
    }

    #[test]
    fn agent_variables_are_stripped() {
        for v in ["SSH_AUTH_SOCK", "SSH_AGENT_PID", "GPG_AGENT_INFO"] {
            assert!(is_agent_variable(v), "{v}");
        }
        let kept = scrubbed_env([
            ("SSH_AUTH_SOCK".into(), "/x".into()),
            ("HOME".into(), "/h".into()),
        ]);
        assert_eq!(kept, vec![(OsString::from("HOME"), OsString::from("/h"))]);
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn the_seccomp_filter_is_well_formed_and_every_jump_lands_inside_it() {
        let f = seccomp_filter();
        assert_eq!(seccomp_bytes(&f).len(), f.len() * 8);
        for (i, insn) in f.iter().enumerate() {
            if insn.code & 0x07 == 0x05 {
                assert!(i + 1 + (insn.jt as usize) < f.len(), "jt at {i}");
                assert!(i + 1 + (insn.jf as usize) < f.len(), "jf at {i}");
            }
        }
        assert_eq!(f.last().map(|i| i.code), Some(0x06));
    }

    #[test]
    fn the_sandbox_is_read_only_but_for_the_working_copy_and_a_private_tmp() {
        let sandbox = Sandbox {
            cwd: "/w/repo".into(),
            writable: vec!["/w/repo".into()],
            read_only: vec!["/w/repo/target".into()],
            masked: vec!["/run/user/1000".into()],
            new_session: true,
        };
        let args: Vec<String> = bwrap_args(&sandbox, OsStr::new("/bin/sh"), &["-c".into()])
            .into_iter()
            .map(|a| a.into_string().unwrap())
            .collect();
        let joined = args.join(" ");
        assert!(joined.starts_with("--die-with-parent --unshare-pid --unshare-ipc --new-session --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp"));
        assert!(!joined.contains("--dev-bind"), "{joined}");
        let bind = joined.find("--bind /w/repo /w/repo").unwrap();
        let ro = joined.find("--ro-bind /w/repo/target").unwrap();
        assert!(
            bind < ro,
            "what stays read-only is bound after the working copy"
        );
        assert!(joined.contains("--tmpfs /run/user/1000"));
        assert!(joined.ends_with("--chdir /w/repo -- /bin/sh -c"));
    }

    #[test]
    fn a_working_copy_holding_the_home_or_the_state_is_refused() {
        let home = Path::new("/home/a");
        let state = Path::new("/home/a/.agent-sign");
        assert!(working_copy_refusal(&["/home/a".into()], home, state).is_some());
        assert!(working_copy_refusal(&["/home".into()], home, state).is_some());
        assert!(working_copy_refusal(&["/home/a/repo".into()], home, state).is_none());
        assert_eq!(
            protected_inside(
                &["/home/a/repo".into()],
                &[
                    "/home/a/.agent-sign".into(),
                    "/home/a/repo/target/debug".into()
                ]
            ),
            vec![PathBuf::from("/home/a/repo/target/debug")]
        );
    }
}
