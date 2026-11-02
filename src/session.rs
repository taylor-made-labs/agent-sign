//! Launched sessions: the private channel between a session's processes and
//! the service.
//!
//! Why (docs/caller-identity.md, path 2; build plan step S6): until now the
//! service learned who was asking from what the caller said, an environment
//! variable naming a session or a principal in a socket message, and any
//! process of the account could say anything. A session agent-sign's
//! launcher starts (`agent-sign launch`, [`crate::launch`]) instead gets a
//! channel: one end of a `SOCK_SEQPACKET` socket pair the service made for
//! that session alone, inherited as a file descriptor whose number is in
//! `AGENT_SIGN_CHANNEL_FD`. The service knows which session a request is
//! from by which channel it came in on, never by anything in the request.
//!
//! How a request travels: the client makes a fresh stream socket pair, sends
//! one end over the channel with `SCM_RIGHTS` ([`Channel::open_stream`]), and
//! speaks the usual newline-JSON protocol on the other. So many processes of
//! one session (the wrapper, git, the signing program git starts) can ask at
//! once, each on a stream of its own, and each stream belongs to the
//! session whose channel carried it.
//!
//! What the variable is and isn't: the number alone grants nothing. A process
//! that copies a session's environment (from `/proc/<pid>/environ`, P1) gets
//! a number naming whatever that descriptor is in its own process, usually
//! nothing; [`Channel::from_env`] checks that it really is a sequenced-packet
//! Unix socket whose peer runs as the service's account, and treats anything
//! else as no session.
//!
//! The service side (the registry, the session log, ending a session when
//! the launcher's registration closes) is in `agent-signd`; the pieces it
//! shares with clients, passing descriptors and the [`SessionLog`], are
//! here.

use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use rand::RngCore;

use crate::protocol::{Request, Response};

/// The suffix of the variable that names a launched session's channel
/// descriptor: `AGENT_SIGN_CHANNEL_FD`. Not `AGENT_SIGN_SESSION`, which has
/// long meant "treat this as an agent's command".
pub const CHANNEL_FD_SUFFIX: &str = "CHANNEL_FD";

/// The full name of the channel variable.
pub fn channel_fd_var() -> String {
    format!("{}{CHANNEL_FD_SUFFIX}", crate::paths::ENV_PREFIX)
}

/// The append-only record of launched sessions in the state folder.
pub const SESSION_LOG_FILE: &str = "sessions.log";

/// A new session id: 128 random bits as 32 lowercase hex digits, made by the
/// service, never by a caller.
pub fn new_session_id() -> String {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Sends `data` on the socket `sock` with the descriptor `fd` attached
/// (`SCM_RIGHTS`). The receiver gets its own copy of `fd`; the caller still
/// holds this one and closes it when it's done.
pub fn send_with_fd(sock: RawFd, data: &[u8], fd: RawFd) -> io::Result<()> {
    let fd_size = std::mem::size_of::<RawFd>() as libc::c_uint;
    // SAFETY: CMSG_SPACE only computes a size.
    let space = unsafe { libc::CMSG_SPACE(fd_size) } as usize;
    let mut control = vec![0u8; space];
    let mut iov = libc::iovec {
        iov_base: data.as_ptr() as *mut libc::c_void,
        iov_len: data.len(),
    };
    // SAFETY: an all-zero msghdr is a valid empty one; every pointer set
    // below points into `iov` and `control`, which outlive the call.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = space as _;
    // SAFETY: `control` is CMSG_SPACE(one fd) bytes, so the first header
    // exists and its data holds exactly one descriptor.
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return Err(io::Error::other("no room for the descriptor"));
        }
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(fd_size) as _;
        std::ptr::copy_nonoverlapping(
            &fd as *const RawFd as *const u8,
            libc::CMSG_DATA(cmsg),
            fd_size as usize,
        );
    }
    loop {
        // SAFETY: `msg` is fully set up above. MSG_NOSIGNAL: a closed peer
        // (an ended session) is an error, not a SIGPIPE.
        let sent = unsafe { libc::sendmsg(sock, &msg, send_flags()) };
        if sent >= 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

#[cfg(target_os = "linux")]
fn send_flags() -> libc::c_int {
    libc::MSG_NOSIGNAL
}

#[cfg(not(target_os = "linux"))]
fn send_flags() -> libc::c_int {
    0
}

/// Receives up to `buf.len()` bytes from the socket `sock`, and at most one
/// descriptor sent with them, which arrives close-on-exec. The control
/// buffer has room for exactly one descriptor, so the kernel discards any
/// more a sender attaches instead of installing them here. `(0, None)` is the
/// end of the stream (or of the channel).
pub fn recv_with_fd(sock: RawFd, buf: &mut [u8]) -> io::Result<(usize, Option<OwnedFd>)> {
    let fd_size = std::mem::size_of::<RawFd>() as libc::c_uint;
    // SAFETY: CMSG_SPACE only computes a size.
    let space = unsafe { libc::CMSG_SPACE(fd_size) } as usize;
    let mut control = vec![0u8; space];
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    // SAFETY: as in `send_with_fd`.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = space as _;
    let got = loop {
        // SAFETY: `msg` points into `iov`, `buf` and `control`, all live.
        let got = unsafe { libc::recvmsg(sock, &mut msg, recv_flags()) };
        if got >= 0 {
            break got as usize;
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    };
    let mut received: Option<OwnedFd> = None;
    // SAFETY: the kernel filled `control` up to msg_controllen; the CMSG
    // macros walk only within it.
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                let data = libc::CMSG_DATA(cmsg);
                let header = libc::CMSG_LEN(0) as usize;
                let count = ((*cmsg).cmsg_len as usize).saturating_sub(header) / fd_size as usize;
                for i in 0..count {
                    let mut fd: RawFd = -1;
                    std::ptr::copy_nonoverlapping(
                        data.add(i * fd_size as usize),
                        &mut fd as *mut RawFd as *mut u8,
                        fd_size as usize,
                    );
                    if fd < 0 {
                        continue;
                    }
                    let owned = OwnedFd::from_raw_fd(fd);
                    set_cloexec(owned.as_raw_fd());
                    // Only the first is kept; any other is closed here.
                    if received.is_none() {
                        received = Some(owned);
                    }
                }
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }
    Ok((got, received))
}

#[cfg(target_os = "linux")]
fn recv_flags() -> libc::c_int {
    libc::MSG_CMSG_CLOEXEC
}

#[cfg(not(target_os = "linux"))]
fn recv_flags() -> libc::c_int {
    0
}

fn set_cloexec(fd: RawFd) {
    // SAFETY: fcntl on a descriptor this process owns.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFD);
        if flags >= 0 {
            libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC);
        }
    }
}

/// Clears close-on-exec on `fd`, so a program this process starts inherits
/// it: how the launcher hands a session its channel.
pub fn clear_cloexec(fd: RawFd) -> io::Result<()> {
    // SAFETY: fcntl on a descriptor this process owns.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: as above.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The uid of the process on the other end of the Unix socket `fd`, as the
/// kernel recorded it when the connection (or socket pair) was made.
#[cfg(target_os = "linux")]
pub fn peer_uid(fd: RawFd) -> io::Result<u32> {
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
    Ok(cred.uid)
}

/// Whether the process on the other end of the Unix socket `fd` runs in a
/// PID namespace below this one: inside a sandbox, such as a launched
/// session's. Read from the `NSpid:` line of `/proc/<pid>/status`, which
/// lists the process's id in this namespace and then in each namespace
/// below it, so two or more numbers mean it is in a child namespace. (Not
/// from `/proc/<pid>/ns/pid`: reading that needs ptrace rights over the
/// peer, which a non-dumpable launcher, as the launcher makes itself, does
/// not give.) An error when the peer isn't visible here or its status can't
/// be read: the caller then refuses, it never guesses.
#[cfg(target_os = "linux")]
pub fn peer_in_other_pid_namespace(fd: RawFd) -> io::Result<bool> {
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
    if cred.pid <= 0 {
        return Err(io::Error::other("the peer's process isn't visible here"));
    }
    let status = fs::read_to_string(format!("/proc/{}/status", cred.pid))?;
    nspid_count(&status)
        .map(|count| count > 1)
        .ok_or_else(|| io::Error::other("the peer's status has no NSpid line"))
}

/// How many numbers the `NSpid:` line of a `/proc/<pid>/status` text has.
#[cfg(target_os = "linux")]
fn nspid_count(status: &str) -> Option<usize> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("NSpid:"))
        .map(|rest| rest.split_whitespace().count())
}

/// Off Linux there are no PID namespaces.
#[cfg(not(target_os = "linux"))]
pub fn peer_in_other_pid_namespace(_fd: RawFd) -> io::Result<bool> {
    Ok(false)
}

/// The uid of the process on the other end of the Unix socket `fd`.
#[cfg(not(target_os = "linux"))]
pub fn peer_uid(fd: RawFd) -> io::Result<u32> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: getpeereid writes the two ids.
    if unsafe { libc::getpeereid(fd, &mut uid, &mut gid) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(uid)
}

/// A new `SOCK_SEQPACKET` Unix socket pair, both ends close-on-exec: a
/// session's channel (the service keeps one end, the launcher hands the other
/// to the session). On Linux the pair is made close-on-exec atomically, so a
/// program another thread of the service starts meanwhile (git, for finished
/// work) never inherits it.
pub fn seqpacket_pair() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [-1 as RawFd; 2];
    // SAFETY: socketpair writes two descriptors into `fds`.
    let rc = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | atomic_cloexec(),
            0,
            fds.as_mut_ptr(),
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: both descriptors were just made and are owned by no one else.
    let pair = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    set_cloexec(pair.0.as_raw_fd());
    set_cloexec(pair.1.as_raw_fd());
    Ok(pair)
}

#[cfg(target_os = "linux")]
fn atomic_cloexec() -> libc::c_int {
    libc::SOCK_CLOEXEC
}

#[cfg(not(target_os = "linux"))]
fn atomic_cloexec() -> libc::c_int {
    0
}

/// Integer socket option `name` of `fd`.
#[cfg(target_os = "linux")]
fn socket_option(fd: RawFd, name: libc::c_int) -> io::Result<libc::c_int> {
    let mut value: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: getsockopt writes at most `len` bytes into `value`.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            name,
            &mut value as *mut libc::c_int as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(value)
}

/// A launched session's channel, as a client inside the session sees it.
/// The descriptor is borrowed from the process (it was inherited, and must
/// stay open for git and the signing program git starts), so dropping this
/// never closes it.
#[derive(Debug, Clone, Copy)]
pub struct Channel {
    fd: RawFd,
}

impl Channel {
    /// The session channel this process inherited, if `AGENT_SIGN_CHANNEL_FD`
    /// names one that checks out (see [`Channel::check`]); otherwise `None`:
    /// no session. Only Linux has launched sessions.
    pub fn from_env() -> Option<Channel> {
        let value = crate::paths::env_var(CHANNEL_FD_SUFFIX)?;
        let fd: RawFd = value.trim().parse().ok()?;
        Self::check(fd).ok()
    }

    /// `fd` as a channel, if it is one: past standard input, output and
    /// error, open, an `AF_UNIX` `SOCK_SEQPACKET` socket, and connected to a
    /// process running as the service's account (this account, or the owner
    /// of the service's socket). Anything else, such as a jobserver pipe, a
    /// file, or a connection to the service's main socket, is not a channel.
    #[cfg(target_os = "linux")]
    pub fn check(fd: RawFd) -> Result<Channel, String> {
        if fd < 3 {
            return Err(format!(
                "descriptor {fd} is standard input, output or error"
            ));
        }
        let domain = socket_option(fd, libc::SO_DOMAIN)
            .map_err(|e| format!("descriptor {fd} isn't a socket ({e})"))?;
        let kind = socket_option(fd, libc::SO_TYPE)
            .map_err(|e| format!("descriptor {fd} isn't a socket ({e})"))?;
        if domain != libc::AF_UNIX || kind != libc::SOCK_SEQPACKET {
            return Err(format!(
                "descriptor {fd} isn't a sequenced-packet Unix socket"
            ));
        }
        let peer = peer_uid(fd).map_err(|e| format!("descriptor {fd} has no peer ({e})"))?;
        use std::os::unix::fs::MetadataExt;
        // SAFETY: getuid takes no arguments and can't fail.
        let own = unsafe { libc::getuid() };
        let service_owner = fs::metadata(crate::protocol::client_socket_path())
            .ok()
            .map(|m| m.uid());
        if peer != own && Some(peer) != service_owner {
            return Err(format!(
                "descriptor {fd}'s peer runs as uid {peer}, not as the service's account"
            ));
        }
        Ok(Channel { fd })
    }

    /// No launched sessions off Linux (no PID namespaces; see
    /// [`crate::launch`]), so nothing is a channel.
    #[cfg(not(target_os = "linux"))]
    pub fn check(fd: RawFd) -> Result<Channel, String> {
        Err(format!(
            "descriptor {fd}: launched sessions exist only on Linux"
        ))
    }

    /// The descriptor's number.
    pub fn fd(&self) -> RawFd {
        self.fd
    }

    /// A new private stream to the service over this channel: one end of a
    /// fresh socket pair is sent over the channel, the other returned. Fails
    /// once the session has ended (the service closed its end).
    pub fn open_stream(&self) -> io::Result<UnixStream> {
        let (mine, theirs) = UnixStream::pair()?;
        send_with_fd(self.fd, &[0u8], theirs.as_raw_fd())?;
        drop(theirs);
        Ok(mine)
    }

    /// One request and its answer, on a new stream over this channel.
    pub fn ask(&self, req: &Request) -> Result<Response, Box<dyn std::error::Error>> {
        let stream = self.open_stream().map_err(|e| {
            format!("the launched session's channel to the agent-sign service is closed ({e})")
        })?;
        crate::protocol::request_on(stream, req)
    }
}

/// Reads one newline-terminated line from the stream `sock`, picking up the
/// one descriptor that may come with its first bytes: how the launcher
/// receives the answer to `LaunchSession`, with the channel attached.
pub fn read_line_with_fd(sock: &UnixStream) -> io::Result<(String, Option<OwnedFd>)> {
    let mut line: Vec<u8> = Vec::new();
    let mut fd: Option<OwnedFd> = None;
    let mut buf = [0u8; 4096];
    loop {
        let (n, got) = recv_with_fd(sock.as_raw_fd(), &mut buf)?;
        if got.is_some() && fd.is_none() {
            fd = got;
        }
        if n == 0 {
            break;
        }
        line.extend_from_slice(&buf[..n]);
        if line.contains(&b'\n') || line.len() > 1 << 20 {
            break;
        }
    }
    let end = line.iter().position(|b| *b == b'\n').unwrap_or(line.len());
    Ok((String::from_utf8_lossy(&line[..end]).into_owned(), fd))
}

/// `~/.agent-sign/sessions.log`: one line per session start and end,
/// appended and synced, never rewritten. It is the audit record of which
/// principal each launched session had, as which uid, and when; and how the
/// service, after a restart, still never draws a principal a session has
/// had before.
pub struct SessionLog {
    path: PathBuf,
}

impl SessionLog {
    /// The log in the state folder `state`.
    pub fn in_state(state: &Path) -> Self {
        Self {
            path: state.join(SESSION_LOG_FILE),
        }
    }

    /// Every principal a session has ever had, from the log. A log that
    /// doesn't exist yet is empty; one that can't be read is an error, so
    /// the service doesn't start without knowing which names were used.
    pub fn principals(&self) -> io::Result<Vec<String>> {
        let file = match fs::File::open(&self.path) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let mut out = Vec::new();
        for line in BufReader::new(file).lines() {
            let line = line?;
            let words: Vec<&str> = line.split(' ').collect();
            if let [_, "start", _, principal, ..] = words.as_slice() {
                out.push((*principal).to_string());
            }
        }
        Ok(out)
    }

    /// Appends `<secs> <event> <session> <principal> uid=<uid>` and syncs it
    /// to disk before returning, so a session is on record before it can
    /// sign. The file is made 0600 and never followed through a link.
    pub fn append(&self, event: &str, session: &str, principal: &str, uid: u32) -> io::Result<()> {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&self.path)?;
        writeln!(
            file,
            "{} {event} {session} {principal} uid={uid}",
            crate::agents_ca::now_secs()
        )?;
        file.sync_all()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn session_ids_are_128_random_bits_in_hex() {
        let a = new_session_id();
        let b = new_session_id();
        assert_eq!(a.len(), 32);
        assert!(
            a.bytes()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        assert_ne!(a, b);
    }

    #[test]
    fn the_log_remembers_every_principal_it_started() {
        let dir = tempdir().unwrap();
        let log = SessionLog::in_state(dir.path());
        assert!(log.principals().unwrap().is_empty());
        log.append("start", "s1", "codex.0000000a@agents.local", 1000)
            .unwrap();
        log.append("end", "s1", "codex.0000000a@agents.local", 1000)
            .unwrap();
        log.append("start", "s2", "codex.0000000b@agents.local", 1000)
            .unwrap();
        assert_eq!(
            log.principals().unwrap(),
            vec![
                "codex.0000000a@agents.local".to_string(),
                "codex.0000000b@agents.local".to_string()
            ]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_process_in_a_child_pid_namespace_has_more_than_one_nspid() {
        assert_eq!(nspid_count("Name:\tx\nNSpid:\t42\nNSsid:\t1\n"), Some(1));
        assert_eq!(nspid_count("Name:\tx\nNSpid:\t42\t7\nNSsid:\t1\n"), Some(2));
        assert_eq!(nspid_count("Name:\tx\n"), None);
        // This test process shares its own namespace.
        let (a, _b) = UnixStream::pair().unwrap();
        assert!(!peer_in_other_pid_namespace(a.as_raw_fd()).unwrap());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_descriptor_travels_over_a_channel_and_only_a_channel_counts() {
        let (service, client) = seqpacket_pair().unwrap();
        // A stream pair's end, sent over the channel, arrives as a socket.
        let channel = Channel::check(client.as_raw_fd()).unwrap();
        let mut stream = channel.open_stream().unwrap();
        let mut buf = [0u8; 1];
        let (n, fd) = recv_with_fd(service.as_raw_fd(), &mut buf).unwrap();
        assert_eq!(n, 1);
        let mut theirs = UnixStream::from(fd.expect("a descriptor came with the message"));
        stream.write_all(b"hello\n").unwrap();
        let mut line = String::new();
        BufReader::new(&mut theirs).read_line(&mut line).unwrap();
        assert_eq!(line, "hello\n");
        // Not channels: a file, standard input, a stream socket, a pipe. The
        // file and the sockets are this test's own descriptors, whatever
        // numbers they got; standard input is named by its constant, and
        // `check` refuses it by number before it looks at anything (Rust's
        // start-up reopens a closed 0..2 as /dev/null, so no socket of another
        // test can take that number).
        let null = fs::File::open("/dev/null").unwrap();
        assert!(Channel::check(null.as_raw_fd()).is_err());
        assert!(Channel::check(libc::STDIN_FILENO).is_err());
        let (a, _b) = UnixStream::pair().unwrap();
        assert!(Channel::check(a.as_raw_fd()).is_err());
        let mut pipe = [0 as RawFd; 2];
        // SAFETY: pipe writes two descriptors, closed below.
        assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0);
        assert!(Channel::check(pipe[0]).is_err());
        // SAFETY: closing the pipe made above.
        unsafe {
            libc::close(pipe[0]);
            libc::close(pipe[1]);
        }
        // Once the service's end is gone, the channel opens nothing. The end is
        // shut down first, not just dropped: dropping closes this descriptor
        // only, and a thread of another test that is between fork and exec
        // (starting `git`, in repo_info's tests) briefly holds a copy of every
        // open descriptor, so the socket stayed open and the send went through:
        // the flake of 1 Nov 2026 (about half of the runs that shared the
        // binary with repo_info's tests). shutdown(2) acts on the socket
        // itself, whoever holds a copy.
        // SAFETY: shutdown on a descriptor this test owns.
        assert_eq!(
            unsafe { libc::shutdown(service.as_raw_fd(), libc::SHUT_RDWR) },
            0
        );
        drop(service);
        assert!(channel.open_stream().is_err());
    }
}
