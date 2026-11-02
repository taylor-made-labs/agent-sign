//! `agent-launchd`: the launcher, in system mode (docs/system-mode.md,
//! sections 2 to 4, "D6", "How working copies are shared"; build step 3).
//!
//! It runs as its own account (`agent-launch`) and owns the slots: each
//! launched session runs in a static slot account (`agent-slot-<n>`) of its
//! own, inside `agent-session@<n>.service`. For each request on the launch
//! socket it:
//!
//! 1. decides who is asking by the uid the kernel reports, never by
//!    anything the request says: a person's account (`[launcher]
//!    people_accounts`) launches by asking; any other account needs a launch
//!    approval signed by a key in `[launcher] approvers`, used once
//!    ([`agent_sign::launch_approval`]);
//!    Before that, the request itself is held to limits: a caller that is not
//!    a person's is read for at most 64 KiB, and a launch approval is
//!    verified on that head before a single bundle byte is read (the
//!    `bundles_follow` form, [`agent_sign::launcher`]); every line has a
//!    total deadline to arrive in (not a timeout per read, which a slow
//!    drip restarts) and every send to a caller a write timeout, a timeout
//!    meaning the caller has gone. The environment is an allow-list
//!    (`LANG`, `TERM`), whoever asks and whatever an approval says;
//! 2. picks the lowest slot that no session of this launcher holds and
//!    whose session and end units are both inactive (so every process of the
//!    previous session is gone);
//! 3. makes a fresh `current/` in the slot's folder (private until it is
//!    ready, then the slot's group, 0770) and writes the caller's bundles to
//!    `current/in/` (0640): git crosses only as bundles;
//! 4. registers the session with the service on the launcher-only socket,
//!    and only after the service's answer writes the spec and starts the
//!    unit (so the service knows the session before any of its processes
//!    can ask);
//! 5. stays with the caller while the session runs, passing on its output,
//!    and stops the session when the caller goes or `[slots] max_duration`
//!    is reached;
//! 6. at the end: closes the registration (nothing in the slot can get a
//!    signature from then on), waits until the unit is inactive, runs the
//!    end step (`agent-session-end@<n>`, as the slot's account), reads what
//!    it left in `current/out/` refusing links, renames `current/` into the
//!    slot's Trash (always, logged in `sessions.log`, never deleted), and
//!    sends the caller its bundles. Only then is the slot free again.
//!
//! **Its I/O folder (A-2).** The two kinds of file a slot's unit has systemd
//! open *as root* (the spec, `LoadCredential=spec:`, and the output,
//! `StandardOutput=append:`) are not in the launcher's own state folder, which
//! the launcher controls and a compromised launcher could fill with links.
//! They are in `/var/lib/agent-launch-io/{specs,logs}` ([`launcher::io_dir`]),
//! root:agent-launch 0750, where no account but root can make, rename or
//! remove an entry, and which the sitting fills with one regular file per
//! slot and kind (`specs/<n>.json`, `logs/<n>.out`, owned by the launcher,
//! 0600). The launcher only opens those existing files (`O_NOFOLLOW`, never
//! `O_CREAT`, then a check on the descriptor: a regular file, its own, one
//! name), truncates and writes a spec in place, truncates a log before the
//! session starts and reads it to stream the output. It never creates,
//! renames, links or removes an entry there. A slot whose files, or whose
//! folders, aren't exactly right is skipped (said in the log, and in the
//! refusal when no slot is left) until the sitting fixes them; nothing is
//! created in their place.
//!
//! **It never runs git.** A session's repository is the session's: its
//! config and hooks would run as whoever runs git in it. The launcher moves
//! bytes only; the end step, which runs git, runs as the slot.
//!
//! **Partial failures.** Every path out of a launch after the slot is
//! claimed goes through the same end: stop, wait for inactive, Trash. A
//! folder that can't be moved to the Trash keeps its slot out of use (said
//! in the log) until the launcher restarts and sweeps it, so a next session
//! never starts beside leftovers. Nothing is ever deleted.
//!
//! **At start** it stops every slot's session unit still running (the
//! service has already ended those sessions, since their registrations
//! closed when the previous launcher went) and moves their folders to the
//! Trash, before it gives the slot to anyone.
//!
//! **Places for reading (re-checks R1 and R2).** What a connection may hold
//! while it is read is counted in places, so no caller can use up the
//! launcher's memory or its attention: four small places for the first
//! line of a caller that isn't a person's, of which one account (by the
//! kernel's uid) holds at most one ([`MAX_OTHERS_PER_UID`]), and one of the
//! four is never given to any of them ([`MAX_PEOPLE_SMALL_RESERVED`]); two bulk places
//! for the bundles of verified relayers ([`MAX_RELAYED_BULK_READING`]); and one
//! bulk place for the people's accounts together ([`MAX_PEOPLE_BULK_READING`]),
//! which no relayer can take, so a relayer can never keep a person out (a
//! person's account may also use a relayers' place that is free: the three
//! are all the launcher's memory allows, and an idle one is of no use to
//! anyone). A request that is refused lets go of its place, and of its
//! nonce's reservation, *before* the refusal is written, so a caller that
//! reconnects the moment it reads the refusal never finds its own old
//! request still holding a place. A
//! launch approval's nonce is *reserved* as soon as the approval verifies,
//! before any bundle byte is read, and a second presentation of a nonce that
//! is reserved or spent is refused before it takes a bulk place; a launch
//! that ends before a slot is claimed gives the reservation back
//! ([`agent_sign::launch_approval::LaunchNonces::reserve`]).
//!
//! **Races.** One lock covers the choice of slot, the nonce's check and its
//! record (synced before anything starts), and the slot's claim. The file
//! moves in a slot's folder go through descriptors and refuse links
//! ([`agent_sign::slot_fs`]); a session can write only inside its own
//! `current/`, never the slot's folder that holds `current` and `trash`.

use std::process::ExitCode;

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    match daemon::run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("[agent-launchd] {e}");
            ExitCode::from(1)
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() -> ExitCode {
    eprintln!("agent-launchd runs only on Linux, in system mode");
    ExitCode::from(1)
}

#[cfg(target_os = "linux")]
mod daemon {
    use std::collections::{BTreeMap, HashMap};
    use std::fs;
    use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
    use std::os::fd::{FromRawFd, OwnedFd, RawFd};
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex, PoisonError};
    use std::thread;
    use std::time::{Duration, Instant};

    use base64::Engine;
    use serde_json::json;

    use agent_sign::kernel_facts::{KernelFacts, Liveness, session_unit};
    use agent_sign::launch_approval::{self, ApprovedRepo, Approvers, Asked, LaunchNonces};
    use agent_sign::launcher::{
        self, ApprovalIn, BundleOut, CURRENT, IN, LOGS, LaunchBundles, LaunchRequest,
        LaunchResponse, OUT, RETURNED, RepoIn, SPECS, STATUS_FILE, SessionSpec, TRASH,
    };
    use agent_sign::protocol::{Request, Response};
    use agent_sign::slot_fs;
    use agent_sign::system_config::SystemConfig;
    use agent_sign::systemd_port::{Systemd, end_unit};

    /// How often a session's state is looked at.
    const POLL: Duration = Duration::from_millis(250);
    /// The total time a request line from a caller that is not a person's has
    /// to arrive, from the first read to the newline. Such a line is at most
    /// [`SMALL_REQUEST_BYTES`] (64 KiB), and the slowest sender worth
    /// waiting for is taken to manage a rate of 8 KiB per second (at which
    /// 64 KiB takes 8 seconds; a local socket gives a million times that), so
    /// 10 seconds covers every honest caller. The deadline is on the whole
    /// line, not on each read: a client that sends one byte a second would
    /// otherwise never finish, and would hold one of the
    /// [`MAX_OTHERS_READING`] places for as long as it liked.
    const HEAD_DEADLINE: Duration = Duration::from_secs(10);
    /// The total time a line that may carry bundles (a person's request, or the
    /// second line of a verified `bundles_follow` launch) has to arrive. It
    /// may be [`launcher::MAX_REQUEST_BYTES`] (512 MiB), and the slowest
    /// sender worth waiting for is taken to manage a rate of 1 MiB per
    /// second (the caller's own `git bundle` and base64, on the same
    /// machine, are far faster), which is 512 seconds; 600 seconds leaves
    /// room. After this the connection is closed and its memory freed.
    const BULK_DEADLINE: Duration = Duration::from_secs(600);
    /// The slowest rate, in bytes per second, at which the launcher keeps
    /// writing to a caller (1 MiB per second): it sizes how long one whole
    /// message may take to send, see [`write_within`].
    const MIN_RATE_BYTES_PER_SEC: u64 = 1024 * 1024;
    /// How long one write to a caller may make no progress at all before the
    /// caller is counted as gone: a caller that takes not one byte in
    /// 30 seconds is not reading. (A reader that is slow but moving is bounded
    /// by the message's total time, see [`write_within`].)
    const SEND_PATIENCE: Duration = Duration::from_secs(30);
    /// The longest request read from a caller that is not a person's and has not
    /// been verified: enough for a launch approval and a refusal to be told
    /// apart from a misunderstanding, never enough to grow the launcher's
    /// memory. Whether `[launcher] approvers` is empty makes no difference:
    /// bundle bytes are read only after the approval on the head is verified.
    const SMALL_REQUEST_BYTES: u64 = 64 * 1024;
    /// How many requests from callers that aren't people's may be in their
    /// first, small read at once. A person's requests are never counted
    /// here, so nobody can keep a person out.
    const MAX_OTHERS_READING: usize = 4;
    /// How many of the [`MAX_OTHERS_READING`] small places no account that
    /// isn't a person's can ever take (re-check Q1): the place is kept for
    /// the people's accounts, so however many other accounts connect and say
    /// nothing, at most `MAX_OTHERS_READING - MAX_PEOPLE_SMALL_RESERVED` are
    /// held by them together. A person's own first read is counted in the
    /// people's bulk place ([`MAX_PEOPLE_BULK_READING`]), so the kept place is
    /// headroom that is never lent out, not a second queue; the pool stays at
    /// [`MAX_OTHERS_READING`] so the unit's memory floor (which reads it) is
    /// unchanged.
    const MAX_PEOPLE_SMALL_RESERVED: usize = 1;
    /// The most of those [`MAX_OTHERS_READING`] places one account (by the uid
    /// the kernel reports) may hold at once (re-check R1). Without a cap one
    /// local account could keep every place busy by reconnecting: each
    /// connection that sends nothing holds its place for [`HEAD_DEADLINE`],
    /// and the next one is taken the moment it ends, so every honest relayer
    /// would be told the launcher is reading other requests. An honest
    /// caller needs one place at a time, for the milliseconds it takes to
    /// read and verify a head, so two (one for a retry) is plenty; and two is
    /// half of the places, so one account can never leave fewer than two for
    /// everyone else. Since re-check Q1 it is one, and the places other
    /// accounts may take together are one fewer than the pool
    /// ([`MAX_PEOPLE_SMALL_RESERVED`]): two accounts can no longer fill the
    /// pool between them (before, two accounts holding two each took all four).
    /// What the cap does not do: several accounts (the machine's accounts, a
    /// slot's among them, can all reach the 0666 socket) can still hold the
    /// places other accounts may take, one each; the relayers are then told the
    /// launcher is busy until the head deadline, and the people's accounts are
    /// unaffected. Must stay at least 1 and below [`MAX_OTHERS_READING`].
    const MAX_OTHERS_PER_UID: usize = 1;
    /// How many lines that may carry bundles (up to 512 MiB each) are read at
    /// once in all: [`MAX_RELAYED_BULK_READING`] verified relayers' plus
    /// [`MAX_PEOPLE_BULK_READING`] people's. Each is held as text and
    /// parsed (about twice [`launcher::MAX_REQUEST_BYTES`] at its peak, 1 GiB)
    /// and then decoded (another 384 MiB) before it is written to the slot, so
    /// this, times about 1.5 GiB, is the most memory those reads can hold:
    /// what `agent-launchd.service`'s `MemoryMax=` is derived from
    /// (docs/system-mode.md). It is written as a number, not a sum, because the
    /// sitting's tests read it from this line.
    const MAX_BULK_READING: usize = 3;
    /// The bulk places verified relayers (accounts that aren't people's)
    /// share. Two, so that one relayed launch being read doesn't stop another
    /// (and a replayed approval, refused at its reservation, takes none).
    const MAX_RELAYED_BULK_READING: usize = 2;
    /// The bulk place the people's accounts share, which no relayer can take
    /// (re-check R2): a person's launch is never kept out by relayers, however
    /// long they take to send. One, because the people's accounts are the
    /// machine's own users and their reads are a copy of a local `git bundle`
    /// each, quick. A person who finds it taken may use a relayers' place that
    /// is free (so a person is no worse placed than when all three were
    /// shared); only when all of those are held is a person told to try
    /// again. It is one and not two because each bulk place costs about
    /// 1.5 GiB of the launcher's memory ([`MAX_BULK_READING`]), and the unit's
    /// cap is derived from the total.
    const MAX_PEOPLE_BULK_READING: usize = 1;
    const _: () = {
        assert!(MAX_BULK_READING == MAX_RELAYED_BULK_READING + MAX_PEOPLE_BULK_READING);
        assert!(MAX_OTHERS_PER_UID >= 1 && MAX_OTHERS_PER_UID < MAX_OTHERS_READING);
        assert!(MAX_PEOPLE_SMALL_RESERVED >= 1 && MAX_PEOPLE_SMALL_RESERVED < MAX_OTHERS_READING);
    };
    /// How often a stop is asked again of a unit that hasn't stopped.
    const STOP_AGAIN: Duration = Duration::from_secs(30);
    /// How long the service has to answer a registration.
    const SERVICE_PATIENCE: Duration = Duration::from_secs(30);
    /// The most output passed on in one message.
    const OUTPUT_CHUNK: usize = 64 * 1024;

    fn b64() -> base64::engine::GeneralPurpose {
        base64::engine::general_purpose::STANDARD
    }

    fn euid() -> u32 {
        // SAFETY: geteuid takes no arguments and can't fail.
        unsafe { libc::geteuid() }
    }

    struct Launcher {
        config: SystemConfig,
        kernel: Arc<dyn KernelFacts>,
        systemd: Arc<dyn Systemd>,
        approvers: Approvers,
        state: PathBuf,
        /// The I/O folder ([`launcher::io_dir`]): root's, holding every file
        /// a slot unit's systemd opens as root.
        io: PathBuf,
        slots_root: OwnedFd,
        /// Slot n's claim is `busy[n - 1]`: held from the choice of slot to
        /// the end of the Trash move.
        busy: Mutex<Vec<bool>>,
        nonces: Mutex<LaunchNonces>,
        /// Each caller's launches in the last hour ([`launcher::LaunchRate`]),
        /// checked and recorded under the slot lock.
        rate: Mutex<launcher::LaunchRate>,
        max_duration: Duration,
        /// The small first reads of callers that aren't people's, now
        /// ([`MAX_OTHERS_READING`], at most [`MAX_OTHERS_PER_UID`] an account).
        small_places: Places,
        /// The lines that may carry bundles from verified relayers, being read
        /// now ([`MAX_RELAYED_BULK_READING`]).
        relayed_bulk_places: Places,
        /// The people's accounts' lines that may carry bundles, being read now
        /// ([`MAX_PEOPLE_BULK_READING`]): a pool no relayer can take from. A
        /// person whose own place is taken tries `relayed_bulk_places` next.
        people_bulk_places: Places,
    }

    pub(super) fn run() -> Result<(), String> {
        if euid() == 0 {
            return Err("refuses to run as root: it runs as its own account, agent-launch".into());
        }
        let active = agent_sign::system_config::active()?.ok_or(
            "there is no /etc/agent-sign/system.toml: the launcher runs only in system mode",
        )?;
        let config = active.config;
        let kernel = agent_sign::kernel_facts::kernel();
        if !agent_sign::kernel_facts::is_stand_in() {
            let want = kernel.account_uid(&config.launcher.account)?;
            if want != Some(euid()) {
                return Err(format!(
                    "{} sets [launcher] account = {:?}, and this is uid {}: the launcher runs \
                     as that account and no other, so nothing was started",
                    active.path.display(),
                    config.launcher.account,
                    euid()
                ));
            }
        }
        let state = launcher::state_dir();
        if !state.exists() {
            fs::create_dir_all(&state)
                .map_err(|e| format!("{}: can't be made ({e})", state.display()))?;
        }
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("{}: can't be made private ({e})", state.display()))?;
        let lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(state.join("launcher.lock"))
            .map_err(|e| format!("{}: the lock can't be opened ({e})", state.display()))?;
        lock.try_lock().map_err(|_| {
            format!(
                "another agent-launchd holds {}; one launcher per machine",
                state.join("launcher.lock").display()
            )
        })?;
        // Only the returned bundles live in the state folder now: the specs
        // and the logs are in the I/O folder, which this program never makes.
        let returned = state.join(RETURNED);
        if !returned.exists() {
            fs::create_dir(&returned).map_err(|e| format!("{}: {e}", returned.display()))?;
        }
        fs::set_permissions(&returned, fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("{}: {e}", returned.display()))?;
        let nonces = LaunchNonces::open(&state, launcher::now_secs())?;
        let approvers = Approvers::parse(&config.launcher.approvers)?;
        let systemd = agent_sign::systemd_port::systemd(config.slots.count)?;
        let slots_root = slot_fs::open_dir_path(&config.slots.root).map_err(|e| {
            format!(
                "[slots] root {} can't be opened ({e})",
                config.slots.root.display()
            )
        })?;
        let max_duration = launcher::parse_duration(&config.slots.max_duration)
            .map_err(|e| format!("[slots] max_duration: {e}"))?;
        if config.slots.count == 0 {
            return Err("[slots] count is 0: there is nowhere to run a session".into());
        }
        let listener = listener(&config.launcher.socket)?;
        let count = config.slots.count as usize;
        let me = Arc::new(Launcher {
            config,
            kernel,
            systemd,
            approvers,
            state,
            io: launcher::io_dir(),
            slots_root,
            busy: Mutex::new(vec![false; count]),
            nonces: Mutex::new(nonces),
            rate: Mutex::new(launcher::LaunchRate::default()),
            max_duration,
            small_places: Places::new(
                MAX_OTHERS_READING - MAX_PEOPLE_SMALL_RESERVED,
                Some(MAX_OTHERS_PER_UID),
            ),
            relayed_bulk_places: Places::new(MAX_RELAYED_BULK_READING, None),
            people_bulk_places: Places::new(MAX_PEOPLE_BULK_READING, None),
        });
        sweep_at_start(&me);
        for n in 1..=count as u32 {
            if let Err(e) = open_slot_io(&me, n) {
                eprintln!("[agent-launchd] slot {n} is out of use until the sitting fixes it: {e}");
            }
        }
        eprintln!(
            "[agent-launchd] ready: {} slots; {}",
            count,
            if me.approvers.is_empty() {
                "only people's accounts may launch (no launch approvers yet)"
            } else {
                "people's accounts, or a signed launch approval"
            }
        );
        let _lock = lock;
        for conn in listener.incoming() {
            let Ok(conn) = conn else { continue };
            // The kernel's facts about the caller, read at accept.
            let facts = me.kernel.peer(&conn);
            let me = Arc::clone(&me);
            thread::spawn(move || serve(&me, conn, facts));
        }
        Ok(())
    }

    /// The launch socket: from systemd (`agent-launchd.socket`, named
    /// `launch`) or made here, 0666 (the launcher decides by the caller's
    /// uid, so a group would add nothing).
    fn listener(path: &Path) -> Result<UnixListener, String> {
        if let Some(l) = activated()? {
            return Ok(l);
        }
        match fs::symlink_metadata(path) {
            Ok(m) => {
                use std::os::unix::fs::FileTypeExt;
                if !m.file_type().is_socket() {
                    return Err(format!(
                        "{} exists and isn't a socket; nothing was started",
                        path.display()
                    ));
                }
                fs::remove_file(path).map_err(|e| format!("{}: {e}", path.display()))?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("{}: {e}", path.display())),
        }
        let l = UnixListener::bind(path)
            .map_err(|e| format!("can't listen on {} ({e})", path.display()))?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o666))
            .map_err(|e| format!("{}: {e}", path.display()))?;
        Ok(l)
    }

    /// The socket systemd passed (`LISTEN_PID`, `LISTEN_FDS`,
    /// `LISTEN_FDNAMES`): exactly one listening Unix stream socket named
    /// `launch`, or a refusal to start. The variables are removed before any
    /// other thread exists.
    fn activated() -> Result<Option<UnixListener>, String> {
        let Ok(pid) = std::env::var("LISTEN_PID") else {
            return Ok(None);
        };
        if pid.trim().parse::<u32>().ok() != Some(std::process::id()) {
            return Ok(None);
        }
        let count: usize = std::env::var("LISTEN_FDS")
            .ok()
            .and_then(|n| n.trim().parse().ok())
            .ok_or("systemd set LISTEN_PID but no readable LISTEN_FDS")?;
        let names = std::env::var("LISTEN_FDNAMES").unwrap_or_default();
        // SAFETY: called at start, before any other thread exists.
        unsafe {
            std::env::remove_var("LISTEN_PID");
            std::env::remove_var("LISTEN_FDS");
            std::env::remove_var("LISTEN_FDNAMES");
        }
        if count != 1 || names != "launch" {
            return Err(format!(
                "systemd passed {count} sockets named {names:?}; the launcher takes exactly one, \
                 named `launch`"
            ));
        }
        let fd: RawFd = 3;
        let option = |opt: libc::c_int| -> Option<libc::c_int> {
            let mut value: libc::c_int = 0;
            let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
            // SAFETY: getsockopt writes at most `len` bytes into `value`.
            let rc = unsafe {
                libc::getsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    opt,
                    &mut value as *mut libc::c_int as *mut libc::c_void,
                    &mut len,
                )
            };
            (rc == 0).then_some(value)
        };
        if option(libc::SO_DOMAIN) != Some(libc::AF_UNIX)
            || option(libc::SO_TYPE) != Some(libc::SOCK_STREAM)
            || option(libc::SO_ACCEPTCONN) != Some(1)
        {
            return Err("systemd's `launch` socket isn't a listening Unix stream socket".into());
        }
        // SAFETY: systemd passed this descriptor to this process alone.
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        // SAFETY: fcntl on the descriptor just taken.
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFD);
            if flags >= 0 {
                libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC);
            }
        }
        Ok(Some(UnixListener::from(owned)))
    }

    /// [`SEND_PATIENCE`], or in a debug test build only, the number of
    /// milliseconds in `AGENT_SIGN_TEST_SEND_TIMEOUT_MS`.
    fn send_patience() -> Duration {
        #[cfg(feature = "test-authenticator")]
        if let Some(ms) = std::env::var("AGENT_SIGN_TEST_SEND_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
        {
            return Duration::from_millis(ms);
        }
        SEND_PATIENCE
    }

    /// `normal` (a request line's deadline), or in a debug test build only, the
    /// number of milliseconds in `AGENT_SIGN_TEST_REQUEST_DEADLINE_MS`.
    fn deadline(normal: Duration) -> Duration {
        #[cfg(feature = "test-authenticator")]
        if let Some(ms) = std::env::var("AGENT_SIGN_TEST_REQUEST_DEADLINE_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
        {
            return Duration::from_millis(ms);
        }
        normal
    }

    /// Writes all of `bytes` to the caller, or says it can't: false when one
    /// write makes no progress for [`SEND_PATIENCE`], or when the whole message
    /// takes longer than that plus its size at [`MIN_RATE_BYTES_PER_SEC`]. A
    /// caller that has stopped reading (but stays connected) would otherwise
    /// block this thread in a write for ever, and the session loop with it:
    /// the unit never stopped, the slot never freed. False is treated as the
    /// caller having gone (the path the loop already has for a caller that
    /// hung up).
    fn write_within(conn: &mut UnixStream, bytes: &[u8]) -> bool {
        let patience = send_patience();
        let total = patience + Duration::from_secs(bytes.len() as u64 / MIN_RATE_BYTES_PER_SEC);
        let end = Instant::now() + total;
        let mut at = 0;
        while at < bytes.len() {
            let left = end.saturating_duration_since(Instant::now());
            if left.is_zero() || conn.set_write_timeout(Some(patience.min(left))).is_err() {
                return false;
            }
            match conn.write(&bytes[at..]) {
                Ok(0) => return false,
                Ok(k) => at += k,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => return false,
            }
        }
        true
    }

    fn send(conn: &mut UnixStream, r: &LaunchResponse) -> bool {
        match serde_json::to_string(r) {
            Ok(mut s) => {
                s.push('\n');
                write_within(conn, s.as_bytes())
            }
            Err(_) => false,
        }
    }

    fn refuse(conn: &mut UnixStream, message: String) {
        eprintln!("[agent-launchd] refused: {message}");
        let _ = send(conn, &LaunchResponse::Error { message });
    }

    /// Lets go of `held` (a place for reading, a nonce's reservation) and only
    /// then writes the refusal. The caller reads the refusal and may
    /// reconnect at once; if the place were let go after the write, as it
    /// would be at the end of the function, the retry could find the place
    /// still taken by the request it is retrying, and be told the launcher is
    /// busy when nothing else is reading (re-check fix round). The write is
    /// also no longer done while holding a place that others could use.
    fn refuse_free<H>(held: H, conn: &mut UnixStream, message: String) {
        drop(held);
        refuse(conn, message);
    }

    fn serve(
        me: &Arc<Launcher>,
        mut conn: UnixStream,
        facts: std::io::Result<agent_sign::kernel_facts::PeerFacts>,
    ) {
        let facts = match facts {
            Ok(f) => f,
            Err(e) => return refuse(&mut conn, format!("couldn't tell who is asking ({e})")),
        };
        if facts.process == Liveness::Gone {
            return refuse(&mut conn, "the process that asked has already ended".into());
        }
        let person = match is_person(me, facts.uid) {
            Ok(p) => p,
            Err(e) => {
                return refuse(
                    &mut conn,
                    format!("couldn't read the machine's accounts ({e})"),
                );
            }
        };
        // A person's line may carry bundles (up to 512 MiB); any other
        // caller's first line is 64 KiB at most, whatever `approvers` holds.
        let (limit, patience) = if person {
            (launcher::MAX_REQUEST_BYTES, deadline(BULK_DEADLINE))
        } else {
            (SMALL_REQUEST_BYTES, deadline(HEAD_DEADLINE))
        };
        // A person's own place first, then a relayers' place that is free;
        // everyone else a small place.
        let taken = if person {
            me.people_bulk_places
                .take(facts.uid)
                .or_else(|_| me.relayed_bulk_places.take(facts.uid))
        } else {
            me.small_places.take(facts.uid)
        };
        let guard = match taken {
            Ok(g) => g,
            Err(Turned::Full) => {
                return refuse(
                    &mut conn,
                    "the launcher is reading other requests; try again".into(),
                );
            }
            Err(Turned::AccountCap(most)) => {
                return refuse(
                    &mut conn,
                    format!(
                        "uid {} already has {most} requests being read, the most one account \
                         may have at once; try again when one has ended",
                        facts.uid
                    ),
                );
            }
        };
        let mut lines = match conn.try_clone() {
            Ok(c) => Lines::new(c),
            Err(e) => {
                return refuse_free(
                    guard,
                    &mut conn,
                    format!("the connection can't be read ({e})"),
                );
            }
        };
        let line = match lines.next(limit, patience) {
            Ok(l) => l,
            Err(e) => return refuse_free(guard, &mut conn, e),
        };
        let _ = conn.set_read_timeout(None);
        let request: LaunchRequest = match serde_json::from_str(line.trim_end()) {
            Ok(r) => r,
            Err(e) => {
                return refuse_free(guard, &mut conn, format!("the request can't be read ({e})"));
            }
        };
        drop(line);
        match request {
            LaunchRequest::Launch {
                agent,
                command,
                env,
                repos,
                approval,
                bundles_follow,
            } => launch(
                me,
                conn,
                Incoming {
                    lines,
                    guard,
                    bundles_follow,
                },
                facts.uid,
                person,
                agent,
                command,
                env,
                repos,
                approval,
            ),
            LaunchRequest::Collect { session } => {
                drop(guard);
                collect(me, conn, facts.uid, &session)
            }
        }
    }

    /// Reads a connection a line at a time, keeping what it has read past a
    /// newline for the next line (a `bundles_follow` launch has two). Each
    /// line has a size limit and a total deadline ([`Lines::next`]).
    struct Lines {
        conn: UnixStream,
        pending: Vec<u8>,
    }

    impl Lines {
        fn new(conn: UnixStream) -> Self {
            Self {
                conn,
                pending: Vec::new(),
            }
        }

        /// The next line, newline included, of at most `limit` bytes, that
        /// arrives within `within` of this call, counted from the start and
        /// not restarted by progress: each read waits only for what is left.
        /// Stops reading as soon as the limit is passed, so a flood is taken
        /// only up to the limit (and what the kernel buffered).
        fn next(&mut self, limit: u64, within: Duration) -> Result<String, String> {
            let end = Instant::now() + within;
            let late = || {
                format!(
                    "no complete request arrived within {} seconds",
                    within.as_secs().max(1)
                )
            };
            let too_long = || format!("the request is longer than the {limit} byte limit");
            let mut chunk = vec![0u8; 64 * 1024];
            let mut searched = 0usize;
            loop {
                if let Some(i) = self.pending[searched..].iter().position(|b| *b == b'\n') {
                    let at = searched + i + 1;
                    if at as u64 > limit {
                        return Err(too_long());
                    }
                    let rest = self.pending.split_off(at);
                    let line = std::mem::replace(&mut self.pending, rest);
                    return String::from_utf8(line).map_err(|_| "the request isn't text".into());
                }
                searched = self.pending.len();
                if searched as u64 >= limit {
                    return Err(too_long());
                }
                let left = end.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Err(late());
                }
                self.conn
                    .set_read_timeout(Some(left))
                    .map_err(|e| format!("the connection can't be read ({e})"))?;
                match self.conn.read(&mut chunk) {
                    Ok(0) => {
                        return Err(
                            "the connection closed before a complete request arrived".into()
                        );
                    }
                    Ok(k) => {
                        // Grow to what is needed, never to a doubling that
                        // would pass the limit by hundreds of MiB.
                        let want = self.pending.len() + k;
                        if want > self.pending.capacity() {
                            let cap = (want * 2).min(limit as usize + chunk.len()).max(want);
                            self.pending.reserve_exact(cap - self.pending.len());
                        }
                        self.pending.extend_from_slice(&chunk[..k]);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(e)
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) =>
                    {
                        return Err(late());
                    }
                    Err(e) => return Err(format!("the request can't be read ({e})")),
                }
            }
        }
    }

    /// What a pool of places is holding now: all of it, and by account.
    #[derive(Default)]
    struct Held {
        total: usize,
        by_uid: HashMap<u32, usize>,
    }

    /// A pool of places for reading requests (see [`MAX_OTHERS_READING`],
    /// [`MAX_RELAYED_BULK_READING`], [`MAX_PEOPLE_BULK_READING`]): `most` in
    /// all and, when `per_uid` is set, no more than that to one account (the
    /// uid the kernel reported). A [`Place`] is given back when it is dropped,
    /// by whatever way its request ends.
    struct Places {
        most: usize,
        per_uid: Option<usize>,
        held: Arc<Mutex<Held>>,
    }

    /// Why no place was given.
    #[derive(Debug, PartialEq, Eq)]
    enum Turned {
        /// Every place in the pool is held.
        Full,
        /// The account already holds the most one account may (the number).
        AccountCap(usize),
    }

    /// One place held by `uid`; given back when dropped.
    struct Place {
        held: Arc<Mutex<Held>>,
        uid: u32,
    }

    impl Places {
        fn new(most: usize, per_uid: Option<usize>) -> Self {
            Self {
                most,
                per_uid,
                held: Arc::new(Mutex::new(Held::default())),
            }
        }

        /// A place for `uid`, or why not. The account's own cap is checked
        /// first, so an account that is holding its share is told so, not
        /// that the launcher is busy.
        fn take(&self, uid: u32) -> Result<Place, Turned> {
            let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
            let mine = held.by_uid.get(&uid).copied().unwrap_or(0);
            if let Some(cap) = self.per_uid
                && mine >= cap
            {
                return Err(Turned::AccountCap(cap));
            }
            if held.total >= self.most {
                return Err(Turned::Full);
            }
            held.total += 1;
            *held.by_uid.entry(uid).or_insert(0) += 1;
            Ok(Place {
                held: Arc::clone(&self.held),
                uid,
            })
        }
    }

    impl Drop for Place {
        fn drop(&mut self) {
            let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
            held.total = held.total.saturating_sub(1);
            let none_left = match held.by_uid.get_mut(&self.uid) {
                Some(n) => {
                    *n = n.saturating_sub(1);
                    *n == 0
                }
                None => false,
            };
            if none_left {
                held.by_uid.remove(&self.uid);
            }
        }
    }

    /// A launch approval's nonce, reserved while its launch is in flight
    /// ([`LaunchNonces::reserve`]); given back when dropped. Dropping after
    /// the nonce was recorded changes nothing: a used nonce stays used.
    struct NonceHold<'a> {
        nonces: &'a Mutex<LaunchNonces>,
        nonce: String,
    }

    impl Drop for NonceHold<'_> {
        fn drop(&mut self) {
            self.nonces
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .release(&self.nonce);
        }
    }

    /// What `serve` hands `launch` besides the head: the connection's reader
    /// (the bundles may be on its next line), the place held for this
    /// request's reading, and whether bundles follow.
    struct Incoming {
        lines: Lines,
        guard: Place,
        bundles_follow: bool,
    }

    /// A request's repositories, checked and decoded.
    struct Repo {
        name: String,
        bundle: Vec<u8>,
    }

    /// Checks everything about a launch request that doesn't need its bundles
    /// (so it can be done before any bundle byte is read): the agent, the
    /// program, the environment ([`launcher::check_env`]: only `LANG` and
    /// `TERM`, plain values), and each repository's name and base. With
    /// `follow`, no repository may carry a bundle: they come on the next line.
    fn check_head(
        agent: &str,
        command: &[String],
        env: &BTreeMap<String, String>,
        repos: &[RepoIn],
        follow: bool,
    ) -> Result<(), String> {
        if agent.trim().is_empty() || agent.len() > 64 || agent.chars().any(char::is_control) {
            return Err("the agent's name must be 1 to 64 printable characters".into());
        }
        if command.is_empty() || command[0].is_empty() {
            return Err("there is no program to run".into());
        }
        if command.iter().any(|a| a.contains('\0')) {
            return Err("the program or an argument has a NUL in it".into());
        }
        launcher::check_env(env)?;
        for (i, r) in repos.iter().enumerate() {
            if !launcher::is_repo_name(&r.name) {
                return Err(format!(
                    "{:?} can't name a repository: 1 to 64 letters, digits, '.', '_' or '-', \
                     not starting with '.' or '-'",
                    r.name
                ));
            }
            if repos[..i].iter().any(|o| o.name == r.name) {
                return Err(format!("the repository {:?} is named twice", r.name));
            }
            let base_ok = (r.base.len() == 40 || r.base.len() == 64)
                && r.base
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
            if !base_ok {
                return Err(format!("{:?}'s base isn't a git commit id", r.name));
            }
            if follow && !r.bundle_b64.is_empty() {
                return Err(format!(
                    "bundles_follow is set, so {:?} must carry no bundle: the bundles come on \
                     the next line",
                    r.name
                ));
            }
        }
        Ok(())
    }

    /// The repositories' bundles, decoded and checked to look like git
    /// bundles ([`check_head`] has checked the rest).
    fn decode_repos(repos: Vec<RepoIn>) -> Result<Vec<Repo>, String> {
        let mut out = Vec::new();
        for r in repos {
            let bundle = b64()
                .decode(r.bundle_b64.as_bytes())
                .map_err(|e| format!("{:?}'s bundle isn't base64 ({e})", r.name))?;
            if !launcher::looks_like_bundle(&bundle) {
                return Err(format!("{:?}'s bundle isn't a git bundle", r.name));
            }
            out.push(Repo {
                name: r.name,
                bundle,
            });
        }
        Ok(out)
    }

    /// Whether `uid` is a person's account (`[launcher] people_accounts`,
    /// looked up by name).
    fn is_person(me: &Launcher, uid: u32) -> Result<bool, String> {
        for name in &me.config.launcher.people_accounts {
            if me.kernel.account_uid(name)? == Some(uid) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// A slot's two files in the I/O folder, opened and checked (A-2): the
    /// spec the launcher writes and the output it truncates and reads. The
    /// descriptors are what was checked, so nothing swapped later can be
    /// written (and in production nothing can be swapped: only root changes
    /// the folder).
    struct SlotIo {
        spec: fs::File,
        log: fs::File,
    }

    /// The owner an I/O folder must have: root. Under the test stand-in for
    /// the kernel only, the test's own account, because a test can't make a
    /// folder root's ([`agent_sign::kernel_facts::is_stand_in`]).
    fn io_folder_owner() -> u32 {
        if agent_sign::kernel_facts::is_stand_in() {
            euid()
        } else {
            0
        }
    }

    /// Checks an open I/O folder: owned by root, with no write for its group
    /// or others, so that the launcher (in its group at most) can't make,
    /// rename or remove an entry in it.
    fn check_io_folder(fd: &OwnedFd, shown: &Path) -> Result<(), String> {
        let st = slot_fs::stat_fd(fd).map_err(|e| format!("{}: {e}", shown.display()))?;
        if st.st_uid != io_folder_owner() || st.st_mode & 0o022 != 0 {
            return Err(format!(
                "{} isn't root's with no write for its group or others (uid {}, mode {:o}): \
                 nothing in it is used",
                shown.display(),
                st.st_uid,
                st.st_mode & 0o7777
            ));
        }
        Ok(())
    }

    /// Opens slot n's spec and output files in the I/O folder, making
    /// nothing: the folders are checked, each file is opened `O_NOFOLLOW`
    /// without `O_CREAT` and checked on the descriptor (a regular file, the
    /// launcher's own, one name; see [`slot_fs::open_existing_file_at`]).
    /// The error says what is wrong in plain words.
    fn open_slot_io(me: &Launcher, n: u32) -> Result<SlotIo, String> {
        let root = slot_fs::open_dir_path(&me.io).map_err(|e| {
            format!(
                "the launcher's I/O folder {} can't be opened ({e}); the sitting makes it",
                me.io.display()
            )
        })?;
        check_io_folder(&root, &me.io)?;
        let sub = |name: &str| -> Result<OwnedFd, String> {
            let shown = me.io.join(name);
            let fd = slot_fs::open_dir_at(&root, name)
                .map_err(|e| format!("{} can't be opened ({e})", shown.display()))?;
            check_io_folder(&fd, &shown)?;
            Ok(fd)
        };
        let specs = sub(SPECS)?;
        let logs = sub(LOGS)?;
        let mine = euid();
        let spec = slot_fs::open_existing_file_at(&specs, &format!("{n}.json"), mine)
            .map_err(|e| format!("{SPECS}/{e}"))?;
        let log = slot_fs::open_existing_file_at(&logs, &format!("{n}.out"), mine)
            .map_err(|e| format!("{LOGS}/{e}"))?;
        // The spec carries a session's environment: nobody but the owner (and
        // root, who needs no permission) may read it.
        for f in [&spec, &log] {
            f.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|e| format!("slot {n}'s file mode can't be set ({e})"))?;
        }
        Ok(SlotIo { spec, log })
    }

    /// Chooses the lowest free slot and claims it, recording the
    /// approval's nonce first if there is one; all under the one lock. A slot
    /// whose I/O files aren't exactly right is skipped, with the reason in
    /// the log (and in the refusal when no slot is left): it comes back into
    /// use as soon as the sitting has fixed its files, and a nonce is never
    /// spent on it.
    fn claim_slot(
        me: &Launcher,
        uid: u32,
        approval: Option<&launch_approval::LaunchApproval>,
        charged: bool,
    ) -> Result<(u32, SlotIo), String> {
        let mut busy = me.busy.lock().unwrap();
        let mut chosen = None;
        let mut out_of_use = Vec::new();
        for (i, held) in busy.iter().enumerate() {
            if *held {
                continue;
            }
            let n = i as u32 + 1;
            let active = |u: &str| me.systemd.is_active(u).unwrap_or(true);
            if active(&session_unit(n)) || active(&end_unit(n)) {
                continue;
            }
            match open_slot_io(me, n) {
                Ok(io) => {
                    chosen = Some((n, io));
                    break;
                }
                Err(e) => {
                    eprintln!("[agent-launchd] slot {n} stays out of use: {e}");
                    out_of_use.push(format!("slot {n}: {e}"));
                }
            }
        }
        let (n, io) = chosen.ok_or_else(|| {
            format!(
                "every slot ({}) is in use, still ending or out of use; nothing was started. Try \
                 again when a session has ended{}",
                busy.len(),
                if out_of_use.is_empty() {
                    String::new()
                } else {
                    format!(". Out of use: {}", out_of_use.join("; "))
                }
            )
        })?;
        // The caller's hourly allowance is checked before the nonce is
        // spent (a refused launch uses up nothing) and counted after it, so
        // a launch that fails to record its nonce costs no allowance either.
        // `charged`: the presentation was already counted when it took a bulk
        // place (re-check Q2), so it is neither checked nor counted again.
        let now = launcher::now_secs();
        let mut rate = me.rate.lock().unwrap();
        if !charged {
            rate.check(uid, now, me.config.launcher.launches_per_hour)?;
        }
        if let Some(a) = approval {
            me.nonces.lock().unwrap().record(&a.nonce, a.expires_at)?;
        }
        if !charged {
            rate.record(uid, now);
        }
        drop(rate);
        busy[n as usize - 1] = true;
        Ok((n, io))
    }

    fn release_slot(me: &Launcher, n: u32) {
        me.busy.lock().unwrap()[n as usize - 1] = false;
    }

    /// A slot's folder, checked: a folder (not a link), the launcher's, with
    /// no write for its group and nothing for others. Returns it and its
    /// group (the slot's, set by the sitting).
    fn open_slot(me: &Launcher, n: u32) -> Result<(OwnedFd, u32), String> {
        let name = n.to_string();
        let fd = slot_fs::open_dir_at(&me.slots_root, &name)
            .map_err(|e| format!("slot {n}'s folder can't be opened ({e})"))?;
        let st = slot_fs::stat_fd(&fd).map_err(|e| e.to_string())?;
        if st.st_uid != euid() || st.st_mode & 0o027 != 0 {
            return Err(format!(
                "slot {n}'s folder isn't the launcher's with mode 0750 (uid {}, mode {:o}): \
                 nothing is made in it",
                st.st_uid,
                st.st_mode & 0o7777
            ));
        }
        Ok((fd, st.st_gid))
    }

    /// The slot's Trash, made 0700 if it isn't there.
    fn open_trash(slot: &OwnedFd) -> Result<OwnedFd, String> {
        match slot_fs::stat_at(slot, TRASH).map_err(|e| e.to_string())? {
            None => slot_fs::make_dir_at(slot, TRASH, 0o700)
                .map_err(|e| format!("the Trash can't be made ({e})")),
            Some(st) if slot_fs::is_dir(&st) && st.st_uid == euid() => {
                let fd = slot_fs::open_dir_at(slot, TRASH).map_err(|e| e.to_string())?;
                slot_fs::set_mode(&fd, 0o700).map_err(|e| e.to_string())?;
                Ok(fd)
            }
            Some(_) => Err("the slot's Trash isn't a folder of the launcher's".into()),
        }
    }

    /// Renames the slot's `current` (which must be `expect`, when given)
    /// into its Trash, under a new name, and logs it. Returns the name.
    fn to_trash(
        me: &Launcher,
        n: u32,
        slot: &OwnedFd,
        expect: Option<&OwnedFd>,
        session: Option<&str>,
        log: serde_json::Value,
    ) -> Result<String, String> {
        let trash = open_trash(slot)?;
        if let Some(cur) = expect {
            let want = slot_fs::stat_fd(cur).map_err(|e| e.to_string())?;
            match slot_fs::stat_at(slot, CURRENT).map_err(|e| e.to_string())? {
                Some(st) if st.st_ino == want.st_ino && st.st_dev == want.st_dev => {}
                _ => {
                    return Err(
                        "the slot's current/ isn't the folder this session was given".into(),
                    );
                }
            }
        }
        let base = launcher::trash_name(launcher::now_secs(), session);
        let mut name = base.clone();
        let mut i = 1;
        loop {
            match slot_fs::rename_noreplace(slot, CURRENT, &trash, &name) {
                Ok(()) => break,
                Err(e) if e.raw_os_error() == Some(libc::EEXIST) && i < 1000 => {
                    i += 1;
                    name = format!("{base}-{i}");
                }
                Err(e) => return Err(format!("current/ couldn't be moved to the Trash ({e})")),
            }
        }
        let _ = slot_fs::sync_dir(&trash);
        let _ = slot_fs::sync_dir(slot);
        let mut entry = log;
        entry["time"] = json!(agent_sign::agents_ca::utc_timestamp(launcher::now_secs()));
        entry["slot"] = json!(n);
        entry["trash"] = json!(format!("{n}/{TRASH}/{name}"));
        if let Err(e) = launcher::log_session(&me.state, &entry) {
            eprintln!("[agent-launchd] sessions.log can't be written ({e}): {entry}");
        }
        eprintln!("[agent-launchd] slot {n}: current/ moved to {TRASH}/{name}");
        Ok(name)
    }

    /// Makes the slot's fresh `current/` with the bundles in `in/`. It stays
    /// private (0700) until it is complete, then becomes the slot group's
    /// (0770). A leftover `current/` (a crash between sessions) is moved to
    /// the Trash first.
    fn prepare(
        me: &Launcher,
        n: u32,
        slot: &OwnedFd,
        gid: u32,
        repos: &[Repo],
    ) -> Result<OwnedFd, String> {
        if slot_fs::stat_at(slot, CURRENT)
            .map_err(|e| e.to_string())?
            .is_some()
        {
            to_trash(
                me,
                n,
                slot,
                None,
                None,
                json!({"event": "leftover", "why": "found before a new session"}),
            )?;
        }
        let cur = slot_fs::make_dir_at(slot, CURRENT, 0o700)
            .map_err(|e| format!("slot {n}'s current/ can't be made ({e})"))?;
        let fill = || -> std::io::Result<()> {
            let inbox = slot_fs::make_dir_at(&cur, IN, 0o700)?;
            for r in repos {
                slot_fs::create_file_at(
                    &inbox,
                    &format!("{}.bundle", r.name),
                    0o640,
                    gid,
                    &r.bundle,
                )?;
            }
            slot_fs::set_group(&inbox, gid)?;
            slot_fs::set_mode(&inbox, 0o750)?;
            slot_fs::set_group(&cur, gid)?;
            slot_fs::set_mode(&cur, 0o770)?;
            slot_fs::sync_dir(&cur)
        };
        if let Err(e) = fill() {
            let why = format!("slot {n}'s current/ couldn't be filled ({e})");
            let _ = to_trash(
                me,
                n,
                slot,
                Some(&cur),
                None,
                json!({"event": "not started", "why": why}),
            );
            return Err(why);
        }
        Ok(cur)
    }

    /// Registers the session with the service; the connection is the
    /// registration, held open for the session's life.
    fn register(
        me: &Launcher,
        n: u32,
        slot_uid: u32,
        agent: &str,
    ) -> Result<(UnixStream, String, String), String> {
        let path = &me.config.service.launcher_socket;
        let mut s =
            agent_sign::protocol::connect_waiting(path, Duration::from_secs(2)).map_err(|e| {
                format!(
                    "the agent-sign service at {} didn't answer ({e})",
                    path.display()
                )
            })?;
        let req = serde_json::to_string(&Request::RegisterSession {
            slot: n,
            uid: slot_uid,
            unit: session_unit(n),
            agent: agent.to_string(),
        })
        .map_err(|e| e.to_string())?;
        s.write_all(format!("{req}\n").as_bytes())
            .map_err(|e| format!("couldn't register the session ({e})"))?;
        let _ = s.set_read_timeout(Some(SERVICE_PATIENCE));
        let mut line = String::new();
        BufReader::new(s.try_clone().map_err(|e| e.to_string())?.take(64 * 1024))
            .read_line(&mut line)
            .map_err(|e| format!("the service didn't answer the registration ({e})"))?;
        let _ = s.set_read_timeout(None);
        match serde_json::from_str::<Response>(line.trim_end()) {
            Ok(Response::SessionStarted { principal, session })
                if launcher::is_session_id(&session) =>
            {
                Ok((s, session, principal))
            }
            Ok(Response::Error { message }) => Err(format!(
                "the agent-sign service refused the session: {message}"
            )),
            _ => Err(format!(
                "the service's answer to the registration can't be used: {}",
                line.trim()
            )),
        }
    }

    /// Writes the session's spec into slot n's existing spec file, in place
    /// (truncated, then written, synced; no new entry, no rename), and
    /// truncates its output file, so the output is only this session's.
    /// Returns the output file, to be read from its start. Done before the
    /// unit starts, so systemd (which opens both as root) finds them final.
    fn write_io(io: SlotIo, spec: &SessionSpec) -> Result<fs::File, String> {
        let SlotIo { spec: mut f, log } = io;
        let text = serde_json::to_string(spec).map_err(|e| e.to_string())?;
        f.set_len(0)
            .and_then(|()| f.seek(SeekFrom::Start(0)).map(|_| ()))
            .and_then(|()| f.write_all(text.as_bytes()))
            .and_then(|()| f.sync_all())
            .map_err(|e| format!("{SPECS}/{}.json: {e}", spec.slot))?;
        log.set_len(0)
            .and_then(|()| log.sync_all())
            .map_err(|e| format!("{LOGS}/{}.out: {e}", spec.slot))?;
        Ok(log)
    }

    /// Passes on what the session wrote since `at`. False once the caller
    /// can't be written to.
    fn pass_output(out: &mut Option<(fs::File, u64)>, conn: &mut UnixStream) -> bool {
        let Some((f, at)) = out.as_mut() else {
            return true;
        };
        if f.seek(SeekFrom::Start(*at)).is_err() {
            return true;
        }
        let mut buf = vec![0u8; OUTPUT_CHUNK];
        loop {
            match f.read(&mut buf) {
                Ok(0) | Err(_) => return true,
                Ok(k) => {
                    *at += k as u64;
                    let msg = LaunchResponse::Output {
                        data_b64: b64().encode(&buf[..k]),
                    };
                    if !send(conn, &msg) {
                        return false;
                    }
                }
            }
        }
    }

    /// What one session needs for its end.
    struct Running {
        n: u32,
        slot: OwnedFd,
        cur: OwnedFd,
        slot_uid: u32,
        session: Option<String>,
        principal: String,
        agent: String,
        by_uid: u32,
        repos: Vec<String>,
    }

    #[allow(clippy::too_many_arguments)]
    fn launch(
        me: &Arc<Launcher>,
        mut conn: UnixStream,
        incoming: Incoming,
        uid: u32,
        person: bool,
        agent: String,
        command: Vec<String>,
        env: BTreeMap<String, String>,
        repos: Vec<RepoIn>,
        approval: Option<ApprovalIn>,
    ) {
        let Incoming {
            mut lines,
            mut guard,
            bundles_follow,
        } = incoming;
        if let Err(e) = check_head(&agent, &command, &env, &repos, bundles_follow) {
            return refuse_free(guard, &mut conn, e);
        }
        let approved_repos: Vec<ApprovedRepo> = repos
            .iter()
            .map(|r| ApprovedRepo {
                name: r.name.clone(),
                base: r.base.clone(),
            })
            .collect();
        // The approval's nonce, reserved from the moment the approval verifies
        // until the launch ends or records it (re-check R2).
        let mut hold: Option<NonceHold<'_>> = None;
        let approved = if person {
            None
        } else {
            let Some(a) = approval else {
                return refuse_free(
                    guard,
                    &mut conn,
                    format!(
                        "uid {uid} isn't a person's account ([launcher] people_accounts), so it \
                         may launch only with a signed launch approval, and it sent none{}",
                        if me.approvers.is_empty() {
                            "; no key may sign one on this machine yet ([launcher] approvers is empty)"
                        } else {
                            ""
                        }
                    ),
                );
            };
            let asked = Asked {
                machine: &me.config.machine,
                agent: &agent,
                command: &command,
                repos: &approved_repos,
                now: launcher::now_secs(),
            };
            match launch_approval::check(&me.approvers, &a.text, &a.signature, &asked) {
                Ok(ok) => {
                    // Reserve the nonce now, before a single bundle byte is
                    // read: a second presentation of an approval that is
                    // being read, or was spent, is refused here and takes no
                    // bulk place (R2). Dropping `hold` on any way out before
                    // the slot is claimed gives the nonce back; the record
                    // itself is made under the slot lock.
                    let reserved = me.nonces.lock().unwrap().reserve(&ok.nonce);
                    if let Err(e) = reserved {
                        return refuse_free(guard, &mut conn, e);
                    }
                    hold = Some(NonceHold {
                        nonces: &me.nonces,
                        nonce: ok.nonce.clone(),
                    });
                    Some(ok)
                }
                Err(e) => return refuse_free(guard, &mut conn, e),
            }
        };
        // A caller over its hourly limit is refused here, before a bundle
        // byte is read; claim_slot checks again under the lock and counts.
        if let Err(e) = me.rate.lock().unwrap().check(
            uid,
            launcher::now_secs(),
            me.config.launcher.launches_per_hour,
        ) {
            return refuse_free((guard, hold), &mut conn, e);
        }
        // Only now, the head and the approval verified, bundle bytes.
        let mut repos = repos;
        // Whether this presentation was counted against the caller's hourly
        // allowance when it took a bulk place (re-check Q2).
        let mut charged = false;
        if bundles_follow {
            if !person {
                // A relayer's bundles are read in the relayers' own places; a
                // person's line already holds the people's (taken at the first
                // read), so a relayer never takes a person's.
                match me.relayed_bulk_places.take(uid) {
                    Ok(g) => guard = g,
                    Err(_) => {
                        return refuse_free(
                            (guard, hold),
                            &mut conn,
                            "the launcher is reading other bundles; try again".into(),
                        );
                    }
                }
                // Re-check Q2: every approval presentation that takes a bulk
                // place is charged one launch against the caller's
                // `launches_per_hour`, whether or not it ends in a launch, so
                // a holder of several valid approvals who presents them in a
                // loop (each time sending the head and leaving) runs out of
                // allowance instead of keeping both relayer places busy for
                // ever. The check and the count are under one lock, so
                // concurrent presentations can't both pass the last unit.
                {
                    let mut rate = me.rate.lock().unwrap();
                    let now = launcher::now_secs();
                    if let Err(e) = rate.check(uid, now, me.config.launcher.launches_per_hour) {
                        drop(rate);
                        return refuse_free((guard, hold), &mut conn, e);
                    }
                    rate.record(uid, now);
                    charged = true;
                }
            }
            let line = match lines.next(launcher::MAX_REQUEST_BYTES, deadline(BULK_DEADLINE)) {
                Ok(l) => l,
                Err(e) => {
                    return refuse_free(
                        (guard, hold),
                        &mut conn,
                        format!("the bundles didn't arrive: {e}"),
                    );
                }
            };
            let _ = conn.set_read_timeout(None);
            let bundles: LaunchBundles = match serde_json::from_str(line.trim_end()) {
                Ok(b) => b,
                Err(e) => {
                    return refuse_free(
                        (guard, hold),
                        &mut conn,
                        format!("the bundles can't be read ({e})"),
                    );
                }
            };
            drop(line);
            if bundles.bundles_b64.len() != repos.len() {
                return refuse_free(
                    (guard, hold),
                    &mut conn,
                    format!(
                        "{} bundles came for {} repositories",
                        bundles.bundles_b64.len(),
                        repos.len()
                    ),
                );
            }
            for (r, b) in repos.iter_mut().zip(bundles.bundles_b64) {
                r.bundle_b64 = b;
            }
        }
        drop(lines);
        let repos = match decode_repos(repos) {
            Ok(r) => r,
            Err(e) => return refuse_free((guard, hold), &mut conn, e),
        };
        let (n, io) = match claim_slot(me, uid, approved.as_ref(), charged) {
            Ok(c) => c,
            Err(e) => return refuse_free((guard, hold), &mut conn, e),
        };
        // The nonce is recorded: the reservation has nothing left to guard.
        drop(hold);
        // From here on the slot is claimed: every way out ends the session.
        let account = format!("{}{n}", me.config.slots.account_prefix);
        let slot_uid = match me.kernel.account_uid(&account) {
            Ok(Some(u)) => u,
            Ok(None) => {
                release_slot(me, n);
                return refuse_free(
                    guard,
                    &mut conn,
                    format!("slot {n}'s account, {account}, doesn't exist"),
                );
            }
            Err(e) => {
                release_slot(me, n);
                return refuse_free(guard, &mut conn, e);
            }
        };
        let (slot, gid) = match open_slot(me, n) {
            Ok(s) => s,
            Err(e) => {
                // The slot's folder is wrong: it stays out of use.
                eprintln!("[agent-launchd] slot {n} stays out of use: {e}");
                return refuse_free(guard, &mut conn, e);
            }
        };
        let cur = match prepare(me, n, &slot, gid, &repos) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[agent-launchd] slot {n} stays out of use: {e}");
                return refuse_free(guard, &mut conn, e);
            }
        };
        // The bundles are on disk: this request holds no more of the launcher's
        // memory than the rest of a session.
        drop(guard);
        let mut run = Running {
            n,
            slot,
            cur,
            slot_uid,
            session: None,
            principal: String::new(),
            agent: agent.clone(),
            by_uid: uid,
            repos: repos.iter().map(|r| r.name.clone()).collect(),
        };
        drop(repos);
        let (registration, session, principal) = match register(me, n, slot_uid, &agent) {
            Ok(r) => r,
            Err(e) => {
                refuse(&mut conn, format!("{e}; nothing was started"));
                finish(
                    me,
                    run,
                    Ending {
                        registration: None,
                        caller: None,
                        ran: false,
                        stop: false,
                        ended_by: "not registered",
                    },
                );
                return;
            }
        };
        run.session = Some(session.clone());
        run.principal = principal.clone();
        let spec = SessionSpec {
            session: session.clone(),
            principal: principal.clone(),
            agent,
            slot: n,
            command,
            env,
            repos: approved_repos,
        };
        let log = match write_io(io, &spec) {
            Ok(log) => log,
            Err(e) => {
                refuse(
                    &mut conn,
                    format!("the session's spec can't be written ({e}); nothing was started"),
                );
                finish(
                    me,
                    run,
                    Ending {
                        registration: Some(registration),
                        caller: None,
                        ran: false,
                        stop: false,
                        ended_by: "spec not written",
                    },
                );
                return;
            }
        };
        // The output is read from its start: it was truncated just now.
        let mut output = Some((log, 0u64));
        let unit = session_unit(n);
        if let Err(e) = me.systemd.start(&unit) {
            refuse(&mut conn, format!("{e}; the session didn't start"));
            finish(
                me,
                run,
                Ending {
                    registration: Some(registration),
                    caller: None,
                    ran: true,
                    stop: true,
                    ended_by: "unit not started",
                },
            );
            return;
        }
        eprintln!(
            "[agent-launchd] slot {n}: session {session} ({principal}) started for uid {uid}"
        );
        if !send(
            &mut conn,
            &LaunchResponse::Launched {
                session: session.clone(),
                slot: n,
                principal,
            },
        ) {
            finish(
                me,
                run,
                Ending {
                    registration: Some(registration),
                    caller: None,
                    ran: true,
                    stop: true,
                    ended_by: "the caller went away",
                },
            );
            return;
        }
        // The caller's going is the session's end.
        let gone = Arc::new(AtomicBool::new(false));
        if let Ok(mut reader) = conn.try_clone() {
            let gone = Arc::clone(&gone);
            thread::spawn(move || {
                let mut buf = [0u8; 256];
                loop {
                    match reader.read(&mut buf) {
                        Ok(0) => break,
                        Ok(_) => continue,
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(_) => break,
                    }
                }
                gone.store(true, Ordering::SeqCst);
            });
        }
        let started = Instant::now();
        let mut ended_by = "the program ended";
        let mut caller = Some(conn);
        loop {
            if !me.systemd.is_active(&unit).unwrap_or(true) {
                break;
            }
            if gone.load(Ordering::SeqCst) {
                ended_by = "the caller went away";
                caller = None;
                break;
            }
            if started.elapsed() >= me.max_duration {
                ended_by = "it reached [slots] max_duration";
                break;
            }
            if let Some(c) = caller.as_mut()
                && !pass_output(&mut output, c)
            {
                ended_by = "the caller went away";
                caller = None;
                break;
            }
            thread::sleep(POLL);
        }
        let stop = ended_by != "the program ended";
        eprintln!("[agent-launchd] slot {n}: session {session} ending: {ended_by}");
        let caller = caller.map(|c| (c, output));
        finish(
            me,
            run,
            Ending {
                registration: Some(registration),
                caller,
                ran: true,
                stop,
                ended_by,
            },
        );
    }

    /// Ends a session whose slot is claimed (see the module documentation,
    /// step 6). `stop` asks the unit to stop first.
    /// How a session is ended (see [`finish`]).
    struct Ending<'a> {
        /// The registration with the service, closed first.
        registration: Option<UnixStream>,
        /// The caller, still connected, and the session's output.
        caller: Option<(UnixStream, Option<(fs::File, u64)>)>,
        /// Whether the unit was (or may have been) started: only then is
        /// it waited for, and the end step run.
        ran: bool,
        /// Whether the unit must be asked to stop.
        stop: bool,
        ended_by: &'a str,
    }

    fn finish(me: &Arc<Launcher>, run: Running, how: Ending<'_>) {
        let Ending {
            registration,
            caller,
            ran,
            stop,
            ended_by,
        } = how;
        let n = run.n;
        // 1. Nothing in the slot can get a signature from now on.
        drop(registration);
        let (mut conn, mut output) = match caller {
            Some((c, o)) => (Some(c), o),
            None => (None, None),
        };
        // 2. The unit stops, and every process in it.
        let unit = session_unit(n);
        let mut last_stop: Option<Instant> = None;
        let mut said = Instant::now();
        let mut waiting = ran;
        while waiting {
            let active = match me.systemd.is_active(&unit) {
                Ok(a) => a,
                Err(e) => {
                    if said.elapsed() > Duration::from_secs(60) {
                        eprintln!("[agent-launchd] slot {n}: {e}; waiting");
                        said = Instant::now();
                    }
                    true
                }
            };
            if !active {
                waiting = false;
                continue;
            }
            if stop && last_stop.is_none_or(|t| t.elapsed() >= STOP_AGAIN) {
                if let Err(e) = me.systemd.stop(&unit) {
                    eprintln!("[agent-launchd] slot {n}: {e}");
                }
                last_stop = Some(Instant::now());
            }
            if let Some(c) = conn.as_mut()
                && !pass_output(&mut output, c)
            {
                conn = None;
            }
            thread::sleep(POLL);
        }
        // 3. The end step, as the slot's account, in a unit of its own.
        let end = end_unit(n);
        if ran {
            match me.systemd.start(&end) {
                Ok(()) => {
                    while me.systemd.is_active(&end).unwrap_or(true) {
                        thread::sleep(POLL);
                    }
                }
                Err(e) => eprintln!("[agent-launchd] slot {n}: the end step didn't run ({e})"),
            }
        }
        if let Some(c) = conn.as_mut()
            && !pass_output(&mut output, c)
        {
            conn = None;
        }
        // 4. What it left, read refusing links.
        let owner = launcher::slot_file_owner(run.slot_uid);
        let mut problems = Vec::new();
        let status = match slot_fs::read_beneath(
            &run.cur,
            &format!("{OUT}/{STATUS_FILE}"),
            owner,
            launcher::MAX_STATUS_BYTES,
        ) {
            Ok(Some(bytes)) => match serde_json::from_slice::<serde_json::Value>(&bytes) {
                Ok(v) if v.is_object() => v,
                _ => json!("the end step's status.json isn't a JSON object"),
            },
            Ok(None) => json!("the end step left no status"),
            Err(e) => {
                problems.push(e.clone());
                json!(format!("the end step's status wasn't read: {e}"))
            }
        };
        let mut bundles = Vec::new();
        for name in &run.repos {
            match slot_fs::read_beneath(
                &run.cur,
                &format!("{OUT}/{name}.bundle"),
                owner,
                launcher::MAX_BUNDLE_BYTES,
            ) {
                Ok(Some(bytes)) if launcher::looks_like_bundle(&bytes) => {
                    bundles.push((name.clone(), bytes))
                }
                Ok(Some(_)) => problems.push(format!(
                    "{OUT}/{name}.bundle isn't a git bundle: not returned"
                )),
                Ok(None) => {}
                Err(e) => problems.push(e),
            }
        }
        // 5. The folder goes to the Trash, always; with it the slot is
        // free again.
        let entry = json!({
            "event": "ended",
            "session": run.session,
            "principal": run.principal,
            "agent": run.agent,
            "launched_by_uid": run.by_uid,
            "ended_by": ended_by,
            "status": status,
            "problems": problems,
        });
        // The move and the slot's release are one step under the slot lock:
        // nobody can see the folder in the Trash and still find the slot
        // taken, or find it free while its folder is still `current/`.
        let trashed = {
            let mut busy = me.busy.lock().unwrap();
            let r = to_trash(
                me,
                n,
                &run.slot,
                Some(&run.cur),
                run.session.as_deref(),
                entry,
            );
            if r.is_ok() {
                busy[n as usize - 1] = false;
            }
            r
        };
        if let Err(e) = &trashed {
            eprintln!("[agent-launchd] slot {n} stays out of use until the launcher restarts: {e}");
        }
        let returned: Vec<BundleOut> = bundles
            .iter()
            .map(|(name, bytes)| BundleOut {
                name: name.clone(),
                bundle_b64: b64().encode(bytes),
            })
            .collect();
        let delivered = match (conn.as_mut(), &run.session) {
            (Some(c), Some(_)) if trashed.is_ok() => send(
                c,
                &LaunchResponse::Ended {
                    status: status_with(&status, &problems),
                    bundles: returned.clone(),
                },
            ),
            (Some(c), _) => {
                let _ = send(
                    c,
                    &LaunchResponse::Error {
                        message: format!(
                            "the session ended ({ended_by}){}",
                            trashed
                                .as_ref()
                                .err()
                                .map(|e| format!(", and its folder wasn't moved to the Trash: {e}"))
                                .unwrap_or_default()
                        ),
                    },
                );
                false
            }
            (None, _) => false,
        };
        if !delivered
            && !returned.is_empty()
            && let Some(session) = &run.session
        {
            keep_for_collect(me, session, run.by_uid, &status, &bundles);
        }
    }

    fn status_with(status: &serde_json::Value, problems: &[String]) -> serde_json::Value {
        if problems.is_empty() {
            return status.clone();
        }
        let mut s = status.clone();
        if let Some(o) = s.as_object_mut() {
            o.insert("launcher".into(), json!(problems));
            return s;
        }
        json!({"end_step": status, "launcher": problems})
    }

    /// Keeps a session's bundles for `agent-sign launch --collect`, in the
    /// launcher's own state, with the uid that launched it.
    fn keep_for_collect(
        me: &Launcher,
        session: &str,
        by_uid: u32,
        status: &serde_json::Value,
        bundles: &[(String, Vec<u8>)],
    ) {
        let dir = me.state.join(RETURNED).join(session);
        let write = || -> std::io::Result<()> {
            fs::create_dir(&dir)?;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
            let put = |name: &str, bytes: &[u8]| -> std::io::Result<()> {
                let mut f = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(dir.join(name))?;
                f.write_all(bytes)?;
                f.sync_all()
            };
            for (name, bytes) in bundles {
                put(&format!("{name}.bundle"), bytes)?;
            }
            put(STATUS_FILE, status.to_string().as_bytes())?;
            put("owner", by_uid.to_string().as_bytes())
        };
        match write() {
            Ok(()) => eprintln!(
                "[agent-launchd] session {session}'s bundles are kept for `agent-sign launch --collect {session}`"
            ),
            Err(e) => {
                eprintln!("[agent-launchd] session {session}'s bundles couldn't be kept ({e})")
            }
        }
    }

    /// `Collect`: a session's kept bundles, for the uid that launched it.
    fn collect(me: &Launcher, mut conn: UnixStream, uid: u32, session: &str) {
        if !launcher::is_session_id(session) {
            return refuse(&mut conn, format!("{session:?} isn't a session id"));
        }
        let dir = me.state.join(RETURNED).join(session);
        let owner = fs::read_to_string(dir.join("owner"))
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok());
        if owner != Some(uid) {
            return refuse(
                &mut conn,
                format!("no bundles are kept for session {session} for uid {uid}"),
            );
        }
        let status = fs::read(dir.join(STATUS_FILE))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_else(|| json!("no status was kept"));
        let mut bundles = Vec::new();
        if let Ok(rd) = fs::read_dir(&dir) {
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                if let Some(repo) = name.strip_suffix(".bundle")
                    && let Ok(bytes) = fs::read(e.path())
                {
                    bundles.push(BundleOut {
                        name: repo.to_string(),
                        bundle_b64: b64().encode(bytes),
                    });
                }
            }
        }
        let _ = send(&mut conn, &LaunchResponse::Ended { status, bundles });
    }

    /// At start: every slot with a unit still active, or a `current/` left
    /// behind, is held, its session unit stopped, and once both its units
    /// are inactive its folder goes to the Trash; only then is it free.
    fn sweep_at_start(me: &Arc<Launcher>) {
        let count = me.busy.lock().unwrap().len() as u32;
        for n in 1..=count {
            let unit = session_unit(n);
            let end = end_unit(n);
            let active = |u: &str| me.systemd.is_active(u).unwrap_or(true);
            let leftover = slot_fs::open_dir_at(&me.slots_root, &n.to_string())
                .ok()
                .and_then(|s| slot_fs::stat_at(&s, CURRENT).ok().flatten())
                .is_some();
            if !(active(&unit) || active(&end) || leftover) {
                continue;
            }
            me.busy.lock().unwrap()[n as usize - 1] = true;
            let me = Arc::clone(me);
            thread::spawn(move || {
                let mut last_stop: Option<Instant> = None;
                while me.systemd.is_active(&unit).unwrap_or(true) {
                    if last_stop.is_none_or(|t| t.elapsed() >= STOP_AGAIN) {
                        let _ = me.systemd.stop(&unit);
                        last_stop = Some(Instant::now());
                    }
                    thread::sleep(POLL);
                }
                while me.systemd.is_active(&end).unwrap_or(true) {
                    thread::sleep(POLL);
                }
                let mut busy = me.busy.lock().unwrap();
                let moved = match open_slot(&me, n) {
                    Ok((slot, _)) => match slot_fs::stat_at(&slot, CURRENT) {
                        Ok(None) => Ok(()),
                        Ok(Some(_)) => to_trash(
                            &me,
                            n,
                            &slot,
                            None,
                            None,
                            json!({"event": "swept", "why": "the launcher restarted"}),
                        )
                        .map(|_| ()),
                        Err(e) => Err(e.to_string()),
                    },
                    Err(e) => Err(e),
                };
                match moved {
                    Ok(()) => busy[n as usize - 1] = false,
                    Err(e) => eprintln!("[agent-launchd] slot {n} stays out of use: {e}"),
                }
            });
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn one_account_holds_at_most_its_cap_and_the_rest_are_for_others() {
            let pool = Places::new(MAX_OTHERS_READING, Some(MAX_OTHERS_PER_UID));
            let mut mine: Vec<Place> = (0..MAX_OTHERS_PER_UID)
                .map(|_| pool.take(7).expect("the account's own share"))
                .collect();
            assert_eq!(
                pool.take(7).err(),
                Some(Turned::AccountCap(MAX_OTHERS_PER_UID))
            );
            // Other accounts still get places, up to the pool's size; then
            // the pool, not the account, is the reason.
            let others: Vec<Place> = (0..MAX_OTHERS_READING - MAX_OTHERS_PER_UID)
                .map(|i| pool.take(100 + i as u32).expect("another account"))
                .collect();
            assert_eq!(pool.take(200).err(), Some(Turned::Full));
            // A place given back is free again, for its account and for others.
            mine.pop();
            assert!(pool.take(7).is_ok());
            drop(others);
            assert!(pool.take(200).is_ok());
        }

        #[test]
        fn the_peoples_places_and_the_relayers_are_separate_pools() {
            let relayers = Places::new(MAX_RELAYED_BULK_READING, None);
            let people = Places::new(MAX_PEOPLE_BULK_READING, None);
            let held: Vec<Place> = (0..MAX_RELAYED_BULK_READING)
                .map(|_| relayers.take(1001).expect("a relayer's place"))
                .collect();
            assert_eq!(relayers.take(1001).err(), Some(Turned::Full));
            assert!(people.take(1000).is_ok(), "a person was kept out");
            drop(held);
        }

        #[test]
        fn a_dropped_place_leaves_no_trace_of_its_account() {
            let pool = Places::new(2, Some(1));
            drop(pool.take(5).unwrap());
            assert!(pool.held.lock().unwrap().by_uid.is_empty());
            assert_eq!(pool.held.lock().unwrap().total, 0);
        }
    }
}
