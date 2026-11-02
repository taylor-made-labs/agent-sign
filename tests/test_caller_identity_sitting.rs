//! Caller identity, the part that needs the server sitting: separate
//! accounts for agent-sign, the launcher and each agent session.
//!
//! The properties and the design are in `test_caller_identity.rs` and
//! `docs/caller-identity.md`. The tests here check what one account can't
//! show: that the agents account (`agents` on hetzner) can't reach
//! agent-sign's keys, config, trust store, authority history or process
//! (P3), can't read a launched session (P4), can't launch a session of its
//! own (P1), and gets no attested signature from the real service (P1, P7).
//!
//! **Every test is marked `#[ignore = "needs the server sitting: ..."]`**:
//! a plain `cargo test` lists them as ignored, never as passed. Run them on
//! the server, as the agents account, after the sitting:
//!
//! ```text
//! cargo test --test test_caller_identity_sitting -- --ignored
//! ```
//!
//! When a test finds the sitting hasn't happened (no agent-sign account, no
//! service running in it, no launched session), it fails with "NEEDS THE
//! SERVER SITTING" and what is missing. It never passes for lack of
//! something to check.
//!
//! What the sitting provides, with the names these tests look for (each can
//! be changed with the environment variable after it):
//! - an `agent-sign` account (`AGENT_SIGN_SITTING_SERVICE_ACCOUNT`) whose
//!   home holds agent-sign's state (`~/.agent-sign`), with the service
//!   running as that account under the system unit `agent-signd.service`
//!   (`AGENT_SIGN_SITTING_UNIT`);
//! - an `agent-launch` account (`AGENT_SIGN_SITTING_LAUNCHER_ACCOUNT`) for
//!   the launcher, which starts each session in a static slot account of
//!   its own, `agent-slot-<n>` (prefix `AGENT_SIGN_SITTING_SLOT_PREFIX`;
//!   D6, 1 Nov 2026: not a DynamicUser);
//! - the machine's trust file `/etc/agent-sign/allowed_signers`
//!   (`AGENT_SIGN_SITTING_TRUST_FILE`), which git's verifiers name;
//! - this machine's label `hetzner` (`AGENT_SIGN_SITTING_MACHINE`);
//! - for the P4 test, one session started through the launcher and still
//!   running, so at least one process runs in a slot account.
//!
//! Nothing here needs root, and nothing here writes outside a temporary
//! directory: every write attempted on agent-sign's state is one that must
//! fail.

#![cfg(target_os = "linux")]

use std::fs;
use std::io::{BufRead, BufReader, ErrorKind, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use serde_json::json;
use sha2::{Digest, Sha256};
use tempfile::tempdir;

use agent_sign::protocol::Response;

fn setting(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

struct Account {
    name: String,
    uid: u32,
    home: PathBuf,
}

fn account(name: &str) -> Option<Account> {
    let passwd = fs::read_to_string("/etc/passwd").ok()?;
    passwd.lines().find_map(|line| {
        let f: Vec<&str> = line.split(':').collect();
        (f.len() >= 6 && f[0] == name).then(|| Account {
            name: name.to_string(),
            uid: f[2].parse().unwrap_or(u32::MAX),
            home: PathBuf::from(f[5]),
        })
    })
}

/// The uids of the accounts whose names start with `prefix`: the launcher's
/// slot accounts (`agent-slot-1`, `agent-slot-2`, ...).
fn uids_with_prefix(prefix: &str) -> Vec<u32> {
    assert!(
        !prefix.is_empty(),
        "an empty slot account prefix would match every account"
    );
    fs::read_to_string("/etc/passwd")
        .unwrap_or_default()
        .lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split(':').collect();
            if f.len() >= 3 && f[0].starts_with(prefix) {
                f[2].parse().ok()
            } else {
                None
            }
        })
        .collect()
}

fn my_uid() -> u32 {
    // SAFETY: getuid takes no arguments and can't fail.
    unsafe { libc::getuid() }
}

/// The agent-sign account, after checking this is a sitting to test: run
/// as an ordinary account other than agent-sign's.
fn service_account() -> Account {
    let me = my_uid();
    assert!(
        me != 0,
        "run these tests as the agents account, not as root: root can read everything"
    );
    let name = setting("AGENT_SIGN_SITTING_SERVICE_ACCOUNT", "agent-sign");
    let acct = account(&name).unwrap_or_else(|| {
        panic!(
            "NEEDS THE SERVER SITTING: there is no `{name}` account on this machine, so agent-sign \
             still runs in the agents' own account and nothing here can hold"
        )
    });
    assert!(
        acct.uid != me,
        "run these tests as the agents account, not as `{name}` itself"
    );
    acct
}

fn uid_of(pid: u32) -> Option<u32> {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    status
        .lines()
        .find(|l| l.starts_with("Uid:"))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

fn pids_where(f: impl Fn(u32, u32) -> bool) -> Vec<u32> {
    let mut pids = Vec::new();
    for entry in fs::read_dir("/proc").into_iter().flatten().flatten() {
        if let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>()
            && let Some(uid) = uid_of(pid)
            && f(pid, uid)
        {
            pids.push(pid);
        }
    }
    pids
}

/// Everything an ordinary process might try on another's: each `(what,
/// managed)` it managed.
fn intrusions(pid: u32) -> Vec<String> {
    let mut got = Vec::new();
    if fs::read(format!("/proc/{pid}/environ")).is_ok_and(|e| !e.is_empty()) {
        got.push("read its environment".to_string());
    }
    if fs::read_dir(format!("/proc/{pid}/fd")).is_ok_and(|mut d| d.next().is_some()) {
        got.push("listed its open files".to_string());
    }
    if let Ok(maps) = fs::read_to_string(format!("/proc/{pid}/maps"))
        && let Some(start) = maps
            .lines()
            .next()
            .and_then(|l| l.split('-').next())
            .and_then(|h| u64::from_str_radix(h, 16).ok())
        && let Ok(mem) = fs::File::open(format!("/proc/{pid}/mem"))
    {
        use std::os::unix::fs::FileExt;
        let mut buf = [0u8; 16];
        if mem.read_at(&mut buf, start).is_ok() {
            got.push("read its memory".to_string());
        }
    }
    // SAFETY: plain syscalls on integers; every descriptor returned is closed.
    unsafe {
        let pidfd = libc::syscall(libc::SYS_pidfd_open, pid as libc::c_int, 0) as libc::c_int;
        if pidfd >= 0 {
            for target in 0..16 {
                let fd = libc::syscall(libc::SYS_pidfd_getfd, pidfd, target, 0) as libc::c_int;
                if fd >= 0 {
                    libc::close(fd);
                    got.push(format!("took its descriptor {target}"));
                }
            }
            libc::close(pidfd);
        }
        if libc::kill(pid as libc::pid_t, 0) == 0 {
            got.push("could signal it".to_string());
        }
    }
    got
}

fn session8(session: &str) -> String {
    Sha256::digest(session.as_bytes())[..4]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn trust_file() -> PathBuf {
    let file = PathBuf::from(setting(
        "AGENT_SIGN_SITTING_TRUST_FILE",
        "/etc/agent-sign/allowed_signers",
    ));
    assert!(
        fs::read_to_string(&file).is_ok(),
        "NEEDS THE SERVER SITTING: the machine's trust file {} doesn't exist or isn't readable",
        file.display()
    );
    file
}

fn domain() -> String {
    format!(
        "{}.agents.local",
        setting("AGENT_SIGN_SITTING_MACHINE", "hetzner")
    )
}

fn ask_at(socket: &Path, request: serde_json::Value) -> Option<Response> {
    let mut stream = UnixStream::connect(socket).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .ok()?;
    writeln!(stream, "{request}").ok()?;
    let mut line = String::new();
    BufReader::new(&stream).read_line(&mut line).ok()?;
    serde_json::from_str(&line).ok()
}

/// A throwaway repository with one commit, and a commit buffer for a new
/// commit on it by `principal`.
fn repo_and_buffer(dir: &Path, principal: &str) -> (String, Vec<u8>) {
    let git = |args: &[&str]| {
        let out = Command::new(agent_sign::paths::real_git())
            .args(args)
            .current_dir(dir)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .unwrap();
        assert!(out.status.success(), "setup git {args:?}");
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };
    git(&["init", "-q", "-b", "work"]);
    fs::write(dir.join("a.txt"), "a\n").unwrap();
    git(&["add", "a.txt"]);
    git(&[
        "-c",
        "user.name=t",
        "-c",
        "user.email=t@example.com",
        "commit",
        "-q",
        "-m",
        "a",
    ]);
    let head = git(&["rev-parse", "HEAD"]);
    let tree = git(&["rev-parse", "HEAD^{tree}"]);
    let now = now_secs();
    let ident = format!("Claude Code <{principal}>");
    let buffer = format!(
        "tree {tree}\nparent {head}\nauthor {ident} {now} +0000\ncommitter {ident} {now} +0000\n\nsitting\n"
    );
    (
        fs::canonicalize(dir)
            .unwrap()
            .to_string_lossy()
            .into_owned(),
        buffer.into_bytes(),
    )
}

/// Every signature `socket` gives a process that asks, in its own words,
/// for `principal`.
fn signatures_claiming(socket: &Path, repo: &str, principal: &str, buffer: &[u8]) -> Vec<String> {
    let _ = ask_at(
        socket,
        json!({"type": "RequestLease", "payload": {"repo": repo, "branch": "work", "intent": "sitting", "duration_secs": null}}),
    );
    let identity = json!({"slug": "claude-code", "name": "Claude Code", "principal": principal});
    let b64 = base64::engine::general_purpose::STANDARD.encode(buffer);
    let mut sigs = Vec::new();
    for kind in ["IssueIdentifiedToken", "IssueRunToken"] {
        if let Some(Response::TokenIssued { token }) = ask_at(
            socket,
            json!({"type": kind, "payload": {"repo": repo, "branch": "work", "identity": identity}}),
        ) && let Some(Response::Signed { signature_pem }) = ask_at(
            socket,
            json!({"type": "SignCommit", "payload": {"token": token, "buffer_b64": b64, "repo": repo, "branch": "work"}}),
        ) {
            sigs.push(signature_pem);
        }
    }
    sigs
}

fn good_under(trust: &Path, principal: &str, sig: &str, data: &[u8], scratch: &Path) -> bool {
    let sig_file = scratch.join("check.sig");
    fs::write(&sig_file, sig).unwrap();
    let mut child = Command::new("ssh-keygen")
        .args(["-Y", "verify", "-n", "git", "-I", principal, "-f"])
        .arg(trust)
        .arg("-s")
        .arg(&sig_file)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(data).unwrap();
    child.wait().unwrap().success()
}

// ===========================================================================

/// P3. From the agents account, agent-sign's state directory and what's in
/// it (config, keys, authority history, leases) can't be read, changed or
/// added to, and the machine's trust file can be read (verifiers need it)
/// but not changed.
#[test]
#[ignore = "needs the server sitting: an agent-sign account holding agent-sign's state"]
fn sitting_p3_the_agents_account_cant_read_or_change_agent_signs_state() {
    let acct = service_account();
    let state = agent_sign::paths::state_dir_in(&acct.home);
    match fs::symlink_metadata(&state) {
        Err(e) if e.kind() == ErrorKind::NotFound => panic!(
            "NEEDS THE SERVER SITTING: no agent-sign state at {} (agent-sign isn't installed in \
             the `{}` account yet)",
            state.display(),
            acct.name
        ),
        Err(_) => {} // Not even reachable: the strongest answer.
        Ok(meta) => assert_eq!(
            meta.uid(),
            acct.uid,
            "P3: agent-sign's state directory {} doesn't belong to `{}`",
            state.display(),
            acct.name
        ),
    }
    let mut breaches = Vec::new();
    for name in ["config.toml", "leases.json", "keys/agents_cas.pub", "keys"] {
        let path = state.join(name);
        if fs::read(&path).is_ok() || fs::read_dir(&path).is_ok() {
            breaches.push(format!("read {}", path.display()));
        }
        if fs::OpenOptions::new().append(true).open(&path).is_ok() {
            breaches.push(format!("opened {} for writing", path.display()));
        }
    }
    for dir in [state.clone(), state.join("keys")] {
        let probe = dir.join(format!("sitting-probe-{}", std::process::id()));
        if fs::write(&probe, "").is_ok() {
            let _ = fs::remove_file(&probe);
            breaches.push(format!("created a file in {}", dir.display()));
        }
    }
    let trust = trust_file();
    if fs::OpenOptions::new().append(true).open(&trust).is_ok() {
        breaches.push(format!(
            "opened the trust file {} for writing",
            trust.display()
        ));
    }
    assert!(
        breaches.is_empty(),
        "P3: the agents account {}",
        breaches.join("; ")
    );
}

/// P3. The service runs as the agent-sign account, and the agents account
/// can't read its environment, files or memory, take its descriptors,
/// signal it, or restart its unit.
#[test]
#[ignore = "needs the server sitting: agent-signd running as the agent-sign account"]
fn sitting_p3_the_agents_account_cant_reach_the_service_process() {
    let acct = service_account();
    let pids = pids_where(|_, uid| uid == acct.uid);
    assert!(
        !pids.is_empty(),
        "NEEDS THE SERVER SITTING: no process runs as `{}` (the service isn't running in its own account)",
        acct.name
    );
    for pid in pids {
        let got = intrusions(pid);
        assert!(
            got.is_empty(),
            "P3: the agents account reached agent-sign's process {pid}: {}",
            got.join(", ")
        );
    }
    let unit = setting("AGENT_SIGN_SITTING_UNIT", "agent-signd.service");
    let restart = Command::new("systemctl")
        .args(["--no-ask-password", "restart", &unit])
        .output()
        .unwrap();
    assert!(
        !restart.status.success(),
        "P3: the agents account restarted {unit}"
    );
}

/// P3. A service the agents account starts itself, whether with its own
/// HOME or pointed at agent-sign's, changes nothing verifiers trust, and its
/// signatures are Good for no principal under the machine's trust file.
#[test]
#[ignore = "needs the server sitting: an agent-sign account and the machine's trust file"]
fn sitting_p3_a_service_the_agents_account_starts_is_trusted_by_no_verifier() {
    let acct = service_account();
    let trust = trust_file();
    let before = fs::read_to_string(&trust).unwrap();
    let scratch = tempdir().unwrap();
    let principal = format!("claude-code.{}@{}", session8("sitting-rogue"), domain());
    for home in [scratch.path().join("home"), acct.home.clone()] {
        fs::create_dir_all(scratch.path().join("home/.agent-sign")).unwrap();
        let _ = fs::write(
            scratch.path().join("home/.agent-sign/config.toml"),
            format!(
                "[identity]\nmachine = \"{}\"\n",
                setting("AGENT_SIGN_SITTING_MACHINE", "hetzner")
            ),
        );
        let socket = scratch.path().join("rogue.sock");
        let _ = fs::remove_file(&socket);
        let mut child = Command::new(env!("CARGO_BIN_EXE_agent-signd"))
            .arg("--socket")
            .arg(&socket)
            .arg("--auto-approve")
            .env("HOME", &home)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let start = Instant::now();
        while !socket.exists() && start.elapsed() < Duration::from_secs(10) {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let repo_dir = scratch.path().join(format!("repo-{}", now_secs()));
        fs::create_dir_all(&repo_dir).unwrap();
        let (repo, buffer) = repo_and_buffer(&repo_dir, &principal);
        let sigs = if socket.exists() {
            signatures_claiming(&socket, &repo, &principal, &buffer)
        } else {
            Vec::new()
        };
        let _ = child.kill();
        let _ = child.wait();
        for sig in sigs {
            assert!(
                !good_under(&trust, &principal, &sig, &buffer, scratch.path()),
                "P3: a service the agents account started (HOME {}) signed as {principal}, Good under \
                 the machine's trust file",
                home.display()
            );
        }
        assert_eq!(
            fs::read_to_string(&trust).unwrap(),
            before,
            "P3: a service the agents account started (HOME {}) changed the machine's trust file",
            home.display()
        );
    }
}

/// P1 and P7. A plain process of the agents account asks the real service
/// (on its socket in agent-sign's state, if the account can reach it at
/// all) for signatures as a session: none is Good under the machine's trust
/// file. The service sees the caller's uid (SO_PEERCRED), which no launcher
/// gave a session, so whatever it claims, it isn't one.
#[test]
#[ignore = "needs the server sitting: agent-signd in its own account, reading peer credentials"]
fn sitting_p1_p7_a_plain_agents_process_gets_no_attested_signature_from_the_service() {
    let acct = service_account();
    let trust = trust_file();
    let socket = PathBuf::from(setting(
        "AGENT_SIGN_SITTING_SOCKET",
        &agent_sign::paths::state_dir_in(&acct.home)
            .join("daemon.sock")
            .to_string_lossy(),
    ));
    let scratch = tempdir().unwrap();
    let principal = format!("claude-code.{}@{}", session8("sitting-plain"), domain());
    let (repo, buffer) = repo_and_buffer(scratch.path(), &principal);
    for sig in signatures_claiming(&socket, &repo, &principal, &buffer) {
        assert!(
            !good_under(&trust, &principal, &sig, &buffer, scratch.path()),
            "P1/P7: the real service signed, Good as {principal}, for a plain process of the agents account"
        );
    }
}

/// P4. Every launched session runs under an account of its own, a static
/// slot account (`agent-slot-<n>`), and the agents account can't read its
/// environment, files or memory, take its descriptors (its signing channel
/// among them) or signal it.
///
/// DELIBERATE EVAL CHANGE (D6, 1 Nov 2026): static slot accounts, not
/// DynamicUser. Sessions are found by the slot account prefix instead of the
/// DynamicUser uid range, and the test requires at least one process in a
/// slot account. Before this, the launcher's own process alone satisfied the
/// test's "a session is running" check, so it could pass with no session
/// checked. The intrusion checks themselves are unchanged and still run on
/// the launcher's process too.
#[test]
#[ignore = "needs the server sitting: the launcher in its own account, and one launched session running"]
fn sitting_p4_the_agents_account_cant_reach_a_launched_session() {
    let _ = service_account();
    let launcher = setting("AGENT_SIGN_SITTING_LAUNCHER_ACCOUNT", "agent-launch");
    let launcher_uid = account(&launcher).map(|a| a.uid).unwrap_or_else(|| {
        panic!("NEEDS THE SERVER SITTING: there is no `{launcher}` account for the launcher")
    });
    // DELIBERATE EVAL CHANGE (D6, 1 Nov 2026): static slot accounts, not DynamicUser
    let prefix = setting("AGENT_SIGN_SITTING_SLOT_PREFIX", "agent-slot-");
    let slot_uids = uids_with_prefix(&prefix);
    assert!(
        !pids_where(|_, uid| slot_uids.contains(&uid)).is_empty(),
        "NEEDS THE SERVER SITTING: no launched session is running (no process runs in an \
         `{prefix}` account; {} such accounts exist); start one through the launcher, then run \
         this test",
        slot_uids.len()
    );
    let sessions = pids_where(|_, uid| uid == launcher_uid || slot_uids.contains(&uid));
    for pid in sessions {
        let got = intrusions(pid);
        assert!(
            got.is_empty(),
            "P4: the agents account reached launched process {pid} (uid {:?}): {}",
            uid_of(pid),
            got.join(", ")
        );
    }
}

/// P1. The agents account can't start a session itself: `agent-sign
/// launch` run by it, as any agent, doesn't run its program as a session
/// (only the launcher's own callers, the person or an approved job, can).
#[test]
#[ignore = "needs the server sitting: the launcher in its own account"]
fn sitting_p1_the_agents_account_cant_launch_a_session_itself() {
    let _ = service_account();
    let launcher = setting("AGENT_SIGN_SITTING_LAUNCHER_ACCOUNT", "agent-launch");
    assert!(
        account(&launcher).is_some(),
        "NEEDS THE SERVER SITTING: there is no `{launcher}` account for the launcher"
    );
    let probe = "sitting-launch-probe";
    let out = Command::new(env!("CARGO_BIN_EXE_agent-sign"))
        .args(["launch", "--agent", "codex", "--", "/bin/sh", "-c"])
        .arg(format!("echo {probe}"))
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        !(out.status.success() && String::from_utf8_lossy(&out.stdout).contains(probe)),
        "P1: the agents account launched a session as codex by itself"
    );
}
