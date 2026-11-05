#![cfg(target_os = "linux")]
//! Fix round 1 for signed acts v0: the findings of the independent review, as tests (written by someone other than
//! the builder, before the fixes).
//!
//! * **F1 (high)**: a launched session could sign as `person:taylor` when Taylor's ssh-agent socket was reachable.
//!   The environment kept `SSH_AUTH_SOCK`, the sandbox left sockets connectable, and "am I in a session" was decided
//!   from an environment variable the session can drop. Required: no `SSH_AUTH_SOCK` in a session; no ssh-agent
//!   socket outside the session can be connected to from inside it (any path, an inherited descriptor, a path given
//!   as an argument); `act sign --assigner ...` is refused inside a session whatever its environment, and the
//!   refusal does not come after touching an agent.
//! * **F3 (medium/low)**: the launcher's key was made anew at each start under the one identity `harness:launcher`,
//!   so no old key could be revoked alone and old lines stayed trusted. Required: each launcher key is identified
//!   separately in the trust lines (the identity is the second word of its `assigner harness:...` line; this file
//!   does not fix its spelling, only that two starts differ), revoking an old one leaves the current one working,
//!   and `act trust-lines` marks the current lines (a comment containing "current" on, or directly above, each).
//! * **F4 (low)**: `act verify` followed symlinks and accepted a group- or world-writable trust file. Required: a
//!   symlink, or a group- or world-writable trust file or payload file, is refused (verify: exit 2, `verified`
//!   false, reason `error`, with a detail that says why; sign: non-zero, nothing on stdout).
//!
//! Keys live only in memory and in test ssh-agents; the agents here run on sockets under the test's private home.

#[path = "support/act_harness.rs"]
mod act_harness;
#[path = "support/die_with_parent.rs"]
mod die_with_parent;
#[path = "support/key_agent.rs"]
mod key_agent;
#[path = "support/memory_keys.rs"]
mod memory_keys;
#[path = "support/no_plain_keys.rs"]
mod no_plain_keys;

use act_harness::*;
use die_with_parent::DieWithParent;
use serde_json::json;
use std::fs;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const BUILDER: &str = "agent:builder-1";

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_agent-sign")
}

fn payload() -> Vec<u8> {
    b"assign evil to role X".to_vec()
}

fn chmod(p: &Path, mode: u32) {
    fs::set_permissions(p, fs::Permissions::from_mode(mode)).unwrap();
}

fn private_dir(p: &Path) {
    let mut b = fs::DirBuilder::new();
    b.recursive(true).mode(0o700);
    b.create(p).unwrap();
}

/// A real `ssh-agent` on `path` (killed when the test ends).
struct AgentAt {
    child: Child,
}

impl AgentAt {
    fn start(w: &ActWorld, path: &Path) -> AgentAt {
        private_dir(path.parent().unwrap());
        let mut cmd = Command::new("ssh-agent");
        cmd.die_with_parent();
        let child = cmd
            .arg("-D")
            .arg("-a")
            .arg(path)
            .env_clear()
            .env("PATH", &w.path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start ssh-agent");
        let start = Instant::now();
        while UnixStream::connect(path).is_err() {
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "no agent socket at {path:?}"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        AgentAt { child }
    }
}

impl Drop for AgentAt {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A listener on `path` that counts connections: a fake agent, to see whether anything ever reaches it.
struct Recorder {
    hits: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Recorder {
    fn at(path: &Path) -> Recorder {
        private_dir(path.parent().unwrap());
        let listener = UnixListener::bind(path).unwrap();
        listener.set_nonblocking(true).unwrap();
        let (hits, stop) = (
            Arc::new(AtomicUsize::new(0)),
            Arc::new(AtomicBool::new(false)),
        );
        let (h, s) = (hits.clone(), stop.clone());
        let thread = std::thread::spawn(move || {
            while !s.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((conn, _)) => {
                        // Counted, then closed at once, so a client that does connect fails fast instead of waiting.
                        h.fetch_add(1, Ordering::SeqCst);
                        drop(conn);
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(5)),
                }
            }
        });
        Recorder {
            hits,
            stop,
            thread: Some(thread),
        }
    }
    fn hits(&self) -> usize {
        std::thread::sleep(Duration::from_millis(100));
        self.hits.load(Ordering::SeqCst)
    }
}

impl Drop for Recorder {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Whether `ssh-add -l` outside any session reaches the agent at `socket` (exit 0 or 1; 2 is "could not connect").
fn reachable_outside(w: &ActWorld, socket: &Path) -> bool {
    let mut cmd = Command::new("ssh-add");
    cmd.env_clear()
        .env("PATH", &w.path)
        .env("SSH_AUTH_SOCK", socket)
        .arg("-l");
    let out = run_within(cmd, None, "ssh-add -l (control)");
    matches!(out.status.code(), Some(0) | Some(1))
}

/// The lines `KEY rc=N` a probe script printed, as a map.
fn rc_of(output: &str, key: &str) -> Option<i32> {
    output.lines().find_map(|l| {
        l.strip_prefix(key)
            .and_then(|r| r.trim().strip_prefix("rc="))
            .and_then(|n| n.parse().ok())
    })
}

fn looks_signed(stdout: &[u8]) -> bool {
    String::from_utf8_lossy(stdout).contains("agent-sign/act-signature/1")
}

// ------------------------------------------------------------------------------------------------------------
// F1
// ------------------------------------------------------------------------------------------------------------

#[test]
fn f1_01_a_session_has_no_ssh_auth_sock_even_when_its_caller_has_one() {
    let w = ActWorld::new(true);
    let dev = w.device("taylor");
    let sock = dev.agent.socket().to_str().unwrap().to_string();
    let out = w.launched(
        Some(BUILDER),
        Path::new("/bin/sh"),
        &["-c", "printf 'SOCK=[%s]\\n' \"${SSH_AUTH_SOCK-unset}\""],
        &[("SSH_AUTH_SOCK", &sock)],
    );
    let t = text(&out);
    assert!(
        out.status.success(),
        "control: the session should run:\n{t}"
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("SOCK=[unset]"),
        "the session kept SSH_AUTH_SOCK (rv1):\n{t}"
    );
}

#[test]
fn f1_02_no_ssh_agent_socket_outside_the_session_can_be_connected_to_from_inside_it() {
    let w = ActWorld::new(true);
    // Where agents really sit: the default path, the password manager's, a custom one, and a device's test agent.
    let dev = w.device("taylor");
    let default = w.home.join(".ssh/agent.sock");
    let onepw = w.home.join(".1password/agent.sock");
    let custom = w.home.join("elsewhere/run/my-agent.sock");
    let _a = AgentAt::start(&w, &default);
    let _b = AgentAt::start(&w, &onepw);
    let _c = AgentAt::start(&w, &custom);
    let paths: Vec<PathBuf> = vec![default, onepw, custom, dev.agent.socket().to_path_buf()];
    let mut problems = Problems::default();
    for p in &paths {
        problems.check(reachable_outside(&w, p), || {
            format!("control: {p:?} should be reachable outside a session")
        });
    }
    let script = r#"
command -v ssh-add python3 >/dev/null && echo TOOLS rc=0 || echo TOOLS rc=1
i=0
for p in "$@"; do
  i=$((i+1))
  SSH_AUTH_SOCK="$p" ssh-add -l >/dev/null 2>&1; echo "ADD$i rc=$?"
  python3 -c 'import socket,sys; s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])' "$p" >/dev/null 2>&1; echo "PY$i rc=$?"
done
"#;
    let strs: Vec<String> = paths
        .iter()
        .map(|p| p.to_str().unwrap().to_string())
        .collect();
    let mut args: Vec<&str> = vec!["-c", script, "sh"];
    args.extend(strs.iter().map(String::as_str));
    let out = w.launched(Some(BUILDER), Path::new("/bin/sh"), &args, &[]);
    let t = text(&out);
    let o = String::from_utf8_lossy(&out.stdout).to_string();
    problems.check(rc_of(&o, "TOOLS") == Some(0), || {
        format!("control: ssh-add and python3 must exist inside the session:\n{t}")
    });
    for (i, p) in paths.iter().enumerate() {
        let n = i + 1;
        problems.check(rc_of(&o, &format!("ADD{n}")) == Some(2), || {
            format!(
                "ssh-add inside the session reached {p:?} (rc {:?}, 2 means could not connect)",
                rc_of(&o, &format!("ADD{n}"))
            )
        });
        problems.check(rc_of(&o, &format!("PY{n}")).is_some_and(|c| c != 0), || {
            format!("a plain connect() inside the session to {p:?} succeeded")
        });
    }
    // Control: blocking sockets must not break the service's own channel; a session still signs as itself.
    let member = w.agent_signs(BUILDER, &payload());
    let trust = w.trust_file(&[]);
    let (code, v) = w.verify(&payload(), &member, &trust, None);
    problems.check(code == 0 && v["verified"] == json!(true), || {
        format!("control: the session should still sign: {code} {v}")
    });
    problems.finish();
}

/// The ways a session might try to sign as Taylor, each as a shell script run inside a launched session. `$1` is
/// the trust file, `$2` the payload file, `$3` the agent socket.
fn sign_as_person_scripts() -> Vec<(&'static str, String)> {
    let b = bin();
    vec![
        (
            "dropping the channel variable (rv2)",
            format!(
                "env -u AGENT_SIGN_CHANNEL_FD {b} act sign --assigner person:taylor --trust-file \"$1\" --payload-file \"$2\"; echo \"rc=$?\""
            ),
        ),
        (
            "an empty environment but the socket",
            format!(
                "env -i PATH=\"$PATH\" HOME=\"$HOME\" SSH_AUTH_SOCK=\"$3\" {b} act sign --assigner person:taylor --trust-file \"$1\" --payload-file \"$2\"; echo \"rc=$?\""
            ),
        ),
        (
            "an empty environment and the socket given inline",
            format!(
                "env -i {b} act sign --assigner person:taylor --trust-file \"$1\" --payload-file \"$2\" ; echo \"rc=$?\"; SSH_AUTH_SOCK=\"$3\" env -i SSH_AUTH_SOCK=\"$3\" {b} act sign --assigner person:taylor --trust-file \"$1\" --payload-file \"$2\"; echo \"rc2=$?\""
            ),
        ),
    ]
}

#[test]
fn f1_03_a_session_cannot_sign_as_taylor_whatever_its_environment() {
    let w = ActWorld::new(true);
    let dev = w.device("taylor");
    let trust = w.trust_file(&[ActWorld::taylor_line(&dev)]);
    let file = w.write("payload", &payload());
    let sock = dev.agent.socket().to_str().unwrap().to_string();
    // Control: outside a session the same call signs as Taylor.
    let control = w.taylor_signs(Some(&dev), &trust, &payload());
    assert!(
        control.status.success(),
        "control: Taylor should sign outside a session:\n{}",
        text(&control)
    );
    let mut problems = Problems::default();
    for (what, script) in sign_as_person_scripts() {
        let out = w.launched(
            Some(BUILDER),
            Path::new("/bin/sh"),
            &[
                "-c",
                &script,
                "sh",
                trust.to_str().unwrap(),
                file.to_str().unwrap(),
                &sock,
            ],
            &[("SSH_AUTH_SOCK", &sock)],
        );
        problems.check(!looks_signed(&out.stdout), || {
            format!("a session signed as Taylor by {what}:\n{}", text(&out))
        });
        let o = String::from_utf8_lossy(&out.stdout).to_string();
        for key in ["rc", "rc2"] {
            problems.check(rc_of(&o, key).is_none_or(|c| c != 0), || {
                format!("{what}: exit 0 ({key})\n{}", text(&out))
            });
        }
    }
    problems.finish();
}

#[test]
fn f1_04_the_refusal_comes_before_any_ssh_agent_is_touched_and_does_not_rest_on_the_environment() {
    let w = ActWorld::new(true);
    let dev = w.device("taylor");
    let trust = w.trust_file(&[ActWorld::taylor_line(&dev)]);
    let file = w.write("payload", &payload());
    let fake = w.home.join(".ssh/agent.sock");
    let rec = Recorder::at(&fake);
    let sock = fake.to_str().unwrap().to_string();
    for (what, script) in sign_as_person_scripts() {
        let out = w.launched(
            Some(BUILDER),
            Path::new("/bin/sh"),
            &[
                "-c",
                &script,
                "sh",
                trust.to_str().unwrap(),
                file.to_str().unwrap(),
                &sock,
            ],
            &[("SSH_AUTH_SOCK", &sock)],
        );
        assert!(!looks_signed(&out.stdout), "{what}: signed\n{}", text(&out));
    }
    assert_eq!(
        rec.hits(),
        0,
        "something inside a session connected to an ssh-agent socket outside it"
    );
}

#[test]
fn f1_05_the_launcher_cannot_be_signed_for_from_a_session_with_an_empty_environment() {
    let w = ActWorld::new(true);
    let file = w.write("payload", &payload());
    let sock = w.socket.to_str().unwrap().to_string();
    let b = bin();
    let script = format!(
        "env -i PATH=\"$PATH\" HOME=\"$HOME\" AGENT_SIGN_SOCKET=\"$2\" {b} act sign --assigner harness:launcher --payload-file \"$1\"; echo \"rc=$?\""
    );
    let out = w.launched(
        Some(BUILDER),
        Path::new("/bin/sh"),
        &["-c", &script, "sh", file.to_str().unwrap(), &sock],
        &[],
    );
    assert!(
        !looks_signed(&out.stdout),
        "a session signed as harness:launcher with an empty environment:\n{}",
        text(&out)
    );
    // Control: outside a session it works.
    assert!(w.launcher_signs(&payload()).status.success());
}

#[test]
fn f1_06_an_agent_connection_inherited_as_a_file_descriptor_does_not_reach_the_session() {
    let w = ActWorld::new(true);
    let dev = w.device("taylor");
    let conn = UnixStream::connect(dev.agent.socket()).unwrap();
    let src = conn.as_raw_fd();
    const TARGET: i32 = 91;
    let script = r#"
python3 - <<'PY'
import os, socket
try:
    os.fstat(91)
    print("FD91 open")
    s = socket.socket(fileno=91)
    s.sendall(bytes([0, 0, 0, 1, 11]))
    s.settimeout(3)
    print("FD91 reply", len(s.recv(4096)))
except Exception as e:
    print("FD91 closed", type(e).__name__)
PY
"#;
    let mut cmd = w.agent_sign();
    cmd.args([
        "launch",
        "--agent",
        "claude-code",
        "--identity",
        BUILDER,
        "--",
        "/bin/sh",
        "-c",
        script,
    ])
    .current_dir(&w.repo);
    unsafe {
        cmd.pre_exec(move || {
            if libc::dup2(src, TARGET) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let out = run_within(cmd, None, "launch with an inherited agent descriptor");
    let t = text(&out);
    let o = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        o.contains("FD91"),
        "control: the probe should have printed something:\n{t}"
    );
    assert!(
        !o.contains("FD91 open") && !o.contains("FD91 reply"),
        "the session inherited the caller's agent connection:\n{t}"
    );
    drop(conn);
}

// ------------------------------------------------------------------------------------------------------------
// F3
// ------------------------------------------------------------------------------------------------------------

/// `(identity, whole line)` of every `assigner harness:...` line in `lines`.
fn launcher_lines(lines: &str) -> Vec<(String, String)> {
    lines
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("assigner harness:"))
        .map(|l| {
            (
                l.split_whitespace().nth(1).unwrap().to_string(),
                l.to_string(),
            )
        })
        .collect()
}

fn restart(w: &mut ActWorld) {
    w.stop_service();
    let _ = fs::remove_file(&w.socket);
    w.start_service();
}

#[test]
fn f3_01_each_launcher_key_has_its_own_identity_and_one_old_key_can_be_revoked_alone() {
    let mut w = ActWorld::new(true);
    let lines1 = w.trust_lines();
    let old = member_of(&w.launcher_signs(b"x"));
    restart(&mut w);
    let lines2 = w.trust_lines();
    let new = member_of(&w.launcher_signs(b"x"));
    let (l1, l2) = (launcher_lines(&lines1), launcher_lines(&lines2));
    assert!(
        !l1.is_empty() && !l2.is_empty(),
        "no launcher lines:\n{lines1}\n--\n{lines2}"
    );
    let mut problems = Problems::default();
    problems.check(l1[0].0 != l2[0].0, || {
        format!(
            "two starts of the service gave their launcher key the same identity {:?} (rv5)",
            l1[0].0
        )
    });
    // Both starts' lines in one trust file, then only the old key's identity revoked.
    let t =
        |extra: &str| w.trust_file_text(&format!("{TRUST_HEADER}\n{lines1}\n{lines2}\n{extra}"));
    let both = t("");
    let (code, v) = w.verify(b"x", &old, &both, None);
    problems.check(code == 0 && v["verified"] == json!(true), || {
        format!("control: old signature under both start's lines: {code} {v}")
    });
    let revoked = t(&format!("revoked {}\n", l1[0].0));
    let (code, v) = w.verify(b"x", &old, &revoked, None);
    problems.check(code == 1 && v["reason"] == json!("revoked"), || {
        format!("the revoked old key's signature: {code} {v}")
    });
    let (code, v) = w.verify(b"x", &new, &revoked, None);
    problems.check(code == 0 && v["verified"] == json!(true), || {
        format!("revoking the old launcher key also killed the current one (rv5/rv6): {code} {v}")
    });
    problems.finish();
}

#[test]
fn f3_02_trust_lines_mark_which_lines_are_current_and_the_marked_output_is_still_a_trust_file() {
    let w = ActWorld::new(true);
    let lines = w.trust_lines();
    let all: Vec<&str> = lines.lines().collect();
    let mut problems = Problems::default();
    for (i, l) in all.iter().enumerate() {
        if l.trim().starts_with("assigner harness:") {
            let marked = l.to_lowercase().contains("current")
                || (i > 0
                    && all[i - 1].trim_start().starts_with('#')
                    && all[i - 1].to_lowercase().contains("current"));
            problems.check(marked, || {
                format!("the launcher line isn't marked current:\n{lines}")
            });
        }
    }
    problems.check(!launcher_lines(&lines).is_empty(), || {
        format!("no launcher line:\n{lines}")
    });
    let trust = w.trust_file(&[]);
    let member = member_of(&w.launcher_signs(b"x"));
    let (code, v) = w.verify(b"x", &member, &trust, None);
    problems.check(code == 0 && v["verified"] == json!(true), || {
        format!("the launcher signature under the marked lines: {code} {v}")
    });
    problems.finish();
}

// ------------------------------------------------------------------------------------------------------------
// F4
// ------------------------------------------------------------------------------------------------------------

fn refused_verdict(code: i32, v: &serde_json::Value, words: &[&str]) -> Result<(), String> {
    let detail = v["detail"].as_str().unwrap_or("").to_lowercase();
    if code != 2 || v["verified"] != json!(false) {
        return Err(format!(
            "expected exit 2 and verified false, got {code} {v}"
        ));
    }
    if !words.iter().any(|w| detail.contains(w)) {
        return Err(format!(
            "the detail doesn't say why (looked for {words:?}): {v}"
        ));
    }
    Ok(())
}

#[test]
fn f4_01_a_symlinked_trust_file_is_refused() {
    let w = ActWorld::new(true);
    let member = w.agent_signs(BUILDER, &payload());
    let real = w.trust_file(&[]);
    let link = w.fresh("trust-link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let (code, v) = w.verify(&payload(), &member, &real, None);
    assert!(
        code == 0 && v["verified"] == json!(true),
        "control: the real file verifies: {code} {v}"
    );
    let (code, v) = w.verify(&payload(), &member, &link, None);
    if let Err(e) = refused_verdict(code, &v, &["symlink", "symbolic", "link"]) {
        panic!("symlinked trust file (rv6): {e}");
    }
    // A link to a link, and a link whose target is a revoking file: refused all the same.
    let link2 = w.fresh("trust-link2");
    std::os::unix::fs::symlink(&link, &link2).unwrap();
    let (code, _) = w.verify(&payload(), &member, &link2, None);
    assert_eq!(code, 2, "a chain of symlinks");
}

#[test]
fn f4_02_a_group_or_world_writable_trust_file_is_refused() {
    let w = ActWorld::new(true);
    let member = w.agent_signs(BUILDER, &payload());
    let trust = w.trust_file(&[]);
    let mut problems = Problems::default();
    for ok in [0o600, 0o644, 0o400] {
        chmod(&trust, ok);
        let (code, v) = w.verify(&payload(), &member, &trust, None);
        problems.check(code == 0 && v["verified"] == json!(true), || {
            format!("control: mode {ok:o} should be accepted: {code} {v}")
        });
    }
    for bad in [0o660, 0o666, 0o620, 0o602, 0o664, 0o606] {
        chmod(&trust, bad);
        let (code, v) = w.verify(&payload(), &member, &trust, None);
        if let Err(e) = refused_verdict(code, &v, &["writable", "permission", "mode"]) {
            problems.check(false, || format!("trust file mode {bad:o} (rv6): {e}"));
        }
    }
    problems.finish();
}

#[test]
fn f4_03_a_symlinked_or_group_or_world_writable_payload_file_is_not_signed() {
    let w = ActWorld::new(true);
    let mut problems = Problems::default();
    let good = w.write("payload", &payload());
    let launcher = |file: &Path| {
        let mut cmd = w.agent_sign();
        cmd.args([
            "act",
            "sign",
            "--assigner",
            "harness:launcher",
            "--payload-file",
        ])
        .arg(file);
        run_within(cmd, None, "launcher signs a payload file")
    };
    let out = launcher(&good);
    problems.check(out.status.success() && looks_signed(&out.stdout), || {
        format!("control: a 0600 payload file:\n{}", text(&out))
    });
    let link = w.fresh("payload-link");
    std::os::unix::fs::symlink(&good, &link).unwrap();
    let out = launcher(&link);
    problems.check(!out.status.success() && out.stdout.is_empty(), || {
        format!("a symlinked payload file was signed:\n{}", text(&out))
    });
    for bad in [0o660, 0o666, 0o602] {
        let f = w.write("payload", &payload());
        chmod(&f, bad);
        let out = launcher(&f);
        problems.check(!out.status.success() && out.stdout.is_empty(), || {
            format!("a mode {bad:o} payload file was signed:\n{}", text(&out))
        });
    }
    // The same inside a session.
    let f = w.write("payload", &payload());
    chmod(&f, 0o666);
    let out = w.in_session(
        Some(BUILDER),
        &["sign", "--payload-file", f.to_str().unwrap()],
        &[],
    );
    problems.check(!out.status.success() && !looks_signed(&out.stdout), || {
        format!(
            "a session signed a world-writable payload file:\n{}",
            text(&out)
        )
    });
    let out = w.in_session(
        Some(BUILDER),
        &["sign", "--payload-file", link.to_str().unwrap()],
        &[],
    );
    problems.check(!out.status.success() && !looks_signed(&out.stdout), || {
        format!("a session signed a symlinked payload file:\n{}", text(&out))
    });
    problems.finish();
}
