//! L1: the per-test ssh agent does not outlive a killed test on macOS.
//!
//! `PR_SET_PDEATHSIG` is Linux-only, so `tests/support/key_agent.rs` starts a
//! parent-pid watchdog beside the agent where the kernel cannot do the job.
//! This file runs the real watchdog script anywhere (it needs only `sh`, `ps`
//! and `ssh-agent`), with a shell standing in for the test process:
//!
//! * control: with no watchdog, the agent survives its parent being killed
//!   (so the eval can fail);
//! * with the watchdog, the agent is gone within a few seconds of the kill;
//! * [`TestAgent::start_watched`] leaves neither agent nor watchdog behind
//!   after a normal drop.

#[path = "support/die_with_parent.rs"]
mod die_with_parent;
#[path = "support/key_agent.rs"]
mod key_agent;

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::{TempDir, tempdir};

/// Whether `pid` is a running process (a zombie is not running).
fn alive(pid: u32) -> bool {
    let out = Command::new("ps")
        .args(["-o", "stat=", "-p", &pid.to_string()])
        .output()
        .expect("ps runs");
    let stat = String::from_utf8_lossy(&out.stdout).trim().to_string();
    !stat.is_empty() && !stat.starts_with('Z')
}

fn gone_within(pid: u32, secs: u64) -> bool {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(secs) {
        if !alive(pid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    !alive(pid)
}

fn kill_pid(pid: u32) {
    let _ = Command::new("kill").args(["-9", &pid.to_string()]).status();
}

/// A shell standing in for a test process: it starts an agent as its child and,
/// when given the watchdog script, the watchdog as its child too, prints the
/// agent's pid, and waits. Killing the shell is "the test was killed".
fn fake_test_process(watchdog: bool) -> (Child, u32, TempDir) {
    let dir = tempdir().unwrap();
    let socket = dir.path().join("a.sock");
    let script = r#"ssh-agent -D -a "$1" >/dev/null 2>&1 &
agent=$!
if [ -n "$2" ]; then sh -c "$2" watchdog $$ $agent >/dev/null 2>&1 & fi
echo $agent
wait"#;
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(script)
        .arg("fake-test")
        .arg(&socket)
        .arg(if watchdog {
            key_agent::WATCHDOG_SCRIPT
        } else {
            ""
        })
        .stdout(Stdio::piped())
        .stdin(Stdio::null())
        .spawn()
        .expect("start the stand-in test process");
    let mut line = String::new();
    BufReader::new(child.stdout.as_mut().unwrap())
        .read_line(&mut line)
        .unwrap();
    let agent: u32 = line
        .trim()
        .parse()
        .expect("the stand-in printed the agent's pid");
    assert!(alive(agent), "the stand-in's agent did not start");
    (child, agent, dir)
}

#[test]
fn control_without_a_watchdog_the_agent_outlives_its_killed_parent() {
    let (mut parent, agent, _dir) = fake_test_process(false);
    parent.kill().unwrap();
    parent.wait().unwrap();
    std::thread::sleep(Duration::from_secs(3));
    let survived = alive(agent);
    kill_pid(agent); // clean up our own test process, whatever happened
    assert!(
        survived,
        "the control is void: the agent died without a watchdog, so the next test proves nothing"
    );
}

#[test]
fn with_the_watchdog_the_agent_dies_when_its_parent_is_killed() {
    let (mut parent, agent, _dir) = fake_test_process(true);
    assert!(alive(agent));
    parent.kill().unwrap();
    parent.wait().unwrap();
    let gone = gone_within(agent, 15);
    if !gone {
        kill_pid(agent); // clean up our own test process
    }
    assert!(gone, "the agent outlived its killed parent by 15 seconds");
}

#[test]
fn a_watched_agent_leaves_nothing_behind_after_a_normal_drop() {
    let agent = key_agent::TestAgent::start_watched();
    let agent_pid = agent.pid();
    let watchdog_pid = agent
        .watchdog_pid()
        .expect("a watched agent has a watchdog");
    assert!(alive(agent_pid) && alive(watchdog_pid));
    drop(agent);
    assert!(!alive(agent_pid), "the agent outlived its drop");
    assert!(!alive(watchdog_pid), "the watchdog outlived its drop");
}
