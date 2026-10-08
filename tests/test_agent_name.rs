//! Agent commits name the agent that made them, when it can be told: the
//! approved v0.1 scope ("commits name the agent where detectable").
//!
//! Detection reads marks agents set on the commands they run (see
//! `KNOWN_AGENTS`), or an explicit `AGENT_COMMITS_AGENT_NAME`. A name the
//! person configured is never replaced by a detected one. This is
//! attribution, not identity: any program can set these variables, which
//! the README states as a limit.

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::process::{Child, Command, Stdio};

use agent_commits::attribution::{KNOWN_AGENTS, detect_agent_with, effective_agent_name};
use tempfile::tempdir;

fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
    let map: HashMap<String, String> = pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    move |k| map.get(k).cloned()
}

#[test]
fn each_known_mark_names_its_agent() {
    assert_eq!(
        detect_agent_with(env_of(&[("CLAUDECODE", "1")])).as_deref(),
        Some("Claude Code")
    );
    assert_eq!(
        detect_agent_with(env_of(&[("GEMINI_CLI", "1")])).as_deref(),
        Some("Gemini CLI")
    );
    assert_eq!(
        detect_agent_with(env_of(&[("CODEX_THREAD_ID", "019a-abc")])).as_deref(),
        Some("Codex")
    );
}

#[test]
fn no_mark_or_an_empty_or_zero_mark_names_nobody() {
    assert_eq!(detect_agent_with(env_of(&[])), None);
    assert_eq!(detect_agent_with(env_of(&[("CLAUDECODE", "")])), None);
    assert_eq!(detect_agent_with(env_of(&[("CLAUDECODE", "0")])), None);
}

#[test]
fn an_explicit_name_beats_any_mark() {
    let get = env_of(&[("CLAUDECODE", "1"), ("AGENT_COMMITS_AGENT_NAME", "Cursor")]);
    assert_eq!(detect_agent_with(get).as_deref(), Some("Cursor"));
    let old = env_of(&[("AGENT_SIGN_AGENT_NAME", "Aider")]);
    assert_eq!(detect_agent_with(old).as_deref(), Some("Aider"));
}

#[test]
fn a_detected_agent_replaces_only_a_default_name() {
    let detected = || Some("Claude Code".to_string());
    assert_eq!(
        effective_agent_name("Agent", false, detected()),
        "Claude Code"
    );
    assert_eq!(
        effective_agent_name("Antigravity Agent", false, detected()),
        "Claude Code"
    );
    assert_eq!(
        effective_agent_name("Build Bot", false, detected()),
        "Build Bot"
    );
    assert_eq!(
        effective_agent_name("Build Bot", true, detected()),
        "Claude Code"
    );
    assert_eq!(effective_agent_name("Agent", false, None), "Agent");
}

// --- End to end: the name on a real commit --------------------------------

struct Service(Child);

impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn git(repo: &Path, args: &[&str]) {
    let ok = Command::new("git")
        .args(args)
        .current_dir(repo)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .status()
        .unwrap()
        .success();
    assert!(ok, "git {args:?} failed");
}

/// Makes one agent commit through the wrapper with exactly the agent marks
/// in `marks` (every known mark is cleared first, so the commands this test
/// runs under don't leak in), and returns the commit's author name.
fn author_of_agent_commit(marks: &[(&str, &str)], config_name: Option<&str>) -> String {
    let dir = tempdir().unwrap();
    let home = dir.path();
    let repo = home.join("repo");
    fs::create_dir_all(&repo).unwrap();
    if let Some(name) = config_name {
        let state = home.join(".agent-commits");
        fs::create_dir_all(&state).unwrap();
        fs::write(
            state.join("config.toml"),
            format!("[agent]\nname = \"{name}\"\n"),
        )
        .unwrap();
    }

    let socket = home.join("s.sock");
    let _svc = Service(
        Command::new(env!("CARGO_BIN_EXE_agent-commitsd"))
            .arg("--socket")
            .arg(&socket)
            .arg("--auto-approve")
            .env("HOME", home)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    git(&repo, &["init", "-q", "-b", "feat/x"]);
    git(&repo, &["config", "user.name", "Person"]);
    git(&repo, &["config", "user.email", "person@example.com"]);
    fs::write(repo.join("a.txt"), "a\n").unwrap();
    git(&repo, &["add", "a.txt"]);

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_agent-commits-git"));
    cmd.args(["commit", "-q", "-m", "feat: a"])
        .current_dir(&repo)
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("AGENT_COMMITS_SOCKET", &socket)
        .env(
            "AGENT_COMMITS_BIN",
            env!("CARGO_BIN_EXE_agent-commits-ssh-sign"),
        )
        .env_remove("AGENT_COMMITS_AGENT_NAME")
        .env_remove("AGENT_SIGN_AGENT_NAME")
        .stdin(Stdio::null());
    for (var, _) in KNOWN_AGENTS {
        cmd.env_remove(var);
    }
    for (var, value) in marks {
        cmd.env(var, value);
    }
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "agent commit failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let log = Command::new("git")
        .args(["log", "-1", "--format=%an|"])
        .current_dir(&repo)
        .output()
        .unwrap();
    let log = String::from_utf8_lossy(&log.stdout).trim().to_string();
    log.split('|').next().unwrap_or_default().to_string()
}

#[test]
fn a_claude_code_commit_is_authored_by_claude_code() {
    assert_eq!(
        author_of_agent_commit(&[("CLAUDECODE", "1")], None),
        "Claude Code"
    );
}

#[test]
fn an_unmarked_agent_commit_keeps_the_default_name() {
    assert_eq!(author_of_agent_commit(&[], None), "Agent");
}

#[test]
fn a_name_the_person_configured_is_kept() {
    assert_eq!(
        author_of_agent_commit(&[("CLAUDECODE", "1")], Some("Build Bot")),
        "Build Bot"
    );
}

#[test]
fn an_agent_started_with_a_name_gets_that_name() {
    assert_eq!(
        author_of_agent_commit(&[("AGENT_COMMITS_AGENT_NAME", "Cursor")], None),
        "Cursor"
    );
}

// --- Who is committing: the person, or an agent ---------------------------

use agent_commits::attribution::{agent_mark_present_with, is_persons_own_commit};

#[test]
fn a_terminal_commit_with_no_mark_is_the_persons() {
    assert!(is_persons_own_commit(true, true, false, false));
}

#[test]
fn an_agent_mark_makes_a_terminal_commit_an_agents() {
    assert!(!is_persons_own_commit(true, true, false, true));
}

#[test]
fn no_terminal_or_forced_is_an_agents() {
    assert!(!is_persons_own_commit(false, true, false, false));
    assert!(!is_persons_own_commit(true, false, false, false));
    assert!(!is_persons_own_commit(true, true, true, false));
}

#[test]
fn only_known_marks_count_not_an_explicit_name() {
    assert!(agent_mark_present_with(env_of(&[("CLAUDECODE", "1")])));
    assert!(agent_mark_present_with(env_of(&[("CODEX_THREAD_ID", "x")])));
    assert!(!agent_mark_present_with(env_of(&[(
        "AGENT_COMMITS_AGENT_NAME",
        "Cursor"
    )])));
    assert!(!agent_mark_present_with(env_of(&[("CLAUDECODE", "0")])));
}
