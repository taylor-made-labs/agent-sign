//! `agent-sign launch` in system mode: the caller's side of the launcher
//! (docs/system-mode.md, "How working copies are shared"; build step 3).
//!
//! Once `/etc/agent-sign/system.toml` exists, a session never runs in the
//! caller's own account (D4): `agent-sign launch --agent NAME -- COMMAND...`
//! asks the launcher (`agent-launchd`) to start it in a slot account, and
//! stays connected until it ends (the launcher stops the session if the
//! caller goes).
//!
//! **Bundles in, bundles out.** If the command is run inside a git working
//! copy, that repository goes with the session: this command bundles the
//! current branch (or `HEAD`) in the caller's own account and sends the
//! bundle, with its base commit, over the launch socket. At the end the
//! launcher sends back the session's commits as bundles, and this command
//! fetches each into the caller's repository as
//! `session/<principal>/<branch>`. Fetching from a bundle runs nothing from
//! it, and no other account ever runs git in the caller's repository.
//!
//! **The environment.** Only `LANG` and `TERM` go with the session: the
//! caller's environment holds the caller's own tokens, which an agent in a
//! slot must not inherit by accident. The launcher accepts nothing else from
//! anyone ([`crate::launcher::check_env`]), and refuses a value that isn't
//! plain, so this command sends one of them only if the launcher will take
//! it ([`session_env`]); a `TERM` with an odd character is left out, with a
//! note, rather than failing the launch.
//!
//! **`agent-sign launch --collect SESSION`** fetches the bundles of a
//! session whose caller had gone before it ended; the launcher gives them
//! only to the account that launched it.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

use base64::Engine;

use crate::launcher::{BundleOut, LaunchRequest, LaunchResponse, RepoIn};

/// The launch socket `system.toml` names (`[launcher] socket`), read
/// leniently, as clients read it; the design's path when it says none.
fn launch_socket(path: &Path) -> Result<PathBuf, String> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        format!(
            "this machine is in system mode ({} exists) but it can't be read ({e}); nothing was run",
            path.display()
        )
    })?;
    let value: toml::Value = toml::from_str(&text).map_err(|e| {
        format!(
            "this machine is in system mode ({} exists) but it isn't valid TOML ({}); nothing \
             was run",
            path.display(),
            e.message()
        )
    })?;
    Ok(value
        .get("launcher")
        .and_then(|l| l.get("socket"))
        .and_then(toml::Value::as_str)
        .map_or_else(
            || PathBuf::from("/run/agent-launch/launch.sock"),
            PathBuf::from,
        ))
}

fn connect(system: &Path) -> Result<UnixStream, String> {
    let socket = launch_socket(system)?;
    UnixStream::connect(&socket).map_err(|e| {
        format!(
            "this machine is in system mode ({}), where sessions run in accounts of their own, \
             and the launcher at {} didn't answer ({e}); nothing was run",
            system.display(),
            socket.display()
        )
    })
}

fn git_out(dir: &Path, args: &[&str]) -> Option<Vec<u8>> {
    let out = Command::new(crate::paths::real_git())
        .args(args)
        .current_dir(dir)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    out.status.success().then_some(out.stdout)
}

fn git_text(dir: &Path, args: &[&str]) -> Option<String> {
    git_out(dir, args).map(|b| String::from_utf8_lossy(&b).trim().to_string())
}

/// The working copy this command runs in, as a repository to send: its
/// name (the folder's, made safe), its `HEAD` commit, and a bundle of the
/// current branch (or of `HEAD` when detached).
fn this_repo(cwd: &Path) -> Result<Option<(PathBuf, RepoIn)>, String> {
    let Some(top) = git_text(cwd, &["rev-parse", "--show-toplevel"]) else {
        return Ok(None);
    };
    let top = PathBuf::from(top);
    let base = git_text(&top, &["rev-parse", "--verify", "-q", "HEAD^{commit}"])
        .ok_or("this repository has no commit yet, so there is nothing to start from")?;
    let what = match git_text(&top, &["symbolic-ref", "-q", "HEAD"]) {
        Some(r) if r.starts_with("refs/heads/") => r,
        _ => "HEAD".to_string(),
    };
    let bundle = git_out(&top, &["bundle", "create", "-q", "-", &what])
        .ok_or("this repository couldn't be bundled")?;
    let raw = top
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let mut name: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' {
                c
            } else {
                '-'
            }
        })
        .collect();
    while name.starts_with('.') || name.starts_with('-') {
        name.remove(0);
    }
    name.truncate(64);
    if !crate::launcher::is_repo_name(&name) {
        name = "repo".into();
    }
    Ok(Some((
        top,
        RepoIn {
            name,
            base,
            bundle_b64: base64::engine::general_purpose::STANDARD.encode(bundle),
        },
    )))
}

/// Fetches the returned bundles into `repo` as `session/<principal>/...`.
fn fetch_back(repo: Option<&Path>, principal: &str, bundles: &[BundleOut]) -> Result<(), String> {
    if bundles.is_empty() {
        return Ok(());
    }
    let Some(repo) = repo else {
        return Err(
            "bundles came back, but this wasn't run in a repository to fetch them into".into(),
        );
    };
    let prefix = format!("refs/heads/session/{principal}");
    if Command::new(crate::paths::real_git())
        .args(["check-ref-format", &format!("{prefix}/x")])
        .status()
        .map_or(true, |s| !s.success())
    {
        return Err(format!(
            "{principal:?} can't name a branch; the bundles weren't fetched"
        ));
    }
    let dir = std::env::temp_dir().join(format!(
        "agent-sign-returned-{}",
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::create_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let result = (|| {
        for b in bundles {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(b.bundle_b64.as_bytes())
                .map_err(|e| format!("{}'s bundle isn't base64 ({e})", b.name))?;
            let file = dir.join(format!("{}.bundle", uuid::Uuid::new_v4().simple()));
            std::fs::write(&file, bytes).map_err(|e| e.to_string())?;
            let f = file.to_string_lossy().to_string();
            let spec = format!("+refs/heads/*:{prefix}/*");
            // The bundle came from a session's code. Git checks the objects
            // it takes in only when asked, so ask on the command line, which
            // wins over the caller's own repository config (a repository
            // that turns these off must not weaken the check): a malformed
            // object (a missing author, a bad tree) refuses the whole
            // fetch and none of it is stored under a ref.
            let ok = Command::new(crate::paths::real_git())
                .args([
                    "-c",
                    "transfer.fsckObjects=true",
                    "-c",
                    "fetch.fsckObjects=true",
                    "fetch",
                    "-q",
                    "--no-tags",
                    &f,
                    &spec,
                ])
                .current_dir(repo)
                .status()
                .is_ok_and(|s| s.success());
            if !ok {
                return Err(format!("{}'s bundle couldn't be fetched", b.name));
            }
            eprintln!(
                "[agent-sign launch] {}: the session's branches are now under session/{principal}/",
                b.name
            );
        }
        Ok(())
    })();
    // The bundles were copies of what the launcher keeps; only this
    // command's own temporary folder goes.
    let _ = std::fs::remove_dir_all(&dir);
    result
}

/// Reads the launcher's answers until the session ends.
fn follow(conn: UnixStream, repo: Option<&Path>) -> Result<ExitCode, String> {
    let mut reader = BufReader::new(conn);
    let mut principal = String::new();
    let mut stdout = std::io::stdout();
    loop {
        let mut line = String::new();
        let n = reader
            .read_line(&mut line)
            .map_err(|e| format!("the launcher's answer can't be read ({e})"))?;
        if n == 0 {
            return Err("the launcher closed the connection before the session ended".into());
        }
        let resp: LaunchResponse = serde_json::from_str(line.trim_end())
            .map_err(|e| format!("the launcher's answer can't be read ({e})"))?;
        match resp {
            LaunchResponse::Launched {
                session,
                slot,
                principal: p,
            } => {
                eprintln!(
                    "[agent-sign launch] session {session} in slot {slot}: signs as {p}, in an account of its own"
                );
                principal = p;
            }
            LaunchResponse::Output { data_b64 } => {
                if let Ok(bytes) =
                    base64::engine::general_purpose::STANDARD.decode(data_b64.as_bytes())
                {
                    let _ = stdout.write_all(&bytes);
                    let _ = stdout.flush();
                }
            }
            LaunchResponse::Ended { status, bundles } => {
                eprintln!("[agent-sign launch] the session ended: {status}");
                fetch_back(repo, &principal, &bundles)?;
                return Ok(ExitCode::SUCCESS);
            }
            LaunchResponse::Error { message } => return Err(message),
        }
    }
}

/// The environment this command sends: each of
/// [`crate::launcher::ALLOWED_ENV`] that `get` finds, if its value is one the
/// launcher accepts ([`crate::launcher::is_env_value`]). A value it would
/// refuse is left out, with a note on standard error.
fn session_env(get: impl Fn(&str) -> Option<String>) -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    for k in crate::launcher::ALLOWED_ENV {
        match get(k) {
            Some(v) if crate::launcher::is_env_value(&v) => {
                env.insert(k.to_string(), v);
            }
            Some(_) => eprintln!(
                "[agent-sign launch] {k} isn't sent: the launcher takes only 1 to {} bytes of \
                 letters, digits and . _ @ + -",
                crate::launcher::MAX_ENV_VALUE_BYTES
            ),
            None => {}
        }
    }
    env
}

/// `agent-sign launch --agent AGENT -- PROGRAM ARGS...` in system mode;
/// `system` is the settings file.
pub fn run(system: &Path, agent: &str, program: &std::ffi::OsStr, args: &[OsString]) -> ExitCode {
    match run_inner(system, agent, program, args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("agent-sign launch: {e}");
            ExitCode::from(1)
        }
    }
}

fn run_inner(
    system: &Path,
    agent: &str,
    program: &std::ffi::OsStr,
    args: &[OsString],
) -> Result<ExitCode, String> {
    let mut command = Vec::new();
    for a in std::iter::once(program).chain(args.iter().map(OsString::as_os_str)) {
        command.push(
            a.to_str()
                .ok_or("the program and its arguments must be valid UTF-8")?
                .to_string(),
        );
    }
    let mut conn = connect(system)?;
    let cwd = std::env::current_dir().map_err(|e| format!("no current folder ({e})"))?;
    let found = this_repo(&cwd)?;
    let (repo_dir, repos) = match found {
        Some((dir, r)) => (Some(dir), vec![r]),
        None => (None, Vec::new()),
    };
    let env = session_env(|k| std::env::var(k).ok());
    let req = LaunchRequest::Launch {
        agent: agent.to_string(),
        command,
        env,
        repos,
        approval: None,
        bundles_follow: false,
    };
    let text = serde_json::to_string(&req).map_err(|e| e.to_string())?;
    conn.write_all(format!("{text}\n").as_bytes())
        .map_err(|e| format!("the request couldn't be sent to the launcher ({e})"))?;
    follow(conn, repo_dir.as_deref())
}

/// `agent-sign launch --collect SESSION` in system mode.
pub fn collect(system: &Path, session: &str) -> ExitCode {
    let go = || -> Result<ExitCode, String> {
        let mut conn = connect(system)?;
        let req = serde_json::to_string(&LaunchRequest::Collect {
            session: session.to_string(),
        })
        .map_err(|e| e.to_string())?;
        conn.write_all(format!("{req}\n").as_bytes())
            .map_err(|e| e.to_string())?;
        let cwd = std::env::current_dir().map_err(|e| e.to_string())?;
        let repo = git_text(&cwd, &["rev-parse", "--show-toplevel"]).map(PathBuf::from);
        let mut line = String::new();
        BufReader::new(conn)
            .read_line(&mut line)
            .map_err(|e| e.to_string())?;
        match serde_json::from_str::<LaunchResponse>(line.trim_end()) {
            Ok(LaunchResponse::Ended { status, bundles }) => {
                eprintln!("[agent-sign launch] session {session}: {status}");
                fetch_back(repo.as_deref(), &format!("collected-{session}"), &bundles)?;
                Ok(ExitCode::SUCCESS)
            }
            Ok(LaunchResponse::Error { message }) => Err(message),
            _ => Err("the launcher's answer can't be read".into()),
        }
    };
    match go() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("agent-sign launch --collect: {e}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_lang_and_term_with_plain_values_are_sent() {
        let env = session_env(|k| {
            Some(match k {
                "LANG" => "en_US.UTF-8".to_string(),
                _ => "has a space".to_string(),
            })
        });
        assert_eq!(env.len(), 1);
        assert_eq!(env["LANG"], "en_US.UTF-8");
        assert!(crate::launcher::check_env(&env).is_ok());
        assert!(session_env(|_| None).is_empty());
    }
}
