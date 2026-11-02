//! `agent-sign session-exec` and `agent-sign session-end`: a launched
//! session's own side, in system mode (docs/system-mode.md, "The session
//! unit" and "D6"; build step 3). Both take no arguments: systemd starts
//! them as a slot's account (`agent-slot-<n>`) in that slot's unit, and they
//! work out the slot from their own uid.
//!
//! Both first refuse unless the mount at the slot's `current/` is exactly
//! that slot's own `current/` ([`check_current_mount`], L2): the unit's
//! `BindPaths=` is set up by systemd as root from a folder the launcher
//! owns, so a link the launcher put there would otherwise show its target
//! to the session.
//!
//! **session-exec** (in `agent-session@<n>.service`):
//! 1. refuses unless its uid is a slot account's and its own cgroup is
//!    exactly that slot's session unit (so a slot account's process started
//!    any other way is never a session, as the service also decides);
//! 2. reads the spec the launcher wrote, handed over by systemd
//!    (`$CREDENTIALS_DIRECTORY/spec`), never from the launcher's folder, and
//!    refuses it unless its environment is only `LANG` and `TERM` with plain
//!    values ([`crate::launcher::check_env`]): the launcher has checked that
//!    already, and this is the same rule applied again where the program
//!    would otherwise run with whatever the spec held (defence in depth);
//! 3. makes `home/`, `work/` and `tmp/` in its fresh `current/`, private;
//! 4. for each repository, takes from the bundle the launcher left in `in/`
//!    only the approved base commit ([`fetch_base`]): the bundle's branches
//!    are fetched into a holding namespace, the base is checked to be there,
//!    and the holding refs are deleted, so a branch the approval never named
//!    (or a commit past the base) is on no ref in the working copy and can't
//!    come back in the end step's bundle. The base is recorded as
//!    `refs/agent-sign/base` and checked out (fetching from a bundle runs
//!    nothing from it);
//! 5. asks the service who this session is (`SessionIdentity`; the service
//!    knows it by uid, unit and live process) and writes the session's git
//!    settings to `home/.gitconfig`;
//! 6. runs the program in `work/<first repository>` with the agent-sign git
//!    wrapper first on `PATH`, replacing itself (`exec`), so the program is
//!    the unit's main process and systemd's stop reaches it directly.
//!
//! **session-end** (in `agent-session-end@<n>.service`, after the session's
//! unit has fully stopped): for each working copy in `work/`, checks that
//! everything is committed (no changed or staged tracked file, no untracked
//! file that isn't ignored, no stash, no merge, rebase, cherry-pick, revert
//! or bisect in progress), writes the branches that moved past the base to
//! `out/<name>.bundle`, and reports "clean" or what was left in
//! `out/status.json`. It removes nothing (the suite PM's decision D6 (b),
//! 1 Nov 2026): the launcher moves the whole session folder, every working
//! copy included, to the slot's Trash, renamed and logged. A planned,
//! not yet built sweep may later delete only Trash folders provably
//! regenerable (a clean working copy whose HEAD is in a delivered bundle or
//! upstream), each deletion logged. `out/` is opened to the slot's group
//! (0750, files 0640), because the session's `UMask=0077` would keep it from
//! the launcher.
//!
//! **Why the end step runs git and the launcher doesn't.** Git in a
//! session's repository reads that repository's config, which the session
//! wrote. Run as the launcher, it could make the launcher run the session's
//! code. Run as the slot's own account, the worst a hostile session can do
//! is make the check report "clean" and lose its own files, which it could
//! do anyway. The check exists so agent-sign never destroys work by
//! accident, not as a defence against the session.

use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

use crate::kernel_facts::session_unit;
use crate::launcher::{HOME, IN, OUT, STATUS_FILE, SessionSpec, TMP, WORK};
use crate::system_config::SystemConfig;
use crate::systemd_port::end_unit;

/// The ref the base commit is recorded as in each working copy.
pub const BASE_REF: &str = "refs/agent-sign/base";

/// Which of the two units a runner must be in.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Step {
    Exec,
    End,
}

/// The cgroup v2 lines a process of `unit` has (as
/// [`crate::kernel_facts::unit_cgroups`] says for the session unit; the end
/// unit's template slice is `system-agent\x2dsession\x2dend.slice`).
fn cgroups_of(unit: &str) -> Vec<String> {
    let template = unit.split('@').next().unwrap_or("").replace('-', "\\x2d");
    vec![
        format!("0::/system.slice/{unit}"),
        format!("0::/system.slice/system-{template}.slice/{unit}"),
    ]
}

/// The slot this process runs as, checked: system mode, a slot account's
/// uid, and this slot's unit for `step` as its cgroup.
fn this_slot(step: Step) -> Result<(SystemConfig, u32), String> {
    let active = crate::system_config::active()?
        .ok_or("this runs only in system mode (there is no /etc/agent-sign/system.toml)")?;
    let config = active.config;
    // SAFETY: getuid takes no arguments and can't fail.
    let uid = unsafe { libc::getuid() };
    let kernel = crate::kernel_facts::kernel();
    let mut slot = None;
    for n in 1..=config.slots.count {
        let account = format!("{}{n}", config.slots.account_prefix);
        if kernel.account_uid(&account)? == Some(uid) {
            slot = Some(n);
            break;
        }
    }
    let n = slot.ok_or_else(|| format!("uid {uid} isn't one of this machine's slot accounts"))?;
    // L2: before anything else, the unit's bind of current/ must be the slot's own.
    check_own_mount(&current_of(&config, n))?;
    let unit = match step {
        Step::Exec => session_unit(n),
        Step::End => end_unit(n),
    };
    let own = fs::read_to_string("/proc/self/cgroup")
        .map_err(|e| format!("this process's cgroup can't be read ({e})"))?;
    let line = own.lines().find(|l| l.starts_with("0::")).unwrap_or("");
    if !cgroups_of(&unit).iter().any(|c| c == line) {
        return Err(format!(
            "this isn't slot {n}'s {unit} (its cgroup is {line:?}): nothing was run"
        ));
    }
    Ok((config, n))
}

/// One line of `/proc/self/mountinfo`, reduced to what the check uses.
struct MountLine {
    /// `major:minor` of the filesystem.
    dev: String,
    /// The mounted directory's path within its own filesystem.
    root: Vec<u8>,
    /// Where it is mounted in this namespace.
    point: Vec<u8>,
}

/// Undoes mountinfo's `\ooo` octal escapes (space, tab, newline, backslash).
fn unescape_mountinfo(field: &str) -> Vec<u8> {
    let b = field.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let oct = |k: usize| b.get(i + k).filter(|c| (b'0'..=b'7').contains(c));
        if b[i] == b'\\'
            && let (Some(a), Some(c), Some(d)) = (oct(1), oct(2), oct(3))
        {
            out.push(((a - b'0') << 6) | ((c - b'0') << 3) | (d - b'0'));
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    out
}

fn parse_mountinfo(text: &str) -> Result<Vec<MountLine>, String> {
    let mut out = Vec::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let f: Vec<&str> = line.split(' ').collect();
        // id parent major:minor root mount-point options [optional...] - fstype source superopts
        if f.len() < 10 || !f.contains(&"-") || !f[2].contains(':') {
            return Err(format!(
                "a line of /proc/self/mountinfo can't be read: {line:?}"
            ));
        }
        out.push(MountLine {
            dev: f[2].to_string(),
            root: unescape_mountinfo(f[3]),
            point: unescape_mountinfo(f[4]),
        });
    }
    if out.is_empty() {
        return Err("/proc/self/mountinfo is empty".into());
    }
    Ok(out)
}

/// `prefix` is `path` or a folder above it (whole path components only).
fn is_path_prefix(prefix: &[u8], path: &[u8]) -> bool {
    prefix == b"/"
        || path == prefix
        || (path.starts_with(prefix) && path.get(prefix.len()) == Some(&b'/'))
}

/// L2 (the launcher is not trusted with root's mounts). `agent-session@` and
/// `agent-session-end@` have `BindPaths=/var/lib/agent-slots/%i/current`,
/// which systemd, as root, sets up from a folder the launcher owns (it must
/// own it: it renames `current/` into `trash/`). A compromised launcher could
/// put a symlink there, and the bind would then show the link's target
/// (bind mounts skip the permission checks on the target's ancestors) inside
/// the session. `man systemd.exec` says nothing about links in `BindPaths=`
/// sources, so nothing may be assumed: the session's own programs check,
/// before anything else, that the mount at `current` is exactly the slot's
/// own `current/`.
///
/// `mountinfo` is `/proc/self/mountinfo` as seen inside the unit; `current`
/// is `<slots root>/<n>/current`, absolute and plain. The decision, as a pure
/// function so it can be tested over fixtures:
/// 1. the filesystem holding the slots folder is the deepest mount at or
///    above the slots folder, ignoring mounts at or below it (the unit's
///    `TemporaryFileSystem=` and the bind itself). A dedicated filesystem
///    mounted at the slots folder is therefore refused, not guessed at;
/// 2. the mount at `current` (the topmost, if stacked) must be on that same
///    device (`major:minor`), and its root (the directory's path within its
///    filesystem) must be that filesystem's own root plus the part of
///    `current` below the mount point. Another path, another slot, a path
///    that only ends the same way, another device, and a followed link
///    anywhere else all differ in one or the other;
/// 3. no mount at `current`, or a line that can't be read, is refused.
pub fn check_current_mount(mountinfo: &str, current: &Path) -> Result<(), String> {
    use std::os::unix::ffi::OsStrExt;
    use std::path::Component;
    let shown = current.display();
    let mut parts = current.components();
    let plain = matches!(parts.next(), Some(Component::RootDir))
        && parts.clone().count() >= 3
        && parts.all(|c| matches!(c, Component::Normal(_)));
    if !plain {
        return Err(format!("{shown} isn't an absolute, plain path"));
    }
    let want = current.as_os_str().as_bytes();
    let slots = current
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| format!("{shown} has no slots folder"))?
        .as_os_str()
        .as_bytes();
    let mounts = parse_mountinfo(mountinfo)?;
    let bound = mounts
        .iter()
        .rev()
        .find(|m| m.point == want)
        .ok_or_else(|| format!("nothing is mounted at {shown}: this isn't the slot's unit"))?;
    // The deepest mount strictly above the slots folder; the first of any
    // stacked at that point (the lowest, the host's own).
    let mut holder: Option<&MountLine> = None;
    for m in &mounts {
        if m.point != slots
            && is_path_prefix(&m.point, slots)
            && holder.is_none_or(|h| m.point.len() > h.point.len())
        {
            holder = Some(m);
        }
    }
    let holder = holder.ok_or("the filesystem holding the slots folder can't be found")?;
    // Below the holder's mount point (for `/` that is the whole path).
    let below: &[u8] = if holder.point == b"/" {
        want
    } else {
        &want[holder.point.len()..]
    };
    let mut expected = holder.root.clone();
    if expected.last() == Some(&b'/') {
        expected.pop();
    }
    expected.extend_from_slice(below);
    let name = |b: &[u8]| String::from_utf8_lossy(b).to_string();
    if bound.dev != holder.dev || bound.root != expected {
        return Err(format!(
            "the mount at {shown} is {} on device {}, not {} on device {}: it isn't the slot's own \
             current/ (a link was followed); nothing was run",
            name(&bound.root),
            bound.dev,
            name(&expected),
            holder.dev
        ));
    }
    Ok(())
}

/// The thin system call around [`check_current_mount`]: reads this process's
/// own `/proc/self/mountinfo`.
pub fn check_own_mount(current: &Path) -> Result<(), String> {
    let text = fs::read_to_string("/proc/self/mountinfo")
        .map_err(|e| format!("/proc/self/mountinfo can't be read ({e}): nothing was run"))?;
    check_current_mount(&text, current)
}

/// The slot's `current/`, from the settings.
fn current_of(config: &SystemConfig, n: u32) -> PathBuf {
    config
        .slots
        .root
        .join(n.to_string())
        .join(crate::launcher::CURRENT)
}

/// Runs the real git with `args` in `dir`, quietly; its standard output.
fn git(dir: &Path, args: &[&str]) -> Result<String, String> {
    let out = Command::new(crate::paths::real_git())
        .args(args)
        .current_dir(dir)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("git couldn't be run ({e})"))?;
    if !out.status.success() {
        return Err(format!(
            "git {} failed: {}",
            args.first().copied().unwrap_or(""),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn make_private_dir(path: &Path) -> Result<(), String> {
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let m = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
            if !m.is_dir() {
                return Err(format!("{} exists and isn't a folder", path.display()));
            }
        }
        Err(e) => return Err(format!("{}: {e}", path.display())),
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("{}: {e}", path.display()))
}

/// Where a bundle's branches are held while the base is looked for. Deleted
/// before [`fetch_base`] returns.
const INCOMING: &str = "refs/agent-sign/incoming";

/// Makes the working copy `dir` (an existing empty folder) from `bundle`, with
/// only `base` taken from it (L4): `git init`, a fetch of every branch of the
/// bundle into [`INCOMING`], a check that `base` is a commit there, then the
/// holding refs are deleted. What stays: [`BASE_REF`] at `base`, `HEAD` at
/// `base` checked out, and a branch of the bundle's that was at exactly
/// `base` (as the branch checked out; else `HEAD` is detached). A branch the
/// approval never named, and any commit past `base`, are on no ref, so
/// nothing of them is reachable and the end step (which bundles the branches
/// that moved past [`BASE_REF`]) can't return them. Their objects may stay in
/// the object store (a fetch indexes the whole pack), unreachable and never
/// sent anywhere. Fetching from a bundle runs nothing from it. A plain
/// message on any failure.
pub fn fetch_base(dir: &Path, bundle: &Path, base: &str) -> Result<(), String> {
    let hex = |c: char| c.is_ascii_digit() || ('a'..='f').contains(&c);
    if !(base.len() == 40 || base.len() == 64) || !base.chars().all(hex) {
        return Err(format!("{base:?} isn't a git commit id"));
    }
    git(dir, &["init", "-q"])?;
    let b = bundle.to_string_lossy().to_string();
    let spec = format!("+refs/heads/*:{INCOMING}/*");
    git(
        dir,
        &["fetch", "-q", "--no-tags", "--update-head-ok", &b, &spec],
    )?;
    let got = git(
        dir,
        &["rev-parse", "--verify", "-q", &format!("{base}^{{commit}}")],
    )
    .map_err(|_| format!("the bundle doesn't hold the base commit {base}"))?;
    if got != base {
        return Err(format!("the base is {got}, not {base}"));
    }
    let held = git(
        dir,
        &[
            "for-each-ref",
            "--format=%(objectname) %(refname)",
            INCOMING,
        ],
    )?;
    let mut branch = None;
    for line in held.lines() {
        let Some((id, name)) = line.split_once(' ') else {
            continue;
        };
        if id == base
            && branch.is_none()
            && let Some(short) = name.strip_prefix(&format!("{INCOMING}/"))
        {
            branch = Some(short.to_string());
        }
        git(dir, &["update-ref", "-d", name])?;
    }
    git(dir, &["update-ref", BASE_REF, base])?;
    // Checked out detached first: a branch name from the bundle is never an
    // argument to checkout (it could start with '-').
    git(dir, &["checkout", "-q", "--detach", base])?;
    if let Some(short) = branch {
        let full = format!("refs/heads/{short}");
        git(dir, &["update-ref", &full, base])?;
        git(dir, &["symbolic-ref", "HEAD", &full])?;
    }
    Ok(())
}

/// `agent-sign session-exec` (see the module documentation). Returns only
/// when it couldn't run the program.
pub fn exec() -> ExitCode {
    match exec_inner() {
        Ok(never) => match never {},
        Err(e) => {
            eprintln!("agent-sign session-exec: {e}");
            ExitCode::from(1)
        }
    }
}

enum Never {}

fn exec_inner() -> Result<Never, String> {
    let (config, n) = this_slot(Step::Exec)?;
    let creds = std::env::var_os("CREDENTIALS_DIRECTORY")
        .ok_or("systemd handed over no spec (no CREDENTIALS_DIRECTORY)")?;
    let text = fs::read_to_string(Path::new(&creds).join("spec"))
        .map_err(|e| format!("the session's spec can't be read ({e})"))?;
    let spec: SessionSpec = serde_json::from_str(&text)
        .map_err(|e| format!("the session's spec can't be read ({e})"))?;
    // Defence in depth (M1): the launcher allows only LANG and TERM; so does
    // this, before anything of the spec is used.
    crate::launcher::check_env(&spec.env)
        .map_err(|e| format!("the session's spec was refused: {e}"))?;
    if spec.slot != n {
        return Err(format!(
            "the spec is for slot {}, and this is slot {n}",
            spec.slot
        ));
    }
    let cur = current_of(&config, n);
    std::env::set_current_dir(&cur).map_err(|e| format!("{}: {e}", cur.display()))?;
    for d in [HOME, WORK, TMP] {
        make_private_dir(&cur.join(d))?;
    }
    let home = cur.join(HOME);
    for r in &spec.repos {
        if !crate::launcher::is_repo_name(&r.name) {
            return Err(format!("{:?} can't name a repository", r.name));
        }
        let bundle = cur.join(IN).join(format!("{}.bundle", r.name));
        let dir = cur.join(WORK).join(&r.name);
        fs::create_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        fetch_base(&dir, &bundle, &r.base).map_err(|e| format!("{}: {e}", r.name))?;
    }
    // Who this session is, from the service, which knows it by uid and unit.
    let identity = match crate::protocol::send_request(
        &crate::protocol::client_socket_path(),
        &crate::protocol::Request::SessionIdentity,
    ) {
        Ok(crate::protocol::Response::SessionIdentity { identity }) => identity,
        Ok(crate::protocol::Response::Error { message }) => {
            return Err(format!(
                "the agent-sign service didn't say who this session is: {message}"
            ));
        }
        Ok(other) => return Err(format!("unexpected answer from the service: {other:?}")),
        Err(e) => return Err(format!("the agent-sign service didn't answer ({e})")),
    };
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let bin = exe
        .parent()
        .ok_or("this program has no folder")?
        .to_path_buf();
    let wrap = bin
        .parent()
        .map(|p| p.join("wrap"))
        .ok_or("no wrap folder")?;
    if !wrap.join("git").exists() {
        return Err(format!(
            "the git wrapper isn't at {}: a session never runs without it",
            wrap.join("git").display()
        ));
    }
    let gitconfig = home.join(".gitconfig");
    let gc = gitconfig.to_string_lossy().to_string();
    let signer = bin.join("agent-ssh-sign").to_string_lossy().to_string();
    for (k, v) in [
        ("user.name", identity.name.as_str()),
        ("user.email", identity.principal.as_str()),
        ("gpg.format", "ssh"),
        ("gpg.ssh.program", signer.as_str()),
        ("commit.gpgsign", "true"),
    ] {
        git(&cur, &["config", "--file", &gc, k, v])?;
    }
    let start = spec
        .repos
        .first()
        .map_or_else(|| cur.clone(), |r| cur.join(WORK).join(&r.name));
    let path: OsString = format!("{}:/usr/local/bin:/usr/bin:/bin", wrap.display()).into();
    let mut env: Vec<(OsString, OsString)> = crate::launch::scrubbed_env(
        spec.env
            .iter()
            .map(|(k, v)| (OsString::from(k), OsString::from(v))),
    );
    env.retain(|(k, _)| !["HOME", "PATH", "TMPDIR", "PWD"].contains(&k.to_str().unwrap_or("")));
    env.push(("HOME".into(), home.into_os_string()));
    env.push(("PATH".into(), path));
    env.push(("TMPDIR".into(), cur.join(TMP).into_os_string()));
    let (program, args) = spec
        .command
        .split_first()
        .ok_or("there is no program to run")?;
    eprintln!(
        "[agent-sign session-exec] session {} in slot {n}: signs as {}, in an account of its own",
        spec.session, identity.principal
    );
    let err = Command::new(program)
        .args(args)
        .env_clear()
        .envs(env)
        .current_dir(&start)
        .exec();
    Err(format!("{program} couldn't be run ({err})"))
}

/// What the end step found in one working copy `dir` (named `name`), with
/// its new commits bundled into `out/<name>.bundle`: "clean" or "left: ...".
/// It changes nothing in the working copy. Public for its test, which runs git and so lives in
/// its own test program (`tests/test_session_end_check.rs`): a process
/// started inside the library's unit tests holds copies of other tests'
/// descriptors until it runs its program.
pub fn check_working_copy(dir: &Path, out: &Path, name: &str) -> String {
    let mut left = Vec::new();
    match git(
        dir,
        &[
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--ignored=no",
        ],
    ) {
        Ok(s) if s.is_empty() => {}
        Ok(_) => left.push("uncommitted changes or untracked files".to_string()),
        Err(e) => left.push(format!("its status couldn't be read ({e})")),
    }
    match git(dir, &["stash", "list"]) {
        Ok(s) if s.is_empty() => {}
        Ok(_) => left.push("a stash".to_string()),
        Err(e) => left.push(format!("its stashes couldn't be read ({e})")),
    }
    for marker in [
        "MERGE_HEAD",
        "rebase-merge",
        "rebase-apply",
        "CHERRY_PICK_HEAD",
        "REVERT_HEAD",
        "BISECT_LOG",
    ] {
        if let Ok(p) = git(dir, &["rev-parse", "--git-path", marker])
            && dir.join(&p).exists()
        {
            left.push(format!("{marker} in progress"));
        }
    }
    let has_base = git(dir, &["rev-parse", "--verify", "-q", BASE_REF]).is_ok();
    let bundle = out.join(format!("{name}.bundle"));
    let b = bundle.to_string_lossy().to_string();
    let mut args = vec!["bundle", "create", "-q", b.as_str(), "--branches"];
    if has_base {
        args.extend(["--not", BASE_REF]);
    }
    match git(dir, &args) {
        Ok(_) => {}
        // Nothing moved past the base: an empty bundle is refused, and there
        // is nothing to return.
        Err(e) if e.contains("empty bundle") => {}
        Err(e) => left.push(format!("its commits couldn't be bundled ({e})")),
    }
    if bundle.exists() {
        let _ = fs::set_permissions(&bundle, fs::Permissions::from_mode(0o640));
    }
    if left.is_empty() {
        "clean".to_string()
    } else {
        format!("left: {}", left.join(", "))
    }
}

/// `agent-sign session-end` (see the module documentation).
pub fn end() -> ExitCode {
    match end_inner() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("agent-sign session-end: {e}");
            ExitCode::from(1)
        }
    }
}

fn end_inner() -> Result<(), String> {
    let (config, n) = this_slot(Step::End)?;
    end_in(&current_of(&config, n))
}

/// The end step on a session folder `cur` (the slot's `current/`): checks
/// each working copy in `cur/work/`, bundles what moved, writes
/// `out/status.json` and opens `out/` to the slot's group. It removes
/// nothing, so the working copies stay for the launcher to move to the
/// Trash whole (the suite PM's decision D6 (b), 1 Nov 2026). Public for its
/// test, which runs git and so lives in its own test program
/// (`tests/test_session_end_check.rs`); the slot lookup stays in `end_inner`.
pub fn end_in(cur: &Path) -> Result<(), String> {
    let out = cur.join(OUT);
    match fs::symlink_metadata(&out) {
        Ok(m) if m.is_dir() => {}
        Ok(_) => {
            return Err(format!(
                "{} isn't a folder; nothing was checked",
                out.display()
            ));
        }
        Err(_) => fs::create_dir(&out).map_err(|e| format!("{}: {e}", out.display()))?,
    }
    fs::set_permissions(&out, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    let mut status = serde_json::Map::new();
    let work = cur.join(WORK);
    let mut names: Vec<String> = match fs::read_dir(&work) {
        Ok(rd) => rd
            .flatten()
            .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| crate::launcher::is_repo_name(n))
            .collect(),
        Err(_) => Vec::new(),
    };
    names.sort();
    for name in names {
        let dir = work.join(&name);
        let said = check_working_copy(&dir, &out, &name);
        status.insert(name, serde_json::Value::String(said));
    }
    let text = serde_json::Value::Object(status).to_string();
    let status_path = out.join(STATUS_FILE);
    fs::write(&status_path, text).map_err(|e| format!("{}: {e}", status_path.display()))?;
    fs::set_permissions(&status_path, fs::Permissions::from_mode(0o640))
        .map_err(|e| e.to_string())?;
    fs::set_permissions(&out, fs::Permissions::from_mode(0o750)).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- L2: the mount at current/ must be the slot's own current/ -----------

    /// The mounts every unit's namespace has that matter here: `/` on the
    /// first partition, `/run` (another device), and a tmpfs over
    /// `/var/lib/agent-slots` (`TemporaryFileSystem=`).
    const BASE: &str = "\
22 1 8:1 / / ro,relatime shared:1 - ext4 /dev/sda1 rw
31 22 0:25 / /run rw,nosuid,nodev shared:5 - tmpfs tmpfs rw,mode=755
40 22 0:30 / /var/lib/agent-slots ro,nosuid,nodev - tmpfs tmpfs ro,mode=755
";

    fn with(extra: &str) -> String {
        format!("{BASE}{extra}")
    }

    fn slot1() -> &'static Path {
        Path::new("/var/lib/agent-slots/1/current")
    }

    /// The bind systemd makes for slot 1 when `/` holds /var.
    const GOOD: &str = "77 40 8:1 /var/lib/agent-slots/1/current /var/lib/agent-slots/1/current rw,relatime - ext4 /dev/sda1 rw\n";

    #[test]
    fn l2_the_slots_own_current_is_accepted() {
        assert_eq!(check_current_mount(&with(GOOD), slot1()), Ok(()));
    }

    #[test]
    fn l2_with_var_on_its_own_filesystem_the_bind_root_is_relative_to_that_filesystem() {
        let m = "\
22 1 8:1 / / ro,relatime shared:1 - ext4 /dev/sda1 rw
23 22 8:2 / /var ro,relatime shared:2 - ext4 /dev/sda2 rw
40 23 0:30 / /var/lib/agent-slots ro - tmpfs tmpfs ro
77 40 8:2 /lib/agent-slots/1/current /var/lib/agent-slots/1/current rw - ext4 /dev/sda2 rw
";
        assert_eq!(check_current_mount(m, slot1()), Ok(()));
        // The same path from the wrong device (a link to the first
        // partition's copy of the path) is refused.
        let wrong_dev = m.replace(
            "77 40 8:2 /lib/agent-slots/1/current",
            "77 40 8:1 /lib/agent-slots/1/current",
        );
        assert!(check_current_mount(&wrong_dev, slot1()).is_err());
        // The root-partition spelling on the /var device is refused too: the
        // root of a bind is relative to its own filesystem.
        let full_path = m.replace(
            "77 40 8:2 /lib/agent-slots/1/current",
            "77 40 8:2 /var/lib/agent-slots/1/current",
        );
        assert!(check_current_mount(&full_path, slot1()).is_err());
    }

    #[test]
    fn l2_a_filesystem_mounted_from_a_subfolder_adds_its_own_root() {
        let m = "\
22 1 8:1 /subvol / ro shared:1 - btrfs /dev/sda1 rw
40 22 0:30 / /var/lib/agent-slots ro - tmpfs tmpfs ro
77 40 8:1 /subvol/var/lib/agent-slots/1/current /var/lib/agent-slots/1/current rw - btrfs /dev/sda1 rw
";
        assert_eq!(check_current_mount(m, slot1()), Ok(()));
        let bad = m.replace("/subvol/var/lib", "/var/lib");
        assert!(check_current_mount(&bad, slot1()).is_err());
    }

    #[test]
    fn l2_a_followed_link_to_etc_is_refused() {
        let m =
            with("77 40 8:1 /etc /var/lib/agent-slots/1/current rw,relatime - ext4 /dev/sda1 rw\n");
        let e = check_current_mount(&m, slot1()).unwrap_err();
        assert!(e.contains("/etc"), "{e}");
    }

    #[test]
    fn l2_a_followed_link_to_another_slots_current_is_refused() {
        let m = with(
            "77 40 8:1 /var/lib/agent-slots/2/current /var/lib/agent-slots/1/current rw - ext4 /dev/sda1 rw\n",
        );
        assert!(check_current_mount(&m, slot1()).is_err());
    }

    #[test]
    fn l2_a_lookalike_path_that_ends_the_same_way_is_refused() {
        for root in [
            "/var/lib/agent-launch/agent-slots/1/current",
            "/srv/var/lib/agent-slots/1/current",
            "/var/lib/agent-slots/1/current/work",
            "/var/lib/agent-slots/1/currentx",
            "/var/lib/agent-slots/1/current/..",
            "/var/lib/agent-slots//1/current",
        ] {
            let m = with(&format!(
                "77 40 8:1 {root} /var/lib/agent-slots/1/current rw - ext4 /dev/sda1 rw\n"
            ));
            assert!(check_current_mount(&m, slot1()).is_err(), "{root}");
        }
    }

    #[test]
    fn l2_the_right_path_on_a_different_device_is_refused() {
        for dev in ["0:25", "8:2", "8:11", "0:1"] {
            let m = with(&format!(
                "77 40 {dev} /var/lib/agent-slots/1/current /var/lib/agent-slots/1/current rw - ext4 x rw\n"
            ));
            assert!(check_current_mount(&m, slot1()).is_err(), "{dev}");
        }
    }

    // -- R3: the component boundary of the holder search ---------------------

    /// A mount at a string-prefix lookalike of the slots folder (`/var/lib/agent`
    /// is not a folder above `/var/lib/agent-slots`), on another device.
    const LOOKALIKE: &str = "33 22 8:9 / /var/lib/agent rw,relatime - ext4 /dev/sda9 rw\n";

    #[test]
    fn r3_a_mount_at_a_string_prefix_lookalike_of_the_slots_folder_is_not_its_holder() {
        // The real holder is `/` on 8:1; the good bind is on 8:1. A bare
        // starts_with would take /var/lib/agent (8:9) as the holder and
        // wrongly refuse the slot's own current/.
        let m = with(&format!("{LOOKALIKE}{GOOD}"));
        assert_eq!(check_current_mount(&m, slot1()), Ok(()));
        // Order in the file doesn't matter.
        let m = with(&format!("{GOOD}{LOOKALIKE}"));
        assert_eq!(check_current_mount(&m, slot1()), Ok(()));
    }

    #[test]
    fn r3_a_lookalike_mount_is_never_taken_as_the_holder_to_accept_a_wrong_bind() {
        // With the lookalike (8:9, root /x) wrongly taken as the holder, the
        // expected root would be /x + "-slots/1/current", so this bind on
        // 8:9 would be accepted. It is on the wrong device for the real
        // holder (`/` on 8:1) and must be refused.
        let lookalike = "33 22 8:9 /x /var/lib/agent rw - ext4 /dev/sda9 rw\n";
        let bind =
            "77 40 8:9 /x-slots/1/current /var/lib/agent-slots/1/current rw - ext4 /dev/sda9 rw\n";
        let m = with(&format!("{lookalike}{bind}"));
        assert!(check_current_mount(&m, slot1()).is_err());
    }

    #[test]
    fn l2_nothing_mounted_at_current_is_refused() {
        let e = check_current_mount(BASE, slot1()).unwrap_err();
        assert!(e.contains("nothing is mounted"), "{e}");
        // A mount somewhere under it, or at a lookalike point, isn't it.
        let m = with(
            "77 40 8:1 /var/lib/agent-slots/1/current /var/lib/agent-slots/1/current/home rw - ext4 /dev/sda1 rw\n78 40 8:1 /var/lib/agent-slots/1/current /var/lib/agent-slots/1/current2 rw - ext4 /dev/sda1 rw\n",
        );
        assert!(check_current_mount(&m, slot1()).is_err());
    }

    #[test]
    fn l2_the_topmost_mount_at_current_decides() {
        let bad = "78 40 8:1 /etc /var/lib/agent-slots/1/current rw - ext4 /dev/sda1 rw\n";
        assert!(check_current_mount(&with(&format!("{GOOD}{bad}")), slot1()).is_err());
        assert_eq!(
            check_current_mount(&with(&format!("{bad}{GOOD}")), slot1()),
            Ok(())
        );
        // A good-looking mount at another point that merely ends the same way
        // does not stand in for the one at current/.
        let other =
            "79 40 8:1 /var/lib/agent-slots/1/current /run/current rw - ext4 /dev/sda1 rw\n";
        assert!(check_current_mount(&with(&format!("{bad}{other}")), slot1()).is_err());
    }

    #[test]
    fn l2_the_check_is_for_this_slot_and_reads_escaped_names() {
        // Slot 2's good bind doesn't make slot 1's mount good, nor the reverse.
        let two = "77 40 8:1 /var/lib/agent-slots/2/current /var/lib/agent-slots/2/current rw - ext4 /dev/sda1 rw\n";
        assert!(check_current_mount(&with(two), slot1()).is_err());
        assert_eq!(
            check_current_mount(&with(two), Path::new("/var/lib/agent-slots/2/current")),
            Ok(())
        );
        // Spaces arrive as \040 in mountinfo.
        let m = "\
22 1 8:1 / / ro - ext4 /dev/sda1 rw
40 22 0:30 / /srv/my\\040slots ro - tmpfs tmpfs ro
77 40 8:1 /srv/my\\040slots/1/current /srv/my\\040slots/1/current rw - ext4 /dev/sda1 rw
";
        assert_eq!(
            check_current_mount(m, Path::new("/srv/my slots/1/current")),
            Ok(())
        );
        assert!(check_current_mount(m, Path::new("/srv/my/slots/1/current")).is_err());
    }

    #[test]
    fn l2_unreadable_input_and_odd_paths_are_refused() {
        assert!(check_current_mount("", slot1()).is_err());
        assert!(check_current_mount(&with("garbage\n"), slot1()).is_err());
        assert!(
            check_current_mount(&with(GOOD), Path::new("var/lib/agent-slots/1/current")).is_err()
        );
        assert!(
            check_current_mount(
                &with(GOOD),
                Path::new("/var/lib/agent-slots/1/../1/current")
            )
            .is_err()
        );
    }

    #[test]
    fn each_unit_has_its_own_cgroups() {
        let exec = cgroups_of("agent-session@3.service");
        assert_eq!(
            exec,
            crate::kernel_facts::unit_cgroups("agent-session@3.service").to_vec()
        );
        let end = cgroups_of("agent-session-end@3.service");
        assert_eq!(
            end[1],
            "0::/system.slice/system-agent\\x2dsession\\x2dend.slice/agent-session-end@3.service"
        );
    }
}
