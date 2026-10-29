//! Follow-up to the per-agent identity change (28 Oct 2026): Taylor's two
//! new requirements and the findings of the independent check after the
//! review-fix round. Each group was written before its change and failed on
//! the code before it (the record is in `docs/ADVERSARIAL_REVIEW.md`, under
//! "Follow-up round"):
//!
//! A. The agents' certificate authority key is never stored unprotected: it
//!    is made in memory at each start, its public half is appended to
//!    `keys/agents_cas.pub`, `agent-sign trust-line` trusts every one, the
//!    service rewrites only the managed block in the user's
//!    allowed-signers file, and a private key file left by an earlier build
//!    stops the service (the installer deletes it, after asking).
//! B. The installer routes the user's own signing through agent-sign
//!    (`gpg.ssh.program` = `agent-ssh-sign`, the old program as
//!    `fallback_program`), says so before asking, and the uninstaller puts
//!    the old program back; `agent-sign doctor` reports it.
//! C. An unmarked commit with no terminal that asks to sign commits
//!    unsigned instead of failing.
//! D. A repository's file can't lower `max_commits_per_minute` (the service
//!    can't enforce it), and says so.
//! E. The installer's config template describes attribution as it is.
//! F. The old-key GitHub notice is printed only while the old key is still
//!    trusted in allowed_signers.
//! G. The old shared key's private half is deleted, not moved aside.
//!
//! Isolation: every process starts from an empty environment plus a
//! temporary HOME, a temporary global git config, no system config, and a
//! PATH without agent-sign's installed `bin`; the service's socket is in the
//! temporary directory. The installer runs from a copy of `scripts/` with
//! the test's own builds as its programs, and with stand-ins first on PATH
//! for everything that would reach the real machine (`launchctl`,
//! `systemctl`, `pkill`, `pgrep`, `codesign`, `curl`, `cargo`), so it never
//! touches the real home, services or processes. Every run is bounded in
//! time.

use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use tempfile::{TempDir, tempdir};

const USER_NAME: &str = "Human Developer";
const USER_EMAIL: &str = "dev@example.com";

/// Every run of a program under test gets at most this long.
const RUN_LIMIT: Duration = Duration::from_secs(30);

const SESSION: &str = "followup-session";
const CLAUDE: &[(&str, &str)] = &[("CLAUDECODE", "1"), ("CLAUDE_CODE_SESSION_ID", SESSION)];

/// The managed block's marker lines in the allowed-signers file.
const BLOCK_BEGIN: &str = "# agent-sign: agents' certificate authorities, managed; do not edit";
const BLOCK_END: &str = "# agent-sign: end of agents' certificate authorities";

/// What every allowed-signers line for the agents' authorities starts with.
const TRUST_PREFIX: &str = "*@agents.local cert-authority,namespaces=\"git\" ";

/// The line an unmarked commit with no terminal prints when it was going to
/// be signed.
const UNSIGNED_NOTE: &str = "agent-sign: no terminal and no agent mark, so this commit was made unsigned (an editor's commit button? commit in a terminal to sign it as yourself)";

fn claude_principal() -> String {
    let session8: String = Sha256::digest(SESSION.as_bytes())[..4]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("claude-code.{session8}@agents.local")
}

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn cleaned_path() -> OsString {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let kept: Vec<PathBuf> = std::env::split_paths(&path)
        .filter(|p| !p.to_string_lossy().contains(".agent-sign"))
        .collect();
    std::env::join_paths(kept).unwrap()
}

fn find_on(path: &OsString, name: &str) -> PathBuf {
    std::env::split_paths(path)
        .map(|d| d.join(name))
        .find(|p| p.is_file())
        .unwrap_or_else(|| panic!("no {name} on the cleaned PATH"))
}

fn text(out: &Output) -> String {
    format!(
        "status: {}\nstdout: {}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// Runs `cmd` (stdin as already set), killing it past [`RUN_LIMIT`].
fn run_within(mut cmd: Command, what: &str, input: Option<&str>) -> Output {
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    if input.is_some() {
        cmd.stdin(Stdio::piped());
    }
    let mut child = cmd.spawn().unwrap();
    // The input stays open until the program ends: `script` turns the end
    // of its input into an end-of-file in the terminal, which a prompt
    // would read before the answer.
    let _held_open = input.map(|input| {
        let mut stdin = child.stdin.take().unwrap();
        let _ = stdin.write_all(input.as_bytes());
        stdin
    });
    let start = Instant::now();
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if start.elapsed() > RUN_LIMIT {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{what} didn't finish within {RUN_LIMIT:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

// ---------------------------------------------------------------------------
// The isolated world.
// ---------------------------------------------------------------------------

struct World {
    _dir: TempDir,
    home: PathBuf,
    global_config: PathBuf,
    path: OsString,
    real_git: PathBuf,
    ssh_keygen: PathBuf,
    socket: PathBuf,
    signer_log: PathBuf,
    service: Option<Child>,
}

impl Drop for World {
    fn drop(&mut self) {
        self.stop_service();
    }
}

impl World {
    /// A world whose `~/.agent-sign/config.toml` is `config`, the user
    /// signing with a fake signer that logs each call and fails.
    fn new(config: &str) -> World {
        let dir = tempdir().unwrap();
        let home = dir.path().join("home");
        fs::create_dir_all(&home).unwrap();
        let path = cleaned_path();
        let world = World {
            global_config: home.join("user.gitconfig"),
            socket: dir.path().join("agent-sign-test.sock"),
            signer_log: home.join("user-signer.log"),
            real_git: find_on(&path, "git"),
            ssh_keygen: find_on(&path, "ssh-keygen"),
            home,
            path,
            service: None,
            _dir: dir,
        };
        world.write_user_setup(config);
        world
    }

    fn cmd(&self, program: &Path) -> Command {
        let mut cmd = Command::new(program);
        cmd.env_clear();
        for keep in ["TMPDIR", "USER", "LOGNAME", "LANG", "LC_ALL"] {
            if let Some(v) = std::env::var_os(keep) {
                cmd.env(keep, v);
            }
        }
        cmd.env("HOME", &self.home)
            .env("PATH", &self.path)
            .env("GIT_CONFIG_GLOBAL", &self.global_config)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_EDITOR", "true")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("AGENT_SIGN_SOCKET", &self.socket)
            .env("AGENT_SIGN_REAL_GIT", &self.real_git)
            .env("AGENT_SIGN_BIN", env!("CARGO_BIN_EXE_agent-ssh-sign"))
            .env("AGENT_SIGN_CONNECT_WAIT_MS", "200")
            .stdin(Stdio::null());
        cmd
    }

    fn state(&self) -> PathBuf {
        self.home.join(".agent-sign")
    }

    fn keys(&self) -> PathBuf {
        self.state().join("keys")
    }

    fn fake_signer(&self) -> PathBuf {
        self.home.join("user-signer.sh")
    }

    fn write_user_setup(&self, config: &str) {
        let key = self.home.join("user_key");
        let out = self
            .cmd(&self.ssh_keygen)
            .args(["-q", "-t", "ed25519", "-N", "", "-C", "user", "-f"])
            .arg(&key)
            .output()
            .unwrap();
        assert!(out.status.success(), "ssh-keygen: {}", text(&out));
        let fake = self.fake_signer();
        fs::write(
            &fake,
            format!(
                "#!/bin/sh\necho \"called: $*\" >> '{}'\nexit 1\n",
                self.signer_log.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&fake, fs::Permissions::from_mode(0o755)).unwrap();
        fs::create_dir_all(self.state()).unwrap();
        fs::write(self.state().join("config.toml"), config).unwrap();
        fs::write(
            &self.global_config,
            format!(
                "[user]\n\tname = {USER_NAME}\n\temail = {USER_EMAIL}\n\tsigningkey = \"{}.pub\"\n\
                 [commit]\n\tgpgsign = true\n[gpg]\n\tformat = ssh\n[gpg \"ssh\"]\n\tprogram = \"{}\"\n",
                key.display(),
                fake.display()
            ),
        )
        .unwrap();
    }

    fn set_global(&self, key: &str, value: &str) {
        let out = self
            .cmd(&self.real_git)
            .args(["config", "--global", key, value])
            .output()
            .unwrap();
        assert!(out.status.success(), "git config {key}: {}", text(&out));
    }

    fn get_global(&self, key: &str) -> Option<String> {
        let out = self
            .cmd(&self.real_git)
            .args(["config", "--global", "--get", key])
            .output()
            .unwrap();
        out.status
            .success()
            .then(|| stdout(&out).trim().to_string())
    }

    fn service_log(&self) -> String {
        fs::read_to_string(self.home.join("service.log")).unwrap_or_default()
    }

    fn service_command(&self) -> Command {
        let log = fs::File::options()
            .create(true)
            .append(true)
            .open(self.home.join("service.log"))
            .unwrap();
        let mut cmd = self.cmd(Path::new(env!("CARGO_BIN_EXE_agent-signd")));
        cmd.arg("--socket")
            .arg(&self.socket)
            .env("AGENT_SIGN_TEST_AUTH", "fail")
            .env("AGENT_SIGN_REFUSAL_BACKOFF", "none")
            .stdout(Stdio::null())
            .stderr(Stdio::from(log));
        cmd
    }

    fn start_service(&mut self) {
        self.stop_service();
        self.service = Some(self.service_command().spawn().unwrap());
        let start = Instant::now();
        while !self.socket.exists() {
            if let Some(status) = self.service.as_mut().unwrap().try_wait().unwrap() {
                panic!(
                    "test service stopped ({status}) at start:\n{}",
                    self.service_log()
                );
            }
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "test service didn't start: {}",
                self.service_log()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn stop_service(&mut self) {
        if let Some(mut child) = self.service.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = fs::remove_file(&self.socket);
    }

    /// Starts the service and waits up to 10 seconds for it either to stop
    /// (`Some(status)`) or to open its socket (`None`, and it is stopped).
    fn service_stops_at_start(&mut self) -> Option<std::process::ExitStatus> {
        self.stop_service();
        let mut child = self.service_command().spawn().unwrap();
        let start = Instant::now();
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                return Some(status);
            }
            if self.socket.exists() || start.elapsed() > Duration::from_secs(10) {
                let _ = child.kill();
                let _ = child.wait();
                let _ = fs::remove_file(&self.socket);
                return None;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn signer_calls(&self) -> usize {
        fs::read_to_string(&self.signer_log)
            .map(|s| s.lines().count())
            .unwrap_or(0)
    }

    fn git(&self, repo: &Path, args: &[&str]) -> Output {
        self.cmd(&self.real_git)
            .args(args)
            .current_dir(repo)
            .output()
            .unwrap()
    }

    fn git_ok(&self, repo: &Path, args: &[&str]) -> String {
        let out = self.git(repo, args);
        assert!(out.status.success(), "setup git {args:?}: {}", text(&out));
        stdout(&out).trim().to_string()
    }

    /// The wrapper as a program with no terminal runs it, with `marks` set.
    fn wrapper(&self, repo: &Path, marks: &[(&str, &str)], args: &[&str]) -> Output {
        let mut cmd = self.cmd(Path::new(env!("CARGO_BIN_EXE_agent-git")));
        for (k, v) in marks {
            cmd.env(k, v);
        }
        cmd.args(args).current_dir(repo);
        run_within(cmd, &format!("git {args:?} with {marks:?}"), None)
    }

    /// A repository on branch `work` with one unsigned commit.
    fn repo(&self) -> PathBuf {
        let repo = self.home.join("repo");
        fs::create_dir_all(&repo).unwrap();
        self.git_ok(&repo, &["init", "-q", "-b", "work"]);
        fs::write(repo.join("base.txt"), "base\n").unwrap();
        self.git_ok(&repo, &["add", "base.txt"]);
        self.git_ok(
            &repo,
            &["-c", "commit.gpgsign=false", "commit", "-q", "-m", "base"],
        );
        repo
    }

    fn stage(&self, repo: &Path, file: &str) {
        fs::write(repo.join(file), format!("{file}\n")).unwrap();
        self.git_ok(repo, &["add", file]);
    }

    fn agent_commit(&self, repo: &Path, file: &str) -> String {
        self.stage(repo, file);
        let out = self.wrapper(repo, CLAUDE, &["commit", "-q", "-m", file]);
        assert!(
            out.status.success(),
            "agent commit {file}: {}\nservice log:\n{}",
            text(&out),
            self.service_log()
        );
        self.git_ok(repo, &["rev-parse", "HEAD"])
    }

    /// `agent-sign trust-line`'s output.
    fn trust_line_output(&self) -> Output {
        let mut cmd = self.cmd(Path::new(env!("CARGO_BIN_EXE_agent-sign")));
        cmd.arg("trust-line");
        run_within(cmd, "agent-sign trust-line", None)
    }

    /// `(%G?, %GS)` of `rev`, checked by plain ssh-keygen against an
    /// allowed-signers file holding `allowed`.
    fn signature_under(&self, repo: &Path, rev: &str, allowed: &str) -> (String, String) {
        let file = self.home.join("check_allowed_signers");
        fs::write(&file, allowed).unwrap();
        let program = format!("gpg.ssh.program={}", self.ssh_keygen.display());
        let signers = format!("gpg.ssh.allowedSignersFile={}", file.display());
        let fmt = self.git_ok(
            repo,
            &[
                "-c",
                &program,
                "-c",
                &signers,
                "log",
                "-1",
                "--format=%G?%x1f%GS",
                rev,
            ],
        );
        let (g, s) = fmt.split_once('\x1f').unwrap_or((fmt.as_str(), ""));
        (g.to_string(), s.to_string())
    }

    fn author_and_committer(&self, repo: &Path) -> (String, String) {
        let both = self.git_ok(repo, &["log", "-1", "--format=%an <%ae>%x1f%cn <%ce>"]);
        let (a, c) = both.split_once('\x1f').unwrap();
        (a.to_string(), c.to_string())
    }
}

/// Every regular file under `dir`, recursively.
fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let meta = fs::symlink_metadata(&path).unwrap();
        if meta.is_dir() {
            out.extend(files_under(&path));
        } else if meta.is_file() {
            out.push(path);
        }
    }
    out
}

/// Why `bytes` look like private key material, if they do: an armored
/// private key, or a raw ed25519 seed or keypair (32 or 64 bytes that
/// aren't text).
fn private_key_material(bytes: &[u8]) -> Option<&'static str> {
    if bytes.windows(11).any(|w| w == b"PRIVATE KEY") {
        return Some("an armored private key");
    }
    let is_text = std::str::from_utf8(bytes)
        .map(|s| s.chars().all(|c| !c.is_control() || c == '\n' || c == '\t'))
        .unwrap_or(false);
    if (bytes.len() == 32 || bytes.len() == 64) && !is_text {
        return Some("a raw ed25519 seed");
    }
    None
}

// ---------------------------------------------------------------------------
// A. The agents' certificate authority key is never stored unprotected.
// ---------------------------------------------------------------------------

#[test]
fn a_no_file_under_the_state_dir_holds_private_key_material_after_start() {
    let mut w = World::new("");
    w.start_service();
    let repo = w.repo();
    w.agent_commit(&repo, "a.txt");
    let found: Vec<String> = files_under(&w.state())
        .into_iter()
        .filter_map(|f| {
            private_key_material(&fs::read(&f).unwrap())
                .map(|why| format!("{} ({why})", f.display()))
        })
        .collect();
    assert!(
        found.is_empty(),
        "private key material on disk after the service started: {found:?}"
    );
}

#[test]
fn a_a_commit_certified_before_a_restart_still_verifies_after_it() {
    let mut w = World::new("");
    w.start_service();
    let repo = w.repo();
    let first = w.agent_commit(&repo, "before.txt");
    let ca_before = fs::read_to_string(w.keys().join("agents_ca_ed25519.pub")).unwrap();
    w.start_service(); // stops the first, starts a new one
    let second = w.agent_commit(&repo, "after.txt");
    let ca_after = fs::read_to_string(w.keys().join("agents_ca_ed25519.pub")).unwrap();
    assert_ne!(
        ca_before, ca_after,
        "each start should make a new authority, in memory"
    );

    let out = w.trust_line_output();
    assert!(out.status.success(), "trust-line: {}", text(&out));
    let lines: Vec<String> = stdout(&out).lines().map(str::to_string).collect();
    assert_eq!(
        lines.len(),
        2,
        "trust-line should print one line per authority the service has started with:\n{}",
        stdout(&out)
    );
    assert!(
        lines.iter().all(|l| l.starts_with(TRUST_PREFIX)),
        "{lines:?}"
    );
    let history = fs::read_to_string(w.keys().join("agents_cas.pub")).unwrap();
    assert_eq!(history.lines().count(), 2, "agents_cas.pub: {history}");

    let allowed = stdout(&out);
    for rev in [&first, &second] {
        assert_eq!(
            w.signature_under(&repo, rev, &allowed),
            ("G".to_string(), claude_principal()),
            "commit {rev} under trust-line's output"
        );
    }
}

#[test]
fn a_the_service_rewrites_only_the_managed_trust_block() {
    let mut w = World::new("");
    let allowed = w.home.join("allowed_signers");
    let before_block = format!(
        "{USER_EMAIL} namespaces=\"git\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIUserKeyLine\n\
         # a comment of the user's, with trailing spaces   \n\n{BLOCK_BEGIN}\n"
    );
    let after_block =
        format!("{BLOCK_END}\nother@example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtherKeyLine");
    fs::write(
        &allowed,
        format!("{before_block}{TRUST_PREFIX}ssh-ed25519 AAAAstale\n{after_block}"),
    )
    .unwrap();
    w.set_global("gpg.ssh.allowedSignersFile", &allowed.display().to_string());
    // A second file, without the markers, must be left as it is.
    let unmarked = w.home.join("unmarked_signers");
    let unmarked_content =
        format!("{USER_EMAIL} ssh-ed25519 AAAAx\n{TRUST_PREFIX}ssh-ed25519 AAAAy\n");
    fs::write(&unmarked, &unmarked_content).unwrap();

    w.start_service();
    let trust = w.trust_line_output();
    assert!(trust.status.success(), "trust-line: {}", text(&trust));
    let content = fs::read_to_string(&allowed).unwrap();
    assert!(
        content.starts_with(&before_block),
        "the lines before the block changed:\n{content}"
    );
    assert!(
        content.ends_with(&after_block),
        "the lines after the block changed:\n{content}"
    );
    let block = &content[before_block.len()..content.len() - after_block.len()];
    assert_eq!(
        block,
        stdout(&trust),
        "the block should hold exactly trust-line's lines"
    );

    // And an agent commit verifies through the user's own file.
    let repo = w.repo();
    let rev = w.agent_commit(&repo, "a.txt");
    assert_eq!(
        w.signature_under(&repo, &rev, &content),
        ("G".to_string(), claude_principal())
    );

    // A file with no markers: untouched, byte for byte.
    w.stop_service();
    w.set_global(
        "gpg.ssh.allowedSignersFile",
        &unmarked.display().to_string(),
    );
    w.start_service();
    assert_eq!(fs::read_to_string(&unmarked).unwrap(), unmarked_content);
}

#[test]
fn a_a_ca_private_key_left_by_an_earlier_build_stops_the_service() {
    let mut w = World::new("");
    fs::create_dir_all(w.keys()).unwrap();
    let leftover = w.keys().join("agents_ca_ed25519");
    fs::write(&leftover, [7u8; 32]).unwrap();
    fs::set_permissions(&leftover, fs::Permissions::from_mode(0o600)).unwrap();
    let stopped = w.service_stops_at_start();
    assert!(
        stopped.is_some_and(|s| !s.success()),
        "the service started with an unprotected authority key on disk: {stopped:?}\n{}",
        w.service_log()
    );
    assert!(
        w.service_log().contains(&leftover.display().to_string()),
        "the message should name the file:\n{}",
        w.service_log()
    );
    assert!(leftover.exists(), "the service doesn't delete it itself");
}

// ---------------------------------------------------------------------------
// C. An unmarked commit with no terminal that asks to sign commits unsigned.
// ---------------------------------------------------------------------------

#[test]
fn c_an_unmarked_commit_that_asks_to_sign_is_made_unsigned() {
    let cases: [&[&str]; 4] = [
        &["commit", "-S", "-m", "editor"],
        &["commit", "--gpg-sign=SOMEKEY", "-m", "editor"],
        &["-c", "commit.gpgsign=true", "commit", "-m", "editor"],
        &["commit", "-qS", "-m", "-S"],
    ];
    for args in cases {
        let w = World::new("");
        let repo = w.repo();
        let before = w.git_ok(&repo, &["rev-parse", "HEAD"]);
        w.stage(&repo, "editor.txt");
        let out = w.wrapper(&repo, &[], args);
        assert!(
            out.status.success(),
            "unmarked {args:?} with no terminal failed:\n{}",
            text(&out)
        );
        assert_ne!(w.git_ok(&repo, &["rev-parse", "HEAD"]), before, "{args:?}");
        assert_eq!(
            w.signature_under(&repo, "HEAD", "").0,
            "N",
            "{args:?} should be unsigned"
        );
        let gits_own = format!("{USER_NAME} <{USER_EMAIL}>");
        assert_eq!(w.author_and_committer(&repo), (gits_own.clone(), gits_own));
        assert_eq!(w.signer_calls(), 0, "{args:?} reached the user's signer");
        assert_eq!(
            stderr(&out).lines().filter(|l| *l == UNSIGNED_NOTE).count(),
            1,
            "{args:?} should say why it is unsigned:\n{}",
            text(&out)
        );
        if args.last() == Some(&"-S") {
            assert_eq!(
                w.git_ok(&repo, &["log", "-1", "--format=%s"]),
                "-S",
                "a message that reads -S is the message, not an option"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// D. A repository's file can't lower max_commits_per_minute.
// ---------------------------------------------------------------------------

#[test]
fn d_a_repository_file_cant_lower_max_commits_per_minute() {
    let mut config = agent_sign::config::Config::default();
    let before = config.security.max_commits_per_minute;
    let file: toml::Value = toml::from_str("[security]\nmax_commits_per_minute = 1\n").unwrap();
    let ignored = agent_sign::config::tighten_with_repo_file(&mut config, &file);
    assert_eq!(
        config.security.max_commits_per_minute, before,
        "the service can't enforce a repository's rate, so it mustn't look applied"
    );
    assert_eq!(ignored, ["[security] max_commits_per_minute"]);

    // The wrapper's warning names it, and promises nothing about it.
    let mut w = World::new("");
    w.start_service();
    let repo = w.repo();
    fs::write(
        repo.join(".agent-sign.toml"),
        "[security]\nmax_commits_per_minute = 1\n",
    )
    .unwrap();
    w.stage(&repo, "a.txt");
    let out = w.wrapper(&repo, CLAUDE, &["commit", "-q", "-m", "a"]);
    assert!(out.status.success(), "{}", text(&out));
    let err = stderr(&out);
    let warning: Vec<&str> = err.lines().filter(|l| l.contains("ignored")).collect();
    assert_eq!(warning.len(), 1, "{err}");
    assert!(
        warning[0].contains("max_commits_per_minute"),
        "{}",
        warning[0]
    );
    assert!(
        !warning[0].contains("lower max_commits_per_minute"),
        "the warning still promises a lower rate: {}",
        warning[0]
    );
}

// ---------------------------------------------------------------------------
// E. The installer's template and SPEC describe attribution as it is.
// ---------------------------------------------------------------------------

#[test]
fn e_the_config_template_and_spec_say_every_mode_commits_as_the_agent() {
    let install = fs::read_to_string(manifest_dir().join("scripts/install.sh")).unwrap();
    let start = install
        .find("[attribution]")
        .expect("template's [attribution]");
    let end = start
        + install[start..]
            .find("[human]")
            .expect("template's [human]");
    let template = &install[start..end];
    for stale in ["Committer: you", "Author and Committer: you", "(Agent)"] {
        assert!(
            !template.contains(stale),
            "the template's attribution comments still say {stale:?}:\n{template}"
        );
    }
    assert!(
        template.contains("every mode"),
        "the template should say every mode commits as the agent:\n{template}"
    );
    let spec = fs::read_to_string(manifest_dir().join("SPEC.md")).unwrap();
    assert!(
        !spec.contains("used by \"split\", \"trailers\" and \"alias\" only"),
        "SPEC.md still says [agent] is used by split and alias"
    );
}

// ---------------------------------------------------------------------------
// The installer, run for real against a throwaway home.
// ---------------------------------------------------------------------------

/// A copy of `scripts/` whose installer finds the test's own builds as its
/// programs, and a folder of stand-ins put first on PATH for everything that
/// would reach the real machine. `check-binary-clean.sh` is replaced by one
/// that passes: the test builds carry the test authenticator, which it
/// (rightly) refuses to install.
struct Installer {
    src: PathBuf,
    fakebin: PathBuf,
}

fn installer(w: &World) -> Installer {
    let root = w.home.parent().unwrap().join("installer");
    let src = root.join("src");
    let scripts = src.join("scripts");
    fs::create_dir_all(&scripts).unwrap();
    for entry in fs::read_dir(manifest_dir().join("scripts")).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() {
            fs::copy(entry.path(), scripts.join(entry.file_name())).unwrap();
        }
    }
    fs::write(scripts.join("check-binary-clean.sh"), "#!/bin/sh\nexit 0\n").unwrap();
    let release = src.join("target/release");
    fs::create_dir_all(&release).unwrap();
    for (name, built) in [
        ("agent-signd", env!("CARGO_BIN_EXE_agent-signd")),
        ("agent-sign", env!("CARGO_BIN_EXE_agent-sign")),
        ("agent-ssh-sign", env!("CARGO_BIN_EXE_agent-ssh-sign")),
        ("agent-git", env!("CARGO_BIN_EXE_agent-git")),
    ] {
        fs::copy(built, release.join(name)).unwrap();
    }
    let fakebin = root.join("fakebin");
    fs::create_dir_all(&fakebin).unwrap();
    for (name, status) in [
        ("launchctl", 0),
        ("systemctl", 0),
        ("loginctl", 0),
        ("codesign", 0),
        ("pkill", 1),
        ("pgrep", 1),
        ("curl", 1),
        ("cargo", 1),
    ] {
        let stub = fakebin.join(name);
        fs::write(
            &stub,
            format!("#!/bin/sh\necho \"{name} $*\" >> \"$HOME/stand-ins.log\"\nexit {status}\n"),
        )
        .unwrap();
        fs::set_permissions(&stub, fs::Permissions::from_mode(0o755)).unwrap();
    }
    Installer { src, fakebin }
}

impl Installer {
    fn env(&self, w: &World, program: &str) -> Command {
        let mut cmd = w.cmd(Path::new(program));
        let mut path = vec![self.fakebin.clone()];
        path.extend(std::env::split_paths(&w.path));
        cmd.env("PATH", std::env::join_paths(path).unwrap())
            .env_remove("AGENT_SIGN_SOCKET")
            .env_remove("AGENT_SIGN_REAL_GIT")
            .env_remove("AGENT_SIGN_BIN")
            .env_remove("AGENT_SIGN_CONNECT_WAIT_MS")
            .env("TERM", "dumb")
            .current_dir(&self.src);
        cmd
    }

    /// `install.sh --yes`, with no terminal.
    fn install(&self, w: &World) -> Output {
        let mut cmd = self.env(w, "/bin/bash");
        cmd.arg(self.src.join("scripts/install.sh")).arg("--yes");
        run_within(cmd, "install.sh --yes", None)
    }

    /// `install.sh` in a terminal, answering `answer` to its question.
    fn install_answering(&self, w: &World, answer: &str) -> Output {
        let script = self.src.join("scripts/install.sh");
        #[cfg(target_os = "macos")]
        let cmd = {
            let mut cmd = self.env(w, "/usr/bin/script");
            cmd.args(["-q", "/dev/null", "/bin/bash"]).arg(&script);
            cmd
        };
        #[cfg(not(target_os = "macos"))]
        let cmd = {
            let mut cmd = self.env(w, "/usr/bin/script");
            cmd.args([
                "-qec",
                &format!("/bin/bash '{}'", script.display()),
                "/dev/null",
            ]);
            cmd
        };
        run_within(cmd, "install.sh in a terminal", Some(answer))
    }

    /// `install.sh` in a terminal whose input ends at once, as when the
    /// user presses Ctrl-D at the question.
    fn install_with_closed_input(&self, w: &World) -> Output {
        let script = self.src.join("scripts/install.sh");
        #[cfg(target_os = "macos")]
        let mut cmd = {
            let mut cmd = self.env(w, "/usr/bin/script");
            cmd.args(["-q", "/dev/null", "/bin/bash"]).arg(&script);
            cmd
        };
        #[cfg(not(target_os = "macos"))]
        let mut cmd = {
            let mut cmd = self.env(w, "/usr/bin/script");
            cmd.args([
                "-qec",
                &format!("/bin/bash '{}'", script.display()),
                "/dev/null",
            ]);
            cmd
        };
        cmd.stdin(Stdio::null());
        run_within(cmd, "install.sh with closed input", None)
    }

    fn uninstall(&self, w: &World) -> Output {
        let mut cmd = self.env(w, "/bin/bash");
        cmd.arg(self.src.join("scripts/uninstall.sh"));
        run_within(cmd, "uninstall.sh", None)
    }
}

fn all_output(out: &Output) -> String {
    format!("{}{}", stdout(out), stderr(out))
}

/// The installed signing program, as the installer names it.
fn installed_agent_ssh_sign(w: &World) -> String {
    w.state().join("bin/agent-ssh-sign").display().to_string()
}

fn config_fallback(w: &World) -> Option<String> {
    let config = fs::read_to_string(w.state().join("config.toml")).ok()?;
    let value: toml::Value = toml::from_str(&config).ok()?;
    value
        .get("ssh")?
        .get("fallback_program")?
        .as_str()
        .map(str::to_string)
}

// ---------------------------------------------------------------------------
// B. The installer routes the user's own signing through agent-sign.
// ---------------------------------------------------------------------------

#[test]
fn b_the_installer_routes_the_users_signing_and_uninstall_restores_it() {
    // The user signs with their own program (the fake signer here).
    let w = World::new("");
    fs::remove_dir_all(w.state()).unwrap();
    let inst = installer(&w);
    let theirs = w.fake_signer().display().to_string();
    assert_eq!(
        w.get_global("gpg.ssh.program").as_deref(),
        Some(theirs.as_str())
    );

    let out = inst.install(&w);
    assert!(out.status.success(), "install: {}", all_output(&out));
    assert_eq!(
        w.get_global("gpg.ssh.program"),
        Some(installed_agent_ssh_sign(&w)),
        "the user's signing should go through agent-ssh-sign:\n{}",
        all_output(&out)
    );
    assert_eq!(config_fallback(&w).as_deref(), Some(theirs.as_str()));

    // doctor says so.
    let mut doctor = inst.env(&w, &w.state().join("bin/agent-sign").display().to_string());
    doctor.arg("doctor");
    let report = stdout(&run_within(doctor, "agent-sign doctor", None));
    assert!(
        report.contains("Your own signing goes through agent-sign"),
        "doctor should report the routing:\n{report}"
    );

    // Installing again keeps the user's program as the fallback.
    let out = inst.install(&w);
    assert!(out.status.success(), "reinstall: {}", all_output(&out));
    assert_eq!(config_fallback(&w).as_deref(), Some(theirs.as_str()));

    let out = inst.uninstall(&w);
    assert!(out.status.success(), "uninstall: {}", all_output(&out));
    assert_eq!(
        w.get_global("gpg.ssh.program").as_deref(),
        Some(theirs.as_str()),
        "uninstall should put the user's program back:\n{}",
        all_output(&out)
    );
}

#[test]
fn b_with_no_program_set_uninstall_leaves_it_unset_again() {
    let w = World::new("");
    fs::remove_dir_all(w.state()).unwrap();
    let out = w
        .cmd(&w.real_git)
        .args(["config", "--global", "--unset", "gpg.ssh.program"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let inst = installer(&w);
    let out = inst.install(&w);
    assert!(out.status.success(), "install: {}", all_output(&out));
    assert_eq!(
        w.get_global("gpg.ssh.program"),
        Some(installed_agent_ssh_sign(&w))
    );
    assert_eq!(config_fallback(&w).as_deref(), Some("ssh-keygen"));
    let out = inst.uninstall(&w);
    assert!(out.status.success(), "uninstall: {}", all_output(&out));
    assert_eq!(
        w.get_global("gpg.ssh.program"),
        None,
        "{}",
        all_output(&out)
    );
}

#[test]
fn b_doctor_reports_when_the_users_signing_isnt_routed() {
    let w = World::new("");
    let mut doctor = w.cmd(Path::new(env!("CARGO_BIN_EXE_agent-sign")));
    doctor.arg("doctor");
    let report = stdout(&run_within(doctor, "agent-sign doctor", None));
    assert!(
        report.contains("Your own signing doesn't go through agent-sign"),
        "doctor should say the routing isn't in place:\n{report}"
    );
}

#[test]
fn b_g_the_summary_names_the_routing_and_the_deletion_before_asking() {
    let w = World::new("");
    fs::create_dir_all(w.keys()).unwrap();
    let legacy = w.keys().join("agent_ed25519");
    // Assembled at run time, so the repository's own history scan for
    // private key blocks never matches this stand-in.
    let header = format!("-----BEGIN OPENSSH {} KEY-----", "PRIVATE");
    fs::write(&legacy, format!("{header}\nx\n")).unwrap();
    let inst = installer(&w);
    let out = inst.install_answering(&w, "n\n");
    let shown = all_output(&out);
    assert!(shown.contains("This will:"), "no summary:\n{shown}");
    assert!(
        shown.contains("gpg.ssh.program") && shown.contains("agent-ssh-sign"),
        "the summary should say the user's signing is routed:\n{shown}"
    );
    assert!(
        shown.contains("delete") && shown.contains("agent_ed25519"),
        "the summary should list deleting the old key's private half:\n{shown}"
    );
    assert!(legacy.exists(), "answering no must change nothing");
    assert_eq!(
        w.get_global("gpg.ssh.program"),
        Some(w.fake_signer().display().to_string())
    );
}

// ---------------------------------------------------------------------------
// A (installer). The managed block, and an unprotected authority key.
// ---------------------------------------------------------------------------

#[test]
fn a_the_installer_deletes_the_authority_key_and_writes_the_managed_block() {
    let mut w = World::new("");
    fs::remove_dir_all(w.state()).unwrap();
    let allowed = w.home.join("allowed_signers");
    let users_lines = format!("{USER_EMAIL} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIUser\n");
    // An earlier development build: its authority's private key on disk, and
    // its bare trust line.
    fs::create_dir_all(w.keys()).unwrap();
    let old_ca = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOldDevBuildAuthority";
    fs::write(w.keys().join("agents_ca_ed25519"), [5u8; 32]).unwrap();
    fs::write(
        w.keys().join("agents_ca_ed25519.pub"),
        format!("{old_ca}\n"),
    )
    .unwrap();
    fs::write(&allowed, format!("{users_lines}{TRUST_PREFIX}{old_ca}\n")).unwrap();
    w.set_global("gpg.ssh.allowedSignersFile", &allowed.display().to_string());

    let inst = installer(&w);
    let out = inst.install(&w);
    assert!(out.status.success(), "install: {}", all_output(&out));
    assert!(
        !w.keys().join("agents_ca_ed25519").exists(),
        "the installer should delete the unprotected authority key:\n{}",
        all_output(&out)
    );
    let content = fs::read_to_string(&allowed).unwrap();
    assert!(content.starts_with(&users_lines), "{content}");
    assert!(
        content.contains(BLOCK_BEGIN) && content.contains(BLOCK_END),
        "no managed block:\n{content}"
    );
    // Changed 28 Oct, after the follow-up round's check: that authority's
    // private key sat in a plain file, so it counts as exposed, and its trust
    // line is dropped rather than moved into the block.
    assert_eq!(
        content.matches(old_ca).count(),
        0,
        "the earlier build's exposed authority must not stay trusted:\n{content}"
    );

    // The service, started now, adds its new authority to the block.
    w.start_service();
    let trust = stdout(&w.trust_line_output());
    let content = fs::read_to_string(&allowed).unwrap();
    assert_eq!(trust.lines().count(), 1, "{trust}");
    assert!(!trust.contains(old_ca), "{trust}");
    assert_eq!(
        content,
        format!("{users_lines}{BLOCK_BEGIN}\n{trust}{BLOCK_END}\n")
    );
}

// ---------------------------------------------------------------------------
// F and G. The old shared key.
// ---------------------------------------------------------------------------

/// A world with the old shared agent key in `keys/`, whose public half is
/// `ssh-ed25519 <data>`, and an allowed-signers file that does or doesn't
/// still trust it under the user's email.
fn world_with_old_key(still_trusted: bool) -> (World, String) {
    let w = World::new("");
    fs::remove_dir_all(w.state()).unwrap();
    fs::create_dir_all(w.keys()).unwrap();
    let key = w.keys().join("agent_ed25519");
    let out = w
        .cmd(&w.ssh_keygen)
        .args(["-q", "-t", "ed25519", "-N", "", "-C", "old-agent", "-f"])
        .arg(&key)
        .output()
        .unwrap();
    assert!(out.status.success(), "ssh-keygen: {}", text(&out));
    let pub_line = fs::read_to_string(w.keys().join("agent_ed25519.pub")).unwrap();
    let data = pub_line.split_whitespace().nth(1).unwrap().to_string();
    let allowed = w.home.join("allowed_signers");
    let mut content = format!("{USER_EMAIL} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIUser\n");
    if still_trusted {
        content.push_str(&format!("{USER_EMAIL} ssh-ed25519 {data}\n"));
    }
    fs::write(&allowed, content).unwrap();
    w.set_global("gpg.ssh.allowedSignersFile", &allowed.display().to_string());
    (w, data)
}

#[test]
fn f_the_github_notice_is_printed_only_while_the_old_key_is_trusted() {
    for still_trusted in [false, true] {
        let (w, data) = world_with_old_key(still_trusted);
        let out = installer(&w).install(&w);
        assert!(out.status.success(), "install: {}", all_output(&out));
        let shown = all_output(&out);
        assert_eq!(
            shown.contains("gh ssh-key"),
            still_trusted,
            "GitHub notice with the old key {} in allowed_signers:\n{shown}",
            if still_trusted { "still" } else { "no longer" }
        );
        if still_trusted {
            assert!(
                shown.contains(&format!("grep -vF '{data}'")),
                "the exact command to remove the old line:\n{shown}"
            );
        }
    }
}

#[test]
fn g_the_installer_deletes_the_old_keys_private_half_and_keeps_its_public_half() {
    let (w, _) = world_with_old_key(true);
    // A copy an earlier build of this change moved aside, unprotected too.
    let retired = w.keys().join("retired");
    fs::create_dir_all(&retired).unwrap();
    fs::copy(
        w.keys().join("agent_ed25519"),
        retired.join("agent_ed25519.20261028-120000"),
    )
    .unwrap();
    let out = installer(&w).install(&w);
    assert!(out.status.success(), "install: {}", all_output(&out));
    assert!(
        !w.keys().join("agent_ed25519").exists(),
        "{}",
        all_output(&out)
    );
    assert!(
        files_under(&retired).is_empty(),
        "a private half moved aside earlier should be deleted too: {:?}",
        files_under(&retired)
    );
    assert!(
        w.keys().join("agent_ed25519.pub").exists(),
        "the public half stays, so old commits still verify"
    );
    let found: Vec<PathBuf> = files_under(&w.state())
        .into_iter()
        .filter(|f| private_key_material(&fs::read(f).unwrap()).is_some())
        .collect();
    assert!(found.is_empty(), "private keys left: {found:?}");
}

// ---------------------------------------------------------------------------
// Fixed after the follow-up round's independent check (28 Oct).
// ---------------------------------------------------------------------------

#[test]
fn b_a_signer_set_in_an_included_file_becomes_the_fallback() {
    // The user's signer is set in a file their global config includes, so
    // `git config --global` alone doesn't see it.
    let w = World::new("");
    fs::remove_dir_all(w.state()).unwrap();
    let theirs = w.fake_signer().display().to_string();
    let included = w.home.join("local.gitconfig");
    fs::write(&included, format!("[gpg \"ssh\"]\n\tprogram = {theirs}\n")).unwrap();
    for args in [
        vec!["config", "--global", "--unset", "gpg.ssh.program"],
        vec![
            "config",
            "--global",
            "include.path",
            included.to_str().unwrap(),
        ],
    ] {
        let out = w.cmd(&w.real_git).args(&args).output().unwrap();
        assert!(out.status.success(), "{args:?}: {}", text(&out));
    }
    let inst = installer(&w);
    let out = inst.install(&w);
    assert!(out.status.success(), "install: {}", all_output(&out));
    assert_eq!(
        config_fallback(&w).as_deref(),
        Some(theirs.as_str()),
        "the signer from the included file should become the fallback:\n{}",
        all_output(&out)
    );
    let effective = w
        .cmd(&w.real_git)
        .args([
            "config",
            "--global",
            "--includes",
            "--get",
            "gpg.ssh.program",
        ])
        .output()
        .unwrap();
    assert_eq!(stdout(&effective).trim(), installed_agent_ssh_sign(&w));
}

#[test]
fn b_ending_the_installers_question_with_ctrl_d_changes_nothing() {
    let w = World::new("");
    fs::remove_dir_all(w.state()).unwrap();
    let theirs = w.fake_signer().display().to_string();
    let inst = installer(&w);
    let out = inst.install_with_closed_input(&w);
    assert!(
        all_output(&out).contains("Nothing was changed."),
        "closed input at the question must mean no:\n{}",
        all_output(&out)
    );
    assert_eq!(
        w.get_global("gpg.ssh.program").as_deref(),
        Some(theirs.as_str())
    );
    assert!(!w.state().join("bin/agent-ssh-sign").exists());
}
