//! The reverse leak: commits that git makes by itself for an agent (merge,
//! pull, rebase, cherry-pick, revert, am, a shell alias) must never be signed
//! with the person's own key. (Their author and committer are left to the
//! per-agent identity change: see the two ignored tests in group 3.)
//!
//! The wrapper handles only `git commit`; every other command goes to the
//! real git unchanged, so git signs the commits it creates itself with
//! whatever the person's global config says (on the person's Mac, their
//! 1Password signer and their own key). These tests pin that down before a
//! fix exists, and also pin what a fix must keep: the person's own merges in
//! a terminal still use their signer, and agents can still verify
//! signatures.
//!
//! The person's signer here is a fake: a shell script that logs one line per
//! call and exits 1. "Never signed with the person's key" is checked as "the
//! fake was called 0 times".
//!
//! Isolation: every process these tests start, setup included, runs with an
//! empty environment plus only what it needs: a temporary HOME, a temporary
//! global git config (GIT_CONFIG_GLOBAL), no system config, a PATH without
//! agent-sign's installed `bin`, and a socket inside the temporary directory.
//! Only the binaries cargo built for this test are run, never the installed
//! ones, and never the person's own service socket.

use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use tempfile::{TempDir, tempdir};

const PERSON_NAME: &str = "Human Developer";
const PERSON_EMAIL: &str = "dev@example.com";
const ORIGINAL_AUTHOR: &str = "Original Author";
const ORIGINAL_AUTHOR_EMAIL: &str = "orig@example.com";

/// Whether the command carries an agent's mark (see attribution::KNOWN_AGENTS).
#[derive(Clone, Copy, Debug)]
enum Mark {
    /// `CLAUDECODE=1`, as Claude Code sets in the shell it runs commands in.
    ClaudeCode,
    /// No agent mark at all.
    Unmarked,
}

/// What the person's global git config uses to sign.
#[derive(Clone, Copy, PartialEq)]
enum PersonSigner {
    /// `gpg.ssh.program` is the fake signer.
    Fake,
    /// `gpg.ssh.program` is agent-sign's signing program (as an install sets
    /// it), whose `fallback_program` in `~/.agent-sign/config.toml` is the
    /// fake signer.
    ThroughAgentSshSign,
    /// No `gpg.ssh.program`: git's default, ssh-keygen. Git also calls
    /// `gpg.ssh.program` to verify, and the fake refuses everything, so the
    /// verification scenario uses git's default program.
    GitDefault,
}

/// One isolated world: a temporary home, the person's global git config and
/// fake signer, and (when asked for) a test agent-sign service in
/// auto-approve.
struct World {
    dir: TempDir,
    home: PathBuf,
    global_config: PathBuf,
    path: OsString,
    real_git: PathBuf,
    socket: PathBuf,
    signer_log: PathBuf,
    service: Option<Child>,
}

impl Drop for World {
    fn drop(&mut self) {
        if let Some(mut child) = self.service.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// `PATH` with every entry containing `.agent-sign` removed, so the installed
/// wrapper (and anything else agent-sign installed) is never found.
fn cleaned_path() -> OsString {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let kept: Vec<PathBuf> = std::env::split_paths(&path)
        .filter(|p| !p.to_string_lossy().contains(".agent-sign"))
        .collect();
    std::env::join_paths(kept).unwrap()
}

/// The first `name` on `path` that is a file.
fn find_on(path: &OsString, name: &str) -> PathBuf {
    std::env::split_paths(path)
        .map(|d| d.join(name))
        .find(|p| p.is_file())
        .unwrap_or_else(|| panic!("no {name} on the cleaned PATH"))
}

impl World {
    fn new(signer: PersonSigner, with_service: bool) -> World {
        let dir = tempdir().unwrap();
        let home = dir.path().to_path_buf();
        let path = cleaned_path();
        let real_git = find_on(&path, "git");
        let mut world = World {
            global_config: home.join("person.gitconfig"),
            socket: home.join("agent-sign-test.sock"),
            signer_log: home.join("person-signer.log"),
            home,
            path,
            real_git,
            service: None,
            dir,
        };
        world.write_person_setup(signer);
        if with_service {
            world.start_service();
        }
        world
    }

    /// The one place the isolated environment is built: every process the
    /// tests start goes through here.
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

    fn mark(cmd: &mut Command, mark: Mark) {
        if let Mark::ClaudeCode = mark {
            cmd.env("CLAUDECODE", "1");
        }
    }

    /// Writes the throwaway key, the fake signer, and the person's global git
    /// config (and for `ThroughAgentSshSign`, agent-sign's config.toml).
    fn write_person_setup(&self, signer: PersonSigner) {
        let key = self.home.join("person_key");
        let out = self
            .cmd(&find_on(&self.path, "ssh-keygen"))
            .args(["-q", "-t", "ed25519", "-N", "", "-C", "person", "-f"])
            .arg(&key)
            .output()
            .unwrap();
        assert!(out.status.success(), "ssh-keygen: {}", text(&out));

        let fake = self.home.join("person-signer.sh");
        fs::write(
            &fake,
            format!(
                "#!/bin/sh\necho \"called: $*\" >> '{}'\nexit 1\n",
                self.signer_log.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&fake, fs::Permissions::from_mode(0o755)).unwrap();

        let program = match signer {
            PersonSigner::Fake => Some(fake.clone()),
            PersonSigner::ThroughAgentSshSign => {
                let state = self.home.join(".agent-sign");
                fs::create_dir_all(&state).unwrap();
                fs::write(
                    state.join("config.toml"),
                    format!("[ssh]\nfallback_program = \"{}\"\n", fake.display()),
                )
                .unwrap();
                Some(PathBuf::from(env!("CARGO_BIN_EXE_agent-ssh-sign")))
            }
            PersonSigner::GitDefault => None,
        };
        let mut config = format!(
            "[user]\n\tname = {PERSON_NAME}\n\temail = {PERSON_EMAIL}\n\tsigningkey = \"{}.pub\"\n\
             [commit]\n\tgpgsign = true\n[gpg]\n\tformat = ssh\n",
            key.display()
        );
        if let Some(p) = program {
            config.push_str(&format!("[gpg \"ssh\"]\n\tprogram = \"{}\"\n", p.display()));
        }
        fs::write(&self.global_config, config).unwrap();
    }

    /// A test service on a socket in the temporary directory, approving
    /// every lease without asking.
    fn start_service(&mut self) {
        let log = fs::File::create(self.home.join("service.log")).unwrap();
        let child = self
            .cmd(Path::new(env!("CARGO_BIN_EXE_agent-signd")))
            .arg("--socket")
            .arg(&self.socket)
            .arg("--auto-approve")
            .stdout(Stdio::null())
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap();
        self.service = Some(child);
        let start = Instant::now();
        while !self.socket.exists() {
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "test service didn't start"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// How many times the person's (fake) signer has been called.
    fn signer_calls(&self) -> usize {
        fs::read_to_string(&self.signer_log)
            .map(|s| s.lines().count())
            .unwrap_or(0)
    }

    /// The real git, directly, with no agent mark (setup and inspection).
    fn git(&self, repo: &Path, args: &[&str]) -> Output {
        self.real_git_as(repo, Mark::Unmarked, args)
    }

    fn git_ok(&self, repo: &Path, args: &[&str]) -> String {
        let out = self.git(repo, args);
        assert!(out.status.success(), "setup git {args:?}: {}", text(&out));
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    /// The real git, directly, bypassing the wrapper.
    fn real_git_as(&self, repo: &Path, mark: Mark, args: &[&str]) -> Output {
        let mut cmd = self.cmd(&self.real_git);
        Self::mark(&mut cmd, mark);
        cmd.args(args).current_dir(repo).output().unwrap()
    }

    /// The wrapper, as an agent runs it: no terminal.
    fn agent(&self, repo: &Path, mark: Mark, args: &[&str]) -> Output {
        let mut cmd = self.cmd(Path::new(env!("CARGO_BIN_EXE_agent-git")));
        Self::mark(&mut cmd, mark);
        cmd.args(args).current_dir(repo).output().unwrap()
    }

    /// An unsigned setup commit adding `file`.
    fn commit(&self, repo: &Path, file: &str, author: Option<(&str, &str)>) {
        fs::write(repo.join(file), format!("{file}\n")).unwrap();
        self.git_ok(repo, &["add", file]);
        let mut args = vec!["-c", "commit.gpgsign=false", "commit", "-q", "-m", file];
        let author_arg;
        if let Some((name, email)) = author {
            author_arg = format!("--author={name} <{email}>");
            args.push(&author_arg);
        }
        self.git_ok(repo, &args);
    }

    /// A repository on branch `work` (base, w1), with `feature` branched
    /// from base (f1, f2, both by the original author), `work` checked out.
    fn repo(&self) -> PathBuf {
        let repo = self.home.join("repo");
        fs::create_dir_all(&repo).unwrap();
        self.git_ok(&repo, &["init", "-q", "-b", "work"]);
        self.commit(&repo, "base.txt", None);
        self.git_ok(&repo, &["checkout", "-q", "-b", "feature"]);
        let orig = Some((ORIGINAL_AUTHOR, ORIGINAL_AUTHOR_EMAIL));
        self.commit(&repo, "f1.txt", orig);
        self.commit(&repo, "f2.txt", orig);
        self.git_ok(&repo, &["checkout", "-q", "work"]);
        self.commit(&repo, "w1.txt", None);
        repo
    }

    fn author_of(&self, repo: &Path, rev: &str) -> String {
        self.git_ok(repo, &["log", "-1", "--format=%an", rev])
    }

    /// Fails unless the person's signer was never called and `out` succeeded.
    fn assert_no_person_signer_and_success(&self, what: &str, out: &Output) {
        assert_eq!(
            self.signer_calls(),
            0,
            "{what}: the person's signer was called (log: {:?})\n{}",
            fs::read_to_string(&self.signer_log).unwrap_or_default(),
            text(out)
        );
        assert!(out.status.success(), "{what} failed:\n{}", text(out));
    }

    fn assert_no_person_signer(&self, what: &str, out: &Output) {
        assert_eq!(
            self.signer_calls(),
            0,
            "{what}: the person's signer was called (log: {:?})\n{}",
            fs::read_to_string(&self.signer_log).unwrap_or_default(),
            text(out)
        );
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }
}

fn text(out: &Output) -> String {
    format!(
        "status: {}\nstdout: {}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// Two tests per scenario: with Claude Code's mark, and with no mark at all.
macro_rules! with_and_without_mark {
    ($scenario:ident, $marked:ident, $unmarked:ident) => {
        #[test]
        fn $marked() {
            $scenario(Mark::ClaudeCode);
        }
        #[test]
        fn $unmarked() {
            $scenario(Mark::Unmarked);
        }
    };
}

// ---------------------------------------------------------------------------
// 1. Commits git makes itself for an agent, through the wrapper: they succeed
//    and never call the person's signer.
// ---------------------------------------------------------------------------

fn agent_merge(mark: Mark) {
    let w = World::new(PersonSigner::Fake, true);
    let repo = w.repo();
    let out = w.agent(
        &repo,
        mark,
        &["merge", "--no-ff", "-m", "merge feature", "feature"],
    );
    w.assert_no_person_signer_and_success("merge --no-ff", &out);
}
with_and_without_mark!(agent_merge, merge_claude_code, merge_unmarked);

fn agent_pull(mark: Mark) {
    let w = World::new(PersonSigner::Fake, true);
    let upstream = w.repo();
    let down = w.path().join("down");
    w.git_ok(
        w.path(),
        &[
            "clone",
            "-q",
            "-b",
            "work",
            upstream.to_str().unwrap(),
            "down",
        ],
    );
    w.commit(&down, "d1.txt", None);
    let out = w.agent(
        &down,
        mark,
        &[
            "pull",
            "--no-rebase",
            "--no-edit",
            upstream.to_str().unwrap(),
            "feature",
        ],
    );
    w.assert_no_person_signer_and_success("pull --no-rebase", &out);
}
with_and_without_mark!(agent_pull, pull_claude_code, pull_unmarked);

fn agent_rebase(mark: Mark) {
    let w = World::new(PersonSigner::Fake, true);
    let repo = w.repo();
    w.git_ok(&repo, &["checkout", "-q", "feature"]);
    let out = w.agent(&repo, mark, &["rebase", "work"]);
    w.assert_no_person_signer_and_success("rebase (2 commits)", &out);
    assert_eq!(
        w.git_ok(&repo, &["rev-parse", "HEAD~2"]),
        w.git_ok(&repo, &["rev-parse", "work"]),
        "rebase should have replayed both feature commits onto work"
    );
}
with_and_without_mark!(agent_rebase, rebase_claude_code, rebase_unmarked);

fn agent_cherry_pick(mark: Mark) {
    let w = World::new(PersonSigner::Fake, true);
    let repo = w.repo();
    let out = w.agent(&repo, mark, &["cherry-pick", "feature~1"]);
    w.assert_no_person_signer_and_success("cherry-pick", &out);
}
with_and_without_mark!(
    agent_cherry_pick,
    cherry_pick_claude_code,
    cherry_pick_unmarked
);

fn agent_revert(mark: Mark) {
    let w = World::new(PersonSigner::Fake, true);
    let repo = w.repo();
    let out = w.agent(&repo, mark, &["revert", "--no-edit", "HEAD"]);
    w.assert_no_person_signer_and_success("revert --no-edit", &out);
}
with_and_without_mark!(agent_revert, revert_claude_code, revert_unmarked);

/// A patch of f2 (made with format-patch), ready to apply on `work`.
fn patch_of_f2(w: &World, repo: &Path) -> PathBuf {
    let patches = w.path().join("patches");
    let made = w.git_ok(
        repo,
        &[
            "format-patch",
            "-1",
            "feature",
            "-o",
            patches.to_str().unwrap(),
        ],
    );
    PathBuf::from(made.lines().next().expect("format-patch wrote a patch"))
}

fn agent_am(mark: Mark) {
    let w = World::new(PersonSigner::Fake, true);
    let repo = w.repo();
    let patch = patch_of_f2(&w, &repo);
    let out = w.agent(&repo, mark, &["am", patch.to_str().unwrap()]);
    w.assert_no_person_signer_and_success("am", &out);
}
with_and_without_mark!(agent_am, am_claude_code, am_unmarked);

fn agent_shell_alias(mark: Mark) {
    let w = World::new(PersonSigner::Fake, true);
    let repo = w.repo();
    w.git_ok(
        &repo,
        &["config", "alias.mm", "!git merge --no-ff -m msg feature"],
    );
    let out = w.agent(&repo, mark, &["mm"]);
    w.assert_no_person_signer_and_success("shell alias running merge --no-ff", &out);
}
with_and_without_mark!(
    agent_shell_alias,
    shell_alias_claude_code,
    shell_alias_unmarked
);

// ---------------------------------------------------------------------------
// 2. Explicit signing requests by an agent: never the person's signer.
//    Refusing, or signing with the agent's key, are both acceptable.
// ---------------------------------------------------------------------------

#[test]
fn signed_tag_by_agent_never_calls_persons_signer() {
    let w = World::new(PersonSigner::Fake, true);
    let repo = w.repo();
    let out = w.agent(&repo, Mark::ClaudeCode, &["tag", "-s", "-m", "v1", "v1"]);
    w.assert_no_person_signer("tag -s", &out);
}

#[test]
fn signed_commit_tree_by_agent_never_calls_persons_signer() {
    let w = World::new(PersonSigner::Fake, true);
    let repo = w.repo();
    let out = w.agent(
        &repo,
        Mark::ClaudeCode,
        &[
            "commit-tree",
            "-S",
            "-p",
            "HEAD",
            "-m",
            "tree",
            "HEAD^{tree}",
        ],
    );
    w.assert_no_person_signer("commit-tree -S", &out);
}

#[test]
fn signed_merge_by_agent_never_calls_persons_signer() {
    let w = World::new(PersonSigner::Fake, true);
    let repo = w.repo();
    let out = w.agent(
        &repo,
        Mark::ClaudeCode,
        &["merge", "-S", "--no-ff", "-m", "merge feature", "feature"],
    );
    w.assert_no_person_signer("merge -S --no-ff", &out);
}

// ---------------------------------------------------------------------------
// 3. Attribution: commits an agent creates are not the person's; commits it
//    replays keep their original author.
// ---------------------------------------------------------------------------

fn assert_authored_by_agent(w: &World, repo: &Path, what: &str) {
    let author = w.author_of(repo, "HEAD");
    assert_ne!(author, PERSON_NAME, "{what} commit authored as the person");
    assert_eq!(author, "Claude Code", "{what} commit author");
}

#[test]
#[ignore = "moved to the per-agent identity change (26 Oct): giving agent merges the agent's name through GIT_AUTHOR_* made the wrapper call itself and relabelled the person's own merges from editors and scripts (security review), so author and committer are designed there"]
fn agent_merge_commit_is_not_authored_as_the_person() {
    let w = World::new(PersonSigner::Fake, true);
    let repo = w.repo();
    let out = w.agent(
        &repo,
        Mark::ClaudeCode,
        &["merge", "--no-ff", "-m", "merge feature", "feature"],
    );
    assert!(
        out.status.success(),
        "merge failed (person's signer calls: {}):\n{}",
        w.signer_calls(),
        text(&out)
    );
    assert_authored_by_agent(&w, &repo, "merge");
}

#[test]
#[ignore = "moved to the per-agent identity change (26 Oct): giving agent merges the agent's name through GIT_AUTHOR_* made the wrapper call itself and relabelled the person's own merges from editors and scripts (security review), so author and committer are designed there"]
fn agent_revert_commit_is_not_authored_as_the_person() {
    let w = World::new(PersonSigner::Fake, true);
    let repo = w.repo();
    let out = w.agent(&repo, Mark::ClaudeCode, &["revert", "--no-edit", "HEAD"]);
    assert!(
        out.status.success(),
        "revert failed (person's signer calls: {}):\n{}",
        w.signer_calls(),
        text(&out)
    );
    assert_authored_by_agent(&w, &repo, "revert");
}

fn assert_original_author(w: &World, repo: &Path, rev: &str, what: &str) {
    assert_eq!(
        w.author_of(repo, rev),
        ORIGINAL_AUTHOR,
        "{what}: {rev} should keep its original author"
    );
}

#[test]
fn rebased_commits_keep_their_original_author() {
    let w = World::new(PersonSigner::Fake, true);
    let repo = w.repo();
    w.git_ok(&repo, &["checkout", "-q", "feature"]);
    let out = w.agent(&repo, Mark::ClaudeCode, &["rebase", "work"]);
    assert!(
        out.status.success(),
        "rebase failed (person's signer calls: {}):\n{}",
        w.signer_calls(),
        text(&out)
    );
    assert_original_author(&w, &repo, "HEAD", "rebase");
    assert_original_author(&w, &repo, "HEAD~1", "rebase");
}

#[test]
fn cherry_picked_commit_keeps_its_original_author() {
    let w = World::new(PersonSigner::Fake, true);
    let repo = w.repo();
    let out = w.agent(&repo, Mark::ClaudeCode, &["cherry-pick", "feature~1"]);
    assert!(
        out.status.success(),
        "cherry-pick failed (person's signer calls: {}):\n{}",
        w.signer_calls(),
        text(&out)
    );
    assert_original_author(&w, &repo, "HEAD", "cherry-pick");
}

#[test]
fn applied_patch_keeps_its_original_author() {
    let w = World::new(PersonSigner::Fake, true);
    let repo = w.repo();
    let patch = patch_of_f2(&w, &repo);
    let out = w.agent(&repo, Mark::ClaudeCode, &["am", patch.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "am failed (person's signer calls: {}):\n{}",
        w.signer_calls(),
        text(&out)
    );
    assert_original_author(&w, &repo, "HEAD", "am");
}

// ---------------------------------------------------------------------------
// 4. The real git called directly, bypassing the wrapper, with agent-sign's
//    signing program installed as gpg.ssh.program.
// ---------------------------------------------------------------------------

#[test]
fn direct_git_merge_by_marked_agent_never_calls_persons_signer() {
    let w = World::new(PersonSigner::ThroughAgentSshSign, false);
    let repo = w.repo();
    let out = w.real_git_as(
        &repo,
        Mark::ClaudeCode,
        &["merge", "--no-ff", "-m", "merge feature", "feature"],
    );
    w.assert_no_person_signer("direct git merge with CLAUDECODE=1", &out);
}

#[test]
fn direct_git_merge_with_no_mark_still_uses_persons_signer() {
    let w = World::new(PersonSigner::ThroughAgentSshSign, false);
    let repo = w.repo();
    let out = w.real_git_as(
        &repo,
        Mark::Unmarked,
        &["merge", "--no-ff", "-m", "merge feature", "feature"],
    );
    assert!(
        w.signer_calls() >= 1,
        "the person's own merge should reach their signer:\n{}",
        text(&out)
    );
}

// ---------------------------------------------------------------------------
// 5. The person's own merge in a terminal, through the wrapper, still uses
//    their signer.
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
#[test]
fn persons_merge_in_a_terminal_uses_their_signer() {
    let w = World::new(PersonSigner::Fake, true);
    let repo = w.repo();
    let out = w
        .cmd(Path::new("/usr/bin/script"))
        .args(["-q", "/dev/null", env!("CARGO_BIN_EXE_agent-git")])
        .args(["merge", "--no-ff", "-m", "merge feature", "feature"])
        .env("TERM", "dumb")
        .current_dir(&repo)
        .output()
        .unwrap();
    assert!(
        w.signer_calls() >= 1,
        "the person's merge in a terminal should reach their signer:\n{}",
        text(&out)
    );
}

// ---------------------------------------------------------------------------
// 6. Agents can still verify signatures.
// ---------------------------------------------------------------------------

#[test]
fn agent_can_still_verify_an_agent_signed_commit() {
    let w = World::new(PersonSigner::GitDefault, true);
    let repo = w.repo();
    fs::write(repo.join("agent.txt"), "agent work\n").unwrap();
    w.git_ok(&repo, &["add", "agent.txt"]);
    let out = w.agent(
        &repo,
        Mark::ClaudeCode,
        &["commit", "-m", "feat: agent work"],
    );
    assert!(out.status.success(), "agent commit failed:\n{}", text(&out));

    let pub_key = fs::read_to_string(w.home.join(".agent-sign/keys/agent_ed25519.pub")).unwrap();
    let allowed = w.home.join("allowed_signers");
    fs::write(&allowed, format!("{PERSON_EMAIL} {}\n", pub_key.trim())).unwrap();

    let out = w.agent(
        &repo,
        Mark::ClaudeCode,
        &[
            "-c",
            &format!("gpg.ssh.allowedSignersFile={}", allowed.display()),
            "log",
            "-1",
            "--show-signature",
        ],
    );
    let all = text(&out);
    assert!(
        all.contains("Good \"git\" signature"),
        "expected a good signature:\n{all}"
    );
}

// ---------------------------------------------------------------------------
// 7. Added after the security review of the fix (26 Oct 2026), one test per
//    confirmed finding.
// ---------------------------------------------------------------------------

/// Runs `cmd` and waits at most `limit`; a run that doesn't finish in time
/// is killed and fails the test. A wrapper that calls itself never finishes.
fn run_within(mut cmd: Command, limit: Duration, what: &str) -> Output {
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let start = Instant::now();
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if start.elapsed() > limit {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{what} didn't finish within {limit:?}: the wrapper may be calling itself");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The wrapper installed the way the installer does it: as `git` in a
/// `.agent-sign/bin` folder first on `PATH`, with no `AGENT_SIGN_REAL_GIT`,
/// so agent-sign has to find the real git itself.
fn wrapper_first_on_path(w: &World, repo: &Path, mark: Mark, args: &[&str]) -> Command {
    let bin = w.home.join(".agent-sign/bin");
    fs::create_dir_all(&bin).unwrap();
    let git = bin.join("git");
    if !git.exists() {
        std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_agent-git"), &git).unwrap();
    }
    let mut path = vec![bin];
    path.extend(std::env::split_paths(&w.path));
    let mut cmd = w.cmd(&git);
    cmd.env_remove("AGENT_SIGN_REAL_GIT")
        .env("PATH", std::env::join_paths(path).unwrap())
        .args(args)
        .current_dir(repo);
    World::mark(&mut cmd, mark);
    cmd
}

#[test]
fn wrapper_first_on_path_never_calls_itself() {
    let w = World::new(PersonSigner::Fake, true);
    let repo = w.repo();
    let limit = Duration::from_secs(20);
    for (mark, args) in [
        (Mark::ClaudeCode, vec!["status", "--short"]),
        (Mark::Unmarked, vec!["rev-parse", "HEAD"]),
        (
            Mark::ClaudeCode,
            vec!["merge", "--no-ff", "-m", "merge feature", "feature"],
        ),
    ] {
        let what = format!("{mark:?} git {args:?}");
        let out = run_within(wrapper_first_on_path(&w, &repo, mark, &args), limit, &what);
        assert!(out.status.success(), "{what} failed:\n{}", text(&out));
    }
    // An agent commit loads agent-sign's config, which looks up the person's
    // git name: that lookup must reach the real git, not the wrapper.
    fs::write(repo.join("agent.txt"), "agent work\n").unwrap();
    w.git_ok(&repo, &["add", "agent.txt"]);
    let what = "agent commit with the wrapper first on PATH";
    let out = run_within(
        wrapper_first_on_path(&w, &repo, Mark::ClaudeCode, &["commit", "-m", "feat: x"]),
        limit,
        what,
    );
    assert!(out.status.success(), "{what} failed:\n{}", text(&out));
    assert_eq!(
        w.signer_calls(),
        0,
        "{what}: the person's signer was called"
    );
}

#[test]
fn the_wrapper_stops_when_it_is_calling_itself() {
    let w = World::new(PersonSigner::Fake, false);
    let repo = w.repo();
    let mut cmd = w.cmd(Path::new(env!("CARGO_BIN_EXE_agent-git")));
    cmd.env("AGENT_SIGN_DEPTH", "8")
        .args(["status"])
        .current_dir(&repo);
    let out = run_within(cmd, Duration::from_secs(10), "wrapper at depth 8");
    assert!(
        !out.status.success(),
        "the wrapper should stop:\n{}",
        text(&out)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("calling itself"),
        "{}",
        text(&out)
    );
}

#[cfg(target_os = "macos")]
#[test]
fn a_terminal_carrying_the_wrappers_mark_is_still_the_persons() {
    // The wrapper's mark reaches whatever git starts (an editor, say), and a
    // terminal opened from that is the person's.
    let w = World::new(PersonSigner::Fake, true);
    let repo = w.repo();
    let out = w
        .cmd(Path::new("/usr/bin/script"))
        .args(["-q", "/dev/null", env!("CARGO_BIN_EXE_agent-git")])
        .args(["merge", "--no-ff", "-m", "merge feature", "feature"])
        .env("TERM", "dumb")
        .env("AGENT_SIGN_AGENT_RUN", "1")
        .current_dir(&repo)
        .output()
        .unwrap();
    assert!(
        w.signer_calls() >= 1,
        "the person's merge in a terminal should reach their signer:\n{}",
        text(&out)
    );
}

/// A throwaway GnuPG home with one signing key, or `None` when gpg isn't
/// installed. Returns the home and the key's fingerprint.
fn gpg_home(w: &World) -> Option<(PathBuf, PathBuf, String)> {
    let gpg = std::env::split_paths(&w.path)
        .map(|d| d.join("gpg"))
        .find(|p| p.is_file())?;
    let home = w.home.join("gnupg");
    fs::create_dir_all(&home).unwrap();
    fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
    let out = w
        .cmd(&gpg)
        .env("GNUPGHOME", &home)
        .args(["--batch", "--pinentry-mode", "loopback", "--passphrase", ""])
        .args([
            "--quick-gen-key",
            "Signer <signer@example.com>",
            "ed25519",
            "sign",
            "never",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "gpg key: {}", text(&out));
    let listing = w
        .cmd(&gpg)
        .env("GNUPGHOME", &home)
        .args(["--batch", "--with-colons", "--list-secret-keys"])
        .output()
        .unwrap();
    let fpr = String::from_utf8_lossy(&listing.stdout)
        .lines()
        .find(|l| l.starts_with("fpr:"))
        .and_then(|l| l.split(':').nth(9).map(str::to_string))
        .expect("a fingerprint");
    Some((gpg, home, fpr))
}

fn stop_gpg_agent(w: &World, gnupg: &Path) {
    if let Some(gpgconf) = std::env::split_paths(&w.path)
        .map(|d| d.join("gpgconf"))
        .find(|p| p.is_file())
    {
        let _ = w
            .cmd(&gpgconf)
            .env("GNUPGHOME", gnupg)
            .args(["--kill", "gpg-agent"])
            .output();
    }
}

#[test]
fn agent_can_still_verify_an_openpgp_signature() {
    let w = World::new(PersonSigner::Fake, false);
    let Some((gpg, gnupg, fpr)) = gpg_home(&w) else {
        eprintln!("gpg isn't installed; skipped");
        return;
    };
    let repo = w.repo();
    fs::write(repo.join("pgp.txt"), "pgp\n").unwrap();
    w.git_ok(&repo, &["add", "pgp.txt"]);
    let mut setup = w.cmd(&w.real_git);
    let out = setup
        .env("GNUPGHOME", &gnupg)
        .args(["-c", "gpg.format=openpgp", "-c"])
        .arg(format!("gpg.program={}", gpg.display()))
        .args(["-c", &format!("user.signingkey={fpr}")])
        .args(["commit", "-q", "-S", "-m", "pgp signed"])
        .current_dir(&repo)
        .output()
        .unwrap();
    assert!(out.status.success(), "pgp setup commit: {}", text(&out));

    let mut cmd = w.cmd(Path::new(env!("CARGO_BIN_EXE_agent-git")));
    let out = cmd
        .env("GNUPGHOME", &gnupg)
        .env("CLAUDECODE", "1")
        .args(["log", "-1", "--format=%G?"])
        .current_dir(&repo)
        .output()
        .unwrap();
    stop_gpg_agent(&w, &gnupg);
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "G",
        "an agent should see a good OpenPGP signature:\n{}",
        text(&out)
    );
}

#[test]
fn agent_openpgp_signing_request_is_refused() {
    let w = World::new(PersonSigner::Fake, false);
    let repo = w.repo();
    let out = w.agent(
        &repo,
        Mark::ClaudeCode,
        &["-c", "gpg.format=openpgp", "tag", "-s", "-m", "v1", "v1"],
    );
    assert!(
        !out.status.success(),
        "signing should be refused:\n{}",
        text(&out)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("Refused"),
        "{}",
        text(&out)
    );
    w.assert_no_person_signer("openpgp tag -s", &out);
}

#[test]
fn local_push_hook_commit_never_reaches_the_person_when_signing_is_routed() {
    // Pushing to a repository on the same machine runs its hooks with git's
    // configuration from the environment cleared, so the wrapper's settings
    // don't reach them. With the person's gpg.ssh.program routed through
    // agent-sign (as the README recommends), the signing program still sees
    // the agent's mark and refuses.
    let w = World::new(PersonSigner::ThroughAgentSshSign, true);
    let repo = w.repo();
    let bare = w.path().join("remote.git");
    w.git_ok(w.path(), &["init", "-q", "--bare", bare.to_str().unwrap()]);
    let deploy = w.path().join("deploy");
    w.git_ok(
        w.path(),
        &["init", "-q", "-b", "work", deploy.to_str().unwrap()],
    );
    let hook = bare.join("hooks/post-receive");
    fs::write(
        &hook,
        format!(
            "#!/bin/sh\nunset GIT_DIR\ncd '{}' || exit 0\ngit commit -q --allow-empty -m 'from the hook' 2> '{}'\necho $? > '{}'\n",
            deploy.display(),
            w.home.join("hook.err").display(),
            w.home.join("hook.status").display()
        ),
    )
    .unwrap();
    fs::set_permissions(&hook, fs::Permissions::from_mode(0o755)).unwrap();
    let out = w.agent(
        &repo,
        Mark::ClaudeCode,
        &["push", "-q", bare.to_str().unwrap(), "work"],
    );
    w.assert_no_person_signer_and_success(
        "push to a local repository with a committing hook",
        &out,
    );
    // The hook did try to commit, and agent-sign's signing program refused.
    let status = fs::read_to_string(w.home.join("hook.status")).expect("the hook ran");
    assert_ne!(
        status.trim(),
        "0",
        "the hook's commit should have been refused"
    );
    let err = fs::read_to_string(w.home.join("hook.err")).unwrap_or_default();
    assert!(err.contains("Refused"), "hook's commit error: {err}");
}

// ---------------------------------------------------------------------------
// 8. Added after checking the review fixes (26 Oct 2026).
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
#[test]
fn a_leaked_wrapper_mark_never_blocks_the_persons_routed_terminal_commit() {
    // With the person's signing routed through agent-sign, a terminal that
    // inherited the wrapper's mark (from an editor an agent's git started)
    // must still sign the person's own commit with their signer.
    let w = World::new(PersonSigner::ThroughAgentSshSign, true);
    let repo = w.repo();
    fs::write(repo.join("mine.txt"), "mine\n").unwrap();
    w.git_ok(&repo, &["add", "mine.txt"]);
    let out = w
        .cmd(Path::new("/usr/bin/script"))
        .args(["-q", "/dev/null", env!("CARGO_BIN_EXE_agent-git")])
        .args(["commit", "-m", "my own work"])
        .env("TERM", "dumb")
        .env("AGENT_SIGN_AGENT_RUN", "1")
        .current_dir(&repo)
        .output()
        .unwrap();
    assert!(
        w.signer_calls() >= 1,
        "the person's commit in a terminal should reach their signer:\n{}",
        text(&out)
    );
}

#[test]
fn a_signing_request_disguised_as_a_check_is_refused() {
    // git asks gpg to sign with `-bsau <key>`; a key named `--verify` must
    // not make that look like a request to check a signature.
    let w = World::new(PersonSigner::Fake, false);
    let repo = w.repo();
    let out = w.agent(
        &repo,
        Mark::ClaudeCode,
        &[
            "-c",
            "gpg.format=openpgp",
            "-c",
            "user.signingkey=--verify",
            "commit-tree",
            "-S",
            "-m",
            "x",
            "HEAD^{tree}",
        ],
    );
    assert!(
        !out.status.success(),
        "signing should be refused:\n{}",
        text(&out)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("Refused"),
        "{}",
        text(&out)
    );
}

#[test]
fn a_real_git_that_is_really_the_wrapper_stops_instead_of_looping() {
    // Misconfigured: agent-sign is told the wrapper is the real git. Every
    // git the wrapper starts, its alias lookup included, counts one level
    // deeper, so the chain stops rather than filling the process table.
    let w = World::new(PersonSigner::Fake, false);
    let repo = w.repo();
    let mut cmd = w.cmd(Path::new(env!("CARGO_BIN_EXE_agent-git")));
    cmd.env("AGENT_SIGN_REAL_GIT", env!("CARGO_BIN_EXE_agent-git"))
        .env("CLAUDECODE", "1")
        .args(["status"])
        .current_dir(&repo);
    let out = run_within(cmd, Duration::from_secs(30), "wrapper as its own real git");
    assert!(!out.status.success(), "{}", text(&out));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("calling itself"),
        "{}",
        text(&out)
    );
}
