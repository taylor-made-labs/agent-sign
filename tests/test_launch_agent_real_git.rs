//! macOS speed: the LaunchAgent the installer writes tells the service which
//! git to run (`AGENT_SIGN_REAL_GIT`).
//!
//! Why: the service runs every git through `paths::real_git()`, which honours
//! `AGENT_SIGN_REAL_GIT`. Without it, under launchd (`PATH=/usr/bin:...`) that
//! is `/usr/bin/git`, Apple's shim, which looks up the real git through xcrun
//! on every run (about 0.14 s each). So the installer finds the real git
//! (`xcrun --find git` when the first git is the shim, otherwise the first
//! git outside `~/.agent-sign`), checks that it is an executable git, and
//! writes it into the plist.
//!
//! These checks run on every OS, without launchd: they load the installer's
//! helpers (`AGENT_SIGN_INSTALL_FUNCTIONS_ONLY=1`, which stops the script
//! right after defining them, before it changes anything), render the real
//! template `scripts/agent-signd.plist`, and read the result with Python's
//! plistlib, a real plist parser. The git lookup runs against stand-ins: a
//! wrapper in a `.agent-sign/bin`, a stand-in shim (`GIT_SHIM`), a stand-in
//! `xcrun`, and stand-in gits that answer `--version`. Nothing here touches a
//! real `~/.agent-sign`, launchd or the user's git.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use tempfile::{TempDir, tempdir};

fn scripts() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts")
}

fn write_executable(path: &Path, body: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, body).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

/// Runs `script` in bash after loading only the installer's helpers, with
/// `PATH` and `GIT_SHIM` as given and nothing else from the environment but
/// a temporary HOME.
fn with_installer_helpers(home: &Path, path: &str, shim: &Path, script: &str) -> Output {
    installer_helpers(home, path, script)
        .env("GIT_SHIM", shim)
        .output()
        .unwrap()
}

/// bash with the installer's helpers loaded; `$1` is install.sh, and the
/// command's further arguments follow as `$2`, `$3`...
fn installer_helpers(home: &Path, path: &str, script: &str) -> Command {
    let mut cmd = Command::new("/bin/bash");
    cmd.env_clear()
        .env("HOME", home)
        .env("PATH", path)
        .env("AGENT_SIGN_INSTALL_FUNCTIONS_ONLY", "1")
        .arg("-c")
        .arg(format!("source \"$1\"; {script}"))
        .arg("bash")
        .arg(scripts().join("install.sh"));
    cmd
}

fn shown(out: &Output) -> String {
    format!(
        "status {}\nstdout: {}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// The plist the installer would write for `git`, read back with plistlib:
/// `AGENT_SIGN_REAL_GIT` from EnvironmentVariables (or "<none>" when the
/// entry is left out), then the Label and the program launchd runs.
fn render_and_read(git: &str) -> Vec<String> {
    let dir = tempdir().unwrap();
    let rendered = dir.path().join("agent-signd.plist");
    let out = installer_helpers(
        dir.path(),
        "/usr/bin:/bin",
        "render_launch_agent_plist \"$2\" \"$3\" > \"$4\"",
    )
    .arg(scripts().join("agent-signd.plist"))
    .arg(git)
    .arg(&rendered)
    .output()
    .unwrap();
    assert!(out.status.success(), "rendering failed: {}", shown(&out));
    let text = fs::read_to_string(&rendered).unwrap();
    assert!(
        !text.contains("@AGENT_SIGN_REAL_GIT@"),
        "the placeholder is left in the plist:\n{text}"
    );
    let read = Command::new("python3")
        .arg("-I")
        .arg("-c")
        .arg(
            "import plistlib, sys\n\
             p = plistlib.load(open(sys.argv[1], 'rb'))\n\
             print(p.get('EnvironmentVariables', {}).get('AGENT_SIGN_REAL_GIT', '<none>'))\n\
             print(p['Label'])\n\
             print(p['ProgramArguments'][-1])\n",
        )
        .arg(&rendered)
        .output()
        .expect("python3 should be installed (the installer needs it too)");
    assert!(
        read.status.success(),
        "the plist doesn't parse: {}\n{text}",
        shown(&read)
    );
    String::from_utf8_lossy(&read.stdout)
        .lines()
        .map(str::to_string)
        .collect()
}

#[test]
fn the_launch_agent_carries_the_real_git() {
    let read = render_and_read("/Library/Developer/CommandLineTools/usr/bin/git");
    assert_eq!(read[0], "/Library/Developer/CommandLineTools/usr/bin/git");
    assert_eq!(read[1], "com.agentsign.agent-signd");
    assert!(
        read[2].contains("agent-sign.app/Contents/MacOS/agent-signd"),
        "the program launchd runs changed: {read:?}"
    );
}

#[test]
fn a_git_path_with_xml_characters_is_escaped() {
    let git = "/Users/a&b <c>/\"git's\"/bin/git";
    let read = render_and_read(git);
    assert_eq!(read[0], git);
}

#[test]
fn with_no_real_git_the_entry_is_left_out_and_the_plist_still_reads() {
    let read = render_and_read("");
    assert_eq!(read[0], "<none>");
    assert_eq!(read[1], "com.agentsign.agent-signd");
}

/// The stand-ins for the git lookup.
struct Gits {
    _dir: TempDir,
    home: PathBuf,
    wrapper_dir: PathBuf,
    shim: PathBuf,
    shim_dir: PathBuf,
    other_dir: PathBuf,
    xcrun_dir: PathBuf,
    clt_git: PathBuf,
}

const A_GIT: &str = "#!/bin/sh\necho 'git version 2.50.0'\n";

impl Gits {
    fn new() -> Gits {
        let dir = tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let home = root.join("home");
        let wrapper_dir = home.join(".agent-sign/bin");
        write_executable(&wrapper_dir.join("git"), A_GIT);
        let shim_dir = root.join("usr-bin");
        let shim = shim_dir.join("git");
        write_executable(&shim, A_GIT);
        let other_dir = root.join("homebrew-bin");
        write_executable(&other_dir.join("git"), A_GIT);
        let clt_git = root.join("CommandLineTools/usr/bin/git");
        write_executable(&clt_git, A_GIT);
        let xcrun_dir = root.join("xcrun-bin");
        write_executable(
            &xcrun_dir.join("xcrun"),
            &format!(
                "#!/bin/sh\n[ \"$1\" = --find ] && [ \"$2\" = git ] && echo '{}' && exit 0\nexit 1\n",
                clt_git.display()
            ),
        );
        Gits {
            _dir: dir,
            home,
            wrapper_dir,
            shim,
            shim_dir,
            other_dir,
            xcrun_dir,
            clt_git,
        }
    }

    /// Only the given folders: no system folder, whose git or xcrun (on a
    /// Mac) would answer instead of the stand-ins. The lookup itself needs
    /// only bash's own commands.
    fn path(&self, dirs: &[&Path]) -> String {
        let all: Vec<String> = dirs.iter().map(|d| d.display().to_string()).collect();
        all.join(":")
    }

    /// What find_real_git prints, or None when it finds nothing.
    fn found(&self, dirs: &[&Path]) -> Option<String> {
        let out = with_installer_helpers(&self.home, &self.path(dirs), &self.shim, "find_real_git");
        let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if out.status.success() {
            assert!(!text.is_empty(), "{}", shown(&out));
            Some(text)
        } else {
            assert!(text.is_empty(), "printed a git but failed: {}", shown(&out));
            None
        }
    }
}

#[test]
fn when_the_first_git_is_the_shim_xcrun_names_the_real_one() {
    let g = Gits::new();
    let found = g.found(&[&g.wrapper_dir, &g.shim_dir, &g.xcrun_dir]);
    assert_eq!(found, Some(g.clt_git.display().to_string()));
}

#[test]
fn otherwise_the_first_git_outside_agent_sign_is_used() {
    let g = Gits::new();
    let found = g.found(&[&g.wrapper_dir, &g.other_dir, &g.shim_dir, &g.xcrun_dir]);
    assert_eq!(found, Some(g.other_dir.join("git").display().to_string()));
}

#[test]
fn the_wrapper_is_never_the_real_git() {
    let g = Gits::new();
    // Only the wrapper and the shim on PATH, and no xcrun: nothing usable.
    let found = g.found(&[&g.wrapper_dir, &g.shim_dir]);
    assert_eq!(found, None);
}

#[test]
fn a_git_that_isnt_git_is_refused() {
    let g = Gits::new();
    write_executable(&g.other_dir.join("git"), "#!/bin/sh\necho 'not a git'\n");
    let found = g.found(&[&g.other_dir]);
    assert_eq!(found, None);
    fs::set_permissions(g.other_dir.join("git"), fs::Permissions::from_mode(0o644)).unwrap();
    write_executable(&g.clt_git, "#!/bin/sh\nexit 1\n");
    let found = g.found(&[&g.other_dir, &g.xcrun_dir]);
    assert_eq!(
        found, None,
        "a non-executable git or a failing one was accepted"
    );
}

/// The installer writes the LaunchAgent through the renderer, never by
/// copying the template (which would leave the placeholder in place).
#[test]
fn the_installer_writes_the_launch_agent_through_the_renderer() {
    let installer = fs::read_to_string(scripts().join("install.sh")).unwrap();
    assert!(
        installer.contains("render_launch_agent_plist \"$PLIST_SRC\" \"$SERVICE_GIT\""),
        "install.sh doesn't render the LaunchAgent with the real git"
    );
    assert!(
        !installer.contains("cp \"$PLIST_SRC\""),
        "install.sh still copies the LaunchAgent template as is"
    );
}
