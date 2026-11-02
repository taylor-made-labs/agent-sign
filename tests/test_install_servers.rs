//! The installer on servers (interface item 6): `--machine <label>` and
//! `--launcher-unit <unit>`, and the uninstaller undoing the drop-ins.
//!
//! Serves plan check 8's "nothing broken" and the install steps behind checks
//! 1 and 6: the machine name is in `[identity]` before the service's first
//! start (so no commit is ever signed under the old `@agents.local` domain),
//! the background launchers (`sheprd-node.service`, `herdr-server.service`)
//! get agent-sign's `git` first on PATH through a systemd drop-in, and the
//! installer never restarts a launcher itself (restarting would kill running
//! agents; the plan says to coordinate it).
//!
//! Every test here fails today because `install.sh` doesn't know `--machine`
//! or `--launcher-unit` (it stops with "Unknown option" and exit status 2),
//! and the checks that a bad value is refused also require a message that
//! names the offending value, which "Unknown option" doesn't.
//!
//! Isolation (same approach as `test_identity_followup.rs`): the installer runs
//! from a copy of `scripts/` with the test's own builds as its programs, from
//! an empty environment plus a temporary HOME, a temporary global git config
//! and no system config. A folder of stand-ins is first on PATH for
//! `launchctl`, `systemctl`, `loginctl`, `codesign`, `pkill`, `pgrep`, `curl`
//! and `cargo`, so the real user systemd manager is never reached: with no
//! `XDG_RUNTIME_DIR` or bus address in the environment a real `systemctl
//! --user` couldn't reach it either, and each test first proves that
//! `systemctl` resolves to the stand-in. The `systemctl` and `launchctl`
//! stand-ins log every call (with the contents of `~/.agent-sign/config.toml`
//! at that moment, which is how "written before the first start" is
//! observed), and the `systemctl` stand-in answers `show-environment` with a
//! user manager PATH that is not the test's own PATH, so the drop-in's PATH
//! can only come from asking the manager. Every run is bounded in time.
//!
//! Note for the implementer: the stand-in answers `systemctl --user
//! show-environment` (one `NAME=value` per line, as the real command does).
//! Reading the user manager's PATH any other way would not see it.

use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use tempfile::{TempDir, tempdir};

const RUN_LIMIT: Duration = Duration::from_secs(60);

/// The user manager's PATH as the `systemctl show-environment` stand-in
/// reports it. Deliberately unlike the PATH of the test itself.
const MANAGER_PATH: &str = "/opt/manager-bin:/usr/local/bin:/usr/bin:/bin";

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn text(out: &Output) -> String {
    format!(
        "status: {}\nstdout: {}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn all_output(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn run_within(mut cmd: Command, what: &str) -> Output {
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap();
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

fn cleaned_path() -> OsString {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let kept: Vec<PathBuf> = std::env::split_paths(&path)
        .filter(|p| !p.to_string_lossy().contains(".agent-sign"))
        .collect();
    std::env::join_paths(kept).unwrap()
}

/// One stand-in call: what was asked, and the config file as it was then.
struct Call {
    args: String,
    config: Option<String>,
}

impl Call {
    /// The first argument that isn't an option: `enable`, `restart`,
    /// `bootstrap` and so on.
    fn verb(&self) -> &str {
        self.args
            .split_whitespace()
            .skip(1) // the program's name
            .find(|a| !a.starts_with('-'))
            .unwrap_or("")
    }

    // Used only by the Linux-only launcher-unit tests below.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fn mentions(&self, unit: &str) -> bool {
        self.args.split_whitespace().any(|a| a == unit)
    }

    /// A call that starts or restarts something.
    fn starts_something(&self) -> bool {
        matches!(
            self.verb(),
            "start"
                | "restart"
                | "try-restart"
                | "reload-or-restart"
                | "reload-or-try-restart"
                | "enable"
                | "bootstrap"
                | "kickstart"
                | "load"
        ) && !self.args.contains("show-environment")
    }
}

struct Lab {
    _dir: TempDir,
    home: PathBuf,
    global_config: PathBuf,
    src: PathBuf,
    fakebin: PathBuf,
    path: OsString,
}

impl Lab {
    /// A fresh home with no `~/.agent-sign` and no git signing set up.
    fn new() -> Lab {
        let dir = tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let home = root.join("home");
        fs::create_dir_all(&home).unwrap();
        let global_config = home.join("user.gitconfig");
        fs::write(
            &global_config,
            "[user]\n\tname = Human Developer\n\temail = dev@example.com\n",
        )
        .unwrap();

        let src = root.join("installer/src");
        let scripts = src.join("scripts");
        fs::create_dir_all(&scripts).unwrap();
        for entry in fs::read_dir(manifest_dir().join("scripts")).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_file() {
                fs::copy(entry.path(), scripts.join(entry.file_name())).unwrap();
            }
        }
        // The test builds carry the test authenticator, which the real check
        // rightly refuses to install.
        fs::write(scripts.join("check-binary-clean.sh"), "#!/bin/sh\nexit 0\n").unwrap();
        fs::write(
            src.join("Cargo.toml"),
            "[package]\nname = \"installer-fixture\"\nversion = \"0.0.0\"\n",
        )
        .unwrap();
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

        let fakebin = root.join("installer/fakebin");
        fs::create_dir_all(&fakebin).unwrap();
        for (name, status) in [
            ("loginctl", 0),
            ("codesign", 0),
            ("pkill", 1),
            ("pgrep", 1),
            ("curl", 1),
            ("cargo", 0),
        ] {
            write_executable(
                &fakebin.join(name),
                &format!(
                    "#!/bin/sh\necho \"{name} $*\" >> \"$HOME/stand-ins.log\"\nexit {status}\n"
                ),
            );
        }
        // The service managers: log the call, keep the config as it is at
        // this moment, and (systemctl) answer show-environment.
        for name in ["systemctl", "launchctl"] {
            write_executable(
                &fakebin.join(name),
                &format!(
                    "#!/bin/sh\n\
                     d=\"$HOME/stand-in-calls\"\n\
                     mkdir -p \"$d\"\n\
                     n=$(ls \"$d\" | grep -c '\\.call$')\n\
                     echo \"{name} $*\" >> \"$HOME/stand-ins.log\"\n\
                     echo \"{name} $*\" > \"$d/$n.call\"\n\
                     cp \"$HOME/.agent-sign/config.toml\" \"$d/$n.config\" 2>/dev/null\n\
                     case \"$*\" in\n\
                       *show-environment*) echo 'LANG=C'; echo 'PATH={MANAGER_PATH}' ;;\n\
                     esac\n\
                     exit 0\n"
                ),
            );
        }

        let mut path_dirs = vec![fakebin.clone()];
        path_dirs.extend(std::env::split_paths(&cleaned_path()));
        let path = std::env::join_paths(path_dirs).unwrap();

        let lab = Lab {
            _dir: dir,
            home,
            global_config,
            src,
            fakebin,
            path,
        };
        // The real user systemd manager must be unreachable: systemctl is the
        // stand-in, and there is no runtime directory or bus in the env.
        let resolved = std::env::split_paths(&lab.path)
            .map(|d| d.join("systemctl"))
            .find(|p| p.is_file())
            .unwrap();
        assert_eq!(resolved, lab.fakebin.join("systemctl"));
        lab
    }

    fn cmd(&self, program: &str) -> Command {
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
            .env("TERM", "dumb")
            .current_dir(&self.src)
            .stdin(Stdio::null());
        cmd
    }

    fn state(&self) -> PathBuf {
        self.home.join(".agent-sign")
    }

    /// `install.sh --yes <args>`, with no terminal.
    fn install(&self, args: &[&str]) -> Output {
        let mut cmd = self.cmd("/bin/bash");
        cmd.arg(self.src.join("scripts/install.sh"))
            .arg("--yes")
            .args(args);
        run_within(cmd, "install.sh")
    }

    // Used only by the Linux-only launcher-unit tests below.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fn uninstall(&self) -> Output {
        let mut cmd = self.cmd("/bin/bash");
        cmd.arg(self.src.join("scripts/uninstall.sh"));
        run_within(cmd, "uninstall.sh")
    }

    fn config_text(&self) -> Option<String> {
        fs::read_to_string(self.state().join("config.toml")).ok()
    }

    fn config(&self) -> Option<toml::Value> {
        toml::from_str(&self.config_text()?).ok()
    }

    fn machine(&self) -> Option<String> {
        self.config()?
            .get("identity")?
            .get("machine")?
            .as_str()
            .map(str::to_string)
    }

    /// Every `systemctl`/`launchctl` call, in order.
    fn calls(&self) -> Vec<Call> {
        let dir = self.home.join("stand-in-calls");
        let mut n = 0;
        let mut calls = Vec::new();
        while let Ok(args) = fs::read_to_string(dir.join(format!("{n}.call"))) {
            calls.push(Call {
                args: args.trim().to_string(),
                config: fs::read_to_string(dir.join(format!("{n}.config"))).ok(),
            });
            n += 1;
        }
        calls
    }

    fn global_git(&self, key: &str) -> Option<String> {
        let out = Command::new("git")
            .env_clear()
            .env("PATH", &self.path)
            .env("HOME", &self.home)
            .env("GIT_CONFIG_GLOBAL", &self.global_config)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .args(["config", "--global", "--get", key])
            .output()
            .unwrap();
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
    }
}

fn write_executable(path: &Path, body: &str) {
    fs::write(path, body).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

/// The `machine` the config held when this call was made.
fn machine_in(config: &Option<String>) -> Option<String> {
    let value: toml::Value = toml::from_str(config.as_ref()?).ok()?;
    value
        .get("identity")?
        .get("machine")?
        .as_str()
        .map(str::to_string)
}

// ---------------------------------------------------------------------------
// --machine
// ---------------------------------------------------------------------------

/// Plan checks 1 and 6 (interface item 6): `--machine hetzner` puts `[identity]
/// machine = "hetzner"` in the config before the service's first start, so no
/// agent ever gets a certificate in the old domain.
///
/// Fails today because `install.sh` stops with "Unknown option: --machine".
#[test]
fn machine_is_in_the_config_before_the_service_first_starts() {
    let lab = Lab::new();
    let out = lab.install(&["--machine", "hetzner"]);
    assert!(
        out.status.success(),
        "install.sh --yes --machine hetzner should succeed:\n{}",
        text(&out)
    );
    assert_eq!(
        lab.machine().as_deref(),
        Some("hetzner"),
        "config.toml should hold [identity] machine = \"hetzner\":\n{:?}\n{}",
        lab.config_text(),
        all_output(&out)
    );

    let starts: Vec<Call> = lab
        .calls()
        .into_iter()
        .filter(|c| c.starts_something())
        .collect();
    assert!(
        !starts.is_empty(),
        "the installer never asked the service manager to start the service \
         (the stand-in saw {} calls); this check would prove nothing",
        lab.calls().len()
    );
    for call in &starts {
        assert_eq!(
            machine_in(&call.config).as_deref(),
            Some("hetzner"),
            "the service was started ({:?}) before [identity] machine was in config.toml:\n{:?}",
            call.args,
            call.config
        );
    }
}

/// An existing install: the machine is added to a config that has no
/// `[identity]` yet, and everything else in the file is kept.
///
/// Fails today because `install.sh` stops with "Unknown option: --machine".
#[test]
fn machine_is_added_to_an_existing_config_without_identity() {
    let lab = Lab::new();
    fs::create_dir_all(lab.state()).unwrap();
    fs::write(
        lab.state().join("config.toml"),
        "[security]\napproval = \"none\"\nmax_commits_per_minute = 7\n\n[attribution]\nmode = \"agent\"\n",
    )
    .unwrap();
    let out = lab.install(&["--machine", "hetzner"]);
    assert!(out.status.success(), "install: {}", text(&out));
    assert_eq!(
        lab.machine().as_deref(),
        Some("hetzner"),
        "{:?}",
        lab.config_text()
    );
    let config = lab.config().expect("config.toml should still parse");
    assert_eq!(
        config["security"]["max_commits_per_minute"].as_integer(),
        Some(7),
        "the user's own setting was lost:\n{:?}",
        lab.config_text()
    );
}

/// An existing `[identity]` section (with the user's allowed agents) gets the
/// machine added to it, keeping its other keys and not repeating the header.
///
/// Fails today because `install.sh` stops with "Unknown option: --machine".
#[test]
fn machine_joins_an_existing_identity_section_and_keeps_allowed_agents() {
    let lab = Lab::new();
    fs::create_dir_all(lab.state()).unwrap();
    fs::write(
        lab.state().join("config.toml"),
        "[security]\napproval = \"none\"\n\n[identity]\nallowed_agents = [\"herdr-agent\", \"sheprd-node\"]\n\n[ssh]\nfallback_program = \"ssh-keygen\"\n",
    )
    .unwrap();
    let out = lab.install(&["--machine", "pi"]);
    assert!(out.status.success(), "install: {}", text(&out));
    let raw = lab.config_text().unwrap();
    let config = lab
        .config()
        .unwrap_or_else(|| panic!("config.toml no longer parses (duplicate [identity]?):\n{raw}"));
    assert_eq!(config["identity"]["machine"].as_str(), Some("pi"), "{raw}");
    let allowed: Vec<&str> = config["identity"]["allowed_agents"]
        .as_array()
        .unwrap_or_else(|| panic!("allowed_agents was lost:\n{raw}"))
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(allowed, ["herdr-agent", "sheprd-node"], "{raw}");
    assert_eq!(raw.matches("[identity]").count(), 1, "{raw}");
}

/// Installing again with the same machine is a no-op for the config: one
/// `[identity]`, one `machine`, and the file is byte-for-byte the same.
///
/// Fails today because `install.sh` stops with "Unknown option: --machine".
#[test]
fn installing_again_with_the_same_machine_changes_nothing() {
    let lab = Lab::new();
    let first = lab.install(&["--machine", "hetzner"]);
    assert!(first.status.success(), "first install: {}", text(&first));
    let after_first = lab.config_text().expect("a config after the first install");
    let second = lab.install(&["--machine", "hetzner"]);
    assert!(second.status.success(), "second install: {}", text(&second));
    let after_second = lab.config_text().unwrap();
    assert_eq!(after_first, after_second);
    assert_eq!(
        after_second.matches("[identity]").count(),
        1,
        "{after_second}"
    );
    let machine_lines = after_second
        .lines()
        .filter(|l| l.trim_start().starts_with("machine"))
        .count();
    assert_eq!(machine_lines, 1, "{after_second}");
    assert_eq!(lab.machine().as_deref(), Some("hetzner"));
}

/// Labels the daemon accepts (`^[a-z0-9]+(-[a-z0-9]+)*$`, at most 63
/// characters) are accepted by the installer, including the longest one.
///
/// Fails today because `install.sh` stops with "Unknown option: --machine".
#[test]
fn valid_machine_labels_are_accepted() {
    let longest = "a".repeat(63);
    for label in [
        "a",
        "0",
        "pi-4",
        "x1-2-3",
        "ubuntu-16gb-hel1-1",
        longest.as_str(),
    ] {
        let lab = Lab::new();
        let out = lab.install(&["--machine", label]);
        assert!(
            out.status.success(),
            "--machine {label:?} is a valid label and should be accepted:\n{}",
            text(&out)
        );
        assert_eq!(
            lab.machine().as_deref(),
            Some(label),
            "{:?}",
            lab.config_text()
        );
    }
}

/// An invalid label is refused up front, with a message that names it, and
/// before anything changes: no programs installed, no service started, no git
/// setting touched, no machine written. (OpenSSH's `*` matches `@` and `.`,
/// so a bad label in the trust line would widen what is trusted; that is why
/// the rule is strict.)
///
/// Fails today because `install.sh` stops with "Unknown option: --machine",
/// which doesn't name the bad value (and the missing-value case needs a
/// message that isn't "Unknown option").
#[test]
fn an_invalid_machine_label_is_refused_before_anything_changes() {
    let too_long = "a".repeat(64);
    let bad: Vec<&str> = vec![
        "Hetzner",
        "-hetzner",
        "hetzner-",
        "het--zner",
        "het_zner",
        "het.zner",
        "het zner",
        "hetzner.agents.local",
        "*",
        "a@b",
        too_long.as_str(),
    ];
    for label in bad {
        let lab = Lab::new();
        let out = lab.install(&["--machine", label]);
        let shown = all_output(&out);
        assert!(
            !out.status.success(),
            "--machine {label:?} should be refused:\n{}",
            text(&out)
        );
        assert!(
            !shown.contains("Unknown option"),
            "--machine {label:?} was refused only because the installer doesn't know the option:\n{shown}"
        );
        assert!(
            shown.contains(label),
            "the refusal for --machine {label:?} should name the bad value:\n{shown}"
        );
        assert!(
            shown.to_lowercase().contains("machine"),
            "the refusal for --machine {label:?} should say what a machine name may be:\n{shown}"
        );
        assert_nothing_changed(&lab, label);
    }
}

/// `--machine` with no value, or an empty one, is refused too.
///
/// Fails today because `install.sh` stops with "Unknown option".
#[test]
fn a_missing_or_empty_machine_value_is_refused() {
    for args in [vec!["--machine"], vec!["--machine", ""]] {
        let lab = Lab::new();
        let out = lab.install(&args);
        let shown = all_output(&out);
        assert!(
            !out.status.success(),
            "{args:?} should be refused:\n{}",
            text(&out)
        );
        assert!(
            !shown.contains("Unknown option"),
            "{args:?} was refused only because the installer doesn't know the option:\n{shown}"
        );
        assert!(shown.contains("--machine"), "{args:?}: {shown}");
        assert_nothing_changed(&lab, &format!("{args:?}"));
    }
}

fn assert_nothing_changed(lab: &Lab, what: &str) {
    assert!(
        !lab.state().join("bin").exists(),
        "{what}: programs were installed although the label was refused"
    );
    assert!(
        lab.calls().iter().all(|c| !c.starts_something()),
        "{what}: the service was started although the label was refused: {:?}",
        lab.calls()
            .iter()
            .map(|c| c.args.clone())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        lab.global_git("gpg.ssh.program"),
        None,
        "{what}: git's signing program was changed although the label was refused"
    );
    assert_eq!(lab.machine(), None, "{what}: a machine was written");
}

// ---------------------------------------------------------------------------
// --launcher-unit (Linux only)
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod launcher_units {
    use super::*;

    fn drop_in(lab: &Lab, unit: &str) -> PathBuf {
        lab.home
            .join(".config/systemd/user")
            .join(format!("{unit}.d"))
            .join("agent-sign.conf")
    }

    /// The non-blank, non-comment lines of a drop-in.
    fn lines_of(path: &Path) -> Vec<String> {
        fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("{} should exist: {e}", path.display()))
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with(';'))
            .map(str::to_string)
            .collect()
    }

    fn expected_lines(lab: &Lab) -> Vec<String> {
        vec![
            "[Service]".to_string(),
            format!(
                "Environment=PATH={}/.agent-sign/bin:{MANAGER_PATH}",
                lab.home.display()
            ),
        ]
    }

    const RESTARTING_VERBS: &[&str] = &[
        "restart",
        "try-restart",
        "reload-or-restart",
        "reload-or-try-restart",
        "start",
        "stop",
        "kill",
        "reload",
        "kickstart",
    ];

    /// Plan step 5 (interface item 6): `--launcher-unit` writes
    /// `~/.config/systemd/user/<unit>.d/agent-sign.conf` holding `[Service]`
    /// and `Environment=PATH=<home>/.agent-sign/bin:<the user manager's
    /// PATH>`, for each unit given (the flag repeats), together with
    /// `--machine`.
    ///
    /// Fails today because `install.sh` stops with "Unknown option:
    /// --machine" (and would do the same for `--launcher-unit`).
    #[test]
    fn the_drop_in_holds_agent_signs_bin_first_on_the_user_managers_path() {
        let lab = Lab::new();
        let out = lab.install(&[
            "--machine",
            "hetzner",
            "--launcher-unit",
            "foo.service",
            "--launcher-unit",
            "bar.service",
        ]);
        assert!(out.status.success(), "install: {}", text(&out));
        for unit in ["foo.service", "bar.service"] {
            assert_eq!(
                lines_of(&drop_in(&lab, unit)),
                expected_lines(&lab),
                "drop-in for {unit}"
            );
        }
    }

    /// `--launcher-unit` on its own (no machine name) works the same.
    ///
    /// Fails today because `install.sh` stops with "Unknown option:
    /// --launcher-unit".
    #[test]
    fn a_launcher_unit_needs_no_machine_name() {
        let lab = Lab::new();
        let out = lab.install(&["--launcher-unit", "foo.service"]);
        assert!(out.status.success(), "install: {}", text(&out));
        assert_eq!(
            lines_of(&drop_in(&lab, "foo.service")),
            expected_lines(&lab)
        );
    }

    /// The installer must never restart (or stop, start or signal) a launcher
    /// unit itself: restarting `sheprd-node.service` kills the agents it is
    /// running. It prints the command for the user instead. The service
    /// manager stand-in sees every call, so this is checked for each unit.
    ///
    /// Fails today because `install.sh` stops with "Unknown option:
    /// --launcher-unit".
    #[test]
    fn the_installer_never_restarts_a_launcher_unit_and_prints_the_command() {
        let lab = Lab::new();
        let out = lab.install(&[
            "--launcher-unit",
            "foo.service",
            "--launcher-unit",
            "bar.service",
        ]);
        assert!(out.status.success(), "install: {}", text(&out));
        for unit in ["foo.service", "bar.service"] {
            for call in lab.calls() {
                assert!(
                    !(call.mentions(unit) && RESTARTING_VERBS.contains(&call.verb())),
                    "the installer touched the launcher unit {unit}: {:?}",
                    call.args
                );
            }
            let shown = all_output(&out);
            assert!(
                shown.contains(&format!("systemctl --user restart {unit}")),
                "the installer should print the restart command for {unit}:\n{shown}"
            );
        }
        // Nothing but agent-signd's own service is started, enabled or stopped.
        for call in lab.calls() {
            if RESTARTING_VERBS.contains(&call.verb()) || call.verb() == "enable" {
                assert!(
                    call.mentions("agent-signd"),
                    "the installer started or stopped something other than agent-signd: {:?}",
                    call.args
                );
            }
        }
    }

    /// Installing again with the same units leaves one identical drop-in each.
    ///
    /// Fails today because `install.sh` stops with "Unknown option:
    /// --launcher-unit".
    #[test]
    fn installing_again_leaves_one_identical_drop_in() {
        let lab = Lab::new();
        let args = ["--launcher-unit", "foo.service"];
        let first = lab.install(&args);
        assert!(first.status.success(), "{}", text(&first));
        let before = fs::read_to_string(drop_in(&lab, "foo.service")).unwrap();
        let second = lab.install(&args);
        assert!(second.status.success(), "{}", text(&second));
        let after = fs::read_to_string(drop_in(&lab, "foo.service")).unwrap();
        assert_eq!(before, after);
        assert_eq!(after.matches("[Service]").count(), 1, "{after}");
    }

    /// A unit name is required.
    ///
    /// Fails today because the installer's refusal is "Unknown option", not
    /// one about the missing unit.
    #[test]
    fn a_launcher_unit_flag_without_a_name_is_refused() {
        let lab = Lab::new();
        let out = lab.install(&["--launcher-unit"]);
        let shown = all_output(&out);
        assert!(!out.status.success(), "{}", text(&out));
        assert!(
            !shown.contains("Unknown option"),
            "refused only because the installer doesn't know the option:\n{shown}"
        );
        assert!(shown.contains("--launcher-unit"), "{shown}");
        assert!(!lab.state().join("bin").exists(), "programs were installed");
    }

    /// Uninstall removes the drop-ins agent-sign wrote, leaves a drop-in the
    /// user wrote beside them untouched, and doesn't restart anything.
    ///
    /// Fails today because `install.sh` stops with "Unknown option:
    /// --launcher-unit", so there is nothing to uninstall.
    #[test]
    fn uninstall_removes_the_drop_ins_and_leaves_the_users_own() {
        let lab = Lab::new();
        let user_dir = lab.home.join(".config/systemd/user/foo.service.d");
        fs::create_dir_all(&user_dir).unwrap();
        let users_own = user_dir.join("10-mine.conf");
        let users_text = "[Service]\nEnvironment=MINE=1\n";
        fs::write(&users_own, users_text).unwrap();

        let out = lab.install(&[
            "--launcher-unit",
            "foo.service",
            "--launcher-unit",
            "bar.service",
        ]);
        assert!(out.status.success(), "install: {}", text(&out));
        for unit in ["foo.service", "bar.service"] {
            assert!(
                drop_in(&lab, unit).is_file(),
                "no drop-in for {unit} after install"
            );
        }
        assert_eq!(fs::read_to_string(&users_own).unwrap(), users_text);

        let calls_before = lab.calls().len();
        let out = lab.uninstall();
        assert!(out.status.success(), "uninstall: {}", text(&out));
        for unit in ["foo.service", "bar.service"] {
            assert!(
                !drop_in(&lab, unit).exists(),
                "uninstall left the drop-in for {unit}"
            );
        }
        assert_eq!(
            fs::read_to_string(&users_own).unwrap(),
            users_text,
            "uninstall touched the user's own drop-in"
        );
        for call in lab.calls().iter().skip(calls_before) {
            assert!(
                !((call.mentions("foo.service") || call.mentions("bar.service"))
                    && RESTARTING_VERBS.contains(&call.verb())),
                "uninstall restarted a launcher unit: {:?}",
                call.args
            );
        }
    }
}
