//! The launcher's three questions to systemd, behind a port
//! (docs/system-mode.md, section 2; build step 3).
//!
//! **Why a port.** The launcher (`agent-launchd`) asks systemd for exactly
//! three things: start a unit, stop a unit, and whether a unit is active.
//! Tests can't start system units (that needs root and the sitting's polkit
//! rule), so the launcher reaches systemd only through [`Systemd`], and the
//! tests put a folder in its place (the stand-in below, in debug test builds
//! only).
//!
//! **The real adapter** runs `systemctl` from its root-owned place
//! (`/usr/bin/systemctl` or `/bin/systemctl`, never a `PATH` lookup), with an
//! empty environment and `--no-ask-password`. `systemctl` speaks systemd's
//! D-Bus interface, and polkit decides: the sitting's rule
//! `50-agent-launch.rules` lets the launcher's account start and stop
//! exactly `agent-session@1..N` and `agent-session-end@1..N`, and nothing
//! else. That is the boundary; this adapter adds its own check on top
//! ([`is_slot_unit`]), so a bug in the launcher can't even ask for another
//! unit. Running the system's own client instead of speaking D-Bus here
//! adds no dependency and no protocol code of our own to audit.
//!
//! - **start** waits for the start job (a session unit is `Type=exec`, so it
//!   returns once the program runs) and reports a refusal.
//! - **stop** doesn't wait (`--no-block`): a process that won't die mustn't
//!   hold the launcher up. The launcher polls [`Systemd::is_active`] instead,
//!   and a slot is never given out again until its units are inactive.
//! - **is-active** answers "not active" only for `inactive` and `failed`.
//!   Everything else, an error included, counts as active: a slot whose
//!   state can't be learned stays busy (fail closed).

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;

/// What the launcher asks systemd (see the module documentation).
pub trait Systemd: Send + Sync {
    /// Starts `unit`.
    fn start(&self, unit: &str) -> Result<(), String>;
    /// Asks `unit` to stop, without waiting for it.
    fn stop(&self, unit: &str) -> Result<(), String>;
    /// Whether `unit` is active, activating or deactivating. An error when
    /// systemd wouldn't say; the caller then treats the unit as active.
    fn is_active(&self, unit: &str) -> Result<bool, String>;
}

/// Slot `n`'s end-of-session unit.
pub fn end_unit(slot: u32) -> String {
    format!("agent-session-end@{slot}.service")
}

/// Whether `unit` is one of the units the launcher may touch:
/// `agent-session@<n>.service` or `agent-session-end@<n>.service` with `n`
/// from 1 to `count`, written exactly so (no leading zero).
pub fn is_slot_unit(unit: &str, count: u32) -> bool {
    let rest = unit
        .strip_prefix("agent-session-end@")
        .or_else(|| unit.strip_prefix("agent-session@"));
    let Some(n) = rest.and_then(|r| r.strip_suffix(".service")) else {
        return false;
    };
    if n.is_empty() || n.starts_with('0') || !n.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    n.parse::<u32>().is_ok_and(|n| n >= 1 && n <= count)
}

/// The real adapter: the system's `systemctl` (see the module
/// documentation).
pub struct Systemctl {
    program: PathBuf,
    count: u32,
}

impl Systemctl {
    /// The adapter for a machine with `count` slots, or why there is none.
    pub fn new(count: u32) -> Result<Self, String> {
        let program = ["/usr/bin/systemctl", "/bin/systemctl"]
            .into_iter()
            .map(PathBuf::from)
            .find(|p| p.is_file())
            .ok_or("systemctl isn't at /usr/bin/systemctl or /bin/systemctl")?;
        Ok(Self { program, count })
    }

    fn run(&self, args: &[&str], unit: &str) -> Result<std::process::Output, String> {
        if !is_slot_unit(unit, self.count) {
            return Err(format!(
                "{unit:?} isn't a slot's session or end unit, so the launcher never asks for it"
            ));
        }
        Command::new(&self.program)
            .env_clear()
            .arg("--no-ask-password")
            .args(args)
            .arg("--")
            .arg(unit)
            .stdin(Stdio::null())
            .output()
            .map_err(|e| format!("couldn't run {} ({e})", self.program.display()))
    }

    fn say(out: &std::process::Output) -> String {
        let err = String::from_utf8_lossy(&out.stderr);
        let first = err.lines().next().unwrap_or("").trim();
        if first.is_empty() {
            format!("systemctl exited with {}", out.status)
        } else {
            first.to_string()
        }
    }
}

impl Systemd for Systemctl {
    fn start(&self, unit: &str) -> Result<(), String> {
        let out = self.run(&["start"], unit)?;
        if out.status.success() {
            Ok(())
        } else {
            Err(format!("systemd didn't start {unit}: {}", Self::say(&out)))
        }
    }

    fn stop(&self, unit: &str) -> Result<(), String> {
        let out = self.run(&["--no-block", "stop"], unit)?;
        if out.status.success() {
            Ok(())
        } else {
            Err(format!("systemd didn't stop {unit}: {}", Self::say(&out)))
        }
    }

    fn is_active(&self, unit: &str) -> Result<bool, String> {
        let out = self.run(&["is-active"], unit)?;
        let state = String::from_utf8_lossy(&out.stdout).trim().to_string();
        match state.as_str() {
            "inactive" | "failed" => Ok(false),
            "" => Err(format!(
                "systemd didn't say whether {unit} is active: {}",
                Self::say(&out)
            )),
            _ => Ok(true),
        }
    }
}

/// The systemd the launcher uses: the real one, or, in test builds only,
/// the folder `AGENT_SIGN_TEST_SYSTEMD` names.
pub fn systemd(count: u32) -> Result<Arc<dyn Systemd>, String> {
    #[cfg(feature = "test-authenticator")]
    if let Some(dir) = std::env::var_os("AGENT_SIGN_TEST_SYSTEMD") {
        return Ok(Arc::new(test_seam::FolderSystemd {
            dir: PathBuf::from(dir),
        }));
    }
    Ok(Arc::new(Systemctl::new(count)?))
}

/// The test stand-in (`tests/test_launcher_daemon.rs` defines it): `start U`
/// and `stop U` are appended to `<dir>/calls.log`; starting a session unit
/// makes the marker `<dir>/active/U`; stopping removes it unless
/// `<dir>/stuck/U` exists; `is-active U` is whether the marker exists.
#[cfg(feature = "test-authenticator")]
mod test_seam {
    use super::Systemd;
    use std::io::Write;
    use std::path::PathBuf;

    pub(super) struct FolderSystemd {
        pub(super) dir: PathBuf,
    }

    impl FolderSystemd {
        fn log(&self, line: &str) -> Result<(), String> {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open(self.dir.join("calls.log"))
                .map_err(|e| e.to_string())?;
            f.write_all(format!("{line}\n").as_bytes())
                .map_err(|e| e.to_string())
        }
    }

    impl Systemd for FolderSystemd {
        fn start(&self, unit: &str) -> Result<(), String> {
            self.log(&format!("start {unit}"))?;
            if unit.starts_with("agent-session@") {
                std::fs::write(self.dir.join("active").join(unit), "")
                    .map_err(|e| e.to_string())?;
            }
            Ok(())
        }

        fn stop(&self, unit: &str) -> Result<(), String> {
            self.log(&format!("stop {unit}"))?;
            if !self.dir.join("stuck").join(unit).exists() {
                let _ = std::fs::remove_file(self.dir.join("active").join(unit));
            }
            Ok(())
        }

        fn is_active(&self, unit: &str) -> Result<bool, String> {
            Ok(self.dir.join("active").join(unit).exists())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_slots_own_units_are_asked_for() {
        for good in [
            "agent-session@1.service",
            "agent-session@8.service",
            "agent-session-end@3.service",
        ] {
            assert!(is_slot_unit(good, 8), "{good}");
        }
        for bad in [
            "agent-session@0.service",
            "agent-session@9.service",
            "agent-session@01.service",
            "agent-session@1.service ",
            "agent-session@.service",
            "agent-signd.service",
            "agent-session@1.socket",
            "agent-session@1",
            "agent-session@-1.service",
            "agent-session@1x.service",
        ] {
            assert!(!is_slot_unit(bad, 8), "{bad}");
        }
    }
}
