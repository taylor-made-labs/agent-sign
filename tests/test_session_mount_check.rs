//! L2: the session's own programs refuse unless the mount at `current/` is
//! the slot's own `current/` (`agent_sign::session_runner::check_current_mount`,
//! with its fixtures in the library's unit tests). This program checks the
//! parts the fixtures can't: the thin system call reads the real
//! `/proc/self/mountinfo`, and both programs call the check before doing
//! anything else. Not testable here: a real bind mount of a followed link
//! (needs root or a user namespace; neither exists for the agents account on
//! hetzner), so the real systemd behaviour is covered by the fixtures only,
//! shaped like real mountinfo lines.

#![cfg(target_os = "linux")]

use std::fs;
use std::path::Path;

use agent_sign::session_runner::check_own_mount;

fn source(rel: &str) -> String {
    fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)).unwrap()
}

/// The thin call reads this process's real mountinfo: a folder that is not a
/// mount point of its own is refused ("nothing is mounted"), whichever
/// folder it is, including a plain slot-shaped path in a temp folder.
#[test]
fn the_real_mountinfo_has_no_mount_at_an_ordinary_slot_path() {
    let t = tempfile::tempdir().unwrap();
    let cur = fs::canonicalize(t.path()).unwrap().join("slots/1/current");
    fs::create_dir_all(&cur).unwrap();
    let e = check_own_mount(&cur).unwrap_err();
    assert!(e.contains("nothing is mounted"), "{e}");
    // The real root is a mount, but not at a slot's current/.
    assert!(check_own_mount(Path::new("/var/lib/agent-slots/1/current")).is_err());
}

/// Both session programs run the check in `this_slot`, which both call first,
/// after finding the slot and before the cgroup check, the spec, or any
/// write. A source check: it fails if the call is removed or moved after
/// anything that reads or makes files.
#[test]
fn both_session_programs_check_the_mount_before_anything_else() {
    let src = source("src/session_runner.rs");
    let this_slot = src
        .split("fn this_slot(step: Step)")
        .nth(1)
        .expect("this_slot is gone");
    let body = this_slot.split("\n}\n").next().unwrap();
    let call = body
        .find("check_own_mount(&current_of(&config, n))?;")
        .expect("this_slot no longer checks the mount at current/");
    let cgroup = body.find("/proc/self/cgroup").unwrap();
    assert!(
        call < cgroup,
        "the mount check must come before reading anything else"
    );
    for f in ["fn exec_inner()", "fn end_inner()"] {
        let b = src.split(f).nth(1).unwrap();
        let first = b.lines().nth(1).unwrap();
        assert!(
            first.contains("this_slot(Step::"),
            "{f} must start with this_slot (which runs the mount check): {first}"
        );
    }
}

/// The unit files and the doc keep `BindPaths=` on the slot's own `current`,
/// the thing the check is written for; the doc says what the check is.
#[test]
fn the_doc_describes_the_mount_check() {
    let doc = source("docs/system-mode.md");
    assert!(
        doc.contains("/proc/self/mountinfo"),
        "docs/system-mode.md doesn't describe the mount check"
    );
    assert!(doc.contains("check_current_mount"));
}
