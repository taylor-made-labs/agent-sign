//! Launch approvals: how an account other than a person's may ask the
//! launcher (`agent-launchd`) to start a session (docs/system-mode.md,
//! section 3, way 2; build step 3).
//!
//! **Why.** In system mode the agents account must not be able to start a
//! session by asking (sitting test P1): a session signs as an attested agent,
//! so whoever can start one decides what gets signed. A person's account
//! (`[launcher] people_accounts`) launches by asking, because its uid is
//! already trusted with root. Anyone else needs a launch approval: a text
//! signed by a key listed in `[launcher] approvers` (the commitments approval
//! key, once it exists; until then the list is empty and only a person's
//! account launches, which is the suite PM's decision Q1 of 1 Nov 2026).
//!
//! **The same verifier as commit approvals.** The signature is checked by
//! [`crate::commit_approval::CommitmentsKey::verify_in`], the code that
//! checks commit approvals, in the namespace [`LAUNCH_NAMESPACE`]. A
//! signature the key made for anything else (a commit approval, a git
//! commit) is never a launch approval, and nothing in the text is read
//! before the signature verifies.
//!
//! **What it binds.** The text has exactly the fields of
//! [`LaunchApproval`] (a field this version doesn't know, or one given twice,
//! is refused): kind "launch", this machine, the agent's name, each
//! repository's name and base commit in order, `program` (the lowercase hex
//! SHA-256 of the compact JSON text of the command array, so another program
//! or other arguments are another hash), the expiry and a nonce. The request
//! must match it exactly: the approval is what is trusted, so whoever relays
//! it (the agents account, a job runner) can change nothing.
//!
//! **What it does not bind: the environment.** The approval names no
//! environment variables, so a relayer can add any to a genuine one. The
//! launcher therefore never takes the environment from the approval or the
//! relayer's wishes: every caller gets only `LANG` and `TERM` with plain
//! values ([`crate::launcher::check_env`]), and anything else refuses the
//! request before the approval's nonce is touched. Widening what an approval
//! covers (an `env` field) would be a change to the signed text and to the
//! commitments key's signer, and is not built.
//!
//! **Used once.** The nonce is recorded, synced to disk, under the launcher's
//! lock, before the session is started ([`LaunchNonces::record`]), and an
//! approval whose nonce is recorded is refused ever after. A refused approval
//! is not used up: every check runs before the record, so presenting a
//! captured approval with another program, or before a slot is free, can't
//! spend it before the real job runner does.
//!
//! **Reserved when it verifies (re-check R2).** The record comes late: after
//! the bundles have been read, which a verified relayer may take up to
//! 600 s over. Left at that, one valid approval could be presented again and
//! again, each presentation holding a place for reading bundles until its
//! deadline, because none of them had spent the nonce yet. So a nonce is
//! *reserved* ([`LaunchNonces::reserve`]) the moment its approval verifies,
//! before any bundle byte is read: a second presentation of a nonce that is
//! reserved or spent is refused at once, taking no place. The reservation is
//! memory only and is given back ([`LaunchNonces::release`]) by any launch
//! that ends before a slot is claimed, so a refusal still doesn't use the
//! approval up; a recorded nonce is spent for good. What a reservation costs
//! the real job runner, if someone holding a copy of its approval presents it
//! first, is that it is refused until that presentation ends (at most the
//! request deadline); the approval is not lost.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::commit_approval::{
    CommitmentsKey, KEEP_NONCES_AFTER_EXPIRY_SECS, append_synced, complete_lines, is_nonce,
    is_object_id, replace_file,
};

/// The SSHSIG namespace of a launch approval.
pub const LAUNCH_NAMESPACE: &str = "agent-sign-launch-approval";

/// The one kind of approval the launcher starts sessions on.
pub const LAUNCH_KIND: &str = "launch";

/// One repository a launch approval names: its name in the session
/// (`work/<name>`) and the commit the session starts from.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedRepo {
    pub name: String,
    pub base: String,
}

/// What one launch approval names (see the module documentation).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchApproval {
    /// [`LAUNCH_KIND`].
    pub kind: String,
    /// The machine (`system.toml`'s `machine`) whose launcher may start it.
    pub machine: String,
    /// The agent's name, exactly as the request gives it.
    pub agent: String,
    /// The repositories, in the request's order.
    pub repos: Vec<ApprovedRepo>,
    /// [`program_hash`] of the command.
    pub program: String,
    /// When the approval stops being good, in seconds since the epoch.
    pub expires_at: u64,
    /// Single use.
    pub nonce: String,
}

/// The lowercase hex SHA-256 of the compact JSON text of `command`
/// (`["sleep","3600"]`): what a launch approval's `program` is.
pub fn program_hash(command: &[String]) -> String {
    let text = serde_json::to_string(command).unwrap_or_default();
    Sha256::digest(text.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The keys whose launch approvals the launcher accepts (`[launcher]
/// approvers`). Empty until the commitments approval key exists.
#[derive(Debug, Clone, Default)]
pub struct Approvers(Vec<CommitmentsKey>);

impl Approvers {
    /// The keys in `lines`, each one OpenSSH `ssh-ed25519` public key line.
    /// One that doesn't read is an error naming it: the launcher then
    /// refuses to start, rather than run with fewer approvers than the
    /// settings say.
    pub fn parse(lines: &[String]) -> Result<Self, String> {
        let mut keys = Vec::new();
        for (i, line) in lines.iter().enumerate() {
            keys.push(
                CommitmentsKey::parse(line)
                    .map_err(|e| format!("[launcher] approvers, entry {}: {e}", i + 1))?,
            );
        }
        Ok(Self(keys))
    }

    /// Whether no key may sign a launch approval (only people launch).
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// What a launch request asks for, as the approval is checked against it.
pub struct Asked<'a> {
    pub machine: &'a str,
    pub agent: &'a str,
    pub command: &'a [String],
    /// Each repository's name and base commit, in the request's order.
    pub repos: &'a [ApprovedRepo],
    /// Now, in seconds since the epoch.
    pub now: u64,
}

/// Checks a presented approval (`text`, `signature`) against `asked`: the
/// signature first (by one of `approvers`, in [`LAUNCH_NAMESPACE`], over
/// exactly `text`), then every field. Does not look at or record the nonce's
/// use: that is [`LaunchNonces`]'s, under the launcher's lock.
pub fn check(
    approvers: &Approvers,
    text: &str,
    signature: &str,
    asked: &Asked<'_>,
) -> Result<LaunchApproval, String> {
    let refused = |why: String| Err(format!("launch approval refused: {why}"));
    if approvers.is_empty() {
        return refused(
            "no key may sign launch approvals on this machine yet ([launcher] approvers is \
             empty), so only a person's account may launch"
                .into(),
        );
    }
    let mut why = String::new();
    let verified = approvers.0.iter().any(|key| {
        match key.verify_in(LAUNCH_NAMESPACE, text.as_bytes(), signature) {
            Ok(()) => true,
            Err(e) => {
                why = e;
                false
            }
        }
    });
    if !verified {
        return refused(format!(
            "its signature isn't one of [launcher] approvers' in the {LAUNCH_NAMESPACE} \
             namespace over exactly its text ({why})"
        ));
    }
    let approval: LaunchApproval = match serde_json::from_str(text) {
        Ok(a) => a,
        Err(e) => return refused(format!("its text isn't a launch approval ({e})")),
    };
    if approval.kind != LAUNCH_KIND {
        return refused(format!("its kind is {:?}, not \"launch\"", approval.kind));
    }
    if approval.machine != asked.machine {
        return refused(format!(
            "it is for machine {:?}, and this is {:?}",
            approval.machine, asked.machine
        ));
    }
    if approval.agent != asked.agent {
        return refused(format!(
            "it is for agent {:?}, and the request names {:?}",
            approval.agent, asked.agent
        ));
    }
    if approval.program != program_hash(asked.command) {
        return refused(
            "the program or its arguments aren't the ones approved (their SHA-256 differs from \
             the approval's program)"
                .into(),
        );
    }
    if approval.repos != asked.repos {
        return refused("the repositories or their base commits aren't the ones approved".into());
    }
    if !approval.repos.iter().all(|r| is_object_id(&r.base)) {
        return refused("its base commits must be git object ids".into());
    }
    if !is_nonce(&approval.nonce) {
        return refused("its nonce isn't 16 to 128 letters, digits, '-' or '_'".into());
    }
    if asked.now >= approval.expires_at {
        return refused("it has expired".into());
    }
    Ok(approval)
}

/// The used launch nonces' file in the launcher's state folder.
pub const NONCES_FILE: &str = "launch-nonces";

/// One used nonce, as [`NONCES_FILE`] keeps it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UsedNonce {
    nonce: String,
    expires_at: u64,
}

/// The launch nonces used, kept in `<state>/approvals/launch-nonces`, one
/// JSON line each, synced before a session starts, so an approval is never
/// launched on twice, even across a crash. Nonces long past their expiry are
/// pruned at open (an expired approval is refused anyway).
#[derive(Debug)]
pub struct LaunchNonces {
    dir: PathBuf,
    used: HashMap<String, u64>,
    /// Nonces whose approval verified and whose launch has not yet either
    /// recorded them or ended (memory only; see the module documentation).
    /// Bounded by the launches in flight, which the launcher's read places
    /// bound.
    reserved: HashSet<String>,
}

impl LaunchNonces {
    /// The store in `state_dir` (its `approvals/` made 0700 if new). A line
    /// that can't be read stops the launcher: a store it can't trust would
    /// let a used approval launch again.
    pub fn open(state_dir: &Path, now: u64) -> Result<Self, String> {
        let dir = state_dir.join("approvals");
        let err = |what: &str, e: std::io::Error| format!("{}: {what}: {e}", dir.display());
        fs::create_dir_all(&dir).map_err(|e| err("can't be made", e))?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
            .map_err(|e| err("can't be made private", e))?;
        let path = dir.join(NONCES_FILE);
        let text = match fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(err(NONCES_FILE, e)),
        };
        let mut used = HashMap::new();
        let mut kept = String::new();
        for line in complete_lines(&text) {
            let u: UsedNonce = serde_json::from_str(line)
                .map_err(|e| format!("{}: a line can't be read ({e})", path.display()))?;
            if u.expires_at.saturating_add(KEEP_NONCES_AFTER_EXPIRY_SECS) > now {
                kept.push_str(line);
                kept.push('\n');
                used.insert(u.nonce, u.expires_at);
            }
        }
        replace_file(&dir, &path, &kept).map_err(|e| err(NONCES_FILE, e))?;
        Ok(Self {
            dir,
            used,
            reserved: HashSet::new(),
        })
    }

    /// Whether `nonce` has launched a session.
    pub fn is_used(&self, nonce: &str) -> bool {
        self.used.contains_key(nonce)
    }

    /// Whether `nonce` is reserved by a launch now in flight.
    pub fn is_reserved(&self, nonce: &str) -> bool {
        self.reserved.contains(nonce)
    }

    /// Reserves `nonce` for the launch that presented its verified
    /// approval: refused when the nonce is used (the approval was already
    /// launched on) or reserved (another request is presenting it right now).
    /// Writes nothing to disk. The launch must [`LaunchNonces::release`] it
    /// on every way out that has not recorded it; [`LaunchNonces::record`]
    /// ends the reservation itself, because a used nonce is refused first.
    pub fn reserve(&mut self, nonce: &str) -> Result<(), String> {
        if self.is_used(nonce) {
            return Err("launch approval refused: it was already used".into());
        }
        if !self.reserved.insert(nonce.to_string()) {
            return Err(
                "launch approval refused: another request is presenting it right \
                 now. If that request ends without starting a session the approval can be \
                 presented again"
                    .into(),
            );
        }
        Ok(())
    }

    /// Gives a reservation back (a no-op for a nonce that is not reserved, or
    /// that has since been recorded: a used nonce stays used).
    pub fn release(&mut self, nonce: &str) {
        self.reserved.remove(nonce);
    }

    /// Records `nonce` as used, synced to disk before it returns; refuses
    /// one already used. The caller holds the launcher's lock from the
    /// check to the record. A successful record ends the nonce's
    /// reservation, if it had one.
    pub fn record(&mut self, nonce: &str, expires_at: u64) -> Result<(), String> {
        if self.is_used(nonce) {
            return Err("launch approval refused: it was already used".into());
        }
        let line = serde_json::to_string(&UsedNonce {
            nonce: nonce.to_string(),
            expires_at,
        })
        .map_err(|e| e.to_string())?;
        append_synced(&self.dir.join(NONCES_FILE), &line).map_err(|e| {
            format!(
                "the launch approval's nonce can't be recorded in {} ({e}), so nothing was \
                 started",
                self.dir.display()
            )
        })?;
        // Memory stays bounded by what the approvals' lifetimes allow: a
        // nonce long past its expiry leaves the map when the next one is
        // recorded (the file is rewritten without it at the next open).
        // Nothing is lost: an expired approval is refused on its expiry
        // before its nonce is ever looked at.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        self.used
            .retain(|_, exp| exp.saturating_add(KEEP_NONCES_AFTER_EXPIRY_SECS) > now);
        self.used.insert(nonce.to_string(), expires_at);
        self.reserved.remove(nonce);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_program_hash_is_of_the_compact_json_array() {
        let cmd = vec!["sleep".to_string(), "3600".to_string()];
        let want: String = Sha256::digest(br#"["sleep","3600"]"#)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(program_hash(&cmd), want);
        assert_ne!(
            program_hash(&cmd),
            program_hash(&["sleep".into(), "1".into()])
        );
    }

    #[test]
    fn an_approval_text_has_exactly_its_fields() {
        let a = LaunchApproval {
            kind: "launch".into(),
            machine: "m".into(),
            agent: "a".into(),
            repos: vec![],
            program: "p".into(),
            expires_at: 1,
            nonce: "n".into(),
        };
        let text = serde_json::to_string(&a).unwrap();
        assert!(serde_json::from_str::<LaunchApproval>(&text).is_ok());
        let extra = text.replace("\"kind\"", "\"extra\":1,\"kind\"");
        assert!(serde_json::from_str::<LaunchApproval>(&extra).is_err());
    }

    #[test]
    fn no_approvers_means_no_launch_approval_is_good() {
        let e = check(
            &Approvers::default(),
            "{}",
            "x",
            &Asked {
                machine: "m",
                agent: "a",
                command: &[],
                repos: &[],
                now: 0,
            },
        )
        .unwrap_err();
        assert!(e.contains("approvers"), "{e}");
    }

    #[test]
    fn a_reserved_nonce_is_refused_until_released_and_a_spent_one_stays_spent() {
        let dir = tempfile::tempdir().unwrap();
        let mut n = LaunchNonces::open(dir.path(), 10).unwrap();
        let nonce = "nonce-0123456789abcdef";
        n.reserve(nonce).unwrap();
        assert!(n.is_reserved(nonce) && !n.is_used(nonce));
        // A second presentation is refused, and says why.
        let e = n.reserve(nonce).unwrap_err();
        assert!(e.contains("presenting it right now"), "{e}");
        // Releasing (a launch that ended before a slot) lets it be presented
        // again, and nothing was written: a restart sees it unused.
        n.release(nonce);
        assert!(!n.is_reserved(nonce));
        assert!(!LaunchNonces::open(dir.path(), 50).unwrap().is_used(nonce));
        n.reserve(nonce).unwrap();
        // Recording ends the reservation and spends the nonce for good: a
        // late release changes nothing, and reserving it again is refused as
        // used.
        n.record(nonce, 100).unwrap();
        assert!(!n.is_reserved(nonce) && n.is_used(nonce));
        n.release(nonce);
        let e = n.reserve(nonce).unwrap_err();
        assert!(e.contains("already used"), "{e}");
        // Releasing a nonce never reserved is harmless.
        n.release("nonce-never-reserved-00");
    }

    #[test]
    fn a_nonce_is_used_once_and_survives_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let mut n = LaunchNonces::open(dir.path(), 10).unwrap();
        n.record("nonce-0123456789abcdef", 100).unwrap();
        assert!(n.record("nonce-0123456789abcdef", 100).is_err());
        let again = LaunchNonces::open(dir.path(), 50).unwrap();
        assert!(again.is_used("nonce-0123456789abcdef"));
        let later = LaunchNonces::open(dir.path(), 100 + KEEP_NONCES_AFTER_EXPIRY_SECS).unwrap();
        assert!(!later.is_used("nonce-0123456789abcdef"));
    }
}
