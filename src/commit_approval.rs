//! Commit approvals: the suite's model layer's way to have a commit signed.
//!
//! Why (docs/caller-identity.md, path 1): the service can't learn who is
//! calling from a field in the request, since any process in the account
//! can write any field. A commit approval is something the caller can't
//! forge: the commitments check approves one commit for one agent and signs
//! the approval with the commitments approval key, whose public half is
//! `[approvals] commitments_key` in agent-sign's own config
//! ([`crate::config::ApprovalsConfig`]). Whoever presents the approval
//! doesn't matter; the approval is what is trusted, so it must bind
//! everything a replay could change (P5).
//!
//! An approval is the JSON text of [`CommitApproval`], signed as an SSHSIG
//! (sha512) in the namespace [`APPROVAL_NAMESPACE`] by a plain `ssh-ed25519`
//! key. The service signs the presented commit as the approval's principal
//! only when [`check`] passes, which is all of:
//! - the signature verifies, by exactly the commitments key, in that
//!   namespace, over exactly the presented text (nothing in the text is read
//!   before that);
//! - the text has exactly [`CommitApproval`]'s fields, each once, and its
//!   kind is "commit";
//! - it names this machine, and a principal `<agent>.<8 hex>@<this
//!   machine's domain>` whose agent name this machine certifies (never a
//!   reserved or person's name: [`crate::attribution::IdentityPolicy`]);
//! - it names the request's working copy (canonical path) and branch;
//! - its `commit_sha256` is the SHA-256 of exactly the bytes the service is
//!   asked to sign: the unsigned commit object, message, names and dates
//!   included (decision D3, the suite PM, 31 Oct 2026: binding only the
//!   tree, parents and emails let whoever presented a captured approval
//!   first sign the approved tree with their own message and dates, under
//!   the approval's attestation). The runner builds the commit object first,
//!   with fixed author and committer dates, hashes it, asks for the
//!   approval, and presents both;
//! - the commit's headers are exactly its `tree`, its `parent`s in order,
//!   one `author` and one `committer`, both with the principal as their
//!   email ([`check_buffer`]: the critique of the build plan, 31 Oct 2026,
//!   found that binding only the committer let whoever presented a captured
//!   approval first sign a commit authored by "Taylor"). The hash already
//!   binds these; the check stays so that an approval the commitments check
//!   made for a malformed commit still signs nothing outside these rules;
//! - it hasn't expired, and its nonce was never used.
//!
//! The service adds what needs its own state: the branch isn't protected,
//! the principal isn't one today's plain path is signing as, the nonce is
//! checked and recorded in one step under the service's lock and synced to
//! disk before the signature is made ([`ApprovalStore`]), and the commit's
//! date is inside the one-off certificate's window. A refused approval is
//! not used up, so presenting a captured approval with other content can't
//! spend it before the real runner does.
//!
//! The field names are the tests' (`commit_sha256` is the builder's choice,
//! D3); when the commitments format is written, they are aligned with it in
//! one labelled change to the tests.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ssh_key::{Algorithm, HashAlg, PublicKey, SshSig};

use crate::attribution::{AgentIdentity, IdentityPolicy};

/// The SSHSIG namespace of a commit approval: a signature the commitments
/// key makes for anything else (a git commit, say) is never an approval.
pub const APPROVAL_NAMESPACE: &str = "agent-sign-commit-approval";

/// The one kind of approval this path signs on.
pub const COMMIT_KIND: &str = "commit";

/// The commitments approval key: the public key whose approvals the service
/// signs on. Only a plain `ssh-ed25519` key; never a certificate, which
/// would make trust depend on whoever issued it.
#[derive(Debug, Clone)]
pub struct CommitmentsKey(PublicKey);

impl CommitmentsKey {
    /// The key in `line`, one OpenSSH public key line (`ssh-ed25519 AAAA...
    /// [comment]`).
    pub fn parse(line: &str) -> Result<Self, String> {
        let line = line.trim();
        if line.contains('\n') || line.contains('\r') {
            return Err("must be one OpenSSH public key line, not several".to_string());
        }
        let key = PublicKey::from_openssh(line)
            .map_err(|e| format!("isn't an OpenSSH public key line ({e})"))?;
        if key.algorithm() != Algorithm::Ed25519 {
            return Err(format!(
                "must be an ssh-ed25519 key, not {}",
                key.algorithm().as_str()
            ));
        }
        Ok(Self(key))
    }

    /// The key's SHA-256 fingerprint, for the service's log.
    pub fn fingerprint(&self) -> String {
        self.0.fingerprint(HashAlg::Sha256).to_string()
    }

    /// Whether `armored` is this key's SSHSIG (sha512, namespace
    /// [`APPROVAL_NAMESPACE`]) over exactly `text`.
    pub fn verify(&self, text: &[u8], armored: &str) -> Result<(), String> {
        self.verify_in(APPROVAL_NAMESPACE, text, armored)
    }

    /// Whether `armored` is this key's SSHSIG (sha512) in `namespace` over
    /// exactly `text`: the same verifier for every kind of approval, so a
    /// launch approval (`crate::launch_approval`, namespace
    /// `agent-sign-launch-approval`) is checked by exactly the code commit
    /// approvals are, and a signature made for one namespace is never good
    /// in another.
    pub fn verify_in(&self, namespace: &str, text: &[u8], armored: &str) -> Result<(), String> {
        if armored.trim().is_empty() {
            return Err("the approval carries no signature".to_string());
        }
        let sig = SshSig::from_pem(armored.trim())
            .map_err(|e| format!("the approval's signature can't be read ({e})"))?;
        if sig.hash_alg() != HashAlg::Sha512 {
            return Err("the approval's signature isn't sha512".to_string());
        }
        self.0.verify(namespace, text, &sig).map_err(|e| match e {
            ssh_key::Error::PublicKey => {
                "the approval isn't signed by the commitments approval key".to_string()
            }
            ssh_key::Error::Namespace => {
                format!("the approval's signature isn't in the {namespace} namespace")
            }
            _ => "the approval's signature doesn't verify over its text".to_string(),
        })
    }
}

/// What one commit approval names. The text must have exactly these fields
/// (a field this version doesn't know, or one given twice, is refused, so
/// an approval never says more than the service checks).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommitApproval {
    /// [`COMMIT_KIND`].
    pub kind: String,
    /// Whom the commit is signed as: `<agent>.<8 hex>@<machine domain>`.
    pub principal: String,
    /// The machine (its `[identity] machine`) whose service may sign it.
    pub machine: String,
    /// The working copy's canonical path.
    pub repo: String,
    /// The branch the commit is made on.
    pub branch: String,
    /// The commit's tree.
    pub tree: String,
    /// The commit's parents, in order.
    pub parents: Vec<String>,
    /// Single use: the service records it and refuses it ever after.
    pub nonce: String,
    /// When the approval stops being good, in seconds since the epoch.
    pub expires_at: u64,
    /// The lowercase hex SHA-256 of the exact unsigned commit object the
    /// approval is for: the bytes git hands its signing program (the commit
    /// without its `gpgsig` header), which are the bytes signed. Required:
    /// an approval without it binds nothing about the commit's message,
    /// names or dates (D3).
    pub commit_sha256: String,
}

/// What the service checks an approval against.
pub struct Context<'a> {
    pub key: &'a CommitmentsKey,
    /// This machine's `[identity] machine`.
    pub machine: &'a str,
    /// Which principals this machine certifies.
    pub policy: &'a IdentityPolicy,
    /// Now, in seconds since the epoch.
    pub now: u64,
}

/// A `SignApproved` request, its repository already canonical.
pub struct Presented<'a> {
    pub text: &'a str,
    pub signature: &'a str,
    pub buffer: &'a [u8],
    pub repo: &'a str,
    pub branch: &'a str,
}

/// An approval that passed [`check`]: what it names, and the SHA-256 of its
/// text (lowercase hex), which the certificate's attestation records.
#[derive(Debug, Clone)]
pub struct Approved {
    pub approval: CommitApproval,
    pub sha256: String,
}

pub(crate) fn is_lower_hex(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Whether `id` is a git object id: 40 (SHA-1) or 64 (SHA-256) lowercase hex.
pub(crate) fn is_object_id(id: &str) -> bool {
    (id.len() == 40 || id.len() == 64) && is_lower_hex(id)
}

/// Whether `nonce` is one the store can keep: 16 to 128 letters, digits,
/// `-` or `_`. Short ones are too easy to repeat by accident.
pub(crate) fn is_nonce(nonce: &str) -> bool {
    (16..=128).contains(&nonce.len())
        && nonce
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// The identity a principal `<agent>.<8 hex>@<domain>` names, if it has
/// that shape. The display name is the agent name: approvals don't carry
/// one, and the commit's author name is the runner's to choose.
fn identity_of(principal: &str) -> Option<AgentIdentity> {
    let (local, _domain) = principal.split_once('@')?;
    let (slug, session) = local.split_once('.')?;
    if session.len() != 8 || !is_lower_hex(session) {
        return None;
    }
    Some(AgentIdentity {
        slug: slug.to_string(),
        name: slug.to_string(),
        principal: principal.to_string(),
    })
}

/// Checks a presented approval and its commit (everything in the module
/// documentation the service doesn't add itself). Returns what it approves.
pub fn check(ctx: &Context<'_>, req: &Presented<'_>) -> Result<Approved, String> {
    let refused = |why: String| Err(format!("approval refused: {why}"));
    // The signature first: nothing in the text is read before it verifies.
    if let Err(why) = ctx.key.verify(req.text.as_bytes(), req.signature) {
        return refused(why);
    }
    let approval: CommitApproval = match serde_json::from_str(req.text) {
        Ok(a) => a,
        Err(e) => return refused(format!("its text isn't a commit approval ({e})")),
    };
    if approval.kind != COMMIT_KIND {
        return refused(format!("its kind is {:?}, not \"commit\"", approval.kind));
    }
    if approval.machine != ctx.machine {
        return refused(format!(
            "it is for machine {:?}, and this is {:?}",
            approval.machine, ctx.machine
        ));
    }
    let Some(identity) = identity_of(&approval.principal) else {
        return refused(format!(
            "its principal {:?} isn't <agent>.<8 hex>@{}",
            approval.principal, ctx.policy.domain
        ));
    };
    if let Err(why) = ctx.policy.check(&identity) {
        return refused(why);
    }
    if !is_nonce(&approval.nonce) {
        return refused("its nonce isn't 16 to 128 letters, digits, '-' or '_'".to_string());
    }
    if ctx.now >= approval.expires_at {
        return refused("it has expired".to_string());
    }
    if approval.repo != req.repo {
        return refused(format!(
            "it is for working copy {:?}, not {:?}",
            approval.repo, req.repo
        ));
    }
    if approval.branch != req.branch {
        return refused(format!(
            "it is for branch {:?}, not {:?}",
            approval.branch, req.branch
        ));
    }
    if let Err(why) = crate::repo_info::check_branch_name(&approval.branch) {
        return refused(why);
    }
    if !is_object_id(&approval.tree) || !approval.parents.iter().all(|p| is_object_id(p)) {
        return refused("its tree and parents must be git object ids".to_string());
    }
    if approval.commit_sha256.len() != 64 || !is_lower_hex(&approval.commit_sha256) {
        return refused("its commit_sha256 isn't a lowercase hex SHA-256".to_string());
    }
    if sha256_hex(req.buffer) != approval.commit_sha256 {
        return refused(
            "the commit presented isn't the one approved (its SHA-256 differs from the \
             approval's commit_sha256: another message, name or date)"
                .to_string(),
        );
    }
    if let Err(why) = check_buffer(req.buffer, &approval) {
        return refused(why);
    }
    let sha256 = sha256_hex(req.text.as_bytes());
    Ok(Approved { approval, sha256 })
}

/// The lowercase hex SHA-256 of `data`.
fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The email of a git ident `Name <email> <time> <zone>`, if it has exactly
/// that shape.
fn ident_email(ident: &str) -> Option<&str> {
    let open = ident.find('<')?;
    let close = open + ident[open..].find('>')?;
    let (name, rest) = (&ident[..open], &ident[close + 1..]);
    if name.contains('>') || rest.contains('<') || rest.contains('>') {
        return None;
    }
    Some(&ident[open + 1..close])
}

/// Whether the commit object `buffer` is exactly what `approval` names: its
/// headers are its `tree`, its `parent`s in order, one `author` and one
/// `committer` whose emails are the principal, and at most an `encoding
/// UTF-8` (the encoding the guardrails also insist on);
/// nothing else (no signature, no merge tag, no continuation lines).
pub fn check_buffer(buffer: &[u8], approval: &CommitApproval) -> Result<(), String> {
    let text = std::str::from_utf8(buffer).map_err(|_| "the commit isn't UTF-8".to_string())?;
    let (headers, _message) = text
        .split_once("\n\n")
        .ok_or("the commit has no message separator")?;
    let mut lines = headers.split('\n').peekable();
    let header = |line: &str| -> Result<(String, String), String> {
        line.split_once(' ')
            .filter(|(name, _)| !name.is_empty())
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .ok_or_else(|| format!("the commit has a header line {line:?} it can't read"))
    };
    let (name, tree) = header(lines.next().unwrap_or_default())?;
    if name != "tree" || tree != approval.tree {
        return Err(format!(
            "the commit's tree isn't the approved tree {}",
            approval.tree
        ));
    }
    let mut parents = Vec::new();
    while let Some(line) = lines.peek() {
        let (name, value) = header(line)?;
        if name != "parent" {
            break;
        }
        parents.push(value);
        lines.next();
    }
    if parents != approval.parents {
        return Err("the commit's parents aren't the approved parents".to_string());
    }
    for role in ["author", "committer"] {
        let (name, ident) = header(lines.next().unwrap_or_default())?;
        if name != role {
            return Err(format!("the commit has no single {role} line"));
        }
        if ident_email(&ident) != Some(approval.principal.as_str()) {
            return Err(format!(
                "the commit's {role} isn't the approved agent {}",
                approval.principal
            ));
        }
    }
    for line in lines {
        let (name, value) = header(line)?;
        if name != "encoding" || value != "UTF-8" {
            return Err(format!(
                "the commit has a `{name}` header, which a commit approval doesn't cover"
            ));
        }
    }
    Ok(())
}

/// How long after an approval expires its nonce is kept: past expiry the
/// approval is refused anyway, so the nonce needn't be; the margin covers a
/// clock set back by up to this much.
pub const KEEP_NONCES_AFTER_EXPIRY_SECS: u64 = 24 * 60 * 60;

/// The folder of the approval path's state in a state directory
/// (`~/.agent-sign/approvals`).
pub fn approvals_dir_in(state_dir: &Path) -> PathBuf {
    state_dir.join("approvals")
}

/// The used nonces, one JSON line each ([`UsedNonce`]).
pub const NONCES_FILE: &str = "nonces";

/// Every principal an approval has been signed for, one per line, never
/// pruned: today's plain path refuses them ([`ApprovalStore::was_approved`]),
/// and the launcher (later) must never draw a session that names one.
pub const PRINCIPALS_FILE: &str = "principals";

/// One used nonce, as [`NONCES_FILE`] keeps it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UsedNonce {
    nonce: String,
    expires_at: u64,
    principal: String,
}

/// The approval path's durable state: the nonces used, and the principals
/// approved. The service holds it under its state lock, and
/// [`ApprovalStore::record`] syncs each new entry to disk before returning,
/// so a nonce is never answered for twice, even across a crash.
#[derive(Debug)]
pub struct ApprovalStore {
    dir: PathBuf,
    nonces: HashMap<String, u64>,
    principals: HashSet<String>,
}

/// The complete lines of `text`: every line ended by a newline. A last line
/// without one is a write a crash cut short, which was never answered for
/// (the service answers only after the sync), so it is dropped.
pub(crate) fn complete_lines(text: &str) -> impl Iterator<Item = &str> {
    let end = text.rfind('\n').map_or(0, |i| i + 1);
    text[..end].lines()
}

/// Writes `content` to `path` through a file beside it, synced, then renamed
/// into place, and syncs the folder, so a crash leaves the old or the new.
pub(crate) fn replace_file(dir: &Path, path: &Path, content: &str) -> std::io::Result<()> {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = dir.join(format!(".{name}.new"));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    file.write_all(content.as_bytes())?;
    file.sync_all()?;
    fs::rename(&tmp, path)?;
    fs::File::open(dir)?.sync_all()
}

/// Appends `line` to `path` and syncs it.
pub(crate) fn append_synced(path: &Path, line: &str) -> std::io::Result<()> {
    let mut file = fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(format!("{line}\n").as_bytes())?;
    file.sync_all()
}

impl ApprovalStore {
    /// The store in `state_dir`'s [`approvals_dir_in`] (made private, 0700,
    /// if new), with nonces expired more than
    /// [`KEEP_NONCES_AFTER_EXPIRY_SECS`] before `now` pruned. A line that
    /// can't be read stops the service: a store it can't trust would let a
    /// used approval sign again.
    pub fn open(state_dir: &Path, now: u64) -> Result<Self, String> {
        let dir = approvals_dir_in(state_dir);
        let err = |what: &str, e: std::io::Error| format!("{}: {what}: {e}", dir.display());
        fs::create_dir_all(&dir).map_err(|e| err("can't be made", e))?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
            .map_err(|e| err("can't be made private", e))?;
        let read = |name: &str| match fs::read_to_string(dir.join(name)) {
            Ok(text) => Ok(text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
            Err(e) => Err(err(name, e)),
        };

        let mut nonces = HashMap::new();
        let mut kept = String::new();
        for line in complete_lines(&read(NONCES_FILE)?) {
            let used: UsedNonce = serde_json::from_str(line).map_err(|e| {
                format!(
                    "{}: a line can't be read ({e})",
                    dir.join(NONCES_FILE).display()
                )
            })?;
            if used
                .expires_at
                .saturating_add(KEEP_NONCES_AFTER_EXPIRY_SECS)
                > now
            {
                kept.push_str(line);
                kept.push('\n');
                nonces.insert(used.nonce, used.expires_at);
            }
        }
        let mut principals = HashSet::new();
        let mut all = String::new();
        for line in complete_lines(&read(PRINCIPALS_FILE)?) {
            if line.is_empty() || line.contains(char::is_whitespace) {
                return Err(format!(
                    "{}: a line isn't a principal",
                    dir.join(PRINCIPALS_FILE).display()
                ));
            }
            if principals.insert(line.to_string()) {
                all.push_str(line);
                all.push('\n');
            }
        }
        replace_file(&dir, &dir.join(NONCES_FILE), &kept).map_err(|e| err(NONCES_FILE, e))?;
        replace_file(&dir, &dir.join(PRINCIPALS_FILE), &all)
            .map_err(|e| err(PRINCIPALS_FILE, e))?;
        Ok(Self {
            dir,
            nonces,
            principals,
        })
    }

    /// Whether an approval with `nonce` has been signed.
    pub fn is_used(&self, nonce: &str) -> bool {
        self.nonces.contains_key(nonce)
    }

    /// Whether an approval has ever been signed for `principal`.
    pub fn was_approved(&self, principal: &str) -> bool {
        self.principals.contains(principal)
    }

    /// Records `nonce` (good until `expires_at`) and `principal` as used,
    /// synced to disk before it returns. Refuses a nonce already used. The
    /// caller holds the service's lock from [`ApprovalStore::is_used`] to
    /// the signature, so the check and the record are one step.
    pub fn record(&mut self, nonce: &str, expires_at: u64, principal: &str) -> Result<(), String> {
        if self.is_used(nonce) {
            return Err("approval refused: it was already used".to_string());
        }
        let line = serde_json::to_string(&UsedNonce {
            nonce: nonce.to_string(),
            expires_at,
            principal: principal.to_string(),
        })
        .map_err(|e| format!("the approval's nonce can't be recorded ({e})"))?;
        let fail = |e: std::io::Error| {
            format!(
                "the approval's nonce can't be recorded in {} ({e}), so it wasn't signed",
                self.dir.display()
            )
        };
        append_synced(&self.dir.join(NONCES_FILE), &line).map_err(fail)?;
        if !self.principals.contains(principal) {
            append_synced(&self.dir.join(PRINCIPALS_FILE), principal).map_err(fail)?;
        }
        self.nonces.insert(nonce.to_string(), expires_at);
        self.principals.insert(principal.to_string());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TREE: &str = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";
    const PARENT: &str = "1111111111111111111111111111111111111111";
    const PRINCIPAL: &str = "claude-code.1a2b3c4d@hetzner.agents.local";

    fn approval() -> CommitApproval {
        CommitApproval {
            kind: "commit".into(),
            principal: PRINCIPAL.into(),
            machine: "hetzner".into(),
            repo: "/w/repo".into(),
            branch: "work".into(),
            tree: TREE.into(),
            parents: vec![PARENT.into()],
            nonce: "0123456789abcdef".into(),
            expires_at: 2_000_000_000,
            commit_sha256: "0".repeat(64),
        }
    }

    fn buffer(author: &str, committer: &str, extra: &str) -> Vec<u8> {
        format!(
            "tree {TREE}\nparent {PARENT}\nauthor {author} 1 +0000\ncommitter {committer} 1 +0000\n{extra}\nmessage\n"
        )
        .into_bytes()
    }

    #[test]
    fn the_commit_must_be_exactly_what_was_approved() {
        let me = format!("Claude Code <{PRINCIPAL}>");
        let a = approval();
        assert!(check_buffer(&buffer(&me, &me, ""), &a).is_ok());
        let person = "Taylor <taylor@example.com>";
        for (what, buf) in [
            ("another author", buffer(person, &me, "")),
            ("another committer", buffer(&me, person, "")),
            ("a signature", buffer(&me, &me, "gpgsig x\n y\n")),
            (
                "two parents",
                format!("tree {TREE}\nparent {PARENT}\nparent {PARENT}\nauthor {me} 1 +0000\ncommitter {me} 1 +0000\n\nm\n")
                    .into_bytes(),
            ),
            (
                "no parent",
                format!("tree {TREE}\nauthor {me} 1 +0000\ncommitter {me} 1 +0000\n\nm\n").into_bytes(),
            ),
            (
                "a carriage return",
                format!("tree {TREE}\r\nparent {PARENT}\nauthor {me} 1 +0000\ncommitter {me} 1 +0000\n\nm\n")
                    .into_bytes(),
            ),
            (
                "an email in the name",
                buffer(&format!("x <{PRINCIPAL}> <a@b>"), &me, ""),
            ),
        ] {
            assert!(check_buffer(&buf, &a).is_err(), "{what}");
        }
        assert!(check_buffer(&buffer(&me, &me, "encoding UTF-8\n"), &a).is_ok());
        assert!(check_buffer(&buffer(&me, &me, "encoding ISO-8859-1\n"), &a).is_err());
    }

    #[test]
    fn an_approval_text_has_exactly_its_fields() {
        let text = serde_json::to_string(&approval()).unwrap();
        assert!(serde_json::from_str::<CommitApproval>(&text).is_ok());
        let extra = text.replace("\"kind\"", "\"extra\":1,\"kind\"");
        assert!(serde_json::from_str::<CommitApproval>(&extra).is_err());
        let twice = text.replace("\"kind\"", "\"nonce\":\"aaaaaaaaaaaaaaaaaa\",\"kind\"");
        assert!(serde_json::from_str::<CommitApproval>(&twice).is_err());
    }

    #[test]
    fn principals_must_name_an_agent_and_a_session() {
        assert!(identity_of(PRINCIPAL).is_some());
        for bad in [
            "claude-code.nosession@hetzner.agents.local",
            "claude-code.1A2B3C4D@hetzner.agents.local",
            "claude-code.1a2b3c4@hetzner.agents.local",
            "claude-code@hetzner.agents.local",
            "claude-code.1a2b3c4d",
        ] {
            assert!(identity_of(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn a_nonce_is_used_once_and_survives_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = ApprovalStore::open(dir.path(), 1_000).unwrap();
        assert!(!store.is_used("n-0123456789abcdef"));
        store
            .record("n-0123456789abcdef", 2_000, PRINCIPAL)
            .unwrap();
        assert!(
            store
                .record("n-0123456789abcdef", 2_000, PRINCIPAL)
                .is_err()
        );
        let again = ApprovalStore::open(dir.path(), 1_500).unwrap();
        assert!(again.is_used("n-0123456789abcdef"));
        assert!(again.was_approved(PRINCIPAL));
        // Long expired: the nonce goes, the principal stays.
        let later = ApprovalStore::open(dir.path(), 2_000 + KEEP_NONCES_AFTER_EXPIRY_SECS).unwrap();
        assert!(!later.is_used("n-0123456789abcdef"));
        assert!(later.was_approved(PRINCIPAL));
        let mode = fs::metadata(approvals_dir_in(dir.path()))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn a_torn_last_line_is_dropped_and_a_bad_line_stops_the_store() {
        let dir = tempfile::tempdir().unwrap();
        let approvals = approvals_dir_in(dir.path());
        fs::create_dir_all(&approvals).unwrap();
        fs::write(
            approvals.join(NONCES_FILE),
            "{\"nonce\":\"n-0123456789abcdef\",\"expires_at\":9,\"principal\":\"p\"}\n{\"nonce\":\"n-torn",
        )
        .unwrap();
        let store = ApprovalStore::open(dir.path(), 1).unwrap();
        assert!(store.is_used("n-0123456789abcdef"));
        assert_eq!(
            fs::read_to_string(approvals.join(NONCES_FILE))
                .unwrap()
                .lines()
                .count(),
            1
        );
        fs::write(approvals.join(NONCES_FILE), "not json\n").unwrap();
        assert!(ApprovalStore::open(dir.path(), 1).is_err());
    }
}
