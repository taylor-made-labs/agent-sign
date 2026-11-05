//! Signed acts: agent-sign signs, and checks, the exact bytes of an act.
//!
//! Why (EVALS.md, "signed acts v0"): role-commitments decides "may X do E"
//! and lists empty seats from signed acts, but until something could sign an
//! act, no real role assignment existed and every seat read empty. This
//! module is that something, and nothing more: it knows identities and
//! signatures, never roles (a lower layer never names an upper one).
//!
//! Three kinds of signer, one verifier:
//! - **an agent** signs as the identity its launcher gave it
//!   (`agent-sign launch --identity agent:<name>`). The service signs with
//!   the session's in-memory key; the member carries the session's
//!   certificate from the agents' certificate authority, whose principal is
//!   the identity. The identity is never read from anything the session
//!   says: the service keeps it with the session it launched.
//! - **an assigner** signs with a key agent-sign never holds in a file:
//!   Taylor's key stays in his own ssh-agent ([`agent_sign_with`]), the
//!   launcher's key lives in the service's memory ([`LauncherKey`]; OpenBao
//!   is the planned second home).
//! - **the verifier** ([`verify_member`]) decides who signed from the trust
//!   file and the certificate alone ([`TrustFile`]), never from text in the
//!   signature member.
//!
//! Domain separation is the SSH signature namespace: an act is
//! `agent-sign/act/1`, a credential `agent-sign/credential/1`, a git commit
//! `git`. A signature in one is never accepted as another.
//!
//! The signature member is one JSON object `{schema, signature,
//! certificate}`. The armored SSHSIG inside carries the signer's plain
//! ed25519 key (so plain `ssh-keygen -Y verify` can read it too); the
//! certificate, when there is one, travels beside it and must be for that
//! same key.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256, Sha512};
use ssh_key::Certificate;
use ssh_key::certificate::CertType;

/// The SSH-signature namespace of an act.
pub const ACT_NAMESPACE: &str = "agent-sign/act/1";
/// The namespace of a session credential.
pub const CREDENTIAL_NAMESPACE: &str = "agent-sign/credential/1";
/// The first line of an acts trust file.
pub const TRUST_HEADER: &str = "agent-sign/acts-trust/1";
/// The `schema` of a signature member.
pub const MEMBER_SCHEMA: &str = "agent-sign/act-signature/1";
/// The `schema` of a credential.
pub const CREDENTIAL_SCHEMA: &str = "agent-sign/act-credential/1";
/// The fewest and most bytes an act may be.
pub const MIN_PAYLOAD: usize = 1;
/// See [`MIN_PAYLOAD`].
pub const MAX_PAYLOAD: usize = 65536;
/// A credential is good for this long after `issued_at`.
pub const CREDENTIAL_MAX_AGE_SECS: u64 = 300;
/// A credential dated further ahead than this is refused (clock skew only).
pub const CREDENTIAL_MAX_AHEAD_SECS: u64 = 60;
/// The most `verify` reads from standard input, and a trust file's size limit.
pub const MAX_INPUT_BYTES: usize = 256 * 1024;
const MAX_TRUST_BYTES: usize = 64 * 1024;
const MAX_ARMOR_CHARS: usize = 8 * 1024;
const MAX_CERT_CHARS: usize = 8 * 1024;
/// The launcher's identity, as an assigner.
pub const LAUNCHER_ASSIGNER: &str = "harness:launcher";

// ---------------------------------------------------------------------------------------------------------------
// identities
// ---------------------------------------------------------------------------------------------------------------

/// Whether `name` is a plain name: 1 to 64 of a-z, 0-9, `.`, `_`, `-`,
/// starting with a letter or digit.
fn name_ok(name: &str) -> bool {
    let mut chars = name.chars();
    let first_ok = chars
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    first_ok
        && name.len() <= 64
        && chars.all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '_' || c == '-'
        })
}

/// Checks an agent identity `agent:<name>`, as `--identity` takes it.
/// `person:` and `harness:` names are reserved for assigners and are
/// refused here.
pub fn check_agent_identity(identity: &str) -> Result<(), String> {
    match identity.strip_prefix("agent:") {
        Some(name) if name_ok(name) => Ok(()),
        Some(_) => Err(format!(
            "{identity:?} isn't an agent identity: after `agent:` use 1 to 64 of a-z, 0-9, `.`, `_`, `-`, starting with a letter or digit"
        )),
        None => Err(format!(
            "{identity:?} isn't an agent identity: it must be `agent:<name>` (`person:` and `harness:` are for assigners and can't be launched)"
        )),
    }
}

fn is_assigner_identity(identity: &str) -> bool {
    ["person:", "harness:"]
        .iter()
        .any(|p| identity.strip_prefix(p).is_some_and(name_ok))
}

fn is_any_identity(identity: &str) -> bool {
    check_agent_identity(identity).is_ok() || is_assigner_identity(identity)
}

// ---------------------------------------------------------------------------------------------------------------
// wire helpers and SSHSIG
// ---------------------------------------------------------------------------------------------------------------

fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn read_string<'a>(bytes: &'a [u8], at: &mut usize) -> Option<&'a [u8]> {
    let len = u32::from_be_bytes(bytes.get(*at..*at + 4)?.try_into().ok()?) as usize;
    let start = *at + 4;
    let out = bytes.get(start..start.checked_add(len)?)?;
    *at = start + len;
    Some(out)
}

/// The 32 key bytes of a plain `ssh-ed25519` wire blob, and nothing else.
fn plain_key(blob: &[u8]) -> Option<[u8; 32]> {
    let mut at = 0;
    if read_string(blob, &mut at)? != b"ssh-ed25519" {
        return None;
    }
    let key = read_string(blob, &mut at)?;
    (at == blob.len()).then_some(())?;
    key.try_into().ok()
}

/// A public key from `ssh-ed25519 <base64>`, the parts of an OpenSSH line.
fn parse_key(alg: &str, b64: &str) -> Result<[u8; 32], String> {
    if alg != "ssh-ed25519" {
        return Err(format!("{alg:?} isn't an ssh-ed25519 key"));
    }
    let blob = STANDARD
        .decode(b64)
        .map_err(|_| "the key isn't canonical base64".to_string())?;
    let key = plain_key(&blob).ok_or("the key isn't a plain ssh-ed25519 public key")?;
    VerifyingKey::from_bytes(&key).map_err(|_| "the key isn't a valid ed25519 key".to_string())?;
    Ok(key)
}

/// The OpenSSH public key line of an ed25519 key.
pub fn public_line(key: &VerifyingKey) -> String {
    crate::crypto::openssh_ed25519_line(key)
}

/// An armored SSHSIG made by `key` over `payload` in `namespace`, carrying
/// the plain public key.
pub fn sign_plain(key: &SigningKey, namespace: &str, payload: &[u8]) -> String {
    crate::crypto::sshsig_armored_in(
        &crate::crypto::ed25519_wire(&key.verifying_key()),
        key,
        namespace.as_bytes(),
        payload,
    )
}

/// What an armored SSHSIG says, read strictly.
struct ParsedSig {
    public_key_blob: Vec<u8>,
    namespace: Vec<u8>,
    hash_alg: Vec<u8>,
    signature: [u8; 64],
}

fn parse_armored(armored: &str) -> Result<ParsedSig, String> {
    if armored.len() > MAX_ARMOR_CHARS {
        return Err("the signature is too long".into());
    }
    let lines: Vec<&str> = armored.lines().collect();
    if lines.len() < 3
        || lines[0] != "-----BEGIN SSH SIGNATURE-----"
        || lines[lines.len() - 1] != "-----END SSH SIGNATURE-----"
    {
        return Err("not an armored SSH signature".into());
    }
    let body: String = lines[1..lines.len() - 1].concat();
    let raw = STANDARD
        .decode(body)
        .map_err(|_| "the signature isn't canonical base64".to_string())?;
    let rest = raw
        .strip_prefix(b"SSHSIG")
        .ok_or("not an SSH signature (no SSHSIG magic)")?;
    let version = rest.get(..4).ok_or("the signature is cut short")?;
    if version != 1u32.to_be_bytes() {
        return Err("an SSH signature of an unknown version".into());
    }
    let mut at = 4;
    let cut = || "the signature is cut short".to_string();
    let public_key_blob = read_string(rest, &mut at).ok_or_else(cut)?.to_vec();
    let namespace = read_string(rest, &mut at).ok_or_else(cut)?.to_vec();
    let _reserved = read_string(rest, &mut at).ok_or_else(cut)?;
    let hash_alg = read_string(rest, &mut at).ok_or_else(cut)?.to_vec();
    let sig_blob = read_string(rest, &mut at).ok_or_else(cut)?;
    if at != rest.len() {
        return Err("bytes after the signature".into());
    }
    let mut sat = 0;
    if read_string(sig_blob, &mut sat) != Some(b"ssh-ed25519") {
        return Err("not an ed25519 signature".into());
    }
    let sig = read_string(sig_blob, &mut sat).ok_or_else(cut)?;
    if sat != sig_blob.len() {
        return Err("bytes after the ed25519 signature".into());
    }
    Ok(ParsedSig {
        public_key_blob,
        namespace,
        hash_alg,
        signature: sig
            .try_into()
            .map_err(|_| "an ed25519 signature that isn't 64 bytes".to_string())?,
    })
}

/// Whether the SSHSIG `sig` is a good signature by `key` over `payload`.
fn sshsig_good(sig: &ParsedSig, key: &[u8; 32], payload: &[u8]) -> bool {
    let digest: Vec<u8> = match sig.hash_alg.as_slice() {
        b"sha512" => Sha512::digest(payload).to_vec(),
        b"sha256" => Sha256::digest(payload).to_vec(),
        _ => return false,
    };
    let mut signed = b"SSHSIG".to_vec();
    put_string(&mut signed, &sig.namespace);
    put_string(&mut signed, b"");
    put_string(&mut signed, &sig.hash_alg);
    put_string(&mut signed, &digest);
    let Ok(key) = VerifyingKey::from_bytes(key) else {
        return false;
    };
    key.verify_strict(&signed, &Signature::from_bytes(&sig.signature))
        .is_ok()
}

// ---------------------------------------------------------------------------------------------------------------
// the trust file
// ---------------------------------------------------------------------------------------------------------------

/// A parsed acts trust file (`agent-sign/acts-trust/1`): who may vouch for
/// agents, which keys are assigners, and which identities are revoked. One
/// file, one digest: a verdict names the digest of the bytes it was made
/// under.
#[derive(Debug, Default)]
pub struct TrustFile {
    /// Certificate authorities for agents' sessions: domain and key.
    pub authorities: Vec<(String, [u8; 32])>,
    /// Assigner identities (`person:..`, `harness:..`) and their keys.
    pub assigners: Vec<(String, [u8; 32])>,
    /// Revoked identities of any kind.
    pub revoked: Vec<String>,
}

impl TrustFile {
    /// Reads a trust file. Refused whole on a wrong first line, an unknown
    /// word, a malformed line, one key for two identities, or one key
    /// listed under two kinds.
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut lines = text
            .lines()
            .map(str::trim)
            .enumerate()
            .filter(|(_, l)| !l.is_empty() && !l.starts_with('#'));
        match lines.next() {
            Some((_, l)) if l == TRUST_HEADER => {}
            Some((n, _)) => {
                return Err(format!(
                    "line {}: the first line must be `{TRUST_HEADER}`",
                    n + 1
                ));
            }
            None => return Err(format!("empty: the first line must be `{TRUST_HEADER}`")),
        }
        let mut trust = TrustFile::default();
        // Which kind and identity each key was listed under.
        let mut seen: HashMap<[u8; 32], (&'static str, String)> = HashMap::new();
        for (n, line) in lines {
            let at = |why: String| format!("line {}: {why}", n + 1);
            let t: Vec<&str> = line.split_whitespace().collect();
            match t[0] {
                "authority" => {
                    if t.len() < 4 {
                        return Err(at("expected `authority <domain> <public key line>`".into()));
                    }
                    let domain = t[1];
                    if domain.len() > 253
                        || !domain
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
                    {
                        return Err(at(format!("{domain:?} isn't a domain")));
                    }
                    let key = parse_key(t[2], t[3]).map_err(&at)?;
                    claim(&mut seen, key, "authority", domain).map_err(&at)?;
                    if !trust
                        .authorities
                        .iter()
                        .any(|(d, k)| d == domain && *k == key)
                    {
                        trust.authorities.push((domain.to_string(), key));
                    }
                }
                "assigner" => {
                    if t.len() < 4 {
                        return Err(at("expected `assigner <identity> <public key line>`".into()));
                    }
                    if !is_assigner_identity(t[1]) {
                        return Err(at(format!(
                            "{:?} isn't an assigner identity (`person:<name>` or `harness:<name>`)",
                            t[1]
                        )));
                    }
                    let key = parse_key(t[2], t[3]).map_err(&at)?;
                    claim(&mut seen, key, "assigner", t[1]).map_err(&at)?;
                    if !trust.assigners.iter().any(|(i, k)| i == t[1] && *k == key) {
                        trust.assigners.push((t[1].to_string(), key));
                    }
                }
                "revoked" => {
                    if t.len() != 2 || !is_any_identity(t[1]) {
                        return Err(at("expected `revoked <identity>`".into()));
                    }
                    if !trust.revoked.iter().any(|r| r == t[1]) {
                        trust.revoked.push(t[1].to_string());
                    }
                }
                other => return Err(at(format!("unknown word {other:?}"))),
            }
        }
        Ok(trust)
    }

    fn is_revoked(&self, identity: &str) -> bool {
        self.revoked.iter().any(|r| r == identity)
    }

    /// The keys listed for an assigner identity.
    pub fn assigner_keys(&self, identity: &str) -> Vec<[u8; 32]> {
        self.assigners
            .iter()
            .filter(|(i, _)| i == identity)
            .map(|(_, k)| *k)
            .collect()
    }
}

fn claim(
    seen: &mut HashMap<[u8; 32], (&'static str, String)>,
    key: [u8; 32],
    kind: &'static str,
    who: &str,
) -> Result<(), String> {
    match seen.get(&key) {
        Some((k, w)) if *k == kind && w == who => Ok(()),
        Some((k, w)) => Err(format!(
            "this key is already listed as {k} {w:?}, so it can't also be {kind} {who:?}"
        )),
        None => {
            seen.insert(key, (kind, who.to_string()));
            Ok(())
        }
    }
}

/// Reads and parses the trust file at the absolute `path`. `Err` is a
/// finished verdict: `no_trust_file` for a missing or relative one, `error`
/// for one that can't be read or parsed.
pub fn load_trust(path: &Path) -> Result<(TrustFile, String), Verdict> {
    if !path.is_absolute() {
        return Err(Verdict::cannot_run(
            "no_trust_file",
            format!("the trust file path {} isn't absolute", path.display()),
            None,
        ));
    }
    let bytes = match std::fs::File::open(path) {
        Ok(f) => {
            let mut v = Vec::new();
            f.take(MAX_TRUST_BYTES as u64 + 1)
                .read_to_end(&mut v)
                .map_err(|e| {
                    Verdict::cannot_run(
                        "error",
                        format!("couldn't read the trust file ({e})"),
                        None,
                    )
                })?;
            v
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(Verdict::cannot_run(
                "no_trust_file",
                format!("there is no trust file at {}", path.display()),
                None,
            ));
        }
        Err(e) => {
            return Err(Verdict::cannot_run(
                "error",
                format!("couldn't open the trust file ({e})"),
                None,
            ));
        }
    };
    let digest = hex(&Sha256::digest(&bytes));
    if bytes.len() > MAX_TRUST_BYTES {
        return Err(Verdict::cannot_run(
            "error",
            "the trust file is too long".into(),
            Some(digest),
        ));
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| {
        Verdict::cannot_run(
            "error",
            "the trust file isn't text".into(),
            Some(digest.clone()),
        )
    })?;
    match TrustFile::parse(text) {
        Ok(trust) => Ok((trust, digest)),
        Err(why) => Err(Verdict::cannot_run(
            "error",
            format!("the trust file is refused: {why}"),
            Some(digest),
        )),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------------------------------------------
// the signature member, the envelope, the verdict
// ---------------------------------------------------------------------------------------------------------------

/// The `certificate` key of a member: present always, a string or null.
/// (A plain `Option` would let a missing key read as null.)
#[derive(Debug)]
pub struct CertField(pub Option<String>);

impl<'de> Deserialize<'de> for CertField {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl serde::de::Visitor<'_> for V {
            type Value = CertField;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a certificate line or null")
            }
            fn visit_unit<E>(self) -> Result<CertField, E> {
                Ok(CertField(None))
            }
            fn visit_none<E>(self) -> Result<CertField, E> {
                Ok(CertField(None))
            }
            fn visit_str<E>(self, v: &str) -> Result<CertField, E> {
                Ok(CertField(Some(v.to_string())))
            }
        }
        d.deserialize_any(V)
    }
}

/// A signature member: exactly `schema`, `signature` and `certificate`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Member {
    pub schema: String,
    pub signature: String,
    pub certificate: CertField,
}

/// What `act verify` reads: exactly `payload_b64` and `signature`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub payload_b64: String,
    pub signature: Member,
}

/// What `act verify-credential` reads.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    pub schema: String,
    pub issued_at: u64,
    pub signature: Member,
}

/// A signature member as JSON.
pub fn member_json(armored: &str, certificate: Option<&str>) -> Value {
    json!({"schema": MEMBER_SCHEMA, "signature": armored, "certificate": certificate})
}

/// The bytes a credential signs.
pub fn credential_bytes(issued_at: u64) -> Vec<u8> {
    format!("{CREDENTIAL_NAMESPACE}\n{issued_at}").into_bytes()
}

/// The answer of a check. `reason` is one of `ok, bad_signature,
/// wrong_namespace, untrusted_key, untrusted_authority, outside_window,
/// revoked, no_act_identity, malformed, stale, no_trust_file, error`.
#[derive(Debug)]
pub struct Verdict {
    pub verified: bool,
    pub signer: Option<String>,
    pub kind: Option<&'static str>,
    pub reason: &'static str,
    pub detail: String,
    pub trust_sha256: Option<String>,
}

impl Verdict {
    fn cannot_run(reason: &'static str, detail: String, digest: Option<String>) -> Self {
        Verdict {
            verified: false,
            signer: None,
            kind: None,
            reason,
            detail,
            trust_sha256: digest,
        }
    }

    /// Exit code: 0 only when verified, 1 for any other verdict about a
    /// signature, 2 when the check could not run.
    pub fn exit_code(&self) -> u8 {
        match (self.verified, self.reason) {
            (true, _) => 0,
            (false, "no_trust_file" | "error") => 2,
            (false, _) => 1,
        }
    }

    /// The one JSON object printed.
    pub fn to_json(&self) -> Value {
        json!({
            "verified": self.verified,
            "signer": self.signer,
            "kind": self.kind,
            "reason": self.reason,
            "detail": self.detail,
            "trust_sha256": self.trust_sha256,
        })
    }

    fn refused(reason: &'static str, detail: impl Into<String>, digest: &str) -> Self {
        Verdict {
            verified: false,
            signer: None,
            kind: None,
            reason,
            detail: detail.into(),
            trust_sha256: Some(digest.to_string()),
        }
    }

    fn ok(signer: String, kind: &'static str, digest: &str) -> Self {
        Verdict {
            verified: true,
            detail: format!("signed by the {kind} {signer}"),
            signer: Some(signer),
            kind: Some(kind),
            reason: "ok",
            trust_sha256: Some(digest.to_string()),
        }
    }
}

/// Who signed, and as which kind.
type Signer = (String, &'static str);
type Refusal = (&'static str, String);

/// Checks one signature member over `payload` in `namespace` against
/// `trust`, at time `now`. The signer is read from the trust file (an
/// assigner's key) or from the certificate of a trusted authority (an
/// agent's principal), never from any other text of the member.
fn check_member(
    trust: &TrustFile,
    namespace: &str,
    payload: &[u8],
    member: &Member,
    now: u64,
) -> Result<Signer, Refusal> {
    let malformed = |why: String| ("malformed", why);
    if member.schema != MEMBER_SCHEMA {
        return Err(malformed("an unknown signature member schema".into()));
    }
    let sig = parse_armored(&member.signature).map_err(malformed)?;
    if sig.namespace != namespace.as_bytes() {
        return Err((
            "wrong_namespace",
            format!("the signature is not in the namespace {namespace}"),
        ));
    }
    let key = plain_key(&sig.public_key_blob).ok_or_else(|| {
        malformed("the signature carries something other than a plain ed25519 key".into())
    })?;
    if !sshsig_good(&sig, &key, payload) {
        return Err((
            "bad_signature",
            "the signature does not match these bytes".into(),
        ));
    }
    let Some(line) = &member.certificate.0 else {
        // An assigner: known by its key in the trust file, and by nothing else.
        return match trust.assigners.iter().find(|(_, k)| *k == key) {
            Some((id, _)) if trust.is_revoked(id) => {
                Err(("revoked", format!("{id} is revoked in the trust file")))
            }
            Some((id, _)) => Ok((id.clone(), "assigner")),
            None => Err((
                "untrusted_key",
                "the key is not listed as an assigner and the signature has no certificate".into(),
            )),
        };
    };
    if line.len() > MAX_CERT_CHARS {
        return Err(malformed("the certificate is too long".into()));
    }
    let cert =
        Certificate::from_openssh(line).map_err(|_| malformed("unreadable certificate".into()))?;
    let subject = cert.public_key().ed25519().map(|k| k.0);
    if subject != Some(key) {
        return Err((
            "bad_signature",
            "the certificate is not for the key that signed".into(),
        ));
    }
    let ca = cert.signature_key().ed25519().map(|k| k.0);
    if !ca.is_some_and(|ca| trust.authorities.iter().any(|(_, k)| *k == ca)) {
        return Err((
            "untrusted_authority",
            "the certificate is from an authority the trust file does not name".into(),
        ));
    }
    if cert.verify_signature().is_err() {
        return Err((
            "bad_signature",
            "the certificate's own signature is not good".into(),
        ));
    }
    let principals = cert.valid_principals();
    let identity = match principals {
        [one]
            if cert.cert_type() == CertType::User
                && check_agent_identity(one).is_ok()
                && cert.critical_options().is_empty() =>
        {
            one.clone()
        }
        _ => {
            return Err((
                "no_act_identity",
                "the certificate does not name exactly one agent identity".into(),
            ));
        }
    };
    if trust.is_revoked(&identity) {
        return Err((
            "revoked",
            format!("{identity} is revoked in the trust file"),
        ));
    }
    if now < cert.valid_after() || now >= cert.valid_before() {
        return Err((
            "outside_window",
            "the certificate is not valid at this time".into(),
        ));
    }
    Ok((identity, "agent"))
}

/// Verifies an act: a signature member over `payload`.
pub fn verify_act(
    trust: &TrustFile,
    digest: &str,
    payload: &[u8],
    member: &Member,
    now: u64,
) -> Verdict {
    match check_member(trust, ACT_NAMESPACE, payload, member, now) {
        Ok((signer, kind)) => Verdict::ok(signer, kind, digest),
        Err((reason, detail)) => Verdict::refused(reason, detail, digest),
    }
}

/// Verifies a session credential: fresh (at most [`CREDENTIAL_MAX_AGE_SECS`]
/// old, at most [`CREDENTIAL_MAX_AHEAD_SECS`] ahead) and an agent's.
pub fn verify_credential(
    trust: &TrustFile,
    digest: &str,
    credential: &Credential,
    now: u64,
) -> Verdict {
    if credential.schema != CREDENTIAL_SCHEMA {
        return Verdict::refused("malformed", "an unknown credential schema", digest);
    }
    let bytes = credential_bytes(credential.issued_at);
    match check_member(
        trust,
        CREDENTIAL_NAMESPACE,
        &bytes,
        &credential.signature,
        now,
    ) {
        Ok((_, "assigner")) => {
            Verdict::refused("no_act_identity", "only agents have credentials", digest)
        }
        Ok((signer, kind)) => {
            let issued = credential.issued_at;
            if now > issued.saturating_add(CREDENTIAL_MAX_AGE_SECS)
                || issued > now.saturating_add(CREDENTIAL_MAX_AHEAD_SECS)
            {
                Verdict::refused("stale", "the credential is not fresh", digest)
            } else {
                Verdict::ok(signer, kind, digest)
            }
        }
        Err((reason, detail)) => Verdict::refused(reason, detail, digest),
    }
}

/// Decodes an envelope's payload: canonical base64, 1 to 65536 bytes.
pub fn decode_payload(b64: &str) -> Result<Vec<u8>, String> {
    if b64.len() > MAX_PAYLOAD / 3 * 4 + 8 {
        return Err("the payload is too long".into());
    }
    let bytes = STANDARD
        .decode(b64)
        .map_err(|_| "payload_b64 isn't canonical base64".to_string())?;
    check_payload_len(bytes.len())?;
    Ok(bytes)
}

/// A payload must be [`MIN_PAYLOAD`] to [`MAX_PAYLOAD`] bytes.
pub fn check_payload_len(len: usize) -> Result<(), String> {
    if (MIN_PAYLOAD..=MAX_PAYLOAD).contains(&len) {
        Ok(())
    } else {
        Err(format!(
            "an act is {MIN_PAYLOAD} to {MAX_PAYLOAD} bytes, and this is {len}"
        ))
    }
}

// ---------------------------------------------------------------------------------------------------------------
// the launcher's key
// ---------------------------------------------------------------------------------------------------------------

/// The launcher's assigner key, held in the service's memory only and made
/// anew at each start (`[acts] launcher_assigner = "memory"`). It is zeroed
/// when dropped. Whoever can ask the service's socket (in one-account mode,
/// any process of the service's account outside a session) can have it sign:
/// it vouches for the machine's launcher, not for a person.
pub struct LauncherKey(SigningKey);

impl LauncherKey {
    /// A new random key.
    pub fn generate() -> Self {
        Self(SigningKey::generate(&mut OsRng))
    }

    /// The key as an OpenSSH public key line.
    pub fn public_line(&self) -> String {
        public_line(&self.0.verifying_key())
    }

    /// An armored act signature over `payload`.
    pub fn sign(&self, payload: &[u8]) -> String {
        sign_plain(&self.0, ACT_NAMESPACE, payload)
    }
}

/// The lines `act trust-lines` prints for a service: its authority and, when
/// it has one, the launcher's assigner key.
pub fn trust_lines(
    domain: &str,
    authority_line: &str,
    launcher: Option<&LauncherKey>,
) -> Vec<String> {
    let mut lines = vec![format!("authority {domain} {authority_line}")];
    if let Some(l) = launcher {
        lines.push(format!("assigner {LAUNCHER_ASSIGNER} {}", l.public_line()));
    }
    lines
}

// ---------------------------------------------------------------------------------------------------------------
// signing through the user's own ssh-agent
// ---------------------------------------------------------------------------------------------------------------

/// Asks the ssh-agent at `socket` to sign `payload` in the act namespace
/// with the key `key` (Taylor's device key stays in his agent or device),
/// and checks the answer against `key` before using it. Returns the armored
/// signature.
pub fn agent_sign_with(socket: &Path, key: &[u8; 32], payload: &[u8]) -> Result<String, String> {
    let verifying = VerifyingKey::from_bytes(key).map_err(|_| "a bad key".to_string())?;
    let blob = crate::crypto::ed25519_wire(&verifying);
    let data = crate::crypto::sshsig_signed_data(ACT_NAMESPACE.as_bytes(), payload);
    let mut body = vec![13u8]; // SSH_AGENTC_SIGN_REQUEST
    put_string(&mut body, &blob);
    put_string(&mut body, &data);
    body.extend_from_slice(&0u32.to_be_bytes());
    let mut stream = UnixStream::connect(socket)
        .map_err(|e| format!("couldn't reach the ssh-agent at {} ({e})", socket.display()))?;
    let wait = Some(Duration::from_secs(60));
    let _ = stream.set_read_timeout(wait);
    let _ = stream.set_write_timeout(wait);
    let mut request = (body.len() as u32).to_be_bytes().to_vec();
    request.extend_from_slice(&body);
    stream
        .write_all(&request)
        .map_err(|e| format!("couldn't ask the ssh-agent ({e})"))?;
    let mut len = [0u8; 4];
    stream
        .read_exact(&mut len)
        .map_err(|e| format!("the ssh-agent didn't answer ({e})"))?;
    let len = u32::from_be_bytes(len) as usize;
    if !(1..=64 * 1024).contains(&len) {
        return Err("the ssh-agent's answer is not sensible".into());
    }
    let mut reply = vec![0u8; len];
    stream
        .read_exact(&mut reply)
        .map_err(|e| format!("the ssh-agent's answer was cut short ({e})"))?;
    if reply[0] != 14 {
        return Err("the ssh-agent refused to sign with that key".into());
    }
    let mut at = 1;
    let sig_blob = read_string(&reply, &mut at).ok_or("the ssh-agent's signature is cut short")?;
    let mut sat = 0;
    if read_string(sig_blob, &mut sat) != Some(b"ssh-ed25519") {
        return Err("the ssh-agent signed with something other than ed25519".into());
    }
    let sig: [u8; 64] = read_string(sig_blob, &mut sat)
        .and_then(|s| s.try_into().ok())
        .ok_or("the ssh-agent's signature isn't 64 bytes")?;
    verifying
        .verify_strict(&data, &Signature::from_bytes(&sig))
        .map_err(|_| "the ssh-agent's signature doesn't verify under that key".to_string())?;
    Ok(crate::crypto::armor(&crate::crypto::sshsig_assemble(
        &blob,
        ACT_NAMESPACE.as_bytes(),
        &sig,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agents_ca::{AgentsCa, SessionSigner, now_secs};

    fn trust_with(ca: &AgentsCa, extra: &str) -> TrustFile {
        use crate::agents_ca::CertificateIssuer;
        TrustFile::parse(&format!(
            "{TRUST_HEADER}\nauthority agents.local {}\n{extra}",
            ca.public_key_openssh()
        ))
        .unwrap()
    }

    fn member_of(armored: String, cert: Option<String>) -> Member {
        Member {
            schema: MEMBER_SCHEMA.into(),
            signature: armored,
            certificate: CertField(cert),
        }
    }

    #[test]
    fn identities_are_agent_names_only() {
        for good in ["agent:builder-1", "agent:a", "agent:x.y_z"] {
            assert!(check_agent_identity(good).is_ok(), "{good}");
        }
        for bad in [
            "person:taylor",
            "harness:launcher",
            "taylor",
            "agent:",
            "agent:Builder",
            "agent:a b",
            "agent:x\ny",
            "agent:../x",
            "agent:-x",
        ] {
            assert!(check_agent_identity(bad).is_err(), "{bad:?}");
        }
        assert!(check_agent_identity(&format!("agent:{}", "a".repeat(65))).is_err());
    }

    #[test]
    fn an_agent_signature_names_the_certificates_principal() {
        let ca = AgentsCa::generate("host");
        let signer = SessionSigner::new(&ca, "agent:builder-1", now_secs()).unwrap();
        let sig = signer.act_signature(ACT_NAMESPACE, b"hello");
        let member = member_of(sig, Some(signer.certificate_line()));
        let trust = trust_with(&ca, "");
        let v = verify_act(&trust, "d", b"hello", &member, now_secs());
        assert!(v.verified, "{v:?}");
        assert_eq!(v.signer.as_deref(), Some("agent:builder-1"));
        let v = verify_act(&trust, "d", b"hellp", &member, now_secs());
        assert_eq!(v.reason, "bad_signature");
        let revoked = trust_with(&ca, "revoked agent:builder-1\n");
        let v = verify_act(&revoked, "d", b"hello", &member, now_secs());
        assert_eq!(v.reason, "revoked");
        let v = verify_act(&trust, "d", b"hello", &member, now_secs() + 13 * 3600);
        assert_eq!(v.reason, "outside_window");
        let other = AgentsCa::generate("host");
        let v = verify_act(&trust_with(&other, ""), "d", b"hello", &member, now_secs());
        assert_eq!(v.reason, "untrusted_authority");
    }

    #[test]
    fn a_session_certificate_without_an_act_identity_is_not_one() {
        let ca = AgentsCa::generate("host");
        let signer = SessionSigner::new(&ca, "claude.abcd1234@agents.local", now_secs()).unwrap();
        let member = member_of(
            signer.act_signature(ACT_NAMESPACE, b"x"),
            Some(signer.certificate_line()),
        );
        let v = verify_act(&trust_with(&ca, ""), "d", b"x", &member, now_secs());
        assert_eq!(v.reason, "no_act_identity");
    }

    #[test]
    fn the_namespace_separates_acts_from_everything_else() {
        let key = SigningKey::generate(&mut OsRng);
        let trust = TrustFile::parse(&format!(
            "{TRUST_HEADER}\nassigner person:taylor {}\n",
            public_line(&key.verifying_key())
        ))
        .unwrap();
        let ok = member_of(sign_plain(&key, ACT_NAMESPACE, b"x"), None);
        assert_eq!(
            verify_act(&trust, "d", b"x", &ok, 0).signer.as_deref(),
            Some("person:taylor")
        );
        for ns in [
            "git",
            "agent-sign/act",
            "agent-sign/act/1 ",
            CREDENTIAL_NAMESPACE,
        ] {
            let m = member_of(sign_plain(&key, ns, b"x"), None);
            assert_eq!(
                verify_act(&trust, "d", b"x", &m, 0).reason,
                "wrong_namespace",
                "{ns}"
            );
        }
    }

    #[test]
    fn a_trust_file_with_a_mistake_is_refused_whole() {
        let key = public_line(&SigningKey::generate(&mut OsRng).verifying_key());
        let other = public_line(&SigningKey::generate(&mut OsRng).verifying_key());
        let h = TRUST_HEADER;
        for bad in [
            String::new(),
            "# only a comment\n".to_string(),
            "agent-sign/acts-trust/2\n".to_string(),
            format!("{h}\nallow person:x {key}\n"),
            format!("{h}\nassigner person:x ssh-ed25519 AAAA\n"),
            format!("{h}\nassigner person:x {key}\nassigner person:y {key}\n"),
            format!("{h}\nauthority a.local {key}\nassigner person:x {key}\n"),
            format!("{h}\nassigner agent:x {key}\n"),
            format!("{h}\nrevoked builder\n"),
        ] {
            assert!(TrustFile::parse(&bad).is_err(), "{bad:?}");
        }
        let good = format!(
            "{h}\n# c\n\nassigner person:x {key}\nassigner person:x {other}\nrevoked person:x\n"
        );
        assert_eq!(
            TrustFile::parse(&good)
                .unwrap()
                .assigner_keys("person:x")
                .len(),
            2
        );
    }

    #[test]
    fn a_credential_is_good_for_300_seconds() {
        let ca = AgentsCa::generate("host");
        let signer = SessionSigner::new(&ca, "agent:a", now_secs()).unwrap();
        let issued = now_secs();
        let sig = signer.act_signature(CREDENTIAL_NAMESPACE, &credential_bytes(issued));
        let cred = Credential {
            schema: CREDENTIAL_SCHEMA.into(),
            issued_at: issued,
            signature: member_of(sig, Some(signer.certificate_line())),
        };
        let trust = trust_with(&ca, "");
        assert!(verify_credential(&trust, "d", &cred, issued + 300).verified);
        assert_eq!(
            verify_credential(&trust, "d", &cred, issued + 301).reason,
            "stale"
        );
        assert!(verify_credential(&trust, "d", &cred, issued - 60).verified);
        assert_eq!(
            verify_credential(&trust, "d", &cred, issued - 61).reason,
            "stale"
        );
    }
}
