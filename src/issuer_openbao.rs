//! The OpenBao issuer: the second [`CertificateIssuer`], used in system mode
//! (design build step 4, `docs/system-mode.md` section 5).
//!
//! Why: in system mode the agents' certificate authority lives in OpenBao's
//! SSH secrets engine and its private key never leaves OpenBao, so no key
//! of the authority is ever in this service's memory or on its disk, and a
//! restart doesn't change who is trusted. This adapter asks OpenBao to sign
//! each session key and then **checks what comes back** before anything uses
//! it: OpenBao is a separate system, and a certificate that is not exactly
//! the one asked for (another principal, for every user, a host certificate,
//! a critical option, an extension nobody asked for, a different lifetime, a
//! different authority) must never become a signature on an agent's commit.
//!
//! What it does, and the rules that shaped it:
//! - **Login.** AppRole (`auth/approle/login`). The role ID and the secret ID
//!   are read from `$CREDENTIALS_DIRECTORY` (files `role-id` and `secret-id`,
//!   the names the sitting gives them) at each login and not held. The token
//!   OpenBao gives back is kept in memory only and zeroed when dropped. A
//!   login happens when there is no token and again, once, when a signing
//!   request is refused (401 or 403: the token expired or was revoked).
//! - **Signing.** `POST <mount>/sign/<role>` with the session key, exactly one
//!   principal, `cert_type` user, the attestation extension (if any) and a
//!   12 hour `ttl`; no `key_id` (the role refuses one; OpenBao derives it). The
//!   principal must be `<name>@<machine>.agents.local` with a plain name; a
//!   list, a wildcard or another domain is refused before any request,
//!   because OpenBao takes `a,b` for two principals and (on 2.7.1) its role
//!   cannot be relied on to keep other domains out.
//! - **Checking** ([`check_issued`]): signed by the authority read at start,
//!   a user certificate for exactly the asked principal and key, no critical
//!   options, exactly the asked extension, an OpenBao-derived key id that is
//!   non-empty printable ASCII of at most 256 characters (never used for
//!   attribution), and a window within a minute of five minutes
//!   before now to twelve hours after it.
//! - **Fails closed.** Unreachable, sealed, slow (every call has a deadline),
//!   an error, an HTML page, an oversized body or any certificate unlike the
//!   request is a refusal in plain words. There is no fallback to a local
//!   key: this module has no key to fall back to.
//! - **Never writes trust.** At start it reads the authority's public key
//!   from OpenBao and the single line of the trust file (`[service]
//!   trust_file`, root's, set at the sitting) and compares them. If they
//!   differ, or the trust file is missing or not one `cert-authority` line
//!   for this machine's domain, it signs nothing and says why. It only ever
//!   *reads* the trust file. Until the comparison has succeeded it is tried
//!   again at the next request, so a service that started before OpenBao
//!   was up (or before trust was installed) needs no restart.
//! - **Start never fails** and never panics, whatever OpenBao does: the
//!   service still starts and answers plain-path questions, and
//!   [`Started::problem`] is what `agent-sign doctor` prints.
//! - **Secrets stay out of messages.** The secret ID, role ID and token never
//!   appear in a message, a URL or a log (nothing here logs): text OpenBao
//!   sends back is shown only as printable ASCII, cut short, with any secret
//!   this adapter holds blanked.
//!
//! TLS: the HTTP client is `ureq` over `rustls` with the `ring` provider. The
//! connection trusts only the CA file named in `[authority] ca_cert` (no
//! bundled roots), checks the certificate against the name in `address`
//! while connecting to the IP in `resolve`, speaks TLS 1.3 only (the crypto
//! provider is given the three TLS 1.3 cipher suites and no TLS 1.2 one, so
//! a server that offers only TLS 1.2 cannot be negotiated with), uses no
//! proxy from the environment, follows no redirect, keeps no connection
//! between calls, and reads at most [`MAX_BODY`] bytes of any answer.
//!
//! The service builds it at start in system mode (`agent-signd`'s
//! `system_issuer`, design step 2), and `agent-sign doctor` uses
//! [`OpenBaoIssuer::ready`] for its `authority:` line.

use std::fs;
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::VerifyingKey;
use rustls::crypto::CryptoProvider;
use rustls::crypto::ring::cipher_suite::{
    TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384, TLS13_CHACHA20_POLY1305_SHA256,
};
use serde_json::{Value, json};
use ssh_key::certificate::CertType;
use ssh_key::public::{Ed25519PublicKey, KeyData};
use ssh_key::{Certificate, HashAlg, PublicKey};
use ureq::Agent;
use ureq::config::Config;
use ureq::http::Uri;
use ureq::tls::{RootCerts, TlsConfig, TlsProvider};
use ureq::unversioned::resolver::{DefaultResolver, ResolvedSocketAddrs, Resolver};
use ureq::unversioned::transport::{DefaultConnector, NextTimeout};
use zeroize::Zeroizing;

use crate::agents_ca::{
    CERT_BACKDATE_SECS, CERT_LIFETIME_SECS, CertificateIssuer, trust_line_prefix,
};
use crate::attestation::{Attestation, EXTENSION};
use crate::attribution::{AGENTS_DOMAIN, check_machine_label};
use crate::crypto::openssh_ed25519_line;

/// The most of any answer this module reads, in bytes. A certificate answer
/// is about a kilobyte; anything near this is not OpenBao.
pub const MAX_BODY: u64 = 256 * 1024;

/// Every call gives up after this long, from the first connection attempt to
/// the last byte. A signer that waits on a silent server stops every agent's
/// commits, so this is short; a start and a retry together stay well under
/// the half minute a caller may wait.
const CALL_DEADLINE: Duration = Duration::from_secs(10);

/// Connecting alone gives up sooner.
const CONNECT_DEADLINE: Duration = Duration::from_secs(5);

/// How far a certificate's window may be from the expected one, in seconds.
/// OpenBao stamps the window with its own clock and a moment later than the
/// request's `now`; a minute is far more than that and far less than any
/// window an attacker would gain from.
const WINDOW_TOLERANCE_SECS: u64 = 60;

/// The longest file (the pinned CA, the trust file, a login credential) read.
const MAX_FILE: u64 = 64 * 1024;

/// What `[authority]` and the rest of `system.toml` give the adapter.
#[derive(Clone, Debug)]
pub struct Settings {
    /// `https://<name>:<port>`: the name the server's certificate is
    /// checked for.
    pub address: String,
    /// The IP address the name is reached at (`[authority] resolve`). Empty
    /// means the system's own name lookup.
    pub resolve: String,
    /// The only CA the TLS connection trusts (`[authority] ca_cert`).
    pub ca_cert: PathBuf,
    /// The SSH engine's mount, such as `ssh-agents-hetzner`.
    pub mount: String,
    /// The role to sign with, such as `agent-sign-hetzner`.
    pub role: String,
    /// The machine label: the domain is `<machine>.agents.local`.
    pub machine: String,
    /// `[service] trust_file`: read, compared, never written.
    pub trust_file: PathBuf,
    /// Where `role-id` and `secret-id` are read from, each time
    /// (`$CREDENTIALS_DIRECTORY` in the service).
    pub credentials_dir: PathBuf,
}

/// A started issuer: the port the service uses, and why it will sign
/// nothing (`None` when it is ready to).
pub struct Started {
    pub issuer: Box<dyn CertificateIssuer>,
    pub problem: Option<String>,
}

/// Starts the issuer. Never fails and never panics, whatever OpenBao or the
/// settings are like: the service must still start. When the issuer can't
/// sign yet, `problem` says why, in words `agent-sign doctor` can print, and
/// every `issue` refuses with the same words (trying again first, when the
/// reason may have passed).
pub fn start(settings: &Settings) -> Started {
    match OpenBaoIssuer::new(settings) {
        Ok(issuer) => {
            let problem = issuer.ready().err();
            Started {
                issuer: Box::new(issuer),
                problem,
            }
        }
        Err(problem) => Started {
            issuer: Box::new(Refusing {
                why: problem.clone(),
            }),
            problem: Some(problem),
        },
    }
}

/// The issuer for settings that can't be used: refuses everything, saying
/// what is wrong with them.
struct Refusing {
    why: String,
}

impl CertificateIssuer for Refusing {
    fn public_key_openssh(&self) -> String {
        String::new()
    }

    fn issue(
        &self,
        _principal: &str,
        _subject: &VerifyingKey,
        _now: u64,
        _attestation: Option<&Attestation>,
    ) -> Result<Certificate, String> {
        Err(self.why.clone())
    }
}

/// The settings, checked and turned into what the calls need.
struct Plan {
    /// `https://<name>:<port>` without a trailing slash.
    base: String,
    machine: String,
    /// `<machine>.agents.local`.
    domain: String,
    mount: String,
    role: String,
    trust_file: PathBuf,
    credentials_dir: PathBuf,
}

/// The authority OpenBao reported, once it matched the trust file.
#[derive(Clone)]
struct Authority {
    /// `ssh-ed25519 AAAA...`, no comment.
    line: String,
}

struct State {
    authority: Option<Authority>,
    /// The AppRole token: in memory only, zeroed when dropped.
    token: Option<Zeroizing<String>>,
}

/// The OpenBao adapter of [`CertificateIssuer`]. See the module comment.
pub struct OpenBaoIssuer {
    plan: Plan,
    agent: Agent,
    state: Mutex<State>,
}

/// Looks up the pinned address instead of the name, whatever the URL says.
#[derive(Debug)]
struct PinnedResolver {
    ip: IpAddr,
}

impl Resolver for PinnedResolver {
    fn resolve(
        &self,
        uri: &Uri,
        _config: &Config,
        _timeout: NextTimeout,
    ) -> Result<ResolvedSocketAddrs, ureq::Error> {
        let port = uri.authority().and_then(|a| a.port_u16()).unwrap_or(443);
        let mut found = self.empty();
        found.push(SocketAddr::new(self.ip, port));
        Ok(found)
    }
}

/// Either the pinned address or the system's lookup.
#[derive(Debug)]
enum Lookup {
    Pinned(PinnedResolver),
    System(DefaultResolver),
}

impl Resolver for Lookup {
    fn resolve(
        &self,
        uri: &Uri,
        config: &Config,
        timeout: NextTimeout,
    ) -> Result<ResolvedSocketAddrs, ureq::Error> {
        match self {
            Lookup::Pinned(r) => r.resolve(uri, config, timeout),
            Lookup::System(r) => r.resolve(uri, config, timeout),
        }
    }
}

impl OpenBaoIssuer {
    /// An issuer for `settings`, or the reason they can't be used. Makes no
    /// request.
    pub fn new(settings: &Settings) -> Result<Self, String> {
        let plan = plan_from(settings)?;
        let roots = read_pinned_ca(&settings.ca_cert)?;
        let lookup = match settings.resolve.trim() {
            "" => Lookup::System(DefaultResolver::default()),
            ip => Lookup::Pinned(PinnedResolver {
                ip: ip.parse().map_err(|_| {
                    "[authority] resolve isn't an IP address (such as 100.64.0.10)".to_string()
                })?,
            }),
        };
        let agent = build_agent(roots, lookup)?;
        Ok(Self {
            plan,
            agent,
            state: Mutex::new(State {
                authority: None,
                token: None,
            }),
        })
    }

    /// Whether the issuer can sign now, trying to find out if it doesn't yet
    /// know: `Err` says why not.
    pub fn ready(&self) -> Result<(), String> {
        let mut state = self.state.lock().map_err(|_| poisoned())?;
        self.authority(&mut state).map(|_| ())
    }

    /// The authority, from OpenBao's public key, if it is the trust file's.
    /// Makes the comparison again each time until it has succeeded once.
    fn authority(&self, state: &mut State) -> Result<Authority, String> {
        if let Some(a) = &state.authority {
            return Ok(a.clone());
        }
        let url = format!("{}/v1/{}/public_key", self.plan.base, self.plan.mount);
        let (status, body) = self.get(&url)?;
        if status != 200 {
            return Err(format!(
                "OpenBao wouldn't give the authority's public key (HTTP {status}){}: nothing is signed",
                detail(&body, &[])
            ));
        }
        let reported = PublicKey::from_openssh(body.trim()).map_err(|_| {
            "OpenBao's answer for the authority's public key isn't an ed25519 key: nothing is signed"
                .to_string()
        })?;
        let trusted = trust_file_key(&self.plan.trust_file, &self.plan.domain)?;
        if reported.key_data() != trusted.key_data() {
            return Err(format!(
                "the certificate authority OpenBao reports ({}) is not the one in the trust file {} \
                 ({}): nothing is signed. Trust is root's and is set at the sitting; this service \
                 never changes it",
                reported.fingerprint(HashAlg::Sha256),
                self.plan.trust_file.display(),
                trusted.fingerprint(HashAlg::Sha256)
            ));
        }
        let authority = Authority {
            line: key_line(&reported),
        };
        state.authority = Some(authority.clone());
        Ok(authority)
    }

    /// Logs in with the role ID and secret ID read from the credentials
    /// folder now, and keeps the token it gets.
    fn login(&self, state: &mut State) -> Result<(), String> {
        state.token = None;
        let role_id = read_credential(&self.plan.credentials_dir, "role-id")?;
        let secret_id = read_credential(&self.plan.credentials_dir, "secret-id")?;
        let body = Zeroizing::new(
            json!({"role_id": role_id.as_str(), "secret_id": secret_id.as_str()}).to_string(),
        );
        let url = format!("{}/v1/auth/approle/login", self.plan.base);
        let (status, answer) = self.post(&url, None, &body)?;
        let secrets = [role_id.as_str(), secret_id.as_str()];
        if status != 200 {
            return Err(format!(
                "OpenBao refused the login (HTTP {status}){}: nothing is signed",
                detail(&answer, &secrets)
            ));
        }
        let token = serde_json::from_str::<Value>(&answer)
            .ok()
            .and_then(|v| v["auth"]["client_token"].as_str().map(str::to_string))
            .map(Zeroizing::new)
            .filter(|t| !t.is_empty() && t.len() <= 4096 && t.chars().all(|c| c.is_ascii_graphic()))
            .ok_or_else(|| {
                "OpenBao's login answer held no usable token: nothing is signed".to_string()
            })?;
        state.token = Some(token);
        Ok(())
    }

    /// One signing request. `Ok(None)` means the token was refused (401 or
    /// 403), so the caller may log in again.
    fn sign(&self, token: &str, body: &str) -> Result<Option<Certificate>, String> {
        let url = format!(
            "{}/v1/{}/sign/{}",
            self.plan.base, self.plan.mount, self.plan.role
        );
        let (status, answer) = self.post(&url, Some(token), body)?;
        match status {
            200 => {}
            401 | 403 => return Ok(None),
            _ => {
                return Err(format!(
                    "OpenBao refused to sign (HTTP {status}){}",
                    detail(&answer, &[token])
                ));
            }
        }
        let signed = serde_json::from_str::<Value>(&answer)
            .ok()
            .and_then(|v| v["data"]["signed_key"].as_str().map(str::to_string))
            .ok_or("OpenBao's answer to the signing request held no signed key")?;
        let cert = Certificate::from_openssh(signed.trim())
            .map_err(|_| "OpenBao's signed key isn't an SSH certificate".to_string())?;
        Ok(Some(cert))
    }

    /// A GET with no token (the public key needs none): status and body.
    fn get(&self, url: &str) -> Result<(u16, String), String> {
        let sent = self.agent.get(url).call();
        self.answer(sent)
    }

    /// A POST of JSON, with the token if there is one.
    fn post(&self, url: &str, token: Option<&str>, body: &str) -> Result<(u16, String), String> {
        let mut request = self.agent.post(url).content_type("application/json");
        if let Some(token) = token {
            request = request.header("X-Vault-Token", token);
        }
        let sent = request.send(body);
        self.answer(sent)
    }

    fn answer(
        &self,
        sent: Result<ureq::http::Response<ureq::Body>, ureq::Error>,
    ) -> Result<(u16, String), String> {
        let response = sent.map_err(|e| {
            format!(
                "OpenBao at {} couldn't be reached safely ({}): nothing is signed",
                self.plan.base,
                shown(&e.to_string(), 160)
            )
        })?;
        let status = response.status().as_u16();
        let body = response
            .into_body()
            .with_config()
            .limit(MAX_BODY)
            .lossy_utf8(true)
            .read_to_string()
            .map_err(|e| {
                format!(
                    "OpenBao's answer couldn't be read ({}): nothing is signed",
                    shown(&e.to_string(), 160)
                )
            })?;
        Ok((status, body))
    }
}

fn poisoned() -> String {
    "the OpenBao issuer stopped working after an internal error: restart the service".to_string()
}

impl CertificateIssuer for OpenBaoIssuer {
    /// The authority's public key, when it is known and trusted; empty
    /// before that. The service doesn't need it to sign, only to report.
    fn public_key_openssh(&self) -> String {
        self.state
            .lock()
            .ok()
            .and_then(|s| s.authority.as_ref().map(|a| a.line.clone()))
            .unwrap_or_default()
    }

    /// A user certificate from OpenBao for `subject`, naming `principal`
    /// only: refused, in words, unless OpenBao's authority is the trust
    /// file's, `principal` is one plain name in this machine's domain, and
    /// the certificate OpenBao returns passes [`check_issued`].
    fn issue(
        &self,
        principal: &str,
        subject: &VerifyingKey,
        now: u64,
        attestation: Option<&Attestation>,
    ) -> Result<Certificate, String> {
        check_principal(principal, &self.plan.domain)?;
        let mut state = self.state.lock().map_err(|_| poisoned())?;
        let authority = self.authority(&mut state)?;

        // No `key_id`: the role has `allow_user_key_ids` false, so OpenBao
        // refuses any request that sets one (400) and derives the id itself.
        // Who signed is read from the principal and the attestation
        // extension, never from the key id.
        let mut request = json!({
            "public_key": openssh_ed25519_line(subject),
            "valid_principals": principal,
            "cert_type": "user",
            "ttl": format!("{CERT_LIFETIME_SECS}s"),
        });
        if let Some(attestation) = attestation {
            request["extensions"] = json!({ EXTENSION: attestation.encode() });
        }
        let body = request.to_string();

        let mut logged_in_now = false;
        let cert = loop {
            if state.token.is_none() {
                self.login(&mut state)?;
                logged_in_now = true;
            }
            let token = state.token.clone().ok_or("no token")?;
            match self.sign(&token, &body)? {
                Some(cert) => break cert,
                None if logged_in_now => {
                    state.token = None;
                    return Err(
                        "OpenBao refused the token it had just issued: nothing is signed \
                                (is the login's policy right?)"
                            .to_string(),
                    );
                }
                None => {
                    state.token = None;
                }
            }
        };

        if cert.signature_key()
            != PublicKey::from_openssh(&authority.line)
                .map_err(|_| "the authority's key can't be read".to_string())?
                .key_data()
        {
            // OpenBao's authority changed under us: forget what was checked,
            // so the next request compares again with the trust file.
            state.authority = None;
        }
        check_issued(
            &cert,
            &authority.line,
            &self.plan.machine,
            principal,
            subject,
            attestation,
            now,
        )
        .map_err(|why| format!("OpenBao returned a certificate that was not used: {why}"))?;
        Ok(cert)
    }
}

/// Checks a certificate OpenBao returned against what was asked: signed by
/// `ca_public_key` (one OpenSSH line), a user certificate for exactly
/// `principal` and nobody else, for `subject`'s key, no critical options,
/// exactly the one extension `attestation` encodes (none when there is no
/// attestation), a key id that is only safe to show (OpenBao derives it; it
/// is never used for attribution, see [`check_key_id`]), and a validity window
/// within a minute of `[now - 5 min, now + 12 h]`. Pure: no server needed.
/// `principal` must also be in `machine`'s domain, so a certificate for
/// another domain is refused even if it was asked for (the role's
/// `allowed_users` is `*`, so this is one of the layers that keep it out).
pub fn check_issued(
    cert: &Certificate,
    ca_public_key: &str,
    machine: &str,
    principal: &str,
    subject: &VerifyingKey,
    attestation: Option<&Attestation>,
    now: u64,
) -> Result<(), String> {
    check_principal(principal, &format!("{machine}.{AGENTS_DOMAIN}"))?;
    let ca = PublicKey::from_openssh(ca_public_key)
        .map_err(|_| "the authority's public key can't be read".to_string())?;
    if cert.signature_key() != ca.key_data() {
        return Err("it isn't signed by the authority OpenBao reported at start".to_string());
    }
    // The signature itself, checked at a moment inside its own window so only
    // the authority and the signature are tested here, not the date.
    cert.validate_at(cert.valid_after(), &[ca.fingerprint(HashAlg::Sha256)])
        .map_err(|_| "its signature doesn't verify under the authority".to_string())?;
    if cert.cert_type() != CertType::User {
        return Err("it isn't a user certificate".to_string());
    }
    if cert.valid_principals() != [principal.to_string()] {
        return Err(format!(
            "it names {} instead of exactly the one principal asked for, {}",
            if cert.valid_principals().is_empty() {
                "every user".to_string()
            } else {
                shown(&format!("{:?}", cert.valid_principals()), 120)
            },
            shown(principal, 120)
        ));
    }
    if cert.public_key() != &KeyData::Ed25519(Ed25519PublicKey(subject.to_bytes())) {
        return Err("it is for another key than the one sent".to_string());
    }
    if !cert.critical_options().is_empty() {
        return Err("it carries critical options nobody asked for".to_string());
    }
    let wanted_extensions: Vec<(String, String)> = attestation
        .map(|a| vec![(EXTENSION.to_string(), a.encode())])
        .unwrap_or_default();
    let found_extensions: Vec<(String, String)> = cert
        .extensions()
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    if found_extensions != wanted_extensions {
        return Err(if wanted_extensions.is_empty() {
            "it carries extensions nobody asked for".to_string()
        } else {
            "its extensions aren't exactly the attestation asked for".to_string()
        });
    }
    check_key_id(cert.key_id())?;
    let near = |found: u64, wanted: u64| found.abs_diff(wanted) <= WINDOW_TOLERANCE_SECS;
    if !near(cert.valid_after(), now.saturating_sub(CERT_BACKDATE_SECS))
        || !near(cert.valid_before(), now.saturating_add(CERT_LIFETIME_SECS))
    {
        return Err(format!(
            "its validity ({} to {}, seconds since the epoch) isn't {CERT_BACKDATE_SECS} seconds \
             before now to {CERT_LIFETIME_SECS} seconds after it",
            cert.valid_after(),
            cert.valid_before()
        ));
    }
    Ok(())
}

/// OpenBao's own key id is accepted only if it is non-empty, printable ASCII
/// and at most 256 characters, so nothing odd reaches verifiers' logs. It
/// says nothing about who the certificate is for: that comes only from the
/// principal and the attestation extension.
fn check_key_id(id: &str) -> Result<(), String> {
    if id.is_empty() || id.len() > 256 || !id.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
        return Err(
            "its key id isn't non-empty printable ASCII of at most 256 characters".to_string(),
        );
    }
    Ok(())
}

/// Whether `principal` is `<name>@<domain>`, one plain name: lowercase
/// letters, digits, `.` and `-` (what the agents' principals are made of,
/// see [`crate::attribution`]), and nothing that OpenBao would read as a
/// list or a pattern.
fn check_principal(principal: &str, domain: &str) -> Result<(), String> {
    let refuse = || {
        format!(
            "the principal {} isn't one plain name in this machine's domain (<name>@{domain}): \
             nothing is signed",
            shown(principal, 80)
        )
    };
    let (name, at) = principal.rsplit_once('@').ok_or_else(refuse)?;
    let plain = !name.is_empty()
        && name.len() <= 128
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-');
    if at == domain && plain {
        Ok(())
    } else {
        Err(refuse())
    }
}

/// The settings, checked.
fn plan_from(s: &Settings) -> Result<Plan, String> {
    check_machine_label(&s.machine)
        .map_err(|e| e.replace("[identity] machine", "the machine name"))?;
    let plain = |what: &str, v: &str| {
        let ok = !v.is_empty()
            && v.len() <= 128
            && v.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
            && !v.starts_with('.');
        if ok {
            Ok(v.to_string())
        } else {
            Err(format!(
                "[authority] {what} = {} isn't a plain name (letters, digits, '-', '_' and '.')",
                shown(v, 60)
            ))
        }
    };
    let mount = plain("mount", &s.mount)?;
    let role = plain("role", &s.role)?;
    let base = s.address.trim().trim_end_matches('/').to_string();
    let authority = base.strip_prefix("https://").ok_or_else(|| {
        "[authority] address must start with https:// (OpenBao is only reached over TLS)"
            .to_string()
    })?;
    let host_ok = !authority.is_empty()
        && authority.len() <= 253
        && authority
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'));
    if !host_ok {
        return Err(
            "[authority] address must be https://<name>[:<port>] and nothing more".to_string(),
        );
    }
    Ok(Plan {
        base,
        domain: format!("{}.{AGENTS_DOMAIN}", s.machine),
        machine: s.machine.clone(),
        mount,
        role,
        trust_file: s.trust_file.clone(),
        credentials_dir: s.credentials_dir.clone(),
    })
}

/// The certificates in the pinned CA file: the only roots the connection
/// trusts.
fn read_pinned_ca(path: &Path) -> Result<Arc<Vec<ureq::tls::Certificate<'static>>>, String> {
    let pem = read_small(path).map_err(|e| {
        format!(
            "the pinned CA file {} can't be read ({e}): nothing is signed",
            path.display()
        )
    })?;
    let certs: Vec<ureq::tls::Certificate<'static>> = pem_certificates(&pem)
        .iter()
        .map(|der| ureq::tls::Certificate::from_der(der).to_owned())
        .collect();
    if certs.is_empty() {
        return Err(format!(
            "the pinned CA file {} holds no certificate: nothing is signed",
            path.display()
        ));
    }
    Ok(Arc::new(certs))
}

/// The DER bytes of every `CERTIFICATE` block in `pem`; anything else in
/// the file (any other block, text around them, a block whose base64 doesn't
/// read) is skipped. Our own reader rather than the TLS library's general
/// PEM parser, which knows every kind of block, private keys included: this
/// one can't read a private key by construction, and linking that parser
/// would put private-key block names into the installed service, which the
/// "no private key material" scans of the state folder and binaries reject.
fn pem_certificates(pem: &str) -> Vec<Vec<u8>> {
    use base64::Engine;
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let mut out = Vec::new();
    let mut body: Option<String> = None;
    for line in pem.lines().map(str::trim) {
        match &mut body {
            None if line == BEGIN => body = Some(String::new()),
            None => {}
            Some(_) if line == END => {
                if let Some(text) = body.take()
                    && let Ok(der) = base64::engine::general_purpose::STANDARD.decode(text)
                    && !der.is_empty()
                {
                    out.push(der);
                }
            }
            Some(text) => text.push_str(line),
        }
    }
    out
}

/// The HTTP client: TLS 1.3 only, the pinned roots only, no proxy, no
/// redirect, no kept connection, deadlines on everything.
fn build_agent(
    roots: Arc<Vec<ureq::tls::Certificate<'static>>>,
    lookup: Lookup,
) -> Result<Agent, String> {
    let provider = CryptoProvider {
        cipher_suites: vec![
            TLS13_AES_256_GCM_SHA384,
            TLS13_AES_128_GCM_SHA256,
            TLS13_CHACHA20_POLY1305_SHA256,
        ],
        ..rustls::crypto::ring::default_provider()
    };
    let tls = TlsConfig::builder()
        .provider(TlsProvider::Rustls)
        .root_certs(RootCerts::Specific(roots))
        .unversioned_rustls_crypto_provider(Arc::new(provider))
        .build();
    let config = Config::builder()
        .tls_config(tls)
        .https_only(true)
        .proxy(None)
        .max_redirects(0)
        .http_status_as_error(false)
        .max_idle_connections(0)
        .timeout_global(Some(CALL_DEADLINE))
        .timeout_connect(Some(CONNECT_DEADLINE))
        .user_agent("agent-sign")
        .build();
    Ok(Agent::with_parts(config, DefaultConnector::new(), lookup))
}

/// The one authority key in the trust file: exactly one line that isn't blank
/// or a comment, and it must be `*@<domain> cert-authority,namespaces="git"
/// <key>`, so a file that trusts something else, or more than one thing, is
/// not "the trust file" and the issuer signs nothing.
fn trust_file_key(path: &Path, domain: &str) -> Result<PublicKey, String> {
    let text = read_small(path).map_err(|e| {
        format!(
            "the trust file {} can't be read ({e}): nothing is signed",
            path.display()
        )
    })?;
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    let [line] = lines.as_slice() else {
        return Err(format!(
            "the trust file {} must hold exactly one certificate authority line, and holds {}: \
             nothing is signed",
            path.display(),
            lines.len()
        ));
    };
    let prefix = format!("{} ", trust_line_prefix(domain));
    let key = line
        .strip_prefix(prefix.as_str())
        .and_then(|rest| {
            let mut words = rest.split_whitespace();
            Some(format!("{} {}", words.next()?, words.next()?))
        })
        .and_then(|k| PublicKey::from_openssh(&k).ok())
        .ok_or_else(|| {
            format!(
                "the line in the trust file {} isn't a cert-authority line for *@{domain} with an \
                 ed25519 key: nothing is signed",
                path.display()
            )
        })?;
    Ok(key)
}

/// A key as `ssh-ed25519 AAAA...`, without a comment.
fn key_line(key: &PublicKey) -> String {
    key.to_openssh()
        .unwrap_or_default()
        .split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ")
}

/// A login credential from the credentials folder: the file's text without
/// surrounding whitespace, which must be printable ASCII.
fn read_credential(dir: &Path, name: &str) -> Result<Zeroizing<String>, String> {
    let path = dir.join(name);
    let text = read_small(&path).map_err(|e| {
        format!(
            "the login's {name} can't be read from {} ({e}): nothing is signed",
            path.display()
        )
    })?;
    let text = Zeroizing::new(text);
    let value = text.trim();
    if value.is_empty() || !value.chars().all(|c| c.is_ascii_graphic()) {
        return Err(format!(
            "the login's {name} in {} is empty or isn't plain text: nothing is signed",
            path.display()
        ));
    }
    Ok(Zeroizing::new(value.to_string()))
}

/// A whole small text file, at most [`MAX_FILE`] bytes, as a string. The error
/// is a few words and never the file's content.
fn read_small(path: &Path) -> Result<String, String> {
    let file = fs::File::open(path).map_err(|e| e.to_string())?;
    let mut text = String::new();
    file.take(MAX_FILE + 1)
        .read_to_string(&mut text)
        .map_err(|_| "it isn't text".to_string())?;
    if text.len() as u64 > MAX_FILE {
        return Err("it is too big".to_string());
    }
    Ok(text)
}

/// What OpenBao said in `errors`, for a message: `": <text>"`, or nothing.
/// Only printable ASCII, cut short, and with any of `secrets` blanked.
fn detail(body: &str, secrets: &[&str]) -> String {
    let said = serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|v| {
            v["errors"].as_array().map(|list| {
                list.iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join("; ")
            })
        })
        .unwrap_or_default();
    let mut said = shown(&said, 200);
    for secret in secrets.iter().filter(|s| s.len() >= 4) {
        said = said.replace(secret, "[hidden]");
    }
    if said.is_empty() {
        String::new()
    } else {
        format!(": {said}")
    }
}

/// `text` as printable ASCII only (other characters become `?`), at most
/// `max` characters, with `...` when cut.
fn shown(text: &str, max: usize) -> String {
    let mut out: String = text
        .chars()
        .map(|c| if (' '..='~').contains(&c) { c } else { '?' })
        .take(max)
        .collect();
    if text.chars().count() > max {
        out.push_str("...");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_certificate_blocks_are_read_from_the_pinned_ca_file() {
        let pem = "junk\n-----BEGIN CERTIFICATE-----\nAQID\nBA==\n-----END CERTIFICATE-----\n\
                   -----BEGIN OTHER-----\nBQY=\n-----END OTHER-----\n\
                   -----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n\
                   -----BEGIN CERTIFICATE-----\nBwg=\n-----END CERTIFICATE-----\n";
        assert_eq!(pem_certificates(pem), vec![vec![1, 2, 3, 4], vec![7, 8]]);
        assert!(pem_certificates("").is_empty());
    }

    #[test]
    fn a_principal_is_one_plain_name_in_the_domain() {
        let d = "hetzner.agents.local";
        assert!(check_principal("claude-code.0a1b2c3d@hetzner.agents.local", d).is_ok());
        for bad in [
            "claude-code.0a1b2c3d@other.agents.local",
            "claude-code.0a1b2c3d@agents.local",
            "claude-code.0a1b2c3d",
            "@hetzner.agents.local",
            "*@hetzner.agents.local",
            "a@hetzner.agents.local,b@hetzner.agents.local",
            "a b@hetzner.agents.local",
            "A@hetzner.agents.local",
            "a\"b@hetzner.agents.local",
            "a@hetzner.agents.local.evil",
            "",
        ] {
            assert!(check_principal(bad, d).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn text_from_the_server_is_shown_plain_short_and_without_secrets() {
        let body = r#"{"errors":["bad secret s3cr3t-value\u0007 and more"]}"#;
        let said = detail(body, &["s3cr3t-value"]);
        assert!(!said.contains("s3cr3t-value"), "{said}");
        assert!(said.starts_with(": "), "{said}");
        assert!(said.is_ascii() && !said.contains('\u{7}'));
        assert_eq!(detail("<html>", &[]), "");
        assert!(shown(&"x".repeat(1000), 10).len() <= 13);
    }

    #[test]
    fn settings_that_cant_be_used_are_refused_in_words() {
        let ok = |address: &str| Settings {
            address: address.into(),
            resolve: "127.0.0.1".into(),
            ca_cert: PathBuf::from("/nonexistent/ca.pem"),
            mount: "ssh-agents-hetzner".into(),
            role: "agent-sign-hetzner".into(),
            machine: "hetzner".into(),
            trust_file: PathBuf::from("/nonexistent/allowed_signers"),
            credentials_dir: PathBuf::from("/nonexistent"),
        };
        assert!(plan_from(&ok("https://openbao.test:8200")).is_ok());
        for bad in [
            "http://openbao.test:8200",
            "https://user@openbao.test:8200",
            "https://openbao.test:8200/v1",
            "https://openbao.test:8200?x=1",
            "https://",
            "openbao.test",
        ] {
            assert!(plan_from(&ok(bad)).is_err(), "accepted {bad}");
        }
        let mut s = ok("https://openbao.test:8200");
        s.mount = "a/b".into();
        assert!(plan_from(&s).is_err());
        let mut s = ok("https://openbao.test:8200");
        s.machine = "Bad.Machine".into();
        assert!(plan_from(&s).is_err());
        // Settings that can't be used still start: the issuer refuses.
        let started = start(&ok("https://openbao.test:8200"));
        assert!(started.problem.is_some());
        let subject = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]).verifying_key();
        assert!(
            started
                .issuer
                .issue("a@hetzner.agents.local", &subject, 1_000_000, None)
                .is_err()
        );
    }
}
