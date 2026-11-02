//! The machine's system settings, `/etc/agent-sign/system.toml`, and the
//! mode switch they make (docs/system-mode.md, sections 1, 2, 4 and 5;
//! build step 1).
//!
//! **Why a file of its own.** On a laptop agent-sign runs in one account and
//! reads `~/.agent-sign/config.toml`. On a server it runs in accounts of its
//! own, and every setting that decides who may sign must be root's, not the
//! agents'. So there is one place to look, written by agent-sign's sitting,
//! and **its existence alone means system mode** (the same rule one-account
//! launch already follows, [`crate::launch::system_config`]).
//!
//! **What system mode changes in the service** (the decisions are in the
//! service; this module only reads and checks the file):
//! - the service reads only this file: a `config.toml` in its state folder
//!   is ignored, with a warning;
//! - it refuses to start as any account but `[service] account`
//!   ([`SystemConfig::check_runs_as`]);
//! - it needs `[authority] issuer = "openbao"`; the in-memory authority is
//!   never used there, so a failure can't fall back to a local key
//!   ([`SystemConfig::openbao`]);
//! - it never runs git in a caller's repository.
//!
//! **Unknown keys are refused**, in every table, outside any table, and in
//! `[security]` (whose keys are `config.toml`'s): a misspelt setting that
//! quietly fell back to a default would loosen a rule nobody knew was off.
//! The refusal names the key and the file, and it happens before the service
//! touches its state folder or opens its socket. Clients are more tolerant
//! ([`client_socket`] reads only `[service] socket`), because a client built
//! before a new key existed must still find the service.
//!
//! **The issuer.** The OpenBao adapter (`crate::issuer_openbao`, build step
//! 4) is wired into the service's start path (step 2). [`ClosedIssuer`]
//! stands in whenever it can't be used (its login isn't loaded, or its
//! settings are unusable): the service starts and answers plain-path
//! questions, and every signature is refused.

use std::path::{Path, PathBuf};

use ed25519_dalek::VerifyingKey;
use serde::Deserialize;
use ssh_key::Certificate;

use crate::agents_ca::CertificateIssuer;
use crate::attestation::Attestation;
use crate::config::{
    AgentConfig, ApprovalsConfig, AttributionConfig, Config, HumanConfig, IdentityConfig,
    SecurityConfig, SshConfig,
};

/// Where the service's socket is when the file doesn't say (the design's
/// path, made by the service's socket unit).
pub const DEFAULT_SERVICE_SOCKET: &str = "/run/agent-sign/daemon.sock";

/// The only issuer system mode accepts.
pub const ISSUER_OPENBAO: &str = "openbao";

/// The parsed `system.toml`. Every table's keys are fixed: a key not listed
/// here is an error (see the module documentation).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemConfig {
    /// The machine's name, such as `hetzner`: agents' principals become
    /// `<agent>.<session>@<machine>.agents.local`.
    pub machine: String,
    pub service: ServiceSection,
    #[serde(default)]
    pub launcher: LauncherSection,
    #[serde(default)]
    pub slots: SlotsSection,
    #[serde(default)]
    pub identity: IdentitySection,
    /// Where signing certificates come from. Required in system mode (see
    /// [`SystemConfig::openbao`]), but optional to parse, so that its absence
    /// is refused with a message about the issuer rather than about TOML.
    #[serde(default)]
    pub authority: Option<AuthoritySection>,
    #[serde(default)]
    pub approvals: ApprovalsSection,
    /// `config.toml`'s `[security]` keys; checked against them by
    /// [`SystemConfig::parse`] (serde can't deny unknown keys in a type it
    /// shares with `config.toml`).
    #[serde(default)]
    security: Option<toml::Value>,
}

/// `[service]`: the signing service itself.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceSection {
    /// The only account the service runs as in system mode.
    pub account: String,
    #[serde(default = "default_service_socket")]
    pub socket: PathBuf,
    #[serde(default = "default_launcher_socket")]
    pub launcher_socket: PathBuf,
    /// The root-owned allowed-signers file git verifies commits with.
    #[serde(default = "default_trust_file")]
    pub trust_file: PathBuf,
    /// Accounts whose plain-path questions the service answers.
    #[serde(default)]
    pub client_accounts: Vec<String>,
}

fn default_service_socket() -> PathBuf {
    PathBuf::from(DEFAULT_SERVICE_SOCKET)
}
fn default_launcher_socket() -> PathBuf {
    PathBuf::from("/run/agent-sign/launcher.sock")
}
fn default_trust_file() -> PathBuf {
    PathBuf::from("/etc/agent-sign/allowed_signers")
}

/// `[launcher]`: the program that starts sessions (build step 3).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LauncherSection {
    pub account: String,
    pub socket: PathBuf,
    /// Accounts that may launch a session by asking, with no signed request.
    pub people_accounts: Vec<String>,
    /// Public keys that may sign a launch request.
    pub approvers: Vec<String>,
    /// The most launches one caller account may make in any hour, counted
    /// from the launcher's kernel-reported uid, not from anything a request
    /// says. A launch over the limit is refused at once, in plain words,
    /// before its approval is used up. The default is
    /// [`DEFAULT_LAUNCHES_PER_HOUR`], which is worked out from the slots and
    /// the session length; raise it only with more slots or shorter sessions.
    /// `0` refuses every launch.
    pub launches_per_hour: u32,
}

/// The default for [`LauncherSection::launches_per_hour`]: 48 launches an hour
/// for one caller account. It is derived, not guessed: `[slots] count` is 8 by
/// default, and a session worth a launch runs for at least about ten minutes
/// (the slot must be prepared, the work done and the end step run; anything
/// shorter is a probe, not work), so a slot can turn over at most six times an
/// hour, and 8 slots times 6 launches is 48 launches an hour, the most the
/// slots could serve in an hour of real use. Sessions may run up to the longest
/// session length (`[slots] max_duration`, 12 h by default), so real use is far
/// lower; a caller at 48 an hour is looping, and each launch it makes writes a
/// line to `sessions.log`, fills a nonce record and costs the launcher a slot
/// claim. One caller's limit does not count against another's. A machine with
/// more slots or shorter sessions sets its own number.
pub const DEFAULT_LAUNCHES_PER_HOUR: u32 = 48;

impl Default for LauncherSection {
    fn default() -> Self {
        Self {
            account: "agent-launch".into(),
            socket: PathBuf::from("/run/agent-launch/launch.sock"),
            people_accounts: Vec::new(),
            approvers: Vec::new(),
            launches_per_hour: DEFAULT_LAUNCHES_PER_HOUR,
        }
    }
}

/// `[slots]`: the per-session accounts (build steps 2 and 3).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SlotsSection {
    pub count: u32,
    pub account_prefix: String,
    pub root: PathBuf,
    /// The longest a session may run, such as `12h`.
    pub max_duration: String,
}

impl Default for SlotsSection {
    fn default() -> Self {
        Self {
            count: 8,
            account_prefix: "agent-slot-".into(),
            root: PathBuf::from("/var/lib/agent-slots"),
            max_duration: "12h".into(),
        }
    }
}

/// `[identity]`: as `config.toml`'s, minus `machine` (top level here).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct IdentitySection {
    /// People's names, never certified as agents' (`config.toml`'s
    /// `[identity] people`).
    pub people: Vec<String>,
    /// Agent names allowed besides the built-in ones (`config.toml`'s
    /// `[identity] allowed_agents`).
    pub allowed_agents: Vec<String>,
}

/// `[authority]`: where agents' signing certificates come from.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoritySection {
    /// Must be `openbao` in system mode.
    #[serde(default)]
    pub issuer: Option<String>,
    /// OpenBao's address, such as `https://hetzner.example.ts.net:8200`.
    #[serde(default)]
    pub address: Option<String>,
    /// The only certificate authorities trusted when talking to OpenBao.
    #[serde(default)]
    pub ca_cert: Option<String>,
    /// The IP address to connect to for `address`'s host name, if the name
    /// should not be looked up.
    #[serde(default)]
    pub resolve: Option<String>,
    /// The SSH secrets engine's mount, such as `ssh-agents-hetzner`.
    #[serde(default)]
    pub mount: Option<String>,
    /// The engine's role, such as `agent-sign-hetzner`.
    #[serde(default)]
    pub role: Option<String>,
}

/// `[approvals]`: as `config.toml`'s.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ApprovalsSection {
    /// The commitments approval key (one OpenSSH line); unset until it
    /// exists.
    pub commitments_key: Option<String>,
}

/// What `[authority]` says when the issuer is OpenBao: the settings the
/// adapter (build step 4) is built from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenBaoSettings {
    pub address: String,
    pub ca_cert: String,
    pub resolve: Option<String>,
    pub mount: String,
    pub role: String,
}

impl SystemConfig {
    /// Reads and checks the file at `path`. Every error names the file.
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("{}: can't be read ({e})", path.display()))?;
        Self::parse(&text, path)
    }

    /// Checks `text`, which came from `path` (named in every error): TOML
    /// that reads, no key or table agent-sign doesn't know, and values that
    /// make sense.
    pub fn parse(text: &str, path: &Path) -> Result<Self, String> {
        let at = path.display();
        let config: SystemConfig =
            toml::from_str(text).map_err(|e| format!("{at}: {}", e.to_string().trim_end()))?;
        if let Some(security) = &config.security {
            let table = security
                .as_table()
                .ok_or_else(|| format!("{at}: `security` must be a table, [security]"))?;
            let known = security_keys();
            for key in table.keys() {
                if !known.contains(key) {
                    return Err(format!(
                        "{at}: [security] has the key `{key}`, which agent-sign doesn't read; \
                         fix the spelling or remove it"
                    ));
                }
            }
        }
        crate::attribution::check_machine_label(&config.machine)
            .map_err(|e| format!("{at}: machine: {e}"))?;
        if config.service.account.trim().is_empty() {
            return Err(format!("{at}: [service] account is empty"));
        }
        for (what, socket) in [
            ("[service] socket", &config.service.socket),
            ("[service] launcher_socket", &config.service.launcher_socket),
        ] {
            if !socket.is_absolute() {
                return Err(format!(
                    "{at}: {what} = {:?} must be a full path",
                    socket.display()
                ));
            }
        }
        Ok(config)
    }

    /// Refuses unless the service, running as user id `euid`, is the
    /// account `[service] account` names ("stops at once, before it makes
    /// anything": the caller checks this before the state folder or the
    /// socket). `path` is the settings file, for the message.
    pub fn check_runs_as(&self, euid: u32, path: &Path) -> Result<(), String> {
        let want = &self.service.account;
        let accounts = crate::accounts::all_accounts().map_err(|e| {
            format!("couldn't read the machine's accounts to check [service] account ({e})")
        })?;
        let running = accounts.iter().find(|a| a.uid == euid).map_or_else(
            || format!("uid {euid}"),
            |a| format!("`{}` (uid {euid})", a.login),
        );
        match accounts.iter().find(|a| &a.login == want) {
            Some(a) if a.uid == euid => Ok(()),
            Some(a) => Err(format!(
                "system mode: {} sets [service] account = `{want}` (uid {}), but this service is \
                 running as {running}. In system mode the service runs as that account and no \
                 other, so nothing was started",
                path.display(),
                a.uid
            )),
            None => Err(format!(
                "system mode: {} sets [service] account = `{want}`, which isn't an account on \
                 this machine, and this service is running as {running}. In system mode the \
                 service runs as that account and no other, so nothing was started",
                path.display()
            )),
        }
    }

    /// The OpenBao settings, or why system mode can't start: the issuer is
    /// missing, or isn't `openbao` (the in-memory authority is never used in
    /// system mode), or an OpenBao setting is missing. Every message says
    /// "issuer".
    pub fn openbao(&self, path: &Path) -> Result<OpenBaoSettings, String> {
        let at = path.display();
        let authority = self.authority.as_ref().ok_or_else(|| {
            format!(
                "system mode needs an issuer: {at} has no [authority] table, so there is no \
                 [authority] issuer = \"{ISSUER_OPENBAO}\". The in-memory authority is never used \
                 in system mode"
            )
        })?;
        match authority.issuer.as_deref() {
            Some(ISSUER_OPENBAO) => {}
            Some(other) => {
                return Err(format!(
                    "system mode needs the issuer \"{ISSUER_OPENBAO}\", and {at} sets \
                     [authority] issuer = {other:?}. A local or in-memory authority is never \
                     used in system mode"
                ));
            }
            None => {
                return Err(format!(
                    "system mode needs an issuer: [authority] in {at} has no `issuer`; set \
                     issuer = \"{ISSUER_OPENBAO}\". The in-memory authority is never used in \
                     system mode"
                ));
            }
        }
        let need = |key: &str, value: &Option<String>| {
            value
                .as_deref()
                .filter(|v| !v.trim().is_empty())
                .map(str::to_string)
                .ok_or_else(|| {
                    format!(
                        "the issuer \"{ISSUER_OPENBAO}\" needs [authority] {key}, and {at} \
                         doesn't set it"
                    )
                })
        };
        Ok(OpenBaoSettings {
            address: need("address", &authority.address)?,
            ca_cert: need("ca_cert", &authority.ca_cert)?,
            resolve: authority.resolve.clone().filter(|v| !v.trim().is_empty()),
            mount: need("mount", &authority.mount)?,
            role: need("role", &authority.role)?,
        })
    }

    /// The [`Config`] the service runs with in system mode, built from this
    /// file alone: `[security]`, `[identity]` (with the machine's name) and
    /// `[approvals]`, checked as `config.toml`'s are. No environment
    /// override applies, and nothing is read from git: the `[human]` name is
    /// left empty (it names no one; the people are `[identity] people` and
    /// the machine's accounts).
    pub fn to_config(&self, path: &Path) -> Result<Config, String> {
        let at = path.display();
        let security: SecurityConfig = match &self.security {
            None => SecurityConfig::default(),
            Some(value) => value.clone().try_into().map_err(|e| {
                format!("{at}: [security] has a setting agent-sign can't read: {e}")
            })?,
        };
        let config = Config {
            attribution: AttributionConfig::default(),
            agent: AgentConfig::default(),
            human: HumanConfig {
                name: String::new(),
                email: String::new(),
                github_username: String::new(),
            },
            security,
            ssh: SshConfig::default(),
            identity: IdentityConfig {
                machine: Some(self.machine.clone()),
                allowed_agents: self.identity.allowed_agents.clone(),
                people: self.identity.people.clone(),
            },
            approvals: ApprovalsConfig {
                commitments_key: self.approvals.commitments_key.clone(),
            },
        };
        config
            .validate_selected_security()
            .map_err(|e| format!("{at}: [security] {e}"))?;
        config
            .identity
            .check_against(&config.human)
            .map_err(|e| format!("{at}: {e}"))?;
        config
            .approvals
            .check(&config.identity)
            .map_err(|e| format!("{at}: {e}"))?;
        Ok(config)
    }
}

/// The keys `[security]` takes: the ones `config.toml`'s `[security]` takes
/// (read from its own defaults, so a new setting is never missed here).
fn security_keys() -> Vec<String> {
    toml::Value::try_from(SecurityConfig::default())
        .ok()
        .and_then(|v| v.as_table().map(|t| t.keys().cloned().collect()))
        .unwrap_or_default()
}

/// The system settings in force on this machine, once read.
#[derive(Debug, Clone)]
pub struct Active {
    /// The file they came from.
    pub path: PathBuf,
    pub config: SystemConfig,
}

/// The system settings, if this machine is in system mode: `Ok(None)` when
/// nothing is at the file's path (a laptop), `Ok(Some)` when it reads, and
/// an error when something is there that doesn't (an unreadable file, a
/// link to nothing, a key agent-sign doesn't know): the service must then
/// refuse to start, never fall back to one-account mode.
pub fn active() -> Result<Option<Active>, String> {
    let Some(path) = crate::launch::system_config() else {
        return Ok(None);
    };
    let config = SystemConfig::load(&path)?;
    Ok(Some(Active { path, config }))
}

/// The service socket `system.toml` names, for a client (the command line,
/// the git wrapper, the signing program, `agent-signd status`): `None` on a
/// machine without the file. It reads only `[service] socket`, and leniently
/// (a key it doesn't know is not its business), so a client older than the
/// file still finds the service. A file that can't be read or isn't TOML is
/// said on stderr and treated as absent: a client has no way to refuse, and
/// the service itself refuses to start on such a file.
pub fn client_socket() -> Option<PathBuf> {
    let path = crate::launch::system_config_path();
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            eprintln!(
                "[agent-sign] {} can't be read ({e}); using the default socket",
                path.display()
            );
            return None;
        }
    };
    let value: toml::Value = match toml::from_str(&text) {
        Ok(value) => value,
        Err(e) => {
            eprintln!(
                "[agent-sign] {} isn't valid TOML ({}); using the default socket",
                path.display(),
                e.message()
            );
            return None;
        }
    };
    let socket = value
        .get("service")
        .and_then(|s| s.get("socket"))
        .and_then(toml::Value::as_str)
        .map_or_else(|| PathBuf::from(DEFAULT_SERVICE_SOCKET), PathBuf::from);
    socket.is_absolute().then_some(socket)
}

/// The issuer system mode uses when the OpenBao adapter can't be (its login
/// isn't loaded, or its settings can't be used): it signs nothing, so the
/// service starts and answers plain-path questions while every signature is
/// refused, which is how the design's "fails closed" looks then. It holds no
/// key, so nothing local can ever sign in its place.
pub struct ClosedIssuer {
    reason: String,
}

impl ClosedIssuer {
    /// An issuer that refuses every certificate, saying `reason`.
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

impl CertificateIssuer for ClosedIssuer {
    /// There is no authority key here: empty. Nothing in system mode asks
    /// (trust is the root-owned file), and an empty line can't be mistaken
    /// for a key.
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
        Err(self.reason.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"
machine = "hetzner"

[service]
account = "agent-sign"

[authority]
issuer = "openbao"
address = "https://127.0.0.1:8200"
ca_cert = "/etc/ssl/certs/ca-certificates.crt"
mount = "ssh-agents-hetzner"
role = "agent-sign-hetzner"
"#;

    fn parse(text: &str) -> Result<SystemConfig, String> {
        SystemConfig::parse(text, Path::new("/etc/agent-sign/system.toml"))
    }

    #[test]
    fn a_minimal_file_reads_with_the_designs_defaults() {
        let c = parse(GOOD).unwrap();
        assert_eq!(c.slots.count, 8);
        assert_eq!(c.service.socket, PathBuf::from(DEFAULT_SERVICE_SOCKET));
        let o = c.openbao(Path::new("/etc/agent-sign/system.toml")).unwrap();
        assert_eq!(o.mount, "ssh-agents-hetzner");
        assert_eq!(o.resolve, None);
    }

    #[test]
    fn unknown_keys_are_refused_and_named() {
        for (extra, needle) in [
            ("bogus = 1\n", "bogus"),
            ("[slots]\nbogus_slots = 1\n", "bogus_slots"),
            (
                "[security]\nmax_commits_per_minut = 5\n",
                "max_commits_per_minut",
            ),
            ("[bogus_table]\nx = 1\n", "bogus_table"),
        ] {
            // A bare key must come before the first table.
            let text = if extra.starts_with('[') {
                format!("{GOOD}\n{extra}")
            } else {
                format!("{extra}{GOOD}")
            };
            let e = parse(&text).unwrap_err();
            assert!(e.contains(needle), "{e}");
            assert!(e.contains("system.toml"), "{e}");
        }
    }

    #[test]
    fn a_missing_or_wrong_issuer_says_issuer() {
        let path = Path::new("/etc/agent-sign/system.toml");
        let none = parse("machine = \"hetzner\"\n[service]\naccount = \"a\"\n").unwrap();
        assert!(none.openbao(path).unwrap_err().contains("issuer"));
        let memory = parse(&GOOD.replace("\"openbao\"", "\"memory\"")).unwrap();
        assert!(memory.openbao(path).unwrap_err().contains("issuer"));
        let no_role = parse(&GOOD.replace("role = \"agent-sign-hetzner\"\n", "")).unwrap();
        let e = no_role.openbao(path).unwrap_err();
        assert!(e.contains("issuer") && e.contains("role"), "{e}");
    }

    #[test]
    fn the_config_comes_from_the_file_alone() {
        let text = format!("{GOOD}\n[security]\nmax_commits_per_minute = 3\n");
        let c = parse(&text)
            .unwrap()
            .to_config(Path::new("/etc/agent-sign/system.toml"))
            .unwrap();
        assert_eq!(c.security.max_commits_per_minute, 3);
        assert_eq!(c.identity.machine.as_deref(), Some("hetzner"));
    }

    #[test]
    fn the_closed_issuer_signs_nothing() {
        let issuer = ClosedIssuer::new("closed");
        let key = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
        assert_eq!(
            issuer
                .issue("a.b@hetzner.agents.local", &key.verifying_key(), 0, None)
                .unwrap_err(),
            "closed"
        );
    }
}
