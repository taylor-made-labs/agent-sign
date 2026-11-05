//! agent-sign's settings: built-in defaults, then the person's config file in
//! the state directory (`~/.agent-sign/config.toml`), then the repository's
//! `.agent-sign.toml`, then environment variables.
//!
//! A repository's file is written by whoever wrote the repository, so since
//! the identity review (28 Oct 2026) it can only tighten the person's rules
//! (see [`tighten_with_repo_file`]): before, it overlaid every table, and a
//! cloned repository could name the person, or anyone, as the author and
//! committer of commits carrying a Good agent signature. The person's own
//! file must read in full: the service refuses to start on one it can't
//! read, or on a key it doesn't know (see [`Config::check_file`]), since a
//! misspelt `approval` that fell back to the default would quietly mean no
//! approval at all.
//!
//! `[identity]` (the machine's name, the allowed agent names and the
//! people's names never allowed, see [`IdentityConfig`]) is read only from
//! the user's own file: a repository's file can't set it (it is ignored
//! there, like every table but `[security]`), since it decides whose names
//! the service certifies. `[approvals]` (the commitments approval key, see
//! [`ApprovalsConfig`]) is the same: only the user's own file sets it, since
//! it decides whose approvals the service signs on.

use crate::attribution::AttributionMode;
use crate::paths;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub attribution: AttributionConfig,
    #[serde(default)]
    pub agent: AgentConfig,
    #[serde(default)]
    pub human: HumanConfig,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub ssh: SshConfig,
    #[serde(default)]
    pub identity: IdentityConfig,
    #[serde(default)]
    pub approvals: ApprovalsConfig,
    #[serde(default)]
    pub acts: ActsConfig,
}

/// `[acts]`: signed acts ([`crate::acts`]). Off by default; read only from
/// the user's own file (a repository's `.agent-sign.toml` can't turn it on),
/// since it decides whether the service signs as the launcher at all.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ActsConfig {
    /// Whether the service signs acts: launches with `--identity`, signs for
    /// those sessions, and as the launcher.
    #[serde(default)]
    pub enabled: bool,
    /// Where the launcher's assigner key lives: `"memory"` (made anew at
    /// each start, never written anywhere; the default when acts are on) or
    /// `"openbao"` (system mode; not built in this version, so the service
    /// refuses to start with it rather than quietly use another home). No
    /// key file setting exists, and any other value stops the service.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub launcher_assigner: Option<String>,
}

impl ActsConfig {
    /// Whether these settings read: a `launcher_assigner` needs
    /// `enabled = true` and must be `memory` or `openbao`.
    pub fn check(&self) -> Result<(), String> {
        match (self.enabled, self.launcher_assigner.as_deref()) {
            (false, Some(_)) => {
                Err("[acts] launcher_assigner is set, but [acts] enabled isn't true".to_string())
            }
            (true, Some("memory" | "openbao")) | (_, None) => Ok(()),
            (true, Some(other)) => Err(format!(
                "[acts] launcher_assigner = {other:?} is not a place agent-sign keeps a key: use \"memory\" or \"openbao\" (there is no key file setting)"
            )),
        }
    }

    /// The launcher key's home when acts are on: the setting, or `memory`.
    pub fn launcher_home(&self) -> &str {
        self.launcher_assigner.as_deref().unwrap_or("memory")
    }
}

/// `[approvals]`: the suite's model layer's way to have a commit signed
/// (docs/caller-identity.md, path 1). The commitments check approves a
/// commit and signs the approval with the commitments approval key; the
/// service signs the commit as the agent the approval names only when that
/// key signed it (see [`crate::commit_approval`]). Read only from the user's
/// own `~/.agent-sign/config.toml` (or the service's `--config` file), never
/// from a repository's `.agent-sign.toml`: whoever sets this key decides
/// which commits get agents' signatures.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ApprovalsConfig {
    /// The commitments approval key's public key, one OpenSSH line
    /// (`ssh-ed25519 AAAA... [comment]`). Unset (the default) turns the
    /// approval path off: every `SignApproved` request is refused. Needs
    /// `[identity] machine`, since every approval names the machine it is
    /// for. Checked by [`ApprovalsConfig::check`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commitments_key: Option<String>,
}

impl ApprovalsConfig {
    /// Whether these settings read: no key, or exactly one plain
    /// `ssh-ed25519` public key line (not a certificate, not several keys),
    /// with `[identity] machine` (`identity`) set. A bad key stops the
    /// service at start rather than leaving the approval path quietly off.
    pub fn check(&self, identity: &IdentityConfig) -> Result<(), String> {
        let Some(line) = &self.commitments_key else {
            return Ok(());
        };
        crate::commit_approval::CommitmentsKey::parse(line)
            .map_err(|e| format!("[approvals] commitments_key: {e}"))?;
        if identity.machine.is_none() {
            return Err(
                "[approvals] commitments_key is set, but [identity] machine isn't: every commit                  approval names the machine it is for, so this machine must have a name to check                  it against"
                    .to_string(),
            );
        }
        Ok(())
    }
}

/// `[identity]`: which names this machine's agents get. Read only from the
/// user's own `~/.agent-sign/config.toml` (or the service's `--config`
/// file), never from a repository's `.agent-sign.toml`.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct IdentityConfig {
    /// This machine's name, such as "hetzner": agents' principals become
    /// `<tool>.<session8>@<machine>.agents.local`, and the service certifies
    /// only names in that domain. Unset (the default) keeps `@agents.local`.
    /// It must pass [`crate::attribution::check_machine_label`]; an empty
    /// string is an error, not "unset". Never taken from the host name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine: Option<String>,
    /// Agent names (slugs, such as "cursor" or "my-bot-2") the service
    /// certifies besides the built-in and widely used ones (see
    /// [`crate::attribution::IdentityPolicy`]). A person's own name is
    /// refused here (see [`IdentityConfig::check_against`]).
    #[serde(default)]
    pub allowed_agents: Vec<String>,
    /// People's names, such as "Taylor" or "Dana Example": no agent is ever
    /// certified under one, or under any word of one, whatever
    /// `allowed_agents` says (security review fix round, 31 Oct 2026, M2).
    /// For the people who use this machine and whose names agent-sign can't
    /// know otherwise: git's `user.name` may be an agent's, and a person may
    /// have no account here. `install.sh --person <name>` adds one. Each
    /// must pass [`check_person_name`].
    #[serde(default)]
    pub people: Vec<String>,
}

/// The longest entry of `[identity] people`, in characters.
pub const MAX_PERSON_NAME_LEN: usize = 64;

/// Whether `name` can be an entry of `[identity] people`: 1 to
/// [`MAX_PERSON_NAME_LEN`] characters, at least one ASCII letter or digit
/// once it is [`crate::attribution::normalize_name`]d (agents' names are made
/// of those, so a name without any could never match one and would protect
/// nothing; fullwidth "ＴＡＹＬＯＲ" normalises to "taylor", so it counts),
/// and no control character, `"` or `\` (so the installer can write it into
/// the file as it is). `is_valid_person_name` in scripts/install.sh is the
/// same rule without the normalising, so the installer is stricter: it
/// refuses a name whose only letters are fullwidth, which can still be
/// written into the file by hand.
pub fn check_person_name(name: &str) -> Result<(), String> {
    let ok = !name.trim().is_empty()
        && name.chars().count() <= MAX_PERSON_NAME_LEN
        && crate::attribution::normalize_name(name)
            .chars()
            .any(|c| c.is_ascii_alphanumeric())
        && !name
            .chars()
            .any(|c| c.is_control() || c == '"' || c == '\\');
    if ok {
        Ok(())
    } else {
        Err(format!(
            "[identity] people lists {name:?}, which isn't a person's name agent-sign can use: \
             use 1 to {MAX_PERSON_NAME_LEN} characters, with at least one letter a-z or digit, \
             and no quotes, backslashes or control characters (such as \"Taylor\" or \
             \"Dana Example\")"
        ))
    }
}

impl IdentityConfig {
    /// The service's and the wrapper's [`crate::attribution::IdentityPolicy`]
    /// for these settings (which must have been checked).
    /// It refuses the reserved names and every name in `people`; the service
    /// adds the configured `[human]` and the machine's people's accounts.
    pub fn policy(&self) -> crate::attribution::IdentityPolicy {
        crate::attribution::IdentityPolicy::new(self.machine.as_deref(), &self.allowed_agents)
            .with_persons(self.people_names())
            .with_person_emails(self.people_emails())
    }

    /// The entries of `people` that are email addresses (they contain an
    /// `@`), as the policy refuses them as a session's commit author. An
    /// entry that is a name gives none.
    pub fn people_emails(&self) -> Vec<crate::attribution::PersonEmail> {
        self.people
            .iter()
            .filter_map(|entry| {
                crate::attribution::PersonEmail::of(
                    entry,
                    &format!("a person's email ([identity] people lists {entry:?})"),
                )
            })
            .collect()
    }

    /// The names in `people`, as the policy refuses them.
    pub fn people_names(&self) -> Vec<crate::attribution::PersonName> {
        self.people
            .iter()
            .flat_map(|name| {
                crate::attribution::PersonName::all_of(
                    name,
                    &format!("a person's name ([identity] people lists {name:?})"),
                )
            })
            .collect()
    }

    /// The agents' domain these settings give (see
    /// [`crate::attribution::agents_domain`]).
    pub fn domain(&self) -> String {
        crate::attribution::agents_domain(self.machine.as_deref())
    }

    /// Whether these settings read: a valid machine name if one is set,
    /// every allowed agent a slug, and every person's name usable. Needs
    /// nothing but the settings, so the git wrapper can check them without
    /// running git.
    pub fn check(&self) -> Result<(), String> {
        if let Some(machine) = &self.machine {
            crate::attribution::check_machine_label(machine)?;
        }
        for slug in &self.allowed_agents {
            if !crate::attribution::is_agent_slug(slug) {
                return Err(format!(
                    "[identity] allowed_agents lists {slug:?}, which isn't an agent name: use the \
                     name's slug, 1 to 64 lowercase letters and digits in words joined by single \
                     '-' (\"My Bot 2\" is \"my-bot-2\")"
                ));
            }
        }
        for name in &self.people {
            check_person_name(name)?;
        }
        Ok(())
    }

    /// [`IdentityConfig::check`], and no allowed agent is a person's name:
    /// a reserved one ([`crate::attribution::RESERVED_PERSON_NAMES`]), a name
    /// in `people` or any word of one, or `human`'s name, any word of it, or
    /// the part of their email before the `@` (as before). An agent named
    /// after a person would get a Good signature under the person's name,
    /// which is what per-agent identities exist to prevent, so such a config
    /// is refused rather than the entry silently skipped. The service holds
    /// the same names again at each token ([`crate::attribution::IdentityPolicy::check`]),
    /// together with the machine's people's accounts.
    pub fn check_against(&self, human: &HumanConfig) -> Result<(), String> {
        self.check()?;
        let mut persons = crate::attribution::PersonName::reserved();
        persons.extend(self.people_names());
        persons.extend(crate::attribution::PersonName::of_human(
            Some(&human.name),
            Some(&human.email),
        ));
        for slug in &self.allowed_agents {
            let builtin = crate::attribution::BUILT_IN_AGENT_SLUGS.contains(&slug.as_str())
                || crate::attribution::WIDELY_USED_AGENT_SLUGS.contains(&slug.as_str());
            if builtin {
                continue;
            }
            if let Some(person) = persons.iter().find(|p| &p.slug == slug) {
                return Err(format!(
                    "[identity] allowed_agents lists {slug:?}, which is {}: agent-sign never \
                     certifies an agent under a person's name. Remove it from allowed_agents",
                    person.source
                ));
            }
        }
        Ok(())
    }

    /// The `[identity]` settings in the user's own config file in `home`
    /// (`~/.agent-sign/config.toml`), checked with [`IdentityConfig::check`],
    /// or the defaults when there is no file. Reads only that file and runs
    /// nothing, so the git wrapper can name an agent without a full
    /// [`Config::try_load`] (which runs git for the person's name). A file
    /// that can't be read or parsed is an error, never the defaults, so a
    /// broken setting can't quietly drop the machine name.
    pub fn load_user_in(home: &Path) -> Result<Self, String> {
        let path = paths::state_dir_in(home).join("config.toml");
        let content = match std::fs::read_to_string(&path) {
            Ok(content) => content,
            Err(e)
                if e.kind() == std::io::ErrorKind::NotFound
                    && std::fs::symlink_metadata(&path).is_err() =>
            {
                return Ok(Self::default());
            }
            Err(e) => return Err(format!("{}: {e}", path.display())),
        };
        let file: toml::Value =
            toml::from_str(&content).map_err(|e| format!("{}: {e}", path.display()))?;
        let identity: IdentityConfig = match file.get("identity") {
            None => Self::default(),
            Some(table) => table
                .clone()
                .try_into()
                .map_err(|e| format!("{}: [identity] can't be read: {e}", path.display()))?,
        };
        identity
            .check()
            .map_err(|e| format!("{}: {e}", path.display()))?;
        Ok(identity)
    }

    /// [`IdentityConfig::load_user_in`] for the current `HOME`.
    pub fn load_user() -> Result<Self, String> {
        Self::load_user_in(&paths::home_dir())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributionConfig {
    #[serde(default)]
    pub mode: AttributionMode,
    #[serde(default = "default_true")]
    pub include_lease_trailer: bool,
    #[serde(default = "default_true")]
    pub include_signer_trailer: bool,
}

fn default_true() -> bool {
    true
}

impl Default for AttributionConfig {
    fn default() -> Self {
        Self {
            mode: AttributionMode::default(),
            include_lease_trailer: true,
            include_signer_trailer: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    #[serde(default = "default_agent_name")]
    pub name: String,
    #[serde(default = "default_agent_email")]
    pub email: String,
}

fn default_agent_name() -> String {
    "Agent".to_string()
}

fn default_agent_email() -> String {
    "agent@local.internal".to_string()
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            name: default_agent_name(),
            email: default_agent_email(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HumanConfig {
    #[serde(default = "detect_git_user_name")]
    pub name: String,
    #[serde(default = "detect_git_user_email")]
    pub email: String,
    #[serde(default)]
    pub github_username: String,
}

// git is the real git (see paths::real_git): through PATH it could be the
// wrapper, which loads this config, which would call the wrapper again.
fn detect_git_user_name() -> String {
    let out = Command::new(paths::real_git())
        .args(["config", "--get", "user.name"])
        .output();
    if let Ok(o) = out {
        let name = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if !name.is_empty() {
            return name;
        }
    }
    "Developer".to_string()
}

fn detect_git_user_email() -> String {
    let out = Command::new(paths::real_git())
        .args(["config", "--get", "user.email"])
        .output();
    if let Ok(o) = out {
        let email = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if !email.is_empty() {
            return email;
        }
    }
    "developer@example.com".to_string()
}

impl Default for HumanConfig {
    fn default() -> Self {
        Self {
            name: detect_git_user_name(),
            email: detect_git_user_email(),
            github_username: String::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum LeaseMode {
    #[default]
    Identity,
    Timed,
    Process,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum LeaseScope {
    #[default]
    Branch,
    Repo,
}

/// Whether a lease needs anyone's approval (`[security] approval`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ApprovalMode {
    /// The service grants leases without asking, and records each grant
    /// (which identity, which repository and branch) in its log. The default:
    /// agents sign as themselves, never as the person, so there is nothing of
    /// the person's to approve.
    #[default]
    None,
    /// The device's owner approves each lease (Touch ID or the login
    /// password on macOS), as every lease needed before per-agent identities.
    DeviceOwner,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Whether leases need the device owner's approval: "none" (the default)
    /// or "device-owner".
    #[serde(default)]
    pub approval: ApprovalMode,
    #[serde(default)]
    pub lease_mode: LeaseMode,
    #[serde(default)]
    pub lease_scope: LeaseScope,
    #[serde(default = "default_lease_duration_str")]
    pub default_lease_duration: String,
    #[serde(default = "default_max_lease_ceiling")]
    pub max_lease_ceiling: String,
    /// The backstop: a lease ends after this long with no agent commit under
    /// it, such as "7d", or "none" to turn it off.
    #[serde(default = "default_end_after_idle")]
    pub end_after_idle: String,
    /// How long approval requests are held back after one is refused (Deny, a
    /// cancelled or failed Touch ID, a timeout), doubling with each refusal in
    /// a row, such as "60s"; "none" turns it off. It stops an agent from
    /// keeping a prompt coming until a reflexive touch gives in.
    #[serde(default = "default_refusal_backoff")]
    pub refusal_backoff: String,
    #[serde(default = "default_block_branches")]
    pub block_branches: Vec<String>,
    #[serde(default)]
    pub allow_main_branch: bool,
    /// Whether a lease follows the agent from branch to branch. Off by
    /// default: the narrowest approval, one branch of one repository, is the
    /// safe one, and the approval prompt says exactly that. Turn it on (or
    /// set `lease_scope = "repo"`) to approve a repository's unprotected
    /// branches at once.
    #[serde(default)]
    pub allow_branch_switching: bool,
    #[serde(default = "default_max_commits_per_minute")]
    pub max_commits_per_minute: u32,
    #[serde(default)]
    pub auto_approve: bool,
    #[serde(default = "default_forbidden_paths")]
    pub forbidden_paths: Vec<String>,
    #[serde(default = "default_max_diff_lines")]
    pub max_diff_lines: usize,
    #[serde(default)]
    pub enforce_conventional_commits: bool,
    /// Written by installers before 30 Sept 2026 and no longer used: every
    /// lease now ends when its branch is merged or deleted. Accepted, so an
    /// existing config still starts the service, and never written back.
    #[serde(default, skip_serializing)]
    pub auto_revoke_on_branch_delete: Option<bool>,
    /// The branches a repository's `.agent-sign.toml` added to
    /// `block_branches` (see [`tighten_with_repo_file`]). The service never
    /// reads repository files, so the wrapper refuses these itself; the
    /// person's own list is the service's to enforce (it may be set on the
    /// service's command line). Never read from or written to a file.
    #[serde(skip)]
    pub repo_block_branches: Vec<String>,
}

fn default_lease_duration_str() -> String {
    "2h".to_string()
}

fn default_max_lease_ceiling() -> String {
    "none".to_string()
}

/// A week without agent commits: long enough for work that pauses over a
/// weekend, short enough that a forgotten approval doesn't stay open.
fn default_end_after_idle() -> String {
    "7d".to_string()
}

fn default_refusal_backoff() -> String {
    "60s".to_string()
}

fn default_block_branches() -> Vec<String> {
    vec!["main".to_string(), "master".to_string()]
}

fn default_max_commits_per_minute() -> u32 {
    10
}

fn default_forbidden_paths() -> Vec<String> {
    vec![
        ".github/workflows/*".to_string(),
        ".circleci/*".to_string(),
        "*.pem".to_string(),
        "*.key".to_string(),
        "id_rsa*".to_string(),
        "id_ed25519*".to_string(),
    ]
}

/// No limit (0). Nothing about signing limits a commit's size, and a fixed
/// limit refused ordinary work such as a generated lockfile. A person who
/// wants a guard against runaway commits can set one.
fn default_max_diff_lines() -> usize {
    0
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            approval: ApprovalMode::default(),
            lease_mode: LeaseMode::default(),
            lease_scope: LeaseScope::default(),
            default_lease_duration: default_lease_duration_str(),
            max_lease_ceiling: default_max_lease_ceiling(),
            end_after_idle: default_end_after_idle(),
            refusal_backoff: default_refusal_backoff(),
            block_branches: default_block_branches(),
            allow_main_branch: false,
            allow_branch_switching: false,
            max_commits_per_minute: default_max_commits_per_minute(),
            auto_approve: false,
            forbidden_paths: default_forbidden_paths(),
            max_diff_lines: default_max_diff_lines(),
            enforce_conventional_commits: false,
            auto_revoke_on_branch_delete: None,
            repo_block_branches: Vec::new(),
        }
    }
}

impl SecurityConfig {
    pub fn lease_duration(&self) -> Duration {
        parse_duration_string(&self.default_lease_duration).unwrap_or(Duration::from_secs(7200))
    }

    /// The longest a lifetime (`identity`) lease may last, or `None` for no
    /// ceiling ("none" or empty). A value that isn't a duration is an error,
    /// not "no ceiling": the person meant to bound leases, so the service
    /// refuses to start rather than silently leave them unbounded.
    /// The idle backstop (`end_after_idle`), or `None` when it's "none". As
    /// with the ceiling, a value that isn't a duration stops the service
    /// rather than silently leaving leases without the backstop.
    pub fn idle_limit_duration(&self) -> Result<Option<Duration>, String> {
        let s = self.end_after_idle.trim();
        if s.is_empty() || s.eq_ignore_ascii_case("none") {
            Ok(None)
        } else {
            parse_duration_string(s).map(Some).ok_or_else(|| {
                format!(
                    "end_after_idle = \"{}\" is not a duration; use a number with s, m, h or d (for example \"7d\"), or \"none\"",
                    s
                )
            })
        }
    }

    /// The hold-back after a refused approval (`refusal_backoff`); zero when
    /// it's "none". A value that isn't a duration stops the service, as the
    /// other duration settings do, rather than silently turning the guard off.
    pub fn refusal_backoff_duration(&self) -> Result<Duration, String> {
        let s = self.refusal_backoff.trim();
        if s.is_empty() || s.eq_ignore_ascii_case("none") {
            Ok(Duration::ZERO)
        } else {
            parse_duration_string(s).ok_or_else(|| {
                format!(
                    "refusal_backoff = \"{}\" is not a duration; use a number with s, m, h or d (for example \"60s\"), or \"none\"",
                    s
                )
            })
        }
    }

    pub fn max_ceiling_duration(&self) -> Result<Option<Duration>, String> {
        let s = self.max_lease_ceiling.trim();
        if s.is_empty() || s.eq_ignore_ascii_case("none") {
            Ok(None)
        } else {
            parse_duration_string(s).map(Some).ok_or_else(|| {
                format!(
                    "max_lease_ceiling = \"{}\" is not a duration; use a number with s, m, h or d (for example \"7d\"), or \"none\"",
                    s
                )
            })
        }
    }
}

pub fn parse_duration_string(s: &str) -> Option<Duration> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if let Some(val) = s.strip_suffix('h') {
        val.parse::<u64>()
            .ok()
            .and_then(|h| h.checked_mul(3600))
            .map(Duration::from_secs)
    } else if let Some(val) = s.strip_suffix('m') {
        val.parse::<u64>()
            .ok()
            .and_then(|m| m.checked_mul(60))
            .map(Duration::from_secs)
    } else if let Some(val) = s.strip_suffix('s') {
        val.parse::<u64>().ok().map(Duration::from_secs)
    } else if let Some(val) = s.strip_suffix('d') {
        val.parse::<u64>()
            .ok()
            .and_then(|d| d.checked_mul(86400))
            .map(Duration::from_secs)
    } else {
        s.parse::<u64>().ok().map(Duration::from_secs)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshConfig {
    #[serde(default = "default_ssh_keygen")]
    pub fallback_program: String,
    #[serde(default = "default_key_path")]
    pub agent_key_path: PathBuf,
}

fn default_ssh_keygen() -> String {
    "/usr/bin/ssh-keygen".to_string()
}

fn default_key_path() -> PathBuf {
    key_path_in(&paths::home_dir())
}

/// The default agent key path for a home: `<state dir>/keys/agent_ed25519`.
fn key_path_in(home: &Path) -> PathBuf {
    paths::state_dir_in(home).join("keys/agent_ed25519")
}

impl Default for SshConfig {
    fn default() -> Self {
        Self {
            fallback_program: default_ssh_keygen(),
            agent_key_path: default_key_path(),
        }
    }
}

fn merge_toml(base: &mut toml::Value, overlay: toml::Value) {
    if let (toml::Value::Table(base_table), toml::Value::Table(overlay_table)) = (base, overlay) {
        for (k, v) in overlay_table {
            if let Some(existing) = base_table.get_mut(&k) {
                if existing.is_table() && v.is_table() {
                    merge_toml(existing, v);
                } else {
                    *existing = v;
                }
            } else {
                base_table.insert(k, v);
            }
        }
    }
}

/// Keys an older installer wrote that this version accepts but no longer
/// uses, by table: an existing config must keep starting the service (see
/// [`Config::check_file`]). Every key any version of `scripts/install.sh`
/// has written is either a field of [`Config`] or listed here.
const RETIRED_KEYS: &[(&str, &str)] = &[("security", "auto_revoke_on_branch_delete")];

/// Keys [`Config`] reads that its defaults leave out (an unset `Option`
/// isn't serialized), by table, so [`known_keys`] still knows them.
const OPTIONAL_KEYS: &[(&str, &str)] = &[
    ("identity", "machine"),
    ("approvals", "commitments_key"),
    ("acts", "launcher_assigner"),
];

/// Every table and key [`Config`] reads, from its own defaults (each field
/// serializes, so none is missed), plus [`RETIRED_KEYS`] and
/// [`OPTIONAL_KEYS`].
fn known_keys() -> Vec<(String, Vec<String>)> {
    let defaults = toml::Value::try_from(Config::default())
        .unwrap_or(toml::Value::Table(toml::map::Map::new()));
    let mut known: Vec<(String, Vec<String>)> = defaults
        .as_table()
        .map(|t| {
            t.iter()
                .map(|(table, keys)| {
                    let keys = keys
                        .as_table()
                        .map(|k| k.keys().cloned().collect())
                        .unwrap_or_default();
                    (table.clone(), keys)
                })
                .collect()
        })
        .unwrap_or_default();
    for (table, key) in RETIRED_KEYS.iter().chain(OPTIONAL_KEYS) {
        if let Some((_, keys)) = known.iter_mut().find(|(t, _)| t == table) {
            keys.push(key.to_string());
        }
    }
    known
}

/// The first table or key in `file` that [`Config`] doesn't read, in plain
/// words, or `None` when every one is known. A key in the wrong table says
/// where it belongs.
fn unknown_key(file: &toml::Value) -> Option<String> {
    let known = known_keys();
    let belongs = |key: &str| {
        known
            .iter()
            .find(|(_, keys)| keys.iter().any(|k| k == key))
            .map(|(t, _)| format!(" (it belongs under [{t}])"))
            .unwrap_or_default()
    };
    for (name, value) in file.as_table()? {
        let Some((_, keys)) = known.iter().find(|(t, _)| t == name) else {
            return Some(if value.is_table() {
                format!("an unknown table [{name}]")
            } else {
                format!("the key `{name}` outside any table{}", belongs(name))
            });
        };
        let Some(table) = value.as_table() else {
            return Some(format!("`{name}`, which should be a table [{name}]"));
        };
        for key in table.keys() {
            if !keys.iter().any(|k| k == key) {
                return Some(format!(
                    "an unknown key `{key}` in [{name}]{}",
                    belongs(key)
                ));
            }
        }
    }
    None
}

/// Applies a repository's `.agent-sign.toml` (`file`, parsed) to `config`,
/// keeping only what tightens the `[security]` rules:
/// - `forbidden_paths` and `block_branches` entries are added to the
///   person's, never replacing them;
/// - `max_diff_lines` applies only when lower (0 means no limit, so any
///   limit is lower).
///
/// Everything else (`[attribution]`, `[agent]`, `[human]`, `[ssh]`,
/// `[identity]`, any other `[security]` key, or a value of the wrong type) is ignored and
/// named in the returned list, which the caller reports in one warning.
/// That includes `max_commits_per_minute`: the rate is counted by the
/// service, which reads only the person's own config, so a lower value here
/// could never be enforced, and taking it would only look as if it were
/// (follow-up round, 28 Oct 2026).
/// Whoever wrote the repository is not the person: before the identity
/// review its file overlaid every table, so it could loosen the rules or
/// name anyone as an agent commit's author and committer.
pub fn tighten_with_repo_file(config: &mut Config, file: &toml::Value) -> Vec<String> {
    let mut ignored = Vec::new();
    let Some(tables) = file.as_table() else {
        return ignored;
    };
    let strings = |v: &toml::Value| -> Option<Vec<String>> {
        v.as_array()?
            .iter()
            .map(|e| e.as_str().map(str::to_string))
            .collect()
    };
    for (name, value) in tables {
        let Some(security) = value.as_table().filter(|_| name == "security") else {
            ignored.push(format!("[{name}]"));
            continue;
        };
        for (key, value) in security {
            let sec = &mut config.security;
            let applied = match key.as_str() {
                "forbidden_paths" => strings(value).map(|more| {
                    for p in more {
                        if !sec.forbidden_paths.contains(&p) {
                            sec.forbidden_paths.push(p);
                        }
                    }
                }),
                "block_branches" => strings(value).map(|more| {
                    for b in more {
                        if !sec.block_branches.contains(&b) {
                            sec.block_branches.push(b.clone());
                        }
                        sec.repo_block_branches.push(b);
                    }
                }),
                "max_diff_lines" => value
                    .as_integer()
                    .and_then(|n| usize::try_from(n).ok())
                    .map(|n| {
                        if n > 0 && (sec.max_diff_lines == 0 || n < sec.max_diff_lines) {
                            sec.max_diff_lines = n;
                        }
                    }),
                _ => None,
            };
            if applied.is_none() {
                ignored.push(format!("[security] {key}"));
            }
        }
    }
    ignored
}

/// The `[human]` name and email the config file at `path` sets itself, if
/// it sets them: unlike [`HumanConfig`], never git's `user.name` and
/// `user.email`, which it falls back to. The service refuses these as agents'
/// names (see [`crate::attribution::PersonName::of_human`]); a person's name
/// that would come from git is never relied on, because on a machine whose
/// agents set `user.name` themselves git names no person (M2, 31 Oct 2026).
/// A file that is missing or can't be read sets nothing (the service has
/// already checked it at start).
pub fn human_set_in_file(path: &Path) -> (Option<String>, Option<String>) {
    let Some(file) = std::fs::read_to_string(path)
        .ok()
        .and_then(|c| toml::from_str::<toml::Value>(&c).ok())
    else {
        return (None, None);
    };
    let get = |key: &str| {
        file.get("human")
            .and_then(|h| h.get(key))
            .and_then(|v| v.as_str())
            .filter(|v| !v.trim().is_empty())
            .map(str::to_string)
    };
    (get("name"), get("email"))
}

impl Config {
    /// The config in an explicit file (`agent-signd --config`): it must
    /// exist and pass [`Config::check_file`].
    pub fn load_from_file(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        if std::fs::symlink_metadata(path).is_err() {
            return Err(format!("{} doesn't exist", path.display()).into());
        }
        Self::check_file(path)?;
        let content = std::fs::read_to_string(path)?;
        let parsed: toml::Value = toml::from_str(&content)?;
        if let Some(what) = unknown_key(&parsed) {
            return Err(format!("{} has {what}", path.display()).into());
        }
        let config: Config = parsed.try_into()?;
        config.validate_selected_security()?;
        config.identity.check_against(&config.human)?;
        config.approvals.check(&config.identity)?;
        config.acts.check()?;
        Ok(config)
    }

    /// Hierarchical config loading for the current `HOME`:
    /// 1. Default built-in configs
    /// 2. Deep-merged with `<state dir>/config.toml` (if present), where the
    ///    state dir is `~/.agent-sign`
    /// 3. Tightened by `<repo_root>/.agent-sign.toml` (if present), see
    ///    [`tighten_with_repo_file`]
    /// 4. Overlaid with environment variables (`AGENT_SIGN_*`)
    pub fn load(repo_path: Option<&Path>) -> Self {
        Self::load_in_home(&paths::home_dir(), repo_path)
    }

    pub fn validate_selected_security(&self) -> Result<(), String> {
        if parse_duration_string(&self.security.default_lease_duration).is_none() {
            return Err("default_lease_duration is not a valid duration".into());
        }
        self.security.max_ceiling_duration()?;
        self.security.idle_limit_duration()?;
        self.security.refusal_backoff_duration()?;
        Ok(())
    }

    /// Production callers must distinguish missing settings from failed loading.
    pub fn try_load(repo_path: Option<&Path>) -> Result<Self, String> {
        Self::try_load_in_home(&paths::home_dir(), repo_path)
    }

    /// Reload the explicitly selected service config, then apply only the
    /// repository's permitted tightening rules. No selected-file failure falls
    /// back to defaults.
    pub fn try_load_selected(file: Option<&Path>, repo: Option<&Path>) -> Result<Self, String> {
        let mut config = match file {
            Some(file) => Self::load_from_file(file).map_err(|e| e.to_string())?,
            None => Self::try_load(None)?,
        };
        if let Some(repo) = repo {
            config.tighten_repository(repo)?;
        }
        Ok(config)
    }

    pub fn tighten_repository(&mut self, repo: &Path) -> Result<(), String> {
        for name in paths::REPO_CONFIG_FILES {
            let file = repo.join(name);
            let content = match std::fs::read_to_string(&file) {
                Ok(content) => content,
                Err(e)
                    if e.kind() == std::io::ErrorKind::NotFound
                        && std::fs::symlink_metadata(&file).is_err() =>
                {
                    continue;
                }
                Err(e) => {
                    return Err(format!(
                        "couldn't read selected policy {}: {e}",
                        file.display()
                    ));
                }
            };
            let overlay = toml::from_str::<toml::Value>(&content)
                .map_err(|e| format!("selected policy {} is invalid: {e}", file.display()))?;
            if let Some(security) = overlay.get("security") {
                let table = security
                    .as_table()
                    .ok_or("selected [security] policy must be a table")?;
                for name in ["forbidden_paths", "block_branches"] {
                    if let Some(value) = table.get(name)
                        && !value
                            .as_array()
                            .is_some_and(|items| items.iter().all(|v| v.as_str().is_some()))
                    {
                        return Err(format!(
                            "selected policy {}: {name} must be an array of strings",
                            file.display()
                        ));
                    }
                }
                if let Some(value) = table.get("max_diff_lines")
                    && !value
                        .as_integer()
                        .is_some_and(|n| usize::try_from(n).is_ok())
                {
                    return Err(format!(
                        "selected policy {}: max_diff_lines must be a nonnegative integer",
                        file.display()
                    ));
                }
            }
            let ignored = tighten_with_repo_file(self, &overlay);
            if !ignored.is_empty() {
                eprintln!(
                    "[agent-sign] {}: ignored {}: a repository's file can only add forbidden_paths and block_branches, or lower max_diff_lines",
                    file.display(),
                    ignored.join(", ")
                );
            }
        }
        Ok(())
    }

    /// Whether the person's config file in `home` (if there is one) reads as
    /// a valid config: [`Config::check_file`] on `~/.agent-sign/config.toml`.
    pub fn check_file_in_home(home: &Path) -> Result<(), String> {
        Self::check_file(&paths::state_dir_in(home).join("config.toml"))
    }

    /// Whether the person's config file at `path` reads in full. Only "not
    /// found" means there is no config; anything else that stops it being
    /// read (its permissions, a link to nothing, a directory), a key or
    /// table agent-sign doesn't know (a misspelt or misplaced `approval`), or
    /// a value it can't read is an error that names the file. [`Config::load`]
    /// falls back to the defaults in those cases, which for a security
    /// setting would quietly loosen it (the default approval is "none"), so
    /// the service checks this first and refuses to start instead.
    pub fn check_file(path: &Path) -> Result<(), String> {
        let content = match std::fs::read_to_string(path) {
            Ok(content) => content,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // A link whose target is missing reads as "not found" too,
                // but the person meant to have a config there.
                if std::fs::symlink_metadata(path).is_ok() {
                    return Err(format!(
                        "{} is a link to a file that doesn't exist; point it at your config or remove it",
                        path.display()
                    ));
                }
                return Ok(());
            }
            Err(e) => {
                return Err(format!(
                    "{} exists but can't be read ({e}); fix its permissions, or move it aside to use the defaults",
                    path.display()
                ));
            }
        };
        let overlay: toml::Value = toml::from_str(&content)
            .map_err(|e| format!("{} isn't valid TOML: {e}", path.display()))?;
        if let Some(what) = unknown_key(&overlay) {
            return Err(format!(
                "{} has {what}, which agent-sign doesn't read; fix the spelling or remove it",
                path.display()
            ));
        }
        let mut defaults = Config::default();
        if let Some(home) = path.parent().and_then(Path::parent) {
            defaults.ssh.agent_key_path = key_path_in(home);
        }
        let mut base: toml::Value = toml::Value::try_from(&defaults)
            .map_err(|e| format!("the built-in defaults don't serialize: {e}"))?;
        merge_toml(&mut base, overlay);
        base.try_into::<Config>().map(|_| ()).map_err(|e| {
            format!(
                "{} has a setting agent-sign can't read: {e}",
                path.display()
            )
        })
    }

    /// [`Config::load`] for an explicit home directory, so loading can be
    /// tested against temporary homes without changing the process's `HOME`.
    pub fn load_in_home(home: &Path, repo_path: Option<&Path>) -> Self {
        Self::try_load_in_home(home, repo_path).unwrap_or_default()
    }

    pub fn try_load_in_home(home: &Path, repo_path: Option<&Path>) -> Result<Self, String> {
        Self::check_file_in_home(home)?;
        let mut defaults = Config::default();
        defaults.ssh.agent_key_path = key_path_in(home);
        let default_str = toml::to_string(&defaults).unwrap_or_default();
        let mut base_val: toml::Value = toml::from_str(&default_str)
            .unwrap_or_else(|_| toml::Value::Table(toml::map::Map::new()));

        // Only an absent file selects defaults; read/parse races still fail.
        let global_config = paths::state_dir_in(home).join("config.toml");
        match std::fs::read_to_string(&global_config) {
            Ok(content) => {
                let overlay = toml::from_str::<toml::Value>(&content)
                    .map_err(|e| format!("{}: {e}", global_config.display()))?;
                if let Some(what) = unknown_key(&overlay) {
                    return Err(format!("{} has {what}", global_config.display()));
                }
                merge_toml(&mut base_val, overlay);
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::NotFound
                    && std::fs::symlink_metadata(&global_config).is_err() => {}
            Err(e) => return Err(format!("{}: {e}", global_config.display())),
        }
        let mut config: Config = base_val
            .try_into()
            .map_err(|e| format!("invalid selected config: {e}"))?;
        if let Some(repo) = repo_path {
            config.tighten_repository(repo)?;
        }

        // 3. Environment overrides
        if let Some(val) = paths::env_var("ALLOW_MAIN") {
            config.security.allow_main_branch = val == "1" || val.eq_ignore_ascii_case("true");
        }

        if let Some(val) = paths::env_var("AUTO_APPROVE") {
            config.security.auto_approve = val == "1" || val.eq_ignore_ascii_case("true");
        }

        if let Some(val) = paths::env_var("LEASE_MODE") {
            match val.to_lowercase().as_str() {
                "identity" => config.security.lease_mode = LeaseMode::Identity,
                "timed" => config.security.lease_mode = LeaseMode::Timed,
                "process" => config.security.lease_mode = LeaseMode::Process,
                _ => {}
            }
        }

        if let Some(val) = paths::env_var("LEASE_SCOPE") {
            match val.to_lowercase().as_str() {
                "branch" => config.security.lease_scope = LeaseScope::Branch,
                "repo" => config.security.lease_scope = LeaseScope::Repo,
                _ => {}
            }
        }

        if let Some(val) = paths::env_var("MAX_LEASE_CEILING") {
            config.security.max_lease_ceiling = val;
        }

        if let Some(val) = paths::env_var("END_AFTER_IDLE") {
            config.security.end_after_idle = val;
        }

        if let Some(val) = paths::env_var("REFUSAL_BACKOFF") {
            config.security.refusal_backoff = val;
        }

        if let Some(val) = paths::env_var("MODE") {
            match val.to_lowercase().as_str() {
                "agent" => config.attribution.mode = AttributionMode::Agent,
                "split" => config.attribution.mode = AttributionMode::Split,
                "trailers" => config.attribution.mode = AttributionMode::Trailers,
                "alias" => config.attribution.mode = AttributionMode::Alias,
                _ => {}
            }
        }

        if let Some(val) = paths::env_var("FALLBACK_PROGRAM")
            && !val.trim().is_empty()
        {
            config.ssh.fallback_program = val;
        }

        config.validate_selected_security()?;
        config.identity.check_against(&config.human)?;
        config.approvals.check(&config.identity)?;
        config.acts.check()?;
        Ok(config)
    }
}

#[cfg(test)]
mod identity_config_tests {
    use super::*;

    fn human(name: &str, email: &str) -> HumanConfig {
        HumanConfig {
            name: name.to_string(),
            email: email.to_string(),
            github_username: String::new(),
        }
    }

    fn listing(slugs: &[&str]) -> IdentityConfig {
        IdentityConfig {
            machine: None,
            allowed_agents: slugs.iter().map(|s| s.to_string()).collect(),
            people: Vec::new(),
        }
    }

    #[test]
    fn a_persons_own_name_is_never_an_allowed_agent() {
        let dana = human("Dana Example", "dee@example.com");
        assert!(
            listing(&["cursor", "my-bot-2"])
                .check_against(&dana)
                .is_ok()
        );
        for slug in ["dana-example", "dana", "dee"] {
            let e = listing(&[slug]).check_against(&dana).unwrap_err();
            assert!(e.contains("allowed_agents"), "{e}");
        }
        assert!(listing(&["My Bot"]).check().is_err());
    }

    /// M2 (31 Oct 2026): the reserved names and the people listed are
    /// refused with a [human] that names nobody in particular, and the
    /// people's names must be usable.
    #[test]
    fn reserved_names_and_listed_people_are_never_allowed_agents() {
        let agent_git = human("work-loop agent on hetzner", "agent@example.com");
        for slug in ["root", "admin", "administrator"] {
            let e = listing(&[slug]).check_against(&agent_git).unwrap_err();
            assert!(e.contains("allowed_agents") && e.contains(slug), "{e}");
        }
        let mut with_people = listing(&["taylor"]);
        assert!(with_people.check_against(&agent_git).is_ok());
        with_people.people = vec!["Taylor".to_string()];
        let e = with_people.check_against(&agent_git).unwrap_err();
        assert!(e.contains("allowed_agents") && e.contains("taylor"), "{e}");
        // The tools' own names stay allowed.
        with_people.allowed_agents = vec!["cursor".to_string()];
        with_people.people = vec!["Cursor Person".to_string()];
        assert!(with_people.check_against(&agent_git).is_ok());
        for bad in [
            "",
            "   ",
            "李明",
            "Ta\"ylor",
            "a\\b",
            "line\nbreak",
            "x".repeat(65).as_str(),
        ] {
            let mut config = listing(&[]);
            config.people = vec![bad.to_string()];
            let e = config.check().unwrap_err();
            assert!(e.contains("people"), "{bad:?}: {e}");
        }
    }

    #[test]
    fn the_human_set_in_a_file_is_only_what_the_file_says() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("config.toml");
        assert_eq!(human_set_in_file(&file), (None, None));
        std::fs::write(&file, "[identity]\nallowed_agents = []\n").unwrap();
        assert_eq!(human_set_in_file(&file), (None, None));
        std::fs::write(&file, "[human]\nname = \"Dana Example\"\n").unwrap();
        assert_eq!(
            human_set_in_file(&file),
            (Some("Dana Example".to_string()), None)
        );
    }

    #[test]
    fn identity_is_read_from_the_users_file_and_an_empty_machine_is_an_error() {
        let home = tempfile::tempdir().unwrap();
        let dir = paths::state_dir_in(home.path());
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(
            IdentityConfig::load_user_in(home.path()).unwrap(),
            IdentityConfig::default()
        );
        std::fs::write(dir.join("config.toml"), "[identity]\nmachine = \"pi\"\n").unwrap();
        let settings = IdentityConfig::load_user_in(home.path()).unwrap();
        assert_eq!(settings.domain(), "pi.agents.local");
        assert!(Config::check_file(&dir.join("config.toml")).is_ok());
        std::fs::write(dir.join("config.toml"), "[identity]\nmachine = \"\"\n").unwrap();
        let e = IdentityConfig::load_user_in(home.path()).unwrap_err();
        assert!(e.contains("machine"), "{e}");
    }

    #[test]
    fn a_repository_file_cant_set_identity() {
        let mut config = Config::default();
        let file: toml::Value =
            toml::from_str("[identity]\nmachine = \"evil\"\nallowed_agents = [\"taylor\"]\n")
                .unwrap();
        let ignored = tighten_with_repo_file(&mut config, &file);
        assert_eq!(ignored, ["[identity]"]);
        assert_eq!(config.identity, IdentityConfig::default());
    }

    /// The commitments approval key's public line, from a fixed seed.
    fn commitments_line() -> String {
        let key = ed25519_dalek::SigningKey::from_bytes(&[21u8; 32]);
        crate::crypto::openssh_ed25519_line(&key.verifying_key())
    }

    #[test]
    fn the_approvals_table_is_read_from_the_users_file_and_checked() {
        let home = tempfile::tempdir().unwrap();
        let dir = paths::state_dir_in(home.path());
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("config.toml");
        let line = commitments_line();
        std::fs::write(
            &file,
            format!("[identity]\nmachine = \"hetzner\"\n[approvals]\ncommitments_key = \"{line} commitments\"\n"),
        )
        .unwrap();
        Config::check_file(&file).unwrap();
        let config = Config::load_from_file(&file).unwrap();
        assert_eq!(
            config.approvals.commitments_key.as_deref(),
            Some(format!("{line} commitments").as_str())
        );

        let refused = [
            ("no machine", format!("[approvals]\ncommitments_key = \"{line}\"\n")),
            (
                "not a key",
                "[identity]\nmachine = \"hetzner\"\n[approvals]\ncommitments_key = \"ssh-ed25519 nope\"\n".to_string(),
            ),
            (
                "two keys",
                format!("[identity]\nmachine = \"hetzner\"\n[approvals]\ncommitments_key = \"{line}\\n{line}\"\n"),
            ),
            (
                "an unknown key",
                format!("[identity]\nmachine = \"hetzner\"\n[approvals]\nkey = \"{line}\"\n"),
            ),
        ];
        for (what, content) in refused {
            std::fs::write(&file, content).unwrap();
            assert!(Config::load_from_file(&file).is_err(), "{what}");
        }
    }

    #[test]
    fn a_repository_file_cant_set_the_approval_key() {
        let mut config = Config::default();
        let file: toml::Value = toml::from_str(&format!(
            "[approvals]\ncommitments_key = \"{}\"\n",
            commitments_line()
        ))
        .unwrap();
        let ignored = tighten_with_repo_file(&mut config, &file);
        assert_eq!(ignored, ["[approvals]"]);
        assert_eq!(config.approvals, ApprovalsConfig::default());
    }
}
