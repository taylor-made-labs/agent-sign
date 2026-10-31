//! Who an agent commit is attributed to, and who signs it.
//!
//! Each agent gets its own identity, read only from the environment the agent
//! itself sets (positive evidence: Claude Code's `CLAUDECODE`, Codex's
//! session or thread id, Gemini CLI's `GEMINI_CLI`, or an explicit
//! `AGENT_SIGN_AGENT_NAME`). No config file can change an identity, so a
//! cloned repository's `.agent-sign.toml` can't make agent work look like
//! someone else's. The identity's principal, `<tool>.<session8>@agents.local`,
//! is the email on the agent's commits and the principal of the certificate
//! the service signs them with (see [`crate::agents_ca`]).
//!
//! Two settings in the user's own config (`[identity]`, never a
//! repository's file) shape this (plan "next: real use on servers", 30 Oct
//! 2026):
//! - `machine`: an optional name for this machine. With it the principal is
//!   `<tool>.<session8>@<machine>.agents.local` ([`agents_domain`]), so an
//!   agent's name says where it ran, and each machine's trust line covers
//!   only its own agents. Without it everything stays `@agents.local`, as
//!   before, so existing installs are unchanged.
//! - `allowed_agents`: the agent names the service will certify besides the
//!   built-in ones ([`IdentityPolicy`]). Before, any well-formed name got a
//!   certificate, so an agent could name itself after the person (`taylor`)
//!   and get a Good signature under that name.
//!
//! These are claims made by processes running as the same user as the
//! person: attribution, not a security boundary, until agents run under
//! their own OS accounts.

use crate::config::{AgentConfig, AttributionConfig, HumanConfig};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AttributionMode {
    /// Author and committer are both the agent's own identity (its display
    /// name and principal). The default.
    #[default]
    Agent,
    /// Before the identity review (28 Oct 2026): author the configured
    /// agent, committer the person. Now the same as `Agent`: a signed agent
    /// commit carries only the agent's identity. Kept so configs that name
    /// it still load.
    Split,
    /// The agent's identity as author and committer, as in `Agent`, plus
    /// `Co-Authored-By` and `X-Agent-*` trailers on a `-m` message. (Before
    /// the identity review the author and committer were the person.)
    Trailers,
    /// Before the identity review: "<person> (Agent)" with the configured
    /// agent email. Now the same as `Agent`; kept so configs still load.
    Alias,
}

/// The domain every agent principal is in when no machine is named. The
/// trust line (`agent-sign trust-line`) trusts the agents' certificate
/// authority for `*@agents.local` only, so a certificate can never vouch for
/// a real email. A named machine's agents are in a sub-domain of it (see
/// [`agents_domain`]).
pub const AGENTS_DOMAIN: &str = "agents.local";

/// The longest machine name: one DNS label.
pub const MAX_MACHINE_LEN: usize = 63;

/// The domain this machine's agents are in: `<machine>.agents.local` when the
/// user's config names the machine (`[identity] machine`), else
/// [`AGENTS_DOMAIN`]. The machine must already have passed
/// [`check_machine_label`].
pub fn agents_domain(machine: Option<&str>) -> String {
    match machine {
        Some(machine) => format!("{machine}.{AGENTS_DOMAIN}"),
        None => AGENTS_DOMAIN.to_string(),
    }
}

/// Whether `label` may name a machine: `^[a-z0-9]+(-[a-z0-9]+)*$`, at most
/// [`MAX_MACHINE_LEN`] characters. No `@` or `.`, because OpenSSH's `*` in an
/// allowed-signers line also matches `@` and `.`, so either would let one
/// machine's trust line reach another domain; and an empty name is an error,
/// not "no machine" (leave the setting out for that). The message names the
/// setting, so the user knows what to fix. A machine name is never taken
/// from the host's own name: host names often break these rules
/// (`ubuntu-16gb-hel1-1` doesn't, `MacBook-Pro.local` does) and can change.
pub fn check_machine_label(label: &str) -> Result<(), String> {
    if label.len() > MAX_MACHINE_LEN || !is_slug(label) {
        return Err(format!(
            "[identity] machine = {label:?} isn't a valid machine name: use 1 to {MAX_MACHINE_LEN} \
             lowercase letters and digits, in words joined by single '-' (such as \"hetzner\" or \"my-box-2\"), \
             or leave machine out"
        ));
    }
    Ok(())
}

/// The slugs of the agents [`identify_agent_with`] recognizes by their own
/// marks. They always get certificates.
pub const BUILT_IN_AGENT_SLUGS: &[&str] = &["claude-code", "codex", "gemini-cli"];

/// Widely used agent tools that have no mark of their own, so their users
/// name them with `AGENT_SIGN_AGENT_NAME`: allowed by default, so those users
/// need no setting (Aider and Antigravity have guides in
/// `docs/integrations`). Any other name, such as "My Bot 2" (`my-bot-2`),
/// must be listed in `[identity] allowed_agents` first.
pub const WIDELY_USED_AGENT_SLUGS: &[&str] = &[
    "aider",
    "antigravity",
    "cline",
    "copilot",
    "cursor",
    "opencode",
    "windsurf",
];

/// Which identities the service certifies: the machine's domain, and the
/// agent names allowed in it. Built from the user's own config by the
/// service (which is authoritative) and the git wrapper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityPolicy {
    /// [`agents_domain`] for the configured machine.
    pub domain: String,
    /// `[identity] allowed_agents`: slugs allowed besides
    /// [`BUILT_IN_AGENT_SLUGS`] and [`WIDELY_USED_AGENT_SLUGS`].
    pub allowed_agents: Vec<String>,
}

impl Default for IdentityPolicy {
    /// No machine and nothing listed: `@agents.local`, built-in and widely
    /// used agents only.
    fn default() -> Self {
        Self {
            domain: AGENTS_DOMAIN.to_string(),
            allowed_agents: Vec::new(),
        }
    }
}

impl IdentityPolicy {
    /// The policy for a machine (already checked) and a list of allowed slugs.
    pub fn new(machine: Option<&str>, allowed_agents: &[String]) -> Self {
        Self {
            domain: agents_domain(machine),
            allowed_agents: allowed_agents.to_vec(),
        }
    }

    /// Whether `slug` is an agent name this policy certifies.
    pub fn allows_slug(&self, slug: &str) -> bool {
        BUILT_IN_AGENT_SLUGS.contains(&slug)
            || WIDELY_USED_AGENT_SLUGS.contains(&slug)
            || self.allowed_agents.iter().any(|a| a == slug)
    }

    /// Whether the service may certify `identity`: its principal is in this
    /// machine's domain (not another machine's, and not plain
    /// `@agents.local` once a machine is named), it is well formed
    /// ([`AgentIdentity::check_in`]), and its slug is allowed. Each refusal
    /// says which setting decides it.
    pub fn check(&self, identity: &AgentIdentity) -> Result<(), String> {
        let domain = identity
            .principal
            .rsplit_once('@')
            .map(|(_, d)| d)
            .unwrap_or("");
        if domain != self.domain {
            return Err(format!(
                "agent identity refused: {} is not in this machine's agents' domain @{} \
                 (set by [identity] machine in agent-sign's config.toml); the git wrapper and \
                 the service must read the same machine setting",
                identity.principal, self.domain
            ));
        }
        identity.check_in(&self.domain)?;
        if !self.allows_slug(&identity.slug) {
            return Err(format!(
                "agent identity refused: `{}` is not an allowed agent name, so agent-sign won't \
                 certify it. To allow it, add \"{}\" to allowed_agents under [identity] in \
                 ~/.agent-sign/config.toml (a person's own name is never allowed)",
                identity.slug, identity.slug
            ));
        }
        Ok(())
    }
}

/// The longest slug or display name an identity keeps.
const MAX_NAME_LEN: usize = 64;

/// One agent's identity: the tool's slug (`claude-code`), its display name
/// ("Claude Code"), and its principal (`claude-code.1a2b3c4d@agents.local`),
/// which is the commits' email and the signing certificate's principal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentIdentity {
    pub slug: String,
    pub name: String,
    pub principal: String,
}

impl AgentIdentity {
    /// The identity for a tool `slug`, display `name`, and session id
    /// (`None`: a marked agent that gave none, `nosession`).
    /// It is in [`AGENTS_DOMAIN`]; [`AgentIdentity::in_domain`] moves it to a
    /// named machine's.
    pub fn new(slug: &str, name: &str, session: Option<&str>) -> Self {
        let session8 = session.map(session8).unwrap_or_else(|| "nosession".into());
        Self::with_session8(slug, name, &session8, AGENTS_DOMAIN)
    }

    fn with_session8(slug: &str, name: &str, session8: &str, domain: &str) -> Self {
        Self {
            slug: slug.to_string(),
            name: name.to_string(),
            principal: format!("{slug}.{session8}@{domain}"),
        }
    }

    /// The same identity in `domain` (see [`agents_domain`]): what the git
    /// wrapper does once it has read the machine setting, so an agent's
    /// principal names the machine it ran on.
    pub fn in_domain(mut self, domain: &str) -> Self {
        let local = self
            .principal
            .rsplit_once('@')
            .map(|(local, _)| local.to_string())
            .unwrap_or_else(|| self.principal.clone());
        self.principal = format!("{local}@{domain}");
        self
    }

    /// A placeholder for an [`AttributionEngine`] built without an identity.
    /// It never passes [`AgentIdentity::check`] (its session part isn't a
    /// session), so the service never signs as it. Before the identity
    /// review, an unmarked commit with no terminal was signed as this
    /// "unidentified agent"; such commits are now left to git, unsigned and
    /// under git's own names, because they are as likely to be the person's
    /// own editor as an agent's.
    pub fn unidentified() -> Self {
        Self::with_session8("agent", "Agent", "unidentified", AGENTS_DOMAIN)
    }

    /// `Name <principal>`, as git shows an author.
    pub fn git_ident(&self) -> String {
        format!("{} <{}>", self.name, self.principal)
    }

    /// Whether this is a well-formed identity, as [`AgentIdentity::new`]
    /// makes them: the service checks every identity a client sends before it
    /// issues a certificate for it, so no request can obtain a certificate for
    /// a principal outside `@agents.local`, or one with characters that could
    /// reshape an allowed-signers line or a commit header.
    ///
    /// The shape is exactly what [`identify_agent_with`] produces, and no
    /// more (identity review, 28 Oct 2026): the slug is lowercase words of
    /// letters and digits joined by single `-` (`^[a-z0-9]+(-[a-z0-9]+)*$`),
    /// and the session part is 8 lowercase hex digits or `nosession`. A looser
    /// check let the authority certify principals no session can have, such
    /// as `codex.admin@agents.local` or `---.a@agents.local`, which a reader
    /// of `git log` could take for something they aren't.
    ///
    /// This is the shape in [`AGENTS_DOMAIN`]; the service checks with
    /// [`IdentityPolicy::check`], which also holds the machine's domain and
    /// the allowed agent names.
    pub fn check(&self) -> Result<(), String> {
        self.check_in(AGENTS_DOMAIN)
    }

    /// [`AgentIdentity::check`] for principals in `domain`.
    pub fn check_in(&self, domain: &str) -> Result<(), String> {
        let bad = |why: &str| Err(format!("agent identity refused: {why}"));
        if self.slug.len() > MAX_NAME_LEN || !is_slug(&self.slug) {
            return bad(
                "the tool name must be 1 to 64 lowercase letters and digits, in words joined by single '-'",
            );
        }
        let Some(rest) = self
            .principal
            .strip_prefix(&format!("{}.", self.slug))
            .and_then(|r| r.strip_suffix(&format!("@{domain}")))
        else {
            return Err(format!(
                "agent identity refused: the principal must be <tool>.<session>@{domain}"
            ));
        };
        if !is_session_part(rest) {
            return bad("the session part must be 8 lowercase hex digits, or 'nosession'");
        }
        if self.name.trim().is_empty()
            || self.name.chars().count() > MAX_NAME_LEN
            || self.name != clean_display_name(&self.name)
        {
            return bad("the display name must be 1 to 64 printable characters, without < or >");
        }
        Ok(())
    }
}

/// Whether `slug` can name an agent: what [`slug_of`] makes, 1 to 64
/// lowercase letters and digits in words joined by single `-`. Entries of
/// `[identity] allowed_agents` must be one.
pub fn is_agent_slug(slug: &str) -> bool {
    slug.len() <= MAX_NAME_LEN && is_slug(slug)
}

/// Whether `slug` matches `^[a-z0-9]+(-[a-z0-9]+)*$`: words of lowercase
/// ASCII letters and digits, joined by single hyphens.
fn is_slug(slug: &str) -> bool {
    !slug.is_empty()
        && slug.split('-').all(|word| {
            !word.is_empty()
                && word
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        })
}

/// Whether `part` is what [`AgentIdentity::new`] puts between the slug and
/// the domain: [`session8`]'s 8 lowercase hex digits, or `nosession`.
fn is_session_part(part: &str) -> bool {
    part == "nosession"
        || (part.len() == 8
            && part
                .chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)))
}

/// The first 8 lowercase hex characters of the SHA-256 of a session id: the
/// session's part of a principal, short and not the id itself.
pub fn session8(session: &str) -> String {
    Sha256::digest(session.as_bytes())[..4]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A display name with control, invisible and direction-changing characters
/// (which could disguise it where it's shown), and `<` and `>` (which would
/// break a commit's author line), removed, trimmed, and at most 64
/// characters.
fn clean_display_name(name: &str) -> String {
    name.chars()
        .filter(|c| {
            !c.is_control()
                && *c != '<'
                && *c != '>'
                && !crate::approval::is_unsafe_display_char(*c)
        })
        .collect::<String>()
        .trim()
        .chars()
        .take(MAX_NAME_LEN)
        .collect::<String>()
        .trim()
        .to_string()
}

/// A display name's slug: lowercase ASCII letters and digits, with every run
/// of other characters turned into one `-` and none at either end ("My Bot
/// 2" is `my-bot-2`, "  My  Bot! (beta) " is `my-bot-beta`), so it always
/// passes [`AgentIdentity::check`]. A name with no letters or digits at all
/// is `agent`.
pub fn slug_of(name: &str) -> String {
    let mut slug = String::new();
    let mut gap = false;
    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            if gap && !slug.is_empty() {
                slug.push('-');
            }
            gap = false;
            slug.push(c.to_ascii_lowercase());
        } else {
            gap = true;
        }
    }
    // Cut to the longest slug allowed, never leaving a '-' at the end.
    slug.truncate(MAX_NAME_LEN);
    let slug = slug.trim_end_matches('-').to_string();
    if slug.is_empty() {
        "agent".to_string()
    } else {
        slug
    }
}

/// Whether `var` is set to a mark: not empty and not `0`.
fn marked(get: &impl Fn(&str) -> Option<String>, var: &str) -> bool {
    get(var).is_some_and(|v| !v.is_empty() && v != "0")
}

/// `var`'s value, if it's set and not blank.
fn non_blank(get: &impl Fn(&str) -> Option<String>, var: &str) -> Option<String> {
    get(var).filter(|v| !v.trim().is_empty())
}

/// The agent behind this process, from the environment `get` reads, or
/// `None` when nothing says there is one (positive evidence only):
///
/// - Claude Code: `CLAUDECODE` (not empty or `0`); session
///   `CLAUDE_CODE_SESSION_ID`.
/// - Codex: `CODEX_SESSION_ID` or `CODEX_THREAD_ID`; session the first of
///   those that is set.
/// - Gemini CLI: `GEMINI_CLI`; it sets no session id of its own.
/// - `AGENT_SIGN_AGENT_NAME` names any agent (its slug is the name's
///   [`slug_of`]) and `AGENT_SIGN_SESSION_ID` gives its session; both
///   override what the agent's own marks say. A session id alone is not a
///   mark.
pub fn identify_agent_with(get: impl Fn(&str) -> Option<String>) -> Option<AgentIdentity> {
    let tool: Option<(&str, &str, Option<String>)> = if marked(&get, "CLAUDECODE") {
        Some((
            "claude-code",
            "Claude Code",
            non_blank(&get, "CLAUDE_CODE_SESSION_ID"),
        ))
    } else if marked(&get, "CODEX_SESSION_ID") || marked(&get, "CODEX_THREAD_ID") {
        Some((
            "codex",
            "Codex",
            non_blank(&get, "CODEX_SESSION_ID").or_else(|| non_blank(&get, "CODEX_THREAD_ID")),
        ))
    } else if marked(&get, "GEMINI_CLI") {
        Some(("gemini-cli", "Gemini CLI", None))
    } else {
        None
    };
    let explicit_name = crate::paths::env_var_with("AGENT_NAME", &get)
        .map(|n| clean_display_name(&n))
        .filter(|n| !n.is_empty());
    let explicit_session =
        crate::paths::env_var_with("SESSION_ID", &get).filter(|s| !s.trim().is_empty());

    let (slug, name, session) = match (explicit_name, tool) {
        (Some(name), tool) => (slug_of(&name), name, tool.and_then(|t| t.2)),
        (None, Some((slug, name, session))) => (slug.to_string(), name.to_string(), session),
        (None, None) => return None,
    };
    let session = explicit_session.or(session);
    Some(AgentIdentity::new(&slug, &name, session.as_deref()))
}

/// [`identify_agent_with`] for this process's environment.
pub fn identify_agent() -> Option<AgentIdentity> {
    identify_agent_with(|k| std::env::var(k).ok())
}

/// Agents that mark the commands they run with an environment variable,
/// and the name agent-sign gives their commits. Only marks seen in
/// practice or documented by the agent are listed, checked in this order:
///
/// - Claude Code sets `CLAUDECODE=1` in the shell it runs commands in
///   (seen, 7 Oct 2026).
/// - Gemini CLI sets `GEMINI_CLI=1` for its shell tool (its own docs,
///   `docs/tools/shell.md`).
/// - Codex sets `CODEX_THREAD_ID` (named in its binary, 0.156; not yet seen
///   in a running session) and `CODEX_SESSION_ID`.
///
/// An agent with no mark (Cursor, Aider) can be started with
/// `AGENT_SIGN_AGENT_NAME` set instead.
pub const KNOWN_AGENTS: &[(&str, &str)] = &[
    ("CLAUDECODE", "Claude Code"),
    ("GEMINI_CLI", "Gemini CLI"),
    ("CODEX_THREAD_ID", "Codex"),
    ("CODEX_SESSION_ID", "Codex"),
];

/// The default agent names agent-sign and agent-sign have used. A
/// configured name other than these is the person's own choice, so a
/// detected agent never replaces it.
const DEFAULT_AGENT_NAMES: &[&str] = &["Agent", "Antigravity Agent"];

/// Which agent is running the command, by display name: the name of
/// [`identify_agent_with`]'s identity (`AGENT_SIGN_AGENT_NAME` if set,
/// otherwise the agent whose mark is set).
pub fn detect_agent_with(get: impl Fn(&str) -> Option<String>) -> Option<String> {
    identify_agent_with(get).map(|id| id.name)
}

/// Whether one of the [`KNOWN_AGENTS`] marks is set (and isn't empty or
/// `0`). Unlike [`detect_agent_with`], `AGENT_SIGN_AGENT_NAME` doesn't
/// count: it names an agent's commits, and may be set in a terminal the
/// person also types in (an editor's terminal settings, say).
pub fn agent_mark_present_with(get: impl Fn(&str) -> Option<String>) -> bool {
    KNOWN_AGENTS
        .iter()
        .any(|(var, _)| get(var).is_some_and(|v| !v.is_empty() && v != "0"))
}

/// Set by the git wrapper on every git it runs for an agent. Git's own nested
/// runs (a shell alias `!...`, a hook, the commits a rebase replays) use git's
/// internal copy of itself, not the wrapper, and the signing program they call
/// sees only the environment: this mark is how the signing program still
/// knows an agent is behind them, so the person's own key is never used for
/// them. The wrapper's terminal test ignores it (it reaches editors git
/// starts, and terminals opened from those are the person's).
pub const AGENT_RUN_VAR: &str = "AGENT_SIGN_AGENT_RUN";

/// Whether an agent is behind this process, from the environment `get`
/// reads: the wrapper's [`AGENT_RUN_VAR`], or one of the [`KNOWN_AGENTS`]
/// marks (set and not empty or `0`).
pub fn agent_run_with(get: impl Fn(&str) -> Option<String>) -> bool {
    get(AGENT_RUN_VAR).is_some_and(|v| !v.is_empty() && v != "0") || agent_mark_present_with(get)
}

/// Whether a commit is the person's own, to be passed to their normal git
/// and signing untouched: standard input and output are both terminals,
/// nothing forces agent handling (`AGENT_SIGN_FORCE`, `_SESSION`), and no
/// agent has marked the command as its own. The mark matters for agents
/// that run commands in a real terminal (a terminal pane, say), which the
/// terminal test alone would take for the person.
pub fn is_persons_own_commit(
    stdin_is_terminal: bool,
    stdout_is_terminal: bool,
    forced: bool,
    agent_marked: bool,
) -> bool {
    stdin_is_terminal && stdout_is_terminal && !forced && !agent_marked
}

/// [`detect_agent_with`] for this process's environment.
pub fn detect_agent() -> Option<String> {
    detect_agent_with(|k| std::env::var(k).ok())
}

/// The author name for an agent commit: the agent detected, when the
/// configured name is still a default; otherwise the configured name.
/// `AGENT_SIGN_AGENT_NAME` is an explicit choice and always wins.
pub fn effective_agent_name(configured: &str, explicit: bool, detected: Option<String>) -> String {
    match detected {
        Some(name) if explicit || DEFAULT_AGENT_NAMES.contains(&configured) => name,
        _ => configured.to_string(),
    }
}

/// `GIT_AUTHOR_*` and `GIT_COMMITTER_*` set to `identity`'s display name and
/// principal: what every commit an identified agent makes carries, signed
/// or not (see [`AttributionEngine::compute_env_vars`]).
pub fn identity_env(identity: &AgentIdentity) -> Vec<(String, String)> {
    ["AUTHOR", "COMMITTER"]
        .into_iter()
        .flat_map(|role| {
            [
                (format!("GIT_{role}_NAME"), identity.name.clone()),
                (format!("GIT_{role}_EMAIL"), identity.principal.clone()),
            ]
        })
        .collect()
}

pub struct AttributionEngine {
    pub mode: AttributionMode,
    pub agent: AgentConfig,
    pub human: HumanConfig,
    /// The agent's own identity, used by [`AttributionMode::Agent`].
    pub identity: AgentIdentity,
}

impl AttributionEngine {
    pub fn new(attr_config: AttributionConfig, agent: AgentConfig, human: HumanConfig) -> Self {
        Self {
            mode: attr_config.mode,
            agent,
            human,
            identity: AgentIdentity::unidentified(),
        }
    }

    /// The same engine, attributing to `identity` in
    /// [`AttributionMode::Agent`].
    pub fn with_identity(mut self, identity: AgentIdentity) -> Self {
        self.identity = identity;
        self
    }

    /// The author and committer variables for an agent's signed commit:
    /// the agent's own identity, in every mode. Until the identity review
    /// (28 Oct 2026) `split`, `trailers` and `alias` put the person's name
    /// (or a configured one) here, and a repository's `.agent-sign.toml`
    /// could pick the mode and the names, so a commit carrying a Good
    /// signature for an agent could name the person, or anyone, as its
    /// committer. A signature for an agent's principal now always comes with
    /// that agent's name and principal; `trailers` only adds trailers.
    pub fn compute_env_vars(&self, _commit_msg: &str) -> HashMap<String, String> {
        identity_env(&self.identity).into_iter().collect()
    }

    pub fn transform_commit_message(&self, message: &str, lease_id: &str) -> String {
        match self.mode {
            AttributionMode::Trailers => {
                let mut msg = message.trim_end().to_string();
                msg.push_str("\n\n");
                msg.push_str(&format!(
                    "Co-Authored-By: {} <{}>\n",
                    self.agent.name, self.agent.email
                ));
                msg.push_str("X-Agent-Signer: agent-sign/v0.1\n");
                msg.push_str(&format!("X-Agent-Lease: {}\n", lease_id));
                msg
            }
            _ => message.to_string(),
        }
    }
}

#[cfg(test)]
mod agent_run_tests {
    use super::*;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k| map.get(k).cloned()
    }

    #[test]
    fn the_wrappers_mark_or_an_agents_own_mark_means_an_agent_is_behind_it() {
        assert!(agent_run_with(env(&[(AGENT_RUN_VAR, "1")])));
        assert!(agent_run_with(env(&[("CLAUDECODE", "1")])));
        assert!(agent_run_with(env(&[("CODEX_THREAD_ID", "t")])));
        assert!(!agent_run_with(env(&[])));
        assert!(!agent_run_with(env(&[(AGENT_RUN_VAR, "0")])));
        assert!(!agent_run_with(env(&[(AGENT_RUN_VAR, "")])));
        // Naming an agent's commits isn't a mark: it may be set in a
        // terminal the person also types in.
        assert!(!agent_run_with(env(&[("AGENT_SIGN_AGENT_NAME", "Cursor")])));
    }
}

#[cfg(test)]
mod identity_tests {
    use super::*;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k| map.get(k).cloned()
    }

    #[test]
    fn each_agent_is_named_by_its_own_marks() {
        let id = identify_agent_with(env(&[
            ("CLAUDECODE", "1"),
            ("CLAUDE_CODE_SESSION_ID", "s1"),
        ]))
        .unwrap();
        assert_eq!(id.slug, "claude-code");
        assert_eq!(id.name, "Claude Code");
        assert_eq!(
            id.principal,
            format!("claude-code.{}@agents.local", session8("s1"))
        );
        let codex = identify_agent_with(env(&[("CODEX_THREAD_ID", "t")])).unwrap();
        assert_eq!(
            codex.principal,
            format!("codex.{}@agents.local", session8("t"))
        );
        let gemini = identify_agent_with(env(&[("GEMINI_CLI", "1")])).unwrap();
        assert_eq!(gemini.principal, "gemini-cli.nosession@agents.local");
    }

    #[test]
    fn only_positive_evidence_identifies_an_agent() {
        assert_eq!(identify_agent_with(env(&[])), None);
        assert_eq!(
            identify_agent_with(env(&[("CLAUDECODE", "0"), ("CLAUDE_CODE_SESSION_ID", "s")])),
            None
        );
        assert_eq!(
            identify_agent_with(env(&[("AGENT_SIGN_SESSION_ID", "s")])),
            None
        );
    }

    #[test]
    fn session8_is_the_start_of_the_sha256() {
        // printf 'abc' | shasum -a 256 → ba7816bf...
        assert_eq!(session8("abc"), "ba7816bf");
    }

    #[test]
    fn an_explicit_name_is_slugged_and_cleaned() {
        let id = identify_agent_with(env(&[("AGENT_SIGN_AGENT_NAME", " My <Bot> 2\u{202E}\n")]))
            .unwrap();
        assert_eq!(id.name, "My Bot 2");
        assert_eq!(id.slug, "my-bot-2");
        assert_eq!(id.principal, "my-bot-2.nosession@agents.local");
        assert!(id.check().is_ok());
        assert_eq!(slug_of("!!!"), "agent");
    }

    #[test]
    fn machine_labels_are_dns_labels_without_dots() {
        for ok in ["a", "pi", "my-box-2", "9lives", &"a".repeat(63)] {
            assert!(check_machine_label(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "a.b",
            "a@b",
            "A",
            "-a",
            "a-",
            "a--b",
            "a_b",
            &"a".repeat(64),
        ] {
            let e = check_machine_label(bad).unwrap_err();
            assert!(e.contains("machine"), "{e}");
        }
        assert_eq!(agents_domain(None), "agents.local");
        assert_eq!(agents_domain(Some("pi")), "pi.agents.local");
    }

    #[test]
    fn the_policy_holds_the_machines_domain_and_the_allowed_names() {
        let policy = IdentityPolicy::new(Some("hetzner"), &["my-bot-2".to_string()]);
        let here =
            |slug: &str| AgentIdentity::new(slug, "N", Some("s")).in_domain("hetzner.agents.local");
        assert!(policy.check(&here("claude-code")).is_ok());
        assert!(policy.check(&here("aider")).is_ok());
        assert!(policy.check(&here("my-bot-2")).is_ok());
        let e = policy.check(&here("taylor")).unwrap_err();
        assert!(e.contains("allowed_agents") && e.contains("taylor"), "{e}");
        for other in ["agents.local", "pi.agents.local", "x.hetzner.agents.local"] {
            let id = AgentIdentity::new("codex", "Codex", Some("s")).in_domain(other);
            assert!(policy.check(&id).is_err(), "{other}");
        }
        let plain = IdentityPolicy::default();
        assert!(
            plain
                .check(&AgentIdentity::new("codex", "Codex", Some("s")))
                .is_ok()
        );
        assert!(plain.check(&here("codex")).is_err());
    }

    #[test]
    fn identities_from_elsewhere_are_checked() {
        // The placeholder is never signed for (identity review, 28 Oct 2026).
        assert!(AgentIdentity::unidentified().check().is_err());
        let mut forged = AgentIdentity::new("codex", "Codex", Some("x"));
        forged.principal = "taylor@example.com".into();
        assert!(forged.check().is_err());
        let mut odd = AgentIdentity::new("codex", "Codex", Some("x"));
        odd.name = "Codex <evil@x>".into();
        assert!(odd.check().is_err());
        let bad_slug = AgentIdentity::new("Code X", "Codex", None);
        assert!(bad_slug.check().is_err());
    }
}
