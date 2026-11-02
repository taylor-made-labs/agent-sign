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
//! - `people`: people's names, never certified as agents' names whatever
//!   `allowed_agents` says (see "People's names" below).
//!
//! People's names (security review fix round, 31 Oct 2026, finding M2). A
//! name listed in `allowed_agents` is still never certified when it is a
//! person's: [`RESERVED_PERSON_NAMES`] (`root`, `admin`, `administrator`,
//! with nothing configured); the `[human]` name, any word of it, or its
//! email's local part; any name in `[identity] people`, or any word of one;
//! and, in the service, the login and full-name words of each person's
//! account on the machine ([`crate::accounts`]). Before, the only person's
//! name the deny-list knew was the one git's `user.name` gave, and on a
//! server whose agents set `user.name` themselves git names no person at
//! all, so `allowed_agents = ["taylor"]` signed. None of these names comes
//! from git now; [`IdentityPolicy::check`] holds them, so the service
//! refuses at token issue whatever any client does.
//!
//! Names are compared after Unicode NFKC normalisation and case folding,
//! on both sides ([`normalize_name`], 31 Oct 2026 follow-up): "Taylor",
//! "TAYLOR" and fullwidth "Ｔａｙｌｏｒ" are the same name, whether they are
//! written in `[identity] people`, the `[human]` name, an account's login or
//! full name, or an agent's name.
//!
//! An agent's display name is printable ASCII only (same follow-up): it
//! becomes the author name on the agent's commits, and NFKC can't catch a
//! look-alike from another alphabet, such as "T\u{430}ylor" (with a
//! Cyrillic small a), which reads as a person's name in `git log`. So
//! [`AgentIdentity::check_in`] refuses any other character, and the service
//! refuses a token for such an identity.
//!
//! These are claims made by processes running as the same user as the
//! person: attribution, not a security boundary, until agents run under
//! their own OS accounts.

use crate::config::{AgentConfig, AttributionConfig, HumanConfig};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use unicode_normalization::UnicodeNormalization;

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

/// Names that are never an agent's, on any machine and with nothing
/// configured: the usual names of an administrator's account. A Good
/// signature under `root.1a2b3c4d@agents.local` would read as the machine's
/// administrator, not an agent.
pub const RESERVED_PERSON_NAMES: &[&str] = &["root", "admin", "administrator"];

/// `name` as agent-sign compares names: Unicode NFKC normalisation, then
/// lowercase, then NFKC again (lowercasing can undo a normal form). So
/// "Taylor", "TAYLOR" and fullwidth "Ｔａｙｌｏｒ" all become "taylor".
/// Every person's name (the `[human]` name and email, `[identity] people`,
/// and accounts' login and full names) goes through this before it is
/// slugged, and so does an agent's slug before it is compared with them.
/// Look-alikes from other alphabets (a Cyrillic small a, U+0430) are not folded by NFKC:
/// the ASCII rule on display names ([`AgentIdentity::check_in`]) is what
/// stops those.
pub fn normalize_name(name: &str) -> String {
    name.nfkc()
        .collect::<String>()
        .to_lowercase()
        .nfkc()
        .collect()
}

/// The agent names a person's `name` could pass for: the slug of the whole
/// [`normalize_name`]d name and each word of it ("Dana Example" gives
/// `dana-example`, `dana` and `example`; fullwidth "Ｄａｎａ" gives `dana`).
/// Only ASCII letters and digits make up a slug, so a name with none of them
/// after normalising gives nothing (it can never be an agent's name), never
/// the `agent` that [`slug_of`] falls back to.
pub fn person_name_slugs(name: &str) -> Vec<String> {
    let name = normalize_name(name);
    if !name.chars().any(|c| c.is_ascii_alphanumeric()) {
        return Vec::new();
    }
    let full = slug_of(&name);
    let mut slugs: Vec<String> = full.split('-').map(str::to_string).collect();
    if !slugs.contains(&full) {
        slugs.push(full);
    }
    slugs
}

/// A name the service never certifies as an agent's, because it is a
/// person's, and where agent-sign learned it (said in the refusal, so the
/// user knows which setting or account decides it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonName {
    /// The slug an agent would have to use: one of [`person_name_slugs`].
    pub slug: String,
    /// Where it came from, in words: "the account taylor on this machine".
    pub source: String,
}

impl PersonName {
    /// Every [`person_name_slugs`] of `name`, each from `source`.
    pub fn all_of(name: &str, source: &str) -> Vec<PersonName> {
        person_name_slugs(name)
            .into_iter()
            .map(|slug| PersonName {
                slug,
                source: source.to_string(),
            })
            .collect()
    }

    /// [`RESERVED_PERSON_NAMES`], as the deny-list holds them.
    pub fn reserved() -> Vec<PersonName> {
        RESERVED_PERSON_NAMES
            .iter()
            .map(|slug| PersonName {
                slug: slug.to_string(),
                source: "a reserved name (root, admin and administrator are never agents' names)"
                    .to_string(),
            })
            .collect()
    }

    /// The names a configured `[human]` gives: its name's slugs and its
    /// email's local part. Only for a `[human]` the user's config sets
    /// itself, never git's `user.name` (see the module header).
    pub fn of_human(name: Option<&str>, email: Option<&str>) -> Vec<PersonName> {
        let mut out = Vec::new();
        if let Some(name) = name {
            out.extend(Self::all_of(
                name,
                &format!("the person's name ([human] name = {name:?})"),
            ));
        }
        if let Some((local, _)) = email.and_then(|e| e.split_once('@')) {
            out.extend(Self::all_of(
                local,
                &format!(
                    "the person's email ([human] email = {:?})",
                    email.unwrap_or("")
                ),
            ));
        }
        out
    }
}

/// A person's email address, which no session's commit may carry as its
/// author (re-check R3), and where agent-sign learned it.
///
/// A name check on the author's email (its local part, slugged) cannot see an
/// address whose local part has no ASCII letters or digits, or the person's
/// address at a different spelling of the same text, so the whole address is
/// compared as well.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonEmail {
    /// The address, [`normalize_name`]d: NFKC, lowercase, NFKC again, so
    /// case and look-alike (fullwidth, compatibility) forms are one address.
    pub email: String,
    /// Where it came from, in words: "the person's email ([human] email = ...)".
    pub source: String,
}

impl PersonEmail {
    /// `email` as a person's address from `source`, or nothing when it has
    /// no `@` (a bare name is [`PersonName`]'s, not an address) or is empty.
    pub fn of(email: &str, source: &str) -> Option<PersonEmail> {
        let email = normalize_name(email.trim());
        email.contains('@').then(|| PersonEmail {
            email,
            source: source.to_string(),
        })
    }

    /// The `[human]` email the user's config sets itself (never git's
    /// `user.email`; see the module header).
    pub fn of_human(email: Option<&str>) -> Vec<PersonEmail> {
        email
            .and_then(|e| Self::of(e, &format!("the person's email ([human] email = {e:?})")))
            .into_iter()
            .collect()
    }
}

/// Which identities the service certifies: the machine's domain, the agent
/// names allowed in it, and the people's names never allowed. Built from the
/// user's own config by the service (which is authoritative, and adds the
/// machine's people's accounts) and the git wrapper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityPolicy {
    /// [`agents_domain`] for the configured machine.
    pub domain: String,
    /// `[identity] allowed_agents`: slugs allowed besides
    /// [`BUILT_IN_AGENT_SLUGS`] and [`WIDELY_USED_AGENT_SLUGS`].
    pub allowed_agents: Vec<String>,
    /// People's names: never certified, whatever `allowed_agents` says.
    /// Always holds [`RESERVED_PERSON_NAMES`]. The built-in and widely used
    /// agents' names are the tools' own and are never refused for being a
    /// word of someone's name (a person named Cline doesn't lose the `cline`
    /// agent).
    pub persons: Vec<PersonName>,
    /// People's email addresses: no session's commit may be authored with
    /// one (the service's author check, re-check R3). The `[human]` email the
    /// config file sets itself and any `[identity] people` entry written as
    /// an address; none comes from git, and in system mode (whose
    /// `system.toml` has no `[human]`) only the `people` entries are known.
    pub person_emails: Vec<PersonEmail>,
}

impl Default for IdentityPolicy {
    /// No machine and nothing listed: `@agents.local`, built-in and widely
    /// used agents only, and the reserved names refused.
    fn default() -> Self {
        Self {
            domain: AGENTS_DOMAIN.to_string(),
            allowed_agents: Vec::new(),
            persons: PersonName::reserved(),
            person_emails: Vec::new(),
        }
    }
}

impl IdentityPolicy {
    /// The policy for a machine (already checked) and a list of allowed slugs,
    /// refusing the reserved names.
    pub fn new(machine: Option<&str>, allowed_agents: &[String]) -> Self {
        Self {
            domain: agents_domain(machine),
            allowed_agents: allowed_agents.to_vec(),
            persons: PersonName::reserved(),
            person_emails: Vec::new(),
        }
    }

    /// This policy, also refusing `more` people's email addresses as a
    /// session's commit author.
    pub fn with_person_emails(mut self, more: impl IntoIterator<Item = PersonEmail>) -> Self {
        for email in more {
            if !self.person_emails.iter().any(|p| p.email == email.email) {
                self.person_emails.push(email);
            }
        }
        self
    }

    /// The person's email address `email` is, if it is one: compared
    /// [`normalize_name`]d, so upper case and fullwidth forms are the same
    /// address.
    ///
    /// A `+tag` on the local part is dropped from both sides first, so
    /// `dana+x@example.org` is `dana@example.org` (see [`without_plus_tag`]).
    pub fn person_email(&self, email: &str) -> Option<&PersonEmail> {
        let email = without_plus_tag(&normalize_name(email.trim()));
        self.person_emails
            .iter()
            .find(|p| without_plus_tag(&p.email) == email)
    }

    /// This policy, also refusing `more` people's names.
    pub fn with_persons(mut self, more: impl IntoIterator<Item = PersonName>) -> Self {
        for person in more {
            if !self.persons.iter().any(|p| p.slug == person.slug) {
                self.persons.push(person);
            }
        }
        self
    }

    /// Whether `slug` is an agent name this policy certifies.
    pub fn allows_slug(&self, slug: &str) -> bool {
        Self::is_tools_own(slug)
            || (self.allowed_agents.iter().any(|a| a == slug) && self.person(slug).is_none())
    }

    /// The built-in and widely used agents' names: always certified.
    fn is_tools_own(slug: &str) -> bool {
        BUILT_IN_AGENT_SLUGS.contains(&slug) || WIDELY_USED_AGENT_SLUGS.contains(&slug)
    }

    /// The person's name `slug` is, if it is one. Both sides are compared
    /// [`normalize_name`]d (the people's slugs already are).
    pub fn person(&self, slug: &str) -> Option<&PersonName> {
        let slug = normalize_name(slug);
        self.persons.iter().find(|p| p.slug == slug)
    }

    /// Whether the service may certify `identity`: its principal is in this
    /// machine's domain (not another machine's, and not plain
    /// `@agents.local` once a machine is named), it is well formed
    /// ([`AgentIdentity::check_in`]), its slug is allowed, and it is no
    /// person's name. Each refusal says which setting decides it.
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
        if !Self::is_tools_own(&identity.slug)
            && let Some(person) = self.person(&identity.slug)
        {
            return Err(format!(
                "agent identity refused: `{}` is {}, and agent-sign never certifies an agent \
                 under a person's name, whatever allowed_agents says. Give the agent another \
                 name (and take \"{}\" out of allowed_agents in ~/.agent-sign/config.toml if \
                 it is there)",
                identity.slug, person.source, identity.slug
            ));
        }
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
        if !is_printable_ascii(&self.name) {
            return Err(format!(
                "agent identity refused: the display name \"{}\" has characters that aren't \
                 printable ASCII (shown here as \\u{{...}}). An agent's display name becomes \
                 its commits' author name, and letters from other alphabets can look exactly \
                 like a person's name, so agent-sign takes only printable ASCII: letters A-Z \
                 and a-z, digits, spaces and punctuation. Set AGENT_SIGN_AGENT_NAME to such a \
                 name (\"My Bot 2\", say)",
                escape_non_ascii(&self.name)
            ));
        }
        Ok(())
    }
}

/// Whether every character of `name` is printable ASCII (space to `~`).
fn is_printable_ascii(name: &str) -> bool {
    name.chars().all(|c| (' '..='~').contains(&c))
}

/// `name` with each character that isn't printable ASCII written as
/// `\u{hex}`, so a refusal shows a look-alike for what it is ("T\u{430}ylor",
/// not a name that looks like "Taylor").
fn escape_non_ascii(name: &str) -> String {
    name.chars()
        .map(|c| {
            if (' '..='~').contains(&c) {
                c.to_string()
            } else {
                format!("\\u{{{:x}}}", c as u32)
            }
        })
        .collect()
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

/// `email` (already [`normalize_name`]d) without a plus-address tag: the text
/// from the first `+` of the local part up to the `@` is dropped, so
/// `dana+x@example.org` gives `dana@example.org`. Mail systems deliver
/// plus-addressed mail to the same mailbox, so a commit author written that
/// way is still the person; without this, a whole-address match and the
/// local part's name slug (`dana-x`) both missed it. An address with no `@`
/// is treated as a bare local part. A leading `+` is kept (no local part would
/// be left).
pub fn without_plus_tag(email: &str) -> String {
    let (local, domain) = match email.rsplit_once('@') {
        Some((l, d)) => (l, Some(d)),
        None => (email, None),
    };
    let local = match local.find('+') {
        Some(i) if i > 0 => &local[..i],
        _ => local,
    };
    match domain {
        Some(d) => format!("{local}@{d}"),
        None => local.to_string(),
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

/// The slug and display name for an agent named `name` the way
/// `AGENT_SIGN_AGENT_NAME` names one (a display name or a slug), as the
/// launcher's `--agent` takes it: the built-in agents' slugs get their own
/// display names ("claude-code" is "Claude Code"), any other name is cleaned
/// as [`identify_agent_with`] cleans it and slugged with [`slug_of`]. `None`
/// when nothing is left of the name.
pub fn named_agent(name: &str) -> Option<(String, String)> {
    let name = clean_display_name(name);
    if name.is_empty() {
        return None;
    }
    let slug = slug_of(&name);
    let display = match slug.as_str() {
        "claude-code" => "Claude Code".to_string(),
        "codex" => "Codex".to_string(),
        "gemini-cli" => "Gemini CLI".to_string(),
        _ => name,
    };
    Some((slug, display))
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

    /// M2 (security review fix round, 31 Oct 2026): people's names are
    /// refused at the policy, whatever allowed_agents lists, with nothing
    /// from git; the tools' own names never are.
    #[test]
    fn a_persons_email_is_recognised_whole_in_any_case_and_width() {
        let policy = IdentityPolicy::default()
            .with_person_emails(PersonEmail::of_human(Some("李明@example.org")))
            .with_person_emails(PersonEmail::of("Dana@Example.com", "a test"));
        // The local part has no ASCII letter or digit: only the whole
        // address can be told.
        assert!(policy.person_email("李明@example.org").is_some());
        assert!(policy.person_email("李明@EXAMPLE.ORG").is_some());
        assert!(
            policy
                .person_email("李明@\u{FF45}\u{FF58}ample.org")
                .is_some()
        );
        assert!(policy.person_email(" dana@example.com ").is_some());
        // The same name at another domain is another address.
        assert!(policy.person_email("李明@example.net").is_none());
        // A bare name is a name, not an address; an unset email adds none.
        assert!(PersonEmail::of("Taylor", "x").is_none());
        assert!(PersonEmail::of_human(None).is_empty());
        // Adding an address twice keeps one.
        let twice = policy.with_person_emails(PersonEmail::of("DANA@example.com", "again"));
        assert_eq!(twice.person_emails.len(), 2);
    }

    #[test]
    fn peoples_names_are_never_certified_whatever_allowed_agents_says() {
        let listed: Vec<String> = [
            "root",
            "admin",
            "administrator",
            "taylor",
            "dana",
            "my-bot-2",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let id = |slug: &str| AgentIdentity::new(slug, "N", Some("s"));
        let plain = IdentityPolicy::new(None, &listed);
        for reserved in RESERVED_PERSON_NAMES {
            let e = plain.check(&id(reserved)).unwrap_err();
            assert!(e.contains("allowed_agents") && e.contains(reserved), "{e}");
        }
        assert!(plain.check(&id("taylor")).is_ok());
        assert!(plain.check(&id("my-bot-2")).is_ok());

        let people = plain
            .clone()
            .with_persons(PersonName::all_of("Taylor", "a person's name"))
            .with_persons(PersonName::of_human(
                Some("Dana Example"),
                Some("dee@x.org"),
            ));
        for refused in ["taylor", "dana"] {
            let e = people.check(&id(refused)).unwrap_err();
            assert!(e.contains("allowed_agents") && e.contains(refused), "{e}");
        }
        assert!(people.check(&id("my-bot-2")).is_ok());
        // A tool's own name stays certified even when it is a word of a name.
        let cline = people.with_persons(PersonName::all_of("Patsy Cline", "a person's name"));
        assert!(cline.check(&id("cline")).is_ok());
        assert!(cline.check(&id("claude-code")).is_ok());
    }

    #[test]
    fn a_persons_name_gives_its_slug_and_words_and_nothing_without_letters() {
        assert_eq!(
            person_name_slugs("Dana Example"),
            ["dana", "example", "dana-example"]
        );
        assert_eq!(person_name_slugs("Taylor"), ["taylor"]);
        assert!(person_name_slugs("李明").is_empty());
    }

    /// 31 Oct 2026 follow-up, item (2): names are compared after NFKC and
    /// case folding, on both sides.
    #[test]
    fn names_are_compared_after_nfkc_and_case_folding() {
        let fullwidth = "\u{FF34}\u{FF41}\u{FF59}\u{FF4C}\u{FF4F}\u{FF52}";
        for name in ["Taylor", "TAYLOR", "taylor", fullwidth] {
            assert_eq!(normalize_name(name), "taylor", "{name:?}");
            assert_eq!(person_name_slugs(name), ["taylor"], "{name:?}");
        }
        assert_eq!(
            person_name_slugs("\u{FF24}\u{FF41}\u{FF4E}\u{FF41} Example"),
            ["dana", "example", "dana-example"]
        );
        let policy = IdentityPolicy::new(None, &["taylor".to_string()])
            .with_persons(PersonName::all_of(fullwidth, "a person's name"));
        let id = AgentIdentity::new("taylor", "TAYLOR", Some("s"));
        let e = policy.check(&id).unwrap_err();
        assert!(e.contains("allowed_agents") && e.contains("taylor"), "{e}");
        assert!(policy.person("TAYLOR").is_some());
    }

    /// 31 Oct 2026 follow-up, item (1): a display name is printable ASCII
    /// only, so a look-alike can't become a commit's author name.
    #[test]
    fn a_display_name_is_printable_ascii_only() {
        let policy = IdentityPolicy::new(None, &["t-ylor".to_string(), "my-bot-2".to_string()]);
        for name in ["T\u{0430}ylor", "\u{FF34}aylor", "Ag\u{00E9}nt"] {
            let id = AgentIdentity::new(&slug_of(name), name, Some("s"));
            let e = id.check().unwrap_err();
            assert!(
                e.contains("ASCII") && e.contains("AGENT_SIGN_AGENT_NAME"),
                "{e}"
            );
            assert!(policy.check(&id).is_err(), "{name:?}");
        }
        let e = AgentIdentity::new("t-ylor", "T\u{0430}ylor", None)
            .check()
            .unwrap_err();
        assert!(e.contains("T\\u{430}ylor"), "{e}");
        for name in [
            "My Bot 2",
            "My Bot (beta) #2",
            "a~!@#$%^&*()_+={}[]|:;'\",.?/`",
        ] {
            let id = AgentIdentity::new(&slug_of(name), name, Some("s"));
            assert!(id.check().is_ok(), "{name:?}: {:?}", id.check());
        }
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
