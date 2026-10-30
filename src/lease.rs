//! Leases: the person's approval, given once, for the agent key to sign
//! commits without asking again, in the repositories the person chose.
//!
//! agent-sign's lease model: a lease's terms are fixed when the person approves it,
//! and they never grow on their own. The terms are its coverage (one
//! repository, every repository under a folder, or every repository: see
//! [`Coverage`]), which branches it covers (in one repository, either one
//! branch or every unprotected branch), and its end (a
//! time, or "until revoked" for the default lifetime mode). Using a lease
//! never moves its end. A later config change can narrow a lease already
//! granted (a shorter ceiling, branch following turned off), never widen it:
//! what applies is always what was approved, intersected with what the config
//! allows now. Leases are saved to `leases.json`, so they survive a crash, a
//! restart, or sleep without asking the person again; saving changes nothing
//! about their terms.
//!
//! Branch rules sit beside leases: a lease never covers a protected branch,
//! and that is checked whenever a commit token is issued.

use crate::approval::BranchReach;
use crate::config::{LeaseMode, LeaseScope};
use crate::protocol::LeaseInfo;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// What one approval covers. The service now only ever asks for
/// [`Coverage::Repository`] (the narrowest: one branch of one repository, or
/// every unprotected branch of it when the config lets leases follow the
/// agent); folder and everywhere leases are no longer offered, but the engine
/// still honours them, so a lease saved earlier keeps working and can be
/// revoked.
///
/// A folder covers every repository whose path is inside it, compared by
/// whole path components, so `/w/dev` covers `/w/dev/app` but never
/// `/w/dev2`. Wider scopes always cover every unprotected branch of the
/// repositories they reach; a lease for one branch only makes sense in one
/// repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "kind", content = "path", rename_all = "lowercase")]
pub enum Coverage {
    /// The repository the agent asked from, and nothing else. Leases saved
    /// before scopes existed load as this.
    #[default]
    Repository,
    /// Every repository under this folder (a canonical absolute path).
    Folder(String),
    /// Every repository on this computer.
    Everywhere,
}

/// The name `agent-sign leases` shows for a lease covering everywhere, and
/// that `agent-sign revoke` takes to end it.
pub const EVERYWHERE: &str = "everywhere";

impl Coverage {
    /// The key a lease with this coverage is filed under. Repository leases
    /// keep the plain repository path, as before, so lease files written by
    /// earlier versions still match; the other kinds get keys no repository
    /// path can collide with.
    fn key(&self, repo: &str) -> String {
        match self {
            Coverage::Repository => repo.to_string(),
            Coverage::Folder(folder) => format!("folder:{folder}"),
            Coverage::Everywhere => EVERYWHERE.to_string(),
        }
    }

    /// Whether this coverage reaches `repo`, given the repository (or folder)
    /// the lease is filed for.
    fn reaches(&self, lease_repo: &str, repo: &str) -> bool {
        match self {
            Coverage::Repository => lease_repo == repo,
            Coverage::Folder(folder) => std::path::Path::new(repo).starts_with(folder),
            Coverage::Everywhere => true,
        }
    }

    /// How specific the coverage is: the most specific lease that covers a
    /// commit is the one used (and counted).
    fn specificity(&self) -> usize {
        match self {
            Coverage::Repository => usize::MAX,
            Coverage::Folder(folder) => folder.len(),
            Coverage::Everywhere => 0,
        }
    }

    /// The coverage in plain words, for `agent-sign leases`.
    pub fn describe(&self) -> String {
        match self {
            Coverage::Repository => "this repository".to_string(),
            Coverage::Folder(folder) => format!("every repository under {folder}"),
            Coverage::Everywhere => "every repository on this computer".to_string(),
        }
    }
}

pub fn current_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lease {
    pub id: String,
    pub repo: String,
    pub branch: String,
    pub intent: String,
    pub mode: LeaseMode,
    pub scope: LeaseScope,
    pub granted_at_secs: u64,
    pub last_used_at_secs: u64,
    /// The end recorded when the person approved the lease; `None` means
    /// until revoked. Nothing extends it. See [`LeaseEngine::effective_end`]
    /// for how the current config can bring it forward.
    pub expires_at_secs: Option<u64>,
    pub commit_count: u64,
    /// Whether the lease covers every unprotected branch of its repository,
    /// following the agent as it switches branches, as approved. `None` for
    /// leases granted before agent-sign recorded this term: for those the current
    /// config decides, which is how they behaved when they were granted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub follows_branches: Option<bool>,
    /// What the approval covers, as the person chose it. For a folder or
    /// everywhere, `repo` holds the folder or [`EVERYWHERE`] instead of the
    /// repository asked from, since that's what the lease is for and what
    /// `agent-sign revoke` takes.
    #[serde(default)]
    pub coverage: Coverage,
    /// The piece of work the lease was approved for. When it's finished
    /// (merged or deleted, see [`crate::work`]) the lease ends. `None` when
    /// the branch couldn't be read at approval, and for leases saved before
    /// this was recorded: those end only by the other rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub work: Option<Work>,
}

/// The work a lease was approved for: the repository and branch the agent
/// asked from, and the branch's tip at that moment (so that commits made
/// since can be told from where the branch started).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Work {
    pub repo: String,
    pub branch: String,
    pub base: String,
}

impl Lease {
    /// Whether the end recorded at approval has passed. The service uses
    /// [`LeaseEngine::is_lease_active`], which also applies the current config.
    pub fn is_expired(&self) -> bool {
        if let Some(exp) = self.expires_at_secs {
            current_epoch_secs() >= exp
        } else {
            false
        }
    }

    pub fn time_remaining_secs(&self) -> Option<u64> {
        self.expires_at_secs.map(|exp| {
            let now = current_epoch_secs();
            exp.saturating_sub(now)
        })
    }
}

#[derive(Debug, Clone)]
pub struct LeasePolicy {
    pub mode: LeaseMode,
    pub scope: LeaseScope,
    pub default_ttl: Duration,
    pub max_ceiling: Option<Duration>,
    pub block_branches: Vec<String>,
    pub allow_main_branch: bool,
    pub allow_branch_switching: bool,
    pub max_commits_per_minute: u32,
    /// The backstop: a lease ends after this long with no agent commit under
    /// it (`end_after_idle` in the config), so one whose work is never merged
    /// or deleted still ends. `None` turns the backstop off.
    pub idle_limit: Option<Duration>,
}

impl Default for LeasePolicy {
    fn default() -> Self {
        Self {
            mode: LeaseMode::Identity,
            scope: LeaseScope::Branch,
            default_ttl: Duration::from_secs(7200),
            max_ceiling: None,
            block_branches: vec!["main".to_string(), "master".to_string()],
            allow_main_branch: false,
            allow_branch_switching: false,
            max_commits_per_minute: 10,
            idle_limit: None,
        }
    }
}

/// A new lease's terms in plain words: what the person approves is exactly
/// what the lease will be. The system's prompt is too short to carry them
/// (it says what is being approved: see [`BranchReach`]), so they are written
/// to the service's log with each approval, and `agent-sign leases` shows the
/// ones in force.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TermsText {
    /// Which branches it covers.
    pub covers: String,
    /// When it ends.
    pub ends: String,
}

impl LeasePolicy {
    /// Whether leases may follow the agent across branches under this config.
    /// Wider scopes need it: they cover many repositories, so they can't be
    /// tied to one branch.
    pub fn follows_branches(&self) -> bool {
        self.scope == LeaseScope::Repo || self.allow_branch_switching
    }

    /// Which branches a lease approved now for `branch` would reach, for the
    /// approval prompt to say: only `branch` unless the config lets leases
    /// follow the agent between branches.
    pub fn branch_reach(&self, branch: &str) -> BranchReach {
        if !self.follows_branches() {
            BranchReach::This(branch.to_string())
        } else if self.allow_main_branch || self.block_branches.is_empty() {
            BranchReach::Any
        } else {
            BranchReach::AnyUnprotected
        }
    }

    /// How long a lease granted now lasts, in a few words for the approval
    /// prompt. Every lease ends with its work, so that comes first; the
    /// longest it can last (a ceiling, or a timed lease's term), or the idle
    /// backstop, follows when there is one.
    pub fn end_phrase(&self) -> String {
        let cap = match self.mode {
            LeaseMode::Identity => self.max_ceiling,
            LeaseMode::Timed | LeaseMode::Process => Some(self.default_ttl),
        };
        match (cap, self.idle_limit) {
            (Some(cap), _) => format!("until merged, at most {}", describe_duration(cap)),
            (None, Some(idle)) => format!("until merged or {} idle", describe_duration(idle)),
            (None, None) => "until merged".to_string(),
        }
    }

    /// The terms a lease granted now for `branch` would get.
    pub fn describe_terms(&self, branch: &str) -> TermsText {
        let covers = if self.scope == LeaseScope::Repo || self.allow_branch_switching {
            if self.allow_main_branch || self.block_branches.is_empty() {
                "every branch".to_string()
            } else {
                format!(
                    "every branch except protected ones ({})",
                    self.block_branches.join(", ")
                )
            }
        } else {
            format!("only branch '{}'", branch)
        };
        // Every lease ends with its work, after the idle backstop, and when
        // revoked; a time limit, if one applies, is said first.
        let mut endings = vec![format!(
            "when the work on branch '{}' is merged or the branch is deleted",
            branch
        )];
        if let Some(idle) = self.idle_limit {
            endings.push(format!(
                "after {} with no agent commits",
                describe_duration(idle)
            ));
        }
        endings.push("when you turn it off (agent-sign revoke)".to_string());
        let either = join_alternatives(&endings);
        let ends = match (self.mode, self.max_ceiling) {
            (LeaseMode::Identity, None) => either,
            (LeaseMode::Identity, Some(cap)) => format!(
                "{} after approval at the latest; sooner {}",
                describe_duration(cap),
                either
            ),
            (LeaseMode::Timed, _) => format!(
                "{} after approval at the latest; sooner {}",
                describe_duration(self.default_ttl),
                either
            ),
            (LeaseMode::Process, _) => format!(
                "{} after approval at the latest (\"process\" mode is not tied to a process yet; it works as \"timed\"); sooner {}",
                describe_duration(self.default_ttl),
                either
            ),
        };
        TermsText { covers, ends }
    }
}

/// "a, b, or c".
fn join_alternatives(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [one] => one.clone(),
        [rest @ .., last] => format!("{}, or {}", rest.join(", "), last),
    }
}

/// A duration in the largest whole unit that fits: "7 days", "2 hours".
pub fn describe_duration(d: Duration) -> String {
    let secs = d.as_secs();
    let (n, unit) = if secs >= 86400 && secs.is_multiple_of(86400) {
        (secs / 86400, "day")
    } else if secs >= 3600 && secs.is_multiple_of(3600) {
        (secs / 3600, "hour")
    } else if secs >= 60 && secs.is_multiple_of(60) {
        (secs / 60, "minute")
    } else {
        (secs, "second")
    };
    format!("{} {}{}", n, unit, if n == 1 { "" } else { "s" })
}

/// Whether `branch` matches one of `patterns` (`block_branches`): a name, or
/// a prefix ending in `*`, compared without regard to ASCII case. On a disk
/// that ignores case (macOS by default) `refs/heads/MAIN` and
/// `refs/heads/main` are the same file, and a remote may only ever see one
/// of them, so a branch named `MAIN` must be as protected as `main`
/// (identity review, 28 Oct 2026; before, it slipped past).
pub fn branch_matches_blocked(branch: &str, patterns: &[String]) -> bool {
    let branch = branch.to_ascii_lowercase();
    patterns.iter().any(|pattern| {
        let pattern = pattern.to_ascii_lowercase();
        match pattern.strip_suffix('*') {
            Some(prefix) => branch.starts_with(prefix),
            None => branch == pattern,
        }
    })
}

pub struct LeaseEngine {
    pub policy: LeasePolicy,
    storage_path: Option<PathBuf>,
    storage_unavailable: bool,
    leases: HashMap<String, Lease>,
    commit_timestamps: HashMap<String, Vec<Instant>>,
}

impl LeaseEngine {
    pub fn new(policy: LeasePolicy) -> Self {
        Self {
            policy,
            storage_path: None,
            storage_unavailable: false,
            leases: HashMap::new(),
            commit_timestamps: HashMap::new(),
        }
    }

    /// Loads the leases saved by an earlier run, keeping those still in force.
    ///
    /// A file that can't be read is never overwritten, since it may hold
    /// leases the person approved. If it isn't valid leases, it is moved aside
    /// (`leases.json.unreadable-<time>`) and the service starts with none, so
    /// each repository asks for approval again (failing closed). If it can't
    /// be read at all, leases granted in this run are kept in memory only.
    pub fn new_with_storage(policy: LeasePolicy, storage_path: Option<PathBuf>) -> Self {
        let mut engine = Self {
            policy,
            storage_path,
            storage_unavailable: false,
            leases: HashMap::new(),
            commit_timestamps: HashMap::new(),
        };
        let Some(path) = engine.storage_path.clone() else {
            return engine;
        };
        match fs::read_to_string(&path) {
            Ok(content) => match serde_json::from_str::<HashMap<String, Lease>>(&content) {
                Ok(loaded) => {
                    // Keep the leases still in force under the current
                    // config; drop the ones that have ended.
                    for (k, v) in loaded {
                        if engine.is_lease_active(&v) {
                            engine.leases.insert(k, v);
                        }
                    }
                }
                Err(e) => {
                    let aside =
                        path.with_extension(format!("json.unreadable-{}", current_epoch_secs()));
                    match fs::rename(&path, &aside) {
                        Ok(()) => eprintln!(
                            "[agent-sign] {} is not a valid lease file ({}). Moved it to {} and started with no leases: each repository will ask for approval again.",
                            path.display(),
                            e,
                            aside.display()
                        ),
                        Err(re) => {
                            eprintln!(
                                "[agent-sign] {} is not a valid lease file ({}) and could not be moved aside ({}). Leaving it untouched; leases granted now last until the service stops.",
                                path.display(),
                                e,
                                re
                            );
                            engine.storage_path = None;
                            engine.storage_unavailable = true;
                        }
                    }
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                eprintln!(
                    "[agent-sign] Could not read {} ({}). Leaving it untouched and starting with no leases; leases granted now last until the service stops.",
                    path.display(),
                    e
                );
                engine.storage_path = None;
                engine.storage_unavailable = true;
            }
        }
        engine.save_to_disk();
        engine
    }

    /// Saves every lease to the lease file: written to a temporary file
    /// created with 0600 permissions, then renamed over the old one, so the
    /// file is never half-written or readable by others. A failure is
    /// reported, and the leases still apply until the service stops.
    fn save_to_disk(&self) {
        let Some(ref path) = self.storage_path else {
            return;
        };
        if let Err(e) = self.write_lease_file(path) {
            eprintln!(
                "[agent-sign] Could not save leases to {} ({}). They still apply until the service stops.",
                path.display(),
                e
            );
        }
    }

    fn write_lease_file(&self, path: &std::path::Path) -> std::io::Result<()> {
        use std::io::Write;
        #[cfg(unix)]
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
            #[cfg(unix)]
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        }
        let json = serde_json::to_string_pretty(&self.leases).map_err(std::io::Error::other)?;
        let tmp_path = path.with_extension(format!("tmp.{}", Uuid::new_v4()));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let written = options
            .open(&tmp_path)
            .and_then(|mut f| f.write_all(json.as_bytes()).and_then(|_| f.sync_all()))
            .and_then(|_| fs::rename(&tmp_path, path))
            .and_then(|_| match path.parent() {
                Some(parent) => fs::File::open(parent)?.sync_all(),
                None => Ok(()),
            });
        if written.is_err() {
            let _ = fs::remove_file(&tmp_path);
        }
        written
    }

    /// The longest a lease of this mode may last under the current config.
    fn current_cap(&self, mode: LeaseMode) -> Option<Duration> {
        match mode {
            LeaseMode::Identity => self.policy.max_ceiling,
            LeaseMode::Timed | LeaseMode::Process => Some(self.policy.default_ttl),
        }
    }

    /// When a lease ends: the end recorded at approval, brought forward if the
    /// current config's cap for its mode is shorter, never pushed back.
    /// `None` means until revoked.
    pub fn effective_end(&self, lease: &Lease) -> Option<u64> {
        let capped = self
            .current_cap(lease.mode)
            .map(|cap| lease.granted_at_secs.saturating_add(cap.as_secs()));
        match (lease.expires_at_secs, capped) {
            (Some(recorded), Some(cap)) => Some(recorded.min(cap)),
            (recorded, cap) => recorded.or(cap),
        }
    }

    /// Whether a lease is still in force under its terms and the current
    /// config: before its end, and used within the idle backstop.
    pub fn is_lease_active(&self, lease: &Lease) -> bool {
        let now = current_epoch_secs();
        let before_end = self.effective_end(lease).is_none_or(|end| now < end);
        let recently_used = self
            .policy
            .idle_limit
            .is_none_or(|idle| now < lease.last_used_at_secs.saturating_add(idle.as_secs()));
        before_end && recently_used
    }

    /// Everything besides a fixed end that will end `lease`, in plain words.
    pub fn describe_endings(&self, lease: &Lease) -> String {
        let mut endings = Vec::new();
        if let Some(work) = &lease.work {
            endings.push(format!(
                "when branch '{}' is merged or deleted",
                work.branch
            ));
        }
        if let Some(idle) = self.policy.idle_limit {
            endings.push(format!(
                "after {} with no agent commits",
                describe_duration(idle)
            ));
        }
        endings.push("when you turn it off (agent-sign revoke)".to_string());
        join_alternatives(&endings)
    }

    /// Ends every lease whose work is finished, as `check` reports it (the
    /// service passes [`crate::work::work_state`]). Returns each lease ended,
    /// with why. Leases with no recorded work are left to the other rules.
    pub fn end_finished_work(
        &mut self,
        check: impl Fn(&Work) -> crate::work::WorkState,
    ) -> Vec<(Lease, crate::work::WorkState)> {
        use crate::work::WorkState;
        let finished: Vec<(String, WorkState)> = self
            .leases
            .iter()
            .filter_map(|(key, lease)| {
                let state = check(lease.work.as_ref()?);
                (state != WorkState::Ongoing).then(|| (key.clone(), state))
            })
            .collect();
        let ended: Vec<(Lease, WorkState)> = finished
            .into_iter()
            .filter_map(|(key, state)| self.leases.remove(&key).map(|l| (l, state)))
            .collect();
        if !ended.is_empty() {
            self.save_to_disk();
        }
        ended
    }

    /// Whether a lease covers every unprotected branch of its repository: what
    /// the person approved, intersected with what the current config allows.
    pub fn covers_every_branch(&self, lease: &Lease) -> bool {
        let approved = lease.scope == LeaseScope::Repo
            || lease
                .follows_branches
                .unwrap_or(self.policy.allow_branch_switching);
        let allowed_now =
            self.policy.scope == LeaseScope::Repo || self.policy.allow_branch_switching;
        approved && allowed_now
    }

    /// Whether a lease lets the agent commit on `branch` right now, without
    /// moving it: never on a protected branch; on any other branch if it is a
    /// repository lease covering every branch, otherwise only on its own.
    pub fn lease_covers(&self, lease: &Lease, branch: &str) -> bool {
        if self.is_branch_blocked(branch) {
            return false;
        }
        lease.branch == branch
            || (lease.scope == LeaseScope::Repo && self.covers_every_branch(lease))
    }

    /// The key of the most specific lease in force that reaches `repo` and,
    /// if `branch` is given, covers that branch now.
    fn find_lease_key(&self, repo: &str, branch: Option<&str>) -> Option<String> {
        self.leases
            .iter()
            .filter(|(_, lease)| lease.coverage.reaches(&lease.repo, repo))
            .filter(|(_, lease)| self.is_lease_active(lease))
            .filter(|(_, lease)| branch.is_none_or(|b| self.lease_covers(lease, b)))
            .max_by_key(|(_, lease)| lease.coverage.specificity())
            .map(|(key, _)| key.clone())
    }

    /// The lease that applies to a commit on `branch` in `repo`: the most
    /// specific one in force that covers both. A repository lease for one
    /// branch doesn't hide a wider lease that covers the branch the agent is
    /// on now.
    pub fn find_lease(&self, repo: &str, branch: &str) -> Option<&Lease> {
        self.find_lease_key(repo, Some(branch))
            .and_then(|key| self.leases.get(&key))
    }

    /// The most specific lease in force that reaches `repo`, on any branch.
    pub fn get_active_lease(&self, repo: &str) -> Option<&Lease> {
        self.find_lease_key(repo, None)
            .and_then(|key| self.leases.get(&key))
    }

    pub fn has_active_lease(&self, repo: &str) -> bool {
        self.get_active_lease(repo).is_some()
    }

    /// Whether `branch` is protected under this policy (see
    /// [`branch_matches_blocked`]), unless `allow_main_branch` turns
    /// protection off.
    pub fn is_branch_blocked(&self, branch: &str) -> bool {
        !self.policy.allow_main_branch
            && branch_matches_blocked(branch, &self.policy.block_branches)
    }

    /// Grants a lease for this repository only.
    pub fn try_grant_lease(
        &mut self,
        repo: &str,
        branch: &str,
        intent: &str,
    ) -> Result<Lease, String> {
        self.try_grant_lease_covering(repo, branch, intent, Coverage::Repository)
    }

    /// Grants a lease with the coverage the person chose. A folder or
    /// everywhere is refused when the config keeps leases to one branch,
    /// since those can't be tied to one branch.
    pub fn try_grant_lease_covering(
        &mut self,
        repo: &str,
        branch: &str,
        intent: &str,
        coverage: Coverage,
    ) -> Result<Lease, String> {
        self.try_grant_for_work(repo, branch, intent, coverage, None)
    }

    /// Grants a lease with the coverage the person chose, for a piece of
    /// work: it ends when that work is finished (see [`Self::end_finished_work`]).
    pub fn try_grant_for_work(
        &mut self,
        repo: &str,
        branch: &str,
        intent: &str,
        coverage: Coverage,
        work: Option<Work>,
    ) -> Result<Lease, String> {
        // Enforce branch protection [INV-7] unless allow_main_branch is true
        if self.is_branch_blocked(branch) {
            return Err(format!(
                "Cannot grant lease: branch '{}' is a protected branch",
                branch
            ));
        }
        let wide = coverage != Coverage::Repository;
        if wide && !self.policy.follows_branches() {
            return Err(format!(
                "Cannot grant a lease covering {}: the config keeps leases to one branch",
                coverage.describe()
            ));
        }
        let key = coverage.key(repo);
        let lease_repo = match &coverage {
            Coverage::Repository => repo.to_string(),
            Coverage::Folder(folder) => folder.clone(),
            Coverage::Everywhere => EVERYWHERE.to_string(),
        };

        let now = current_epoch_secs();
        let expires_at_secs = match self.policy.mode {
            LeaseMode::Identity => {
                // If a max ceiling is configured, enforce it; otherwise indefinite
                self.policy.max_ceiling.map(|c| now + c.as_secs())
            }
            LeaseMode::Timed | LeaseMode::Process => Some(now + self.policy.default_ttl.as_secs()),
        };

        let lease = Lease {
            id: Uuid::new_v4().to_string(),
            repo: lease_repo,
            branch: branch.to_string(),
            intent: intent.to_string(),
            mode: self.policy.mode,
            // Wider scopes reach many repositories, so they cover every
            // unprotected branch in each (checked above that config allows it).
            scope: if wide {
                LeaseScope::Repo
            } else {
                self.policy.scope
            },
            granted_at_secs: now,
            last_used_at_secs: now,
            expires_at_secs,
            commit_count: 0,
            follows_branches: Some(self.policy.follows_branches()),
            coverage,
            work,
        };

        self.leases.insert(key, lease.clone());
        self.save_to_disk();
        Ok(lease)
    }

    pub fn grant_lease(&mut self, repo: &str, branch: &str, intent: &str) -> Lease {
        self.try_grant_lease(repo, branch, intent)
            .expect("Failed to grant lease")
    }

    /// Moves a lease that covers every unprotected branch to the branch the
    /// agent is now on. A lease approved for one branch only is never moved:
    /// working on another branch needs a new approval.
    pub fn switch_branch(&mut self, repo: &str, new_branch: &str) -> Result<Lease, String> {
        if self.is_branch_blocked(new_branch) {
            return Err(format!(
                "Cannot switch lease: branch '{}' is a protected branch",
                new_branch
            ));
        }

        let Some(current) = self.leases.get(repo) else {
            return Err(format!("No active lease found for repository '{}'", repo));
        };
        if !self.is_lease_active(current) {
            return Err(format!("Lease for repository '{}' has expired", repo));
        }
        if !self.covers_every_branch(current) {
            return Err(format!(
                "The lease for '{}' covers only branch '{}'; working on '{}' needs a new approval",
                repo, current.branch, new_branch
            ));
        }

        let lease = self.leases.get_mut(repo).expect("checked above");
        lease.branch = new_branch.to_string();
        lease.last_used_at_secs = current_epoch_secs();
        let updated = lease.clone();
        self.save_to_disk();
        Ok(updated)
    }

    /// Ends the lease filed under `target`: a repository's path, a folder's
    /// path (for a folder lease), or [`EVERYWHERE`]. Returns whether one
    /// was found.
    pub fn revoke_lease(&mut self, target: &str) -> bool {
        self.revoke_lease_durable(target).unwrap_or_else(|e| {
            eprintln!("[agent-sign] {e}");
            false
        })
    }

    pub fn revoke_lease_durable(&mut self, target: &str) -> Result<bool, String> {
        let target = if target.len() > 1 {
            target.trim_end_matches('/')
        } else {
            target
        };
        let key = [target.to_string(), format!("folder:{target}")]
            .into_iter()
            .find(|k| self.leases.contains_key(k));
        let removed = key.is_some_and(|k| self.leases.remove(&k).is_some());
        if removed {
            self.persist_revocation()?;
        }
        Ok(removed)
    }

    pub fn revoke_all(&mut self) -> usize {
        self.revoke_all_durable().unwrap_or_else(|e| {
            eprintln!("[agent-sign] {e}");
            0
        })
    }

    pub fn revoke_all_durable(&mut self) -> Result<usize, String> {
        let count = self.leases.len();
        self.leases.clear();
        self.persist_revocation()?;
        Ok(count)
    }

    fn persist_revocation(&self) -> Result<(), String> {
        match &self.storage_path {
            Some(path) => self.write_lease_file(path).map_err(|e| format!("revoked in memory but could not save revocation ({e}); old grants may return after restart. Repair the lease store before restarting; durable revocation was NOT confirmed")),
            None if self.storage_unavailable => Err("revoked in memory, but the existing lease store was unreadable; old grants may return after restart. Repair it before restarting; durable revocation was NOT confirmed".into()),
            None => Ok(()), // Explicitly memory-only engines have no persistent grants.
        }
    }

    pub fn get_status(&self, repo: &str) -> (bool, Option<String>, Option<String>, Option<u64>) {
        if let Some(lease) = self.get_active_lease(repo) {
            // A lease until revoked reports u64::MAX, as agent-sign did.
            let remaining = self
                .effective_end(lease)
                .map_or(u64::MAX, |end| end.saturating_sub(current_epoch_secs()));
            (
                true,
                Some(lease.id.clone()),
                Some(lease.branch.clone()),
                Some(remaining),
            )
        } else {
            (false, None, None, None)
        }
    }

    pub fn list_leases(&self) -> Vec<LeaseInfo> {
        let mut list = Vec::new();
        for lease in self.leases.values() {
            if self.is_lease_active(lease) {
                list.push(LeaseInfo {
                    lease_id: lease.id.clone(),
                    repo: lease.repo.clone(),
                    branch: lease.branch.clone(),
                    mode: format!("{:?}", lease.mode).to_lowercase(),
                    granted_at_epoch: lease.granted_at_secs,
                    last_used_epoch: lease.last_used_at_secs,
                    commit_count: lease.commit_count,
                    covers: lease.coverage.describe(),
                    ends: self.describe_endings(lease),
                    expires_in_secs: self
                        .effective_end(lease)
                        .map(|end| end.saturating_sub(current_epoch_secs())),
                });
            }
        }
        list.sort_by_key(|a| std::cmp::Reverse(a.last_used_epoch));
        list
    }

    /// Checks a single-use commit token for `repo` on `branch` (branch
    /// rules, a lease in force, the rate limit) and counts the commit.
    pub fn issue_commit_token(&mut self, repo: &str, branch: &str) -> Result<String, String> {
        self.token_for(repo, branch)
    }

    /// The same checks for a run token, for one git run that may make
    /// several commits (a rebase replays many). The run counts once against
    /// `max_commits_per_minute`, however many commits it signs: the limit
    /// guards against runaway loops of separate git runs, and counting each
    /// signature made a rebase of more commits than the limit fail halfway
    /// (seen in the live check on the server, 28 Oct). A run token's
    /// signatures stay bounded by its lifetime, its lease, and its
    /// repository and branch.
    pub fn issue_run_token(&mut self, repo: &str, branch: &str) -> Result<String, String> {
        self.token_for(repo, branch)
    }

    /// Records one signature made with a run token for `repo` on `branch`
    /// in the lease's usage record, or refuses it when no lease covers it
    /// any more. It doesn't count against the rate limit: the run already
    /// counted once when its token was issued.
    pub fn record_signature(&mut self, repo: &str, branch: &str) -> Result<(), String> {
        let Some(key) = self.find_lease_key(repo, Some(branch)) else {
            return Err("the lease this git run was signing under has ended".to_string());
        };
        self.note_use(&key);
        Ok(())
    }

    /// Records a commit in `repo`'s sliding 60-second window, or refuses it
    /// when `max_commits_per_minute` are already in it.
    fn count_commit(&mut self, repo: &str) -> Result<(), String> {
        let now = Instant::now();
        let timestamps = self.commit_timestamps.entry(repo.to_string()).or_default();
        timestamps.retain(|&t| now.duration_since(t) < Duration::from_secs(60));
        if timestamps.len() as u32 >= self.policy.max_commits_per_minute {
            return Err(format!(
                "Rate limit exceeded: maximum {} commits per minute allowed",
                self.policy.max_commits_per_minute
            ));
        }
        timestamps.push(now);
        Ok(())
    }

    /// Updates a lease's usage record (never its end).
    fn note_use(&mut self, key: &str) {
        if let Some(lease) = self.leases.get_mut(key) {
            lease.commit_count += 1;
            lease.last_used_at_secs = current_epoch_secs();
            self.save_to_disk();
        }
    }

    fn token_for(&mut self, repo: &str, branch: &str) -> Result<String, String> {
        // 0. Branch rules, checked on every token and for every scope: a lease
        // never covers a protected branch. Checking only when a lease is
        // granted or moved let repository-scoped leases sign on `main`.
        if self.is_branch_blocked(branch) {
            return Err(format!(
                "Branch '{}' is protected: a lease never covers it, so the commit is refused",
                branch
            ));
        }

        // 1. Find the lease in force that covers this repository and branch
        let Some(key) = self.find_lease_key(repo, Some(branch)) else {
            return Err(match (self.get_active_lease(repo), self.leases.get(repo)) {
                (Some(lease), _) => format!(
                    "Lease was granted for branch '{}', not '{}'",
                    lease.branch, branch
                ),
                (None, Some(_)) => format!("Lease for repository '{}' has expired", repo),
                (None, None) => format!("No lease found for repository '{}'", repo),
            });
        };

        // 2. Rate limiter (sliding 60s window): one count per commit or per
        // git run, however many commits the run signs.
        self.count_commit(repo)?;
        // 3. Update lease statistics (never its end)
        self.note_use(&key);

        // 4. Issue the token
        Ok(format!("ev_{}", Uuid::new_v4()))
    }
}
