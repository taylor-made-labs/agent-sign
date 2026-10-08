//! Leases: the person's approval, given once, for the agent key to sign
//! commits in one repository without asking again.
//!
//! agent-commits' lease model: a lease's terms are fixed when the person approves it,
//! and they never grow on their own. The terms are its scope (one repository;
//! within it, either one branch or every unprotected branch) and its end (a
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

use crate::config::{LeaseMode, LeaseScope};
use crate::protocol::LeaseInfo;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

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
    /// leases granted before agent-commits recorded this term: for those the current
    /// config decides, which is how they behaved when they were granted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub follows_branches: Option<bool>,
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
            allow_branch_switching: true,
            max_commits_per_minute: 10,
        }
    }
}

/// A new lease's terms in plain words, for the approval prompt: what the
/// person approves is exactly what the lease will be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TermsText {
    /// Which branches it covers.
    pub covers: String,
    /// When it ends.
    pub ends: String,
}

impl LeasePolicy {
    /// The terms a lease granted now for `branch` would get.
    pub fn describe_terms(&self, branch: &str) -> TermsText {
        let covers = if self.scope == LeaseScope::Repo || self.allow_branch_switching {
            if self.allow_main_branch || self.block_branches.is_empty() {
                "every branch of this repository".to_string()
            } else {
                format!(
                    "every branch of this repository except protected ones ({})",
                    self.block_branches.join(", ")
                )
            }
        } else {
            format!("only branch '{}'", branch)
        };
        let ends = match (self.mode, self.max_ceiling) {
            (LeaseMode::Identity, None) => "when you revoke it (agent-commits revoke)".to_string(),
            (LeaseMode::Identity, Some(cap)) => format!(
                "{} after approval, or sooner if you revoke it",
                describe_duration(cap)
            ),
            (LeaseMode::Timed, _) => format!(
                "{} after approval, or sooner if you revoke it",
                describe_duration(self.default_ttl)
            ),
            (LeaseMode::Process, _) => format!(
                "{} after approval, or sooner if you revoke it (\"process\" mode is not tied to a process yet; it works as \"timed\")",
                describe_duration(self.default_ttl)
            ),
        };
        TermsText { covers, ends }
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

pub struct LeaseEngine {
    pub policy: LeasePolicy,
    storage_path: Option<PathBuf>,
    leases: HashMap<String, Lease>,
    commit_timestamps: HashMap<String, Vec<Instant>>,
}

impl LeaseEngine {
    pub fn new(policy: LeasePolicy) -> Self {
        Self {
            policy,
            storage_path: None,
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
                            "[agent-commits] {} is not a valid lease file ({}). Moved it to {} and started with no leases: each repository will ask for approval again.",
                            path.display(),
                            e,
                            aside.display()
                        ),
                        Err(re) => {
                            eprintln!(
                                "[agent-commits] {} is not a valid lease file ({}) and could not be moved aside ({}). Leaving it untouched; leases granted now last until the service stops.",
                                path.display(),
                                e,
                                re
                            );
                            engine.storage_path = None;
                        }
                    }
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                eprintln!(
                    "[agent-commits] Could not read {} ({}). Leaving it untouched and starting with no leases; leases granted now last until the service stops.",
                    path.display(),
                    e
                );
                engine.storage_path = None;
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
                "[agent-commits] Could not save leases to {} ({}). They still apply until the service stops.",
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
            .and_then(|_| fs::rename(&tmp_path, path));
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

    /// Whether a lease is still in force under its terms and the current config.
    pub fn is_lease_active(&self, lease: &Lease) -> bool {
        self.effective_end(lease)
            .is_none_or(|end| current_epoch_secs() < end)
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

    pub fn get_active_lease(&self, repo: &str) -> Option<&Lease> {
        self.leases
            .get(repo)
            .filter(|lease| self.is_lease_active(lease))
    }

    pub fn has_active_lease(&self, repo: &str) -> bool {
        self.get_active_lease(repo).is_some()
    }

    pub fn is_branch_blocked(&self, branch: &str) -> bool {
        if self.policy.allow_main_branch {
            return false;
        }
        for blocked in &self.policy.block_branches {
            if branch == blocked
                || (blocked.ends_with('*') && branch.starts_with(blocked.trim_end_matches('*')))
            {
                return true;
            }
        }
        false
    }

    pub fn try_grant_lease(
        &mut self,
        repo: &str,
        branch: &str,
        intent: &str,
    ) -> Result<Lease, String> {
        // Enforce branch protection [INV-7] unless allow_main_branch is true
        if self.is_branch_blocked(branch) {
            return Err(format!(
                "Cannot grant lease: branch '{}' is a protected branch",
                branch
            ));
        }

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
            repo: repo.to_string(),
            branch: branch.to_string(),
            intent: intent.to_string(),
            mode: self.policy.mode,
            scope: self.policy.scope,
            granted_at_secs: now,
            last_used_at_secs: now,
            expires_at_secs,
            commit_count: 0,
            follows_branches: Some(
                self.policy.scope == LeaseScope::Repo || self.policy.allow_branch_switching,
            ),
        };

        self.leases.insert(repo.to_string(), lease.clone());
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

    pub fn revoke_lease(&mut self, repo: &str) -> bool {
        let removed = self.leases.remove(repo).is_some();
        if removed {
            self.save_to_disk();
        }
        removed
    }

    pub fn revoke_all(&mut self) -> usize {
        let count = self.leases.len();
        self.leases.clear();
        self.save_to_disk();
        count
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
                    expires_in_secs: self
                        .effective_end(lease)
                        .map(|end| end.saturating_sub(current_epoch_secs())),
                });
            }
        }
        list.sort_by_key(|a| std::cmp::Reverse(a.last_used_epoch));
        list
    }

    pub fn issue_commit_token(&mut self, repo: &str, branch: &str) -> Result<String, String> {
        // 0. Branch rules, checked on every token and for every scope: a lease
        // never covers a protected branch. Checking only when a lease is
        // granted or moved let repository-scoped leases sign on `main`.
        if self.is_branch_blocked(branch) {
            return Err(format!(
                "Branch '{}' is protected: a lease never covers it, so the commit is refused",
                branch
            ));
        }

        // 1. Verify the lease is in force and covers this branch
        let Some(lease) = self.leases.get(repo) else {
            return Err(format!("No lease found for repository '{}'", repo));
        };
        if !self.is_lease_active(lease) {
            return Err(format!("Lease for repository '{}' has expired", repo));
        }
        if !self.lease_covers(lease, branch) {
            return Err(format!(
                "Lease was granted for branch '{}', not '{}'",
                lease.branch, branch
            ));
        }

        // 2. Rate limiter check (sliding 60s window)
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

        // 3. Update lease statistics (never its end)
        let lease = self.leases.get_mut(repo).expect("checked above");
        lease.commit_count += 1;
        lease.last_used_at_secs = current_epoch_secs();
        self.save_to_disk();

        // 4. Issue single-use event token
        Ok(format!("ev_{}", Uuid::new_v4()))
    }
}
