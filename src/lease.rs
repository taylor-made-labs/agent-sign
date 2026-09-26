use std::collections::HashMap;
use std::time::{Duration, Instant};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct Lease {
    pub id: String,
    pub repo: String,
    pub branch: String,
    pub intent: String,
    pub granted_at: Instant,
    pub expires_at: Instant,
}

#[derive(Debug, Clone)]
pub struct LeasePolicy {
    pub default_ttl: Duration,
    pub block_branches: Vec<String>,
    pub allow_main_branch: bool,
    pub allow_branch_switching: bool,
    pub max_commits_per_minute: u32,
}

impl Default for LeasePolicy {
    fn default() -> Self {
        Self {
            default_ttl: Duration::from_secs(7200),
            block_branches: vec!["main".to_string(), "master".to_string()],
            allow_main_branch: false,
            allow_branch_switching: true,
            max_commits_per_minute: 10,
        }
    }
}

pub struct LeaseEngine {
    pub policy: LeasePolicy,
    leases: HashMap<String, Lease>,
    commit_timestamps: HashMap<String, Vec<Instant>>,
}

impl LeaseEngine {
    pub fn new(policy: LeasePolicy) -> Self {
        Self {
            policy,
            leases: HashMap::new(),
            commit_timestamps: HashMap::new(),
        }
    }

    pub fn get_active_lease(&self, repo: &str) -> Option<&Lease> {
        if let Some(lease) = self.leases.get(repo)
            && Instant::now() < lease.expires_at
        {
            return Some(lease);
        }
        None
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

        let now = Instant::now();
        let lease = Lease {
            id: Uuid::new_v4().to_string(),
            repo: repo.to_string(),
            branch: branch.to_string(),
            intent: intent.to_string(),
            granted_at: now,
            expires_at: now + self.policy.default_ttl,
        };

        self.leases.insert(repo.to_string(), lease.clone());
        Ok(lease)
    }

    pub fn switch_branch(&mut self, repo: &str, new_branch: &str) -> Result<Lease, String> {
        if self.is_branch_blocked(new_branch) {
            return Err(format!(
                "Cannot switch lease: branch '{}' is a protected branch",
                new_branch
            ));
        }

        if let Some(lease) = self.leases.get_mut(repo) {
            if Instant::now() >= lease.expires_at {
                return Err(format!("Lease for repository '{}' has expired", repo));
            }
            lease.branch = new_branch.to_string();
            Ok(lease.clone())
        } else {
            Err(format!("No active lease found for repository '{}'", repo))
        }
    }

    pub fn revoke_lease(&mut self, repo: &str) -> bool {
        self.leases.remove(repo).is_some()
    }

    pub fn get_status(&self, repo: &str) -> (bool, Option<String>, Option<String>, Option<u64>) {
        if let Some(lease) = self.get_active_lease(repo) {
            let remaining = lease
                .expires_at
                .saturating_duration_since(Instant::now())
                .as_secs();
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

    pub fn grant_lease(&mut self, repo: &str, branch: &str, intent: &str) -> Lease {
        self.try_grant_lease(repo, branch, intent)
            .expect("Failed to grant lease")
    }

    pub fn issue_commit_token(&mut self, repo: &str, branch: &str) -> Result<String, String> {
        // 1. Verify active lease
        let lease = self
            .leases
            .get(repo)
            .ok_or_else(|| format!("No lease found for repository '{}'", repo))?;

        if Instant::now() >= lease.expires_at {
            return Err(format!("Lease for repository '{}' has expired", repo));
        }

        // Branch check
        if lease.branch != branch {
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

        // 3. Issue single-use event token
        Ok(format!("ev_{}", Uuid::new_v4()))
    }
}
