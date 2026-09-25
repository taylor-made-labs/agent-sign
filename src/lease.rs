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
    pub max_commits_per_minute: u32,
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

    pub fn has_active_lease(&self, repo: &str) -> bool {
        if let Some(lease) = self.leases.get(repo) {
            Instant::now() < lease.expires_at
        } else {
            false
        }
    }

    pub fn try_grant_lease(
        &mut self,
        repo: &str,
        branch: &str,
        intent: &str,
    ) -> Result<Lease, String> {
        // Enforce branch protection [INV-7]
        for blocked in &self.policy.block_branches {
            if branch == blocked
                || (blocked.ends_with('*') && branch.starts_with(blocked.trim_end_matches('*')))
            {
                return Err(format!(
                    "Cannot grant lease: branch '{}' is a protected branch ({})",
                    branch, blocked
                ));
            }
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
