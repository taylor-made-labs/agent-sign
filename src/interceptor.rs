pub struct InterceptorDecision {
    pub is_commit: bool,
    pub commit_index: Option<usize>,
}

pub struct CommandInterceptor;

impl Default for CommandInterceptor {
    fn default() -> Self {
        Self::new()
    }
}

impl CommandInterceptor {
    pub fn new() -> Self {
        Self
    }

    /// Inspects git command arguments to determine if `commit` is being invoked.
    /// Handles preceding git global options (e.g. `git -C /dir commit -m "..."`).
    pub fn inspect_command(&self, args: &[String]) -> InterceptorDecision {
        let mut idx = 0;
        let mut is_commit = false;
        let mut commit_index = None;

        while idx < args.len() {
            let arg = &args[idx];

            // If we encounter standard git options taking 1 argument
            if arg == "-C" || arg == "-c" || arg == "--git-dir" || arg == "--work-tree" {
                idx += 2;
                continue;
            }

            // Flag options
            if arg.starts_with('-') {
                idx += 1;
                continue;
            }

            // First non-flag is the git subcommand
            if arg == "commit" {
                is_commit = true;
                commit_index = Some(idx);
            }
            break;
        }

        InterceptorDecision {
            is_commit,
            commit_index,
        }
    }
}

/// What a commit's own options say about signing, if anything: `Some(false)`
/// for `--no-gpg-sign`, `Some(true)` for `-S`/`--gpg-sign[=key]`, the last
/// one winning as in git; `None` when neither is given. Options after `--`
/// are paths, not options.
pub fn signing_flag(commit_args: &[String]) -> Option<bool> {
    let mut decided = None;
    for arg in commit_args {
        if arg == "--" {
            break;
        }
        if arg == "--no-gpg-sign" {
            decided = Some(false);
        } else if arg.starts_with("-S") || arg.starts_with("--gpg-sign") {
            decided = Some(true);
        }
    }
    decided
}

/// Whether `git config --show-scope --type=bool --get commit.gpgsign` output
/// says signing was turned off for this command or this repository
/// (`command`, `local` or `worktree` scope). A global or system setting
/// doesn't count: agent commits are signed whatever the person's own default.
pub fn config_declines_signing(show_scope_output: &str) -> bool {
    let mut parts = show_scope_output.trim().splitn(2, '\t');
    let scope = parts.next().unwrap_or_default();
    let value = parts.next().unwrap_or_default().trim();
    value == "false" && matches!(scope, "command" | "local" | "worktree")
}
