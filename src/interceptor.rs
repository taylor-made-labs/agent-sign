pub struct InterceptorDecision {
    pub is_commit: bool,
    pub commit_index: Option<usize>,
    /// Where the git subcommand (or alias) is, whatever it is.
    pub subcommand_index: Option<usize>,
}

/// git's global options that take their value as the next argument. Missing
/// one here makes its value look like the subcommand, so a commit after it
/// would skip the wrapper: the list follows `git --help` (git 2.50).
const GLOBAL_OPTIONS_WITH_VALUES: [&str; 9] = [
    "-C",
    "-c",
    "--git-dir",
    "--work-tree",
    "--namespace",
    "--config-env",
    "--attr-source",
    "--super-prefix",
    // Undocumented, but git accepts it.
    "--shallow-file",
];

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
        let mut subcommand_index = None;

        while idx < args.len() {
            let arg = &args[idx];

            // If we encounter standard git options taking 1 argument
            if GLOBAL_OPTIONS_WITH_VALUES.contains(&arg.as_str()) {
                idx += 2;
                continue;
            }

            // Flag options
            if arg.starts_with('-') {
                idx += 1;
                continue;
            }

            // First non-flag is the git subcommand
            subcommand_index = Some(idx);
            if arg == "commit" {
                is_commit = true;
                commit_index = Some(idx);
            }
            break;
        }

        InterceptorDecision {
            is_commit,
            commit_index,
            subcommand_index,
        }
    }
}

/// What a commit's own options say about signing, if anything: `Some(false)`
/// for `--no-gpg-sign`, `Some(true)` for a request to sign, the last one
/// winning as in git; `None` when neither is given. Options after `--` are
/// paths, not options.
///
/// It errs towards "wants signing", which sends the commit through the
/// agent path (asking, and signing with the agent key): any bundle of short
/// options containing `S` (such as `-qS` or `-aS`), and any abbreviation git
/// accepts for `--gpg-sign` (down to `--g`). Reading it wrong the other way
/// is harmless too, since a commit taken for "signing off" runs with signing
/// disabled (see the wrapper's `exec_unsigned`).
pub fn signing_flag(commit_args: &[String]) -> Option<bool> {
    let mut decided = None;
    for arg in commit_args {
        if arg == "--" {
            break;
        }
        if arg == "--no-gpg-sign" {
            decided = Some(false);
        } else if arg.len() >= 3 && "--gpg-sign".starts_with(arg.split('=').next().unwrap_or(""))
            || arg.starts_with("--gpg-sign")
            || (arg.starts_with('-') && !arg.starts_with("--") && arg.contains('S'))
        {
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
