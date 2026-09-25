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
