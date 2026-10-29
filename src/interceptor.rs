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

/// `git commit`'s short options that take a value, attached (`-mmsg`) or as
/// the next argument (`-m msg`): what follows them is never an option.
const COMMIT_SHORT_WITH_VALUE: [char; 5] = ['m', 'F', 'C', 'c', 't'];

/// `git commit`'s long options that take a value, which may be the next
/// argument (`--message -S` is a message that reads "-S").
const COMMIT_LONG_WITH_VALUE: [&str; 12] = [
    "message",
    "file",
    "reuse-message",
    "reedit-message",
    "template",
    "author",
    "date",
    "cleanup",
    "fixup",
    "squash",
    "trailer",
    "pathspec-from-file",
];

/// A commit's own options without any request to sign: `-S` (with its
/// attached key id, and taken out of a bundle such as `-qS`), and
/// `--gpg-sign[=<key>]` with any abbreviation git accepts. Values of options
/// that take one (`-m -S`, `--message -S`) are kept as they are, and so is
/// everything after `--`, which are paths.
///
/// For a commit that must be unsigned whatever it asked (an unmarked commit
/// with no terminal, see the wrapper's `exec_unmarked_commit`): before the
/// follow-up round (28 Oct 2026) such a commit's `-S` came after the
/// wrapper's own settings, so git asked the signing program the wrapper had
/// replaced with one that fails, and the commit failed.
pub fn without_signing_requests(commit_args: &[String]) -> Vec<String> {
    let mut kept = Vec::with_capacity(commit_args.len());
    let mut i = 0;
    while i < commit_args.len() {
        let arg = &commit_args[i];
        i += 1;
        if arg == "--" {
            kept.extend(commit_args[i - 1..].iter().cloned());
            break;
        }
        if let Some(long) = arg.strip_prefix("--") {
            let name = long.split('=').next().unwrap_or("");
            if arg.len() >= 3 && "gpg-sign".starts_with(name) {
                continue;
            }
            kept.push(arg.clone());
            if !long.contains('=')
                && name.len() >= 2
                && COMMIT_LONG_WITH_VALUE.iter().any(|o| o.starts_with(name))
                && i < commit_args.len()
            {
                kept.push(commit_args[i].clone());
                i += 1;
            }
            continue;
        }
        let Some(bundle) = arg.strip_prefix('-').filter(|b| !b.is_empty()) else {
            kept.push(arg.clone());
            continue;
        };
        // The first letter that ends the bundle: `S` (whose key id is the
        // rest), `u` (whose mode is the rest), or one that takes a value.
        match bundle
            .char_indices()
            .find(|(_, c)| *c == 'S' || *c == 'u' || COMMIT_SHORT_WITH_VALUE.contains(c))
        {
            Some((at, 'S')) => {
                if at > 0 {
                    kept.push(format!("-{}", &bundle[..at]));
                }
            }
            Some((at, c)) if c != 'u' && at + 1 == bundle.len() => {
                kept.push(arg.clone());
                if i < commit_args.len() {
                    kept.push(commit_args[i].clone());
                    i += 1;
                }
            }
            _ => kept.push(arg.clone()),
        }
    }
    kept
}

/// git's global options (those before the subcommand) without any setting
/// of `commit.gpgsign` (`-c commit.gpgsign[=...]`, `--config-env
/// commit.gpgsign=VAR`, `--config-env=commit.gpgsign=VAR`, the key in any
/// case, as git reads it). Other options, and their values, are kept as
/// they are.
pub fn without_gpgsign_settings(global_args: &[String]) -> Vec<String> {
    let sets_gpgsign = |setting: &str| {
        setting
            .split('=')
            .next()
            .unwrap_or("")
            .eq_ignore_ascii_case("commit.gpgsign")
    };
    let mut kept = Vec::with_capacity(global_args.len());
    let mut i = 0;
    while i < global_args.len() {
        let arg = global_args[i].as_str();
        let value = global_args.get(i + 1);
        if arg == "-c" || arg == "--config-env" {
            if !value.is_some_and(|v| sets_gpgsign(v)) {
                kept.push(arg.to_string());
                kept.extend(value.cloned());
            }
            i += 2;
        } else if let Some(setting) = arg.strip_prefix("--config-env=") {
            if !sets_gpgsign(setting) {
                kept.push(arg.to_string());
            }
            i += 1;
        } else if GLOBAL_OPTIONS_WITH_VALUES.contains(&arg) {
            kept.push(arg.to_string());
            kept.extend(value.cloned());
            i += 2;
        } else {
            kept.push(arg.to_string());
            i += 1;
        }
    }
    kept
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

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(args: &[&str]) -> Vec<String> {
        args.iter().map(|a| a.to_string()).collect()
    }

    #[test]
    fn signing_requests_are_taken_out_of_a_commits_options() {
        for (given, kept) in [
            (&["-S", "-m", "x"][..], &["-m", "x"][..]),
            (&["-qS", "-m", "x"], &["-q", "-m", "x"]),
            (&["-SKEYID", "-m", "x"], &["-m", "x"]),
            (&["--gpg-sign=KEY", "-a"], &["-a"]),
            (&["--gpg", "-a"], &["-a"]),
            (&["-m", "-S"], &["-m", "-S"]),
            (&["-qm", "-S"], &["-qm", "-S"]),
            (&["-m-S"], &["-m-S"]),
            (&["--message", "-S"], &["--message", "-S"]),
            (&["--message=-S", "-S"], &["--message=-S"]),
            (&["-a", "--", "-S"], &["-a", "--", "-S"]),
            (&["--no-gpg-sign"], &["--no-gpg-sign"]),
        ] {
            assert_eq!(
                without_signing_requests(&strings(given)),
                strings(kept),
                "{given:?}"
            );
        }
    }

    #[test]
    fn gpgsign_settings_are_taken_out_of_global_options() {
        for (given, kept) in [
            (&["-c", "commit.gpgsign=true"][..], &[][..]),
            (&["-c", "Commit.GpgSign"], &[]),
            (
                &["--config-env", "commit.gpgsign=V", "-C", "d"],
                &["-C", "d"],
            ),
            (&["--config-env=commit.gpgsign=V"], &[]),
            (
                &["-c", "user.name=x", "-C", "-c"],
                &["-c", "user.name=x", "-C", "-c"],
            ),
        ] {
            assert_eq!(
                without_gpgsign_settings(&strings(given)),
                strings(kept),
                "{given:?}"
            );
        }
    }
}
