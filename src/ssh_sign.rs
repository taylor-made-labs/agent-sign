//! The signing program git calls as `gpg.ssh.program` (`agent-ssh-sign`).
//!
//! Git runs it with ssh-keygen's arguments (`-Y sign -n git -f <key> <file>`)
//! and expects `<file>.sig` to be written. When the git wrapper has set an
//! `AGENT_EVENT_TOKEN`, the buffer is sent to the service, which signs it with
//! the agent key. Without a token the arguments are passed unchanged to the
//! configured `fallback_program` (the person's own signer), unless an agent is
//! behind the call (see [`crate::attribution::agent_run_with`]): then a request
//! to sign is refused, since agent work is never signed with the person's key,
//! and a request to verify goes to plain `ssh-keygen`, which needs no key.
//!
//! A token counts only with the wrapper's own mark beside it
//! ([`crate::attribution::AGENT_RUN_VAR`]): a token that leaked into another
//! environment (the person's shell, a tool that copied an agent's
//! environment) is ignored, and the person's commit goes to their own
//! signer. With a token, the service is also told which repository and
//! branch the git run is writing ([`crate::git_place`]), and refuses a
//! signature for anywhere other than the token's.
//!
//! It lives in the library so that `agent-ssh-sign` and `agent-sign` (which
//! also accepts git's signing arguments, as it always has) run exactly the
//! same code.

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, ExitCode};

use base64::Engine;

use crate::config::Config;
use crate::multiplexer::{Multiplexer, SigningAction};
use crate::protocol::{Request, Response, client_socket_path, send_request};

/// Environment variable carrying the single-use token from the git wrapper to
/// the signing program.
pub const EVENT_TOKEN_VAR: &str = "AGENT_EVENT_TOKEN";

/// Runs the signing program with git's arguments (without the program name)
/// and returns the exit code to report to git.
pub fn run(args: &[String]) -> ExitCode {
    // Called with gpg's arguments: the git wrapper names this program as
    // `gpg.program` for agents' commands, so that checking an OpenPGP
    // signature still works while making one never reaches the person's key.
    if !args.iter().any(|a| a == "-Y") {
        if is_gpg_verify(args) {
            let gpg = crate::paths::find_on_path_outside_agent_sign("gpg")
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "gpg".to_string());
            return delegate_to_system_ssh_keygen(args, &gpg);
        }
        eprintln!(
            "[agent-ssh-sign] Refused: an agent's git asked for an OpenPGP signature, which would \
             have used your own key. Agent work is never signed with your key."
        );
        return ExitCode::from(1);
    }

    let config = Config::load(None);
    let fallback_prog = config.ssh.fallback_program.clone();
    let multiplexer = Multiplexer::new(config);

    // A token is the wrapper's, for a git it runs for an agent, and that git
    // always has the wrapper's mark too. Without the mark the token leaked
    // (identity review, 28 Oct 2026: a token left in the person's terminal
    // made their own commit sign as the agent), so it's ignored.
    let token_var = env::var(EVENT_TOKEN_VAR)
        .ok()
        .filter(|_| wrappers_mark_present(|k| env::var(k).ok()));
    let action = multiplexer.determine_action(token_var.as_deref());

    match action {
        SigningAction::DelegateToSystemSshKeygen
            if crate::attribution::agent_run_with(|k| env::var(k).ok()) =>
        {
            if is_signing_request(args) {
                eprintln!(
                    "[agent-ssh-sign] Refused: an agent's git asked to sign outside agent-sign's commit \
                     path, which would have used your own key. Agent work is never signed with your key."
                );
                return ExitCode::from(1);
            }
            delegate_to_system_ssh_keygen(args, &plain_ssh_keygen())
        }
        SigningAction::DelegateToSystemSshKeygen => {
            // Forward directly to configured fallback program (e.g. 1Password op-ssh-sign or ssh-keygen)
            delegate_to_system_ssh_keygen(args, &fallback_prog)
        }
        SigningAction::SignWithAgentKey(token) => {
            // Validate token format fails closed
            if let Err(e) = multiplexer.validate_event_token(Some(&token)) {
                eprintln!("[agent-ssh-sign] Event token validation failed: {}", e);
                return ExitCode::from(1);
            }
            sign_with_agent_daemon(args, &token)
        }
    }
}

/// Whether the wrapper's mark ([`crate::attribution::AGENT_RUN_VAR`]) is set
/// (and isn't empty or `0`) in the environment `get` reads: the only
/// environment in which a token is used.
pub fn wrappers_mark_present(get: impl Fn(&str) -> Option<String>) -> bool {
    get(crate::attribution::AGENT_RUN_VAR).is_some_and(|v| !v.is_empty() && v != "0")
}

/// Whether gpg's arguments only check a signature: `--verify`, and nothing
/// that could sign. git asks gpg to sign with `-bsau <key>`, and the key is
/// whatever `user.signingkey` says (even `--verify`), so any bundle of short
/// options with `s`, `b`, `u`, `a`, `e` or `c`, or a long signing or
/// encrypting option, makes it not a check. git checks with
/// `--keyid-format=long --status-fd=1 --verify <file> -`.
pub fn is_gpg_verify(args: &[String]) -> bool {
    let could_sign = args.iter().any(|a| {
        if let Some(long) = a.strip_prefix("--") {
            matches!(
                long.split('=').next().unwrap_or(""),
                "sign"
                    | "detach-sign"
                    | "clearsign"
                    | "clear-sign"
                    | "local-user"
                    | "encrypt"
                    | "symmetric"
            )
        } else if let Some(short) = a.strip_prefix('-') {
            short
                .chars()
                .any(|c| matches!(c, 's' | 'b' | 'u' | 'a' | 'e' | 'c'))
        } else {
            false
        }
    });
    args.iter().any(|a| a == "--verify") && !could_sign
}

/// Whether git is asking for a signature (`-Y sign`), as opposed to checking
/// one (`-Y verify`, `find-principals`, `check-novalidate`).
pub fn is_signing_request(args: &[String]) -> bool {
    args.windows(2).any(|w| w[0] == "-Y" && w[1] == "sign")
}

/// The system's `ssh-keygen`, for checking signatures on an agent's behalf.
fn plain_ssh_keygen() -> String {
    ["/usr/bin/ssh-keygen", "/usr/local/bin/ssh-keygen"]
        .into_iter()
        .find(|p| std::path::Path::new(p).exists())
        .unwrap_or("ssh-keygen")
        .to_string()
}

fn delegate_to_system_ssh_keygen(args: &[String], fallback_program: &str) -> ExitCode {
    let status = Command::new(fallback_program).args(args).status();

    match status {
        Ok(s) => ExitCode::from(s.code().unwrap_or(1) as u8),
        Err(e) => {
            eprintln!(
                "[agent-ssh-sign] Failed to execute fallback signing program '{}': {}",
                fallback_program, e
            );
            ExitCode::from(1)
        }
    }
}

fn sign_with_agent_daemon(args: &[String], token: &str) -> ExitCode {
    // Expected arguments from git:
    // -Y sign -n git -f <key_path> <file_to_sign>
    let mut file_to_sign: Option<PathBuf> = None;
    let mut idx = 0;

    while idx < args.len() {
        let arg = &args[idx];
        if arg == "-Y" || arg == "-n" || arg == "-f" {
            idx += 2;
            continue;
        }
        if !arg.starts_with('-') {
            file_to_sign = Some(PathBuf::from(arg));
            break;
        }
        idx += 1;
    }

    let file_path = match file_to_sign {
        Some(p) => p,
        None => {
            eprintln!(
                "[agent-ssh-sign] Error: No file to sign provided in git arguments: {:?}",
                args
            );
            return ExitCode::from(1);
        }
    };

    let buffer = match fs::read(&file_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!(
                "[agent-ssh-sign] Error reading buffer file {}: {}",
                file_path.display(),
                e
            );
            return ExitCode::from(1);
        }
    };

    let buffer_b64 = base64::engine::general_purpose::STANDARD.encode(&buffer);
    let socket_path = client_socket_path();

    // Where this git run is writing, asked of the real git from git's own
    // folder and environment (git runs its signing program there), so the
    // service can refuse a signature for anywhere but the token's repository
    // and branch. If git can't say, nothing is sent and the service refuses.
    let place = crate::git_place::repo_and_branch(|args| {
        let out = Command::new(crate::paths::real_git())
            .args(args)
            .stdin(std::process::Stdio::null())
            .output()
            .ok()?;
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
    });
    let (repo, branch) = place.unzip();
    let req = Request::SignCommit {
        token: token.to_string(),
        buffer_b64,
        repo,
        branch,
    };

    let resp = match send_request(&socket_path, &req) {
        Ok(r) => r,
        Err(e) => {
            eprintln!(
                "[agent-ssh-sign] Failed to communicate with the agent-sign service at {}: {}",
                socket_path.display(),
                e
            );
            eprintln!("[agent-ssh-sign] Ensure `agent-signd` is running.");
            return ExitCode::from(1);
        }
    };

    match resp {
        Response::Signed { signature_pem } => {
            // OpenSSH ssh-keygen creates <file>.sig
            let sig_file_path = PathBuf::from(format!("{}.sig", file_path.display()));
            if let Err(e) = fs::write(&sig_file_path, signature_pem) {
                eprintln!(
                    "[agent-ssh-sign] Failed to write signature to {}: {}",
                    sig_file_path.display(),
                    e
                );
                return ExitCode::from(1);
            }
            ExitCode::SUCCESS
        }
        Response::Error { message } => {
            eprintln!(
                "[agent-ssh-sign] Signing rejected by the agent-sign service: {}",
                message
            );
            ExitCode::from(1)
        }
        other => {
            eprintln!(
                "[agent-ssh-sign] Unexpected response from the agent-sign service: {:?}",
                other
            );
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::is_signing_request;

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_string).collect()
    }

    #[test]
    fn a_gpg_check_is_told_apart_from_a_disguised_signing_request() {
        assert!(super::is_gpg_verify(&args(
            "--keyid-format=long --status-fd=1 --verify /tmp/sig -"
        )));
        assert!(!super::is_gpg_verify(&args("--status-fd=2 -bsau --verify")));
        assert!(!super::is_gpg_verify(&args("--verify --sign x")));
        assert!(!super::is_gpg_verify(&args("--verify --local-user=k x")));
        assert!(!super::is_gpg_verify(&args("--status-fd=2 -bsau KEY")));
    }

    #[test]
    fn a_request_to_sign_is_told_apart_from_a_check() {
        assert!(is_signing_request(&args("-Y sign -n git -f key.pub buf")));
        assert!(is_signing_request(&args(
            "-Y sign -n git -f key.pub -U buf"
        )));
        assert!(!is_signing_request(&args(
            "-Y verify -n git -f signers -I p -s s"
        )));
        assert!(!is_signing_request(&args(
            "-Y find-principals -f signers -s s"
        )));
        assert!(!is_signing_request(&args(
            "-Y check-novalidate -n git -s s"
        )));
    }
}
