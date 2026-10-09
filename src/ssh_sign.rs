//! The signing program git calls as `gpg.ssh.program` (`agent-ssh-sign`).
//!
//! Git runs it with ssh-keygen's arguments (`-Y sign -n git -f <key> <file>`)
//! and expects `<file>.sig` to be written. When the git wrapper has set an
//! `AGENT_EVENT_TOKEN`, the buffer is sent to the service, which signs it with
//! the agent key. Without a token the arguments are passed unchanged to the
//! configured `fallback_program` (the person's own signer).
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
    let config = Config::load(None);
    let fallback_prog = config.ssh.fallback_program.clone();
    let multiplexer = Multiplexer::new(config);

    let token_var = env::var(EVENT_TOKEN_VAR).ok();
    let action = multiplexer.determine_action(token_var.as_deref());

    match action {
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

    let req = Request::SignCommit {
        token: token.to_string(),
        buffer_b64,
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
