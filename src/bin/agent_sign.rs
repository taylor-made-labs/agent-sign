use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, ExitCode};

use agent_sign::config::Config;
use agent_sign::multiplexer::{Multiplexer, SigningAction};
use agent_sign::protocol::{Request, Response, default_socket_path, send_request};
use base64::Engine;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    let config = Config::load(None);
    let fallback_prog = config.ssh.fallback_program.clone();
    let multiplexer = Multiplexer::new(config);

    let token_var = env::var("AGENT_EVENT_TOKEN").ok();
    let action = multiplexer.determine_action(token_var.as_deref());

    match action {
        SigningAction::DelegateToSystemSshKeygen => {
            // Forward directly to configured fallback program (e.g. 1Password op-ssh-sign or ssh-keygen)
            delegate_to_system_ssh_keygen(&args[1..], &fallback_prog)
        }
        SigningAction::SignWithAgentKey(token) => {
            // Validate token format fails closed
            if let Err(e) = multiplexer.validate_event_token(Some(&token)) {
                eprintln!("[agent-sign] Event token validation failed: {}", e);
                return ExitCode::from(1);
            }
            sign_with_agent_daemon(&args[1..], &token)
        }
    }
}

fn delegate_to_system_ssh_keygen(args: &[String], fallback_program: &str) -> ExitCode {
    let status = Command::new(fallback_program).args(args).status();

    match status {
        Ok(s) => ExitCode::from(s.code().unwrap_or(1) as u8),
        Err(e) => {
            eprintln!(
                "[agent-sign] Failed to execute fallback signing program '{}': {}",
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
                "[agent-sign] Error: No file to sign provided in git arguments: {:?}",
                args
            );
            return ExitCode::from(1);
        }
    };

    let buffer = match fs::read(&file_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!(
                "[agent-sign] Error reading buffer file {}: {}",
                file_path.display(),
                e
            );
            return ExitCode::from(1);
        }
    };

    let buffer_b64 = base64::engine::general_purpose::STANDARD.encode(&buffer);
    let socket_path = env::var("AGENT_SIGN_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|_| default_socket_path());

    let req = Request::SignCommit {
        token: token.to_string(),
        buffer_b64,
    };

    let resp = match send_request(&socket_path, &req) {
        Ok(r) => r,
        Err(e) => {
            eprintln!(
                "[agent-sign] Failed to communicate with daemon at {}: {}",
                socket_path.display(),
                e
            );
            eprintln!("[agent-sign] Ensure `agent-signd` is running.");
            return ExitCode::from(1);
        }
    };

    match resp {
        Response::Signed { signature_pem } => {
            // OpenSSH ssh-keygen creates <file>.sig
            let sig_file_path = PathBuf::from(format!("{}.sig", file_path.display()));
            if let Err(e) = fs::write(&sig_file_path, signature_pem) {
                eprintln!(
                    "[agent-sign] Failed to write signature to {}: {}",
                    sig_file_path.display(),
                    e
                );
                return ExitCode::from(1);
            }
            ExitCode::SUCCESS
        }
        Response::Error { message } => {
            eprintln!("[agent-sign] Signing rejected by daemon: {}", message);
            ExitCode::from(1)
        }
        other => {
            eprintln!("[agent-sign] Unexpected daemon response: {:?}", other);
            ExitCode::from(1)
        }
    }
}
