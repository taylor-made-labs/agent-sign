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

    // Check for diagnostic / utility subcommands
    if args.len() > 1 {
        let first_arg = args[1].as_str();
        if first_arg == "doctor" {
            return run_doctor();
        }
        if first_arg == "--version" || first_arg == "-v" || first_arg == "-V" {
            println!("agent-sign {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        if first_arg == "--help" || first_arg == "-h" {
            print_help();
            return ExitCode::SUCCESS;
        }
    }

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

fn print_help() {
    println!("Agent-Sign: Deterministic Git Commit Signing & Identity Multiplexer for AI Agents");
    println!();
    println!("USAGE:");
    println!("  agent-sign <git-ssh-args...>    (Used internally by Git as gpg.ssh.program)");
    println!("  agent-sign doctor               (Run full system diagnostics and check health)");
    println!("  agent-sign --version            (Show version)");
    println!("  agent-sign --help               (Show this message)");
}

fn run_doctor() -> ExitCode {
    println!("\x1b[1m══════════════════════════════════════════════════\x1b[0m");
    println!("\x1b[1m         Agent-Sign Diagnostic Health Check        \x1b[0m");
    println!("\x1b[1m══════════════════════════════════════════════════\x1b[0m\n");

    let mut passes = 0;
    let mut warnings = 0;
    let mut failures = 0;

    let config = Config::load(None);

    // 1. Check Git configuration
    let gpg_format = Command::new("git")
        .args(["config", "--global", "gpg.format"])
        .output();
    let format_val = gpg_format
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    if format_val == "ssh" {
        println!("  \x1b[32m✓\x1b[0m Git signing format: ssh");
        passes += 1;
    } else {
        println!(
            "  \x1b[33m⚠\x1b[0m Git signing format: '{}' (expected 'ssh')",
            format_val
        );
        println!("    Hint: Run `git config --global gpg.format ssh`");
        warnings += 1;
    }

    // 2. Check Fallback Program
    let fallback = &config.ssh.fallback_program;
    let fallback_path = PathBuf::from(fallback);
    if fallback_path.exists()
        || Command::new("which")
            .arg(fallback)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    {
        println!("  \x1b[32m✓\x1b[0m Human fallback signer: {}", fallback);
        passes += 1;
    } else {
        println!(
            "  \x1b[31m✗\x1b[0m Human fallback signer not found: {}",
            fallback
        );
        println!("    Hint: Check `fallback_program` in ~/.agent-sign/config.toml");
        failures += 1;
    }

    // 3. Check Agent Key Files
    let pub_key_path = config.ssh.agent_key_path.with_extension("pub");
    if config.ssh.agent_key_path.exists() && pub_key_path.exists() {
        println!(
            "  \x1b[32m✓\x1b[0m Agent keypair present: {}",
            config.ssh.agent_key_path.display()
        );
        passes += 1;
    } else {
        println!(
            "  \x1b[31m✗\x1b[0m Agent keypair missing at {}",
            config.ssh.agent_key_path.display()
        );
        println!("    Hint: Run `~/.agent-sign/bin/agent-signd setup` to generate keys");
        failures += 1;
    }

    // 4. Check Allowed Signers
    let allowed_file_out = Command::new("git")
        .args(["config", "--global", "gpg.ssh.allowedSignersFile"])
        .output();
    let allowed_path_str = allowed_file_out
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    if !allowed_path_str.is_empty() {
        let clean_path = allowed_path_str.replace("~", &std::env::var("HOME").unwrap_or_default());
        let allowed_path = PathBuf::from(&clean_path);
        if allowed_path.exists() {
            println!(
                "  \x1b[32m✓\x1b[0m Local allowed_signers registered: {}",
                clean_path
            );
            passes += 1;
        } else {
            println!(
                "  \x1b[33m⚠\x1b[0m allowed_signers file configured but does not exist at {}",
                clean_path
            );
            warnings += 1;
        }
    } else {
        println!("  \x1b[33m⚠\x1b[0m gpg.ssh.allowedSignersFile is not configured in git");
        warnings += 1;
    }

    // 5. Check Daemon Connection
    let socket_path = env::var("AGENT_SIGN_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|_| default_socket_path());

    let ping_req = Request::Ping;
    match send_request(&socket_path, &ping_req) {
        Ok(Response::Pong) => {
            println!(
                "  \x1b[32m✓\x1b[0m Daemon socket active and responsive: {}",
                socket_path.display()
            );
            passes += 1;
        }
        Ok(_) => {
            println!(
                "  \x1b[32m✓\x1b[0m Daemon responded at {}",
                socket_path.display()
            );
            passes += 1;
        }
        Err(e) => {
            println!("  \x1b[31m✗\x1b[0m Daemon connection failed: {}", e);
            println!("    Hint: Start daemon with `~/.agent-sign/bin/agent-signd`");
            failures += 1;
        }
    }

    // 6. Check GitHub CLI registration
    if Command::new("which")
        .arg("gh")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        let gh_check = Command::new("gh").args(["ssh-key", "list"]).output();
        if let Ok(o) = gh_check {
            let out_str = String::from_utf8_lossy(&o.stdout);
            if pub_key_path.exists()
                && let Ok(pub_content) = fs::read_to_string(&pub_key_path)
            {
                let key_data = pub_content.split_whitespace().nth(1).unwrap_or("");
                if !key_data.is_empty() && out_str.contains(key_data) {
                    println!("  \x1b[32m✓\x1b[0m GitHub account: Agent signing key registered!");
                    passes += 1;
                } else {
                    println!(
                        "  \x1b[33m⚠\x1b[0m GitHub account: Agent key not found in `gh ssh-key list`"
                    );
                    println!(
                        "    Hint: Run `gh ssh-key add {} --type signing`",
                        pub_key_path.display()
                    );
                    warnings += 1;
                }
            }
        }
    }

    println!();
    if failures == 0 && warnings == 0 {
        println!(
            "\x1b[1;32mAll {} checks passed! System is fully operational.\x1b[0m\n",
            passes
        );
        ExitCode::SUCCESS
    } else if failures == 0 {
        println!(
            "\x1b[1;33m{} passed, {} warning(s). Agent-sign is usable.\x1b[0m\n",
            passes, warnings
        );
        ExitCode::SUCCESS
    } else {
        println!(
            "\x1b[1;31m{} passed, {} warning(s), {} failure(s). Please review hints above.\x1b[0m\n",
            passes, warnings, failures
        );
        ExitCode::from(1)
    }
}
