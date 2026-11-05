//! `agent-sign act ...`: the command line of signed acts ([`crate::acts`]).
//!
//! - `act sign [--payload-file ABS]`: inside a launched session, signs the
//!   exact bytes (stdin, or the file) as the identity the session was
//!   launched with. The service does the signing, with the session's
//!   in-memory key, over the session's own channel.
//! - `act sign --assigner person:<name> --trust-file ABS` and `act sign
//!   --assigner harness:launcher`: outside any session. A person signs with
//!   the key the trust file lists for them, through their own ssh-agent
//!   (`SSH_AUTH_SOCK`); the launcher signs through the service.
//! - `act verify` and `act verify-credential`: check a signature against a
//!   trust file, printing one JSON verdict (exit 0 verified, 1 not, 2 could
//!   not run).
//! - `act credential`: inside a session, a fresh signed credential.
//! - `act trust-lines`: the running service's trust lines.
//!
//! A session can't pick its identity or sign as an assigner: no option
//! exists for it, `--assigner` is refused when the process is a launched
//! session, and the service refuses it again whatever the client says.

use std::io::Read;
use std::path::Path;
use std::process::ExitCode;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use crate::acts::{self, Envelope, Verdict};
use crate::protocol::{ActKind, Request, Response};

const USAGE: &str = "usage: agent-sign act sign [--payload-file ABS]            (in a launched session)\n       \
agent-sign act sign --assigner person:<name> --trust-file ABS [--payload-file ABS]\n       \
agent-sign act sign --assigner harness:launcher [--payload-file ABS]\n       \
agent-sign act verify --format json --trust-file ABS [--now UNIX]\n       \
agent-sign act credential                               (in a launched session)\n       \
agent-sign act verify-credential --format json --trust-file ABS [--now UNIX]\n       \
agent-sign act trust-lines";

fn usage() -> ExitCode {
    eprintln!("{USAGE}");
    ExitCode::from(2)
}

fn refuse(why: impl std::fmt::Display) -> ExitCode {
    eprintln!("agent-sign act: {why}");
    ExitCode::from(1)
}

/// The options of one subcommand: `--name value` or `--name=value`, each at
/// most once, from the names given.
fn options(args: &[String], names: &[&str]) -> Result<Vec<(String, String)>, String> {
    let mut found: Vec<(String, String)> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        let (name, value) = match arg.split_once('=') {
            Some((n, v)) if n.starts_with("--") => (n.to_string(), v.to_string()),
            _ => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| format!("{arg} needs a value"))?
                    .clone();
                i += 1;
                (arg.clone(), value)
            }
        };
        i += 1;
        if !names.contains(&name.as_str()) {
            return Err(format!("unknown option {name}"));
        }
        if found.iter().any(|(n, _)| *n == name) {
            return Err(format!("{name} given twice"));
        }
        found.push((name, value));
    }
    Ok(found)
}

fn opt<'a>(found: &'a [(String, String)], name: &str) -> Option<&'a str> {
    found
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.as_str())
}

/// Reads at most `cap` + 1 bytes: more than `cap` means too much.
fn read_capped(mut reader: impl Read, cap: usize) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    (&mut reader).take(cap as u64 + 1).read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// The bytes to sign: the absolute `--payload-file`, or standard input.
fn payload(file: Option<&str>) -> Result<Vec<u8>, String> {
    let bytes = match file {
        Some(f) => {
            if !Path::new(f).is_absolute() {
                return Err("--payload-file must be an absolute path".into());
            }
            let file = std::fs::File::open(f).map_err(|e| format!("couldn't open {f} ({e})"))?;
            read_capped(file, acts::MAX_PAYLOAD)
        }
        None => read_capped(std::io::stdin().lock(), acts::MAX_PAYLOAD),
    }
    .map_err(|e| format!("couldn't read the bytes to sign ({e})"))?;
    acts::check_payload_len(bytes.len())?;
    Ok(bytes)
}

fn print_json(value: &serde_json::Value) {
    println!("{}", serde_json::to_string(value).unwrap_or_default());
}

/// Runs `agent-sign act <args>`.
pub fn run(args: &[String]) -> ExitCode {
    let Some((sub, rest)) = args.split_first() else {
        return usage();
    };
    match sub.as_str() {
        "sign" => sign(rest),
        "credential" => credential(rest),
        "verify" => verify(rest, false),
        "verify-credential" => verify(rest, true),
        "trust-lines" => trust_lines(rest),
        _ => usage(),
    }
}

fn in_session() -> bool {
    crate::session::Channel::from_env().is_some()
}

fn sign(args: &[String]) -> ExitCode {
    let Ok(opts) = options(args, &["--payload-file", "--assigner", "--trust-file"]) else {
        return usage();
    };
    let file = opt(&opts, "--payload-file");
    let Some(assigner) = opt(&opts, "--assigner") else {
        if opt(&opts, "--trust-file").is_some() {
            return usage();
        }
        return sign_as_session(file);
    };
    if in_session() {
        return refuse(
            "a launched session can't sign as an assigner (it signs only as the identity it was launched with)",
        );
    }
    if assigner == acts::LAUNCHER_ASSIGNER {
        if opt(&opts, "--trust-file").is_some() {
            return usage();
        }
        return sign_as_launcher(file);
    }
    match opt(&opts, "--trust-file") {
        Some(trust) if assigner.starts_with("person:") => sign_as_person(assigner, trust, file),
        _ => refuse("--assigner takes `person:<name>` with --trust-file, or `harness:launcher`"),
    }
}

fn sign_as_session(file: Option<&str>) -> ExitCode {
    if !in_session() {
        return refuse(
            "`act sign` without --assigner signs as a launched session's agent identity, and this is not one (launch with `agent-sign launch --agent <name> --identity agent:<name> -- ...`)",
        );
    }
    let bytes = match payload(file) {
        Ok(b) => b,
        Err(why) => return refuse(why),
    };
    let request = Request::SignAct {
        payload_b64: STANDARD.encode(&bytes),
        kind: ActKind::Act,
    };
    match crate::protocol::ask_service(&request) {
        Ok(Response::ActSigned {
            signature,
            certificate,
            ..
        }) => {
            print_json(&acts::member_json(&signature, certificate.as_deref()));
            ExitCode::SUCCESS
        }
        Ok(Response::Error { message }) => refuse(message),
        Ok(other) => refuse(format!("unexpected answer from the service: {other:?}")),
        Err(e) => refuse(format!("the service didn't answer ({e})")),
    }
}

fn sign_as_launcher(file: Option<&str>) -> ExitCode {
    let bytes = match payload(file) {
        Ok(b) => b,
        Err(why) => return refuse(why),
    };
    let request = Request::SignActAsLauncher {
        payload_b64: STANDARD.encode(&bytes),
    };
    match crate::protocol::send_request(&crate::protocol::client_socket_path(), &request) {
        Ok(Response::ActSigned {
            signature,
            certificate,
            ..
        }) => {
            print_json(&acts::member_json(&signature, certificate.as_deref()));
            ExitCode::SUCCESS
        }
        Ok(Response::Error { message }) => refuse(message),
        Ok(other) => refuse(format!("unexpected answer from the service: {other:?}")),
        Err(e) => refuse(format!("the service didn't answer ({e})")),
    }
}

fn sign_as_person(identity: &str, trust: &str, file: Option<&str>) -> ExitCode {
    let (trust, _) = match acts::load_trust(Path::new(trust)) {
        Ok(t) => t,
        Err(v) => return refuse(v.detail),
    };
    let keys = trust.assigner_keys(identity);
    if keys.is_empty() {
        return refuse(format!("the trust file lists no key for {identity}"));
    }
    let Some(socket) = std::env::var_os("SSH_AUTH_SOCK").filter(|s| !s.is_empty()) else {
        return refuse(format!(
            "no ssh-agent is reachable (SSH_AUTH_SOCK is not set): {identity}'s key stays in their own agent or device"
        ));
    };
    let bytes = match payload(file) {
        Ok(b) => b,
        Err(why) => return refuse(why),
    };
    let mut last = String::new();
    for key in keys {
        match acts::agent_sign_with(Path::new(&socket), &key, &bytes) {
            Ok(armored) => {
                print_json(&acts::member_json(&armored, None));
                return ExitCode::SUCCESS;
            }
            Err(why) => last = why,
        }
    }
    refuse(format!(
        "the ssh-agent can't sign as {identity} with any key the trust file lists ({last})"
    ))
}

fn credential(args: &[String]) -> ExitCode {
    if !args.is_empty() {
        return usage();
    }
    if !in_session() {
        return refuse("a credential is made only inside a launched session");
    }
    let request = Request::SignAct {
        payload_b64: String::new(),
        kind: ActKind::Credential,
    };
    match crate::protocol::ask_service(&request) {
        Ok(Response::ActSigned {
            signature,
            certificate,
            issued_at: Some(issued_at),
        }) => {
            print_json(&serde_json::json!({
                "schema": acts::CREDENTIAL_SCHEMA,
                "issued_at": issued_at,
                "signature": acts::member_json(&signature, certificate.as_deref()),
            }));
            ExitCode::SUCCESS
        }
        Ok(Response::Error { message }) => refuse(message),
        Ok(other) => refuse(format!("unexpected answer from the service: {other:?}")),
        Err(e) => refuse(format!("the service didn't answer ({e})")),
    }
}

fn trust_lines(args: &[String]) -> ExitCode {
    if !args.is_empty() {
        return usage();
    }
    match crate::protocol::send_request(
        &crate::protocol::client_socket_path(),
        &Request::ActTrustLines,
    ) {
        Ok(Response::ActTrustLines { lines }) => {
            for line in lines {
                println!("{line}");
            }
            ExitCode::SUCCESS
        }
        Ok(Response::Error { message }) => refuse(message),
        Ok(other) => refuse(format!("unexpected answer from the service: {other:?}")),
        Err(e) => refuse(format!("the service didn't answer ({e})")),
    }
}

fn finish(verdict: &Verdict) -> ExitCode {
    print_json(&verdict.to_json());
    ExitCode::from(verdict.exit_code())
}

/// `act verify` and `act verify-credential`.
fn verify(args: &[String], credential: bool) -> ExitCode {
    let Ok(opts) = options(args, &["--format", "--trust-file", "--now"]) else {
        return usage();
    };
    if opt(&opts, "--format") != Some("json") {
        return usage();
    }
    let Some(trust_path) = opt(&opts, "--trust-file") else {
        return usage();
    };
    let now = match opt(&opts, "--now") {
        Some(n) => match n.parse::<u64>() {
            Ok(n) => n,
            Err(_) => return usage(),
        },
        None => crate::agents_ca::now_secs(),
    };
    let (trust, digest) = match acts::load_trust(Path::new(trust_path)) {
        Ok(t) => t,
        Err(verdict) => return finish(&verdict),
    };
    let malformed = |why: &str| {
        finish(&Verdict {
            verified: false,
            signer: None,
            kind: None,
            reason: "malformed",
            detail: why.to_string(),
            trust_sha256: Some(digest.clone()),
        })
    };
    let input = match read_capped(std::io::stdin().lock(), acts::MAX_INPUT_BYTES) {
        Ok(i) => i,
        Err(e) => {
            return finish(&Verdict {
                verified: false,
                signer: None,
                kind: None,
                reason: "error",
                detail: format!("couldn't read standard input ({e})"),
                trust_sha256: Some(digest),
            });
        }
    };
    if input.len() > acts::MAX_INPUT_BYTES {
        return malformed("the input is too long");
    }
    if credential {
        match serde_json::from_slice::<acts::Credential>(&input) {
            Ok(c) => finish(&acts::verify_credential(&trust, &digest, &c, now)),
            Err(_) => malformed("the input is not exactly one credential object"),
        }
    } else {
        let envelope = match serde_json::from_slice::<Envelope>(&input) {
            Ok(e) => e,
            Err(_) => {
                return malformed("the input is not exactly one {payload_b64, signature} object");
            }
        };
        match acts::decode_payload(&envelope.payload_b64) {
            Ok(bytes) => finish(&acts::verify_act(
                &trust,
                &digest,
                &bytes,
                &envelope.signature,
                now,
            )),
            Err(why) => malformed(&why),
        }
    }
}
