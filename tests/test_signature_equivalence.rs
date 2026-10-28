//! Every signing program name signs through the service, and the library's
//! SSHSIG signer is unchanged.
//!
//! Ed25519 signatures are deterministic, so the same key and the same bytes
//! must give the same signature, byte for byte. `GOLDEN_AGENT_SIGN_SIG` was
//! produced on 30 Sept 2026 by the pre-rename `agent-sign` and `agent-signd`
//! binaries (built from commit a036037) with the test seed below and
//! `BUFFER`. The library's signer must still reproduce it, and
//! `ssh-keygen -Y verify` must accept it.
//!
//! Since per-agent identities (28 Oct 2026) the service no longer signs with
//! one shared key: each agent session has its own key, made fresh in the
//! service's memory, with a certificate from the agents' certificate
//! authority. So the programs' signatures can't be byte-identical to a
//! golden one any more; instead each program name must get a signature that
//! `ssh-keygen -Y verify` accepts under the agents' trust line, for the
//! agent the token names. Since the identity review (28 Oct 2026) a program
//! runs as git runs it for an agent: inside the repository the token is for,
//! with the wrapper's mark beside the token (an older wrapper's token with
//! no identity is refused). All runs use a temporary home and socket.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use agent_sign::attribution::AgentIdentity;
use agent_sign::crypto::AgentKeyPair;
use agent_sign::protocol::{Request, Response, send_request};
use tempfile::tempdir;

/// A fixed test seed; never a real key.
const TEST_SEED: [u8; 32] = [7u8; 32];

const BUFFER: &[u8] = b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\nauthor Agent <agent@local.internal> 1700000000 +0000\ncommitter Taylor <person@example.com> 1700000000 +0000\n\nfeat: golden signature buffer\n";

const GOLDEN_AGENT_SIGN_SIG: &str = "-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAg6kpsY+KcUgq+9VB7Ey7F+ZVHdq
6+vnuSQh7qaRRG0iwAAAADZ2l0AAAAAAAAAAZzaGE1MTIAAABTAAAAC3NzaC1lZDI1NTE5
AAAAQJ5GX+AHmsFuihdpeEdVpcLpOx7N87EGjX01Jw26EvjynVJLsofJhUtsE49Mm3DhcU
p2HYltc582JXuC4Z/KsQY=
-----END SSH SIGNATURE-----
";

struct Service {
    child: Child,
}

impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Starts `agent-signd` on `socket`, in `home`.
fn start_service(home: &Path, socket: &Path) -> Service {
    let child = Command::new(env!("CARGO_BIN_EXE_agent-signd"))
        .arg("--socket")
        .arg(socket)
        .arg("--auto-approve")
        .env("HOME", home)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to spawn agent-signd");
    let start = Instant::now();
    while !socket.exists() {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "agent-signd did not start"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    Service { child }
}

/// The agent the tokens sign as.
fn golden_agent() -> AgentIdentity {
    AgentIdentity::new("codex", "Codex", Some("golden"))
}

fn token(socket: &Path, repo: &str) -> String {
    match send_request(
        socket,
        &Request::IssueIdentifiedToken {
            repo: repo.into(),
            branch: "feat/golden".into(),
            identity: golden_agent(),
        },
    )
    .unwrap()
    {
        Response::TokenIssued { token } => token,
        other => panic!("no token: {other:?}"),
    }
}

/// Runs a signing program the way git does and returns the `.sig` it wrote.
fn sign_with(
    program: &Path,
    env_prefix: &str,
    home: &Path,
    socket: &Path,
    token: &str,
    file: &Path,
    repo: &Path,
) -> String {
    fs::write(file, BUFFER).unwrap();
    let out = Command::new(program)
        .current_dir(repo)
        .env("AGENT_SIGN_AGENT_RUN", "1")
        .args(["-Y", "sign", "-n", "git", "-f"])
        .arg(home.join(".agent-sign/keys/agents_ca_ed25519.pub"))
        .arg(file)
        .env("HOME", home)
        .env("AGENT_EVENT_TOKEN", token)
        .env(format!("{env_prefix}SOCKET"), socket)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{} failed: {}",
        program.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    fs::read_to_string(format!("{}.sig", file.display())).unwrap()
}

/// Runs `ssh-keygen -Y verify` on `sig` over `BUFFER` for `principal`
/// against `allowed`, and fails the test with its output if it refuses.
fn assert_verifies(home: &Path, allowed: &Path, principal: &str, sig: &str, what: &str) {
    let data = home.join("data");
    fs::write(&data, BUFFER).unwrap();
    fs::write(home.join("data.sig"), sig).unwrap();
    let verify = Command::new("ssh-keygen")
        .args(["-Y", "verify", "-n", "git", "-I", principal, "-f"])
        .arg(allowed)
        .arg("-s")
        .arg(home.join("data.sig"))
        .stdin(fs::File::open(&data).unwrap())
        .output()
        .unwrap();
    assert!(
        verify.status.success(),
        "{what}: ssh-keygen rejected: {}",
        String::from_utf8_lossy(&verify.stderr)
    );
}

#[test]
fn every_signing_name_signs_as_the_agent_and_the_library_signer_is_unchanged() {
    let tmp = tempdir().unwrap();
    let home = tmp.path();
    let socket = home.join("s.sock");
    let _service = start_service(home, &socket);
    // The service only takes a request about a real git working tree.
    let golden_dir = home.join("golden/repo");
    fs::create_dir_all(&golden_dir).unwrap();
    let init = Command::new("git")
        .args(["init", "-q", "-b", "feat/golden"])
        .current_dir(&golden_dir)
        .status()
        .unwrap();
    assert!(init.success());
    let golden = fs::canonicalize(&golden_dir).unwrap().display().to_string();

    match send_request(
        &socket,
        &Request::RequestLease {
            repo: golden.clone(),
            branch: "feat/golden".into(),
            intent: "golden".into(),
            duration_secs: None,
        },
    )
    .unwrap()
    {
        Response::LeaseGranted { .. } => {}
        other => panic!("lease refused: {other:?}"),
    }

    let links = tempdir().unwrap();
    let old_name = links.path().join("agent-sign");
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_agent-sign"), &old_name).unwrap();

    let programs: [(PathBuf, &str); 3] = [
        (
            PathBuf::from(env!("CARGO_BIN_EXE_agent-ssh-sign")),
            "AGENT_SIGN_",
        ),
        (
            PathBuf::from(env!("CARGO_BIN_EXE_agent-sign")),
            "AGENT_SIGN_",
        ),
        (old_name, "AGENT_SIGN_"),
    ];
    let ca = fs::read_to_string(home.join(".agent-sign/keys/agents_ca_ed25519.pub")).unwrap();
    let trusted = home.join("agents_allowed_signers");
    fs::write(
        &trusted,
        format!(
            "*@agents.local cert-authority,namespaces=\"git\" {}\n",
            ca.trim()
        ),
    )
    .unwrap();
    for (i, (program, prefix)) in programs.iter().enumerate() {
        let tok = token(&socket, &golden);
        let sig = sign_with(
            program,
            prefix,
            home,
            &socket,
            &tok,
            &home.join(format!("buf{i}")),
            &golden_dir,
        );
        assert_verifies(
            home,
            &trusted,
            &golden_agent().principal,
            &sig,
            &program.display().to_string(),
        );
    }

    // The library's signer, which agent-sign used unchanged, agrees too.
    let kp = AgentKeyPair::from_bytes(&TEST_SEED).unwrap();
    assert_eq!(
        kp.sign_git_buffer(BUFFER).to_armored_pem(),
        GOLDEN_AGENT_SIGN_SIG
    );

    // And OpenSSH accepts it for the matching public key.
    let allowed = home.join("allowed_signers");
    fs::write(
        &allowed,
        format!("agent@local.internal {}\n", kp.public_key_openssh()),
    )
    .unwrap();
    assert_verifies(
        home,
        &allowed,
        "agent@local.internal",
        GOLDEN_AGENT_SIGN_SIG,
        "the golden signature",
    );
}

#[test]
fn without_a_token_every_signing_name_forwards_to_the_fallback_unchanged() {
    let tmp = tempdir().unwrap();
    let home = tmp.path();
    let record = home.join("fallback-args");
    let fallback = home.join("fake-signer");
    fs::write(
        &fallback,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" >> '{}'\nexit 3\n",
            record.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&fallback, fs::Permissions::from_mode(0o755)).unwrap();
    fs::create_dir_all(home.join(".agent-sign")).unwrap();
    fs::write(
        home.join(".agent-sign/config.toml"),
        format!("[ssh]\nfallback_program = \"{}\"\n", fallback.display()),
    )
    .unwrap();

    let links = tempdir().unwrap();
    let old_name = links.path().join("agent-sign");
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_agent-sign"), &old_name).unwrap();

    for program in [
        PathBuf::from(env!("CARGO_BIN_EXE_agent-ssh-sign")),
        PathBuf::from(env!("CARGO_BIN_EXE_agent-sign")),
        old_name,
    ] {
        let _ = fs::remove_file(&record);
        let out = Command::new(&program)
            .args(["-Y", "find-principals", "-s", "x.sig", "-f", "allowed"])
            .env("HOME", home)
            .env_remove("AGENT_EVENT_TOKEN")
            .output()
            .unwrap();
        // The fallback's exit code and arguments pass through untouched.
        assert_eq!(out.status.code(), Some(3), "{}", program.display());
        assert_eq!(
            fs::read_to_string(&record).unwrap(),
            "-Y\nfind-principals\n-s\nx.sig\n-f\nallowed\n",
            "{}",
            program.display()
        );
    }
}
