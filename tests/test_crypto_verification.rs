use agent_commits::crypto::AgentKeyPair;
use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn test_agent_key_generation_and_openssh_public_format() {
    let keypair = AgentKeyPair::generate();
    let pub_key_ssh = keypair.public_key_openssh();

    assert!(
        pub_key_ssh.starts_with("ssh-ed25519 "),
        "Public key must start with standard ssh-ed25519 prefix: {}",
        pub_key_ssh
    );
}

#[test]
fn test_signature_format_matches_git_ssh_specification() {
    let keypair = AgentKeyPair::generate();
    let commit_buffer = b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\nauthor Agent <agent@local> 1700000000 +0000\ncommitter Agent <agent@local> 1700000000 +0000\n\ntest commit\n";

    let signature = keypair.sign_git_buffer(commit_buffer);
    let pem = signature.to_armored_pem();

    assert!(pem.starts_with("-----BEGIN SSH SIGNATURE-----\n"));
    assert!(pem.ends_with("\n-----END SSH SIGNATURE-----\n"));
}

#[test]
fn test_generated_signature_validates_with_system_ssh_keygen() {
    let dir = tempdir().expect("Failed to create tempdir");
    let keypair = AgentKeyPair::generate();
    let identity = "agent@local.internal";
    let pub_key_ssh = keypair.public_key_openssh();

    // 1. Create allowed_signers file
    let allowed_signers_path = dir.path().join("allowed_signers");
    let allowed_signers_content = format!("{} {}\n", identity, pub_key_ssh);
    fs::write(&allowed_signers_path, allowed_signers_content)
        .expect("Failed to write allowed_signers");

    // 2. Prepare test commit buffer and write to disk
    let data_path = dir.path().join("commit_data.txt");
    let commit_data = b"tree 0000000000000000000000000000000000000000\nauthor Agent <agent@local.internal> 1700000000 +0000\n\nAutonomous agent commit\n";
    fs::write(&data_path, commit_data).expect("Failed to write commit_data");

    // 3. Sign buffer using AgentKeyPair
    let signature = keypair.sign_git_buffer(commit_data);
    let sig_path = dir.path().join("commit_data.txt.sig");
    fs::write(&sig_path, signature.to_armored_pem()).expect("Failed to write sig file");

    // 4. Verify using system `/usr/bin/ssh-keygen -Y verify`
    let output = Command::new("ssh-keygen")
        .arg("-Y")
        .arg("verify")
        .arg("-f")
        .arg(&allowed_signers_path)
        .arg("-I")
        .arg(identity)
        .arg("-n")
        .arg("git")
        .arg("-s")
        .arg(&sig_path)
        .stdin(fs::File::open(&data_path).expect("Failed to open data file for stdin"))
        .output()
        .expect("Failed to execute ssh-keygen -Y verify");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "ssh-keygen -Y verify failed!\nSTDOUT: {}\nSTDERR: {}",
        stdout,
        stderr
    );
    assert!(
        stderr.contains("Good \"git\" signature") || stdout.contains("Good \"git\" signature"),
        "Expected 'Good \"git\" signature', got stdout: {}, stderr: {}",
        stdout,
        stderr
    );
}
