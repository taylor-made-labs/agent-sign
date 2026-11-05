//! Ed25519 keys and OpenSSH SSHSIG signatures, as git's `gpg.format = ssh`
//! expects them. The SSHSIG wrapper is shared by the legacy agent key
//! ([`AgentKeyPair`]) and the per-session certificates in
//! [`crate::agents_ca`].

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha512};

pub struct AgentKeyPair {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

pub struct SshSignature {
    raw_sshsig: Vec<u8>,
}

fn put_u32(buf: &mut Vec<u8>, val: u32) {
    buf.extend_from_slice(&val.to_be_bytes());
}

fn put_string(buf: &mut Vec<u8>, val: &[u8]) {
    put_u32(buf, val.len() as u32);
    buf.extend_from_slice(val);
}

impl AgentKeyPair {
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let key_bytes: [u8; 32] = bytes.try_into()?;
        let signing_key = SigningKey::from_bytes(&key_bytes);
        let verifying_key = signing_key.verifying_key();
        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    /// OpenSSH wire format of the ed25519 public key
    pub fn public_key_wire(&self) -> Vec<u8> {
        let mut wire = Vec::new();
        put_string(&mut wire, b"ssh-ed25519");
        put_string(&mut wire, self.verifying_key.as_bytes());
        wire
    }

    /// OpenSSH single-line public key format (e.g. `ssh-ed25519 AAAA...`)
    pub fn public_key_openssh(&self) -> String {
        let wire = self.public_key_wire();
        let b64 = base64::engine::general_purpose::STANDARD.encode(&wire);
        format!("ssh-ed25519 {}", b64)
    }

    /// Signs a commit buffer conforming to OpenSSH SSHSIG protocol for namespace "git"
    pub fn sign_git_buffer(&self, buffer: &[u8]) -> SshSignature {
        SshSignature {
            raw_sshsig: sshsig_raw(
                &self.public_key_wire(),
                &self.signing_key,
                GIT_NAMESPACE,
                buffer,
            ),
        }
    }
}

/// The OpenSSH one-line form of an ed25519 public key (`ssh-ed25519 AAAA...`).
pub fn openssh_ed25519_line(key: &VerifyingKey) -> String {
    let mut wire = Vec::new();
    put_string(&mut wire, b"ssh-ed25519");
    put_string(&mut wire, key.as_bytes());
    format!(
        "ssh-ed25519 {}",
        base64::engine::general_purpose::STANDARD.encode(&wire)
    )
}

/// The SSHSIG namespace of git commit signatures.
pub const GIT_NAMESPACE: &[u8] = b"git";

/// The bytes an SSHSIG signature is made over (OpenSSH `PROTOCOL.sshsig`):
/// `"SSHSIG" || string namespace || string reserved || string hash_algorithm ||
/// string H(message)`, with sha512. Exposed so a signature can also be made
/// by a key that never leaves its holder (an ssh-agent signs these bytes).
pub fn sshsig_signed_data(namespace: &[u8], buffer: &[u8]) -> Vec<u8> {
    let mut hasher = Sha512::new();
    hasher.update(buffer);
    let message_hash = hasher.finalize();
    let mut signed_data = Vec::new();
    signed_data.extend_from_slice(b"SSHSIG");
    put_string(&mut signed_data, namespace);
    put_string(&mut signed_data, b"");
    put_string(&mut signed_data, b"sha512");
    put_string(&mut signed_data, &message_hash);
    signed_data
}

/// The complete SSHSIG blob from a public key blob, a namespace and an
/// ed25519 signature (64 bytes) over [`sshsig_signed_data`].
pub fn sshsig_assemble(public_key_blob: &[u8], namespace: &[u8], signature: &[u8; 64]) -> Vec<u8> {
    // string "ssh-ed25519" || string signature_bytes
    let mut sig_blob = Vec::new();
    put_string(&mut sig_blob, b"ssh-ed25519");
    put_string(&mut sig_blob, signature);
    // magic, uint32 version (1), string publickey, string namespace,
    // string reserved, string hash_algorithm, string signature
    let mut sshsig = Vec::new();
    sshsig.extend_from_slice(b"SSHSIG");
    put_u32(&mut sshsig, 1);
    put_string(&mut sshsig, public_key_blob);
    put_string(&mut sshsig, namespace);
    put_string(&mut sshsig, b"");
    put_string(&mut sshsig, b"sha512");
    put_string(&mut sshsig, &sig_blob);
    sshsig
}

/// An SSHSIG signature (OpenSSH PROTOCOL.sshsig) over `buffer` for
/// `namespace` with sha512, made with the ed25519 `signing_key`, whose
/// public half is carried as `public_key_blob`: the plain key's wire form,
/// or an OpenSSH certificate for it, as `ssh-keygen -Y sign` does with a
/// certificate. The signature itself is always a plain "ssh-ed25519" one.
fn sshsig_raw(
    public_key_blob: &[u8],
    signing_key: &SigningKey,
    namespace: &[u8],
    buffer: &[u8],
) -> Vec<u8> {
    let signature = signing_key.sign(&sshsig_signed_data(namespace, buffer));
    sshsig_assemble(public_key_blob, namespace, &signature.to_bytes())
}

/// [`sshsig_raw`] for namespace "git", armored as `ssh-keygen` writes it.
pub fn sshsig_armored(public_key_blob: &[u8], signing_key: &SigningKey, buffer: &[u8]) -> String {
    sshsig_armored_in(public_key_blob, signing_key, GIT_NAMESPACE, buffer)
}

/// [`sshsig_raw`] in any `namespace`, armored.
pub fn sshsig_armored_in(
    public_key_blob: &[u8],
    signing_key: &SigningKey,
    namespace: &[u8],
    buffer: &[u8],
) -> String {
    armor(&sshsig_raw(public_key_blob, signing_key, namespace, buffer))
}

/// A raw SSHSIG blob armored as `ssh-keygen` writes it (70 characters a line).
pub fn armor(raw_sshsig: &[u8]) -> String {
    SshSignature {
        raw_sshsig: raw_sshsig.to_vec(),
    }
    .to_armored_pem()
}

/// The wire form of a plain ed25519 public key.
pub fn ed25519_wire(key: &VerifyingKey) -> Vec<u8> {
    let mut wire = Vec::new();
    put_string(&mut wire, b"ssh-ed25519");
    put_string(&mut wire, key.as_bytes());
    wire
}

impl SshSignature {
    pub fn to_armored_pem(&self) -> String {
        let b64 = base64::engine::general_purpose::STANDARD.encode(&self.raw_sshsig);
        let mut pem = String::from("-----BEGIN SSH SIGNATURE-----\n");

        // OpenSSH armors at 70 characters
        for chunk in b64.as_bytes().chunks(70) {
            pem.push_str(std::str::from_utf8(chunk).unwrap());
            pem.push('\n');
        }

        pem.push_str("-----END SSH SIGNATURE-----\n");
        pem
    }
}
