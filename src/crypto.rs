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
        let namespace = b"git";
        let reserved = b"";
        let hash_alg = b"sha512";

        // 1. Compute H(message) = SHA512(buffer)
        let mut hasher = Sha512::new();
        hasher.update(buffer);
        let message_hash = hasher.finalize();

        // 2. Prepare message to sign:
        // "SSHSIG" || string namespace || string reserved || string hash_algorithm || string H(message)
        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(b"SSHSIG");
        put_string(&mut signed_data, namespace);
        put_string(&mut signed_data, reserved);
        put_string(&mut signed_data, hash_alg);
        put_string(&mut signed_data, &message_hash);

        // 3. Sign signed_data with ed25519
        let signature = self.signing_key.sign(&signed_data);

        // 4. Construct OpenSSH signature blob:
        // string "ssh-ed25519" || string signature_bytes
        let mut sig_blob = Vec::new();
        put_string(&mut sig_blob, b"ssh-ed25519");
        put_string(&mut sig_blob, &signature.to_bytes());

        // 5. Construct complete SSHSIG payload:
        // magic "SSHSIG" (6 bytes)
        // uint32 version (1)
        // string publickey
        // string namespace
        // string reserved
        // string hash_algorithm
        // string signature
        let mut sshsig = Vec::new();
        sshsig.extend_from_slice(b"SSHSIG");
        put_u32(&mut sshsig, 1);
        put_string(&mut sshsig, &self.public_key_wire());
        put_string(&mut sshsig, namespace);
        put_string(&mut sshsig, reserved);
        put_string(&mut sshsig, hash_alg);
        put_string(&mut sshsig, &sig_blob);

        SshSignature { raw_sshsig: sshsig }
    }
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
