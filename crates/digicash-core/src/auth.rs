use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};

use crate::error::CoreError;

/// Length of an Ed25519 secret (seed) key, in bytes.
pub const IDENTITY_SECRET_KEY_LEN: usize = 32;
/// Length of an Ed25519 public key, in bytes.
pub const IDENTITY_PUBLIC_KEY_LEN: usize = 32;
/// Length of an Ed25519 signature, in bytes.
pub const IDENTITY_SIGNATURE_LEN: usize = 64;

/// A wallet's Ed25519 signing keypair - its identity to the bank (spec v1.2 section 2).
///
/// The wallet holds the secret half and signs every request's canonical payload
/// ([`canonical_payload`]); the bank holds the registered public half and verifies. Secret
/// bytes come from the OS CSPRNG, never a userspace PRNG.
pub struct IdentityKeypair {
    signing: SigningKey,
}

impl IdentityKeypair {
    /// Generate a fresh keypair from the operating system CSPRNG.
    pub fn generate() -> Result<Self, CoreError> {
        let mut secret = [0u8; IDENTITY_SECRET_KEY_LEN];
        getrandom::fill(&mut secret).map_err(CoreError::IdentityKeyGeneration)?;
        Ok(Self {
            signing: SigningKey::from_bytes(&secret),
        })
    }

    /// Reconstruct a keypair from its persisted 32-byte secret seed.
    pub fn from_secret_bytes(secret: &[u8; IDENTITY_SECRET_KEY_LEN]) -> Self {
        Self {
            signing: SigningKey::from_bytes(secret),
        }
    }

    /// The 32-byte secret seed, for persistence. Handle as key material.
    pub fn secret_bytes(&self) -> [u8; IDENTITY_SECRET_KEY_LEN] {
        self.signing.to_bytes()
    }

    /// The public half, registered with the bank.
    pub fn public_key(&self) -> IdentityPublicKey {
        IdentityPublicKey {
            verifying: self.signing.verifying_key(),
        }
    }

    /// Sign `message` (the canonical payload bytes), returning the 64-byte signature.
    pub fn sign(&self, message: &[u8]) -> [u8; IDENTITY_SIGNATURE_LEN] {
        self.signing.sign(message).to_bytes()
    }
}

/// The public half of an [`IdentityKeypair`]: what the bank stores per account and verifies
/// signatures against.
#[derive(Clone)]
pub struct IdentityPublicKey {
    verifying: VerifyingKey,
}

impl IdentityPublicKey {
    /// Parse a public key from its 32-byte encoding, rejecting a non-canonical point.
    pub fn from_bytes(bytes: &[u8; IDENTITY_PUBLIC_KEY_LEN]) -> Result<Self, CoreError> {
        VerifyingKey::from_bytes(bytes)
            .map(|verifying| Self { verifying })
            .map_err(CoreError::IdentityPublicKeyInvalid)
    }

    /// The 32-byte encoding, for storage and registration.
    pub fn to_bytes(&self) -> [u8; IDENTITY_PUBLIC_KEY_LEN] {
        self.verifying.to_bytes()
    }

    /// Verify a 64-byte signature over `message` under this key.
    pub fn verify(
        &self,
        message: &[u8],
        signature: &[u8; IDENTITY_SIGNATURE_LEN],
    ) -> Result<(), CoreError> {
        let sig = ed25519_dalek::Signature::from_bytes(signature);
        self.verifying
            .verify(message, &sig)
            .map_err(CoreError::IdentitySignatureInvalid)
    }
}

/// Build the canonical signed payload for a request (spec v1.2 section 2):
/// `method || path || hex(SHA-256(body)) || timestamp || nonce`, the five fields joined by
/// `|` as UTF-8. `method` is upper-cased and the body hash is lowercase hex, so the same
/// request always yields the same string on both the signing and verifying sides. Ed25519
/// signs this string directly (it hashes internally); there is no outer hash.
pub fn canonical_payload(
    method: &str,
    path: &str,
    body: &[u8],
    timestamp: u64,
    nonce: &str,
) -> String {
    use sha2::{Digest, Sha256};
    let body_hash = hex::encode(Sha256::digest(body));
    format!(
        "{}|{}|{}|{}|{}",
        method.to_ascii_uppercase(),
        path,
        body_hash,
        timestamp,
        nonce
    )
}

#[cfg(test)]
mod tests {
    use super::{canonical_payload, IdentityKeypair, IdentityPublicKey};

    #[test]
    fn keypair_generates_distinct_public_keys() {
        let a = IdentityKeypair::generate().expect("OS CSPRNG available in test environment");
        let b = IdentityKeypair::generate().expect("OS CSPRNG available in test environment");
        assert_eq!(a.public_key().to_bytes().len(), 32);
        assert_ne!(
            a.public_key().to_bytes(),
            b.public_key().to_bytes(),
            "two independently generated identity keys collided"
        );
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let kp = IdentityKeypair::generate().expect("keypair");
        let msg = b"POST|/withdraw|deadbeef|1700000000|abcd";
        let sig = kp.sign(msg);
        kp.public_key()
            .verify(msg, &sig)
            .expect("a signature must verify under its own public key");
    }

    #[test]
    fn verify_fails_under_wrong_key() {
        let signer = IdentityKeypair::generate().expect("signer");
        let other = IdentityKeypair::generate().expect("other");
        let msg = b"POST|/deposit|00|1|n";
        let sig = signer.sign(msg);
        assert!(
            other.public_key().verify(msg, &sig).is_err(),
            "signature verified under an unrelated public key"
        );
    }

    #[test]
    fn verify_fails_on_tampered_message() {
        let kp = IdentityKeypair::generate().expect("keypair");
        let sig = kp.sign(b"POST|/withdraw|aa|1|n");
        assert!(
            kp.public_key().verify(b"POST|/withdraw|bb|1|n", &sig).is_err(),
            "signature verified over a different message"
        );
    }

    #[test]
    fn public_key_round_trips_through_bytes() {
        let kp = IdentityKeypair::generate().expect("keypair");
        let bytes = kp.public_key().to_bytes();
        let rebuilt = IdentityPublicKey::from_bytes(&bytes).expect("parse public key");
        assert_eq!(rebuilt.to_bytes(), bytes);
    }

    #[test]
    fn secret_bytes_round_trip_preserves_signatures() {
        let kp = IdentityKeypair::generate().expect("keypair");
        let secret = kp.secret_bytes();
        let restored = IdentityKeypair::from_secret_bytes(&secret);
        assert_eq!(restored.public_key().to_bytes(), kp.public_key().to_bytes());
    }

    #[test]
    fn canonical_payload_is_deterministic_and_formatted() {
        let a = canonical_payload("POST", "/withdraw", b"body-bytes", 1_700_000_000, "n0nce");
        let b = canonical_payload("POST", "/withdraw", b"body-bytes", 1_700_000_000, "n0nce");
        assert_eq!(a, b, "canonical payload is not deterministic");
        // Empty-body known answer: hex(SHA-256("")) is the standard e3b0c442... digest, so the
        // exact string pins both the format and the hashing.
        assert_eq!(
            canonical_payload("GET", "/accounts/x/balance", b"", 5, "nn"),
            "GET|/accounts/x/balance|\
             e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855|5|nn",
            "canonical payload format changed"
        );
    }

    #[test]
    fn canonical_payload_upcases_method() {
        assert_eq!(
            canonical_payload("post", "/x", b"", 1, "n"),
            canonical_payload("POST", "/x", b"", 1, "n"),
        );
    }
}
