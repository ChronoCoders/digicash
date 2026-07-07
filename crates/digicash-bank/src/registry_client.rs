use std::fs;
use std::path::Path;
use std::sync::Arc;

use digicash_core::{canonical_payload, IdentityKeypair, IDENTITY_SECRET_KEY_LEN};
use digicash_proto::{
    SerialOutcome, SerialResponse, SerialSubmission, HEADER_ACCOUNT, HEADER_NONCE, HEADER_SIGNATURE,
    HEADER_TIMESTAMP,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore};
use sha2::{Digest, Sha256};

use crate::error::BankError;

/// A bank's client to the multi-bank registry (production-spec v1.4 section 10): mTLS with the
/// registry CA, and each request Ed25519-signed as a registered member (section 2). Configured
/// from the environment; absent for single-bank operation.
pub struct RegistryClient {
    url: String,
    bank_id: String,
    issuer_id: String,
    keypair: IdentityKeypair,
    agent: ureq::Agent,
}

impl RegistryClient {
    /// Build from the environment, or `None` if `DIGICASH_REGISTRY_URL` is unset (single-bank).
    ///
    /// Reads the registry identity from `key_dir`: `registry-ca.pem` (registry CA),
    /// `registry-cert.pem` / `registry-key.pem` (this bank's mTLS client identity), and
    /// `registry-ed25519.hex` (its Ed25519 request-signing secret). `DIGICASH_BANK_ID` is the
    /// member id; `DIGICASH_COIN_ISSUER_ID` (default: the bank id) is the issuer reported for
    /// deposited coins.
    pub fn from_env(key_dir: &Path) -> Result<Option<Self>, BankError> {
        let Ok(url) = std::env::var("DIGICASH_REGISTRY_URL") else {
            return Ok(None);
        };
        let bank_id = std::env::var("DIGICASH_BANK_ID").map_err(|_| {
            BankError::RegistryConfig("DIGICASH_BANK_ID must be set with DIGICASH_REGISTRY_URL".into())
        })?;
        let issuer_id = std::env::var("DIGICASH_COIN_ISSUER_ID").unwrap_or_else(|_| bank_id.clone());

        let ca_pem = read_identity_file(key_dir, "registry-ca.pem")?;
        let cert_pem = read_identity_file(key_dir, "registry-cert.pem")?;
        let key_pem = read_identity_file(key_dir, "registry-key.pem")?;
        let secret_hex = read_identity_file(key_dir, "registry-ed25519.hex")?;
        let secret: [u8; IDENTITY_SECRET_KEY_LEN] = hex::decode(secret_hex.trim())
            .map_err(|_| BankError::RegistryConfig("registry-ed25519.hex is not valid hex".into()))?
            .as_slice()
            .try_into()
            .map_err(|_| BankError::RegistryConfig("registry Ed25519 secret must be 32 bytes".into()))?;
        let keypair = IdentityKeypair::from_secret_bytes(&secret);

        let config = mtls_config(&ca_pem, &cert_pem, &key_pem)?;
        let agent = ureq::AgentBuilder::new().tls_config(Arc::new(config)).build();
        Ok(Some(Self {
            url,
            bank_id,
            issuer_id,
            keypair,
            agent,
        }))
    }

    /// Submit a coin serial and its transcript digest to the registry at deposit time, and
    /// return the outcome (accepted, cross-bank double-spend, or exposure-cap exceeded).
    pub fn submit_serial(
        &self,
        denomination_cents: u64,
        scheme_id: u8,
        serial: &[u8; 32],
        now: u64,
    ) -> Result<SerialOutcome, BankError> {
        let serial_hex = hex::encode(serial);
        let transcript = self.transcript(&serial_hex, now);
        let submission = SerialSubmission {
            issuing_bank_id: self.issuer_id.clone(),
            denomination_cents,
            scheme_id,
            serial_hex,
            transcript,
        };
        let body = serde_json::to_vec(&submission)
            .map_err(|e| BankError::RegistryHttp(format!("serialize submission: {e}")))?;
        let nonce = random_nonce()?;
        let payload = canonical_payload("POST", "/serials", &body, now, &nonce);
        let signature = hex::encode(self.keypair.sign(payload.as_bytes()));
        let url = format!("{}/serials", self.url);
        let response = self
            .agent
            .post(&url)
            .set("content-type", "application/json")
            .set(HEADER_ACCOUNT, &self.bank_id)
            .set(HEADER_TIMESTAMP, &now.to_string())
            .set(HEADER_NONCE, &nonce)
            .set(HEADER_SIGNATURE, &signature)
            .send_bytes(&body)
            .map_err(|e| BankError::RegistryHttp(format!("POST {url}: {e}")))?;
        let parsed: SerialResponse = response
            .into_json()
            .map_err(|e| BankError::RegistryHttp(format!("decode registry response: {e}")))?;
        Ok(parsed.outcome)
    }

    /// `H(coin_serial || depositing_bank_id || timestamp)`, lowercase hex (spec v1.4 sec. 10).
    fn transcript(&self, serial_hex: &str, now: u64) -> String {
        let mut hasher = Sha256::new();
        hasher.update(serial_hex.as_bytes());
        hasher.update(self.bank_id.as_bytes());
        hasher.update(now.to_string().as_bytes());
        hex::encode(hasher.finalize())
    }
}

fn read_identity_file(key_dir: &Path, name: &str) -> Result<String, BankError> {
    fs::read_to_string(key_dir.join(name))
        .map_err(|e| BankError::RegistryConfig(format!("cannot read {name}: {e}")))
}

fn random_nonce() -> Result<String, BankError> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes)
        .map_err(|e| BankError::RegistryConfig(format!("nonce randomness: {e}")))?;
    Ok(hex::encode(bytes))
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn mtls_config(ca_pem: &str, cert_pem: &str, key_pem: &str) -> Result<ClientConfig, BankError> {
    let mut roots = RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut ca_pem.as_bytes()) {
        let cert = cert.map_err(|e| BankError::RegistryConfig(format!("registry CA PEM: {e}")))?;
        roots
            .add(cert)
            .map_err(|e| BankError::RegistryConfig(format!("add registry CA root: {e}")))?;
    }
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .collect::<Result<_, _>>()
        .map_err(|e| BankError::RegistryConfig(format!("registry client cert PEM: {e}")))?;
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_pem.as_bytes())
        .map_err(|e| BankError::RegistryConfig(format!("registry client key PEM: {e}")))?
        .ok_or_else(|| BankError::RegistryConfig("registry client key PEM held no key".into()))?;
    ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(BankError::Tls)?
        .with_root_certificates(roots)
        .with_client_auth_cert(certs, key)
        .map_err(BankError::Tls)
}
