use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use digicash_core::{canonical_payload, IdentityKeypair};
use digicash_proto::{
    BalanceResponse, CreateAccountRequest, DenominationsResponse, DepositRequest, DepositResponse,
    RegisterRequest, RegisterResponse, WithdrawRequest, WithdrawResponse, HEADER_ACCOUNT,
    HEADER_NONCE, HEADER_SIGNATURE, HEADER_TIMESTAMP,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore};
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::error::WalletError;

/// The crypto provider for the wallet's TLS, matching the bank's (ring).
fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// A client with server-side TLS only, trusting the bank's CA but presenting no client
/// certificate. Used once, to register, before the wallet has a client certificate.
pub struct EnrollClient {
    base_url: String,
    agent: ureq::Agent,
}

impl EnrollClient {
    /// Build an enrollment client that pins the bank via `ca_cert_pem`.
    pub fn new(base_url: String, ca_cert_pem: &str) -> Result<Self, WalletError> {
        let config = ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots_from_pem(ca_cert_pem)?)
            .with_no_client_auth();
        Ok(Self {
            base_url,
            agent: ureq::AgentBuilder::new().tls_config(Arc::new(config)).build(),
        })
    }

    /// `POST /register`: enroll an identity key and receive an issued client certificate.
    pub fn register(&self, req: &RegisterRequest) -> Result<RegisterResponse, WalletError> {
        let url = format!("{}/register", self.base_url);
        let response = self
            .agent
            .post(&url)
            .send_json(req)
            .map_err(|e| http_err(&url, e))?;
        Ok(response.into_json()?)
    }
}

/// A full mutual-TLS client that signs every request with the wallet's Ed25519 identity key
/// (production-spec v1.2 section 2).
pub struct BankClient {
    base_url: String,
    account_id: String,
    keypair: IdentityKeypair,
    agent: ureq::Agent,
}

impl BankClient {
    /// Build an authenticated client from the wallet's stored identity: the Ed25519 keypair
    /// for signing, and the CA/client PEM material for the mTLS connection.
    pub fn new(
        base_url: String,
        account_id: String,
        keypair: IdentityKeypair,
        ca_cert_pem: &str,
        client_cert_pem: &str,
        client_key_pem: &str,
    ) -> Result<Self, WalletError> {
        let config = ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots_from_pem(ca_cert_pem)?)
            .with_client_auth_cert(certs_from_pem(client_cert_pem)?, key_from_pem(client_key_pem)?)?;
        Ok(Self {
            base_url,
            account_id,
            keypair,
            agent: ureq::AgentBuilder::new().tls_config(Arc::new(config)).build(),
        })
    }

    /// `POST /accounts`: create the wallet's account and return its balance.
    pub fn create_account(
        &self,
        req: &CreateAccountRequest,
    ) -> Result<BalanceResponse, WalletError> {
        self.signed_post("/accounts", req)
    }

    /// `GET /accounts/{id}/balance`: fetch this account's balance.
    pub fn balance(&self, account_id: &str) -> Result<BalanceResponse, WalletError> {
        self.signed_get(&format!("/accounts/{account_id}/balance"))
    }

    /// `GET /denominations`: fetch the bank's published denomination public keys.
    pub fn denominations(&self) -> Result<DenominationsResponse, WalletError> {
        self.signed_get("/denominations")
    }

    /// `POST /withdraw`: submit a blinded message and return the blind signature.
    pub fn withdraw(&self, req: &WithdrawRequest) -> Result<WithdrawResponse, WalletError> {
        self.signed_post("/withdraw", req)
    }

    /// `POST /deposit`: deposit a coin and return whether it was accepted.
    pub fn deposit(&self, req: &DepositRequest) -> Result<DepositResponse, WalletError> {
        self.signed_post("/deposit", req)
    }

    fn signed_post<Req: Serialize, Resp: DeserializeOwned>(
        &self,
        path: &str,
        req: &Req,
    ) -> Result<Resp, WalletError> {
        let body = serde_json::to_vec(req)?;
        let auth = self.sign("POST", path, &body)?;
        let url = format!("{}{path}", self.base_url);
        let response = self
            .agent
            .post(&url)
            .set("content-type", "application/json")
            .set(HEADER_ACCOUNT, &self.account_id)
            .set(HEADER_TIMESTAMP, &auth.timestamp)
            .set(HEADER_NONCE, &auth.nonce)
            .set(HEADER_SIGNATURE, &auth.signature)
            .send_bytes(&body)
            .map_err(|e| http_err(&url, e))?;
        Ok(response.into_json()?)
    }

    fn signed_get<Resp: DeserializeOwned>(&self, path: &str) -> Result<Resp, WalletError> {
        let auth = self.sign("GET", path, b"")?;
        let url = format!("{}{path}", self.base_url);
        let response = self
            .agent
            .get(&url)
            .set(HEADER_ACCOUNT, &self.account_id)
            .set(HEADER_TIMESTAMP, &auth.timestamp)
            .set(HEADER_NONCE, &auth.nonce)
            .set(HEADER_SIGNATURE, &auth.signature)
            .call()
            .map_err(|e| http_err(&url, e))?;
        Ok(response.into_json()?)
    }

    /// Build the authentication header values for a request: a fresh timestamp and nonce, and
    /// the Ed25519 signature over the canonical payload for `method`, `path`, and `body`.
    fn sign(&self, method: &str, path: &str, body: &[u8]) -> Result<SignedAuth, WalletError> {
        let timestamp = now_unix()?;
        let nonce = random_nonce()?;
        let payload = canonical_payload(method, path, body, timestamp, &nonce);
        let signature = hex::encode(self.keypair.sign(payload.as_bytes()));
        Ok(SignedAuth {
            timestamp: timestamp.to_string(),
            nonce,
            signature,
        })
    }
}

struct SignedAuth {
    timestamp: String,
    nonce: String,
    signature: String,
}

fn now_unix() -> Result<u64, WalletError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| WalletError::Clock)
}

fn random_nonce() -> Result<String, WalletError> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes)?;
    Ok(hex::encode(bytes))
}

fn roots_from_pem(pem: &str) -> Result<RootCertStore, WalletError> {
    let mut roots = RootCertStore::empty();
    let mut any = false;
    for cert in rustls_pemfile::certs(&mut pem.as_bytes()) {
        roots.add(cert?)?;
        any = true;
    }
    if !any {
        return Err(WalletError::Pem("CA certificate PEM held no certificate"));
    }
    Ok(roots)
}

fn certs_from_pem(pem: &str) -> Result<Vec<CertificateDer<'static>>, WalletError> {
    let certs = rustls_pemfile::certs(&mut pem.as_bytes()).collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        return Err(WalletError::Pem("client certificate PEM held no certificate"));
    }
    Ok(certs)
}

fn key_from_pem(pem: &str) -> Result<PrivateKeyDer<'static>, WalletError> {
    rustls_pemfile::private_key(&mut pem.as_bytes())?
        .ok_or(WalletError::Pem("client key PEM held no private key"))
}

fn http_err(url: &str, source: ureq::Error) -> WalletError {
    WalletError::Http {
        url: url.to_string(),
        source: Box::new(source),
    }
}
