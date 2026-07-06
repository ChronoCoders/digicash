use std::fs;
use std::path::Path;
use std::sync::Arc;

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};

use crate::error::BankError;

const CA_KEY_FILE: &str = "ca-key.pem";
const CA_COMMON_NAME: &str = "digicash bank CA";
const SERVER_COMMON_NAME: &str = "digicash bank";

/// The single crypto provider used across the bank's TLS, matching the wallet's (ring).
/// Chosen explicitly rather than via the process default so a future second provider in the
/// dependency graph cannot make config construction ambiguous.
fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// The bank's self-signed certificate authority plus its issued server identity (spec v1.2
/// section 2).
///
/// One CA per bank instance. Only the CA private key is persisted (to the key directory);
/// the CA certificate and the server certificate are regenerated from that key on every
/// startup. Because the key is stable, client certificates issued in an earlier run still
/// chain to the CA. No public domain or public CA is involved.
pub struct CertAuthority {
    ca_key: KeyPair,
    ca_cert: rcgen::Certificate,
    server_cert_der: CertificateDer<'static>,
    server_key_der: Vec<u8>,
}

impl CertAuthority {
    /// Load the CA key from `key_dir`, generating and persisting it on first run, then derive
    /// the CA certificate and a fresh CA-signed server certificate.
    ///
    /// The CA key is stored as plaintext PEM: acceptable for a local self-signed CA only;
    /// encrypted-at-rest or HSM/KMS storage is a production requirement.
    pub fn load_or_create(key_dir: &Path) -> Result<Self, BankError> {
        fs::create_dir_all(key_dir)?;
        let ca_key_path = key_dir.join(CA_KEY_FILE);
        let ca_key = if ca_key_path.exists() {
            KeyPair::from_pem(&fs::read_to_string(&ca_key_path)?)?
        } else {
            let key = KeyPair::generate()?;
            fs::write(&ca_key_path, key.serialize_pem())?;
            tracing::info!("generated new self-signed TLS certificate authority");
            key
        };
        let ca_cert = ca_params()?.self_signed(&ca_key)?;

        let server_key = KeyPair::generate()?;
        let server_cert = server_params()?.signed_by(&server_key, &ca_cert, &ca_key)?;
        Ok(Self {
            ca_key,
            ca_cert,
            server_cert_der: server_cert.der().clone(),
            server_key_der: server_key.serialize_der(),
        })
    }

    /// The CA certificate in DER: the trust anchor wallets pin to verify the bank, and the
    /// root the bank verifies client certificates against.
    pub fn ca_cert_der(&self) -> CertificateDer<'static> {
        self.ca_cert.der().clone()
    }

    /// The CA certificate as PEM, handed to a wallet at registration so it can trust the bank.
    pub fn ca_cert_pem(&self) -> String {
        self.ca_cert.pem()
    }

    /// A rustls server configuration for mutual TLS: the bank presents its CA-signed server
    /// certificate and requires every client to present a certificate this CA signed. A
    /// connection with no client certificate, or one signed by another CA, fails the
    /// handshake.
    pub fn server_config(&self) -> Result<Arc<ServerConfig>, BankError> {
        let mut roots = RootCertStore::empty();
        roots.add(self.ca_cert_der())?;
        let verifier =
            WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider()).build()?;
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.server_key_der.clone()));
        let config = ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()?
            .with_client_cert_verifier(verifier)
            .with_single_cert(vec![self.server_cert_der.clone()], key)?;
        Ok(Arc::new(config))
    }

    /// Issue a client certificate for `account_id`, signed by the CA. The wallet uses the
    /// returned certificate and key as its mTLS client identity. Used by `POST /register`.
    pub fn issue_client_identity(&self, account_id: &str) -> Result<ClientIdentity, BankError> {
        let key = KeyPair::generate()?;
        let cert = client_params(account_id)?.signed_by(&key, &self.ca_cert, &self.ca_key)?;
        Ok(ClientIdentity {
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
            cert_der: cert.der().clone(),
            key_pkcs8_der: key.serialize_der(),
        })
    }
}

/// A client's issued mTLS identity: a CA-signed leaf certificate and its private key, in both
/// PEM (returned to the wallet over the wire) and DER (for in-process config building).
pub struct ClientIdentity {
    /// The leaf certificate, PEM.
    pub cert_pem: String,
    /// The private key, PKCS#8 PEM.
    pub key_pem: String,
    /// The leaf certificate, DER.
    pub cert_der: CertificateDer<'static>,
    /// The private key, PKCS#8 DER.
    pub key_pkcs8_der: Vec<u8>,
}

fn single_cn(common_name: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    dn
}

fn ca_params() -> Result<CertificateParams, BankError> {
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.distinguished_name = single_cn(CA_COMMON_NAME);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    Ok(params)
}

fn server_params() -> Result<CertificateParams, BankError> {
    let mut params = CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])?;
    params.distinguished_name = single_cn(SERVER_COMMON_NAME);
    params.use_authority_key_identifier_extension = true;
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    Ok(params)
}

fn client_params(account_id: &str) -> Result<CertificateParams, BankError> {
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.distinguished_name = single_cn(account_id);
    params.use_authority_key_identifier_extension = true;
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    Ok(params)
}

#[cfg(test)]
mod tests {
    use super::{provider, CertAuthority, ClientIdentity};
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection};
    use std::sync::Arc;
    use tempfile::TempDir;

    fn ca(tmp: &TempDir) -> CertAuthority {
        CertAuthority::load_or_create(&tmp.path().join("keys")).expect("ca")
    }

    fn roots_of(ca: &CertAuthority) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots.add(ca.ca_cert_der()).expect("add ca root");
        roots
    }

    fn client_with_auth(ca: &CertAuthority, id: &ClientIdentity) -> Arc<ClientConfig> {
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(id.key_pkcs8_der.clone()));
        Arc::new(
            ClientConfig::builder_with_provider(provider())
                .with_safe_default_protocol_versions()
                .expect("versions")
                .with_root_certificates(roots_of(ca))
                .with_client_auth_cert(vec![id.cert_der.clone()], key)
                .expect("client auth cert"),
        )
    }

    fn client_without_auth(ca: &CertAuthority) -> Arc<ClientConfig> {
        Arc::new(
            ClientConfig::builder_with_provider(provider())
                .with_safe_default_protocol_versions()
                .expect("versions")
                .with_root_certificates(roots_of(ca))
                .with_no_client_auth(),
        )
    }

    /// Drive an in-memory TLS handshake between the two configs to completion, surfacing any
    /// certificate-verification error. No sockets: each side's TLS output is fed to the other.
    fn handshake(
        server_config: Arc<ServerConfig>,
        client_config: Arc<ClientConfig>,
    ) -> Result<(), rustls::Error> {
        let name = ServerName::try_from("localhost").expect("server name");
        let mut client = ClientConnection::new(client_config, name)?;
        let mut server = ServerConnection::new(server_config)?;
        for _ in 0..30 {
            pump(&mut |buf| client.write_tls(buf), &mut |rd| server.read_tls(rd))?;
            server.process_new_packets()?;
            pump(&mut |buf| server.write_tls(buf), &mut |rd| client.read_tls(rd))?;
            client.process_new_packets()?;
            if !client.is_handshaking() && !server.is_handshaking() {
                return Ok(());
            }
        }
        Ok(())
    }

    /// Move one flight of TLS records from a writer side to a reader side.
    fn pump(
        write_tls: &mut dyn FnMut(&mut dyn std::io::Write) -> std::io::Result<usize>,
        read_tls: &mut dyn FnMut(&mut dyn std::io::Read) -> std::io::Result<usize>,
    ) -> Result<(), rustls::Error> {
        let mut buf = Vec::new();
        write_tls(&mut buf).expect("write_tls");
        let mut cursor = &buf[..];
        while !cursor.is_empty() {
            let read = read_tls(&mut cursor).expect("read_tls");
            if read == 0 {
                break;
            }
        }
        Ok(())
    }

    #[test]
    fn handshake_succeeds_with_ca_issued_client_cert() {
        let tmp = TempDir::new().expect("tempdir");
        let ca = ca(&tmp);
        let id = ca.issue_client_identity("alice").expect("issue");
        handshake(ca.server_config().expect("server config"), client_with_auth(&ca, &id))
            .expect("mTLS handshake with a CA-issued client cert must succeed");
    }

    #[test]
    fn handshake_fails_without_client_cert() {
        let tmp = TempDir::new().expect("tempdir");
        let ca = ca(&tmp);
        let result = handshake(ca.server_config().expect("server config"), client_without_auth(&ca));
        assert!(
            result.is_err(),
            "server accepted a client that presented no certificate"
        );
    }

    #[test]
    fn handshake_fails_with_client_cert_from_another_ca() {
        let tmp = TempDir::new().expect("tempdir");
        let tmp_other = TempDir::new().expect("tempdir other");
        let ca = ca(&tmp);
        let other_ca = CertAuthority::load_or_create(&tmp_other.path().join("keys")).expect("other");
        let foreign = other_ca.issue_client_identity("mallory").expect("issue");
        // The client trusts the real bank CA as a server root but presents a cert the real CA
        // never signed; the server's verifier must reject it.
        let result = handshake(ca.server_config().expect("server config"), client_with_auth(&ca, &foreign));
        assert!(
            result.is_err(),
            "server accepted a client cert signed by an untrusted CA"
        );
    }

    #[test]
    fn client_cert_survives_ca_reload() {
        let tmp = TempDir::new().expect("tempdir");
        let key_dir = tmp.path().join("keys");
        // Issue a client cert under the first CA instance.
        let id = CertAuthority::load_or_create(&key_dir)
            .expect("ca")
            .issue_client_identity("alice")
            .expect("issue");
        // Reopen the CA (same persisted key) and confirm the earlier client cert still chains.
        let reopened = CertAuthority::load_or_create(&key_dir).expect("reopen ca");
        handshake(reopened.server_config().expect("server config"), client_with_auth(&reopened, &id))
            .expect("a client cert issued before restart must still authenticate after reload");
    }
}
