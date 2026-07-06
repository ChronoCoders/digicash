use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use digicash_core::{
    generate_keypair, DefaultRng, DenominationKeypair, DenominationSecretKey,
    SCHEME_ID_RSA_DETERMINISTIC,
};

use crate::error::BankError;

/// In-memory denomination key store, keyed by `(denomination_cents, scheme_id)`. No key
/// is shared across denominations or schemes (spec v0.3 section 3).
pub(crate) struct KeyStore {
    keys: BTreeMap<(u64, u8), DenominationKeypair>,
}

impl KeyStore {
    /// Load a key for each denomination from `dir`, generating and persisting any that are
    /// missing. Every key is scheme [`SCHEME_ID_RSA_DETERMINISTIC`].
    ///
    /// v1 stores private keys as plaintext PEM files. This is acceptable for a demo bank
    /// only; encrypted-at-rest or HSM/KMS storage is a production requirement.
    pub(crate) fn load_or_create(dir: &Path, denominations: &[u64]) -> Result<Self, BankError> {
        fs::create_dir_all(dir)?;
        let scheme = SCHEME_ID_RSA_DETERMINISTIC;
        let mut keys = BTreeMap::new();
        for &denom in denominations {
            let path = key_path(dir, denom, scheme);
            let keypair = if path.exists() {
                load_key(&path, denom, scheme)?
            } else {
                create_key(&path, denom, scheme)?
            };
            keys.insert((denom, scheme), keypair);
        }
        Ok(Self { keys })
    }

    pub(crate) fn get(&self, denom: u64, scheme: u8) -> Option<&DenominationKeypair> {
        self.keys.get(&(denom, scheme))
    }
}

fn key_path(dir: &Path, denom: u64, scheme: u8) -> PathBuf {
    dir.join(format!("denom_{denom}_scheme_{scheme}.pem"))
}

fn load_key(path: &Path, denom: u64, scheme: u8) -> Result<DenominationKeypair, BankError> {
    let pem = fs::read_to_string(path)?;
    let sk = DenominationSecretKey::from_pem(&pem).map_err(|e| key_err(denom, scheme, "parse PEM", e))?;
    let pk = sk
        .public_key()
        .map_err(|e| key_err(denom, scheme, "derive public key", e))?;
    Ok(DenominationKeypair { pk, sk })
}

fn create_key(path: &Path, denom: u64, scheme: u8) -> Result<DenominationKeypair, BankError> {
    let keypair = generate_keypair(&mut DefaultRng)?;
    let pem = keypair
        .sk
        .to_pem()
        .map_err(|e| key_err(denom, scheme, "encode PEM", e))?;
    fs::write(path, pem)?;
    tracing::info!(denomination = denom, scheme, "generated new denomination key");
    Ok(keypair)
}

/// Wrap a key codec error (from the re-exported `blind-rsa-signatures` methods) as a
/// [`BankError::Key`]. Generic over `Display` so this crate never names that error type.
fn key_err<E: std::fmt::Display>(denom: u64, scheme: u8, context: &str, source: E) -> BankError {
    BankError::Key {
        denom,
        scheme,
        message: format!("{context}: {source}"),
    }
}
