use std::fmt;

use blind_rsa_signatures::Error as BrsaError;

/// Errors returned by digicash-core operations.
#[derive(Debug)]
pub enum CoreError {
    /// The operating system CSPRNG failed while generating a serial number.
    SerialGeneration(getrandom::Error),
    /// Generating a denomination keypair failed.
    KeyGeneration(BrsaError),
    /// Blinding a serial for signing failed.
    Blinding(BrsaError),
    /// Blind-signing a blinded message failed.
    Signing(BrsaError),
    /// Unblinding a blind signature failed, including the signature check that
    /// `finalize` performs before returning the unblinded signature.
    Unblinding(BrsaError),
    /// A coin signature did not verify under the denomination public key.
    Verification(BrsaError),
    /// A `scheme_id` this crate does not implement was supplied.
    UnsupportedScheme(u8),
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CoreError::SerialGeneration(e) => {
                write!(f, "failed to generate a serial from the OS CSPRNG: {e}")
            }
            CoreError::KeyGeneration(e) => {
                write!(f, "failed to generate a denomination keypair: {e}")
            }
            CoreError::Blinding(e) => write!(f, "failed to blind a serial for signing: {e}"),
            CoreError::Signing(e) => write!(f, "failed to blind-sign a blinded message: {e}"),
            CoreError::Unblinding(e) => write!(f, "failed to unblind a blind signature: {e}"),
            CoreError::Verification(e) => {
                write!(f, "coin signature did not verify under the denomination key: {e}")
            }
            CoreError::UnsupportedScheme(id) => {
                write!(f, "unsupported scheme_id {id}; this crate implements only scheme 0")
            }
        }
    }
}

impl std::error::Error for CoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CoreError::SerialGeneration(e) => Some(e),
            CoreError::KeyGeneration(e)
            | CoreError::Blinding(e)
            | CoreError::Signing(e)
            | CoreError::Unblinding(e)
            | CoreError::Verification(e) => Some(e),
            CoreError::UnsupportedScheme(_) => None,
        }
    }
}
