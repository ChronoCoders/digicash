use std::fmt;

use blind_rsa_signatures::Error as BrsaError;

/// Errors returned by digicash-core operations.
#[derive(Debug)]
pub enum CoreError {
    /// The operating system CSPRNG failed while generating a serial number.
    SerialGeneration(getrandom::Error),
    /// Generating a denomination keypair failed.
    KeyGeneration(BrsaError),
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
        }
    }
}

impl std::error::Error for CoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CoreError::SerialGeneration(e) => Some(e),
            CoreError::KeyGeneration(e) => Some(e),
        }
    }
}
