use digicash_core::CoreError;

/// Errors returned by bank operations.
#[derive(Debug, thiserror::Error)]
pub enum BankError {
    /// A sled storage operation failed.
    #[error("storage error: {0}")]
    Sled(#[from] sled::Error),

    /// Reading or writing a key file failed.
    #[error("key directory I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A core cryptographic operation failed.
    #[error("cryptographic error: {0}")]
    Core(#[from] CoreError),

    /// Loading, deriving, or persisting a denomination key failed. The underlying
    /// `blind-rsa-signatures` error is carried as a message to avoid leaking that type
    /// into the bank's public error surface.
    #[error("denomination key error for denomination {denom} scheme {scheme}: {message}")]
    Key {
        denom: u64,
        scheme: u8,
        message: String,
    },

    /// An account balance record was not the expected 8 bytes.
    #[error("corrupt balance record for account {account_id}: expected 8 bytes, found {found}")]
    MalformedBalance { account_id: String, found: usize },

    /// Account creation was requested for an id that already exists.
    #[error("account {0} already exists")]
    AccountExists(String),
}
