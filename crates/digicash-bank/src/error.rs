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

    /// An operation referenced an account that does not exist.
    #[error("account {0} not found")]
    AccountNotFound(String),

    /// A withdrawal asked for more than the account holds.
    #[error("account {account_id} has {balance} cents, cannot withdraw {requested}")]
    InsufficientBalance {
        account_id: String,
        balance: u64,
        requested: u64,
    },

    /// No key is configured for the requested `(denomination, scheme)`.
    #[error("no key for denomination {0} scheme 0")]
    UnknownDenomination(u64),

    /// A persisted withdrawal record could not be decoded or was internally inconsistent.
    #[error("withdrawal record for {request_id} is corrupt: {message}")]
    MalformedRecord { request_id: String, message: String },

    /// Signing failed after the debit; the debit was compensated before returning.
    #[error("withdrawal {request_id} failed and was rolled back: {message}")]
    WithdrawFailed { request_id: String, message: String },

    /// A retry of a `request_id` whose withdrawal previously failed and was rolled back.
    #[error("withdrawal {0} previously failed and was rolled back; use a new request_id")]
    WithdrawPreviouslyFailed(String),

    /// Crediting an account would overflow u64.
    #[error("balance overflow crediting account {0}")]
    BalanceOverflow(String),
}
