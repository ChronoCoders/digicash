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
        /// The denomination whose key failed.
        denom: u64,
        /// The scheme id of the key.
        scheme: u8,
        /// The underlying `blind-rsa-signatures` error, as text.
        message: String,
    },

    /// An account balance record was not the expected 8 bytes.
    #[error("corrupt balance record for account {account_id}: expected 8 bytes, found {found}")]
    MalformedBalance {
        /// The account with the corrupt balance record.
        account_id: String,
        /// The record length that was found, in bytes.
        found: usize,
    },

    /// Account creation was requested for an id that already exists.
    #[error("account {0} already exists")]
    AccountExists(String),

    /// An operation referenced an account that does not exist.
    #[error("account {0} not found")]
    AccountNotFound(String),

    /// A withdrawal asked for more than the account holds.
    #[error("account {account_id} has {balance} cents, cannot withdraw {requested}")]
    InsufficientBalance {
        /// The account that was short.
        account_id: String,
        /// The available balance, in cents.
        balance: u64,
        /// The amount requested, in cents.
        requested: u64,
    },

    /// No key is configured for the requested `(denomination, scheme)`.
    #[error("no key for denomination {0} scheme 0")]
    UnknownDenomination(u64),

    /// A persisted withdrawal record could not be decoded or was internally inconsistent.
    #[error("withdrawal record for {request_id} is corrupt: {message}")]
    MalformedRecord {
        /// The withdrawal whose record could not be decoded.
        request_id: String,
        /// The decode error, as text.
        message: String,
    },

    /// Signing failed after the debit; the debit was compensated before returning.
    #[error("withdrawal {request_id} failed and was rolled back: {message}")]
    WithdrawFailed {
        /// The withdrawal that failed and was rolled back.
        request_id: String,
        /// The signing error, as text.
        message: String,
    },

    /// A retry of a `request_id` whose withdrawal previously failed and was rolled back.
    #[error("withdrawal {0} previously failed and was rolled back; use a new request_id")]
    WithdrawPreviouslyFailed(String),

    /// Crediting an account would overflow u64.
    #[error("balance overflow crediting account {0}")]
    BalanceOverflow(String),

    /// Generating or serializing an X.509 certificate failed.
    #[error("certificate error: {0}")]
    CertGen(#[from] rcgen::Error),

    /// Building a rustls TLS configuration failed.
    #[error("TLS configuration error: {0}")]
    Tls(#[from] rustls::Error),

    /// Building the mTLS client-certificate verifier failed.
    #[error("client certificate verifier error: {0}")]
    ClientVerifier(#[from] rustls::server::VerifierBuilderError),

    /// A registered identity key record was not a valid 32-byte Ed25519 public key.
    #[error("corrupt identity key for account {account_id}: {message}")]
    MalformedIdentity {
        /// The account whose identity key record is corrupt.
        account_id: String,
        /// What was wrong with the record.
        message: String,
    },
}
