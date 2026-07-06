/// Errors returned by wallet operations.
#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    /// A command is not implemented yet.
    #[error("{0} is not implemented yet")]
    NotImplemented(&'static str),

    /// The local coin store (sled) failed.
    #[error("wallet store error: {0}")]
    Store(#[from] sled::Error),

    /// Encoding or decoding a stored coin failed.
    #[error("coin serialization error: {0}")]
    Json(#[from] serde_json::Error),

    /// An HTTP request to the bank failed (transport or non-2xx status).
    #[error("bank request to {url} failed: {source}")]
    Http {
        /// The URL that was requested.
        url: String,
        /// The underlying transport or status error.
        source: Box<ureq::Error>,
    },

    /// Reading or decoding a bank response body failed.
    #[error("bank response error: {0}")]
    Io(#[from] std::io::Error),

    /// No account is configured locally.
    #[error("no account configured; run `account create <id>` first")]
    NoAccount,

    /// The locally stored account id is not valid UTF-8.
    #[error("stored account id is corrupt (not UTF-8)")]
    CorruptAccountId,

    /// A core cryptographic operation (blind, unblind, verify, serial) failed.
    #[error("cryptographic error: {0}")]
    Core(#[from] digicash_core::CoreError),

    /// A bank public key could not be parsed from its published SPKI.
    #[error("could not parse a bank public key: {0}")]
    KeyParse(String),

    /// The OS CSPRNG failed while generating a request id.
    #[error("randomness error: {0}")]
    Random(#[from] getrandom::Error),

    /// The bank does not serve a denomination the wallet needs.
    #[error("the bank does not serve denomination {0} cents")]
    UnknownDenomination(u64),

    /// The local coin stock cannot make the requested amount exactly.
    #[error("cannot spend {requested} cents exactly from local coins (holding {held} cents); re-withdraw the exact denominations")]
    InsufficientCoins {
        /// The amount requested, in cents.
        requested: u64,
        /// The total value of coins held, in cents.
        held: u64,
    },

    /// Building the wallet's TLS client configuration failed.
    #[error("TLS configuration error: {0}")]
    Tls(#[from] rustls::Error),

    /// A PEM document (CA cert, client cert, or client key) held no usable item.
    #[error("{0}")]
    Pem(&'static str),

    /// The wallet has not registered an identity with the bank yet.
    #[error("wallet is not registered; run `account create <id>` first")]
    NotRegistered,

    /// A stored identity record was the wrong size or otherwise corrupt.
    #[error("stored wallet identity is corrupt: {0}")]
    CorruptIdentity(&'static str),

    /// The system clock is before the Unix epoch, so a request timestamp cannot be formed.
    #[error("system clock is before the Unix epoch")]
    Clock,

    /// A required configuration value (for example the bank CA certificate path) was missing
    /// or unreadable.
    #[error("configuration error: {0}")]
    Config(String),
}
