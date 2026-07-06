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
        url: String,
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
}
