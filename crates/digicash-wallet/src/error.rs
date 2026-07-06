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
}
