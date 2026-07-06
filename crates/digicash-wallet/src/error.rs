/// Errors returned by wallet operations.
#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    /// A command is not implemented yet.
    #[error("{0} is not implemented yet")]
    NotImplemented(&'static str),
}
