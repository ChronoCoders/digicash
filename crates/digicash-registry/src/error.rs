/// Errors returned by registry operations.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    /// A Postgres query or connection operation failed.
    #[error("database error: {0}")]
    Db(#[from] tokio_postgres::Error),

    /// Checking out a connection from the pool failed.
    #[error("database pool error: {0}")]
    Pool(#[from] deadpool_postgres::PoolError),

    /// Building the database connection pool failed.
    #[error("database pool build error: {0}")]
    PoolBuild(#[from] deadpool_postgres::BuildError),

    /// A migration connection or query failed.
    #[error("migration connection error: {0}")]
    Sqlx(#[from] sqlx::Error),

    /// Running schema migrations failed.
    #[error("migration error: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),

    /// A TLS / certificate-authority operation (reused from the bank) failed.
    #[error("certificate authority error: {0}")]
    Ca(#[from] digicash_bank::BankError),

    /// A core cryptographic operation failed.
    #[error("cryptographic error: {0}")]
    Core(#[from] digicash_core::CoreError),

    /// A value read from or written to Postgres was out of the expected range.
    #[error("database value out of range: {0}")]
    ValueRange(String),

    /// A stored member identity key was not a valid 32-byte Ed25519 public key.
    #[error("corrupt member key for {bank_id}: {message}")]
    MalformedMember {
        /// The member whose key record is corrupt.
        bank_id: String,
        /// What was wrong with the record.
        message: String,
    },
}
