use deadpool_postgres::Pool;

use crate::db;
use crate::error::RegistryError;

/// The registry: a Postgres-backed store of member banks, the shared spent-serial and
/// transcript store, per-issuer exposure caps, receivables, and the settlement claim ledger
/// (production-spec v1.4 section 10).
pub struct Registry {
    pool: Pool,
}

impl Registry {
    /// Connect to Postgres at `database_url` and run schema migrations.
    pub async fn connect(database_url: &str) -> Result<Self, RegistryError> {
        db::run_migrations(database_url).await?;
        Ok(Self {
            pool: db::create_pool(database_url)?,
        })
    }

    /// A pooled connection to the registry database.
    pub(crate) async fn client(&self) -> Result<deadpool_postgres::Object, RegistryError> {
        Ok(self.pool.get().await?)
    }

    /// Verify the database is reachable (a health probe).
    pub(crate) async fn ping(&self) -> Result<(), RegistryError> {
        self.client().await?.query_one("SELECT 1", &[]).await?;
        Ok(())
    }
}
