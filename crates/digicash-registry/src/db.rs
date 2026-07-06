use std::str::FromStr;

use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod};
use tokio_postgres::NoTls;

use crate::error::RegistryError;

/// The maximum number of pooled Postgres connections.
const POOL_MAX_SIZE: usize = 16;

/// Build a deadpool-postgres connection pool for `database_url`. Plaintext connection
/// (`NoTls`): the database is a trusted backing store on a private network.
pub(crate) fn create_pool(database_url: &str) -> Result<Pool, RegistryError> {
    let config = tokio_postgres::Config::from_str(database_url)?;
    let manager = Manager::from_config(
        config,
        NoTls,
        ManagerConfig {
            recycling_method: RecyclingMethod::Fast,
        },
    );
    Ok(Pool::builder(manager).max_size(POOL_MAX_SIZE).build()?)
}

/// Apply all schema migrations in `./migrations` to `database_url`. Idempotent.
pub(crate) async fn run_migrations(database_url: &str) -> Result<(), RegistryError> {
    use sqlx::Connection;
    let mut connection = sqlx::postgres::PgConnection::connect(database_url).await?;
    sqlx::migrate!("./migrations").run(&mut connection).await?;
    connection.close().await?;
    Ok(())
}
