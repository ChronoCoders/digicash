use std::str::FromStr;

use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod};
use tokio_postgres::NoTls;

use crate::error::BankError;

/// The maximum number of pooled Postgres connections.
const POOL_MAX_SIZE: usize = 16;

/// Build a deadpool-postgres connection pool for `database_url` (production-spec v1.3
/// section 4). Plaintext connection (`NoTls`): the database is a trusted backing store on a
/// private network, not exposed like the client-facing mTLS API.
pub(crate) fn create_pool(database_url: &str) -> Result<Pool, BankError> {
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

/// Apply all schema migrations in `./migrations` to `database_url`, via sqlx. Idempotent:
/// already-applied migrations are skipped. Run at startup before the pool serves requests.
pub(crate) async fn run_migrations(database_url: &str) -> Result<(), BankError> {
    use sqlx::Connection;
    let mut connection = sqlx::postgres::PgConnection::connect(database_url).await?;
    sqlx::migrate!("./migrations").run(&mut connection).await?;
    connection.close().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::test_support::TestDatabase;

    #[tokio::test]
    async fn migrations_create_the_expected_tables() {
        let Some(db) = TestDatabase::create().await.expect("create test database") else {
            eprintln!("skipping: set DATABASE_URL to a Postgres instance to run this test");
            return;
        };
        let pool = db.pool().expect("pool");
        let client = pool.get().await.expect("connection");
        let rows = client
            .query(
                "SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename",
                &[],
            )
            .await
            .expect("query tables");
        let tables: Vec<String> = rows.iter().map(|r| r.get::<_, String>("tablename")).collect();
        for expected in [
            "accounts",
            "deposits",
            "identities",
            "nonce_store",
            "spent_serials",
            "withdraw_states",
        ] {
            assert!(
                tables.iter().any(|t| t == expected),
                "migration did not create table {expected}; found {tables:?}"
            );
        }
    }
}
