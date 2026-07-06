//! Isolated Postgres test databases. Available in this crate's own tests and, via the
//! `test-support` feature, to downstream dev-dependencies (digicash-wallet, digicash-e2e).
//!
//! Each [`TestDatabase`] is a freshly-created, migrated database off the base `DATABASE_URL`,
//! so tests running in parallel never share ledger state. Databases are left in place (drop
//! them by discarding the test Postgres instance); this keeps the helper free of a blocking
//! teardown.

use std::sync::atomic::{AtomicU64, Ordering};

use deadpool_postgres::Pool;
use tokio_postgres::NoTls;

use crate::db;
use crate::error::BankError;

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// The base `DATABASE_URL` for the test Postgres, or `None` if unset (tests should skip).
pub fn base_url() -> Option<String> {
    std::env::var("DATABASE_URL").ok().filter(|u| !u.is_empty())
}

/// A freshly-created, migrated Postgres database dedicated to one test.
pub struct TestDatabase {
    url: String,
}

impl TestDatabase {
    /// Create a uniquely-named database off the base `DATABASE_URL`, run migrations on it, and
    /// return a handle. `Ok(None)` when `DATABASE_URL` is unset, so a caller can skip.
    pub async fn create() -> Result<Option<TestDatabase>, BankError> {
        let Some(base) = base_url() else {
            return Ok(None);
        };
        let name = format!(
            "digicash_test_{}_{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        create_database(&base, &name).await?;
        let url = swap_dbname(&base, &name);
        db::run_migrations(&url).await?;
        Ok(Some(TestDatabase { url }))
    }

    /// The connection URL for this test's database.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// A connection pool to this test's database.
    pub fn pool(&self) -> Result<Pool, BankError> {
        db::create_pool(&self.url)
    }
}

async fn create_database(base_url: &str, name: &str) -> Result<(), BankError> {
    let (client, connection) = tokio_postgres::connect(base_url, NoTls).await?;
    let driver = tokio::spawn(connection);
    // `name` is generated internally (never user input) and identifiers cannot be bound as
    // query parameters, so it is interpolated directly.
    let result = client
        .batch_execute(&format!("CREATE DATABASE \"{name}\""))
        .await;
    drop(client);
    let _ = driver.await;
    result?;
    Ok(())
}

/// Replace the database name in a `postgres://.../dbname[?query]` URL, preserving any query.
fn swap_dbname(url: &str, dbname: &str) -> String {
    let (main, query) = match url.split_once('?') {
        Some((m, q)) => (m, format!("?{q}")),
        None => (url, String::new()),
    };
    let prefix = main.rsplit_once('/').map(|(p, _)| p).unwrap_or(main);
    format!("{prefix}/{dbname}{query}")
}
