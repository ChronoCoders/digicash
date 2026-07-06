//! Isolated Postgres test databases for the registry. Available in this crate's own tests
//! and, via the `test-support` feature, to downstream dev-dependencies (digicash-e2e).

use std::sync::atomic::{AtomicU64, Ordering};

use deadpool_postgres::Pool;
use tokio_postgres::NoTls;

use crate::db;
use crate::error::RegistryError;

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// The base `DATABASE_URL` for the test Postgres, or `None` if unset.
pub fn base_url() -> Option<String> {
    std::env::var("DATABASE_URL").ok().filter(|u| !u.is_empty())
}

/// A freshly-created, migrated Postgres database dedicated to one test.
pub struct TestDatabase {
    url: String,
}

impl TestDatabase {
    /// Create a uniquely-named database off the base `DATABASE_URL`, run the registry
    /// migrations on it, and return a handle. `Ok(None)` when `DATABASE_URL` is unset.
    pub async fn create() -> Result<Option<TestDatabase>, RegistryError> {
        let Some(base) = base_url() else {
            return Ok(None);
        };
        let name = format!(
            "digicash_registry_test_{}_{}",
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
    pub fn pool(&self) -> Result<Pool, RegistryError> {
        db::create_pool(&self.url)
    }
}

async fn create_database(base_url: &str, name: &str) -> Result<(), RegistryError> {
    let (client, connection) = tokio_postgres::connect(base_url, NoTls).await?;
    let driver = tokio::spawn(connection);
    // `name` is generated internally (never user input); identifiers cannot be bound.
    let result = client
        .batch_execute(&format!("CREATE DATABASE \"{name}\""))
        .await;
    drop(client);
    let _ = driver.await;
    result?;
    Ok(())
}

fn swap_dbname(url: &str, dbname: &str) -> String {
    let (main, query) = match url.split_once('?') {
        Some((m, q)) => (m, format!("?{q}")),
        None => (url, String::new()),
    };
    let prefix = main.rsplit_once('/').map(|(p, _)| p).unwrap_or(main);
    format!("{prefix}/{dbname}{query}")
}
