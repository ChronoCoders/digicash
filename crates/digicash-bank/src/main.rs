//! The digicash bank server binary: open the bank state and serve the HTTP API.

use std::sync::Arc;

use digicash_bank::{router, Bank, DENOMINATIONS};

/// Run the demo bank server. Configuration comes from the environment:
/// `DIGICASH_DB` (sled path), `DIGICASH_KEYS` (key directory), `DIGICASH_ADDR` (bind
/// address). No authentication or TLS: for local/trusted-network use only.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let db_path = std::env::var("DIGICASH_DB").unwrap_or_else(|_| "digicash-db".to_string());
    let key_dir = std::env::var("DIGICASH_KEYS").unwrap_or_else(|_| "digicash-keys".to_string());
    let addr = std::env::var("DIGICASH_ADDR").unwrap_or_else(|_| "127.0.0.1:3000".to_string());

    let bank = Bank::open(&db_path, &key_dir, &DENOMINATIONS)?;
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!(%addr, "digicash bank listening");
    axum::serve(listener, router(Arc::new(bank))).await?;
    Ok(())
}
