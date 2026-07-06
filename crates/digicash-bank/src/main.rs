//! The digicash bank server binary: open the bank state and serve the authenticated API.
//!
//! Two TLS listeners (production-spec v1.2 section 2): the value endpoints on `DIGICASH_ADDR`
//! require mutual TLS and Ed25519-signed requests; enrollment (`POST /register`) on
//! `DIGICASH_ENROLL_ADDR` runs over server-authenticated TLS so a wallet can obtain its client
//! certificate before it has one. The self-signed CA is generated on first run and its
//! certificate is written to the key directory (`ca-cert.pem`) for out-of-band distribution.

use std::net::TcpListener;
use std::path::Path;
use std::sync::Arc;

use digicash_bank::{
    authenticated_router, enrollment_router, serve_tls, Bank, CertAuthority, DENOMINATIONS,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let db_path = std::env::var("DIGICASH_DB").unwrap_or_else(|_| "digicash-db".to_string());
    let key_dir = std::env::var("DIGICASH_KEYS").unwrap_or_else(|_| "digicash-keys".to_string());
    let api_addr = std::env::var("DIGICASH_ADDR").unwrap_or_else(|_| "127.0.0.1:3000".to_string());
    let enroll_addr =
        std::env::var("DIGICASH_ENROLL_ADDR").unwrap_or_else(|_| "127.0.0.1:3001".to_string());

    let bank = Arc::new(Bank::open(&db_path, &key_dir, &DENOMINATIONS)?);
    let ca = Arc::new(CertAuthority::load_or_create(Path::new(&key_dir))?);

    let api_config = ca.server_config()?;
    let enroll_config = ca.enrollment_server_config()?;
    let api_app = authenticated_router(bank.clone(), ca.clone());
    let enroll_app = enrollment_router(bank, ca);

    let api_listener = bound(&api_addr)?;
    let enroll_listener = bound(&enroll_addr)?;
    tracing::info!(%api_addr, %enroll_addr, "digicash bank listening (mTLS value + enrollment)");

    tokio::try_join!(
        serve_tls(api_listener, api_app, api_config),
        serve_tls(enroll_listener, enroll_app, enroll_config),
    )?;
    Ok(())
}

fn bound(addr: &str) -> std::io::Result<TcpListener> {
    let listener = TcpListener::bind(addr)?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}
