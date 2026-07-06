//! The digicash registry server binary: open the registry state and serve the API over mTLS
//! with the bank's self-signed CA model (production-spec v1.4 section 10).

use std::net::TcpListener;
use std::path::Path;
use std::sync::Arc;

use digicash_bank::{serve_tls, CertAuthority};
use digicash_core::{IdentityPublicKey, IDENTITY_PUBLIC_KEY_LEN};
use digicash_registry::{router, Registry, RegistryError};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let database_url = std::env::var("DATABASE_URL")
        .map_err(|_| "DATABASE_URL must be set to the registry's Postgres connection string")?;
    let key_dir = std::env::var("DIGICASH_REGISTRY_KEYS")
        .unwrap_or_else(|_| "digicash-registry-keys".to_string());
    let addr =
        std::env::var("DIGICASH_REGISTRY_ADDR").unwrap_or_else(|_| "127.0.0.1:4000".to_string());

    let registry = Arc::new(Registry::connect(&database_url).await?);
    // Seed the governance admin from its published Ed25519 key, if configured. Idempotent
    // across restarts.
    if let Ok(admin_pubkey_hex) = std::env::var("DIGICASH_REGISTRY_ADMIN_PUBKEY") {
        let raw = hex::decode(admin_pubkey_hex.trim())?;
        let bytes: [u8; IDENTITY_PUBLIC_KEY_LEN] = raw
            .as_slice()
            .try_into()
            .map_err(|_| "DIGICASH_REGISTRY_ADMIN_PUBKEY must be a 32-byte hex key")?;
        let pubkey = IdentityPublicKey::from_bytes(&bytes)?;
        match registry.register_member("admin", &pubkey, true).await {
            Ok(()) => tracing::info!("registered governance admin"),
            Err(RegistryError::MemberExists(_)) => {}
            Err(e) => return Err(e.into()),
        }
    }
    let ca = CertAuthority::load_or_create(Path::new(&key_dir))?;
    let server_config = ca.server_config()?;
    let app = router(registry);

    let listener = TcpListener::bind(&addr)?;
    listener.set_nonblocking(true)?;
    tracing::info!(%addr, "digicash registry listening (mTLS)");
    serve_tls(listener, app, server_config).await?;
    Ok(())
}
