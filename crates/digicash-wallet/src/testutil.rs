use std::net::TcpListener;
use std::sync::Arc;

use digicash_bank::test_support::TestDatabase;
use digicash_bank::{authenticated_router, enrollment_router, serve_tls, Bank, CertAuthority};
use tempfile::TempDir;

/// A spawned armed bank: the mTLS value URL, the server-TLS enrollment URL, and the CA
/// certificate PEM (to provision a wallet). Keep the returned `TempDir` alive for the
/// server's lifetime.
pub(crate) struct ArmedBank {
    pub api_url: String,
    pub enroll_url: String,
    pub ca_cert_pem: String,
    pub _tmp: TempDir,
}

/// Spawn a fully-armed bank (mTLS value endpoints + server-TLS enrollment + Ed25519 request
/// authentication) backed by a fresh Postgres test database, on two ephemeral ports.
/// `None` if `DATABASE_URL` is unset, so the caller can skip.
pub(crate) fn spawn_armed_bank(denominations: &'static [u64]) -> Option<ArmedBank> {
    // Create the isolated test database (and run migrations) in a short-lived runtime.
    let database_url = {
        let runtime = tokio::runtime::Runtime::new().expect("runtime");
        runtime.block_on(async {
            TestDatabase::create()
                .await
                .expect("create test database")
                .map(|db| db.url().to_string())
        })?
    };

    let tmp = TempDir::new().expect("tempdir");
    let ca = Arc::new(CertAuthority::load_or_create(&tmp.path().join("cakeys")).expect("ca"));
    let ca_cert_pem = ca.ca_cert_pem();
    let api_config = ca.server_config().expect("api config");
    let enroll_config = ca.enrollment_server_config().expect("enroll config");
    let (api_listener, api_url) = bound_listener();
    let (enroll_listener, enroll_url) = bound_listener();
    let key_dir = tmp.path().join("keys");

    // Build the bank and serve inside the server thread's runtime, so its Postgres pool lives
    // for the server's lifetime.
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Runtime::new().expect("runtime");
        runtime.block_on(async move {
            let bank = Arc::new(
                Bank::connect(&database_url, &key_dir, denominations)
                    .await
                    .expect("bank connect"),
            );
            let api_app = authenticated_router(bank.clone(), ca.clone());
            let enroll_app = enrollment_router(bank, ca);
            tokio::join!(
                async {
                    serve_tls(api_listener, api_app, api_config)
                        .await
                        .expect("api serve");
                },
                async {
                    serve_tls(enroll_listener, enroll_app, enroll_config)
                        .await
                        .expect("enroll serve");
                },
            );
        });
    });

    Some(ArmedBank {
        api_url,
        enroll_url,
        ca_cert_pem,
        _tmp: tmp,
    })
}

fn bound_listener() -> (TcpListener, String) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.set_nonblocking(true).expect("nonblocking");
    let url = format!("https://{}", listener.local_addr().expect("addr"));
    (listener, url)
}
