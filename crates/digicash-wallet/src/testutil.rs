use std::net::TcpListener;
use std::sync::Arc;

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
/// authentication) on two ephemeral ports, backed by a fresh temp directory. Listeners are
/// bound before the server thread starts, so connections queue in the backlog.
pub(crate) fn spawn_armed_bank(denominations: &'static [u64]) -> ArmedBank {
    let tmp = TempDir::new().expect("tempdir");
    let bank = Arc::new(
        Bank::open(
            tmp.path().join("bankdb"),
            tmp.path().join("bankkeys"),
            denominations,
        )
        .expect("bank open"),
    );
    let ca = Arc::new(CertAuthority::load_or_create(&tmp.path().join("cakeys")).expect("ca"));
    let ca_cert_pem = ca.ca_cert_pem();
    let api_config = ca.server_config().expect("api config");
    let enroll_config = ca.enrollment_server_config().expect("enroll config");
    let api_app = authenticated_router(bank.clone(), ca.clone());
    let enroll_app = enrollment_router(bank, ca);

    let (api_listener, api_url) = bound_listener();
    let (enroll_listener, enroll_url) = bound_listener();

    std::thread::spawn(move || {
        let runtime = tokio::runtime::Runtime::new().expect("runtime");
        runtime.block_on(async move {
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

    ArmedBank {
        api_url,
        enroll_url,
        ca_cert_pem,
        _tmp: tmp,
    }
}

fn bound_listener() -> (TcpListener, String) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.set_nonblocking(true).expect("nonblocking");
    let url = format!("https://{}", listener.local_addr().expect("addr"));
    (listener, url)
}
