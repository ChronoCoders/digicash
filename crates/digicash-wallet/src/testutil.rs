use std::net::TcpListener;
use std::sync::Arc;

use tempfile::TempDir;

/// Spawn a bank server on an ephemeral port, backed by a fresh temp directory, and return
/// its base URL along with the `TempDir` (keep it alive for the server's lifetime).
///
/// The listener is bound before the server thread starts, so connections queue in the
/// backlog and clients need not wait for readiness.
pub(crate) fn spawn_test_bank(denominations: &'static [u64]) -> (String, TempDir) {
    let tmp = TempDir::new().expect("tempdir");
    let bank = digicash_bank::Bank::open(
        tmp.path().join("bankdb"),
        tmp.path().join("bankkeys"),
        denominations,
    )
    .expect("bank open");

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.set_nonblocking(true).expect("nonblocking");
    let url = format!("http://{}", listener.local_addr().expect("addr"));

    std::thread::spawn(move || {
        let runtime = tokio::runtime::Runtime::new().expect("runtime");
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(listener).expect("from_std");
            axum::serve(listener, digicash_bank::router(Arc::new(bank)))
                .await
                .expect("serve");
        });
    });

    (url, tmp)
}
