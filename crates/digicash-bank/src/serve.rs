use std::net::TcpListener;
use std::sync::Arc;

use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use rustls::ServerConfig;

/// Serve `app` over mutual TLS on an already-bound TCP listener until the process is
/// terminated. The listener is passed in already bound so a caller can accept the socket
/// (queueing connections in the backlog) before the async server task starts.
pub async fn serve_tls(
    listener: TcpListener,
    app: Router,
    tls_config: Arc<ServerConfig>,
) -> std::io::Result<()> {
    axum_server::from_tcp_rustls(listener, RustlsConfig::from_config(tls_config))
        .serve(app.into_make_service())
        .await
}
