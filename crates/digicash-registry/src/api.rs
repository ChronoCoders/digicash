use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

use crate::error::RegistryError;
use crate::registry::Registry;

/// Build the registry's HTTP router over shared registry state.
pub fn router(registry: Arc<Registry>) -> Router {
    Router::new()
        .route("/health", get(health))
        .with_state(registry)
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
}

async fn health(State(registry): State<Arc<Registry>>) -> Result<Json<HealthResponse>, ApiError> {
    registry.ping().await?;
    Ok(Json(HealthResponse { status: "ok" }))
}

/// An error response with an HTTP status.
struct ApiError {
    status: StatusCode,
    message: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(ErrorBody { error: self.message })).into_response()
    }
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

impl From<RegistryError> for ApiError {
    fn from(error: RegistryError) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: error.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::router;
    use crate::registry::Registry;
    use crate::test_support::TestDatabase;
    use axum::body::{to_bytes, Body};
    use axum::http::{Request, StatusCode};
    use std::sync::Arc;
    use tower::ServiceExt;

    #[tokio::test]
    async fn migrations_apply_and_health_responds() {
        let Some(db) = TestDatabase::create().await.expect("test db") else {
            eprintln!("skipping: set DATABASE_URL to a Postgres instance to run this test");
            return;
        };
        // Migrations created the expected tables.
        let pool = db.pool().expect("pool");
        let client = pool.get().await.expect("connection");
        let rows = client
            .query(
                "SELECT tablename FROM pg_tables WHERE schemaname = 'public'",
                &[],
            )
            .await
            .expect("query tables");
        let tables: Vec<String> = rows.iter().map(|r| r.get::<_, String>("tablename")).collect();
        for expected in [
            "members",
            "serials",
            "transcripts",
            "exposure_caps",
            "receivables",
            "settlement_claims",
            "nonce_store",
        ] {
            assert!(tables.iter().any(|t| t == expected), "missing table {expected}");
        }

        // The health endpoint responds over the router.
        let registry = Arc::new(Registry::connect(db.url()).await.expect("registry"));
        let app = router(registry);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/health")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("send");
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), usize::MAX).await.expect("body");
        assert!(String::from_utf8_lossy(&bytes).contains("ok"));
    }
}
