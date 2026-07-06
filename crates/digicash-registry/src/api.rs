use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use digicash_core::{IdentityPublicKey, IDENTITY_PUBLIC_KEY_LEN};
use digicash_proto::{MembersResponse, RegisterMemberRequest};
use serde::Serialize;

use crate::auth::{verify_signed_request, AuthenticatedBank};
use crate::error::RegistryError;
use crate::registry::Registry;

/// Build the registry's HTTP router (production-spec v1.4 section 10).
///
/// `GET /health` is public. Every other route is wrapped by [`verify_signed_request`], so it
/// is reached only after the request's Ed25519 signature, timestamp, and nonce are verified
/// against the caller's registered member key. Governance routes additionally require the
/// authenticated caller to be the admin.
pub fn router(registry: Arc<Registry>) -> Router {
    let protected = Router::new()
        .route("/members", post(register_member).get(list_members))
        .route_layer(axum::middleware::from_fn_with_state(
            registry.clone(),
            verify_signed_request,
        ));
    let public = Router::new().route("/health", get(health));
    protected.merge(public).with_state(registry)
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
}

async fn health(State(registry): State<Arc<Registry>>) -> Result<Json<HealthResponse>, ApiError> {
    registry.ping().await?;
    Ok(Json(HealthResponse { status: "ok" }))
}

async fn register_member(
    State(registry): State<Arc<Registry>>,
    Extension(auth): Extension<AuthenticatedBank>,
    Json(req): Json<RegisterMemberRequest>,
) -> Result<StatusCode, ApiError> {
    ensure_admin(&registry, &auth).await?;
    let pubkey = parse_pubkey(&req.pubkey_hex)?;
    registry.register_member(&req.bank_id, &pubkey, false).await?;
    Ok(StatusCode::OK)
}

async fn list_members(
    State(registry): State<Arc<Registry>>,
    Extension(_auth): Extension<AuthenticatedBank>,
) -> Result<Json<MembersResponse>, ApiError> {
    Ok(Json(MembersResponse {
        members: registry.list_members().await?,
    }))
}

/// Reject a request whose authenticated caller is not the governance admin.
async fn ensure_admin(registry: &Registry, auth: &AuthenticatedBank) -> Result<(), ApiError> {
    if registry.is_admin(&auth.0).await? {
        Ok(())
    } else {
        Err(ApiError {
            status: StatusCode::FORBIDDEN,
            message: format!("{} is not the registry admin", auth.0),
        })
    }
}

fn parse_pubkey(pubkey_hex: &str) -> Result<IdentityPublicKey, ApiError> {
    let raw = hex::decode(pubkey_hex).map_err(|_| ApiError {
        status: StatusCode::BAD_REQUEST,
        message: "pubkey_hex is not valid hex".to_string(),
    })?;
    let bytes: [u8; IDENTITY_PUBLIC_KEY_LEN] = raw.as_slice().try_into().map_err(|_| ApiError {
        status: StatusCode::BAD_REQUEST,
        message: "pubkey must be 32 bytes".to_string(),
    })?;
    IdentityPublicKey::from_bytes(&bytes).map_err(|e| ApiError {
        status: StatusCode::BAD_REQUEST,
        message: e.to_string(),
    })
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
        let status = match &error {
            RegistryError::MemberExists(_) => StatusCode::CONFLICT,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        Self {
            status,
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
    use axum::response::Response;
    use digicash_core::{canonical_payload, IdentityKeypair};
    use digicash_proto::{
        MembersResponse, RegisterMemberRequest, HEADER_ACCOUNT, HEADER_NONCE, HEADER_SIGNATURE,
        HEADER_TIMESTAMP,
    };
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tower::ServiceExt;

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_secs()
    }

    /// A signed request for `bank_id` using `kp`, with a unique nonce.
    fn signed(
        kp: &IdentityKeypair,
        bank_id: &str,
        method: &str,
        path: &str,
        body: &[u8],
        nonce: &str,
    ) -> Request<Body> {
        let ts = now();
        let payload = canonical_payload(method, path, body, ts, nonce);
        let signature = hex::encode(kp.sign(payload.as_bytes()));
        Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json")
            .header(HEADER_ACCOUNT, bank_id)
            .header(HEADER_TIMESTAMP, ts.to_string())
            .header(HEADER_NONCE, nonce)
            .header(HEADER_SIGNATURE, signature)
            .body(Body::from(body.to_vec()))
            .expect("request")
    }

    async fn json_body<T: serde::de::DeserializeOwned>(resp: Response) -> T {
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.expect("body");
        serde_json::from_slice(&bytes).expect("json")
    }

    #[tokio::test]
    async fn register_two_banks_and_list_members() {
        let Some(db) = TestDatabase::create().await.expect("test db") else {
            eprintln!("skipping: set DATABASE_URL to a Postgres instance to run this test");
            return;
        };
        let registry = Registry::connect(db.url()).await.expect("registry");
        // Bootstrap the admin directly (governance seed).
        let admin = IdentityKeypair::generate().expect("admin key");
        registry
            .register_member("admin", &admin.public_key(), true)
            .await
            .expect("seed admin");
        let app = router(Arc::new(registry));

        for (bank_id, nonce) in [("bank-a", "n1"), ("bank-b", "n2")] {
            let body = serde_json::to_vec(&RegisterMemberRequest {
                bank_id: bank_id.to_string(),
                pubkey_hex: hex::encode(IdentityKeypair::generate().expect("k").public_key().to_bytes()),
            })
            .expect("serialize");
            let resp = app
                .clone()
                .oneshot(signed(&admin, "admin", "POST", "/members", &body, nonce))
                .await
                .expect("register");
            assert_eq!(resp.status(), StatusCode::OK, "registering {bank_id} failed");
        }

        let resp = app
            .oneshot(signed(&admin, "admin", "GET", "/members", b"", "n3"))
            .await
            .expect("list");
        assert_eq!(resp.status(), StatusCode::OK);
        let members: MembersResponse = json_body(resp).await;
        let ids: Vec<&str> = members.members.iter().map(|m| m.bank_id.as_str()).collect();
        assert_eq!(ids, vec!["admin", "bank-a", "bank-b"]);
        assert!(members.members.iter().find(|m| m.bank_id == "admin").expect("admin").is_admin);
    }

    #[tokio::test]
    async fn non_admin_cannot_register_members() {
        let Some(db) = TestDatabase::create().await.expect("test db") else {
            eprintln!("skipping: set DATABASE_URL to a Postgres instance to run this test");
            return;
        };
        let registry = Registry::connect(db.url()).await.expect("registry");
        let admin = IdentityKeypair::generate().expect("admin");
        let member = IdentityKeypair::generate().expect("member");
        registry.register_member("admin", &admin.public_key(), true).await.expect("admin");
        registry.register_member("bank-a", &member.public_key(), false).await.expect("member");
        let app = router(Arc::new(registry));

        let body = serde_json::to_vec(&RegisterMemberRequest {
            bank_id: "bank-c".to_string(),
            pubkey_hex: hex::encode(IdentityKeypair::generate().expect("k").public_key().to_bytes()),
        })
        .expect("serialize");
        // bank-a is a member but not admin: forbidden.
        let resp = app
            .oneshot(signed(&member, "bank-a", "POST", "/members", &body, "n1"))
            .await
            .expect("send");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn migrations_apply_and_health_responds() {
        let Some(db) = TestDatabase::create().await.expect("test db") else {
            eprintln!("skipping: set DATABASE_URL to a Postgres instance to run this test");
            return;
        };
        let pool = db.pool().expect("pool");
        let client = pool.get().await.expect("connection");
        let rows = client
            .query("SELECT tablename FROM pg_tables WHERE schemaname = 'public'", &[])
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

        let registry = Arc::new(Registry::connect(db.url()).await.expect("registry"));
        let resp = router(registry)
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/health")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("send");
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.expect("body");
        assert!(String::from_utf8_lossy(&bytes).contains("ok"));
    }
}
