use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use digicash_core::{IdentityPublicKey, IDENTITY_PUBLIC_KEY_LEN};
use digicash_proto::{
    CapsResponse, MembersResponse, RegisterMemberRequest, SerialResponse, SerialSubmission,
    SetCapRequest, SettleResponse,
};
use serde::Serialize;

use crate::auth::{verify_signed_request, AuthenticatedBank};
use crate::error::RegistryError;
use crate::registry::{now_unix, Registry};

/// Build the registry's HTTP router (production-spec v1.4 section 10).
///
/// `GET /health` is public. Every other route is wrapped by [`verify_signed_request`], so it
/// is reached only after the request's Ed25519 signature, timestamp, and nonce are verified
/// against the caller's registered member key. Governance routes additionally require the
/// authenticated caller to be the admin.
pub fn router(registry: Arc<Registry>) -> Router {
    let protected = Router::new()
        .route("/members", post(register_member).get(list_members))
        .route("/serials", post(post_serial))
        .route("/caps", get(get_caps).post(set_cap))
        .route("/settle", post(post_settle))
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

async fn post_serial(
    State(registry): State<Arc<Registry>>,
    Extension(auth): Extension<AuthenticatedBank>,
    Json(req): Json<SerialSubmission>,
) -> Result<Json<SerialResponse>, ApiError> {
    let response = registry.submit_serial(&auth.0, &req, now_unix()).await?;
    Ok(Json(response))
}

async fn get_caps(
    State(registry): State<Arc<Registry>>,
    Extension(_auth): Extension<AuthenticatedBank>,
) -> Result<Json<CapsResponse>, ApiError> {
    Ok(Json(CapsResponse {
        caps: registry.list_caps().await?,
    }))
}

async fn set_cap(
    State(registry): State<Arc<Registry>>,
    Extension(auth): Extension<AuthenticatedBank>,
    Json(req): Json<SetCapRequest>,
) -> Result<StatusCode, ApiError> {
    ensure_admin(&registry, &auth).await?;
    registry
        .set_cap(&req.issuing_bank_id, &req.depositing_bank_id, req.cap_cents)
        .await?;
    Ok(StatusCode::OK)
}

async fn post_settle(
    State(registry): State<Arc<Registry>>,
    Extension(auth): Extension<AuthenticatedBank>,
) -> Result<Json<SettleResponse>, ApiError> {
    ensure_admin(&registry, &auth).await?;
    Ok(Json(SettleResponse {
        claims: registry.settle(now_unix()).await?,
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
        CapsResponse, MembersResponse, RegisterMemberRequest, SerialOutcome, SerialResponse,
        SerialSubmission, SetCapRequest, SettleResponse, HEADER_ACCOUNT, HEADER_NONCE,
        HEADER_SIGNATURE, HEADER_TIMESTAMP,
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
    async fn serial_accepted_replayed_and_cross_bank_double_spend() {
        let Some(db) = TestDatabase::create().await.expect("test db") else {
            eprintln!("skipping: set DATABASE_URL to a Postgres instance to run this test");
            return;
        };
        let registry = Registry::connect(db.url()).await.expect("registry");
        let bank_a = IdentityKeypair::generate().expect("a");
        let bank_b = IdentityKeypair::generate().expect("b");
        registry.register_member("bank-a", &bank_a.public_key(), false).await.expect("reg a");
        registry.register_member("bank-b", &bank_b.public_key(), false).await.expect("reg b");
        let app = router(Arc::new(registry));

        let body = |serial: &str, transcript: &str| {
            serde_json::to_vec(&SerialSubmission {
                issuing_bank_id: "bank-a".to_string(),
                denomination_cents: 64,
                scheme_id: 0,
                serial_hex: serial.to_string(),
                transcript: transcript.to_string(),
            })
            .expect("serialize")
        };

        // bank-b deposits serial aa (issued by bank-a): accepted, no transcripts returned.
        let resp = app
            .clone()
            .oneshot(signed(&bank_b, "bank-b", "POST", "/serials", &body("aa", "t-b1"), "n1"))
            .await
            .expect("submit");
        assert_eq!(resp.status(), StatusCode::OK);
        let accepted: SerialResponse = json_body(resp).await;
        assert_eq!(accepted.outcome, SerialOutcome::Accepted);
        assert!(accepted.transcripts.is_empty());

        // bank-b replays aa: double-spend, both of bank-b's transcripts retained.
        let resp = app
            .clone()
            .oneshot(signed(&bank_b, "bank-b", "POST", "/serials", &body("aa", "t-b2"), "n2"))
            .await
            .expect("replay");
        let replay: SerialResponse = json_body(resp).await;
        assert_eq!(replay.outcome, SerialOutcome::DoubleSpend);
        assert_eq!(replay.transcripts.len(), 2);

        // Fresh serial bb: bank-b accepts, then bank-a double-spends it across banks.
        let resp = app
            .clone()
            .oneshot(signed(&bank_b, "bank-b", "POST", "/serials", &body("bb", "t-b3"), "n3"))
            .await
            .expect("bb accept");
        assert_eq!(json_body::<SerialResponse>(resp).await.outcome, SerialOutcome::Accepted);
        let resp = app
            .oneshot(signed(&bank_a, "bank-a", "POST", "/serials", &body("bb", "t-a1"), "n4"))
            .await
            .expect("bb cross-bank");
        let cross: SerialResponse = json_body(resp).await;
        assert_eq!(cross.outcome, SerialOutcome::DoubleSpend);
        let banks: Vec<&str> = cross.transcripts.iter().map(|t| t.bank_id.as_str()).collect();
        assert!(
            banks.contains(&"bank-b") && banks.contains(&"bank-a"),
            "cross-bank collision must retain both banks' transcripts: {banks:?}"
        );
    }

    #[tokio::test]
    async fn exposure_cap_enforced_and_updatable() {
        let Some(db) = TestDatabase::create().await.expect("test db") else {
            eprintln!("skipping: set DATABASE_URL to a Postgres instance to run this test");
            return;
        };
        let registry = Registry::connect(db.url()).await.expect("registry");
        let admin = IdentityKeypair::generate().expect("admin");
        let bank_b = IdentityKeypair::generate().expect("b");
        registry.register_member("admin", &admin.public_key(), true).await.expect("admin");
        registry.register_member("bank-b", &bank_b.public_key(), false).await.expect("b");
        let app = router(Arc::new(registry));

        // Admin caps bank-b's receivable against bank-a at 100 cents.
        let cap_body = |cap: u64| {
            serde_json::to_vec(&SetCapRequest {
                issuing_bank_id: "bank-a".to_string(),
                depositing_bank_id: "bank-b".to_string(),
                cap_cents: cap,
            })
            .expect("serialize")
        };
        let resp = app
            .clone()
            .oneshot(signed(&admin, "admin", "POST", "/caps", &cap_body(100), "c1"))
            .await
            .expect("set cap");
        assert_eq!(resp.status(), StatusCode::OK);

        let submit = |serial: &str, nonce: &str| {
            let body = serde_json::to_vec(&SerialSubmission {
                issuing_bank_id: "bank-a".to_string(),
                denomination_cents: 64,
                scheme_id: 0,
                serial_hex: serial.to_string(),
                transcript: format!("t-{serial}"),
            })
            .expect("serialize");
            signed(&bank_b, "bank-b", "POST", "/serials", &body, nonce)
        };
        let outcome = |resp: SerialResponse| resp.outcome;

        // Two 64-cent deposits fit under the 100-cap (outstanding 0, then 64).
        assert_eq!(
            outcome(json_body(app.clone().oneshot(submit("s1", "n1")).await.expect("s1")).await),
            SerialOutcome::Accepted
        );
        assert_eq!(
            outcome(json_body(app.clone().oneshot(submit("s2", "n2")).await.expect("s2")).await),
            SerialOutcome::Accepted
        );
        // Outstanding is now 128 >= 100: the next deposit is capped.
        assert_eq!(
            outcome(json_body(app.clone().oneshot(submit("s3", "n3")).await.expect("s3")).await),
            SerialOutcome::ExposureCapExceeded
        );

        // Admin raises the cap to 500; the previously-capped serial now goes through.
        let resp = app
            .clone()
            .oneshot(signed(&admin, "admin", "POST", "/caps", &cap_body(500), "c2"))
            .await
            .expect("raise cap");
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            outcome(json_body(app.clone().oneshot(submit("s3", "n4")).await.expect("s3 again")).await),
            SerialOutcome::Accepted
        );

        // GET /caps publishes the updated cap.
        let resp = app
            .oneshot(signed(&admin, "admin", "GET", "/caps", b"", "n5"))
            .await
            .expect("get caps");
        let caps: CapsResponse = json_body(resp).await;
        let cap = caps
            .caps
            .iter()
            .find(|c| c.issuing_bank_id == "bank-a" && c.depositing_bank_id == "bank-b")
            .expect("cap present");
        assert_eq!(cap.cap_cents, 500);
    }

    #[tokio::test]
    async fn settlement_nets_receivables_and_is_idempotent() {
        let Some(db) = TestDatabase::create().await.expect("test db") else {
            eprintln!("skipping: set DATABASE_URL to a Postgres instance to run this test");
            return;
        };
        let registry = Registry::connect(db.url()).await.expect("registry");
        let admin = IdentityKeypair::generate().expect("admin");
        let bank_a = IdentityKeypair::generate().expect("a");
        let bank_b = IdentityKeypair::generate().expect("b");
        registry.register_member("admin", &admin.public_key(), true).await.expect("admin");
        registry.register_member("bank-a", &bank_a.public_key(), false).await.expect("a");
        registry.register_member("bank-b", &bank_b.public_key(), false).await.expect("b");
        let app = router(Arc::new(registry));

        let submit = |kp: &IdentityKeypair, bank: String, issuing: &str, serial: &str, nonce: &str| {
            let body = serde_json::to_vec(&SerialSubmission {
                issuing_bank_id: issuing.to_string(),
                denomination_cents: 64,
                scheme_id: 0,
                serial_hex: serial.to_string(),
                transcript: format!("t-{serial}"),
            })
            .expect("serialize");
            signed(kp, &bank, "POST", "/serials", &body, nonce)
        };

        // bank-b deposits two of bank-a's coins (128); bank-a deposits one of bank-b's (64).
        for (kp, bank, issuing, serial, nonce) in [
            (&bank_b, "bank-b", "bank-a", "s1", "n1"),
            (&bank_b, "bank-b", "bank-a", "s2", "n2"),
            (&bank_a, "bank-a", "bank-b", "s3", "n3"),
        ] {
            let resp = app
                .clone()
                .oneshot(submit(kp, bank.to_string(), issuing, serial, nonce))
                .await
                .expect("submit");
            let r: SerialResponse = json_body(resp).await;
            assert_eq!(r.outcome, SerialOutcome::Accepted, "{serial} not accepted");
        }

        // Settle: net = 128 - 64 = 64, bank-a owes bank-b.
        let resp = app
            .clone()
            .oneshot(signed(&admin, "admin", "POST", "/settle", b"", "n4"))
            .await
            .expect("settle");
        assert_eq!(resp.status(), StatusCode::OK);
        let settled: SettleResponse = json_body(resp).await;
        assert_eq!(settled.claims.len(), 1);
        let claim = &settled.claims[0];
        assert_eq!(claim.issuing_bank_id, "bank-a");
        assert_eq!(claim.depositing_bank_id, "bank-b");
        assert_eq!(claim.net_amount_cents, 64);

        // A second settle in the same window nets nothing: idempotent.
        let resp = app
            .oneshot(signed(&admin, "admin", "POST", "/settle", b"", "n5"))
            .await
            .expect("settle again");
        let again: SettleResponse = json_body(resp).await;
        assert!(again.claims.is_empty(), "re-settle must produce no claims: {again:?}");
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
