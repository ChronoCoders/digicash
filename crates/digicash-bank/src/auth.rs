use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::{to_bytes, Body};
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use digicash_core::{canonical_payload, IDENTITY_SIGNATURE_LEN};
use digicash_proto::{AuthHeaderError, AuthHeaders, ErrorResponse};

use crate::bank::Bank;
use crate::error::BankError;

/// Largest request body the signing middleware will buffer to hash, 1 MiB. digicash requests
/// are small; anything larger is rejected rather than read into memory.
const MAX_BODY_BYTES: usize = 1 << 20;
/// Reject a request whose timestamp is more than this many seconds from the bank's clock, in
/// either direction (spec v1.2 section 2: older than 60s; the future bound is symmetric
/// defense against a skewed or lying client clock).
const MAX_TIMESTAMP_SKEW_SECS: u64 = 60;
/// A nonce is remembered for this long; a repeat within the window is a replay.
const NONCE_TTL_SECS: u64 = 120;

/// The account whose registered Ed25519 key verified a request, inserted into the request
/// extensions by [`verify_signed_request`]. Handlers compare it to the request's target
/// account and reject a mismatch, so a caller cannot act on an account it does not hold the
/// key for.
#[derive(Debug, Clone)]
pub struct AuthenticatedAccount(pub String);

/// Axum middleware enforcing production-spec v1.2 section 2 on every request it wraps: parse
/// the authentication headers, look up the claimed account's registered Ed25519 key, reject a
/// stale timestamp, verify the signature over the canonical payload, and reject a replayed
/// nonce - all before the handler runs. On success the authenticated account is recorded in
/// the request extensions.
pub async fn verify_signed_request(
    State(bank): State<Arc<Bank>>,
    request: Request,
    next: Next,
) -> Response {
    match authenticate(&bank, request).await {
        Ok(request) => next.run(request).await,
        Err(rejection) => rejection.into_response(),
    }
}

async fn authenticate(bank: &Bank, request: Request) -> Result<Request, AuthRejection> {
    let (parts, body) = request.into_parts();
    let bytes = to_bytes(body, MAX_BODY_BYTES)
        .await
        .map_err(|_| AuthRejection::bad_request("request body too large or unreadable"))?;

    let auth = AuthHeaders::from_lookup(|name| {
        parts
            .headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string)
    })
    .map_err(AuthRejection::headers)?;

    let pubkey = bank
        .identity_pubkey(&auth.account_id)
        .await
        .map_err(AuthRejection::internal)?
        .ok_or_else(|| AuthRejection::unauthorized("account has no registered signing key"))?;

    let now = now_unix();
    if auth.timestamp.saturating_add(MAX_TIMESTAMP_SKEW_SECS) < now
        || auth.timestamp > now.saturating_add(MAX_TIMESTAMP_SKEW_SECS)
    {
        return Err(AuthRejection::unauthorized(
            "request timestamp outside the accepted window",
        ));
    }

    let signature = decode_signature(&auth.signature)?;
    let payload = canonical_payload(
        parts.method.as_str(),
        parts.uri.path(),
        &bytes,
        auth.timestamp,
        &auth.nonce,
    );
    pubkey
        .verify(payload.as_bytes(), &signature)
        .map_err(|_| AuthRejection::unauthorized("signature verification failed"))?;

    // Only record the nonce for an otherwise-valid request, so bad-signature traffic cannot
    // fill the nonce store, and a replay of a valid request is caught here.
    let fresh = bank
        .check_and_record_nonce(&auth.nonce, now, NONCE_TTL_SECS)
        .map_err(AuthRejection::internal)?;
    if !fresh {
        return Err(AuthRejection::unauthorized("nonce already used (replay)"));
    }

    let mut request = Request::from_parts(parts, Body::from(bytes));
    request
        .extensions_mut()
        .insert(AuthenticatedAccount(auth.account_id));
    Ok(request)
}

fn decode_signature(hex_signature: &str) -> Result<[u8; IDENTITY_SIGNATURE_LEN], AuthRejection> {
    let bytes = hex::decode(hex_signature)
        .map_err(|_| AuthRejection::unauthorized("signature is not valid hex"))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| AuthRejection::unauthorized("signature is not 64 bytes"))
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A rejected request, rendered as an HTTP error with a typed body. Missing or malformed
/// headers are `400`; every authentication failure is `401`.
struct AuthRejection {
    status: StatusCode,
    message: String,
}

impl AuthRejection {
    fn unauthorized(message: &str) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: message.to_string(),
        }
    }

    fn bad_request(message: &str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.to_string(),
        }
    }

    fn headers(error: AuthHeaderError) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: error.to_string(),
        }
    }

    fn internal(error: BankError) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: error.to_string(),
        }
    }
}

impl IntoResponse for AuthRejection {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorResponse {
                error: self.message,
            }),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::{verify_signed_request, AuthenticatedAccount, NONCE_TTL_SECS};
    use crate::bank::Bank;
    use crate::test_support::TestDatabase;
    use axum::body::{to_bytes, Body};
    use axum::http::{Request, StatusCode};
    use axum::response::Response;
    use axum::routing::post;
    use axum::{Extension, Router};
    use digicash_core::{canonical_payload, IdentityKeypair};
    use digicash_proto::{HEADER_ACCOUNT, HEADER_NONCE, HEADER_SIGNATURE, HEADER_TIMESTAMP};
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tempfile::TempDir;
    use tower::ServiceExt;

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_secs()
    }

    fn app(bank: Arc<Bank>) -> Router {
        Router::new()
            .route("/echo", post(echo))
            .layer(axum::middleware::from_fn_with_state(bank, verify_signed_request))
    }

    async fn echo(Extension(account): Extension<AuthenticatedAccount>) -> String {
        account.0
    }

    /// Build a POST /echo request signed by `kp` under `account`, with the given timestamp and
    /// nonce. `mangle_signature` flips a bit of the signature to force a bad-signature case.
    fn signed_request(
        kp: &IdentityKeypair,
        account: &str,
        body: &[u8],
        timestamp: u64,
        nonce: &str,
        mangle_signature: bool,
    ) -> Request<Body> {
        let payload = canonical_payload("POST", "/echo", body, timestamp, nonce);
        let mut signature = kp.sign(payload.as_bytes());
        if mangle_signature {
            signature[0] ^= 0x01;
        }
        Request::builder()
            .method("POST")
            .uri("/echo")
            .header("content-type", "application/json")
            .header(HEADER_ACCOUNT, account)
            .header(HEADER_TIMESTAMP, timestamp.to_string())
            .header(HEADER_NONCE, nonce)
            .header(HEADER_SIGNATURE, hex::encode(signature))
            .body(Body::from(body.to_vec()))
            .expect("request")
    }

    async fn open_bank(tmp: &TempDir) -> Option<(Arc<Bank>, IdentityKeypair)> {
        let db = TestDatabase::create().await.expect("test db")?;
        let bank = Bank::connect(db.url(), tmp.path().join("keys"), &[64])
            .await
            .expect("bank connect");
        let kp = IdentityKeypair::generate().expect("keypair");
        bank.register_identity("alice", &kp.public_key())
            .await
            .expect("register");
        Some((Arc::new(bank), kp))
    }

    macro_rules! bank_or_skip {
        ($tmp:expr) => {
            match open_bank($tmp).await {
                Some(pair) => pair,
                None => {
                    eprintln!("skipping: set DATABASE_URL to a Postgres instance to run this test");
                    return;
                }
            }
        };
    }

    async fn body_text(resp: Response) -> String {
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.expect("body");
        String::from_utf8(bytes.to_vec()).expect("utf8")
    }

    #[tokio::test]
    async fn valid_signed_request_is_accepted() {
        let tmp = TempDir::new().expect("tempdir");
        let (bank, kp) = bank_or_skip!(&tmp);
        let req = signed_request(&kp, "alice", b"{}", now(), "nonce-ok", false);
        let resp = app(bank).oneshot(req).await.expect("send");
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_text(resp).await, "alice", "authenticated account not surfaced");
    }

    #[tokio::test]
    async fn missing_signature_header_is_rejected() {
        let tmp = TempDir::new().expect("tempdir");
        let (bank, _kp) = bank_or_skip!(&tmp);
        let req = Request::builder()
            .method("POST")
            .uri("/echo")
            .header(HEADER_ACCOUNT, "alice")
            .header(HEADER_TIMESTAMP, now().to_string())
            .header(HEADER_NONCE, "n")
            .body(Body::from("{}"))
            .expect("request");
        let resp = app(bank).oneshot(req).await.expect("send");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn bad_signature_is_rejected() {
        let tmp = TempDir::new().expect("tempdir");
        let (bank, kp) = bank_or_skip!(&tmp);
        let req = signed_request(&kp, "alice", b"{}", now(), "nonce-bad", true);
        let resp = app(bank).oneshot(req).await.expect("send");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn stale_timestamp_is_rejected() {
        let tmp = TempDir::new().expect("tempdir");
        let (bank, kp) = bank_or_skip!(&tmp);
        let stale = now() - (NONCE_TTL_SECS + 10);
        let req = signed_request(&kp, "alice", b"{}", stale, "nonce-stale", false);
        let resp = app(bank).oneshot(req).await.expect("send");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn replayed_nonce_is_rejected() {
        let tmp = TempDir::new().expect("tempdir");
        let (bank, kp) = bank_or_skip!(&tmp);
        let ts = now();
        let first = signed_request(&kp, "alice", b"{}", ts, "nonce-replay", false);
        let resp = app(bank.clone()).oneshot(first).await.expect("first");
        assert_eq!(resp.status(), StatusCode::OK);
        // Same nonce again (re-sign identically): the nonce store must reject it.
        let replay = signed_request(&kp, "alice", b"{}", ts, "nonce-replay", false);
        let resp = app(bank).oneshot(replay).await.expect("replay");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn unregistered_account_is_rejected() {
        let tmp = TempDir::new().expect("tempdir");
        let (bank, kp) = bank_or_skip!(&tmp);
        // Sign under an account the bank has no key for.
        let req = signed_request(&kp, "stranger", b"{}", now(), "nonce-x", false);
        let resp = app(bank).oneshot(req).await.expect("send");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
