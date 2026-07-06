use std::sync::Arc;

use axum::extract::{FromRef, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use digicash_core::IdentityPublicKey;
use digicash_proto::{
    BalanceResponse, CreateAccountRequest, DenominationsResponse, DepositRequest, DepositResponse,
    ErrorResponse, RegisterRequest, RegisterResponse, WithdrawRequest, WithdrawResponse,
};

use crate::auth::{verify_signed_request, AuthenticatedAccount};
use crate::bank::Bank;
use crate::error::BankError;
use crate::tls::CertAuthority;

/// Build the bank's plaintext, unauthenticated HTTP router (local development only).
pub fn router(bank: Arc<Bank>) -> Router {
    Router::new()
        .route("/accounts", post(create_account))
        .route("/accounts/{id}/balance", get(get_balance))
        .route("/denominations", get(denominations))
        .route("/withdraw", post(withdraw))
        .route("/deposit", post(deposit))
        .with_state(bank)
}

/// Shared state for the authenticated router: the ledger plus the certificate authority that
/// issues client certificates at registration.
#[derive(Clone)]
struct AppState {
    bank: Arc<Bank>,
    ca: Arc<CertAuthority>,
}

impl FromRef<AppState> for Arc<Bank> {
    fn from_ref(state: &AppState) -> Self {
        state.bank.clone()
    }
}

impl FromRef<AppState> for Arc<CertAuthority> {
    fn from_ref(state: &AppState) -> Self {
        state.ca.clone()
    }
}

/// Build the mTLS value router served on the main port (production-spec v1.2 section 2).
///
/// Every value-bearing route is wrapped by [`verify_signed_request`], so it is reached only
/// after the request's Ed25519 signature, timestamp, and nonce are verified; those handlers
/// additionally require the authenticated account to match the account they act on.
/// `GET /denominations` is public key material and carries no auth. This router is served
/// under mutual TLS, so every client also presents a CA-issued certificate. Registration is
/// not here - it cannot require a client certificate; see [`enrollment_router`].
pub fn authenticated_router(bank: Arc<Bank>, ca: Arc<CertAuthority>) -> Router {
    let protected = Router::new()
        .route("/accounts", post(create_account_authenticated))
        .route("/accounts/{id}/balance", get(get_balance_authenticated))
        .route("/withdraw", post(withdraw_authenticated))
        .route("/deposit", post(deposit_authenticated))
        .route_layer(axum::middleware::from_fn_with_state(
            bank.clone(),
            verify_signed_request,
        ));
    let public = Router::new().route("/denominations", get(denominations));
    protected
        .merge(public)
        .with_state(AppState { bank, ca })
}

/// Build the enrollment router served on the enrollment port over server-authenticated TLS
/// (no client certificate). It exposes only `POST /register`, which binds an account's
/// Ed25519 key and issues its mTLS client certificate.
pub fn enrollment_router(bank: Arc<Bank>, ca: Arc<CertAuthority>) -> Router {
    Router::new()
        .route("/register", post(register))
        .with_state(AppState { bank, ca })
}

async fn register(
    State(bank): State<Arc<Bank>>,
    State(ca): State<Arc<CertAuthority>>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, ApiError> {
    let raw = hex::decode(&req.public_key_hex).map_err(|_| ApiError {
        status: StatusCode::BAD_REQUEST,
        message: "public_key_hex is not valid hex".to_string(),
    })?;
    let bytes: [u8; digicash_core::IDENTITY_PUBLIC_KEY_LEN] =
        raw.as_slice().try_into().map_err(|_| ApiError {
            status: StatusCode::BAD_REQUEST,
            message: "public key must be 32 bytes".to_string(),
        })?;
    let public_key = IdentityPublicKey::from_bytes(&bytes).map_err(|e| ApiError {
        status: StatusCode::BAD_REQUEST,
        message: e.to_string(),
    })?;
    bank.register_identity(&req.account_id, &public_key).await?;
    let identity = ca.issue_client_identity(&req.account_id)?;
    Ok(Json(RegisterResponse {
        client_cert_pem: identity.cert_pem,
        client_key_pem: identity.key_pem,
        ca_cert_pem: ca.ca_cert_pem(),
    }))
}

/// Reject a request whose signed identity does not match the account it targets.
fn ensure_account(authenticated: &AuthenticatedAccount, target: &str) -> Result<(), ApiError> {
    if authenticated.0 == target {
        Ok(())
    } else {
        Err(ApiError {
            status: StatusCode::FORBIDDEN,
            message: format!(
                "authenticated account {} may not act on account {target}",
                authenticated.0
            ),
        })
    }
}

async fn create_account_authenticated(
    State(bank): State<Arc<Bank>>,
    Extension(auth): Extension<AuthenticatedAccount>,
    Json(req): Json<CreateAccountRequest>,
) -> Result<Json<BalanceResponse>, ApiError> {
    ensure_account(&auth, &req.account_id)?;
    Ok(Json(
        bank.create_account(&req.account_id, req.initial_balance_cents)
            .await?,
    ))
}

async fn get_balance_authenticated(
    State(bank): State<Arc<Bank>>,
    Extension(auth): Extension<AuthenticatedAccount>,
    Path(account_id): Path<String>,
) -> Result<Json<BalanceResponse>, ApiError> {
    ensure_account(&auth, &account_id)?;
    balance_response(&bank, account_id).await
}

async fn withdraw_authenticated(
    State(bank): State<Arc<Bank>>,
    Extension(auth): Extension<AuthenticatedAccount>,
    Json(req): Json<WithdrawRequest>,
) -> Result<Json<WithdrawResponse>, ApiError> {
    ensure_account(&auth, &req.account_id)?;
    Ok(Json(bank.withdraw(&req).await?))
}

async fn deposit_authenticated(
    State(bank): State<Arc<Bank>>,
    Extension(auth): Extension<AuthenticatedAccount>,
    Json(req): Json<DepositRequest>,
) -> Result<Json<DepositResponse>, ApiError> {
    ensure_account(&auth, &req.account_id)?;
    Ok(Json(bank.deposit(&req).await?))
}

async fn denominations(
    State(bank): State<Arc<Bank>>,
) -> Result<Json<DenominationsResponse>, ApiError> {
    Ok(Json(DenominationsResponse {
        denominations: bank.published_keys()?,
    }))
}

async fn create_account(
    State(bank): State<Arc<Bank>>,
    Json(req): Json<CreateAccountRequest>,
) -> Result<Json<BalanceResponse>, ApiError> {
    Ok(Json(
        bank.create_account(&req.account_id, req.initial_balance_cents)
            .await?,
    ))
}

async fn get_balance(
    State(bank): State<Arc<Bank>>,
    Path(account_id): Path<String>,
) -> Result<Json<BalanceResponse>, ApiError> {
    balance_response(&bank, account_id).await
}

async fn balance_response(
    bank: &Bank,
    account_id: String,
) -> Result<Json<BalanceResponse>, ApiError> {
    match bank.balance(&account_id).await? {
        Some(balance_cents) => Ok(Json(BalanceResponse {
            account_id,
            balance_cents,
        })),
        None => Err(ApiError {
            status: StatusCode::NOT_FOUND,
            message: format!("account {account_id} not found"),
        }),
    }
}

async fn withdraw(
    State(bank): State<Arc<Bank>>,
    Json(req): Json<WithdrawRequest>,
) -> Result<Json<WithdrawResponse>, ApiError> {
    Ok(Json(bank.withdraw(&req).await?))
}

async fn deposit(
    State(bank): State<Arc<Bank>>,
    Json(req): Json<DepositRequest>,
) -> Result<Json<DepositResponse>, ApiError> {
    Ok(Json(bank.deposit(&req).await?))
}

/// An error response with an HTTP status. Deposit rejections are *not* errors; they are
/// returned as a normal `DepositResponse` with `accepted: false`.
struct ApiError {
    status: StatusCode,
    message: String,
}

impl IntoResponse for ApiError {
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

impl From<BankError> for ApiError {
    fn from(error: BankError) -> Self {
        let status = match &error {
            BankError::AccountExists(_)
            | BankError::WithdrawPreviouslyFailed(_)
            | BankError::IdentityExists(_) => StatusCode::CONFLICT,
            BankError::AccountNotFound(_) => StatusCode::NOT_FOUND,
            BankError::InsufficientBalance { .. } => StatusCode::UNPROCESSABLE_ENTITY,
            BankError::UnknownDenomination(_) => StatusCode::BAD_REQUEST,
            BankError::Sled(_)
            | BankError::Io(_)
            | BankError::Core(_)
            | BankError::Key { .. }
            | BankError::MalformedBalance { .. }
            | BankError::MalformedRecord { .. }
            | BankError::WithdrawFailed { .. }
            | BankError::BalanceOverflow(_)
            | BankError::CertGen(_)
            | BankError::Tls(_)
            | BankError::ClientVerifier(_)
            | BankError::MalformedIdentity { .. }
            | BankError::Db(_)
            | BankError::Pool(_)
            | BankError::PoolBuild(_)
            | BankError::Sqlx(_)
            | BankError::Migrate(_)
            | BankError::ValueRange(_) => StatusCode::INTERNAL_SERVER_ERROR,
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
    use crate::bank::Bank;
    use crate::test_support::TestDatabase;
    use axum::body::{to_bytes, Body};
    use axum::http::{Request, StatusCode};
    use axum::response::Response;
    use digicash_proto::{BalanceResponse, CreateAccountRequest};
    use std::sync::Arc;
    use tempfile::TempDir;
    use tower::ServiceExt;

    /// Build a router over a bank on a fresh test database, or `None` if `DATABASE_URL` is unset.
    async fn app(tmp: &TempDir) -> Option<axum::Router> {
        let db = TestDatabase::create().await.expect("test db")?;
        let bank = Bank::connect(db.url(), tmp.path().join("keys"), &[64])
            .await
            .expect("bank connect");
        Some(router(Arc::new(bank)))
    }

    fn post(uri: &str, body: &impl serde::Serialize) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(body).expect("serialize")))
            .expect("request")
    }

    fn get(uri: &str) -> Request<Body> {
        Request::builder()
            .method("GET")
            .uri(uri)
            .body(Body::empty())
            .expect("request")
    }

    async fn json_body<T: serde::de::DeserializeOwned>(resp: Response) -> T {
        let bytes = to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("read body");
        serde_json::from_slice(&bytes).expect("deserialize")
    }

    #[tokio::test]
    async fn create_credit_and_read_back_balance() {
        let tmp = TempDir::new().expect("tempdir");
        let Some(app) = app(&tmp).await else {
            eprintln!("skipping: set DATABASE_URL to a Postgres instance to run this test");
            return;
        };

        let create = post(
            "/accounts",
            &CreateAccountRequest {
                account_id: "alice".to_string(),
                initial_balance_cents: 500,
            },
        );
        let resp = app.clone().oneshot(create).await.expect("create");
        assert_eq!(resp.status(), StatusCode::OK);
        let created: BalanceResponse = json_body(resp).await;
        assert_eq!(created.balance_cents, 500);

        let resp = app
            .clone()
            .oneshot(get("/accounts/alice/balance"))
            .await
            .expect("balance");
        assert_eq!(resp.status(), StatusCode::OK);
        let balance: BalanceResponse = json_body(resp).await;
        assert_eq!(balance.account_id, "alice");
        assert_eq!(balance.balance_cents, 500);

        let dup = post(
            "/accounts",
            &CreateAccountRequest {
                account_id: "alice".to_string(),
                initial_balance_cents: 1,
            },
        );
        let resp = app.clone().oneshot(dup).await.expect("duplicate");
        assert_eq!(resp.status(), StatusCode::CONFLICT);

        let resp = app
            .oneshot(get("/accounts/nobody/balance"))
            .await
            .expect("missing");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
