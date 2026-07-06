use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use digicash_proto::{
    BalanceResponse, CreateAccountRequest, DenominationsResponse, DepositRequest, DepositResponse,
    ErrorResponse, WithdrawRequest, WithdrawResponse,
};

use crate::bank::Bank;
use crate::error::BankError;

/// Build the bank's HTTP router over shared bank state.
pub fn router(bank: Arc<Bank>) -> Router {
    Router::new()
        .route("/accounts", post(create_account))
        .route("/accounts/{id}/balance", get(get_balance))
        .route("/denominations", get(denominations))
        .route("/withdraw", post(withdraw))
        .route("/deposit", post(deposit))
        .with_state(bank)
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
        bank.create_account(&req.account_id, req.initial_balance_cents)?,
    ))
}

async fn get_balance(
    State(bank): State<Arc<Bank>>,
    Path(account_id): Path<String>,
) -> Result<Json<BalanceResponse>, ApiError> {
    match bank.balance(&account_id)? {
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
    Ok(Json(bank.withdraw(&req)?))
}

async fn deposit(
    State(bank): State<Arc<Bank>>,
    Json(req): Json<DepositRequest>,
) -> Result<Json<DepositResponse>, ApiError> {
    Ok(Json(bank.deposit(&req)?))
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
            BankError::AccountExists(_) | BankError::WithdrawPreviouslyFailed(_) => {
                StatusCode::CONFLICT
            }
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
            | BankError::BalanceOverflow(_) => StatusCode::INTERNAL_SERVER_ERROR,
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
    use axum::body::{to_bytes, Body};
    use axum::http::{Request, StatusCode};
    use axum::response::Response;
    use digicash_proto::{BalanceResponse, CreateAccountRequest};
    use std::sync::Arc;
    use tempfile::TempDir;
    use tower::ServiceExt;

    fn app(tmp: &TempDir) -> axum::Router {
        let bank = Bank::open(tmp.path().join("db"), tmp.path().join("keys"), &[64])
            .expect("bank should open");
        router(Arc::new(bank))
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
        let app = app(&tmp);

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
