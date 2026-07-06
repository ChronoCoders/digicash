//! End-to-end flow over the HTTP router: two accounts, a withdrawal to a coin, a deposit
//! that credits the payee, and the same coin replayed and rejected as a double-spend.

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use axum::response::Response;
use axum::Router;
use digicash_core::{blind, unblind, BlindSignature, DefaultRng, DenominationPublicKey, Serial};
use digicash_proto::{
    BalanceResponse, Coin, CreateAccountRequest, DepositRejection, DepositRequest, DepositResponse,
    WithdrawRequest, WithdrawResponse,
};
use tempfile::TempDir;
use tower::ServiceExt;

use crate::{router, Bank};

async fn call<T: serde::de::DeserializeOwned>(app: &Router, req: Request<Body>) -> (StatusCode, T) {
    let resp: Response = app.clone().oneshot(req).await.expect("request");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.expect("body");
    (status, serde_json::from_slice(&bytes).expect("json"))
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

#[tokio::test]
async fn withdraw_deposit_and_double_spend_over_http() {
    let tmp = TempDir::new().expect("tempdir");
    let bank = Bank::open(tmp.path().join("db"), tmp.path().join("keys"), &[64]).expect("bank");
    // Keep the public key for wallet-side blinding before the bank moves into the router.
    let pk: DenominationPublicKey = bank.denomination_public_key(64, 0).expect("key").clone();
    let app = router(Arc::new(bank));

    let (status, _): (_, BalanceResponse) = call(
        &app,
        post(
            "/accounts",
            &CreateAccountRequest {
                account_id: "alice".to_string(),
                initial_balance_cents: 200,
            },
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _): (_, BalanceResponse) = call(
        &app,
        post(
            "/accounts",
            &CreateAccountRequest {
                account_id: "bob".to_string(),
                initial_balance_cents: 0,
            },
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // alice withdraws a 64-cent coin: the wallet blinds a fresh serial.
    let serial = Serial::generate().expect("serial");
    let blinding = blind(&pk, &mut DefaultRng, &serial).expect("blind");
    let (status, withdrawn): (_, WithdrawResponse) = call(
        &app,
        post(
            "/withdraw",
            &WithdrawRequest {
                account_id: "alice".to_string(),
                request_id: "w1".to_string(),
                denomination_cents: 64,
                blinded_message: blinding.blind_message.0.clone(),
            },
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let sig = unblind(
        &pk,
        &BlindSignature(withdrawn.blind_signature),
        &blinding,
        &serial,
    )
    .expect("unblind");
    let coin = Coin {
        scheme_id: 0,
        denomination_cents: 64,
        serial_number: *serial.as_bytes(),
        signature: sig.0,
    };

    // bob deposits the coin.
    let (status, deposited): (_, DepositResponse) = call(
        &app,
        post(
            "/deposit",
            &DepositRequest {
                coin: coin.clone(),
                account_id: "bob".to_string(),
                request_id: "d1".to_string(),
            },
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(deposited.accepted && deposited.reason.is_none());

    let (_, alice): (_, BalanceResponse) = call(&app, get("/accounts/alice/balance")).await;
    let (_, bob): (_, BalanceResponse) = call(&app, get("/accounts/bob/balance")).await;
    assert_eq!(alice.balance_cents, 200 - 64, "payer not debited");
    assert_eq!(bob.balance_cents, 64, "payee not credited");

    // Replaying the same coin under a new request_id is a double-spend; bob is not credited.
    let (status, replay): (_, DepositResponse) = call(
        &app,
        post(
            "/deposit",
            &DepositRequest {
                coin,
                account_id: "bob".to_string(),
                request_id: "d2".to_string(),
            },
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(replay.reason, Some(DepositRejection::DoubleSpend));
    let (_, bob): (_, BalanceResponse) = call(&app, get("/accounts/bob/balance")).await;
    assert_eq!(bob.balance_cents, 64, "double-spend re-credited the payee");
}
