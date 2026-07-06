use serde::{Deserialize, Serialize};

use crate::coin::Coin;

/// `POST /withdraw` request. No `scheme_id`: the online path is always scheme 0, and the
/// bank signs under the `(denomination_cents, 0)` key. `blinded_message` is the wallet's
/// blinded serial; the bank never sees the serial itself.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct WithdrawRequest {
    pub account_id: String,
    pub request_id: String,
    pub denomination_cents: u64,
    pub blinded_message: Vec<u8>,
}

/// `POST /withdraw` response: the blind signature the wallet unblinds into a coin.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct WithdrawResponse {
    pub blind_signature: Vec<u8>,
}

/// `POST /deposit` request. `account_id` is the deposit target (the payee to credit); the
/// coin itself carries no account, which is what keeps withdrawals unlinkable.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct DepositRequest {
    pub coin: Coin,
    pub account_id: String,
    pub request_id: String,
}

/// `POST /deposit` response.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct DepositResponse {
    pub accepted: bool,
    pub reason: Option<DepositRejection>,
}

/// Why a deposit was rejected. Typed so the bank can report rejection rate by reason
/// rather than parsing free-text strings.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DepositRejection {
    /// The serial was already spent under a different `request_id`.
    DoubleSpend,
    /// The signature did not verify under the coin's `(denomination, scheme_id)` key.
    InvalidSignature,
    /// `denomination_cents` is not among the bank's configured denominations.
    UnknownDenomination,
    /// `scheme_id` is not supported by this bank.
    UnknownScheme,
    /// The deposit target `account_id` does not exist.
    UnknownAccount,
    /// The `request_id` was already used for a different coin.
    RequestIdReuse,
}

/// `POST /accounts` request. Demo-only: this credits a starting balance with no funding
/// behind it and is not a real fiat ramp.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct CreateAccountRequest {
    pub account_id: String,
    pub initial_balance_cents: u64,
}

/// Account balance, returned by `GET /accounts/{id}/balance` and `POST /accounts`.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct BalanceResponse {
    pub account_id: String,
    pub balance_cents: u64,
}

/// Body of an HTTP error response.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}
