use serde::{Deserialize, Serialize};

use crate::coin::Coin;

/// `POST /withdraw` request. No `scheme_id`: the online path is always scheme 0, and the
/// bank signs under the `(denomination_cents, 0)` key. `blinded_message` is the wallet's
/// blinded serial; the bank never sees the serial itself.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct WithdrawRequest {
    /// The account to debit.
    pub account_id: String,
    /// Client-generated idempotency key; a retry returns the original result.
    pub request_id: String,
    /// The denomination to withdraw, in cents.
    pub denomination_cents: u64,
    /// The wallet's blinded serial, for the bank to sign without seeing the serial.
    pub blinded_message: Vec<u8>,
}

/// `POST /withdraw` response: the blind signature the wallet unblinds into a coin.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct WithdrawResponse {
    /// The blind signature the wallet unblinds into a coin signature.
    pub blind_signature: Vec<u8>,
}

/// `POST /deposit` request. `account_id` is the deposit target (the payee to credit); the
/// coin itself carries no account, which is what keeps withdrawals unlinkable.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct DepositRequest {
    /// The coin being deposited.
    pub coin: Coin,
    /// The payee account to credit.
    pub account_id: String,
    /// Client-generated idempotency key; a retry of the same coin replays.
    pub request_id: String,
}

/// `POST /deposit` response.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct DepositResponse {
    /// Whether the coin was accepted and the account credited.
    pub accepted: bool,
    /// Why the deposit was rejected, when `accepted` is false.
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
    /// The account id to create.
    pub account_id: String,
    /// The demo starting balance to credit, in cents.
    pub initial_balance_cents: u64,
}

/// Account balance, returned by `GET /accounts/{id}/balance` and `POST /accounts`.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct BalanceResponse {
    /// The account the balance is for.
    pub account_id: String,
    /// The account balance, in cents.
    pub balance_cents: u64,
}

/// Body of an HTTP error response.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct ErrorResponse {
    /// A human-readable description of the error.
    pub error: String,
}

/// One denomination's public key, as SubjectPublicKeyInfo DER. Published so wallets can
/// blind, unblind, and verify without ever seeing a private key.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DenominationKey {
    /// The denomination this key signs, in cents.
    pub denomination_cents: u64,
    /// The signature scheme; `0` is RSABSSA-SHA384-PSS-Deterministic.
    pub scheme_id: u8,
    /// The public key as SubjectPublicKeyInfo DER.
    pub public_key_spki: Vec<u8>,
}

/// Response of `GET /denominations`: the bank's published denomination public keys.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DenominationsResponse {
    /// One entry per configured `(denomination, scheme)` key.
    pub denominations: Vec<DenominationKey>,
}
