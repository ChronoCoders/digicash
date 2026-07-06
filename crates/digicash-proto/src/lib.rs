//! Wire types for the digicash bank/wallet protocol (JSON over HTTP).
//!
//! Data only, no logic: [`Coin`], the withdraw/deposit/account request and response
//! messages, and the typed [`DepositRejection`]. The bank (which depends on
//! `digicash-core`) owns all validation and the `scheme_id` value; this crate never
//! restates that value.

mod coin;
mod messages;

pub use coin::Coin;
pub use messages::{
    BalanceResponse, CreateAccountRequest, DepositRejection, DepositRequest, DepositResponse,
    ErrorResponse, WithdrawRequest, WithdrawResponse,
};

/// The coin denominations, in integer cents: powers of two from 1 to 8192 (spec v0.3
/// section 3). One bank key exists per denomination, and the wallet decomposes amounts
/// over this set. Single source of truth shared by the bank and the wallet.
pub const DENOMINATIONS: [u64; 14] = [
    1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192,
];

#[cfg(test)]
mod tests {
    use super::*;
    use serde::de::DeserializeOwned;
    use serde::Serialize;
    use std::fmt::Debug;

    fn roundtrip<T: Serialize + DeserializeOwned + PartialEq + Debug>(value: T) {
        let json = serde_json::to_string(&value).expect("serialize");
        let back: T = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(value, back, "JSON round-trip changed the value");
    }

    fn sample_coin() -> Coin {
        Coin {
            scheme_id: 0,
            denomination_cents: 64,
            serial_number: [7u8; 32],
            signature: vec![1, 2, 3, 4, 250, 255],
        }
    }

    #[test]
    fn coin_roundtrip() {
        roundtrip(sample_coin());
    }

    #[test]
    fn withdraw_roundtrip() {
        roundtrip(WithdrawRequest {
            account_id: "alice".into(),
            request_id: "req-1".into(),
            denomination_cents: 128,
            blinded_message: vec![9, 8, 7],
        });
        roundtrip(WithdrawResponse {
            blind_signature: vec![0, 1, 2, 3],
        });
    }

    #[test]
    fn deposit_roundtrip() {
        roundtrip(DepositRequest {
            coin: sample_coin(),
            account_id: "bob".into(),
            request_id: "req-2".into(),
        });
        roundtrip(DepositResponse {
            accepted: true,
            reason: None,
        });
        roundtrip(DepositResponse {
            accepted: false,
            reason: Some(DepositRejection::DoubleSpend),
        });
    }

    #[test]
    fn deposit_rejection_serializes_snake_case() {
        let json = serde_json::to_string(&DepositRejection::RequestIdReuse).expect("serialize");
        assert_eq!(json, "\"request_id_reuse\"");
        for reason in [
            DepositRejection::DoubleSpend,
            DepositRejection::InvalidSignature,
            DepositRejection::UnknownDenomination,
            DepositRejection::UnknownScheme,
            DepositRejection::UnknownAccount,
            DepositRejection::RequestIdReuse,
        ] {
            roundtrip(reason);
        }
    }

    #[test]
    fn account_messages_roundtrip() {
        roundtrip(CreateAccountRequest {
            account_id: "carol".into(),
            initial_balance_cents: 10_000,
        });
        roundtrip(BalanceResponse {
            account_id: "carol".into(),
            balance_cents: 10_000,
        });
        roundtrip(ErrorResponse {
            error: "insufficient balance".into(),
        });
    }

    #[test]
    fn denominations_are_ascending_powers_of_two() {
        for (i, &denom) in DENOMINATIONS.iter().enumerate() {
            assert_eq!(denom, 1u64 << i, "denomination at index {i} is not 2^{i}");
        }
        assert_eq!(DENOMINATIONS[DENOMINATIONS.len() - 1], 8192);
    }
}
