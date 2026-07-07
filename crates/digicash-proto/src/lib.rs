//! Wire types for the digicash bank/wallet protocol (JSON over HTTP).
//!
//! Data only, no logic: [`Coin`], the withdraw/deposit/account request and response
//! messages, and the typed [`DepositRejection`]. The bank (which depends on
//! `digicash-core`) owns all validation and the `scheme_id` value; this crate never
//! restates that value.
//!
//! [`AuthHeaders`] carries the per-request authentication metadata (account claim,
//! timestamp, nonce, signature) that travels in HTTP headers rather than the body, keeping
//! the body hash stable for the canonical payload (spec v1.2 section 2).

mod auth;
mod coin;
mod messages;
mod registry;

pub use auth::{
    AuthHeaderError, AuthHeaders, HEADER_ACCOUNT, HEADER_NONCE, HEADER_SIGNATURE, HEADER_TIMESTAMP,
};
pub use coin::Coin;
pub use registry::{
    CapInfo, CapsResponse, MemberInfo, MembersResponse, RegisterMemberRequest, SerialOutcome,
    SerialResponse, SerialSubmission, SetCapRequest, SettleResponse, SettlementClaimInfo,
    TranscriptEntry,
};
pub use messages::{
    BalanceResponse, CreateAccountRequest, DenominationKey, DenominationsResponse,
    DepositRejection, DepositRequest, DepositResponse, ErrorResponse, RegisterRequest,
    RegisterResponse, WithdrawRequest, WithdrawResponse,
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
            DepositRejection::RegistryDoubleSpend,
            DepositRejection::ExposureCapExceeded,
        ] {
            roundtrip(reason);
        }
    }

    #[test]
    fn registry_messages_roundtrip() {
        roundtrip(RegisterMemberRequest {
            bank_id: "bank-a".into(),
            pubkey_hex: "aa".repeat(32),
        });
        roundtrip(MembersResponse {
            members: vec![
                MemberInfo {
                    bank_id: "admin".into(),
                    pubkey_hex: "bb".repeat(32),
                    is_admin: true,
                },
                MemberInfo {
                    bank_id: "bank-a".into(),
                    pubkey_hex: "cc".repeat(32),
                    is_admin: false,
                },
            ],
        });
    }

    #[test]
    fn register_messages_roundtrip() {
        roundtrip(RegisterRequest {
            account_id: "alice".into(),
            public_key_hex: "aa".repeat(32),
        });
        roundtrip(RegisterResponse {
            client_cert_pem: "-----BEGIN CERTIFICATE-----\nMII...\n-----END CERTIFICATE-----\n"
                .into(),
            client_key_pem: "-----BEGIN PRIVATE KEY-----\nMIG...\n-----END PRIVATE KEY-----\n"
                .into(),
            ca_cert_pem: "-----BEGIN CERTIFICATE-----\nMIIca...\n-----END CERTIFICATE-----\n"
                .into(),
        });
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

    #[test]
    fn denominations_response_roundtrip() {
        roundtrip(DenominationsResponse {
            denominations: vec![
                DenominationKey {
                    denomination_cents: 64,
                    scheme_id: 0,
                    public_key_spki: vec![48, 130, 1, 34, 5, 0],
                },
                DenominationKey {
                    denomination_cents: 512,
                    scheme_id: 0,
                    public_key_spki: vec![],
                },
            ],
        });
    }
}
