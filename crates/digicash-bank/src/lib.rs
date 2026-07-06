//! digicash bank: a sled-backed account ledger, per-denomination key store, spent-serial
//! store, and the withdraw/deposit protocol. Source of truth: `digicash-spec.md` v0.3.
//!
//! No account authentication in this phase: `account_id` is trusted as supplied. Request
//! signing (Ed25519), TLS, and Postgres/HSM storage are production-doc items, out of scope
//! here.

mod api;
mod bank;
mod error;
mod keys;

pub use api::router;
pub use bank::Bank;
pub use error::BankError;

/// The configured coin denominations, in integer cents: powers of two from 1 to 8192
/// (spec v0.3 section 3). One key is generated per denomination.
pub const DENOMINATIONS: [u64; 14] = [
    1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192,
];
