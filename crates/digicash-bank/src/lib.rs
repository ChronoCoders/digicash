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
mod tls;

#[cfg(test)]
mod integration;

pub use api::router;
pub use bank::Bank;
pub use digicash_proto::DENOMINATIONS;
pub use error::BankError;
pub use tls::{CertAuthority, ClientIdentity};
