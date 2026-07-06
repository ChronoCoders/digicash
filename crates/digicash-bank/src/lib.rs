//! digicash bank: a Postgres-backed account ledger, spent-serial store, withdraw state
//! machine, deposit protocol, and anti-replay nonce store (production-spec v1.3 section 4),
//! with per-denomination signing keys held on disk.
//!
//! Production-spec v1.2 section 2 authentication lives here: [`authenticated_router`] wraps
//! every value-bearing endpoint in the Ed25519 request-signing middleware, served over mTLS
//! via [`serve_tls`] with a self-signed [`CertAuthority`]. The legacy plaintext [`router`] is
//! retained for local development only. HSM/KMS key storage remains a production-doc item,
//! out of scope here.

mod api;
mod auth;
mod bank;
mod db;
mod error;
mod keys;
mod serve;
mod tls;

#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

#[cfg(test)]
mod integration;

pub use api::{authenticated_router, enrollment_router, router};
pub use auth::{verify_signed_request, AuthenticatedAccount};
pub use bank::Bank;
pub use digicash_proto::DENOMINATIONS;
pub use error::BankError;
pub use serve::serve_tls;
pub use tls::{CertAuthority, ClientIdentity};
