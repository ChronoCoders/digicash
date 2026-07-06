//! digicash bank: a sled-backed account ledger, per-denomination key store, spent-serial
//! store, and the withdraw/deposit protocol. Source of truth: `digicash-spec.md` v0.3.
//!
//! Production-spec v1.2 section 2 authentication lives here: [`authenticated_router`] wraps
//! every value-bearing endpoint in the Ed25519 request-signing middleware, served over mTLS
//! via [`serve_tls`] with a self-signed [`CertAuthority`]. The legacy plaintext [`router`] is
//! retained for local development only. Postgres/HSM storage remains a production-doc item,
//! out of scope here.

mod api;
mod auth;
mod bank;
mod error;
mod keys;
mod serve;
mod tls;

#[cfg(any(test, feature = "test-support"))]
mod db;
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
