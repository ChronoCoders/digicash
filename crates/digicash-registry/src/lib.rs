//! digicash multi-bank registry: a permissioned, Postgres-backed service holding the shared
//! spent-serial + transcript store, per-issuer exposure caps, receivables, and the
//! append-only settlement claim ledger (production-spec v1.4 section 10).
//!
//! It reuses the bank's self-signed CA and mTLS serving ([`digicash_bank::CertAuthority`],
//! [`digicash_bank::serve_tls`]) and the section 2 Ed25519 request-signing model; member
//! banks and the admin authenticate the same way wallets authenticate to a bank.

mod api;
mod db;
mod error;
mod registry;

#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

pub use api::router;
pub use error::RegistryError;
pub use registry::Registry;
