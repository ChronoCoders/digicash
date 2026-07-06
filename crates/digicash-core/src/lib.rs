//! Cryptographic primitives for digicash online coins.
//!
//! This crate implements the online RSA blind-signature scheme pinned in
//! `digicash-spec.md` v0.2 section 3: RSABSSA-SHA384-PSS-Deterministic per RFC 9474,
//! realized through the `blind-rsa-signatures` crate, with one 3072-bit RSA keypair per
//! denomination.
//!
//! Scope is deliberately narrow: serial generation, denomination keypairs, and the
//! `blind` / `sign` / `unblind` / `verify` operations over a serial. Wire types (the
//! `Coin` struct, deposit/withdraw messages) and the `(denomination, scheme_id)`-keyed
//! coin verification live in `digicash-proto` and the bank (Phase 2), not here.

mod error;
mod serial;

pub use error::CoreError;
pub use serial::Serial;
