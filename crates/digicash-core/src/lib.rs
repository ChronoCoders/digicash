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
mod scheme;
mod serial;

pub use blind_rsa_signatures::{BlindMessage, BlindSignature, BlindingResult, DefaultRng, Signature};
pub use error::CoreError;
pub use scheme::{
    blind, ensure_supported_scheme, generate_keypair, sign_blinded, unblind, verify,
    DenominationKeypair, DenominationPublicKey, DenominationSecretKey, MODULUS_BITS,
    SCHEME_ID_RSA_DETERMINISTIC,
};
pub use serial::Serial;
