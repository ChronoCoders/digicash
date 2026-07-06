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
//!
//! The `auth` module adds the wallet-identity primitives of production-spec v1.2 section 2:
//! an Ed25519 [`IdentityKeypair`] and the [`canonical_payload`] a wallet signs on every
//! request. The transport (mTLS) and the request-signing middleware live in the bank and
//! wallet crates; this crate holds only the primitives.

mod auth;
mod error;
mod scheme;
mod serial;

pub use auth::{
    canonical_payload, IdentityKeypair, IdentityPublicKey, IDENTITY_PUBLIC_KEY_LEN,
    IDENTITY_SECRET_KEY_LEN, IDENTITY_SIGNATURE_LEN,
};
pub use blind_rsa_signatures::{BlindMessage, BlindSignature, BlindingResult, DefaultRng, Signature};
pub use error::CoreError;
pub use scheme::{
    blind, ensure_supported_scheme, generate_keypair, sign_blinded, unblind, verify,
    DenominationKeypair, DenominationPublicKey, DenominationSecretKey, MODULUS_BITS,
    SCHEME_ID_RSA_DETERMINISTIC,
};
pub use serial::Serial;
