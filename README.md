# digicash

**Privacy preserving digital cash.**

![status](https://img.shields.io/badge/status-experimental-orange)
![license](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)
![rust](https://img.shields.io/badge/rust-2021-black)

A Rust implementation of Chaumian blind-signature e-cash: digital bearer coins that a bank
issues and redeems without ever learning which coin belongs to which withdrawal. Payments
are unlinkable by construction, and double-spending is caught at deposit. The blind
signatures use the standardized RFC 9474 (RSABSSA) construction rather than hand-rolled
blinding math.

> [!WARNING]
> **Experimental and unaudited. Do not use to hold real value.** This is a research and
> educational implementation. The online RSA path builds on standardized, audited
> primitives, but the system as a whole has not had a security review, and later
> components (offline double-spend, post-quantum, multi-bank settlement) are research-grade
> by nature. Treat everything here as a prototype.

## How it works

A coin is a bearer instrument: a serial number plus the bank's blind signature over it.
Value is carried by the bytes, so whoever holds a coin can deposit it.

1. **Withdraw.** The wallet generates a random 256-bit serial, *blinds* it, and asks the
   bank to sign the blinded value. The bank debits the account and signs, without ever
   seeing the serial.
2. **Spend.** The wallet unblinds the signature into a coin it can verify locally, then
   hands the coin to a payee out of band (a file, a message, in person). No bank round-trip
   at spend time.
3. **Deposit.** The payee sends the coin to the bank. The bank verifies the signature and
   checks the serial against its spent set: first deposit credits the payee and records the
   serial; a second deposit of the same serial is rejected as a double-spend.

Because the bank signs a blinded serial it never sees, it cannot link a deposit back to the
withdrawal that funded it. That gap is the privacy guarantee.

## Cryptography

- **Scheme:** RSA Blind Signatures per [RFC 9474](https://www.rfc-editor.org/rfc/rfc9474)
  (RSABSSA), specifically the SHA-384 / PSS / Deterministic variant, via the audited
  [`blind-rsa-signatures`](https://crates.io/crates/blind-rsa-signatures) crate. No custom
  blinding math.
- **Keys:** one 3072-bit RSA keypair per denomination. A coin's value is determined
  entirely by which key signed it; keys are never shared across denominations.
- **Serials:** 256-bit, from the operating-system CSPRNG (`getrandom`), never a userspace
  PRNG.
- **Denominations:** fixed powers of two in integer cents (1, 2, 4, ..., 8192), like
  physical bills. Arbitrary amounts decompose into a set of coins. No floating point
  anywhere.

## Using `digicash-core`

The one crate published so far exposes the withdraw-to-verify primitives:

```rust
use digicash_core::{blind, generate_keypair, sign_blinded, unblind, verify, DefaultRng, Serial};

// (inside a function returning Result<(), digicash_core::CoreError>)

// Bank: one keypair per denomination.
let keypair = generate_keypair(&mut DefaultRng)?;

// Wallet: pick a secret serial and blind it.
let serial = Serial::generate()?;
let blinding = blind(&keypair.pk, &mut DefaultRng, &serial)?;

// Bank: blind-sign without seeing the serial.
let blind_sig = sign_blinded(&keypair.sk, &blinding.blind_message)?;

// Wallet: unblind into a coin signature and verify it locally.
let signature = unblind(&keypair.pk, &blind_sig, &blinding, &serial)?;
verify(&keypair.pk, &serial, &signature)?;
```

## Status and roadmap

Built in small, tested, phased steps. Each phase is a tagged release (`v0.N.0`).

- **Phase 1 - `digicash-core`** (done, `v0.1.0`): cryptographic primitives. Serial
  generation, denomination keypairs, and `blind` / `sign` / `unblind` / `verify`, with a
  byte-exact known-answer test against the published RFC 9474 vectors.
- **Phase 2 - `digicash-proto` & `digicash-bank`**: wire types and the `Coin` struct; the
  bank service with an account ledger, per-denomination keys, a durable spent-serial store,
  and `/withdraw` + `/deposit` endpoints.
- **Phase 3 - `digicash-wallet`**: a CLI for creating accounts, withdrawing, spending to a
  coin bundle, and depositing.
- **Phase 4 - end-to-end**: wallet A withdraws, spends to a file, wallet B deposits;
  balances verified; a replayed deposit is rejected.
- **Production (`v1.0.0`)**: authenticated accounts (Ed25519 + TLS), Postgres storage,
  HSM/KMS-backed keys, audit trail and metrics, offline double-spend, a post-quantum blind
  signature backend, and multi-bank interop and settlement.

## Workspace layout

```
digicash/
  crates/
    digicash-core/     # blind/sign/unblind/verify, serials, keys   (Phase 1, done)
    digicash-proto/    # wire message types, Coin, errors           (Phase 2)
    digicash-bank/     # axum server: ledger, keys, spent-serials   (Phase 2)
    digicash-wallet/   # client library + CLI                       (Phase 3)
```

## Build and test

```sh
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
```

The workspace denies warnings, and the tests include the RFC 9474 known-answer test plus
negative checks (wrong key, tampered signature, swapped serial).

## License

Licensed under either of the Apache License, Version 2.0 or the MIT license, at your
option.
