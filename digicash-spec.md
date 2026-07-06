# digicash - RSA Blind-Signature E-Cash (Rust)

Spec v0.2 - locked. Faithful to Chaum's 1982/1990 DigiCash scheme (blind signatures,
bank-mediated online double-spend prevention). Uses RFC 9474 (RSABSSA) as the concrete
blind-RSA realization instead of textbook blinding, to avoid the known malleability/
padding issues in naive multiplicative blinding.

> **Supersession.** The v1 non-goals in section 2 are superseded by
> `digicash-spec-v1-production.md` (v1.1), which is authoritative for production scope
> (auth, storage, key management, offline double-spend, PQ backend, multi-bank interop).
> This document remains authoritative for the online RSA coin: cryptographic variant,
> coin format, and the withdraw/deposit protocol. Where the two overlap (coin format,
> the `scheme_id` field), this document is the source of truth and the production doc
> builds on it.

## 0. Revision notes (v0.2)

Changes from v0.1, all traceable to the v1.1 production audit:

- **Cryptographic variant pinned** (was unspecified): RSABSSA-SHA384-PSS-Deterministic.
  Rationale in section 3. This keeps a coin self-verifiable from its own fields with no
  per-coin randomizer.
- **`scheme_id` added to the coin format** (section 4). Forward-compatibility with the
  production doc's section 9 (PQ / scheme plurality): a coin declares which signature
  scheme signed it. `0` = the RSA/RFC 9474 scheme this document defines. Adding it now
  makes section 9 a non-breaking wire change rather than a coin-format migration.
- **`/deposit` wire format corrected** (section 6). v0.1's request body was `{ coin }`
  but the behavior text credited an `account_id` that the request never carried. The
  deposit target `account_id` is now an explicit field.
- **`/deposit` idempotency defined** (section 6). A lost deposit response must be safely
  retryable; a legitimate retry must not read as a double-spend. `request_id` and the
  retry-vs-double-spend semantics are now specified, mirroring `/withdraw`.
- **Typed rejection reasons** (section 6). `reason: Option<String>` became a typed
  `DepositRejection` enum so the production doc's "rejection rate by reason" metric has
  something to key on.
- **Serial generation pinned to `getrandom`** (section 3). "CSPRNG-generated" was too
  loose to exclude a userspace PRNG; the OS CSPRNG is now named explicitly.
- **Key-resolution invariant stated** (sections 3, 6). Verification keys resolve by the
  `(denomination_cents, scheme_id)` pair, no key shared across schemes; the key map is
  keyed on that pair. Previously keyed on denomination alone, which only held while one
  scheme existed.

## 1. Scope (this version)

Full client-server protocol. Bank service + wallet, over the network. Online double-spend
detection only (bank checks a spent-serial set at deposit time). Offline double-spend
deanonymization and post-quantum blind signatures are explicitly out of scope - deferred
to the production doc.

## 2. Non-goals (v1)

Superseded by `digicash-spec-v1-production.md` (v1.1). Retained here as the historical
scope boundary of the prototype:

- Offline spending / offline double-spend cryptography
- Post-quantum blind signatures
- Real fiat on/off ramp, KYC, multi-bank interop, settlement between banks
- TLS/mTLS hardening (v1 assumes localhost or a private trusted network only -
  this MUST be addressed before any deployment outside a trusted network)
- Custom/hand-rolled RSA blinding math

### 2.1 Threats in scope / out of scope (v1)

In scope:
- Bank learning which serial belongs to which withdrawal (blindness).
- A third party forging a valid coin without the bank's signature (unforgeability).
- Double-spending a coin twice against the bank (caught at deposit via spent_serials).
- A retried withdraw or deposit request double-processing (idempotency key).

Out of scope (accepted risk for v1, not silently ignored):
- Network eavesdropping / MITM (no TLS yet - trusted network assumption).
- Compromise of the bank's private keys (no HSM yet).
- A malicious wallet operator; this is a demo bank, not a regulated custodian.
- Collusion between the withdrawing party and the deposit target to launder value
  (no AML/KYC in this scope).

## 3. Cryptography

- Scheme: RSA Blind Signatures per RFC 9474 (RSABSSA), via the `blind-rsa-signatures`
  crate. Concrete variant: **RSABSSA-SHA384-PSS-Deterministic** (SHA-384, PSS with a
  48-byte salt, no message randomizer prepended).
  - Why Deterministic and not the RFC's Randomized default: the Randomized variant
    prepends a 32-byte randomizer to the message that the verifier must also hold, which
    would force a fourth field onto the coin. Its purpose is to protect low-entropy or
    attacker-influenced messages. Here the signed message is a wallet-chosen, uniformly
    random 256-bit CSPRNG serial, so that protection is not needed, and Deterministic
    keeps a coin verifiable from `{ scheme_id, denomination_cents, serial_number,
    signature }` alone. This is a standardized RFC 9474 variant, not a weakening of it.
- Modulus: 3072-bit RSA per denomination key.
- One RSA keypair per denomination. This is load-bearing: a coin's value is determined
  entirely by which key signed it, since the bank cannot see the serial number it's
  signing. Denominations must never share a key. Verification keys resolve by the
  `(denomination_cents, scheme_id)` pair; no key is ever shared across schemes or across
  denominations.
- Denominations: powers of two, in integer cents (no floating point anywhere):
  1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192 cents.
  A withdrawal/spend of an arbitrary amount decomposes into a set of these coins
  (like physical bill denominations).
- Serial number: 256-bit, generated by the OS CSPRNG via `getrandom`, never a userspace
  PRNG. Chosen by the wallet, never revealed to the bank until deposit (that's the
  unlinkability property).

## 4. Coin format

```
Coin {
    scheme_id: u8,             // 0 = RSA/RFC 9474 (RSABSSA-SHA384-PSS-Deterministic).
                               // Other values reserved; see production spec section 9.
    denomination_cents: u64,   // must match one of the configured denominations
    serial_number: [u8; 32],
    signature: Vec<u8>,        // RFC 9474 signature bytes over serial_number
}
```

A coin is a bearer instrument. Whoever holds the JSON/binary blob can deposit it.

`scheme_id` is covered by nothing but its own byte in v1 - the RSA signature is over
`serial_number` only, exactly as before. A bank rejects a coin whose `scheme_id` it does
not support (section 6). When section 9's scheme plurality lands, the signed payload
binding of `scheme_id` is revisited there; for the single-scheme online path it is a
routing tag.

## 5. Workspace layout

```
digicash/
  Cargo.toml                 # workspace
  crates/
    digicash-core/           # blind/sign/unblind/verify wrapping blind-rsa-signatures
    digicash-proto/          # wire message types (serde), Coin, error types
    digicash-bank/           # axum server: accounts, denomination keys, spent-serial store
    digicash-wallet/         # client library + CLI
```

## 6. Bank

State:
- `accounts: BTreeMap<AccountId, u64>` - balance in cents
- `spent_serials` - persisted set (sled), one namespace per denomination, checked and
  inserted atomically at deposit time. This must be durable from day one: losing this
  set on restart is a correctness bug (a double-spend safety failure), not a
  "come back to it later" item.
- `keys: BTreeMap<(u64 /* denomination */, u8 /* scheme_id */), RsaKeyPair>` - generated at bank startup from
  config, persisted to a key directory. v1 stores private keys as plaintext files on
  disk - acceptable for a demo, but encrypted-at-rest or HSM-backed key storage is a
  hard requirement before any deployment holding real value, not an optional hardening
  pass. Tracked in the production doc, not silently assumed away.

Endpoints (JSON over HTTP, axum):

- `POST /withdraw`
  Request: `{ account_id, request_id, denomination_cents, blinded_message }`
  `request_id` is a client-generated UUID, required, and used as an idempotency key:
  a retried withdraw with the same `request_id` returns the original result instead of
  debiting again. Behavior: check balance >= denomination_cents, debit atomically,
  sign blinded_message with that denomination's key. If debit succeeds but signing
  fails, the debit must be rolled back (compensating credit) before returning the
  error - a lost debit with no coin issued is a correctness bug, not an edge case.
  The issued `blind_signature` is persisted against `request_id` so the idempotent
  replay returns the same coin rather than re-signing.
  Response: `{ blind_signature }`
  No account authentication in v1 - `account_id` in the request body is trusted as-is.
  This is acceptable for a local demo bank only; anything beyond a trusted private
  network requires auth (mTLS or JWT/API key) before this endpoint is exposed. The
  production doc replaces this bare trust with Ed25519 request signing.

- `POST /deposit`
  Request: `{ coin: Coin, account_id, request_id }`
  - `account_id` is the deposit target (the payee to be credited). It is an explicit
    field: the coin itself carries no account (that would break blindness).
  - `request_id` is a client-generated UUID, the deposit idempotency key.
  Behavior: reject if `scheme_id` is unsupported; verify signature under the coin's
  denomination key; check `serial_number` not already in `spent_serials`; if all pass,
  insert serial and credit `account_id`, all in one atomic step, then return success.
  Idempotency and double-spend are distinct cases and must not be conflated:
  - `(request_id, coin)` identical to a prior accepted deposit returns the original
    accepted result. A lost response is safely retryable.
  - Same `serial_number` under a *different* `request_id` is a double-spend and is
    rejected with `DoubleSpend` (do not silently no-op).
  - Same `request_id` bound to a *different* coin is a client fault, rejected with
    `RequestIdReuse`.
  Response: `{ accepted: bool, reason: Option<DepositRejection> }`

  ```
  enum DepositRejection {
      DoubleSpend,          // serial already spent, under a different request_id
      InvalidSignature,     // signature fails verification under the denomination key
      UnknownDenomination,  // denomination_cents not among configured denominations
      UnknownScheme,        // scheme_id not supported by this bank
      UnknownAccount,       // deposit target account_id does not exist
      RequestIdReuse,       // request_id already bound to a different coin
  }
  ```

- `POST /accounts` (demo-only, flagged clearly in code and docs as not a real
  fiat ramp) - creates an account with an admin-credited starting balance. The
  production doc replaces this with an operator-authenticated ledger endpoint.

- `GET /accounts/{id}/balance`

## 7. Wallet

CLI surface:

```
digicash-wallet account create
digicash-wallet balance
digicash-wallet withdraw <amount_cents>        # greedy decomposition over powers-of-two denominations, stores locally
digicash-wallet spend <amount_cents> --out coin-bundle.json   # bearer transfer, no network hop
digicash-wallet deposit --in coin-bundle.json  # deposits a received bundle to the bank
```

`spend` is out-of-band by design (matches the bearer-instrument model): it just selects
coins from the local wallet store covering the amount and writes them to a file/stdout.
Transfer to a merchant is not this program's concern (email it, hand it over, whatever).
`deposit` is how a payee (merchant or anyone) redeems a received bundle at the bank.

Change: v1's greedy decomposition can only pay amounts the wallet already holds exact
coins for. There is no change-making in v1; a spend of an amount the local stock cannot
cover exactly fails, and the user re-withdraws to get the right denominations. Change
handling for the production path is specified in the production doc.

## 8. Protocol flow (withdraw -> spend -> deposit)

1. Wallet generates serial number, blinds it, sends to bank `/withdraw` with desired
   denomination and account_id.
2. Bank debits account, signs blinded value, returns blind signature.
3. Wallet unblinds -> holds `Coin { scheme_id, denomination, serial_number, signature }`,
   verifiable locally against the bank's public key for that denomination.
4. Wallet writes coin(s) to a bundle file (`spend`), hands it to payee out of band.
5. Payee runs `deposit` with its own `account_id` and a fresh `request_id`: bank verifies
   scheme and signature, checks spent_serials, credits payee, marks serial spent.
6. A second deposit of the same serial under a different `request_id` is rejected as a
   double-spend; a retry of the same `(request_id, coin)` returns the original result.

## 9. Phased roadmap

- **Phase 1**: `digicash-core` - wraps `blind-rsa-signatures`, coin/serial types,
  unit tests against RFC 9474 test vectors.
- **Phase 2**: `digicash-bank` - account ledger, per-denomination keys, sled-backed
  spent-serial store, `/withdraw` and `/deposit` endpoints, integration tests.
- **Phase 3**: `digicash-wallet` - CLI: account, withdraw, spend (bundle file), deposit.
- **Phase 4**: End-to-end test - wallet A withdraws, spends to file, wallet B deposits,
  balances verified, replayed deposit of the same bundle is rejected.
- **Production**: everything in `digicash-spec-v1-production.md` - auth, storage, key
  management, offline double-spend, PQ backend, multi-bank interop.

## 10. Decisions (formerly open questions)

- **Serialization**: JSON. Axum ergonomics, tiny message sizes, and debuggability
  during protocol/atomicity validation outweigh bincode's compactness at this stage.
  Revisit only if measurement shows JSON overhead actually matters - not before.
- **Account persistence**: sled, same as spent_serials. A bank that forgets balances
  on restart is the same class of bug as one that forgets spent serials; the
  implementation cost is low and it makes Phase 4's end-to-end test restart-safe
  for free.

Both resolved. Spec v0.2 is locked. Phase 1 (`digicash-core`) is ready to start.
