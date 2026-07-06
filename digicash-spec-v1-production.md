# digicash - Production Requirements (v1.1)

Supersedes the non-goals in `digicash-spec.md` (v0.2, prototype). v0.2 proved the
protocol is correct. This document is the full production scope: everything the prototype
deferred - offline double-spend, PQ blind signatures, multi-bank settlement - is now
in scope, alongside the account/auth/storage/key-management hardening. It does not
replace v0.2's cryptography section (RFC 9474, denomination-per-key, coin format) - that
part was already built to hold and stays the online-coin baseline underneath sections
8-10. Coins carry `scheme_id` as of v0.2, which is what makes section 9's scheme
plurality a non-breaking change here rather than a coin-format break.

**Scope boundary of this document:** engineering requirements only. Licensing, KYC/AML
program design, and banking/custody relationships are not covered here - this document
specifies technical hooks (fields, endpoints, configurable enforcement points) that a
deploying party can wire up however they choose. Nothing below is a gate this spec
imposes; it's infrastructure that supports whatever policy gets layered on top.

## 0. Revision notes (v1.1)

This revision followed a full audit of v1.0. Summary of what changed and why:

- **Section 8 (offline double-spend) was unsound and is now a selection gate, not a
  construction.** v1.0 described cut-and-choose cut over RFC 9474 blind signing. That
  does not work: RSABSSA provides neither the commitment-to-blinded-message binding nor
  the multiplicative homomorphism that Chaum-Fiat-Naor depends on, both of which it
  removes on purpose. The "enough to build against" claim was false and is deleted.
  Section 8 now selects a published, reviewed construction before implementation.
- **Section 4 storage:** the `SELECT ... FOR UPDATE` option was removed - it is a
  phantom race on a not-yet-existing row under READ COMMITTED. Unique constraint +
  `ON CONFLICT DO NOTHING` + rowcount check is now mandated.
- **Section 4.1 (new):** withdraw is a persisted, recoverable state machine now that
  debit (Postgres) and sign (KMS) are separable and a crash can strand funds between
  them.
- **Section 5 key rotation:** bearer coins cannot be silently sunset. A forced-exchange
  lifecycle replaces "valid until retired."
- **Section 6 logging rationale corrected:** the reason not to log serials is that a
  serial+signature pair is spendable money and logs are lower-trust than the ledger, not
  "it recreates linkability" (it cannot - the bank records no serial at withdrawal).
- **Section 2 auth:** the Ed25519 signed-request payload is now canonically specified
  with timestamp + nonce anti-replay.
- **Section 2.1 (new):** operator-authenticated ledger endpoint replacing the demo
  `POST /accounts`.
- **Section 9 hybrid:** dual-issue is require-both-in-window, not accept-either.
- **Section 10:** shared spent-serial store must carry offline transcripts for
  cross-bank attribution; settlement gets per-issuer exposure caps.
- **Sections 11, 12 (new):** denomination change handling; wallet-side coin storage.
- **Sequencing:** TLS folded into the auth step; the offline step is a select-then-build
  gate.

## 1. What backs the ledger balance

A ledger balance in cents reflects value only if something backs it at the deployment
level - a licensed entity, a banking partnership, a trust account, whatever the operator
sets up. This spec doesn't model that relationship; it just assumes the ledger's numbers
mean something to whoever is running the bank.

## 2. Account model - identity and authentication

v0.1 trusted a bare `account_id` string in the request body. That's gone.

- Account record carries an optional `kyc_status` field (unverified / pending /
  verified / rejected) plus `kyc_provider_ref` and `verified_at`. This is a hook, not
  an enforced gate: whether/how it's checked before withdraw or deposit is a
  deployment-level policy decision, configurable per instance, not hardcoded in the
  protocol. A deployment that never sets this field simply runs with it unused.
- Every account has a registered signing keypair (Ed25519), generated client-side at
  account creation, public key registered with the bank. Every request that touches an
  account (`withdraw`, `deposit` where a specific account is credited, balance queries,
  the operator endpoints in 2.1) must be signed by that key. The bank verifies the
  signature before processing - `account_id` in a request body is now a claim to be
  verified, not a fact to be trusted.
- Transport is mTLS or TLS 1.3 with the bank presenting a real certificate. No plaintext
  HTTP anywhere outside local development.

**Canonical signed payload (anti-replay).** "Signed by that key" is underspecified on its
own; define it exactly so it does not become a replay hole the moment TLS terminates at a
proxy:

- The client signs `H(method ‖ path ‖ H(raw_body_bytes) ‖ timestamp ‖ nonce)`, where
  `raw_body_bytes` is the exact bytes on the wire, not a re-serialized structure (every
  proxy or reserializer in the path would otherwise break the signature).
- `timestamp` is UTC; the bank rejects requests outside a small skew window
  (for example +/- 30s), configurable.
- `nonce` is unique per account within the skew window; the bank keeps a per-account
  seen-nonce set spanning the window and rejects reuse. Timestamp bounds the set size.
- The signature, `timestamp`, and `nonce` travel in request headers, not the body, so
  the body hash stays stable.

A captured request is then only replayable inside the skew window and only until the
nonce is seen, and TLS already covers capture in the first place; this is defense in
depth for the case where TLS terminates upstream of the bank.

### 2.1 Operator-authenticated ledger endpoints

The prototype's demo `POST /accounts` (admin-credited starting balance) is not a
production ledger primitive. Replace it with an operator-authenticated endpoint for the
credit/debit that corresponds to real value entering or leaving at the deployment
boundary (section 1):

- Credits and debits to an account that are not the result of a withdraw/deposit are made
  through an operator endpoint signed by an operator key (distinct from account keys),
  with a required external reference (the settlement / funding event it corresponds to).
- Every such operation is a balance-changing operation and therefore lands in the section
  6 audit trail - this is exactly the endpoint an auditor cares most about, since it is
  where the ledger meets off-ledger value.
- Whether a given credit is permitted (funding cleared, KYC satisfied) is deployment
  policy layered on the hook, per this document's scope boundary.

## 3. Blindness vs. traceability (a property to know, not a rule to enforce)

Full Chaumian unlinkability means the bank cannot trace a coin between withdrawal and
deposit - that's preserved and unchanged; this section just documents what that implies
architecturally, in case a deployment ever wants tiered visibility:
- Identity, if tracked at all (via the optional `kyc_status` hook), sits at the account
  boundary - withdraw and deposit - never inside the coin itself.
- Aggregate signals (total withdrawn per account per window, deposit velocity) are
  exposed as queryable fields in section 6's observability layer regardless of whether
  any policy consumes them. Cheap to have, costs nothing to leave unused.
- Coins themselves stay fully unlinkable once withdrawn, full stop. If a future
  deployment wants per-coin traceability above some value, that's a partially-blind or
  non-blind tier - a different product variant, not a change to this protocol's core
  guarantee.

## 4. Storage - moving off sled

- Account ledger and spent_serials move to Postgres. Sled's lack of a replication story
  is disqualifying once real money is involved - single-node embedded storage means a
  single disk failure is a total loss of the ledger.
- Postgres, primary plus at least one synchronous or near-synchronous replica.
  Point-in-time recovery (WAL archiving) configured from day one, not added later.
- Migrations via a real migration tool (`sqlx migrate` or `refinery`), version
  controlled, no manual schema edits against production.
- **`spent_serials` check-and-insert is a unique constraint plus
  `INSERT ... ON CONFLICT DO NOTHING`, with the credit conditioned on the insert having
  actually happened (check the affected-row count), all in one transaction.** Do not use
  `SELECT ... FOR UPDATE` to guard this: Postgres has no gap locks, so `FOR UPDATE` on a
  serial row that does not exist yet locks nothing, and two concurrent deposits of the
  same serial both pass the check and both proceed. The unique constraint is the only
  thing that makes the check-and-insert atomic against a concurrent inserter.
  (SERIALIZABLE isolation would also be correct via serialization-failure + retry, but
  the unique-constraint path is cheaper, needs no retry loop, and does not depend on the
  isolation level - so it is the mandated approach, not the alternative.)
  The idempotency guarantee from v0.2 carries over unchanged, just on a durable,
  replicated store.
- Backups tested by actual restore drills, not just verified to exist.

### 4.1 Withdraw as a recoverable state machine

Once the debit lives in Postgres and the signing lives in a KMS/HSM (section 5), the two
are separate systems and a process crash can land between them. v0.2's "roll back the
debit with a compensating credit if signing fails" assumes a live process that reaches the
rollback; it does not survive a crash after debit and before sign. So withdraw is modeled
as a persisted state machine keyed by `request_id`:

- States: `pending` (debit committed, not yet signed) -> `signed` (blind signature
  obtained and persisted) -> `completed` (returned to client), with `compensated`
  (debit reversed) as the terminal failure state.
- Transitions are durable. The blind signature is persisted at the `signed` transition,
  which is also what makes the idempotent replay of `/withdraw` implementable: a retry
  returns the persisted signature, it is never re-signed.
- Startup recovery scans for `pending` withdrawals and drives each one forward: either
  complete the signing (KMS call is idempotent on the same blinded message input) or, if
  it cannot, compensate the debit. A `pending` withdraw is never left stranded.

## 5. Key management

- Denomination RSA private keys move out of plaintext files. Two acceptable paths:
  - HSM-backed (PKCS#11). Gives you hardware-enforced non-export of the key.
  - Cloud KMS asymmetric signing (e.g. AWS KMS supports RSA signing keys) if a
    hardware HSM is out of budget for this phase - signing operation happens inside
    the KMS, private key material never leaves it.
- Either way: the bank process never holds raw private key bytes in memory longer than
  a single signing call requires, and never persists them outside the HSM/KMS boundary.

### 5.1 Key rotation lifecycle (bearer-safe)

A denomination key is rotated on a schedule or on suspected compromise. But coins are
bearer instruments with no expiry printed on them, so "old key kept valid for verification
until a sunset, then retired" silently confiscates any value not redeemed by the sunset -
a quiet default on the operator's own liabilities. The lifecycle is therefore:

1. **Announcement.** New denomination key published (via section 10's registry once
   multi-bank); the old key stops signing new withdrawals but stays valid for deposit
   verification.
2. **Forced-exchange window.** Holders deposit coins signed by the old key and re-withdraw
   the same value under the new key. The re-withdraw is a fresh blind signature, so
   unlinkability is preserved across the exchange - the bank does not learn a mapping
   between old and new coins.
3. **Straggler policy.** After the window, an explicit, published policy for coins still
   outstanding under the retired key (continued honoring on presentation, escheatment,
   or whatever the deployment's legal frame requires). It is a stated policy, never an
   implicit "they're worthless now."

This lifecycle must be designed before launch, not improvised after the first rotation is
needed.

## 6. Observability and audit

- Structured logging only (already house policy) - every withdraw, deposit, and
  rejected double-spend attempt logged with account, amount, denomination, and
  request_id.
- **Raw coin serial numbers do not go in plaintext application logs.** The reason is
  *not* that it would recreate linkability - it would not; the bank records no serial at
  withdrawal, so nothing logged at deposit can be joined back to a withdrawal, and
  unlinkability holds from the bank's side by construction. The real reasons are
  concrete: a `serial_number + signature` pair is spendable bearer money, and log
  pipelines are lower-trust and more widely readable than the ledger, so a serial in a
  log is a theft and replay exposure. Log a salted hash of the serial if a correlation
  handle is needed.
- An append-only audit trail, separate from application logs, for every balance-
  changing operation - Postgres table with no UPDATE/DELETE grants for the application
  role, or a WORM-backed log store. This is what a regulator or auditor asks for first.
- Metrics (Prometheus or equivalent): withdraw/deposit rate, rejection rate by reason
  (keyed on v0.2's typed `DepositRejection`, not free-text strings), double-spend
  attempt rate, HSM/KMS latency, replica lag. Alerting on anomalies - a spike in
  double-spend attempts is itself a signal worth paging on.

## 7. Abuse resistance

- Rate limiting per account and per IP on `/withdraw` and `/deposit`.
- Withdrawal velocity limits per account (ties into section 3's reporting hooks).
- Idempotency keys (v0.2) double as replay defense. v0.2 defines `request_id` on both
  `/withdraw` and `/deposit` with the retry-vs-double-spend semantics spelled out there;
  this document only adds the anti-replay envelope (section 2) around it.

## 8. Offline double-spend cryptography (Chaum-Fiat-Naor family)

New crate: `digicash-offline`. This changes the coin structure and both the withdrawal
and spend protocols - it is not an add-on to the online coin format, it's a different
coin type (its own `scheme_id` range) that coexists with it. A bank can offer both
online-only and offline-capable denominations; a deployment can support only offline
coins if that's the target.

### 8.1 Why v1.0's construction did not work (do not implement it)

v1.0 sketched Chaum-Fiat-Naor cut-and-choose layered directly on RFC 9474 blind signing:
commit to `k` identity-encoding candidate pairs, let the bank open `k/2`, then have the
bank blind-sign the remaining `k/2` via RFC 9474. **This is unsound and must not be
built.** RFC 9474 (RSABSSA) is engineered to remove precisely the two properties
Chaum-Fiat-Naor runs on:

- **Commitment-to-signed-message binding.** RSABSSA blinding is PSS-encode with a random
  salt, then a multiplicative blind with a fresh factor. There is no operation to open a
  blinded message against a prior commitment, and the random salt makes the encoded
  message non-recomputable, so the bank cannot verify that the blinded message it signs
  is the committed unopened set. A malicious wallet passes the cut on `k` honest
  candidates, then submits a blinded message encoding zero identity - and its
  double-spend reveals nothing. The whole deanonymization property evaporates.
- **Homomorphic aggregation.** Classic Chaum-Fiat-Naor blinds *before* the cut and has
  the bank sign the *product* of the unopened blinded values using textbook RSA's
  multiplicative homomorphism. RSABSSA is hardened against exactly that malleability.

This also means v0.2's "no hand-rolled RSA blinding" rule and any faithful
Chaum-Fiat-Naor-on-RSA are mutually exclusive: there is no faithful cut-and-choose on top
of RSABSSA.

### 8.2 Offline is a scheme-selection gate, not a construction to review after

Because the primitive is not settled, offline double-spend is treated exactly like the PQ
backend in section 9: a published, peer-reviewed construction is **selected and reviewed
before implementation**, not sketched here and reviewed afterward. Sequencing step 8 is
"select and implement a chosen construction," and the independent cryptographic review is
the selection gate.

Selection criteria for the construction:

1. **Published and, ideally, with an audited or reference implementation.** If none
   exists (the common case in this space), the construction inherits section 9's
   experimental treatment: feature-flagged, labeled `experimental`, and untrusted for
   value until it has had the same scrutiny RFC 9474 has had.
2. **Homomorphism filter.** Does it require the multiplicative RSA structure that v0.2's
   no-hand-rolled-blinding rule forbids? There is no free option here:
   - *Textbook-RSA Chaum-Fiat-Naor* needs that structure - choosing it means explicitly
     reopening the no-hand-rolled-blinding rule and doing the PSS/malleability/padding
     analysis that rule exists to avoid.
   - *Brands' representation-based e-cash* and *Baldimtsi-Lysyanskaya blind-signature /
     anonymous-credentials-light* do not use RSA blinding at all, so they sidestep the
     contradiction - at the cost of DL/pairing assumptions and the same "no audited Rust
     library" problem as the PQ path.
3. **Challenge binding to the payee.** Whatever is chosen, the spend challenge must be
   bound to the depositing payee, not freely chosen. If the payee "sends a random
   challenge," two colluding payees (or one operator with two accounts) can accept the
   same coin under the same challenge, producing identical transcripts so that no index
   ever holds both identity shares and attribution fails while detection still fires -
   pushing the loss onto the settlement layer. Bind it:
   `challenge = H(payee_account_id ‖ timestamp ‖ nonce)`, and the bank rejects any
   deposited transcript whose challenge does not match the depositing account. (The exact
   form is pinned once the construction is fixed, since the construction determines the
   challenge space.)
4. **Cross-bank attribution needs the transcript.** Detection across banks needs the
   serial; *attribution* needs both spend transcripts, which may sit at two different
   banks. Section 10's shared store must carry transcripts (or transcript digests plus a
   retrieval flow), not just serials.

### 8.3 What offline buys, and what it costs

The payee can accept a coin with no network round-trip to the bank at spend time, at the
cost of a much heavier (interactive) withdrawal and a larger coin. Decide per-denomination
whether that tradeoff is worth it - high-frequency, low-value, offline-desired payments
are the natural fit; there is no requirement every denomination supports this. This module
does not touch production value until it has had independent cryptographic review - same
standard already applied to not hand-rolling RSA blinding.

## 9. Post-quantum blind signatures - honest state of the field

RSA-3072/RFC 9474 is not post-quantum safe. Unlike the RSA case, there is currently no
NIST-standardized, widely-audited blind signature scheme to swap in - FIPS 204/205/206
standardize *regular* signatures (ML-DSA, SLH-DSA, FN-DSA), not blind ones, and naive
blind versions of Fiat-Shamir-style lattice signatures (the natural starting point) are
vulnerable to ROS-type attacks in concurrent settings. Lattice-based blind signature
constructions exist in the research literature (e.g. Hauck-Kiltz-Loss-Nguyen's
Fiat-Shamir-with-aborts based construction, BLAZE, and forward-secure lattice blind
signature variants), but none carries the audit history that `blind-rsa-signatures` /
RFC 9474 does. This is a real constraint, not a hedge - building this into a system
holding real value means accepting a research-grade primitive where the RSA path had a
standardized one.

Design response, so the system isn't blocked on the crypto community finishing this
research:

- `digicash-core` defines a `BlindSignatureScheme` trait: `blind`, `sign`, `unblind`,
  `verify`, parameterized so bank endpoints, coin format, and the bank/wallet protocol
  never need to know which concrete scheme is behind it beyond a `scheme_id` byte and
  a variable-length signature/key blob. `scheme_id` already exists on the coin as of
  v0.2, so adding a scheme is a new enum value plus an implementation, not a wire break.
- v1 ships one implementation: RSA/RFC 9474, as already built (`scheme_id = 0`).
- A second implementation, behind a feature flag and clearly labeled `experimental`,
  wraps a chosen published lattice-based blind signature construction. This is a real
  implementation task, but it is cryptographic research integration, not library
  plumbing - it needs someone to implement the published scheme precisely against its
  security proof, and it needs independent cryptographic review before any deployment
  trusts it with value, exactly like section 8's offline scheme.
- **Hybrid dual-issue is require-both, not accept-either.** During a migration window a
  coin is signed under both RSA and the lattice scheme, and a verifier requires *both*
  signatures to be valid for the window's coins. Accept-either would make the weaker
  scheme the only real security (an attacker who breaks one just presents that one), so
  it is prohibited during the hybrid window. After cutover the policy becomes
  accept-new-scheme-only. Same pattern as hybrid classical/PQ TLS certificates.
- This module does not get marked production-ready by fiat. It's ready when it's had
  the same level of scrutiny RFC 9474 has had - track that honestly rather than
  shipping an unaudited PQ primitive as the default.

## 10. Multi-bank interop and settlement

- **Bank registry.** A permissioned registry of member banks, each publishing its
  current denomination public keys (and its `scheme_id` support) under a trust anchor.
  This is standalone within digicash - a small append-only registry service/store (its
  own component, `digicash-registry`), not a dependency on any other project.
  Registration, key rotation, revocation, and per-issuer exposure caps (below) are events
  written to this registry.
- **Cross-bank deposit.** A coin issued by Bank A can be deposited at Bank B once Bank B
  trusts Bank A (per the registry) and can verify the coin's signature against Bank A's
  published key for that denomination/scheme. Bank B credits the depositor immediately -
  bearer-cash finality is preserved - and now holds a receivable against Bank A.
- **Shared spent-serial + transcript registry - required, not optional, the moment two
  banks accept the same issuer's coins.** A single bank's local `spent_serials` set is no
  longer sufficient: a double-spend fanned across two different banks within a settlement
  window is invisible to either bank's local check alone. This needs a shared, replicated
  store across all member banks, checked synchronously at deposit time. For offline coins
  it must carry the spend **transcript (or a transcript digest with a retrieval/arbitration
  flow), not just the serial** - because cross-bank attribution needs both transcripts,
  which otherwise sit at two different institutions, and a serial-only store detects the
  double-spend but can never attribute it, gutting section 8's value in the multi-bank
  case. Within digicash's scope this is a small dedicated replicated service (e.g. a
  Raft-replicated store, since the trust set is the member banks themselves and BFT is
  not necessarily required if membership is permissioned and banks are not treated as
  Byzantine toward each other - worth an explicit decision here rather than assuming BFT
  by default).
- **Settlement.** Periodic netting between bank pairs (or through a central settlement
  service): Bank B batches everything it deposited that was issued by Bank A during a
  window, submits it as a settlement claim, and real reserves move from Bank A to Bank
  B for the net amount. Settlement claims are recorded in `digicash-registry`'s ledger
  component - auditable, append-only, multisig'd if multiple signers are required per
  bank - all built within this project, no external system assumed.
- **Per-issuer exposure caps.** Bank B gives depositors immediate finality while its
  receivable against Bank A grows until the next netting; if A defaults mid-window, B
  eats the full outstanding amount. So the registry publishes (at least the existence of)
  a per-issuer exposure cap: a maximum outstanding receivable, past which B stops
  accepting A's coins until settlement clears. The cap *mechanism* (registry-published
  value, enforced at deposit time) is in scope; the cap *value* is a deployment/policy
  decision, consistent with how this document fences KYC and funding policy.
- **Admission to the registry** (which banks are allowed to join) is a governance
  question, not an engineering one - the mechanism for registering, rotating, and
  revoking is what this section specifies; who gets admitted is decided outside this
  document.

## 11. Denomination handling and change

The prototype's greedy decomposition can only pay amounts the wallet holds exact coins
for; there is no change-making. Production must resolve this explicitly rather than
inherit the gap silently:

- **Online coins:** a spend that the local stock cannot cover exactly is made exact by
  round-tripping through the bank - deposit the oversized coin(s) and re-withdraw the
  target amount plus change as fresh coins. This preserves unlinkability (fresh blind
  signatures) at the cost of a bank round-trip, which the online model already assumes.
- **Offline coins (section 8):** the round-trip fallback defeats the entire point of
  offline spend (no bank at spend time). Offline denominations therefore require **exact
  denomination availability by design** - the wallet must pre-provision the coins it
  expects to need offline, and a spend it cannot cover exactly simply cannot be made
  offline. State this as a product constraint of offline denominations, not a bug.

## 12. Wallet-side storage

The wallet holds bearer instruments. For a production bearer system this cannot be
plaintext coin files:

- The local coin store is encrypted at rest (key derived from an operator/user secret,
  not stored beside the ciphertext). Disk loss without the key is not value loss to a
  thief, only to the owner.
- Backup guidance is part of the product: an unbacked coin store means disk failure is
  money loss, since the bank cannot reissue a coin it already blind-signed (it never saw
  the serial). Encrypted backups, and for higher-value holdings a re-withdraw-to-fresh-
  wallet migration path, are specified rather than left to the user to discover after a
  loss.

## 13. Sequencing

This is not "rewrite everything at once." Suggested order, each step still one unit +
test + commit:
1. Postgres migration for accounts + spent_serials, atomicity/idempotency tests ported;
   `spent_serials` on the unique-constraint + `ON CONFLICT` path (section 4).
2. Account signing-key auth (Ed25519) with the canonical anti-replay envelope
   (section 2), **behind TLS from the start** - there is no window where auth runs over
   plaintext transport. (v1.0 split these into steps 2 and 3; they are one unit.)
3. KMS or HSM integration for denomination keys, migrating off plaintext key files, with
   the section 4.1 withdraw state machine (the two are coupled: KMS separation is what
   makes the state machine necessary).
4. Operator-authenticated ledger endpoints (section 2.1), replacing demo `POST /accounts`.
5. Audit trail + structured logging + metrics (section 6).
6. Rate limiting and abuse resistance (section 7).
7. `BlindSignatureScheme` trait extraction in `digicash-core` (needed before either
   section 9's PQ backend or any scheme-plurality in section 10 makes sense) - refactor,
   not new crypto, so it's safe to do early.
8. `digicash-offline` (section 8): **select** a published construction, review it as the
   selection gate, then implement coin structure, withdrawal, interactive spend, and
   double-spend attribution. Not "implement the sketch, review later" - there is no sketch
   to implement.
9. Lattice-based blind signature backend (section 9), experimental flag, same review bar
   as step 8.
10. Bank registry (`digicash-registry`) + cross-bank verification + shared
    spent-serial/transcript store + settlement with exposure caps (section 10) -
    standalone within digicash.
11. Denomination change handling and encrypted wallet storage (sections 11, 12).
12. Launch readiness review - auth, TLS, key management, audit, abuse resistance,
    offline crypto review, PQ backend review, and interop/settlement all in place and
    tested under load.
