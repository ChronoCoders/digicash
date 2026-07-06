-- digicash multi-bank registry schema (production-spec v1.4 section 10): permissioned
-- member banks, the shared spent-serial + transcript store, per-issuer exposure caps,
-- receivables, and the append-only settlement claim ledger.

-- Member banks (and the bootstrapped admin). The pubkey is the Ed25519 request-signing key
-- (section 2), not for coin verification.
CREATE TABLE members (
    bank_id  TEXT    PRIMARY KEY,
    pubkey   BYTEA   NOT NULL,
    is_admin BOOLEAN NOT NULL DEFAULT FALSE
);

-- Shared spent-serial store. The primary key is the unique constraint that makes the
-- cross-bank check-and-insert atomic; first_bank_id/first_transcript record the first
-- depositor for attribution.
CREATE TABLE serials (
    denomination_cents BIGINT   NOT NULL,
    scheme_id          SMALLINT NOT NULL,
    serial_hex         TEXT     NOT NULL,
    first_bank_id      TEXT     NOT NULL,
    first_transcript   TEXT     NOT NULL,
    first_seen_at      BIGINT   NOT NULL,
    PRIMARY KEY (denomination_cents, scheme_id, serial_hex)
);

-- Every submitted transcript digest, append-only. On a serial collision both banks' digests
-- are here, retrievable for bank-level attribution.
CREATE TABLE transcripts (
    id                 BIGSERIAL PRIMARY KEY,
    denomination_cents BIGINT    NOT NULL,
    scheme_id          SMALLINT  NOT NULL,
    serial_hex         TEXT      NOT NULL,
    bank_id            TEXT      NOT NULL,
    transcript         TEXT      NOT NULL,
    seen_at            BIGINT    NOT NULL
);
CREATE INDEX transcripts_serial_idx
    ON transcripts (denomination_cents, scheme_id, serial_hex);

-- Per (issuing_bank_id, depositing_bank_id) exposure cap: the maximum outstanding receivable
-- the depositing bank will hold against the issuer before rejecting further deposits.
CREATE TABLE exposure_caps (
    issuing_bank_id    TEXT   NOT NULL,
    depositing_bank_id TEXT   NOT NULL,
    cap_cents          BIGINT NOT NULL CHECK (cap_cents >= 0),
    PRIMARY KEY (issuing_bank_id, depositing_bank_id)
);

-- Outstanding receivable of the depositing bank against the issuing bank, accumulated at
-- deposit and reset at settlement.
CREATE TABLE receivables (
    issuing_bank_id    TEXT   NOT NULL,
    depositing_bank_id TEXT   NOT NULL,
    amount_cents       BIGINT NOT NULL DEFAULT 0 CHECK (amount_cents >= 0),
    PRIMARY KEY (issuing_bank_id, depositing_bank_id)
);

-- Append-only settlement claim ledger: one row per netted (issuing, depositing) pair per
-- settlement window.
CREATE TABLE settlement_claims (
    id                 BIGSERIAL PRIMARY KEY,
    issuing_bank_id    TEXT      NOT NULL,
    depositing_bank_id TEXT      NOT NULL,
    net_amount_cents   BIGINT    NOT NULL,
    window_end         BIGINT    NOT NULL,
    created_at         BIGINT    NOT NULL
);

-- Anti-replay nonce store for the registry's Ed25519 request auth (section 2).
CREATE TABLE nonce_store (
    nonce      TEXT   PRIMARY KEY,
    expires_at BIGINT NOT NULL
);
CREATE INDEX nonce_store_expires_at_idx ON nonce_store (expires_at);
