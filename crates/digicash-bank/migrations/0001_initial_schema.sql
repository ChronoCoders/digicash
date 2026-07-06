-- Initial digicash bank schema (production-spec v1.3 section 4): the ledger and protocol
-- state that moved off sled. Signing keys stay on disk as files.

CREATE TABLE accounts (
    account_id    TEXT   PRIMARY KEY,
    balance_cents BIGINT NOT NULL CHECK (balance_cents >= 0)
);

-- Registered Ed25519 signing keys (section 2). Separate from accounts: a wallet registers
-- its key before the account ledger row exists.
CREATE TABLE identities (
    account_id TEXT  PRIMARY KEY,
    pubkey     BYTEA NOT NULL
);

-- Spent coin serials. The primary key is the unique constraint that makes the deposit
-- check-and-insert atomic against a concurrent inserter (section 4).
CREATE TABLE spent_serials (
    scheme_id          SMALLINT NOT NULL,
    denomination_cents BIGINT   NOT NULL,
    serial_number      BYTEA    NOT NULL,
    request_id         TEXT     NOT NULL,
    PRIMARY KEY (scheme_id, denomination_cents, serial_number)
);

-- Withdraw state machine (section 4.1), keyed by request_id. The blind signature is
-- persisted at the `signed` transition so a retry replays it and never re-signs.
CREATE TABLE withdraw_states (
    request_id         TEXT     PRIMARY KEY,
    state              TEXT     NOT NULL
        CHECK (state IN ('pending', 'signed', 'completed', 'compensated')),
    account_id         TEXT     NOT NULL,
    denomination_cents BIGINT   NOT NULL,
    blinded_message    BYTEA    NOT NULL,
    blind_signature    BYTEA
);

-- Deposit idempotency index, keyed by request_id, so a retry replays instead of being read
-- as a double-spend and a request_id reused for a different coin is caught.
CREATE TABLE deposits (
    request_id         TEXT     PRIMARY KEY,
    scheme_id          SMALLINT NOT NULL,
    denomination_cents BIGINT   NOT NULL,
    serial_number      BYTEA    NOT NULL,
    account_id         TEXT     NOT NULL
);

-- Anti-replay nonce store (section 2), with an expiry column purged on startup and
-- periodically.
CREATE TABLE nonce_store (
    nonce      TEXT   PRIMARY KEY,
    expires_at BIGINT NOT NULL
);
CREATE INDEX nonce_store_expires_at_idx ON nonce_store (expires_at);
