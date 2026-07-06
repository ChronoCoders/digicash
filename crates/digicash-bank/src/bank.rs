use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use deadpool_postgres::Pool;
use digicash_core::{
    ensure_supported_scheme, sign_blinded, verify, BlindMessage, DenominationPublicKey,
    IdentityPublicKey, Serial, Signature, IDENTITY_PUBLIC_KEY_LEN, SCHEME_ID_RSA_DETERMINISTIC,
};
use digicash_proto::{
    BalanceResponse, DenominationKey, DepositRejection, DepositRequest, DepositResponse,
    WithdrawRequest, WithdrawResponse,
};

use crate::db;
use crate::error::BankError;
use crate::keys::KeyStore;

const NONCES_TREE: &str = "nonces";
const NONCE_DB_DIR: &str = "nonce-db";

/// Prune expired nonces once every this many recorded nonces, bounding the store without an
/// O(n) scan on every request.
const NONCE_PRUNE_INTERVAL: u64 = 1024;

/// State of a withdrawal, keyed by `request_id` (production-spec v1.3 section 4.1).
#[derive(Debug, Clone, Copy, PartialEq)]
enum WithdrawState {
    /// Debit committed, blinded message not yet signed.
    Pending,
    /// Blind signature obtained and persisted; an idempotent retry returns it.
    Signed,
    /// Result returned to the client.
    Completed,
    /// Terminal failure: the debit was reversed by a compensating credit.
    Compensated,
}

impl WithdrawState {
    fn as_str(self) -> &'static str {
        match self {
            WithdrawState::Pending => "pending",
            WithdrawState::Signed => "signed",
            WithdrawState::Completed => "completed",
            WithdrawState::Compensated => "compensated",
        }
    }

    fn parse(value: &str) -> Result<Self, BankError> {
        match value {
            "pending" => Ok(WithdrawState::Pending),
            "signed" => Ok(WithdrawState::Signed),
            "completed" => Ok(WithdrawState::Completed),
            "compensated" => Ok(WithdrawState::Compensated),
            other => Err(BankError::MalformedRecord {
                request_id: "<unknown>".to_string(),
                message: format!("unknown withdraw state {other}"),
            }),
        }
    }
}

/// A withdrawal record read from `withdraw_states`.
#[derive(Debug)]
struct WithdrawalRecord {
    state: WithdrawState,
    account_id: String,
    denomination_cents: u64,
    blinded_message: Vec<u8>,
    blind_signature: Option<Vec<u8>>,
}

/// Outcome of the atomic deposit transaction. Rejections here are normal results carried
/// back in [`DepositResponse`], not errors.
enum DepositOutcome {
    Accepted,
    Replay,
    DoubleSpend,
    RequestIdReuse,
    UnknownAccount,
}

/// The bank: a Postgres-backed account ledger, spent-serial store, withdrawal state machine,
/// and deposit idempotency index (production-spec v1.3 section 4), plus an in-memory
/// denomination key store loaded from a key directory at startup. The anti-replay nonce store
/// is still sled-backed here and moves to Postgres in a later unit.
pub struct Bank {
    pool: Pool,
    nonces: sled::Tree,
    nonce_db: sled::Db,
    nonce_ops: AtomicU64,
    keys: KeyStore,
}

impl Bank {
    /// Connect to Postgres at `database_url`, run schema migrations, load denomination keys
    /// from `key_dir` (generating any that are missing), and open the sled nonce store under
    /// `key_dir`.
    pub async fn connect(
        database_url: &str,
        key_dir: impl AsRef<Path>,
        denominations: &[u64],
    ) -> Result<Self, BankError> {
        let key_dir = key_dir.as_ref();
        db::run_migrations(database_url).await?;
        let pool = db::create_pool(database_url)?;
        let nonce_db = sled::open(key_dir.join(NONCE_DB_DIR))?;
        let nonces = nonce_db.open_tree(NONCES_TREE)?;
        let keys = KeyStore::load_or_create(key_dir, denominations)?;
        Ok(Self {
            pool,
            nonces,
            nonce_db,
            nonce_ops: AtomicU64::new(0),
            keys,
        })
    }

    /// Flush the sled nonce store to disk.
    pub fn flush(&self) -> Result<(), BankError> {
        self.nonce_db.flush()?;
        Ok(())
    }

    /// Create an account with an admin-credited starting balance (demo-only). The insert is
    /// atomic, so a concurrent duplicate create is rejected, not silently overwritten.
    pub async fn create_account(
        &self,
        account_id: &str,
        initial_balance_cents: u64,
    ) -> Result<BalanceResponse, BankError> {
        let balance = to_i64(initial_balance_cents, "initial balance")?;
        let client = self.pool.get().await?;
        let inserted = client
            .execute(
                "INSERT INTO accounts (account_id, balance_cents) VALUES ($1, $2) \
                 ON CONFLICT (account_id) DO NOTHING",
                &[&account_id, &balance],
            )
            .await?;
        if inserted == 0 {
            return Err(BankError::AccountExists(account_id.to_string()));
        }
        Ok(BalanceResponse {
            account_id: account_id.to_string(),
            balance_cents: initial_balance_cents,
        })
    }

    /// The balance of `account_id`, or `None` if the account does not exist.
    pub async fn balance(&self, account_id: &str) -> Result<Option<u64>, BankError> {
        let client = self.pool.get().await?;
        let row = client
            .query_opt(
                "SELECT balance_cents FROM accounts WHERE account_id = $1",
                &[&account_id],
            )
            .await?;
        match row {
            Some(row) => Ok(Some(to_u64(row.get::<_, i64>(0), "balance")?)),
            None => Ok(None),
        }
    }

    /// Register (or replace) the Ed25519 public key `account_id` signs requests with. Registers
    /// once: a second registration for the same account is rejected (spec v1.3 section 2).
    pub async fn register_identity(
        &self,
        account_id: &str,
        public_key: &IdentityPublicKey,
    ) -> Result<(), BankError> {
        let pubkey = public_key.to_bytes().to_vec();
        let client = self.pool.get().await?;
        let inserted = client
            .execute(
                "INSERT INTO identities (account_id, pubkey) VALUES ($1, $2) \
                 ON CONFLICT (account_id) DO NOTHING",
                &[&account_id, &pubkey],
            )
            .await?;
        if inserted == 0 {
            return Err(BankError::IdentityExists(account_id.to_string()));
        }
        Ok(())
    }

    /// The Ed25519 public key registered for `account_id`, or `None` if none is registered.
    pub async fn identity_pubkey(
        &self,
        account_id: &str,
    ) -> Result<Option<IdentityPublicKey>, BankError> {
        let client = self.pool.get().await?;
        let row = client
            .query_opt(
                "SELECT pubkey FROM identities WHERE account_id = $1",
                &[&account_id],
            )
            .await?;
        match row {
            Some(row) => {
                let bytes: Vec<u8> = row.get(0);
                let array: [u8; IDENTITY_PUBLIC_KEY_LEN] =
                    bytes.as_slice().try_into().map_err(|_| BankError::MalformedIdentity {
                        account_id: account_id.to_string(),
                        message: format!(
                            "registered key is {} bytes, expected {IDENTITY_PUBLIC_KEY_LEN}",
                            bytes.len()
                        ),
                    })?;
                Ok(Some(IdentityPublicKey::from_bytes(&array)?))
            }
            None => Ok(None),
        }
    }

    /// Record `nonce` as seen at `now`, returning `true` if fresh and `false` on replay within
    /// `ttl_secs`. Sled-backed here; moves to Postgres in a later unit.
    pub fn check_and_record_nonce(
        &self,
        nonce: &str,
        now: u64,
        ttl_secs: u64,
    ) -> Result<bool, BankError> {
        let expiry = now.saturating_add(ttl_secs).to_be_bytes();
        let key = nonce.as_bytes();
        let outcome: Result<bool, sled::transaction::TransactionError<()>> =
            self.nonces.transaction(|nonces| {
                if let Some(existing) = nonces.get(key)? {
                    if decode_u64(&existing) > now {
                        return Ok(false);
                    }
                }
                nonces.insert(key, &expiry)?;
                Ok(true)
            });
        let fresh = outcome.map_err(|e| match e {
            sled::transaction::TransactionError::Storage(e) => BankError::Sled(e),
            sled::transaction::TransactionError::Abort(()) => {
                BankError::Sled(sled::Error::Unsupported("nonce transaction aborted".to_string()))
            }
        })?;
        self.nonce_db.flush()?;
        if self.nonce_ops.fetch_add(1, Ordering::Relaxed) % NONCE_PRUNE_INTERVAL
            == NONCE_PRUNE_INTERVAL - 1
        {
            self.prune_nonces(now)?;
        }
        Ok(fresh)
    }

    /// Remove every nonce whose window closed at or before `now`.
    fn prune_nonces(&self, now: u64) -> Result<(), BankError> {
        let mut expired = Vec::new();
        for entry in self.nonces.iter() {
            let (k, v) = entry?;
            if decode_u64(&v) <= now {
                expired.push(k.to_vec());
            }
        }
        if expired.is_empty() {
            return Ok(());
        }
        for k in expired {
            self.nonces.remove(k)?;
        }
        self.nonce_db.flush()?;
        Ok(())
    }

    /// Whether a coin serial has already been spent under `(scheme, denomination)`.
    pub async fn is_serial_spent(
        &self,
        scheme: u8,
        denomination_cents: u64,
        serial: &[u8; 32],
    ) -> Result<bool, BankError> {
        let client = self.pool.get().await?;
        let row = client
            .query_opt(
                "SELECT 1 FROM spent_serials \
                 WHERE scheme_id = $1 AND denomination_cents = $2 AND serial_number = $3",
                &[
                    &i16::from(scheme),
                    &to_i64(denomination_cents, "denomination")?,
                    &&serial[..],
                ],
            )
            .await?;
        Ok(row.is_some())
    }

    /// The public key for `(denomination_cents, scheme_id)`, or `None` if the bank does not
    /// serve that pair.
    pub fn denomination_public_key(
        &self,
        denomination_cents: u64,
        scheme: u8,
    ) -> Option<&DenominationPublicKey> {
        self.keys.get(denomination_cents, scheme).map(|kp| &kp.pk)
    }

    /// The bank's denomination public keys as SubjectPublicKeyInfo DER, for publication.
    pub fn published_keys(&self) -> Result<Vec<DenominationKey>, BankError> {
        let mut out = Vec::new();
        for (denom, scheme, pk) in self.keys.public_keys() {
            let public_key_spki = pk.to_spki().map_err(|e| BankError::Key {
                denom,
                scheme,
                message: format!("encode SPKI: {e}"),
            })?;
            out.push(DenominationKey {
                denomination_cents: denom,
                scheme_id: scheme,
                public_key_spki,
            });
        }
        Ok(out)
    }

    /// Withdraw one coin of `denomination_cents` (scheme 0).
    ///
    /// Debits the account and records a `pending` withdrawal atomically, signs the blinded
    /// message, then drives the record to `completed`. `request_id` is an idempotency key: a
    /// retry returns the persisted signature without debiting again. If signing fails after
    /// the debit, the debit is compensated before the error is returned.
    pub async fn withdraw(&self, req: &WithdrawRequest) -> Result<WithdrawResponse, BankError> {
        if let Some(record) = self.load_record(&req.request_id).await? {
            return self.resume_withdraw(&req.request_id, record).await;
        }
        if self
            .keys
            .get(req.denomination_cents, SCHEME_ID_RSA_DETERMINISTIC)
            .is_none()
        {
            return Err(BankError::UnknownDenomination(req.denomination_cents));
        }
        self.debit_and_record_pending(req).await?;
        let signature = self
            .finalize_withdraw(
                &req.request_id,
                &req.account_id,
                req.denomination_cents,
                &req.blinded_message,
            )
            .await?;
        Ok(WithdrawResponse {
            blind_signature: signature,
        })
    }

    async fn resume_withdraw(
        &self,
        request_id: &str,
        record: WithdrawalRecord,
    ) -> Result<WithdrawResponse, BankError> {
        match record.state {
            WithdrawState::Completed | WithdrawState::Signed => {
                let signature = record.blind_signature.clone().ok_or_else(|| {
                    BankError::MalformedRecord {
                        request_id: request_id.to_string(),
                        message: "signed record has no signature".to_string(),
                    }
                })?;
                if record.state == WithdrawState::Signed {
                    self.set_state(request_id, WithdrawState::Completed).await?;
                }
                Ok(WithdrawResponse {
                    blind_signature: signature,
                })
            }
            WithdrawState::Pending => {
                let signature = self
                    .finalize_withdraw(
                        request_id,
                        &record.account_id,
                        record.denomination_cents,
                        &record.blinded_message,
                    )
                    .await?;
                Ok(WithdrawResponse {
                    blind_signature: signature,
                })
            }
            WithdrawState::Compensated => {
                Err(BankError::WithdrawPreviouslyFailed(request_id.to_string()))
            }
        }
    }

    /// Sign the blinded message and drive the record `signed` then `completed`; on a signing
    /// failure, compensate the debit and report it.
    async fn finalize_withdraw(
        &self,
        request_id: &str,
        account_id: &str,
        denomination_cents: u64,
        blinded_message: &[u8],
    ) -> Result<Vec<u8>, BankError> {
        let keypair = self
            .keys
            .get(denomination_cents, SCHEME_ID_RSA_DETERMINISTIC)
            .ok_or(BankError::UnknownDenomination(denomination_cents))?;
        match sign_blinded(&keypair.sk, &BlindMessage(blinded_message.to_vec())) {
            Ok(blind_sig) => {
                let signature = blind_sig.0;
                let client = self.pool.get().await?;
                client
                    .execute(
                        "UPDATE withdraw_states SET state = $1, blind_signature = $2 \
                         WHERE request_id = $3",
                        &[&WithdrawState::Signed.as_str(), &signature, &request_id],
                    )
                    .await?;
                self.set_state(request_id, WithdrawState::Completed).await?;
                Ok(signature)
            }
            Err(e) => {
                self.compensate(request_id, account_id, denomination_cents)
                    .await?;
                Err(BankError::WithdrawFailed {
                    request_id: request_id.to_string(),
                    message: e.to_string(),
                })
            }
        }
    }

    /// Atomically debit the account and write the `pending` record in one transaction, so a
    /// crash can never lose the debit without a record to recover from.
    async fn debit_and_record_pending(&self, req: &WithdrawRequest) -> Result<(), BankError> {
        let denom = to_i64(req.denomination_cents, "denomination")?;
        let mut client = self.pool.get().await?;
        let tx = client.transaction().await?;
        let row = tx
            .query_opt(
                "SELECT balance_cents FROM accounts WHERE account_id = $1 FOR UPDATE",
                &[&req.account_id],
            )
            .await?;
        let Some(row) = row else {
            return Err(BankError::AccountNotFound(req.account_id.clone()));
        };
        let balance: i64 = row.get(0);
        if balance < denom {
            return Err(BankError::InsufficientBalance {
                account_id: req.account_id.clone(),
                balance: to_u64(balance, "balance")?,
                requested: req.denomination_cents,
            });
        }
        tx.execute(
            "UPDATE accounts SET balance_cents = balance_cents - $1 WHERE account_id = $2",
            &[&denom, &req.account_id],
        )
        .await?;
        tx.execute(
            "INSERT INTO withdraw_states \
             (request_id, state, account_id, denomination_cents, blinded_message) \
             VALUES ($1, $2, $3, $4, $5)",
            &[
                &req.request_id,
                &WithdrawState::Pending.as_str(),
                &req.account_id,
                &denom,
                &req.blinded_message,
            ],
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Reverse the debit and mark the withdrawal `compensated`, atomically.
    async fn compensate(
        &self,
        request_id: &str,
        account_id: &str,
        denomination_cents: u64,
    ) -> Result<(), BankError> {
        let denom = to_i64(denomination_cents, "denomination")?;
        let mut client = self.pool.get().await?;
        let tx = client.transaction().await?;
        tx.execute(
            "UPDATE accounts SET balance_cents = balance_cents + $1 WHERE account_id = $2",
            &[&denom, &account_id],
        )
        .await?;
        tx.execute(
            "UPDATE withdraw_states SET state = $1 WHERE request_id = $2",
            &[&WithdrawState::Compensated.as_str(), &request_id],
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn set_state(&self, request_id: &str, state: WithdrawState) -> Result<(), BankError> {
        let client = self.pool.get().await?;
        client
            .execute(
                "UPDATE withdraw_states SET state = $1 WHERE request_id = $2",
                &[&state.as_str(), &request_id],
            )
            .await?;
        Ok(())
    }

    async fn load_record(
        &self,
        request_id: &str,
    ) -> Result<Option<WithdrawalRecord>, BankError> {
        let client = self.pool.get().await?;
        let row = client
            .query_opt(
                "SELECT state, account_id, denomination_cents, blinded_message, blind_signature \
                 FROM withdraw_states WHERE request_id = $1",
                &[&request_id],
            )
            .await?;
        match row {
            Some(row) => Ok(Some(WithdrawalRecord {
                state: WithdrawState::parse(row.get::<_, &str>(0))?,
                account_id: row.get(1),
                denomination_cents: to_u64(row.get::<_, i64>(2), "denomination")?,
                blinded_message: row.get(3),
                blind_signature: row.get(4),
            })),
            None => Ok(None),
        }
    }

    /// Deposit a coin, crediting `account_id`.
    ///
    /// Verifies the signature under the coin's `(denomination, scheme_id)` key, then in one
    /// transaction checks idempotency by `request_id`, does the spent-serial check-and-insert
    /// (unique constraint + `ON CONFLICT DO NOTHING`, credit conditioned on the insert having
    /// happened), and credits the account (production-spec v1.3 section 4). Rejections are
    /// returned in the response, not as errors.
    pub async fn deposit(&self, req: &DepositRequest) -> Result<DepositResponse, BankError> {
        let coin = &req.coin;
        if ensure_supported_scheme(coin.scheme_id).is_err() {
            return Ok(reject(DepositRejection::UnknownScheme));
        }
        let Some(keypair) = self.keys.get(coin.denomination_cents, coin.scheme_id) else {
            return Ok(reject(DepositRejection::UnknownDenomination));
        };
        let serial = Serial::from_bytes(coin.serial_number);
        let signature = Signature(coin.signature.clone());
        if verify(&keypair.pk, &serial, &signature).is_err() {
            return Ok(reject(DepositRejection::InvalidSignature));
        }
        Ok(match self.commit_deposit(req).await? {
            DepositOutcome::Accepted | DepositOutcome::Replay => DepositResponse {
                accepted: true,
                reason: None,
            },
            DepositOutcome::DoubleSpend => reject(DepositRejection::DoubleSpend),
            DepositOutcome::RequestIdReuse => reject(DepositRejection::RequestIdReuse),
            DepositOutcome::UnknownAccount => reject(DepositRejection::UnknownAccount),
        })
    }

    async fn commit_deposit(&self, req: &DepositRequest) -> Result<DepositOutcome, BankError> {
        let coin = &req.coin;
        let scheme = i16::from(coin.scheme_id);
        let denom = to_i64(coin.denomination_cents, "denomination")?;
        let serial = &coin.serial_number[..];
        let mut client = self.pool.get().await?;
        let tx = client.transaction().await?;

        if let Some(row) = tx
            .query_opt(
                "SELECT scheme_id, denomination_cents, serial_number FROM deposits \
                 WHERE request_id = $1",
                &[&req.request_id],
            )
            .await?
        {
            let prior_scheme: i16 = row.get(0);
            let prior_denom: i64 = row.get(1);
            let prior_serial: Vec<u8> = row.get(2);
            let outcome = if prior_scheme == scheme
                && prior_denom == denom
                && prior_serial.as_slice() == serial
            {
                DepositOutcome::Replay
            } else {
                DepositOutcome::RequestIdReuse
            };
            return Ok(outcome);
        }

        let inserted = tx
            .execute(
                "INSERT INTO spent_serials \
                 (scheme_id, denomination_cents, serial_number, request_id) \
                 VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
                &[&scheme, &denom, &serial, &req.request_id],
            )
            .await?;
        if inserted == 0 {
            return Ok(DepositOutcome::DoubleSpend);
        }

        let credited = tx
            .execute(
                "UPDATE accounts SET balance_cents = balance_cents + $1 WHERE account_id = $2",
                &[&denom, &req.account_id],
            )
            .await?;
        if credited == 0 {
            // No such account: undo the spent-serial insert by rolling back the transaction.
            return Ok(DepositOutcome::UnknownAccount);
        }

        tx.execute(
            "INSERT INTO deposits \
             (request_id, scheme_id, denomination_cents, serial_number, account_id) \
             VALUES ($1, $2, $3, $4, $5)",
            &[&req.request_id, &scheme, &denom, &serial, &req.account_id],
        )
        .await?;
        tx.commit().await?;
        Ok(DepositOutcome::Accepted)
    }
}

fn to_i64(value: u64, what: &str) -> Result<i64, BankError> {
    i64::try_from(value)
        .map_err(|_| BankError::ValueRange(format!("{what} {value} exceeds the i64 column range")))
}

fn to_u64(value: i64, what: &str) -> Result<u64, BankError> {
    u64::try_from(value).map_err(|_| BankError::ValueRange(format!("{what} is negative: {value}")))
}

fn decode_u64(bytes: &[u8]) -> u64 {
    <[u8; 8]>::try_from(bytes)
        .map(u64::from_be_bytes)
        .unwrap_or(0)
}

fn reject(reason: DepositRejection) -> DepositResponse {
    DepositResponse {
        accepted: false,
        reason: Some(reason),
    }
}

#[cfg(test)]
mod tests {
    use super::Bank;
    use crate::test_support::TestDatabase;
    use digicash_core::{
        blind, unblind, verify, BlindSignature, BlindingResult, DefaultRng, DenominationPublicKey,
        Serial,
    };
    use digicash_proto::{Coin, DepositRejection, DepositRequest, WithdrawRequest};
    use tempfile::TempDir;

    const DENOMS: &[u64] = &[64];

    /// Connect a bank to a fresh test database, or `None` if `DATABASE_URL` is unset.
    async fn open_bank_with(tmp: &TempDir, denoms: &[u64]) -> Option<(Bank, TestDatabase)> {
        let db = TestDatabase::create().await.expect("test db")?;
        let bank = Bank::connect(db.url(), tmp.path().join("keys"), denoms)
            .await
            .expect("bank connect");
        Some((bank, db))
    }

    macro_rules! bank_or_skip {
        ($tmp:expr, $denoms:expr) => {
            match open_bank_with($tmp, $denoms).await {
                Some(pair) => pair,
                None => {
                    eprintln!("skipping: set DATABASE_URL to a Postgres instance to run this test");
                    return;
                }
            }
        };
    }

    fn valid_withdraw(
        bank: &Bank,
        account: &str,
        request_id: &str,
        denom: u64,
    ) -> (WithdrawRequest, Serial, BlindingResult) {
        let pk = bank.denomination_public_key(denom, 0).expect("denomination key");
        let serial = Serial::generate().expect("serial");
        let blinding = blind(pk, &mut DefaultRng, &serial).expect("blind");
        let req = WithdrawRequest {
            account_id: account.to_string(),
            request_id: request_id.to_string(),
            denomination_cents: denom,
            blinded_message: blinding.blind_message.0.clone(),
        };
        (req, serial, blinding)
    }

    async fn mint_coin(bank: &Bank, account: &str, request_id: &str, denom: u64) -> Coin {
        let (req, serial, blinding) = valid_withdraw(bank, account, request_id, denom);
        let resp = bank.withdraw(&req).await.expect("withdraw");
        let pk = bank.denomination_public_key(denom, 0).expect("key");
        let sig = unblind(pk, &BlindSignature(resp.blind_signature), &blinding, &serial)
            .expect("unblind");
        Coin {
            scheme_id: 0,
            denomination_cents: denom,
            serial_number: *serial.as_bytes(),
            signature: sig.0,
        }
    }

    #[tokio::test]
    async fn account_create_credit_read_and_reconnect() {
        let tmp = TempDir::new().expect("tempdir");
        let (bank, db) = bank_or_skip!(&tmp, DENOMS);

        bank.create_account("alice", 500).await.expect("create");
        assert_eq!(bank.balance("alice").await.expect("balance"), Some(500));

        let err = bank.create_account("alice", 999).await.expect_err("dup must fail");
        assert!(matches!(err, crate::BankError::AccountExists(id) if id == "alice"));
        assert_eq!(bank.balance("nobody").await.expect("missing"), None);

        // Reconnect a new bank to the same database: the account survives.
        drop(bank);
        let reconnected = Bank::connect(db.url(), tmp.path().join("keys2"), DENOMS)
            .await
            .expect("reconnect");
        assert_eq!(reconnected.balance("alice").await.expect("balance"), Some(500));
    }

    #[tokio::test]
    async fn published_keys_round_trip_via_spki() {
        let tmp = TempDir::new().expect("tempdir");
        let (bank, _db) = bank_or_skip!(&tmp, &[64, 512]);
        let published = bank.published_keys().expect("published keys");
        assert_eq!(published.len(), 2);
        for key in &published {
            let parsed =
                DenominationPublicKey::from_spki(&key.public_key_spki).expect("parse spki");
            let expected = bank
                .denomination_public_key(key.denomination_cents, key.scheme_id)
                .expect("key present");
            assert_eq!(
                parsed.to_der().expect("der"),
                expected.to_der().expect("der"),
                "published SPKI did not round-trip"
            );
        }
    }

    #[tokio::test]
    async fn withdraw_signs_a_verifiable_coin() {
        let tmp = TempDir::new().expect("tempdir");
        let (bank, _db) = bank_or_skip!(&tmp, DENOMS);
        bank.create_account("alice", 1_000).await.expect("account");
        let (req, serial, blinding) = valid_withdraw(&bank, "alice", "r1", 64);

        let resp = bank.withdraw(&req).await.expect("withdraw");
        let pk = bank.denomination_public_key(64, 0).expect("key");
        let sig = unblind(pk, &BlindSignature(resp.blind_signature), &blinding, &serial)
            .expect("unblind");
        verify(pk, &serial, &sig).expect("issued signature must verify");
        assert_eq!(bank.balance("alice").await.expect("balance"), Some(1_000 - 64));
    }

    #[tokio::test]
    async fn withdraw_retry_is_idempotent() {
        let tmp = TempDir::new().expect("tempdir");
        let (bank, _db) = bank_or_skip!(&tmp, DENOMS);
        bank.create_account("alice", 1_000).await.expect("account");
        let (req, _serial, _blinding) = valid_withdraw(&bank, "alice", "r1", 64);

        let first = bank.withdraw(&req).await.expect("first");
        let second = bank.withdraw(&req).await.expect("retry");
        assert_eq!(first.blind_signature, second.blind_signature, "retry re-signed");
        assert_eq!(
            bank.balance("alice").await.expect("balance"),
            Some(1_000 - 64),
            "retry double-debited"
        );
    }

    #[tokio::test]
    async fn withdraw_compensates_on_signing_failure() {
        let tmp = TempDir::new().expect("tempdir");
        let (bank, _db) = bank_or_skip!(&tmp, DENOMS);
        bank.create_account("alice", 1_000).await.expect("account");
        let req = WithdrawRequest {
            account_id: "alice".to_string(),
            request_id: "rbad".to_string(),
            denomination_cents: 64,
            blinded_message: vec![1, 2, 3],
        };
        match bank.withdraw(&req).await {
            Err(crate::BankError::WithdrawFailed { .. }) => {}
            other => panic!("expected WithdrawFailed, got {other:?}"),
        }
        assert_eq!(
            bank.balance("alice").await.expect("balance"),
            Some(1_000),
            "debit was not compensated"
        );
    }

    #[tokio::test]
    async fn deposit_accepts_a_valid_coin_and_credits_the_payee() {
        let tmp = TempDir::new().expect("tempdir");
        let (bank, _db) = bank_or_skip!(&tmp, DENOMS);
        bank.create_account("alice", 1_000).await.expect("alice");
        bank.create_account("bob", 0).await.expect("bob");
        let coin = mint_coin(&bank, "alice", "w1", 64).await;

        let resp = bank
            .deposit(&DepositRequest {
                coin,
                account_id: "bob".to_string(),
                request_id: "d1".to_string(),
            })
            .await
            .expect("deposit");
        assert!(resp.accepted && resp.reason.is_none());
        assert_eq!(bank.balance("bob").await.expect("balance"), Some(64));
    }

    #[tokio::test]
    async fn deposit_replay_with_same_request_id_credits_once() {
        let tmp = TempDir::new().expect("tempdir");
        let (bank, _db) = bank_or_skip!(&tmp, DENOMS);
        bank.create_account("alice", 1_000).await.expect("alice");
        bank.create_account("bob", 0).await.expect("bob");
        let coin = mint_coin(&bank, "alice", "w1", 64).await;
        let req = DepositRequest {
            coin,
            account_id: "bob".to_string(),
            request_id: "d1".to_string(),
        };
        assert!(bank.deposit(&req).await.expect("first").accepted);
        assert!(bank.deposit(&req).await.expect("replay").accepted);
        assert_eq!(
            bank.balance("bob").await.expect("balance"),
            Some(64),
            "replay credited twice"
        );
    }

    #[tokio::test]
    async fn deposit_same_coin_different_request_id_is_double_spend() {
        let tmp = TempDir::new().expect("tempdir");
        let (bank, _db) = bank_or_skip!(&tmp, DENOMS);
        bank.create_account("alice", 1_000).await.expect("alice");
        bank.create_account("bob", 0).await.expect("bob");
        let coin = mint_coin(&bank, "alice", "w1", 64).await;

        let first = DepositRequest {
            coin: coin.clone(),
            account_id: "bob".to_string(),
            request_id: "d1".to_string(),
        };
        let again = DepositRequest {
            coin,
            account_id: "bob".to_string(),
            request_id: "d2".to_string(),
        };
        assert!(bank.deposit(&first).await.expect("first").accepted);
        let resp = bank.deposit(&again).await.expect("second");
        assert_eq!(resp.reason, Some(DepositRejection::DoubleSpend));
        assert_eq!(bank.balance("bob").await.expect("balance"), Some(64));
    }

    #[tokio::test]
    async fn deposit_with_tampered_signature_is_rejected() {
        let tmp = TempDir::new().expect("tempdir");
        let (bank, _db) = bank_or_skip!(&tmp, DENOMS);
        bank.create_account("alice", 1_000).await.expect("alice");
        bank.create_account("bob", 0).await.expect("bob");
        let mut coin = mint_coin(&bank, "alice", "w1", 64).await;
        coin.signature[0] ^= 0x01;

        let resp = bank
            .deposit(&DepositRequest {
                coin,
                account_id: "bob".to_string(),
                request_id: "d1".to_string(),
            })
            .await
            .expect("deposit");
        assert_eq!(resp.reason, Some(DepositRejection::InvalidSignature));
        assert_eq!(bank.balance("bob").await.expect("balance"), Some(0));
    }

    #[tokio::test]
    async fn deposit_reuse_of_request_id_for_a_different_coin_is_rejected() {
        let tmp = TempDir::new().expect("tempdir");
        let (bank, _db) = bank_or_skip!(&tmp, DENOMS);
        bank.create_account("alice", 1_000).await.expect("alice");
        bank.create_account("bob", 0).await.expect("bob");
        let coin1 = mint_coin(&bank, "alice", "w1", 64).await;
        let coin2 = mint_coin(&bank, "alice", "w2", 64).await;

        let first = DepositRequest {
            coin: coin1,
            account_id: "bob".to_string(),
            request_id: "d1".to_string(),
        };
        let reuse = DepositRequest {
            coin: coin2,
            account_id: "bob".to_string(),
            request_id: "d1".to_string(),
        };
        assert!(bank.deposit(&first).await.expect("first").accepted);
        let resp = bank.deposit(&reuse).await.expect("reuse");
        assert_eq!(resp.reason, Some(DepositRejection::RequestIdReuse));
    }

    #[tokio::test]
    async fn deposit_to_unknown_account_is_rejected_and_serial_not_spent() {
        let tmp = TempDir::new().expect("tempdir");
        let (bank, _db) = bank_or_skip!(&tmp, DENOMS);
        bank.create_account("alice", 1_000).await.expect("alice");
        let coin = mint_coin(&bank, "alice", "w1", 64).await;
        let serial = coin.serial_number;

        let resp = bank
            .deposit(&DepositRequest {
                coin,
                account_id: "ghost".to_string(),
                request_id: "d1".to_string(),
            })
            .await
            .expect("deposit");
        assert_eq!(resp.reason, Some(DepositRejection::UnknownAccount));
        // The failed deposit rolled back: the serial is not marked spent.
        assert!(!bank.is_serial_spent(0, 64, &serial).await.expect("spent check"));
    }
}
