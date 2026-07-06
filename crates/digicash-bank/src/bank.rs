use std::path::Path;

use digicash_core::{
    ensure_supported_scheme, sign_blinded, verify, BlindMessage, DenominationPublicKey, Serial,
    Signature, SCHEME_ID_RSA_DETERMINISTIC,
};
use digicash_proto::{
    BalanceResponse, DepositRejection, DepositRequest, DepositResponse, WithdrawRequest,
    WithdrawResponse,
};
use serde::{Deserialize, Serialize};
use sled::transaction::{abort, TransactionError};
use sled::Transactional;

use crate::error::BankError;
use crate::keys::KeyStore;

const ACCOUNTS_TREE: &str = "accounts";
const SPENT_TREE: &str = "spent_serials";
const WITHDRAWALS_TREE: &str = "withdrawals";
const DEPOSITS_TREE: &str = "deposits";

/// Persisted state of a withdrawal, keyed by `request_id`. Drives the crash-recoverable
/// state machine (spec v0.3 section 6.1).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
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

/// A withdrawal record. Stores the blinded message so a `Pending` withdrawal can be signed
/// during startup recovery, and the blind signature once produced so retries never re-sign.
#[derive(Debug, Serialize, Deserialize)]
struct WithdrawalRecord {
    state: WithdrawState,
    account_id: String,
    denomination_cents: u64,
    blinded_message: Vec<u8>,
    blind_signature: Option<Vec<u8>>,
}

/// A record of an accepted deposit, keyed by `request_id`, so a retry with the same
/// `request_id` replays instead of being read as a double-spend, and a `request_id` reused
/// for a different coin is caught.
#[derive(Debug, Serialize, Deserialize)]
struct DepositRecord {
    scheme_id: u8,
    denomination_cents: u64,
    serial_number: [u8; 32],
    account_id: String,
}

/// Outcome of the atomic deposit transaction. Rejections here are normal results carried
/// back in [`DepositResponse`], not errors.
enum DepositOutcome {
    Accepted,
    Replay,
    DoubleSpend,
    RequestIdReuse,
}

/// The bank: a sled-backed account ledger, spent-serial store, withdrawal state machine,
/// and deposit idempotency index, plus an in-memory denomination key store loaded from a
/// key directory at startup.
pub struct Bank {
    db: sled::Db,
    accounts: sled::Tree,
    spent: sled::Tree,
    withdrawals: sled::Tree,
    deposits: sled::Tree,
    keys: KeyStore,
}

impl Bank {
    /// Open (or create) the bank's state: sled database at `db_path`, denomination keys in
    /// `key_dir` (one per denomination, generated on first run), for each of `denominations`.
    pub fn open(
        db_path: impl AsRef<Path>,
        key_dir: impl AsRef<Path>,
        denominations: &[u64],
    ) -> Result<Self, BankError> {
        let db = sled::open(db_path)?;
        let accounts = db.open_tree(ACCOUNTS_TREE)?;
        let spent = db.open_tree(SPENT_TREE)?;
        let withdrawals = db.open_tree(WITHDRAWALS_TREE)?;
        let deposits = db.open_tree(DEPOSITS_TREE)?;
        let keys = KeyStore::load_or_create(key_dir.as_ref(), denominations)?;
        let bank = Self {
            db,
            accounts,
            spent,
            withdrawals,
            deposits,
            keys,
        };
        bank.recover_withdrawals()?;
        Ok(bank)
    }

    /// Flush all pending writes to disk. Callers rely on this for durability at points the
    /// protocol requires it (for example after a debit, before signing).
    pub fn flush(&self) -> Result<(), BankError> {
        self.db.flush()?;
        Ok(())
    }

    /// Create an account with an admin-credited starting balance.
    ///
    /// Demo-only: this credit is not backed by any real funding and is not a fiat ramp.
    /// The insert is atomic, so a concurrent duplicate create is rejected, not silently
    /// overwritten.
    pub fn create_account(
        &self,
        account_id: &str,
        initial_balance_cents: u64,
    ) -> Result<BalanceResponse, BankError> {
        let created = self.accounts.compare_and_swap(
            account_id.as_bytes(),
            None as Option<&[u8]>,
            Some(initial_balance_cents.to_be_bytes().to_vec()),
        )?;
        if created.is_err() {
            return Err(BankError::AccountExists(account_id.to_string()));
        }
        self.db.flush()?;
        Ok(BalanceResponse {
            account_id: account_id.to_string(),
            balance_cents: initial_balance_cents,
        })
    }

    /// The balance of `account_id`, or `None` if the account does not exist.
    pub fn balance(&self, account_id: &str) -> Result<Option<u64>, BankError> {
        match self.accounts.get(account_id.as_bytes())? {
            Some(bytes) => Ok(Some(decode_balance(account_id, &bytes)?)),
            None => Ok(None),
        }
    }

    /// Whether a coin serial has already been spent under `(scheme, denomination)`.
    pub fn is_serial_spent(
        &self,
        scheme: u8,
        denomination_cents: u64,
        serial: &[u8; 32],
    ) -> Result<bool, BankError> {
        Ok(self
            .spent
            .contains_key(spent_key(scheme, denomination_cents, serial))?)
    }

    /// The public key for `(denomination_cents, scheme_id)`, or `None` if the bank does not
    /// serve that pair. Clients use this to verify coins locally.
    pub fn denomination_public_key(
        &self,
        denomination_cents: u64,
        scheme: u8,
    ) -> Option<&DenominationPublicKey> {
        self.keys.get(denomination_cents, scheme).map(|kp| &kp.pk)
    }

    /// Withdraw one coin of `denomination_cents` (scheme 0).
    ///
    /// Debits the account, signs the wallet's blinded message with the denomination key,
    /// and returns the blind signature. `request_id` is an idempotency key: a retry returns
    /// the original blind signature without debiting again. If signing fails after the
    /// debit, the debit is compensated before the error is returned.
    pub fn withdraw(&self, req: &WithdrawRequest) -> Result<WithdrawResponse, BankError> {
        if let Some(record) = self.load_record(&req.request_id)? {
            return self.resume_withdraw(&req.request_id, record);
        }
        if self
            .keys
            .get(req.denomination_cents, SCHEME_ID_RSA_DETERMINISTIC)
            .is_none()
        {
            return Err(BankError::UnknownDenomination(req.denomination_cents));
        }
        self.debit_and_record_pending(req)?;
        let signature = self.finalize_withdraw(
            &req.request_id,
            &req.account_id,
            req.denomination_cents,
            &req.blinded_message,
        )?;
        Ok(WithdrawResponse {
            blind_signature: signature,
        })
    }

    fn resume_withdraw(
        &self,
        request_id: &str,
        mut record: WithdrawalRecord,
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
                    record.state = WithdrawState::Completed;
                    self.store_record(request_id, &record)?;
                    self.db.flush()?;
                }
                Ok(WithdrawResponse {
                    blind_signature: signature,
                })
            }
            WithdrawState::Pending => {
                let signature = self.finalize_withdraw(
                    request_id,
                    &record.account_id,
                    record.denomination_cents,
                    &record.blinded_message,
                )?;
                Ok(WithdrawResponse {
                    blind_signature: signature,
                })
            }
            WithdrawState::Compensated => {
                Err(BankError::WithdrawPreviouslyFailed(request_id.to_string()))
            }
        }
    }

    /// Sign the blinded message and drive the record `Signed` then `Completed`; on a signing
    /// failure, compensate the debit and report it.
    fn finalize_withdraw(
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
                let signed = WithdrawalRecord {
                    state: WithdrawState::Signed,
                    account_id: account_id.to_string(),
                    denomination_cents,
                    blinded_message: blinded_message.to_vec(),
                    blind_signature: Some(signature.clone()),
                };
                self.store_record(request_id, &signed)?;
                self.db.flush()?;
                let completed = WithdrawalRecord {
                    state: WithdrawState::Completed,
                    ..signed
                };
                self.store_record(request_id, &completed)?;
                self.db.flush()?;
                Ok(signature)
            }
            Err(e) => {
                self.compensate(request_id, account_id, denomination_cents, blinded_message)?;
                Err(BankError::WithdrawFailed {
                    request_id: request_id.to_string(),
                    message: e.to_string(),
                })
            }
        }
    }

    /// Atomically debit the account and write the `Pending` record, then flush for
    /// durability so a crash cannot lose the debit without a record to recover from.
    fn debit_and_record_pending(&self, req: &WithdrawRequest) -> Result<(), BankError> {
        let pending = WithdrawalRecord {
            state: WithdrawState::Pending,
            account_id: req.account_id.clone(),
            denomination_cents: req.denomination_cents,
            blinded_message: req.blinded_message.clone(),
            blind_signature: None,
        };
        let record_bytes = encode_record(&req.request_id, &pending)?;
        let account_id = req.account_id.as_str();
        let request_id = req.request_id.as_str();
        let denom = req.denomination_cents;
        let outcome: Result<(), TransactionError<BankError>> = (&self.accounts, &self.withdrawals)
            .transaction(|(accounts, withdrawals)| {
                let Some(bytes) = accounts.get(account_id.as_bytes())? else {
                    return abort(BankError::AccountNotFound(account_id.to_string()));
                };
                let balance = match <[u8; 8]>::try_from(bytes.as_ref()) {
                    Ok(a) => u64::from_be_bytes(a),
                    Err(_) => {
                        return abort(BankError::MalformedBalance {
                            account_id: account_id.to_string(),
                            found: bytes.len(),
                        })
                    }
                };
                if balance < denom {
                    return abort(BankError::InsufficientBalance {
                        account_id: account_id.to_string(),
                        balance,
                        requested: denom,
                    });
                }
                accounts.insert(account_id.as_bytes(), &(balance - denom).to_be_bytes()[..])?;
                withdrawals.insert(request_id.as_bytes(), record_bytes.as_slice())?;
                Ok(())
            });
        outcome.map_err(txn_err)?;
        self.db.flush()?;
        Ok(())
    }

    /// Reverse the debit and mark the withdrawal `Compensated`, atomically.
    fn compensate(
        &self,
        request_id: &str,
        account_id: &str,
        denomination_cents: u64,
        blinded_message: &[u8],
    ) -> Result<(), BankError> {
        let record = WithdrawalRecord {
            state: WithdrawState::Compensated,
            account_id: account_id.to_string(),
            denomination_cents,
            blinded_message: blinded_message.to_vec(),
            blind_signature: None,
        };
        let record_bytes = encode_record(request_id, &record)?;
        let outcome: Result<(), TransactionError<BankError>> = (&self.accounts, &self.withdrawals)
            .transaction(|(accounts, withdrawals)| {
                let balance = match accounts.get(account_id.as_bytes())? {
                    Some(bytes) => match <[u8; 8]>::try_from(bytes.as_ref()) {
                        Ok(a) => u64::from_be_bytes(a),
                        Err(_) => {
                            return abort(BankError::MalformedBalance {
                                account_id: account_id.to_string(),
                                found: bytes.len(),
                            })
                        }
                    },
                    None => 0,
                };
                let Some(restored) = balance.checked_add(denomination_cents) else {
                    return abort(BankError::BalanceOverflow(account_id.to_string()));
                };
                accounts.insert(account_id.as_bytes(), &restored.to_be_bytes()[..])?;
                withdrawals.insert(request_id.as_bytes(), record_bytes.as_slice())?;
                Ok(())
            });
        outcome.map_err(txn_err)?;
        self.db.flush()?;
        Ok(())
    }

    /// Drive every non-terminal withdrawal forward at startup: sign pending ones (over the
    /// persisted blinded message) or compensate if that fails, and complete signed ones.
    fn recover_withdrawals(&self) -> Result<(), BankError> {
        let mut to_resume = Vec::new();
        for entry in self.withdrawals.iter() {
            let (key, value) = entry?;
            let request_id = String::from_utf8(key.to_vec()).map_err(|e| {
                BankError::MalformedRecord {
                    request_id: "<non-utf8>".to_string(),
                    message: format!("request_id key not UTF-8: {e}"),
                }
            })?;
            let record = decode_record(&request_id, &value)?;
            if matches!(record.state, WithdrawState::Pending | WithdrawState::Signed) {
                to_resume.push((request_id, record));
            }
        }
        for (request_id, mut record) in to_resume {
            match record.state {
                WithdrawState::Pending => {
                    tracing::warn!(request_id = %request_id, "recovering pending withdrawal");
                    if let Err(e) = self.finalize_withdraw(
                        &request_id,
                        &record.account_id,
                        record.denomination_cents,
                        &record.blinded_message,
                    ) {
                        tracing::warn!(request_id = %request_id, error = %e, "pending withdrawal compensated during recovery");
                    }
                }
                WithdrawState::Signed => {
                    record.state = WithdrawState::Completed;
                    self.store_record(&request_id, &record)?;
                    self.db.flush()?;
                }
                WithdrawState::Completed | WithdrawState::Compensated => {}
            }
        }
        Ok(())
    }

    fn store_record(&self, request_id: &str, record: &WithdrawalRecord) -> Result<(), BankError> {
        let bytes = encode_record(request_id, record)?;
        self.withdrawals.insert(request_id.as_bytes(), bytes)?;
        Ok(())
    }

    fn load_record(&self, request_id: &str) -> Result<Option<WithdrawalRecord>, BankError> {
        match self.withdrawals.get(request_id.as_bytes())? {
            Some(bytes) => Ok(Some(decode_record(request_id, &bytes)?)),
            None => Ok(None),
        }
    }

    /// Deposit a coin, crediting `account_id`.
    ///
    /// Verifies the signature under the coin's `(denomination, scheme_id)` key, then
    /// atomically checks the serial against the spent set and, if fresh, records it and
    /// credits the account. A retry with the same `request_id` and coin replays; a
    /// different `request_id` for an already-spent serial is a double-spend. Rejections are
    /// returned in the response, not as errors.
    pub fn deposit(&self, req: &DepositRequest) -> Result<DepositResponse, BankError> {
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
        if self.balance(&req.account_id)?.is_none() {
            return Ok(reject(DepositRejection::UnknownAccount));
        }
        Ok(match self.commit_deposit(req)? {
            DepositOutcome::Accepted | DepositOutcome::Replay => DepositResponse {
                accepted: true,
                reason: None,
            },
            DepositOutcome::DoubleSpend => reject(DepositRejection::DoubleSpend),
            DepositOutcome::RequestIdReuse => reject(DepositRejection::RequestIdReuse),
        })
    }

    /// Atomically apply a deposit: idempotency check by `request_id`, double-spend check by
    /// serial, and on success record the serial and credit the account, all in one sled
    /// transaction.
    fn commit_deposit(&self, req: &DepositRequest) -> Result<DepositOutcome, BankError> {
        let coin = &req.coin;
        let request_id = req.request_id.as_str();
        let account_id = req.account_id.as_str();
        let denom = coin.denomination_cents;
        let serial_k = spent_key(coin.scheme_id, denom, &coin.serial_number);
        let record = DepositRecord {
            scheme_id: coin.scheme_id,
            denomination_cents: denom,
            serial_number: coin.serial_number,
            account_id: account_id.to_string(),
        };
        let record_bytes = serde_json::to_vec(&record).map_err(|e| BankError::MalformedRecord {
            request_id: request_id.to_string(),
            message: e.to_string(),
        })?;

        let outcome: Result<DepositOutcome, TransactionError<BankError>> =
            (&self.spent, &self.deposits, &self.accounts).transaction(
                |(spent, deposits, accounts)| {
                    if let Some(existing) = deposits.get(request_id.as_bytes())? {
                        let prior: DepositRecord = match serde_json::from_slice(&existing) {
                            Ok(r) => r,
                            Err(e) => {
                                return abort(BankError::MalformedRecord {
                                    request_id: request_id.to_string(),
                                    message: e.to_string(),
                                })
                            }
                        };
                        if prior.scheme_id == coin.scheme_id
                            && prior.denomination_cents == denom
                            && prior.serial_number == coin.serial_number
                        {
                            return Ok(DepositOutcome::Replay);
                        }
                        return Ok(DepositOutcome::RequestIdReuse);
                    }
                    if spent.get(&serial_k[..])?.is_some() {
                        return Ok(DepositOutcome::DoubleSpend);
                    }
                    let Some(bal_bytes) = accounts.get(account_id.as_bytes())? else {
                        return abort(BankError::AccountNotFound(account_id.to_string()));
                    };
                    let balance = match <[u8; 8]>::try_from(bal_bytes.as_ref()) {
                        Ok(a) => u64::from_be_bytes(a),
                        Err(_) => {
                            return abort(BankError::MalformedBalance {
                                account_id: account_id.to_string(),
                                found: bal_bytes.len(),
                            })
                        }
                    };
                    let Some(credited) = balance.checked_add(denom) else {
                        return abort(BankError::BalanceOverflow(account_id.to_string()));
                    };
                    accounts.insert(account_id.as_bytes(), &credited.to_be_bytes()[..])?;
                    spent.insert(&serial_k[..], request_id.as_bytes())?;
                    deposits.insert(request_id.as_bytes(), record_bytes.as_slice())?;
                    Ok(DepositOutcome::Accepted)
                },
            );
        let outcome = outcome.map_err(txn_err)?;
        self.db.flush()?;
        Ok(outcome)
    }
}

/// Encode a spent-serial key as `scheme_id ‖ denomination_be ‖ serial` (1 + 8 + 32 bytes).
pub(crate) fn spent_key(scheme: u8, denomination_cents: u64, serial: &[u8; 32]) -> [u8; 41] {
    let mut key = [0u8; 41];
    key[0] = scheme;
    key[1..9].copy_from_slice(&denomination_cents.to_be_bytes());
    key[9..41].copy_from_slice(serial);
    key
}

fn decode_balance(account_id: &str, bytes: &[u8]) -> Result<u64, BankError> {
    let arr: [u8; 8] = bytes.try_into().map_err(|_| BankError::MalformedBalance {
        account_id: account_id.to_string(),
        found: bytes.len(),
    })?;
    Ok(u64::from_be_bytes(arr))
}

fn encode_record(request_id: &str, record: &WithdrawalRecord) -> Result<Vec<u8>, BankError> {
    serde_json::to_vec(record).map_err(|e| BankError::MalformedRecord {
        request_id: request_id.to_string(),
        message: e.to_string(),
    })
}

fn decode_record(request_id: &str, bytes: &[u8]) -> Result<WithdrawalRecord, BankError> {
    serde_json::from_slice(bytes).map_err(|e| BankError::MalformedRecord {
        request_id: request_id.to_string(),
        message: e.to_string(),
    })
}

fn txn_err(e: TransactionError<BankError>) -> BankError {
    match e {
        TransactionError::Abort(bank_error) => bank_error,
        TransactionError::Storage(sled_error) => BankError::Sled(sled_error),
    }
}

fn reject(reason: DepositRejection) -> DepositResponse {
    DepositResponse {
        accepted: false,
        reason: Some(reason),
    }
}

#[cfg(test)]
mod tests {
    use super::{spent_key, Bank, WithdrawState};
    use digicash_core::{blind, unblind, verify, BlindSignature, BlindingResult, DefaultRng, Serial};
    use digicash_proto::{Coin, DepositRejection, DepositRequest, WithdrawRequest};
    use tempfile::TempDir;

    const DENOMS: &[u64] = &[64];

    fn open_bank(tmp: &TempDir) -> Bank {
        Bank::open(tmp.path().join("db"), tmp.path().join("keys"), DENOMS)
            .expect("bank should open")
    }

    /// Build a withdraw request with a genuinely blinded serial, returning the serial and
    /// blinding factors so the test can unblind and verify the resulting coin.
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

    #[test]
    fn balances_serials_and_keys_survive_reopen() {
        let tmp = TempDir::new().expect("tempdir");
        let serial = [42u8; 32];

        let pk_der_before;
        {
            let bank = open_bank(&tmp);
            bank.create_account("alice", 5_000).expect("create account");
            // Record a spent serial through the private tree; the deposit path (unit 4)
            // writes it atomically, but here we only need persistence.
            bank.spent
                .insert(spent_key(0, 64, &serial), b"req-x".as_slice())
                .expect("insert spent");
            pk_der_before = bank
                .denomination_public_key(64, 0)
                .expect("key present")
                .to_der()
                .expect("der");
            bank.flush().expect("flush");
        }

        let bank = open_bank(&tmp);
        assert_eq!(bank.balance("alice").expect("balance"), Some(5_000));
        assert!(bank.is_serial_spent(0, 64, &serial).expect("spent check"));
        let pk_der_after = bank
            .denomination_public_key(64, 0)
            .expect("key present after reopen")
            .to_der()
            .expect("der");
        assert_eq!(
            pk_der_before, pk_der_after,
            "denomination key was regenerated instead of reloaded"
        );
        assert_eq!(
            bank.balance("unknown").expect("balance of missing account"),
            None
        );
    }

    #[test]
    fn duplicate_account_is_rejected() {
        let tmp = TempDir::new().expect("tempdir");
        let bank = open_bank(&tmp);
        bank.create_account("bob", 100).expect("first create");
        let err = bank.create_account("bob", 999).expect_err("duplicate must fail");
        assert!(matches!(err, crate::BankError::AccountExists(id) if id == "bob"));
        assert_eq!(bank.balance("bob").expect("balance"), Some(100));
    }

    #[test]
    fn withdraw_signs_a_verifiable_coin() {
        let tmp = TempDir::new().expect("tempdir");
        let bank = open_bank(&tmp);
        bank.create_account("alice", 1_000).expect("account");
        let (req, serial, blinding) = valid_withdraw(&bank, "alice", "r1", 64);

        let resp = bank.withdraw(&req).expect("withdraw");
        let pk = bank.denomination_public_key(64, 0).expect("key");
        let sig = unblind(pk, &BlindSignature(resp.blind_signature), &blinding, &serial)
            .expect("unblind");
        verify(pk, &serial, &sig).expect("issued signature must verify");
        assert_eq!(bank.balance("alice").expect("balance"), Some(1_000 - 64));
    }

    #[test]
    fn withdraw_retry_is_idempotent() {
        let tmp = TempDir::new().expect("tempdir");
        let bank = open_bank(&tmp);
        bank.create_account("alice", 1_000).expect("account");
        let (req, _serial, _blinding) = valid_withdraw(&bank, "alice", "r1", 64);

        let first = bank.withdraw(&req).expect("first withdraw");
        let second = bank.withdraw(&req).expect("retry withdraw");
        assert_eq!(
            first.blind_signature, second.blind_signature,
            "retry returned a different signature"
        );
        assert_eq!(
            bank.balance("alice").expect("balance"),
            Some(1_000 - 64),
            "retry double-debited"
        );
    }

    #[test]
    fn withdraw_compensates_on_signing_failure() {
        let tmp = TempDir::new().expect("tempdir");
        let bank = open_bank(&tmp);
        bank.create_account("alice", 1_000).expect("account");
        // A blinded message of the wrong length makes signing fail after the debit.
        let req = WithdrawRequest {
            account_id: "alice".to_string(),
            request_id: "rbad".to_string(),
            denomination_cents: 64,
            blinded_message: vec![1, 2, 3],
        };
        match bank.withdraw(&req) {
            Err(crate::BankError::WithdrawFailed { .. }) => {}
            other => panic!("expected WithdrawFailed, got {other:?}"),
        }
        assert_eq!(
            bank.balance("alice").expect("balance"),
            Some(1_000),
            "debit was not compensated"
        );
    }

    #[test]
    fn recovery_completes_a_pending_withdrawal() {
        let tmp = TempDir::new().expect("tempdir");

        let bank = open_bank(&tmp);
        bank.create_account("alice", 1_000).expect("account");
        let (req, serial, blinding) = valid_withdraw(&bank, "alice", "rp", 64);
        // Simulate a crash after the debit + pending write, before signing.
        bank.debit_and_record_pending(&req).expect("debit and pending");
        assert_eq!(bank.balance("alice").expect("balance"), Some(1_000 - 64));
        bank.flush().expect("flush");
        drop(bank);

        // Reopen: recovery signs and completes the pending withdrawal.
        let bank = open_bank(&tmp);
        let record = bank.load_record("rp").expect("load").expect("record present");
        assert_eq!(record.state, WithdrawState::Completed);
        let pk = bank.denomination_public_key(64, 0).expect("key");
        let sig_bytes = record.blind_signature.clone().expect("signature");
        let sig = unblind(pk, &BlindSignature(sig_bytes), &blinding, &serial).expect("unblind");
        verify(pk, &serial, &sig).expect("recovered signature must verify");
        assert_eq!(
            bank.balance("alice").expect("balance"),
            Some(1_000 - 64),
            "completed withdrawal must stay debited"
        );
    }

    /// Withdraw and unblind a full coin, ready to deposit.
    fn mint_coin(bank: &Bank, account: &str, request_id: &str, denom: u64) -> Coin {
        let (req, serial, blinding) = valid_withdraw(bank, account, request_id, denom);
        let resp = bank.withdraw(&req).expect("withdraw");
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

    #[test]
    fn deposit_accepts_a_valid_coin_and_credits_the_payee() {
        let tmp = TempDir::new().expect("tempdir");
        let bank = open_bank(&tmp);
        bank.create_account("alice", 1_000).expect("alice");
        bank.create_account("bob", 0).expect("bob");
        let coin = mint_coin(&bank, "alice", "w1", 64);

        let req = DepositRequest {
            coin,
            account_id: "bob".to_string(),
            request_id: "d1".to_string(),
        };
        let resp = bank.deposit(&req).expect("deposit");
        assert!(resp.accepted && resp.reason.is_none());
        assert_eq!(bank.balance("bob").expect("balance"), Some(64));
    }

    #[test]
    fn deposit_replay_with_same_request_id_credits_once() {
        let tmp = TempDir::new().expect("tempdir");
        let bank = open_bank(&tmp);
        bank.create_account("alice", 1_000).expect("alice");
        bank.create_account("bob", 0).expect("bob");
        let coin = mint_coin(&bank, "alice", "w1", 64);
        let req = DepositRequest {
            coin,
            account_id: "bob".to_string(),
            request_id: "d1".to_string(),
        };

        let first = bank.deposit(&req).expect("first deposit");
        let second = bank.deposit(&req).expect("replay deposit");
        assert!(first.accepted);
        assert!(second.accepted && second.reason.is_none(), "replay was not accepted");
        assert_eq!(
            bank.balance("bob").expect("balance"),
            Some(64),
            "replay credited twice"
        );
    }

    #[test]
    fn deposit_same_coin_different_request_id_is_double_spend() {
        let tmp = TempDir::new().expect("tempdir");
        let bank = open_bank(&tmp);
        bank.create_account("alice", 1_000).expect("alice");
        bank.create_account("bob", 0).expect("bob");
        let coin = mint_coin(&bank, "alice", "w1", 64);

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
        assert!(bank.deposit(&first).expect("first").accepted);
        let resp = bank.deposit(&again).expect("second");
        assert_eq!(resp.reason, Some(DepositRejection::DoubleSpend));
        assert_eq!(
            bank.balance("bob").expect("balance"),
            Some(64),
            "double-spend credited a second time"
        );
    }

    #[test]
    fn deposit_with_tampered_signature_is_rejected() {
        let tmp = TempDir::new().expect("tempdir");
        let bank = open_bank(&tmp);
        bank.create_account("alice", 1_000).expect("alice");
        bank.create_account("bob", 0).expect("bob");
        let mut coin = mint_coin(&bank, "alice", "w1", 64);
        coin.signature[0] ^= 0x01;

        let req = DepositRequest {
            coin,
            account_id: "bob".to_string(),
            request_id: "d1".to_string(),
        };
        let resp = bank.deposit(&req).expect("deposit");
        assert_eq!(resp.reason, Some(DepositRejection::InvalidSignature));
        assert_eq!(bank.balance("bob").expect("balance"), Some(0));
    }

    #[test]
    fn deposit_reuse_of_request_id_for_a_different_coin_is_rejected() {
        let tmp = TempDir::new().expect("tempdir");
        let bank = open_bank(&tmp);
        bank.create_account("alice", 1_000).expect("alice");
        bank.create_account("bob", 0).expect("bob");
        let coin1 = mint_coin(&bank, "alice", "w1", 64);
        let coin2 = mint_coin(&bank, "alice", "w2", 64);

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
        assert!(bank.deposit(&first).expect("first").accepted);
        let resp = bank.deposit(&reuse).expect("reuse");
        assert_eq!(resp.reason, Some(DepositRejection::RequestIdReuse));
    }
}
