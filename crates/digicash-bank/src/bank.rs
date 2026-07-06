use std::path::Path;

use digicash_core::DenominationPublicKey;
use digicash_proto::BalanceResponse;

use crate::error::BankError;
use crate::keys::KeyStore;

const ACCOUNTS_TREE: &str = "accounts";
const SPENT_TREE: &str = "spent_serials";

/// The bank: a sled-backed account ledger and spent-serial store, plus an in-memory
/// denomination key store loaded from a key directory at startup.
pub struct Bank {
    db: sled::Db,
    accounts: sled::Tree,
    spent: sled::Tree,
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
        let keys = KeyStore::load_or_create(key_dir.as_ref(), denominations)?;
        Ok(Self {
            db,
            accounts,
            spent,
            keys,
        })
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

#[cfg(test)]
mod tests {
    use super::{spent_key, Bank};
    use tempfile::TempDir;

    const DENOMS: &[u64] = &[64, 128];

    fn open_bank(tmp: &TempDir) -> Bank {
        Bank::open(tmp.path().join("db"), tmp.path().join("keys"), DENOMS)
            .expect("bank should open")
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
}
