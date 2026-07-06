use std::path::Path;

use digicash_proto::{BalanceResponse, CreateAccountRequest};

use crate::client::BankClient;
use crate::error::WalletError;
use crate::store::Store;

/// A wallet: a bank client plus a local coin store.
pub struct Wallet {
    client: BankClient,
    store: Store,
}

impl Wallet {
    /// Open a wallet talking to the bank at `bank_url`, with its store at `store_path`.
    pub fn open(bank_url: String, store_path: impl AsRef<Path>) -> Result<Self, WalletError> {
        Ok(Self {
            client: BankClient::new(bank_url),
            store: Store::open(store_path)?,
        })
    }

    /// Create this wallet's account with a starting balance and record the id locally.
    pub fn create_account(
        &self,
        account_id: &str,
        initial_balance_cents: u64,
    ) -> Result<BalanceResponse, WalletError> {
        let response = self.client.create_account(&CreateAccountRequest {
            account_id: account_id.to_string(),
            initial_balance_cents,
        })?;
        self.store.set_account_id(account_id)?;
        Ok(response)
    }

    /// The balance of this wallet's account, as reported by the bank.
    pub fn balance(&self) -> Result<BalanceResponse, WalletError> {
        let account_id = self.store.account_id()?.ok_or(WalletError::NoAccount)?;
        self.client.balance(&account_id)
    }
}

#[cfg(test)]
mod tests {
    use super::Wallet;
    use crate::testutil::spawn_test_bank;
    use crate::WalletError;
    use tempfile::TempDir;

    #[test]
    fn create_account_and_read_balance() {
        let (url, _bank) = spawn_test_bank(&[]);
        let store = TempDir::new().expect("store tempdir");
        let wallet = Wallet::open(url, store.path().join("store")).expect("wallet open");

        let created = wallet.create_account("alice", 500).expect("create account");
        assert_eq!(created.account_id, "alice");
        assert_eq!(created.balance_cents, 500);

        let balance = wallet.balance().expect("balance");
        assert_eq!(balance.account_id, "alice");
        assert_eq!(balance.balance_cents, 500);
    }

    #[test]
    fn balance_without_account_errors() {
        let (url, _bank) = spawn_test_bank(&[]);
        let store = TempDir::new().expect("store tempdir");
        let wallet = Wallet::open(url, store.path().join("store")).expect("wallet open");
        assert!(matches!(wallet.balance(), Err(WalletError::NoAccount)));
    }
}
