use std::collections::HashMap;
use std::path::Path;

use digicash_core::{
    blind, unblind, verify, BlindSignature, DefaultRng, DenominationPublicKey, Serial,
    SCHEME_ID_RSA_DETERMINISTIC,
};
use digicash_proto::{BalanceResponse, Coin, CreateAccountRequest, WithdrawRequest, DENOMINATIONS};

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

    /// Withdraw `amount_cents`, decomposing it greedily into denomination coins. Each coin
    /// is blinded, signed by the bank, unblinded, verified locally, and stored.
    pub fn withdraw(&self, amount_cents: u64) -> Result<Vec<Coin>, WalletError> {
        let account_id = self.store.account_id()?.ok_or(WalletError::NoAccount)?;
        let keys = self.bank_public_keys()?;
        let mut coins = Vec::new();
        for denomination_cents in decompose(amount_cents) {
            let pk = keys
                .get(&denomination_cents)
                .ok_or(WalletError::UnknownDenomination(denomination_cents))?;
            let serial = Serial::generate()?;
            let blinding = blind(pk, &mut DefaultRng, &serial)?;
            let response = self.client.withdraw(&WithdrawRequest {
                account_id: account_id.clone(),
                request_id: new_request_id()?,
                denomination_cents,
                blinded_message: blinding.blind_message.0.clone(),
            })?;
            let signature =
                unblind(pk, &BlindSignature(response.blind_signature), &blinding, &serial)?;
            verify(pk, &serial, &signature)?;
            let coin = Coin {
                scheme_id: SCHEME_ID_RSA_DETERMINISTIC,
                denomination_cents,
                serial_number: *serial.as_bytes(),
                signature: signature.0,
            };
            self.store.put_coin(&coin)?;
            coins.push(coin);
        }
        Ok(coins)
    }

    /// Every coin currently held locally.
    pub fn stored_coins(&self) -> Result<Vec<Coin>, WalletError> {
        self.store.list_coins()
    }

    /// Fetch and parse the bank's denomination public keys (scheme 0 only), keyed by
    /// denomination.
    fn bank_public_keys(&self) -> Result<HashMap<u64, DenominationPublicKey>, WalletError> {
        let response = self.client.denominations()?;
        let mut keys = HashMap::new();
        for key in response.denominations {
            if key.scheme_id != SCHEME_ID_RSA_DETERMINISTIC {
                continue;
            }
            let pk = DenominationPublicKey::from_spki(&key.public_key_spki)
                .map_err(|e| WalletError::KeyParse(e.to_string()))?;
            keys.insert(key.denomination_cents, pk);
        }
        Ok(keys)
    }
}

/// Greedy powers-of-two decomposition, largest denomination first. Since the denomination
/// set includes 1, every amount decomposes exactly; amounts above the largest denomination
/// use it repeatedly.
fn decompose(amount_cents: u64) -> Vec<u64> {
    let mut remaining = amount_cents;
    let mut coins = Vec::new();
    for &denomination in DENOMINATIONS.iter().rev() {
        while remaining >= denomination {
            coins.push(denomination);
            remaining -= denomination;
        }
    }
    coins
}

/// A fresh, unique request id (128 random bits, hex-encoded) for withdraw idempotency.
fn new_request_id() -> Result<String, WalletError> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
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

    #[test]
    fn decompose_is_greedy_powers_of_two() {
        assert_eq!(super::decompose(576), vec![512, 64]);
        assert_eq!(super::decompose(0), Vec::<u64>::new());
        assert_eq!(super::decompose(1), vec![1]);
        assert_eq!(super::decompose(7), vec![4, 2, 1]);
        // amounts above the largest denomination repeat it
        assert_eq!(super::decompose(8192 + 8192 + 1), vec![8192, 8192, 1]);
    }

    #[test]
    fn withdraw_decomposes_and_stores_verifiable_coins() {
        use digicash_core::{verify, DenominationPublicKey, Serial, Signature};

        let (url, _bank) = spawn_test_bank(&[64, 512]);
        let store = TempDir::new().expect("store tempdir");
        let wallet = Wallet::open(url.clone(), store.path().join("store")).expect("wallet open");
        wallet.create_account("alice", 1000).expect("account");

        let coins = wallet.withdraw(576).expect("withdraw");
        let mut denoms: Vec<u64> = coins.iter().map(|c| c.denomination_cents).collect();
        denoms.sort_unstable();
        assert_eq!(denoms, vec![64, 512], "wrong denomination set");

        let mut stored: Vec<u64> = wallet
            .stored_coins()
            .expect("stored")
            .iter()
            .map(|c| c.denomination_cents)
            .collect();
        stored.sort_unstable();
        assert_eq!(stored, vec![64, 512], "coins not stored locally");

        let published = crate::BankClient::new(url)
            .denominations()
            .expect("denominations");
        for coin in &coins {
            let entry = published
                .denominations
                .iter()
                .find(|k| k.denomination_cents == coin.denomination_cents)
                .expect("published key");
            let pk = DenominationPublicKey::from_spki(&entry.public_key_spki).expect("spki");
            verify(
                &pk,
                &Serial::from_bytes(coin.serial_number),
                &Signature(coin.signature.clone()),
            )
            .expect("coin must verify against the bank key");
        }

        assert_eq!(
            wallet.balance().expect("balance").balance_cents,
            1000 - 576,
            "account not debited by the withdrawn amount"
        );
    }
}
