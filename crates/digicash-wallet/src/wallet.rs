use std::collections::HashMap;
use std::path::Path;

use digicash_core::{
    blind, unblind, verify, BlindSignature, DefaultRng, DenominationPublicKey, Serial,
    SCHEME_ID_RSA_DETERMINISTIC,
};
use digicash_proto::{
    BalanceResponse, Coin, CreateAccountRequest, DepositRejection, DepositRequest, WithdrawRequest,
    DENOMINATIONS,
};

use crate::client::BankClient;
use crate::error::WalletError;
use crate::store::Store;

/// The result of depositing one coin from a bundle.
#[derive(Debug)]
pub struct DepositOutcome {
    pub denomination_cents: u64,
    pub accepted: bool,
    pub reason: Option<DepositRejection>,
}

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

    /// Select coins summing to exactly `amount_cents`, write them as a JSON bundle to
    /// `out_path`, and remove them from the local store. No bank contact. If the local
    /// coins cannot make the amount exactly, no bundle is written and an error reports the
    /// shortfall (no silent rounding or partial spend).
    pub fn spend(&self, amount_cents: u64, out_path: &Path) -> Result<Vec<Coin>, WalletError> {
        let held = self.store.list_coins()?;
        let held_total = held
            .iter()
            .map(|c| c.denomination_cents)
            .fold(0u64, u64::saturating_add);
        let selected =
            select_exact(held, amount_cents).ok_or(WalletError::InsufficientCoins {
                requested: amount_cents,
                held: held_total,
            })?;
        // Write the bundle first (the payee's coins are then preserved on disk), then remove
        // from the local store so the wallet will not re-spend them.
        let bundle = serde_json::to_vec_pretty(&selected)?;
        std::fs::write(out_path, bundle)?;
        for coin in &selected {
            self.store.remove_coin(&coin.serial_number)?;
        }
        Ok(selected)
    }

    /// Deposit every coin in the bundle at `bundle_path` to this wallet's account, returning
    /// the per-coin outcome. Accepted coins credit the account; already-spent serials are
    /// rejected as double-spends.
    pub fn deposit(&self, bundle_path: &Path) -> Result<Vec<DepositOutcome>, WalletError> {
        let account_id = self.store.account_id()?.ok_or(WalletError::NoAccount)?;
        let coins: Vec<Coin> = serde_json::from_slice(&std::fs::read(bundle_path)?)?;
        let mut outcomes = Vec::new();
        for coin in coins {
            let denomination_cents = coin.denomination_cents;
            let response = self.client.deposit(&DepositRequest {
                coin,
                account_id: account_id.clone(),
                request_id: new_request_id()?,
            })?;
            outcomes.push(DepositOutcome {
                denomination_cents,
                accepted: response.accepted,
                reason: response.reason,
            });
        }
        Ok(outcomes)
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

/// Select coins summing to exactly `amount`, greedily largest first. Returns `None` if the
/// coins cannot make the amount exactly. Correct for the powers-of-two denomination set.
fn select_exact(mut coins: Vec<Coin>, amount: u64) -> Option<Vec<Coin>> {
    coins.sort_unstable_by_key(|c| std::cmp::Reverse(c.denomination_cents));
    let mut remaining = amount;
    let mut selected = Vec::new();
    for coin in coins {
        if coin.denomination_cents <= remaining {
            remaining -= coin.denomination_cents;
            selected.push(coin);
            if remaining == 0 {
                break;
            }
        }
    }
    (remaining == 0).then_some(selected)
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

    fn coins_of(denoms: &[u64]) -> Vec<digicash_proto::Coin> {
        denoms
            .iter()
            .map(|&d| digicash_proto::Coin {
                scheme_id: 0,
                denomination_cents: d,
                serial_number: [d as u8; 32],
                signature: vec![],
            })
            .collect()
    }

    #[test]
    fn select_exact_is_greedy_or_none() {
        let selected = super::select_exact(coins_of(&[512, 64]), 576).expect("exact");
        let mut denoms: Vec<u64> = selected.iter().map(|c| c.denomination_cents).collect();
        denoms.sort_unstable();
        assert_eq!(denoms, vec![64, 512]);

        assert!(super::select_exact(coins_of(&[512, 64]), 100).is_none());
        assert!(super::select_exact(coins_of(&[64, 64]), 64).is_some());
        assert!(super::select_exact(coins_of(&[]), 0).expect("empty exact").is_empty());
    }

    #[test]
    fn spend_writes_bundle_and_removes_selected_coins() {
        use digicash_proto::Coin;

        let (url, _bank) = spawn_test_bank(&[64, 512]);
        let store_dir = TempDir::new().expect("store");
        let out_dir = TempDir::new().expect("out");
        let wallet = Wallet::open(url, store_dir.path().join("store")).expect("wallet");
        wallet.create_account("alice", 1000).expect("account");
        wallet.withdraw(576).expect("withdraw"); // coins [512, 64]

        let bundle_path = out_dir.path().join("bundle.json");
        let spent = wallet.spend(512, &bundle_path).expect("spend");
        assert_eq!(spent.len(), 1);
        assert_eq!(spent[0].denomination_cents, 512);

        let bytes = std::fs::read(&bundle_path).expect("read bundle");
        let bundle: Vec<Coin> = serde_json::from_slice(&bytes).expect("parse bundle");
        assert_eq!(bundle.len(), 1);
        assert_eq!(bundle[0].denomination_cents, 512);

        let remaining: Vec<u64> = wallet
            .stored_coins()
            .expect("stored")
            .iter()
            .map(|c| c.denomination_cents)
            .collect();
        assert_eq!(remaining, vec![64], "spent coin not removed, or wrong coin removed");

        match wallet.spend(100, &out_dir.path().join("x.json")) {
            Err(WalletError::InsufficientCoins { requested: 100, .. }) => {}
            other => panic!("expected InsufficientCoins, got {other:?}"),
        }
        assert!(
            !out_dir.path().join("x.json").exists(),
            "a failed spend must not write a bundle"
        );
    }

    #[test]
    fn deposit_accepts_then_rejects_replay() {
        use digicash_proto::DepositRejection;

        let (url, _bank) = spawn_test_bank(&[64, 512]);
        let stores = TempDir::new().expect("stores");
        let out_dir = TempDir::new().expect("out");

        // Payer withdraws and spends a bundle out of band.
        let payer = Wallet::open(url.clone(), stores.path().join("payer")).expect("payer");
        payer.create_account("alice", 1000).expect("alice");
        payer.withdraw(576).expect("withdraw");
        let bundle = out_dir.path().join("bundle.json");
        payer.spend(576, &bundle).expect("spend");

        // Payee deposits the received bundle to its own account.
        let payee = Wallet::open(url, stores.path().join("payee")).expect("payee");
        payee.create_account("bob", 0).expect("bob");
        let outcomes = payee.deposit(&bundle).expect("deposit");
        assert_eq!(outcomes.len(), 2);
        assert!(outcomes.iter().all(|o| o.accepted), "a coin was rejected: {outcomes:?}");
        assert_eq!(payee.balance().expect("balance").balance_cents, 576);

        // Replaying the same bundle: every coin is a double-spend, no extra credit.
        let replay = payee.deposit(&bundle).expect("replay");
        assert!(replay
            .iter()
            .all(|o| !o.accepted && o.reason == Some(DepositRejection::DoubleSpend)));
        assert_eq!(payee.balance().expect("balance").balance_cents, 576);
    }
}
