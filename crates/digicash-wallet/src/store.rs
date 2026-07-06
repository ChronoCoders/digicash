use std::path::Path;

use digicash_proto::Coin;

use crate::error::WalletError;

const COINS_TREE: &str = "coins";
const META_TREE: &str = "meta";
const ACCOUNT_ID_KEY: &[u8] = b"account_id";

/// The wallet's local coin store, backed by sled. Coins are bearer instruments, keyed by
/// their 32-byte serial number, and survive restarts. The meta tree holds the wallet's
/// account id.
pub struct Store {
    db: sled::Db,
    coins: sled::Tree,
    meta: sled::Tree,
}

impl Store {
    /// Open (or create) the store at `path`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, WalletError> {
        let db = sled::open(path)?;
        let coins = db.open_tree(COINS_TREE)?;
        let meta = db.open_tree(META_TREE)?;
        Ok(Self { db, coins, meta })
    }

    /// Record this wallet's account id.
    pub fn set_account_id(&self, account_id: &str) -> Result<(), WalletError> {
        self.meta.insert(ACCOUNT_ID_KEY, account_id.as_bytes())?;
        self.db.flush()?;
        Ok(())
    }

    /// This wallet's account id, if one has been created.
    pub fn account_id(&self) -> Result<Option<String>, WalletError> {
        match self.meta.get(ACCOUNT_ID_KEY)? {
            Some(bytes) => Ok(Some(
                String::from_utf8(bytes.to_vec()).map_err(|_| WalletError::CorruptAccountId)?,
            )),
            None => Ok(None),
        }
    }

    /// Store a coin, keyed by its serial number, and flush for durability.
    pub fn put_coin(&self, coin: &Coin) -> Result<(), WalletError> {
        let bytes = serde_json::to_vec(coin)?;
        self.coins.insert(coin.serial_number, bytes)?;
        self.db.flush()?;
        Ok(())
    }

    /// Retrieve a coin by its serial number.
    pub fn get_coin(&self, serial: &[u8; 32]) -> Result<Option<Coin>, WalletError> {
        match self.coins.get(serial)? {
            Some(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Every coin currently held.
    pub fn list_coins(&self) -> Result<Vec<Coin>, WalletError> {
        let mut coins = Vec::new();
        for entry in self.coins.iter() {
            let (_serial, bytes) = entry?;
            coins.push(serde_json::from_slice(&bytes)?);
        }
        Ok(coins)
    }

    /// Remove a coin by its serial number, returning whether it was present.
    pub fn remove_coin(&self, serial: &[u8; 32]) -> Result<bool, WalletError> {
        let removed = self.coins.remove(serial)?.is_some();
        self.db.flush()?;
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::Store;
    use digicash_proto::Coin;
    use tempfile::TempDir;

    fn sample_coin() -> Coin {
        Coin {
            scheme_id: 0,
            denomination_cents: 64,
            serial_number: [9u8; 32],
            signature: vec![1, 2, 3, 4],
        }
    }

    #[test]
    fn coin_survives_reopen() {
        let tmp = TempDir::new().expect("tempdir");
        let coin = sample_coin();
        {
            let store = Store::open(tmp.path().join("wallet")).expect("open");
            store.put_coin(&coin).expect("put");
        }

        let store = Store::open(tmp.path().join("wallet")).expect("reopen");
        let got = store
            .get_coin(&[9u8; 32])
            .expect("get")
            .expect("coin present after reopen");
        assert_eq!(got, coin);
        assert!(
            store.get_coin(&[0u8; 32]).expect("get missing").is_none(),
            "unexpected coin for an unknown serial"
        );
    }
}
