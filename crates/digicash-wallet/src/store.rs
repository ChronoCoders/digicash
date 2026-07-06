use std::path::Path;

use digicash_proto::Coin;

use crate::error::WalletError;

const COINS_TREE: &str = "coins";

/// The wallet's local coin store, backed by sled. Coins are bearer instruments, keyed by
/// their 32-byte serial number, and survive restarts.
pub struct Store {
    db: sled::Db,
    coins: sled::Tree,
}

impl Store {
    /// Open (or create) the store at `path`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, WalletError> {
        let db = sled::open(path)?;
        let coins = db.open_tree(COINS_TREE)?;
        Ok(Self { db, coins })
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
