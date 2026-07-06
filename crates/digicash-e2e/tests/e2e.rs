//! End-to-end tests: a real `digicash-bank` process serving wallets over HTTP.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use digicash_wallet::{BankClient, Wallet};
use tempfile::TempDir;

/// A spawned `digicash-bank` process, killed on drop. The caller owns the data and key
/// directories (so a restart can reuse the same data dir).
struct BankProcess {
    child: Child,
    url: String,
}

impl BankProcess {
    /// Spawn the bank binary on a free port against `db_dir`/`key_dir` and block until it
    /// answers `GET /denominations`.
    fn spawn(db_dir: &Path, key_dir: &Path) -> BankProcess {
        let addr = format!("127.0.0.1:{}", free_port());
        let url = format!("http://{addr}");
        let child = Command::new(bank_binary())
            .env("DIGICASH_ADDR", &addr)
            .env("DIGICASH_DB", db_dir)
            .env("DIGICASH_KEYS", key_dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn bank process (build it with `cargo build -p digicash-bank`)");
        let bank = BankProcess { child, url };
        bank.wait_ready();
        bank
    }

    fn url(&self) -> &str {
        &self.url
    }

    fn wait_ready(&self) {
        let client = BankClient::new(self.url.clone());
        let deadline = Instant::now() + Duration::from_secs(120);
        while client.denominations().is_err() {
            assert!(
                Instant::now() < deadline,
                "bank at {} did not become ready within 120s",
                self.url
            );
            std::thread::sleep(Duration::from_millis(500));
        }
    }
}

impl Drop for BankProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local addr")
        .port()
}

fn bank_binary() -> PathBuf {
    let mut path = std::env::current_exe().expect("current exe path");
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    let mut bin = path.join("digicash-bank");
    if cfg!(windows) {
        bin.set_extension("exe");
    }
    bin
}

/// A shared, persistent key directory so the 14-key startup generation runs at most once
/// per machine (until the temp dir is cleared) instead of on every bank spawn. The data
/// directory is always fresh per test, so this shares only signing keys, never ledger state.
fn shared_key_dir() -> &'static Path {
    static KEYS: OnceLock<PathBuf> = OnceLock::new();
    KEYS.get_or_init(|| {
        let dir = std::env::temp_dir().join("digicash-e2e-shared-keys");
        std::fs::create_dir_all(&dir).expect("create shared key dir");
        let warmup_db = TempDir::new().expect("warmup db tempdir");
        let _warm = BankProcess::spawn(warmup_db.path(), &dir);
        dir
    })
    .as_path()
}

fn open_wallet(bank_url: &str, store_dir: &Path) -> Wallet {
    Wallet::open(bank_url.to_string(), store_dir).expect("open wallet")
}

#[test]
fn bank_spawns_responds_and_shuts_down() {
    let db = TempDir::new().expect("db tempdir");
    let bank = BankProcess::spawn(db.path(), shared_key_dir());

    let client = BankClient::new(bank.url().to_string());
    let denoms = client
        .denominations()
        .expect("GET /denominations should respond");
    assert_eq!(
        denoms.denominations.len(),
        digicash_proto::DENOMINATIONS.len(),
        "bank should publish one key per configured denomination"
    );

    drop(bank);
}

#[test]
fn two_accounts_created_with_expected_balances() {
    let db = TempDir::new().expect("db tempdir");
    let bank = BankProcess::spawn(db.path(), shared_key_dir());
    let store_a = TempDir::new().expect("store a");
    let store_b = TempDir::new().expect("store b");

    let wallet_a = open_wallet(bank.url(), store_a.path());
    let wallet_b = open_wallet(bank.url(), store_b.path());
    wallet_a.create_account("wallet-a", 1000).expect("create wallet-a");
    wallet_b.create_account("wallet-b", 0).expect("create wallet-b");

    assert_eq!(wallet_a.balance().expect("balance a").balance_cents, 1000);
    assert_eq!(wallet_b.balance().expect("balance b").balance_cents, 0);

    // Verify directly against the live bank as well.
    let client = BankClient::new(bank.url().to_string());
    assert_eq!(client.balance("wallet-a").expect("get a").balance_cents, 1000);
    assert_eq!(client.balance("wallet-b").expect("get b").balance_cents, 0);
}

#[test]
fn full_flow_withdraw_spend_deposit() {
    let db = TempDir::new().expect("db tempdir");
    let bank = BankProcess::spawn(db.path(), shared_key_dir());
    let store_a = TempDir::new().expect("store a");
    let store_b = TempDir::new().expect("store b");
    let bundle_dir = TempDir::new().expect("bundle dir");

    let wallet_a = open_wallet(bank.url(), store_a.path());
    let wallet_b = open_wallet(bank.url(), store_b.path());
    wallet_a.create_account("wallet-a", 1000).expect("create wallet-a");
    wallet_b.create_account("wallet-b", 0).expect("create wallet-b");

    // A withdraws 576, which must decompose to 512 + 64.
    let coins = wallet_a.withdraw(576).expect("withdraw");
    let mut denoms: Vec<u64> = coins.iter().map(|c| c.denomination_cents).collect();
    denoms.sort_unstable();
    assert_eq!(denoms, vec![64, 512], "576 must decompose to 512 + 64");

    // A spends 576 to a bundle file, out of band (no bank contact).
    let bundle = bundle_dir.path().join("bundle.json");
    wallet_a.spend(576, &bundle).expect("spend");

    // B deposits the received bundle without ever sharing A's store.
    let outcomes = wallet_b.deposit(&bundle).expect("deposit");
    assert_eq!(outcomes.len(), 2);
    assert!(
        outcomes.iter().all(|o| o.accepted),
        "every coin should be accepted: {outcomes:?}"
    );

    assert_eq!(
        wallet_a.balance().expect("balance a").balance_cents,
        1000 - 576
    );
    assert_eq!(wallet_b.balance().expect("balance b").balance_cents, 576);

    let client = BankClient::new(bank.url().to_string());
    assert_eq!(client.balance("wallet-a").expect("get a").balance_cents, 424);
    assert_eq!(client.balance("wallet-b").expect("get b").balance_cents, 576);
}

#[test]
fn spent_serials_survive_bank_restart() {
    let db = TempDir::new().expect("db tempdir");
    let store_a = TempDir::new().expect("store a");
    let store_b = TempDir::new().expect("store b");
    let bundle_dir = TempDir::new().expect("bundle dir");
    let bundle = bundle_dir.path().join("bundle.json");

    // Initial flow: A withdraws, spends to a bundle, B deposits it.
    {
        let bank = BankProcess::spawn(db.path(), shared_key_dir());
        let wallet_a = open_wallet(bank.url(), store_a.path());
        let wallet_b = open_wallet(bank.url(), store_b.path());
        wallet_a.create_account("wallet-a", 1000).expect("create wallet-a");
        wallet_b.create_account("wallet-b", 0).expect("create wallet-b");
        wallet_a.withdraw(576).expect("withdraw");
        wallet_a.spend(576, &bundle).expect("spend");
        let outcomes = wallet_b.deposit(&bundle).expect("deposit");
        assert!(
            outcomes.iter().all(|o| o.accepted),
            "initial deposit must be accepted"
        );
        assert_eq!(wallet_b.balance().expect("balance b").balance_cents, 576);
        // Block end: the bank process is killed and the wallet stores are released.
    }

    // Restart the bank as a new process against the same data directory.
    let bank = BankProcess::spawn(db.path(), shared_key_dir());
    let wallet_b = open_wallet(bank.url(), store_b.path());

    // spent_serials survived the restart: the same bundle is a double-spend on every coin.
    let replay = wallet_b.deposit(&bundle).expect("re-deposit after restart");
    assert_eq!(replay.len(), 2);
    assert!(
        replay
            .iter()
            .all(|o| o.reason == Some(digicash_proto::DepositRejection::DoubleSpend)),
        "every coin must be rejected as a double-spend after restart: {replay:?}"
    );
    assert_eq!(
        wallet_b.balance().expect("balance b after replay").balance_cents,
        576,
        "rejected replay must not credit the account again"
    );
}

#[test]
fn tampered_coin_signature_is_rejected() {
    let db = TempDir::new().expect("db tempdir");
    let bank = BankProcess::spawn(db.path(), shared_key_dir());
    let store_a = TempDir::new().expect("store a");
    let store_b = TempDir::new().expect("store b");
    let wallet_a = open_wallet(bank.url(), store_a.path());
    let wallet_b = open_wallet(bank.url(), store_b.path());
    wallet_a.create_account("wallet-a", 500).expect("create wallet-a");
    wallet_b.create_account("wallet-b", 0).expect("create wallet-b");

    let mut coin = wallet_a
        .withdraw(64)
        .expect("withdraw")
        .pop()
        .expect("one coin");
    coin.signature[0] ^= 0x01;

    let client = BankClient::new(bank.url().to_string());
    let resp = client
        .deposit(&digicash_proto::DepositRequest {
            coin,
            account_id: "wallet-b".to_string(),
            request_id: "tampered".to_string(),
        })
        .expect("deposit call");
    assert_eq!(
        resp.reason,
        Some(digicash_proto::DepositRejection::InvalidSignature)
    );
    assert_eq!(client.balance("wallet-b").expect("balance b").balance_cents, 0);
}

#[test]
fn withdraw_beyond_balance_is_rejected() {
    let db = TempDir::new().expect("db tempdir");
    let bank = BankProcess::spawn(db.path(), shared_key_dir());
    let store_a = TempDir::new().expect("store a");
    let wallet_a = open_wallet(bank.url(), store_a.path());
    wallet_a.create_account("wallet-a", 500).expect("create wallet-a");

    // 1024 decomposes to a single 1024-cent coin, exceeding the 500-cent balance.
    let result = wallet_a.withdraw(1024);
    assert!(
        matches!(result, Err(digicash_wallet::WalletError::Http { .. })),
        "withdraw beyond balance must be rejected by the bank: {result:?}"
    );
    assert_eq!(
        wallet_a.balance().expect("balance a").balance_cents,
        500,
        "a rejected withdraw must not debit the account"
    );
}

#[test]
fn unknown_denomination_is_rejected() {
    let db = TempDir::new().expect("db tempdir");
    let bank = BankProcess::spawn(db.path(), shared_key_dir());
    let store_a = TempDir::new().expect("store a");
    let wallet_a = open_wallet(bank.url(), store_a.path());
    wallet_a.create_account("wallet-a", 500).expect("create wallet-a");

    // 100 cents is not a power of two, so the bank has no key for it.
    let client = BankClient::new(bank.url().to_string());
    let result = client.withdraw(&digicash_proto::WithdrawRequest {
        account_id: "wallet-a".to_string(),
        request_id: "unknown-denom".to_string(),
        denomination_cents: 100,
        blinded_message: vec![0u8; 8],
    });
    assert!(
        matches!(result, Err(digicash_wallet::WalletError::Http { .. })),
        "unknown denomination must be rejected: {result:?}"
    );
    assert_eq!(
        wallet_a.balance().expect("balance a").balance_cents,
        500,
        "a rejected withdraw must not debit the account"
    );
}
