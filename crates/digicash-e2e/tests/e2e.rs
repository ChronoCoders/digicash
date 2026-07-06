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
