//! End-to-end tests: a real `digicash-bank` process serving wallets over mutual TLS with
//! Ed25519-signed requests (production-spec v1.2 section 2). The valid flow runs through the
//! `digicash-wallet` library; a small raw signing client drives the anti-replay, tampered
//! signature, and stale timestamp rejections against the live process.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use digicash_core::{canonical_payload, IdentityKeypair};
use digicash_proto::{
    RegisterRequest, RegisterResponse, HEADER_ACCOUNT, HEADER_NONCE, HEADER_SIGNATURE,
    HEADER_TIMESTAMP,
};
use digicash_wallet::Wallet;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore};
use tempfile::TempDir;

/// A spawned `digicash-bank` process, killed on drop. The caller owns the data and key
/// directories (so a restart can reuse the same data dir).
struct BankProcess {
    child: Child,
    api_addr: String,
    enroll_addr: String,
    api_url: String,
    enroll_url: String,
    ca_cert_pem: String,
}

impl BankProcess {
    /// Spawn the bank binary on two free ports against Postgres `database_url` and `key_dir`,
    /// and block until both listeners accept connections, then read the published CA cert.
    fn spawn(database_url: &str, key_dir: &Path) -> BankProcess {
        let api_addr = format!("127.0.0.1:{}", free_port());
        let enroll_addr = format!("127.0.0.1:{}", free_port());
        let child = Command::new(bank_binary())
            .env("DIGICASH_ADDR", &api_addr)
            .env("DIGICASH_ENROLL_ADDR", &enroll_addr)
            .env("DATABASE_URL", database_url)
            .env("DIGICASH_KEYS", key_dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn bank process (build it with `cargo build -p digicash-bank`)");
        let mut bank = BankProcess {
            child,
            api_url: format!("https://{api_addr}"),
            enroll_url: format!("https://{enroll_addr}"),
            api_addr,
            enroll_addr,
            ca_cert_pem: String::new(),
        };
        bank.wait_ready();
        bank.ca_cert_pem = read_ca_cert(key_dir);
        bank
    }

    fn wait_ready(&self) {
        for addr in [&self.api_addr, &self.enroll_addr] {
            let deadline = Instant::now() + Duration::from_secs(120);
            while std::net::TcpStream::connect(addr).is_err() {
                assert!(
                    Instant::now() < deadline,
                    "bank listener {addr} did not become ready within 120s"
                );
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    }
}

impl Drop for BankProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Read the bank's published CA certificate, retrying briefly since it is written just before
/// the listeners bind.
fn read_ca_cert(key_dir: &Path) -> String {
    let path = key_dir.join("ca-cert.pem");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(pem) = std::fs::read_to_string(&path) {
            if pem.contains("BEGIN CERTIFICATE") {
                return pem;
            }
        }
        assert!(Instant::now() < deadline, "CA certificate not published");
        std::thread::sleep(Duration::from_millis(100));
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

/// A shared, persistent key directory so the 14-key startup generation (and the CA key) runs
/// at most once per machine instead of on every bank spawn. The data directory is always
/// fresh per test, so this shares only signing keys, never ledger state.
fn shared_key_dir() -> &'static Path {
    static KEYS: OnceLock<PathBuf> = OnceLock::new();
    KEYS.get_or_init(|| {
        let dir = std::env::temp_dir().join("digicash-e2e-shared-keys-v3");
        std::fs::create_dir_all(&dir).expect("create shared key dir");
        // Reached only after a caller obtained a database URL, so DATABASE_URL is set.
        let warmup_url = fresh_db_url().expect("DATABASE_URL for warmup");
        let _warm = BankProcess::spawn(&warmup_url, &dir);
        dir
    })
    .as_path()
}

/// Create a fresh, migrated Postgres test database and return its URL, or `None` if
/// `DATABASE_URL` is unset (tests skip). Uses the bank's own test-support helper.
fn fresh_db_url() -> Option<String> {
    std::env::var("DATABASE_URL").ok().filter(|u| !u.is_empty())?;
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    runtime.block_on(async {
        digicash_bank::test_support::TestDatabase::create()
            .await
            .expect("create test database")
            .map(|db| db.url().to_string())
    })
}

/// Skip the current test (with a message) unless `DATABASE_URL` is set, otherwise bind a fresh
/// database URL.
macro_rules! db_url_or_skip {
    () => {
        match fresh_db_url() {
            Some(url) => url,
            None => {
                eprintln!(
                    "skipping: set DATABASE_URL to a Postgres instance (e.g. \
                     postgres://user:pass@127.0.0.1:5432/db) to run this test"
                );
                return;
            }
        }
    };
}

/// Open a wallet, register `account` against the running bank (obtaining an mTLS client
/// certificate), and create its account with `balance`.
fn registered_wallet(bank: &BankProcess, store_dir: &Path, account: &str, balance: u64) -> Wallet {
    let wallet = Wallet::open(bank.api_url.clone(), store_dir).expect("open wallet");
    wallet
        .register(account, &bank.ca_cert_pem, &bank.enroll_url)
        .expect("register");
    wallet.create_account(balance).expect("create account");
    wallet
}

#[test]
fn full_flow_withdraw_spend_deposit_over_mtls() {
    let db_url = db_url_or_skip!();
    let bank = BankProcess::spawn(&db_url, shared_key_dir());
    let store_a = TempDir::new().expect("store a");
    let store_b = TempDir::new().expect("store b");
    let bundle_dir = TempDir::new().expect("bundle dir");

    let wallet_a = registered_wallet(&bank, store_a.path(), "wallet-a", 1000);
    let wallet_b = registered_wallet(&bank, store_b.path(), "wallet-b", 0);

    // A withdraws 576 (must decompose to 512 + 64), all requests signed over mTLS.
    let coins = wallet_a.withdraw(576).expect("withdraw");
    let mut denoms: Vec<u64> = coins.iter().map(|c| c.denomination_cents).collect();
    denoms.sort_unstable();
    assert_eq!(denoms, vec![64, 512], "576 must decompose to 512 + 64");

    // A spends 576 to a bundle file (no bank contact), B deposits it to its own account.
    let bundle = bundle_dir.path().join("bundle.json");
    wallet_a.spend(576, &bundle).expect("spend");
    let outcomes = wallet_b.deposit(&bundle).expect("deposit");
    assert_eq!(outcomes.len(), 2);
    assert!(
        outcomes.iter().all(|o| o.accepted),
        "every coin should be accepted: {outcomes:?}"
    );

    assert_eq!(wallet_a.balance().expect("balance a").balance_cents, 424);
    assert_eq!(wallet_b.balance().expect("balance b").balance_cents, 576);
}

#[test]
fn spent_serials_survive_bank_restart() {
    let db_url = db_url_or_skip!();
    let store_a = TempDir::new().expect("store a");
    let store_b = TempDir::new().expect("store b");
    let bundle_dir = TempDir::new().expect("bundle dir");
    let bundle = bundle_dir.path().join("bundle.json");

    {
        let bank = BankProcess::spawn(&db_url, shared_key_dir());
        let wallet_a = registered_wallet(&bank, store_a.path(), "wallet-a", 1000);
        let wallet_b = registered_wallet(&bank, store_b.path(), "wallet-b", 0);
        wallet_a.withdraw(576).expect("withdraw");
        wallet_a.spend(576, &bundle).expect("spend");
        assert!(
            wallet_b.deposit(&bundle).expect("deposit").iter().all(|o| o.accepted),
            "initial deposit must be accepted"
        );
        // Block end: the bank process is killed; the wallet stores persist.
    }

    // Restart against the same Postgres database: spent serials, the withdraw state machine,
    // identities, and the nonce store all survive the new process.
    let bank = BankProcess::spawn(&db_url, shared_key_dir());
    let wallet_b = Wallet::open(bank.api_url.clone(), store_b.path()).expect("reopen wallet b");
    let replay = wallet_b.deposit(&bundle).expect("re-deposit after restart");
    assert!(
        replay
            .iter()
            .all(|o| o.reason == Some(digicash_proto::DepositRejection::DoubleSpend)),
        "every coin must be a double-spend after restart: {replay:?}"
    );
    assert_eq!(
        wallet_b.balance().expect("balance after replay").balance_cents,
        576,
        "a rejected replay must not credit again"
    );
}

#[test]
fn replay_tampered_and_stale_requests_are_rejected() {
    let db_url = db_url_or_skip!();
    let bank = BankProcess::spawn(&db_url, shared_key_dir());
    let client = SignedClient::enroll(&bank, "adversary");

    let now = now_unix();
    // A fresh, well-formed signed balance request is accepted.
    assert_eq!(
        client.balance_status(now, "nonce-first", false),
        200,
        "a valid signed request must be accepted"
    );
    // Replaying the same nonce is rejected.
    assert_eq!(
        client.balance_status(now, "nonce-first", false),
        401,
        "a replayed nonce must be rejected"
    );
    // A tampered signature (fresh nonce) is rejected.
    assert_eq!(
        client.balance_status(now, "nonce-tampered", true),
        401,
        "a tampered signature must be rejected"
    );
    // A stale timestamp (fresh nonce) is rejected.
    assert_eq!(
        client.balance_status(now - 120, "nonce-stale", false),
        401,
        "a stale timestamp must be rejected"
    );
}

/// A minimal raw client that signs requests itself, for the adversarial cases the wallet
/// library never produces. It registers its own identity and account against the bank.
struct SignedClient {
    api_url: String,
    account_id: String,
    keypair: IdentityKeypair,
    agent: ureq::Agent,
}

impl SignedClient {
    fn enroll(bank: &BankProcess, account_id: &str) -> SignedClient {
        let keypair = IdentityKeypair::generate().expect("keypair");
        // Register over the server-TLS enrollment endpoint (no client cert yet).
        let enroll_agent = ureq::AgentBuilder::new()
            .tls_config(Arc::new(server_tls(&bank.ca_cert_pem)))
            .build();
        let response: RegisterResponse = enroll_agent
            .post(&format!("{}/register", bank.enroll_url))
            .send_json(RegisterRequest {
                account_id: account_id.to_string(),
                public_key_hex: hex::encode(keypair.public_key().to_bytes()),
            })
            .expect("register")
            .into_json()
            .expect("register response");
        let agent = ureq::AgentBuilder::new()
            .tls_config(Arc::new(mtls(
                &response.ca_cert_pem,
                &response.client_cert_pem,
                &response.client_key_pem,
            )))
            .build();
        let client = SignedClient {
            api_url: bank.api_url.clone(),
            account_id: account_id.to_string(),
            keypair,
            agent,
        };
        // Create the account so a valid balance request returns 200 rather than 404.
        let created = client.signed_post_status(
            "/accounts",
            &format!("{{\"account_id\":\"{account_id}\",\"initial_balance_cents\":0}}"),
            now_unix(),
            "nonce-create",
            false,
        );
        assert_eq!(created, 200, "account creation for the signed client failed");
        client
    }

    /// Send a signed `GET /accounts/{id}/balance` and return the HTTP status code.
    fn balance_status(&self, timestamp: u64, nonce: &str, tamper: bool) -> u16 {
        let path = format!("/accounts/{}/balance", self.account_id);
        let signature = self.sign("GET", &path, b"", timestamp, nonce, tamper);
        self.status(
            self.agent
                .get(&format!("{}{path}", self.api_url))
                .set(HEADER_ACCOUNT, &self.account_id)
                .set(HEADER_TIMESTAMP, &timestamp.to_string())
                .set(HEADER_NONCE, nonce)
                .set(HEADER_SIGNATURE, &signature)
                .call(),
        )
    }

    fn signed_post_status(
        &self,
        path: &str,
        body: &str,
        timestamp: u64,
        nonce: &str,
        tamper: bool,
    ) -> u16 {
        let signature = self.sign("POST", path, body.as_bytes(), timestamp, nonce, tamper);
        self.status(
            self.agent
                .post(&format!("{}{path}", self.api_url))
                .set("content-type", "application/json")
                .set(HEADER_ACCOUNT, &self.account_id)
                .set(HEADER_TIMESTAMP, &timestamp.to_string())
                .set(HEADER_NONCE, nonce)
                .set(HEADER_SIGNATURE, &signature)
                .send_bytes(body.as_bytes()),
        )
    }

    fn sign(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        timestamp: u64,
        nonce: &str,
        tamper: bool,
    ) -> String {
        let payload = canonical_payload(method, path, body, timestamp, nonce);
        let mut signature = self.keypair.sign(payload.as_bytes());
        if tamper {
            signature[0] ^= 0x01;
        }
        hex::encode(signature)
    }

    fn status(&self, result: Result<ureq::Response, ureq::Error>) -> u16 {
        match result {
            Ok(response) => response.status(),
            Err(ureq::Error::Status(code, _)) => code,
            Err(e) => panic!("transport error: {e}"),
        }
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs()
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn roots(ca_pem: &str) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut ca_pem.as_bytes()) {
        roots.add(cert.expect("ca cert")).expect("add root");
    }
    roots
}

fn server_tls(ca_pem: &str) -> ClientConfig {
    ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_root_certificates(roots(ca_pem))
        .with_no_client_auth()
}

fn mtls(ca_pem: &str, client_cert_pem: &str, client_key_pem: &str) -> ClientConfig {
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut client_cert_pem.as_bytes())
        .collect::<Result<_, _>>()
        .expect("client certs");
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut client_key_pem.as_bytes())
        .expect("client key read")
        .expect("client key present");
    ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_root_certificates(roots(ca_pem))
        .with_client_auth_cert(certs, key)
        .expect("client auth cert")
}

// ---- Multi-bank registry integration (production-spec v1.4 section 10) ----

/// A fresh Postgres database migrated with the registry's schema (its own migration set,
/// distinct from the bank's), or `None` if `DATABASE_URL` is unset.
fn registry_db_url() -> Option<String> {
    std::env::var("DATABASE_URL").ok().filter(|u| !u.is_empty())?;
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    runtime.block_on(async {
        digicash_registry::test_support::TestDatabase::create()
            .await
            .expect("create registry test database")
            .map(|db| db.url().to_string())
    })
}

/// The digicash-registry binary path, alongside the bank binary.
fn registry_binary() -> PathBuf {
    let mut bin = bank_binary();
    bin.set_file_name(if cfg!(windows) { "digicash-registry.exe" } else { "digicash-registry" });
    bin
}

/// A spawned registry process, killed on drop.
struct RegistryProcess {
    child: Child,
    addr: String,
    url: String,
    ca_cert_pem: String,
    key_dir: PathBuf,
}

impl RegistryProcess {
    fn spawn(database_url: &str, key_dir: &Path, admin_pubkey_hex: &str) -> RegistryProcess {
        let addr = format!("127.0.0.1:{}", free_port());
        let child = Command::new(registry_binary())
            .env("DIGICASH_REGISTRY_ADDR", &addr)
            .env("DATABASE_URL", database_url)
            .env("DIGICASH_REGISTRY_KEYS", key_dir)
            .env("DIGICASH_REGISTRY_ADMIN_PUBKEY", admin_pubkey_hex)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn registry process (build it with `cargo build -p digicash-registry`)");
        let mut registry = RegistryProcess {
            child,
            url: format!("https://{addr}"),
            addr,
            ca_cert_pem: String::new(),
            key_dir: key_dir.to_path_buf(),
        };
        let deadline = Instant::now() + Duration::from_secs(120);
        while std::net::TcpStream::connect(&registry.addr).is_err() {
            assert!(Instant::now() < deadline, "registry did not become ready");
            std::thread::sleep(Duration::from_millis(200));
        }
        registry.ca_cert_pem = read_ca_cert(key_dir);
        registry
    }
}

impl Drop for RegistryProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A raw governance client to the registry (mTLS + Ed25519), for the admin operations the
/// banks do not perform themselves.
struct RegistryAdmin {
    url: String,
    bank_id: String,
    keypair: IdentityKeypair,
    agent: ureq::Agent,
}

impl RegistryAdmin {
    fn new(registry: &RegistryProcess, bank_id: &str, keypair: IdentityKeypair) -> RegistryAdmin {
        // Issue this caller an mTLS client certificate from the registry's own CA.
        let ca = digicash_bank::CertAuthority::load_or_create(&registry.key_dir).expect("registry ca");
        let id = ca.issue_client_identity(bank_id).expect("issue client cert");
        let agent = ureq::AgentBuilder::new()
            .tls_config(Arc::new(mtls(&registry.ca_cert_pem, &id.cert_pem, &id.key_pem)))
            .build();
        RegistryAdmin {
            url: registry.url.clone(),
            bank_id: bank_id.to_string(),
            keypair,
            agent,
        }
    }

    /// POST a signed request; return the response, mapping a non-2xx status to its response
    /// body and panicking only on a transport error.
    fn post(&self, path: &str, body: &[u8], nonce: &str) -> ureq::Response {
        let ts = now_unix();
        let payload = canonical_payload("POST", path, body, ts, nonce);
        let sig = hex::encode(self.keypair.sign(payload.as_bytes()));
        let result = self
            .agent
            .post(&format!("{}{path}", self.url))
            .set("content-type", "application/json")
            .set(HEADER_ACCOUNT, &self.bank_id)
            .set(HEADER_TIMESTAMP, &ts.to_string())
            .set(HEADER_NONCE, nonce)
            .set(HEADER_SIGNATURE, &sig)
            .send_bytes(body);
        match result {
            Ok(response) => response,
            Err(ureq::Error::Status(_, response)) => response,
            Err(e) => panic!("registry transport error on {path}: {e}"),
        }
    }

    fn register_member(&self, bank_id: &str, pubkey: &IdentityKeypair, nonce: &str) {
        let body = serde_json::to_vec(&digicash_proto::RegisterMemberRequest {
            bank_id: bank_id.to_string(),
            pubkey_hex: hex::encode(pubkey.public_key().to_bytes()),
        })
        .expect("serialize");
        assert_eq!(
            self.post("/members", &body, nonce).status(),
            200,
            "registering {bank_id} failed"
        );
    }

    fn set_cap(&self, issuing: &str, depositing: &str, cap_cents: u64, nonce: &str) {
        let body = serde_json::to_vec(&digicash_proto::SetCapRequest {
            issuing_bank_id: issuing.to_string(),
            depositing_bank_id: depositing.to_string(),
            cap_cents,
        })
        .expect("serialize");
        assert_eq!(self.post("/caps", &body, nonce).status(), 200);
    }

    fn settle(&self, nonce: &str) -> digicash_proto::SettleResponse {
        self.post("/settle", b"", nonce)
            .into_json()
            .expect("settle response")
    }
}

/// Write the registry identity files a bank needs into its `key_dir`: the registry CA, an
/// mTLS client certificate/key issued by that CA, and the bank's Ed25519 signing secret.
fn provision_bank_registry_identity(
    registry: &RegistryProcess,
    bank_key_dir: &Path,
    bank_id: &str,
    bank_kp: &IdentityKeypair,
) {
    let ca = digicash_bank::CertAuthority::load_or_create(&registry.key_dir).expect("registry ca");
    let id = ca.issue_client_identity(bank_id).expect("issue client cert");
    std::fs::create_dir_all(bank_key_dir).expect("create key dir");
    std::fs::write(bank_key_dir.join("registry-ca.pem"), &registry.ca_cert_pem).expect("ca");
    std::fs::write(bank_key_dir.join("registry-cert.pem"), id.cert_pem).expect("cert");
    std::fs::write(bank_key_dir.join("registry-key.pem"), id.key_pem).expect("key");
    std::fs::write(
        bank_key_dir.join("registry-ed25519.hex"),
        hex::encode(bank_kp.secret_bytes()),
    )
    .expect("ed25519");
}

/// Copy the shared denomination keys into `dst` so two banks issue/verify the same coins,
/// while keeping their own registry identities in separate directories.
fn copy_denomination_keys(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).expect("create key dir");
    for entry in std::fs::read_dir(src).expect("read shared keys") {
        let entry = entry.expect("dir entry");
        let name = entry.file_name();
        if name.to_string_lossy().starts_with("denom_") {
            std::fs::copy(entry.path(), dst.join(name)).expect("copy denom key");
        }
    }
}

impl BankProcess {
    /// Spawn a bank wired to the registry: `bank_id` is the registry member id and
    /// `issuer_id` is the issuer reported for deposited coins.
    fn spawn_with_registry(
        database_url: &str,
        key_dir: &Path,
        registry_url: &str,
        bank_id: &str,
        issuer_id: &str,
    ) -> BankProcess {
        let api_addr = format!("127.0.0.1:{}", free_port());
        let enroll_addr = format!("127.0.0.1:{}", free_port());
        let child = Command::new(bank_binary())
            .env("DIGICASH_ADDR", &api_addr)
            .env("DIGICASH_ENROLL_ADDR", &enroll_addr)
            .env("DATABASE_URL", database_url)
            .env("DIGICASH_KEYS", key_dir)
            .env("DIGICASH_REGISTRY_URL", registry_url)
            .env("DIGICASH_BANK_ID", bank_id)
            .env("DIGICASH_COIN_ISSUER_ID", issuer_id)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn bank process");
        let mut bank = BankProcess {
            child,
            api_url: format!("https://{api_addr}"),
            enroll_url: format!("https://{enroll_addr}"),
            api_addr,
            enroll_addr,
            ca_cert_pem: String::new(),
        };
        bank.wait_ready();
        bank.ca_cert_pem = read_ca_cert(key_dir);
        bank
    }
}

#[test]
fn multi_bank_registry_double_spend_cap_and_settlement() {
    use digicash_proto::DepositRejection;

    let Some(registry_db) = registry_db_url() else {
        eprintln!("skipping: set DATABASE_URL to a Postgres instance to run this test");
        return;
    };
    let db_a = fresh_db_url().expect("db a");
    let db_b = fresh_db_url().expect("db b");

    // Registry with a seeded admin.
    let admin_kp = IdentityKeypair::generate().expect("admin");
    let registry_keys = TempDir::new().expect("registry keys");
    let registry = RegistryProcess::spawn(
        &registry_db,
        registry_keys.path(),
        &hex::encode(admin_kp.public_key().to_bytes()),
    );
    let admin = RegistryAdmin::new(&registry, "admin", admin_kp);

    // Register the two member banks.
    let bank_a_kp = IdentityKeypair::generate().expect("bank-a key");
    let bank_b_kp = IdentityKeypair::generate().expect("bank-b key");
    admin.register_member("bank-a", &bank_a_kp, "m1");
    admin.register_member("bank-b", &bank_b_kp, "m2");

    // Two bank binaries sharing denomination keys, each with its own registry identity.
    let keys_a = TempDir::new().expect("keys a");
    let keys_b = TempDir::new().expect("keys b");
    copy_denomination_keys(shared_key_dir(), keys_a.path());
    copy_denomination_keys(shared_key_dir(), keys_b.path());
    provision_bank_registry_identity(&registry, keys_a.path(), "bank-a", &bank_a_kp);
    provision_bank_registry_identity(&registry, keys_b.path(), "bank-b", &bank_b_kp);
    let bank_a = BankProcess::spawn_with_registry(&db_a, keys_a.path(), &registry.url, "bank-a", "bank-a");
    let bank_b = BankProcess::spawn_with_registry(&db_b, keys_b.path(), &registry.url, "bank-b", "bank-a");

    let stores = TempDir::new().expect("stores");
    let bundles = TempDir::new().expect("bundles");

    // Bank A issues a coin; a payer withdraws and spends it to a bundle.
    let payer = registered_wallet(&bank_a, &stores.path().join("payer"), "payer", 1000);
    payer.withdraw(64).expect("withdraw");
    let bundle = bundles.path().join("coin.json");
    payer.spend(64, &bundle).expect("spend");

    // Bank B deposits it: the registry accepts (fresh serial), B credits.
    let payee = registered_wallet(&bank_b, &stores.path().join("payee"), "payee", 0);
    let outcomes = payee.deposit(&bundle).expect("deposit at B");
    assert!(outcomes.iter().all(|o| o.accepted), "B deposit should be accepted: {outcomes:?}");
    assert_eq!(payee.balance().expect("balance").balance_cents, 64);

    // Bank B replays the same bundle: the registry reports a double-spend.
    let replay = payee.deposit(&bundle).expect("replay at B");
    assert!(
        replay.iter().all(|o| o.reason == Some(DepositRejection::RegistryDoubleSpend)),
        "B replay must be a registry double-spend: {replay:?}"
    );
    assert_eq!(payee.balance().expect("balance").balance_cents, 64, "replay re-credited");

    // Bank A also tries to deposit it: cross-bank double-spend detected by the registry.
    let payee_a = registered_wallet(&bank_a, &stores.path().join("payee-a"), "payee-a", 0);
    let cross = payee_a.deposit(&bundle).expect("cross-bank deposit at A");
    assert!(
        cross.iter().all(|o| o.reason == Some(DepositRejection::RegistryDoubleSpend)),
        "A deposit must be a cross-bank double-spend: {cross:?}"
    );

    // Exposure cap: bank-b's outstanding receivable against bank-a is 64; cap it at 50 so the
    // next fresh coin from bank-a is rejected across banks.
    admin.set_cap("bank-a", "bank-b", 50, "cap1");
    payer.withdraw(64).expect("withdraw 2");
    let bundle2 = bundles.path().join("coin2.json");
    payer.spend(64, &bundle2).expect("spend 2");
    let capped = payee.deposit(&bundle2).expect("capped deposit at B");
    assert!(
        capped.iter().all(|o| o.reason == Some(DepositRejection::ExposureCapExceeded)),
        "deposit past the cap must be rejected: {capped:?}"
    );
    assert_eq!(payee.balance().expect("balance").balance_cents, 64, "capped deposit credited");

    // Settlement: netting produces one claim, bank-a owes bank-b 64.
    let settled = admin.settle("settle1");
    assert_eq!(settled.claims.len(), 1);
    let claim = &settled.claims[0];
    assert_eq!(claim.issuing_bank_id, "bank-a");
    assert_eq!(claim.depositing_bank_id, "bank-b");
    assert_eq!(claim.net_amount_cents, 64);

    drop((bank_a, bank_b, registry));
}
