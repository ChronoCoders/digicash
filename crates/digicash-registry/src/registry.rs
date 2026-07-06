use std::sync::atomic::{AtomicU64, Ordering};

use deadpool_postgres::Pool;
use digicash_core::{IdentityPublicKey, IDENTITY_PUBLIC_KEY_LEN};
use digicash_proto::MemberInfo;

use crate::db;
use crate::error::RegistryError;

/// Purge expired nonces once every this many recorded nonces.
const NONCE_PRUNE_INTERVAL: u64 = 1024;

/// The registry: a Postgres-backed store of member banks, the shared spent-serial and
/// transcript store, per-issuer exposure caps, receivables, and the settlement claim ledger
/// (production-spec v1.4 section 10).
pub struct Registry {
    pool: Pool,
    nonce_ops: AtomicU64,
}

impl Registry {
    /// Connect to Postgres at `database_url`, run schema migrations, and purge expired nonces.
    pub async fn connect(database_url: &str) -> Result<Self, RegistryError> {
        db::run_migrations(database_url).await?;
        let registry = Self {
            pool: db::create_pool(database_url)?,
            nonce_ops: AtomicU64::new(0),
        };
        registry.purge_expired_nonces(now_unix()).await?;
        Ok(registry)
    }

    /// Register (or seed) a member bank's Ed25519 request-signing key. First-wins: a second
    /// registration for the same `bank_id` is rejected. `is_admin` marks the governance admin.
    pub async fn register_member(
        &self,
        bank_id: &str,
        public_key: &IdentityPublicKey,
        is_admin: bool,
    ) -> Result<(), RegistryError> {
        let pubkey = public_key.to_bytes().to_vec();
        let inserted = self
            .client()
            .await?
            .execute(
                "INSERT INTO members (bank_id, pubkey, is_admin) VALUES ($1, $2, $3) \
                 ON CONFLICT (bank_id) DO NOTHING",
                &[&bank_id, &pubkey, &is_admin],
            )
            .await?;
        if inserted == 0 {
            return Err(RegistryError::MemberExists(bank_id.to_string()));
        }
        Ok(())
    }

    /// Every registered member, in ascending `bank_id` order.
    pub async fn list_members(&self) -> Result<Vec<MemberInfo>, RegistryError> {
        let rows = self
            .client()
            .await?
            .query(
                "SELECT bank_id, pubkey, is_admin FROM members ORDER BY bank_id",
                &[],
            )
            .await?;
        let mut members = Vec::new();
        for row in rows {
            let pubkey: Vec<u8> = row.get(1);
            members.push(MemberInfo {
                bank_id: row.get(0),
                pubkey_hex: hex::encode(pubkey),
                is_admin: row.get(2),
            });
        }
        Ok(members)
    }

    /// The Ed25519 public key registered for `bank_id`, or `None` if not a member.
    pub(crate) async fn member_pubkey(
        &self,
        bank_id: &str,
    ) -> Result<Option<IdentityPublicKey>, RegistryError> {
        let row = self
            .client()
            .await?
            .query_opt("SELECT pubkey FROM members WHERE bank_id = $1", &[&bank_id])
            .await?;
        match row {
            Some(row) => {
                let bytes: Vec<u8> = row.get(0);
                let array: [u8; IDENTITY_PUBLIC_KEY_LEN] =
                    bytes.as_slice().try_into().map_err(|_| RegistryError::MalformedMember {
                        bank_id: bank_id.to_string(),
                        message: format!(
                            "key is {} bytes, expected {IDENTITY_PUBLIC_KEY_LEN}",
                            bytes.len()
                        ),
                    })?;
                Ok(Some(IdentityPublicKey::from_bytes(&array)?))
            }
            None => Ok(None),
        }
    }

    /// Whether `bank_id` is the governance admin.
    pub(crate) async fn is_admin(&self, bank_id: &str) -> Result<bool, RegistryError> {
        let row = self
            .client()
            .await?
            .query_opt("SELECT is_admin FROM members WHERE bank_id = $1", &[&bank_id])
            .await?;
        Ok(row.map(|r| r.get::<_, bool>(0)).unwrap_or(false))
    }

    /// Record `nonce` as seen at `now`, returning `true` if fresh and `false` on replay within
    /// `ttl_secs` (production-spec v1.4 section 2). Atomic via the primary key.
    pub(crate) async fn check_and_record_nonce(
        &self,
        nonce: &str,
        now: u64,
        ttl_secs: u64,
    ) -> Result<bool, RegistryError> {
        let expiry = to_i64(now.saturating_add(ttl_secs), "nonce expiry")?;
        let now_i = to_i64(now, "nonce timestamp")?;
        let affected = self
            .client()
            .await?
            .execute(
                "INSERT INTO nonce_store (nonce, expires_at) VALUES ($1, $2) \
                 ON CONFLICT (nonce) DO UPDATE SET expires_at = EXCLUDED.expires_at \
                 WHERE nonce_store.expires_at <= $3",
                &[&nonce, &expiry, &now_i],
            )
            .await?;
        if self.nonce_ops.fetch_add(1, Ordering::Relaxed) % NONCE_PRUNE_INTERVAL
            == NONCE_PRUNE_INTERVAL - 1
        {
            self.purge_expired_nonces(now).await?;
        }
        Ok(affected == 1)
    }

    async fn purge_expired_nonces(&self, now: u64) -> Result<(), RegistryError> {
        let now = to_i64(now, "nonce timestamp")?;
        self.client()
            .await?
            .execute("DELETE FROM nonce_store WHERE expires_at <= $1", &[&now])
            .await?;
        Ok(())
    }

    /// A pooled connection to the registry database.
    pub(crate) async fn client(&self) -> Result<deadpool_postgres::Object, RegistryError> {
        Ok(self.pool.get().await?)
    }

    /// Verify the database is reachable (a health probe).
    pub(crate) async fn ping(&self) -> Result<(), RegistryError> {
        self.client().await?.query_one("SELECT 1", &[]).await?;
        Ok(())
    }
}

pub(crate) fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub(crate) fn to_i64(value: u64, what: &str) -> Result<i64, RegistryError> {
    i64::try_from(value)
        .map_err(|_| RegistryError::ValueRange(format!("{what} {value} exceeds the i64 range")))
}
