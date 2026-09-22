//! Router storage in PostgreSQL (Plan §8, §19, §34, §75): the device registry and the encrypted
//! mailbox. The mailbox table is UNLOGGED, so it never reaches the WAL archive or a backup.

use std::str::FromStr;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions};
use sqlx::{AssertSqlSafe, Row};
use uuid::Uuid;

/// Largest blob a mailbox accepts: an encrypted text message is far smaller.
pub const MAX_BLOB: usize = 64 * 1024;
/// Blobs waiting per device at most; beyond that, senders keep the message on their phone.
pub const MAX_BLOBS_PER_DEVICE: i64 = 1000;

pub struct Db {
    pool: PgPool,
}

impl Db {
    pub async fn connect(url: &str) -> Result<Self> {
        let pool = PgPoolOptions::new().max_connections(10).connect(url).await.context("cannot reach PostgreSQL")?;
        Self::migrated(pool).await
    }

    /// For tests: a fresh schema of its own in the given database.
    pub async fn connect_isolated(url: &str) -> Result<Self> {
        let schema = format!("test_{}", Uuid::now_v7().simple());
        let admin = PgPoolOptions::new().max_connections(1).connect(url).await?;
        sqlx::query(AssertSqlSafe(format!("CREATE SCHEMA {schema}"))).execute(&admin).await?;
        let options = PgConnectOptions::from_str(url)?.options([("search_path", schema.as_str())]);
        let pool = PgPoolOptions::new().max_connections(4).connect_with(options).await?;
        Self::migrated(pool).await
    }

    async fn migrated(pool: PgPool) -> Result<Self> {
        sqlx::migrate!("./migrations").run(&pool).await.context("cannot migrate the router database")?;
        Ok(Self { pool })
    }

    /// Adds the device or refreshes its capability (the app registers on every start).
    pub async fn register(&self, device_id: &str, signing_key: &[u8; 32], capability_hash: &[u8; 32]) -> Result<()> {
        sqlx::query(
            "INSERT INTO devices (device_id, signing_key, capability_hash) VALUES ($1, $2, $3)
             ON CONFLICT (device_id) DO UPDATE SET capability_hash = excluded.capability_hash, updated_at = now()",
        )
        .bind(device_id)
        .bind(signing_key.as_slice())
        .bind(capability_hash.as_slice())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn signing_key(&self, device_id: &str) -> Result<Option<[u8; 32]>> {
        let row = sqlx::query("SELECT signing_key FROM devices WHERE device_id = $1").bind(device_id).fetch_optional(&self.pool).await?;
        row.map(|row| {
            let key: Vec<u8> = row.get("signing_key");
            key.try_into().map_err(|_| anyhow::anyhow!("corrupt signing key"))
        })
        .transpose()
    }

    /// Whether `capability` is the one the device registered (§34).
    pub async fn capability_matches(&self, device_id: &str, capability: &[u8; 32]) -> Result<bool> {
        let row = sqlx::query("SELECT capability_hash FROM devices WHERE device_id = $1").bind(device_id).fetch_optional(&self.pool).await?;
        Ok(row.is_some_and(|row| row.get::<Vec<u8>, _>("capability_hash") == blake3::hash(capability).as_bytes()))
    }

    /// Removes the device and everything waiting for it (`DELETE /v1/device`).
    pub async fn forget(&self, device_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM mailbox WHERE device_id = $1").bind(device_id).execute(&self.pool).await?;
        sqlx::query("DELETE FROM devices WHERE device_id = $1").bind(device_id).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn deposit(&self, device_id: &str, blob: &[u8], ttl: Duration) -> Result<Uuid> {
        if blob.len() > MAX_BLOB {
            bail!("the blob is too large");
        }
        let waiting: i64 = sqlx::query("SELECT COUNT(*) AS n FROM mailbox WHERE device_id = $1 AND expires_at > now()")
            .bind(device_id)
            .fetch_one(&self.pool)
            .await?
            .get("n");
        if waiting >= MAX_BLOBS_PER_DEVICE {
            bail!("the mailbox is full");
        }
        let id = Uuid::now_v7();
        sqlx::query("INSERT INTO mailbox (id, device_id, blob, expires_at) VALUES ($1, $2, $3, now() + make_interval(secs => $4))")
            .bind(id)
            .bind(device_id)
            .bind(blob)
            .bind(ttl.as_secs_f64())
            .execute(&self.pool)
            .await?;
        Ok(id)
    }

    /// The device's unexpired blobs, oldest first.
    pub async fn collect(&self, device_id: &str) -> Result<Vec<(Uuid, Vec<u8>)>> {
        let rows = sqlx::query("SELECT id, blob FROM mailbox WHERE device_id = $1 AND expires_at > now() ORDER BY id")
            .bind(device_id)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.iter().map(|row| (row.get("id"), row.get("blob"))).collect())
    }

    /// Deletes a blob its owner has stored (ACK, §19). False if it is not theirs or not there.
    pub async fn acknowledge(&self, device_id: &str, id: Uuid) -> Result<bool> {
        let result = sqlx::query("DELETE FROM mailbox WHERE id = $1 AND device_id = $2").bind(id).bind(device_id).execute(&self.pool).await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn purge_expired(&self) -> Result<u64> {
        Ok(sqlx::query("DELETE FROM mailbox WHERE expires_at <= now()").execute(&self.pool).await?.rows_affected())
    }

    /// `p` permanent, `u` unlogged: lets the tests check the mailbox never reaches the WAL.
    pub async fn persistence(&self, table: &str) -> Result<String> {
        let row = sqlx::query("SELECT relpersistence::text AS p FROM pg_class WHERE relname = $1 AND relnamespace = current_schema()::regnamespace")
            .bind(table)
            .fetch_one(&self.pool)
            .await?;
        Ok(row.get("p"))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    /// Each test gets its own schema in the local test database.
    async fn db() -> Db {
        let url = std::env::var("FT_TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://postgres:test@127.0.0.1:55432/ft_router_test".to_owned());
        Db::connect_isolated(&url).await.expect("connects to the test database")
    }

    const KEY: [u8; 32] = [1; 32];
    const CAPABILITY: [u8; 32] = [2; 32];

    fn capability_hash() -> [u8; 32] {
        *blake3::hash(&CAPABILITY).as_bytes()
    }

    #[tokio::test]
    async fn a_registered_device_is_known_by_its_key() {
        let db = db().await;
        assert!(db.signing_key("ft_a").await.unwrap().is_none());
        db.register("ft_a", &KEY, &capability_hash()).await.expect("registers");
        assert_eq!(db.signing_key("ft_a").await.unwrap(), Some(KEY));
    }

    // Registering again (every app start) refreshes the capability.
    #[tokio::test]
    async fn registering_again_updates_the_capability() {
        let db = db().await;
        db.register("ft_a", &KEY, &capability_hash()).await.expect("registers");
        let other = [3; 32];
        db.register("ft_a", &KEY, blake3::hash(&other).as_bytes()).await.expect("re-registers");
        assert!(db.capability_matches("ft_a", &other).await.unwrap());
        assert!(!db.capability_matches("ft_a", &CAPABILITY).await.unwrap());
    }

    #[tokio::test]
    async fn only_the_right_capability_opens_the_route() {
        let db = db().await;
        db.register("ft_a", &KEY, &capability_hash()).await.expect("registers");
        assert!(db.capability_matches("ft_a", &CAPABILITY).await.unwrap());
        assert!(!db.capability_matches("ft_a", &[9; 32]).await.unwrap());
        assert!(!db.capability_matches("ft_unknown", &CAPABILITY).await.unwrap());
    }

    #[tokio::test]
    async fn the_mailbox_hands_blobs_over_in_order_until_acknowledged() {
        let db = db().await;
        let first = db.deposit("ft_a", b"one", Duration::from_secs(60)).await.expect("deposits");
        db.deposit("ft_a", b"two", Duration::from_secs(60)).await.expect("deposits");
        db.deposit("ft_b", b"not yours", Duration::from_secs(60)).await.expect("deposits");

        let blobs = db.collect("ft_a").await.expect("collects");
        assert_eq!(blobs.iter().map(|(_, blob)| blob.as_slice()).collect::<Vec<_>>(), [b"one".as_slice(), b"two"]);

        assert!(db.acknowledge("ft_a", first).await.expect("deletes"));
        assert_eq!(db.collect("ft_a").await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn nobody_can_acknowledge_someone_elses_mail() {
        let db = db().await;
        let id = db.deposit("ft_a", b"one", Duration::from_secs(60)).await.expect("deposits");
        assert!(!db.acknowledge("ft_b", id).await.expect("refuses"));
        assert_eq!(db.collect("ft_a").await.unwrap().len(), 1);
    }

    // §19: TTL, never kept for good.
    #[tokio::test]
    async fn expired_mail_is_neither_handed_over_nor_kept() {
        let db = db().await;
        db.deposit("ft_a", b"old", Duration::ZERO).await.expect("deposits");
        assert!(db.collect("ft_a").await.unwrap().is_empty());
        assert_eq!(db.purge_expired().await.expect("purges"), 1);
    }

    #[tokio::test]
    async fn a_mailbox_has_a_quota_and_blobs_a_maximum_size() {
        let db = db().await;
        assert!(db.deposit("ft_a", &vec![0; MAX_BLOB + 1], Duration::from_secs(60)).await.is_err());
        for _ in 0..MAX_BLOBS_PER_DEVICE {
            db.deposit("ft_a", b"x", Duration::from_secs(60)).await.expect("within the quota");
        }
        assert!(db.deposit("ft_a", b"x", Duration::from_secs(60)).await.is_err());
    }

    // §73 / §75: the mailbox must never reach the WAL archive or a backup.
    #[tokio::test]
    async fn the_mailbox_table_is_unlogged() {
        let db = db().await;
        assert_eq!(db.persistence("mailbox").await.unwrap(), "u");
        assert_eq!(db.persistence("devices").await.unwrap(), "p");
    }

    #[tokio::test]
    async fn forgetting_a_device_removes_its_registration_and_mail() {
        let db = db().await;
        db.register("ft_a", &KEY, &capability_hash()).await.expect("registers");
        db.deposit("ft_a", b"one", Duration::from_secs(60)).await.expect("deposits");
        db.forget("ft_a").await.expect("forgets");
        assert!(db.signing_key("ft_a").await.unwrap().is_none());
        assert!(db.collect("ft_a").await.unwrap().is_empty());
    }
}
