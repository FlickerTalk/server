use std::borrow::Cow;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use sqlx::migrate::Migrator;
use sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions};
use sqlx::{AssertSqlSafe, Row};
use uuid::Uuid;

pub const MAX_BLOB: usize = 64 * 1024;
pub const MAX_BLOBS_MAIN_LIST: i64 = 1000;
pub const MAX_BLOBS_PER_SESSION: i64 = 200;

// sqlx also hashes comments; these are the checksums existing databases recorded for these files.
const RECORDED_CHECKSUMS: [(i64, &str); 5] = [
    (1, "327824ab11e36398fe285d83f71aabf82598fa5919fa986eeb5ddb697efdd183a7340fb951ab88ddfde645244e8cbd79"),
    (2, "fa865ab6577314471029caa54f1164c8e67c01b8db3114b00769dcc7157d5899f924340f8b886bf3a7cac51a4c1349a9"),
    (3, "9caa8ac05f4ffadb55fac9d964f37f16a9ead308da414a894c6c6d062f6ec5304052c623b0bc5bfeba21e0f74ce9ef17"),
    (4, "b2d546e49f03d29c2863956f6ef1c8221a0727868f75257ed6ad206cb9a068e47752e96ff6387661d80c086e582ceaaa"),
    (5, "8e7d24d24d3ad7579e8a6ae306f98a2cae0c25d8430daf3a3f54ecebc686978f5eb91a9b32da8a6a21b2a70711c434fa"),
];

fn migrator() -> Migrator {
    let mut migrator = sqlx::migrate!("./migrations");
    for migration in migrator.migrations.to_mut() {
        if let Some((_, checksum)) = RECORDED_CHECKSUMS.iter().find(|(version, _)| *version == migration.version) {
            migration.checksum = Cow::Owned(bytes(checksum));
        }
    }
    migrator
}

fn bytes(hex: &str) -> Vec<u8> {
    (0..hex.len()).step_by(2).map(|at| u8::from_str_radix(&hex[at..at + 2], 16).expect("a hex checksum")).collect()
}

pub struct Db {
    pool: PgPool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Route {
    pub slot: u8,
    pub silent: bool,
}

impl Db {
    pub async fn connect(url: &str) -> Result<Self> {
        let pool = PgPoolOptions::new().max_connections(10).connect(url).await.context("cannot reach PostgreSQL")?;
        Self::migrated(pool).await
    }

    pub async fn connect_isolated(url: &str) -> Result<Self> {
        Self::migrated(isolated_pool(url).await?).await
    }

    async fn migrated(pool: PgPool) -> Result<Self> {
        migrator().run(&pool).await.context("cannot migrate the router database")?;
        Ok(Self { pool })
    }

    pub async fn register(&self, device_id: &str, signing_key: &[u8; 32], capability_hash: &[u8; 32], silent_slots: u8) -> Result<u8> {
        // The subquery sees the row as it was before this statement.
        let row = sqlx::query(
            "WITH before AS (SELECT silent_slots FROM devices WHERE device_id = $1)
             INSERT INTO devices (device_id, signing_key, capability_hash, silent_slots) VALUES ($1, $2, $3, $4)
             ON CONFLICT (device_id) DO UPDATE
             SET capability_hash = excluded.capability_hash, silent_slots = excluded.silent_slots, updated_at = now()
             RETURNING COALESCE((SELECT silent_slots FROM before), 0)::smallint AS before",
        )
        .bind(device_id)
        .bind(signing_key.as_slice())
        .bind(capability_hash.as_slice())
        .bind(i16::from(silent_slots))
        .fetch_one(&self.pool)
        .await?;
        Ok(row.get::<i16, _>("before") as u8)
    }

    pub async fn signing_key(&self, device_id: &str) -> Result<Option<[u8; 32]>> {
        let row = sqlx::query("SELECT signing_key FROM devices WHERE device_id = $1").bind(device_id).fetch_optional(&self.pool).await?;
        row.map(|row| {
            let key: Vec<u8> = row.get("signing_key");
            key.try_into().map_err(|_| anyhow::anyhow!("corrupt signing key"))
        })
        .transpose()
    }

    pub async fn capability_slot(&self, device_id: &str, capability: &[u8; 32]) -> Result<Option<u8>> {
        Ok(self.route(device_id, capability).await?.map(|route| route.slot))
    }

    /// A silent slot takes exactly as long to find as any other.
    pub async fn route(&self, device_id: &str, capability: &[u8; 32]) -> Result<Option<Route>> {
        let hash = blake3::hash(capability);
        let row = sqlx::query("SELECT capability_hash, silent_slots FROM devices WHERE device_id = $1")
            .bind(device_id)
            .fetch_optional(&self.pool)
            .await?;
        let Some(row) = row else { return Ok(None) };
        let silent_slots = row.get::<i16, _>("silent_slots") as u8;
        let route = |slot: u8| Route { slot, silent: crate::push::silent(silent_slots, slot) };
        if row.get::<Vec<u8>, _>("capability_hash") == hash.as_bytes() {
            return Ok(Some(route(0)));
        }
        let slot = sqlx::query("SELECT slot FROM capabilities WHERE device_id = $1 AND capability_hash = $2")
            .bind(device_id)
            .bind(hash.as_bytes().as_slice())
            .fetch_optional(&self.pool)
            .await?;
        Ok(slot.map(|row| route(row.get::<i16, _>("slot") as u8)))
    }

    pub async fn set_capabilities(&self, device_id: &str, hashes: &[[u8; 32]; 8]) -> Result<()> {
        let mut transaction = self.pool.begin().await?;
        sqlx::query("DELETE FROM capabilities WHERE device_id = $1").bind(device_id).execute(&mut *transaction).await?;
        for (slot, hash) in hashes.iter().enumerate() {
            sqlx::query("INSERT INTO capabilities (device_id, slot, capability_hash) VALUES ($1, $2, $3)")
                .bind(device_id)
                .bind(slot as i16)
                .bind(hash.as_slice())
                .execute(&mut *transaction)
                .await?;
        }
        transaction.commit().await?;
        Ok(())
    }

    pub async fn forget(&self, device_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM mailbox WHERE device_id = $1").bind(device_id).execute(&self.pool).await?;
        sqlx::query("DELETE FROM devices WHERE device_id = $1").bind(device_id).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn set_push(&self, device_id: &str, provider: &str, sealed: &[u8]) -> Result<bool> {
        let updated = sqlx::query("UPDATE devices SET push_provider = $2, push_target = $3, updated_at = now() WHERE device_id = $1")
            .bind(device_id)
            .bind(provider)
            .bind(sealed)
            .execute(&self.pool)
            .await?;
        Ok(updated.rows_affected() == 1)
    }

    pub async fn clear_push(&self, device_id: &str) -> Result<()> {
        sqlx::query("UPDATE devices SET push_provider = NULL, push_target = NULL WHERE device_id = $1")
            .bind(device_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn push_of(&self, device_id: &str) -> Result<Option<(String, Vec<u8>)>> {
        let row = sqlx::query("SELECT push_provider, push_target FROM devices WHERE device_id = $1 AND push_target IS NOT NULL")
            .bind(device_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|row| (row.get("push_provider"), row.get("push_target"))))
    }

    pub async fn push_for(&self, device_id: &str, slot: u8) -> Result<Option<(String, Vec<u8>)>> {
        let row = sqlx::query(
            "SELECT push_provider, push_target, silent_slots FROM devices WHERE device_id = $1 AND push_target IS NOT NULL",
        )
        .bind(device_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row
            .filter(|row| !crate::push::silent(row.get::<i16, _>("silent_slots") as u8, slot))
            .map(|row| (row.get("push_provider"), row.get("push_target"))))
    }

    pub async fn silent_slots(&self, device_id: &str) -> Result<Option<u8>> {
        let row = sqlx::query("SELECT silent_slots FROM devices WHERE device_id = $1").bind(device_id).fetch_optional(&self.pool).await?;
        Ok(row.map(|row| row.get::<i16, _>("silent_slots") as u8))
    }

    /// Withheld blobs count too, and a full slot refuses the same way silent or not.
    pub async fn deposit(&self, device_id: &str, slot: u8, blob: &[u8], ttl: Duration) -> Result<Uuid> {
        if blob.len() > MAX_BLOB {
            bail!("the blob is too large");
        }
        let waiting: i64 = sqlx::query("SELECT COUNT(*) AS n FROM mailbox WHERE device_id = $1 AND slot = $2 AND expires_at > now()")
            .bind(device_id)
            .bind(i16::from(slot))
            .fetch_one(&self.pool)
            .await?
            .get("n");
        if waiting >= quota(slot) {
            bail!("the mailbox is full");
        }
        let id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO mailbox (id, device_id, slot, blob, expires_at) VALUES ($1, $2, $3, $4, now() + make_interval(secs => $5))",
        )
        .bind(id)
        .bind(device_id)
        .bind(i16::from(slot))
        .bind(blob)
        .bind(ttl.as_secs_f64())
        .execute(&self.pool)
        .await?;
        Ok(id)
    }

    pub async fn collect(&self, device_id: &str) -> Result<Vec<(Uuid, Vec<u8>)>> {
        let rows = sqlx::query(
            "SELECT id, blob FROM mailbox
             WHERE device_id = $1 AND expires_at > now()
               AND (slot = 0 OR (COALESCE((SELECT silent_slots FROM devices WHERE device_id = $1), 0)::int >> slot) & 1 = 0)
             ORDER BY id",
        )
            .bind(device_id)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.iter().map(|row| (row.get("id"), row.get("blob"))).collect())
    }

    pub async fn mail_through(&self, device_id: &str, slots: u8) -> Result<bool> {
        let row = sqlx::query(
            "SELECT EXISTS (SELECT 1 FROM mailbox WHERE device_id = $1 AND expires_at > now() AND ($2::int >> slot) & 1 = 1) AS waiting",
        )
        .bind(device_id)
        .bind(i32::from(slots))
        .fetch_one(&self.pool)
        .await?;
        Ok(row.get("waiting"))
    }

    pub async fn acknowledge(&self, device_id: &str, id: Uuid) -> Result<bool> {
        let result = sqlx::query("DELETE FROM mailbox WHERE id = $1 AND device_id = $2").bind(id).bind(device_id).execute(&self.pool).await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn purge_expired(&self) -> Result<u64> {
        Ok(sqlx::query("DELETE FROM mailbox WHERE expires_at <= now()").execute(&self.pool).await?.rows_affected())
    }

    /// `p` permanent, `u` unlogged
    pub async fn persistence(&self, table: &str) -> Result<String> {
        let row = sqlx::query("SELECT relpersistence::text AS p FROM pg_class WHERE relname = $1 AND relnamespace = current_schema()::regnamespace")
            .bind(table)
            .fetch_one(&self.pool)
            .await?;
        Ok(row.get("p"))
    }
}

fn quota(slot: u8) -> i64 {
    if slot == 0 {
        MAX_BLOBS_MAIN_LIST
    } else {
        MAX_BLOBS_PER_SESSION
    }
}

async fn isolated_pool(url: &str) -> Result<PgPool> {
    let schema = format!("test_{}", Uuid::now_v7().simple());
    let admin = PgPoolOptions::new().max_connections(1).connect(url).await?;
    sqlx::query(AssertSqlSafe(format!("CREATE SCHEMA {schema}"))).execute(&admin).await?;
    let options = PgConnectOptions::from_str(url)?.options([("search_path", schema.as_str())]);
    Ok(PgPoolOptions::new().max_connections(4).connect_with(options).await?)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn url() -> String {
        std::env::var("FT_TEST_DATABASE_URL").unwrap_or_else(|_| "postgres://postgres:test@127.0.0.1:55432/ft_router_test".to_owned())
    }

    async fn db() -> Db {
        Db::connect_isolated(&url()).await.expect("connects to the test database")
    }

    const PRODUCTION_CHECKSUMS: [(i64, &str); 5] = [
        (1, "327824ab11e36398fe285d83f71aabf82598fa5919fa986eeb5ddb697efdd183a7340fb951ab88ddfde645244e8cbd79"),
        (2, "fa865ab6577314471029caa54f1164c8e67c01b8db3114b00769dcc7157d5899f924340f8b886bf3a7cac51a4c1349a9"),
        (3, "9caa8ac05f4ffadb55fac9d964f37f16a9ead308da414a894c6c6d062f6ec5304052c623b0bc5bfeba21e0f74ce9ef17"),
        (4, "b2d546e49f03d29c2863956f6ef1c8221a0727868f75257ed6ad206cb9a068e47752e96ff6387661d80c086e582ceaaa"),
        (5, "8e7d24d24d3ad7579e8a6ae306f98a2cae0c25d8430daf3a3f54ecebc686978f5eb91a9b32da8a6a21b2a70711c434fa"),
    ];

    #[tokio::test]
    async fn a_database_holding_the_production_checksums_still_migrates() {
        let pool = isolated_pool(&url()).await.expect("a fresh schema");
        Db::migrated(pool.clone()).await.expect("migrates");
        for (version, checksum) in PRODUCTION_CHECKSUMS {
            let updated = sqlx::query("UPDATE _sqlx_migrations SET checksum = decode($2, 'hex') WHERE version = $1")
                .bind(version)
                .bind(checksum)
                .execute(&pool)
                .await
                .expect("records the checksum production holds");
            assert_eq!(updated.rows_affected(), 1);
        }
        Db::migrated(pool).await.expect("a database migrated by an earlier router still migrates");
    }

    #[tokio::test]
    async fn a_fresh_database_records_the_production_checksums() {
        let pool = isolated_pool(&url()).await.expect("a fresh schema");
        Db::migrated(pool.clone()).await.expect("migrates");
        let recorded: Vec<(i64, String)> = sqlx::query_as("SELECT version, encode(checksum, 'hex') FROM _sqlx_migrations ORDER BY version")
            .fetch_all(&pool)
            .await
            .expect("reads the recorded migrations");
        assert_eq!(recorded, PRODUCTION_CHECKSUMS.map(|(version, checksum)| (version, checksum.to_owned())));
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
        db.register("ft_a", &KEY, &capability_hash(), 0).await.expect("registers");
        assert_eq!(db.signing_key("ft_a").await.unwrap(), Some(KEY));
    }

    #[tokio::test]
    async fn registering_again_updates_the_capability() {
        let db = db().await;
        db.register("ft_a", &KEY, &capability_hash(), 0).await.expect("registers");
        let other = [3; 32];
        db.register("ft_a", &KEY, blake3::hash(&other).as_bytes(), 0).await.expect("re-registers");
        assert!(db.capability_slot("ft_a", &other).await.unwrap().is_some());
        assert!(db.capability_slot("ft_a", &CAPABILITY).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn only_the_right_capability_opens_the_route() {
        let db = db().await;
        db.register("ft_a", &KEY, &capability_hash(), 0).await.expect("registers");
        assert!(db.capability_slot("ft_a", &CAPABILITY).await.unwrap().is_some());
        assert!(db.capability_slot("ft_a", &[9; 32]).await.unwrap().is_none());
        assert!(db.capability_slot("ft_unknown", &CAPABILITY).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn the_mailbox_hands_blobs_over_in_order_until_acknowledged() {
        let db = db().await;
        let first = db.deposit("ft_a", 0, b"one", Duration::from_secs(60)).await.expect("deposits");
        db.deposit("ft_a", 0, b"two", Duration::from_secs(60)).await.expect("deposits");
        db.deposit("ft_b", 0, b"not yours", Duration::from_secs(60)).await.expect("deposits");

        let blobs = db.collect("ft_a").await.expect("collects");
        assert_eq!(blobs.iter().map(|(_, blob)| blob.as_slice()).collect::<Vec<_>>(), [b"one".as_slice(), b"two"]);

        assert!(db.acknowledge("ft_a", first).await.expect("deletes"));
        assert_eq!(db.collect("ft_a").await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn nobody_can_acknowledge_someone_elses_mail() {
        let db = db().await;
        let id = db.deposit("ft_a", 0, b"one", Duration::from_secs(60)).await.expect("deposits");
        assert!(!db.acknowledge("ft_b", id).await.expect("refuses"));
        assert_eq!(db.collect("ft_a").await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn expired_mail_is_neither_handed_over_nor_kept() {
        let db = db().await;
        db.deposit("ft_a", 0, b"old", Duration::ZERO).await.expect("deposits");
        assert!(db.collect("ft_a").await.unwrap().is_empty());
        assert_eq!(db.purge_expired().await.expect("purges"), 1);
    }

    #[tokio::test]
    async fn a_mailbox_has_a_quota_and_blobs_a_maximum_size() {
        let db = db().await;
        assert!(db.deposit("ft_a", 0, &vec![0; MAX_BLOB + 1], Duration::from_secs(60)).await.is_err());
        for _ in 0..MAX_BLOBS_MAIN_LIST {
            db.deposit("ft_a", 0, b"x", Duration::from_secs(60)).await.expect("within the quota");
        }
        assert!(db.deposit("ft_a", 0, b"x", Duration::from_secs(60)).await.is_err());
    }

    #[tokio::test]
    async fn the_mailbox_table_is_unlogged() {
        let db = db().await;
        assert_eq!(db.persistence("mailbox").await.unwrap(), "u");
        assert_eq!(db.persistence("devices").await.unwrap(), "p");
    }

    #[tokio::test]
    async fn each_registration_replaces_the_silent_slots() {
        let db = db().await;
        assert_eq!(db.silent_slots("ft_a").await.unwrap(), None, "not registered");
        db.register("ft_a", &KEY, &capability_hash(), 0b0000_0110).await.expect("registers");
        assert_eq!(db.silent_slots("ft_a").await.unwrap(), Some(0b0000_0110));
        db.register("ft_a", &KEY, &capability_hash(), 0).await.expect("re-registers");
        assert_eq!(db.silent_slots("ft_a").await.unwrap(), Some(0));
        db.register("ft_a", &KEY, &capability_hash(), 0b1111_1110).await.expect("re-registers");
        assert_eq!(db.silent_slots("ft_a").await.unwrap(), Some(0b1111_1110), "the whole byte");
    }

    #[tokio::test]
    async fn there_is_nowhere_to_push_for_a_silent_slot() {
        let db = db().await;
        db.register("ft_a", &KEY, &capability_hash(), 0b0000_1001).await.expect("registers");
        assert!(db.push_for("ft_a", 3).await.unwrap().is_none(), "no target yet");
        assert!(db.set_push("ft_a", "fcm", b"sealed").await.unwrap());
        assert_eq!(db.push_for("ft_a", 3).await.unwrap(), None, "slot 3 is silent");
        assert_eq!(db.push_for("ft_a", 2).await.unwrap(), Some(("fcm".to_owned(), b"sealed".to_vec())));
        assert_eq!(db.push_for("ft_a", 0).await.unwrap(), Some(("fcm".to_owned(), b"sealed".to_vec())), "the main list always");
        assert!(db.push_for("ft_unknown", 0).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn a_route_says_whether_its_slot_is_silent() {
        let db = db().await;
        db.register("ft_a", &KEY, &capability_hash(), 0b1000_1001).await.expect("registers");
        let mut hashes = [[0u8; 32]; 8];
        for (slot, hash) in hashes.iter_mut().enumerate() {
            *hash = *blake3::hash(&[slot as u8 + 10; 32]).as_bytes();
        }
        db.set_capabilities("ft_a", &hashes).await.expect("eight");
        assert_eq!(db.route("ft_a", &CAPABILITY).await.unwrap(), Some(Route { slot: 0, silent: false }), "the main list");
        assert_eq!(db.route("ft_a", &[13; 32]).await.unwrap(), Some(Route { slot: 3, silent: true }));
        assert_eq!(db.route("ft_a", &[14; 32]).await.unwrap(), Some(Route { slot: 4, silent: false }));
        assert_eq!(db.route("ft_a", &[17; 32]).await.unwrap(), Some(Route { slot: 7, silent: true }));
        assert_eq!(db.route("ft_a", &[99; 32]).await.unwrap(), None);
        assert_eq!(db.route("ft_unknown", &CAPABILITY).await.unwrap(), None);
    }

    #[tokio::test]
    async fn the_silent_slots_migration_applies_to_an_existing_database() {
        let pool = isolated_pool(&url()).await.expect("a fresh schema");
        migrator().run_to(3, &pool).await.expect("migrates up to 0003");
        sqlx::query("INSERT INTO devices (device_id, signing_key, capability_hash, push_provider, push_target) VALUES ('ft_old', $1, $2, 'fcm', $3)")
            .bind(KEY.as_slice())
            .bind(capability_hash().as_slice())
            .bind(b"sealed".as_slice())
            .execute(&pool)
            .await
            .expect("an existing device");

        let db = Db::migrated(pool).await.expect("migrates the rest");
        assert_eq!(db.silent_slots("ft_old").await.unwrap(), Some(0));
        assert_eq!(db.push_for("ft_old", 5).await.unwrap(), Some(("fcm".to_owned(), b"sealed".to_vec())));
        assert_eq!(db.signing_key("ft_old").await.unwrap(), Some(KEY));
    }

    #[tokio::test]
    async fn forgetting_a_device_removes_its_registration_and_mail() {
        let db = db().await;
        db.register("ft_a", &KEY, &capability_hash(), 0).await.expect("registers");
        db.deposit("ft_a", 0, b"one", Duration::from_secs(60)).await.expect("deposits");
        db.forget("ft_a").await.expect("forgets");
        assert!(db.signing_key("ft_a").await.unwrap().is_none());
        assert!(db.collect("ft_a").await.unwrap().is_empty());
    }

    async fn fill(db: &Db, device: &str, slot: u8, quota: i64) {
        for _ in 0..quota {
            db.deposit(device, slot, b"x", Duration::from_secs(60)).await.expect("within the quota");
        }
    }

    #[tokio::test]
    async fn a_session_that_fills_up_holds_back_no_other_slot() {
        let db = db().await;
        db.register("ft_a", &KEY, &capability_hash(), 0b0000_1000).await.expect("registers");
        fill(&db, "ft_a", 3, MAX_BLOBS_PER_SESSION).await;
        assert!(db.deposit("ft_a", 3, b"x", Duration::from_secs(60)).await.is_err(), "slot 3 is full");
        db.deposit("ft_a", 0, b"main", Duration::from_secs(60)).await.expect("the main list is not");
        db.deposit("ft_a", 5, b"five", Duration::from_secs(60)).await.expect("nor slot 5");

        fill(&db, "ft_a", 5, MAX_BLOBS_PER_SESSION - 1).await;
        assert!(db.deposit("ft_a", 5, b"x", Duration::from_secs(60)).await.is_err(), "a slot that is not silent fills the same way");
    }

    #[tokio::test]
    async fn the_main_list_keeps_its_quota() {
        assert_eq!(MAX_BLOBS_MAIN_LIST, 1000);
        let db = db().await;
        fill(&db, "ft_a", 6, MAX_BLOBS_PER_SESSION).await;
        fill(&db, "ft_a", 0, MAX_BLOBS_MAIN_LIST).await;
        assert!(db.deposit("ft_a", 0, b"x", Duration::from_secs(60)).await.is_err());
    }

    #[tokio::test]
    async fn expired_blobs_do_not_count_against_a_slot() {
        let db = db().await;
        for _ in 0..MAX_BLOBS_PER_SESSION {
            db.deposit("ft_a", 3, b"old", Duration::ZERO).await.expect("deposits");
        }
        db.deposit("ft_a", 3, b"new", Duration::from_secs(60)).await.expect("the expired ones do not count");
    }

    #[tokio::test]
    async fn opening_the_session_and_collecting_frees_its_quota() {
        let db = db().await;
        db.register("ft_a", &KEY, &capability_hash(), 0b0000_1000).await.expect("registers");
        fill(&db, "ft_a", 3, MAX_BLOBS_PER_SESSION).await;
        assert!(db.deposit("ft_a", 3, b"x", Duration::from_secs(60)).await.is_err());
        db.register("ft_a", &KEY, &capability_hash(), 0).await.expect("comes back");
        let (id, _) = db.collect("ft_a").await.unwrap()[0].clone();
        assert!(db.acknowledge("ft_a", id).await.unwrap());
        db.deposit("ft_a", 3, b"x", Duration::from_secs(60)).await.expect("room again");
    }

    async fn collectable(db: &Db, device: &str) -> Vec<Vec<u8>> {
        db.collect(device).await.expect("collects").into_iter().map(|(_, blob)| blob).collect()
    }

    #[tokio::test]
    async fn mail_through_a_silent_slot_is_kept_but_withheld() {
        let db = db().await;
        db.register("ft_a", &KEY, &capability_hash(), 0b0000_1000).await.expect("registers");
        db.deposit("ft_a", 0, b"main", Duration::from_secs(60)).await.expect("deposits");
        db.deposit("ft_a", 3, b"left", Duration::from_secs(60)).await.expect("deposits");
        db.deposit("ft_a", 5, b"five", Duration::from_secs(60)).await.expect("deposits");
        assert_eq!(collectable(&db, "ft_a").await, [b"main".to_vec(), b"five".to_vec()]);

        db.register("ft_a", &KEY, &capability_hash(), 0).await.expect("comes back");
        assert_eq!(collectable(&db, "ft_a").await, [b"main".to_vec(), b"left".to_vec(), b"five".to_vec()]);

        db.register("ft_a", &KEY, &capability_hash(), 0b0010_1000).await.expect("leaves again");
        assert_eq!(collectable(&db, "ft_a").await, [b"main".to_vec()], "withheld again, slot 5 too");
    }

    #[tokio::test]
    async fn withheld_mail_expires_like_any_other() {
        let db = db().await;
        db.register("ft_a", &KEY, &capability_hash(), 0b0000_1000).await.expect("registers");
        db.deposit("ft_a", 3, b"old", Duration::ZERO).await.expect("deposits");
        db.deposit("ft_a", 3, b"recent", Duration::from_secs(60)).await.expect("deposits");
        assert_eq!(db.purge_expired().await.expect("purges"), 1);
        db.register("ft_a", &KEY, &capability_hash(), 0).await.expect("comes back");
        assert_eq!(collectable(&db, "ft_a").await, [b"recent".to_vec()]);
    }

    #[tokio::test]
    async fn a_blob_comes_through_one_of_eight_slots() {
        let db = db().await;
        for slot in 0..8 {
            db.deposit("ft_a", slot, b"x", Duration::from_secs(60)).await.expect("one of the eight");
        }
        assert!(db.deposit("ft_a", 8, b"x", Duration::from_secs(60)).await.is_err());
        assert_eq!(db.collect("ft_a").await.unwrap().len(), 8);
    }

    #[tokio::test]
    async fn a_registration_tells_the_mask_it_replaced() {
        let db = db().await;
        assert_eq!(db.register("ft_a", &KEY, &capability_hash(), 0b0000_0110).await.unwrap(), 0, "new");
        assert_eq!(db.register("ft_a", &KEY, &capability_hash(), 0b0000_0010).await.unwrap(), 0b0000_0110);
        assert_eq!(db.register("ft_a", &KEY, &capability_hash(), 0).await.unwrap(), 0b0000_0010);
    }

    #[tokio::test]
    async fn mail_waiting_through_some_slots() {
        let db = db().await;
        db.deposit("ft_a", 3, b"x", Duration::from_secs(60)).await.expect("deposits");
        db.deposit("ft_a", 6, b"x", Duration::ZERO).await.expect("deposits");
        db.deposit("ft_b", 2, b"x", Duration::from_secs(60)).await.expect("deposits");
        assert!(db.mail_through("ft_a", 0b0000_1000).await.unwrap());
        assert!(db.mail_through("ft_a", 0b0100_1100).await.unwrap());
        assert!(!db.mail_through("ft_a", 0b0000_0100).await.unwrap(), "slot 2 is another device's");
        assert!(!db.mail_through("ft_a", 0b0100_0000).await.unwrap(), "expired");
        assert!(!db.mail_through("ft_a", 0).await.unwrap());
    }

    #[tokio::test]
    async fn the_mailbox_slot_migration_applies_to_a_database_from_0_5_1() {
        let pool = isolated_pool(&url()).await.expect("a fresh schema");
        migrator().run_to(4, &pool).await.expect("migrates up to 0004");
        sqlx::query("INSERT INTO devices (device_id, signing_key, capability_hash, silent_slots) VALUES ('ft_old', $1, $2, 254)")
            .bind(KEY.as_slice())
            .bind(capability_hash().as_slice())
            .execute(&pool)
            .await
            .expect("an existing device that left every session");
        sqlx::query("INSERT INTO mailbox (id, device_id, blob, expires_at) VALUES ($1, 'ft_old', 'waiting', now() + interval '1 hour')")
            .bind(Uuid::now_v7())
            .execute(&pool)
            .await
            .expect("mail waiting");

        let db = Db::migrated(pool).await.expect("migrates the rest");
        assert_eq!(collectable(&db, "ft_old").await, [b"waiting".to_vec()]);
        assert_eq!(db.persistence("mailbox").await.unwrap(), "u");
    }
}
