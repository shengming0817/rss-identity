use rss_identity_core::account::AccountKey;
use rss_identity_core::{
    PrincipalId,
    account::{LoginKey, Password},
};
use rss_identity_postgres::*;
use rss_request_context::{Clock, Deadline, ExecutionTimer, TenantId};
use rss_transactional_messaging::{
    fence::{Epoch, ExecutionBinding, StorageIdentity},
    policy::{DeliveryBudget, OperationDeadline},
};
use rss_transactional_messaging_postgres::{PgConfig, PgPassword, PgRuntime};
use sqlx::{
    PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
pub const A: &str = "11111111-1111-4111-8111-111111111111";
pub const B: &str = "22222222-2222-4222-8222-222222222222";
pub const PASSWORD: &str = "correct horse battery staple";
pub fn password() -> Password {
    Password::new(PASSWORD.into()).unwrap()
}
pub fn login(s: &str) -> LoginKey {
    LoginKey::parse(s).unwrap()
}
pub fn source() -> AttemptSource {
    AttemptSource::parse("local-test").unwrap()
}
pub fn deadline() -> OperationDeadline {
    OperationDeadline::from_remaining(Duration::from_secs(30))
}
struct Timer;
impl Clock for Timer {
    fn now(&self) -> Instant {
        Instant::now()
    }
}
impl ExecutionTimer for Timer {
    async fn sleep_until(&self, d: Deadline) {
        tokio::time::sleep(d.remaining(self.now()).unwrap_or_default()).await;
    }
}
pub struct Fixture {
    pub owner: PgPool,
    pub admin: PgPool,
    pub database: String,
    pub port: u16,
    pub runtime: Arc<PgRuntime>,
    pub maintenance_runtime: Arc<PgRuntime>,
    pub store: Authority,
    pub maintenance: Authority,
    pub key: AccountKey,
}
impl Fixture {
    pub async fn new() -> anyhow::Result<Self> {
        let port = std::env::var("IDENTITY_TEST_PG_PORT")?.parse()?;
        let options = PgConnectOptions::new()
            .host("127.0.0.1")
            .port(port)
            .username("postgres")
            .password("fixture-only");
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect_with(options.clone().database("postgres"))
            .await?;
        let db = format!("identity_{}", uuid::Uuid::new_v4().simple());
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {db}")))
            .execute(&admin)
            .await?;
        let owner = PgPoolOptions::new()
            .max_connections(4)
            .connect_with(options.database(&db))
            .await?;
        sqlx::raw_sql("DO $$ BEGIN IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='rss_tmsg_relay') THEN CREATE ROLE rss_tmsg_relay NOLOGIN NOBYPASSRLS; CREATE ROLE identity_runtime LOGIN PASSWORD 'fixture-only' NOBYPASSRLS; CREATE ROLE identity_maintenance LOGIN PASSWORD 'fixture-only' NOBYPASSRLS; END IF; END $$;").execute(&owner).await?;
        sqlx::raw_sql(rss_transactional_messaging_postgres::MIGRATION_SQL)
            .execute(&owner)
            .await?;
        sqlx::raw_sql(MIGRATION_SQL).execute(&owner).await?;
        sqlx::raw_sql("GRANT identity_account_runtime TO identity_runtime; GRANT identity_account_maintenance TO identity_maintenance;").execute(&owner).await?;
        sqlx::raw_sql("GRANT USAGE ON SCHEMA rss_transactional_messaging TO identity_runtime; GRANT SELECT ON rss_transactional_messaging.policy TO identity_runtime; GRANT SELECT,INSERT,UPDATE,DELETE ON rss_transactional_messaging.inbox TO identity_runtime; GRANT SELECT,INSERT ON rss_transactional_messaging.outbox TO identity_runtime; GRANT USAGE ON ALL SEQUENCES IN SCHEMA rss_transactional_messaging TO identity_runtime; GRANT EXECUTE ON FUNCTION rss_transactional_messaging.claim_outbox(uuid,text,integer,bigint),rss_transactional_messaging.outbox_lease(uuid,bigint,uuid,bigint,bigint,uuid),rss_transactional_messaging.settle_outbox(uuid,bigint,uuid,bigint,text,uuid),rss_transactional_messaging.check_execution() TO identity_runtime;").execute(&owner).await?;
        sqlx::raw_sql("GRANT USAGE ON SCHEMA rss_transactional_messaging TO identity_maintenance; GRANT SELECT ON rss_transactional_messaging.policy TO identity_maintenance; GRANT SELECT,INSERT,UPDATE,DELETE ON rss_transactional_messaging.inbox TO identity_maintenance; GRANT SELECT,INSERT ON rss_transactional_messaging.outbox TO identity_maintenance; GRANT USAGE ON ALL SEQUENCES IN SCHEMA rss_transactional_messaging TO identity_maintenance; GRANT EXECUTE ON FUNCTION rss_transactional_messaging.claim_outbox(uuid,text,integer,bigint),rss_transactional_messaging.outbox_lease(uuid,bigint,uuid,bigint,bigint,uuid),rss_transactional_messaging.settle_outbox(uuid,bigint,uuid,bigint,text,uuid),rss_transactional_messaging.check_execution() TO identity_maintenance;").execute(&owner).await?;
        sqlx::query("INSERT INTO rss_transactional_messaging.storage_lineage VALUES(true,$1,$2)")
            .bind([1_u8; 16].as_slice())
            .bind([2_u8; 16].as_slice())
            .execute(&owner)
            .await?;
        for tenant in [A, B] {
            sqlx::query("INSERT INTO rss_transactional_messaging.tenant_epoch VALUES($1::uuid,1)")
                .bind(tenant)
                .execute(&owner)
                .await?;
        }
        let binding = ExecutionBinding::new(
            StorageIdentity::new([1; 16], [2; 16])?,
            vec![
                (TenantId::parse(A)?, Epoch::new(1)?),
                (TenantId::parse(B)?, Epoch::new(1)?),
            ],
        )?;
        let runtime = Arc::new(
            PgRuntime::connect(
                PgConfig::new_for_test_plaintext(
                    "127.0.0.1",
                    port,
                    &db,
                    "identity_runtime",
                    PgPassword::new("fixture-only"),
                ),
                Timer,
                binding.clone(),
            )
            .await?,
        );
        let maintenance_runtime = Arc::new(
            PgRuntime::connect(
                PgConfig::new_for_test_plaintext(
                    "127.0.0.1",
                    port,
                    &db,
                    "identity_maintenance",
                    PgPassword::new("fixture-only"),
                ),
                Timer,
                binding,
            )
            .await?,
        );
        let budget = DeliveryBudget::new(
            Duration::from_secs(60),
            Duration::from_secs(5),
            Duration::from_secs(5),
            Duration::from_secs(5),
        )?;
        let store = Authority::connect(
            runtime.clone(),
            budget,
            TenantId::parse(A)?,
            AuthorityProfile::Runtime,
            deadline(),
        )
        .await?;
        let maintenance = Authority::connect(
            maintenance_runtime.clone(),
            budget,
            TenantId::parse(A)?,
            AuthorityProfile::Maintenance,
            deadline(),
        )
        .await?;
        Ok(Self {
            owner,
            admin,
            database: db,
            port,
            runtime,
            maintenance_runtime,
            store,
            maintenance,
            key: AccountKey {
                tenant: TenantId::parse(A)?,
                principal: PrincipalId::generate(),
            },
        })
    }
    pub async fn additional_runtime(&self) -> anyhow::Result<Arc<PgRuntime>> {
        let binding = ExecutionBinding::new(
            StorageIdentity::new([1; 16], [2; 16])?,
            vec![
                (TenantId::parse(A)?, Epoch::new(1)?),
                (TenantId::parse(B)?, Epoch::new(1)?),
            ],
        )?;
        Ok(Arc::new(
            PgRuntime::connect(
                PgConfig::new_for_test_plaintext(
                    "127.0.0.1",
                    self.port,
                    &self.database,
                    "identity_runtime",
                    PgPassword::new("fixture-only"),
                ),
                Timer,
                binding,
            )
            .await?,
        ))
    }
    pub async fn probe(&self, profile: AuthorityProfile) -> Result<Authority, AuthorityError> {
        let budget = DeliveryBudget::new(
            Duration::from_secs(60),
            Duration::from_secs(5),
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
        .unwrap();
        Authority::connect(
            self.runtime.clone(),
            budget,
            self.key.tenant,
            profile,
            deadline(),
        )
        .await
    }
    pub async fn bootstrap(&self) -> anyhow::Result<()> {
        self.maintenance
            .initialize(self.key, login("Admin"), password(), deadline())
            .await?;
        Ok(())
    }
    pub async fn actor(&self) -> anyhow::Result<AuthenticationCandidate> {
        Ok(self
            .store
            .verify_password(
                self.key.tenant,
                login("admin"),
                password(),
                source(),
                deadline(),
            )
            .await?)
    }
    pub async fn reset_attempts(&self) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM identity_authority.attempts")
            .execute(&self.owner)
            .await?;
        Ok(())
    }
    pub async fn events(&self) -> anyhow::Result<i64> {
        Ok(
            sqlx::query_scalar("SELECT count(*) FROM rss_transactional_messaging.outbox")
                .fetch_one(&self.owner)
                .await?,
        )
    }
    pub async fn close(self) {
        self.runtime.close().await;
        self.maintenance_runtime.close().await;
        self.owner.close().await;
        // Generated UUID database identity; no caller input enters SQL identifiers.
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP DATABASE {}",
            self.database
        )))
        .execute(&self.admin)
        .await
        .unwrap();
        sqlx::raw_sql(
            "DROP ROLE identity_account_runtime; DROP ROLE identity_account_maintenance;",
        )
        .execute(&self.admin)
        .await
        .unwrap();
        self.admin.close().await;
    }
}
