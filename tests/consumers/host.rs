//! An independent product host. Only public fixed-Git APIs are available here.
use rss_identity_core::{
    InstanceId, PrincipalId,
    account::{AccountKey, LoginKey, Password, PasswordKdf},
    session::{SessionPolicy, SessionSecret},
};
use rss_identity_postgres::*;
use rss_request_context::{Clock, Deadline, ExecutionTimer, TenantId};
use rss_transactional_messaging::{
    fence::{Epoch, ExecutionBinding, StorageIdentity},
    policy::{DeliveryBudget, OperationDeadline},
};
use rss_transactional_messaging_postgres::{PgConfig, PgPassword, PgRuntime};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
pub const PASSWORD: &str = "independent host password";
pub struct Timer;
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
pub struct Policy(AccountKey);
impl ManagementPolicy for Policy {
    fn authorize(
        &self,
        c: &ManagementContext<'_>,
    ) -> Result<ReauthenticationRequirement, ManagementDenied> {
        if c.actor() != self.0 {
            return Err(ManagementDenied);
        }
        Ok(ReauthenticationRequirement::Recent(Duration::from_secs(
            300,
        )))
    }
}
pub fn deadline() -> OperationDeadline {
    OperationDeadline::from_remaining(Duration::from_secs(30))
}
pub fn password() -> Password {
    Password::new(PASSWORD.into()).unwrap()
}
pub fn secret(s: &IssuedSession) -> SessionSecret {
    SessionSecret::parse(s.secret().expose().into()).unwrap()
}
pub struct Host {
    pub authority: Authority,
    pub maintenance: Authority,
    pub runtime: Arc<PgRuntime>,
    pub maintenance_runtime: Arc<PgRuntime>,
    pub key: AccountKey,
}
impl Host {
    pub async fn start() -> anyhow::Result<Self> {
        let port = std::env::var("IDENTITY_CONSUMER_PG_PORT")?.parse()?;
        let options = sqlx::postgres::PgConnectOptions::new()
            .host("127.0.0.1")
            .port(port)
            .username("postgres")
            .password("fixture-only")
            .database("postgres");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await?;
        sqlx::raw_sql("CREATE ROLE rss_tmsg_relay NOLOGIN NOBYPASSRLS; CREATE ROLE host_app LOGIN PASSWORD 'fixture-only' NOBYPASSRLS; CREATE ROLE host_maintenance LOGIN PASSWORD 'fixture-only' NOBYPASSRLS;").execute(&pool).await?;
        sqlx::raw_sql(rss_transactional_messaging_postgres::MIGRATION_SQL)
            .execute(&pool)
            .await?;
        let instance = InstanceId::generate();
        let tenant = TenantId::parse("11111111-1111-4111-8111-111111111111")?;
        let key = AccountKey {
            tenant,
            principal: PrincipalId::generate(),
        };
        let mut owner = pool.acquire().await?;
        install(&mut owner, instance).await?;
        grant_profile(&mut owner, "host_app", AuthorityProfile::Runtime).await?;
        grant_profile(
            &mut owner,
            "host_maintenance",
            AuthorityProfile::Maintenance,
        )
        .await?;
        drop(owner);
        sqlx::query("INSERT INTO rss_transactional_messaging.storage_lineage VALUES(true,$1,$2)")
            .bind([1u8; 16].as_slice())
            .bind([2u8; 16].as_slice())
            .execute(&pool)
            .await?;
        sqlx::query("INSERT INTO rss_transactional_messaging.tenant_epoch VALUES($1::uuid,1)")
            .bind(tenant.to_string())
            .execute(&pool)
            .await?;
        pool.close().await;
        let binding = ExecutionBinding::new(
            StorageIdentity::new([1; 16], [2; 16])?,
            vec![(tenant, Epoch::new(1)?)],
        )?;
        let runtime = Arc::new(
            PgRuntime::connect_producer(
                PgConfig::new_for_test_plaintext(
                    "127.0.0.1",
                    port,
                    "postgres",
                    "host_app",
                    PgPassword::new("fixture-only"),
                ),
                Timer,
                binding.clone(),
            )
            .await?,
        );
        let maintenance_runtime = Arc::new(
            PgRuntime::connect_producer(
                PgConfig::new_for_test_plaintext(
                    "127.0.0.1",
                    port,
                    "postgres",
                    "host_maintenance",
                    PgPassword::new("fixture-only"),
                ),
                Timer,
                binding,
            )
            .await?,
        );
        let config = AuthorityConfig::new(
            instance,
            vec![tenant],
            SessionPolicy::new(900, 14400)?,
            DeliveryBudget::new(
                Duration::from_secs(60),
                Duration::from_secs(5),
                Duration::from_secs(5),
                Duration::from_secs(5),
            )?,
        )?;
        let kdf = Arc::new(PasswordKdf::new());
        let authority = Authority::connect_runtime(
            runtime.clone(),
            kdf.clone(),
            config.clone(),
            Arc::new(Policy(key)),
            deadline(),
        )
        .await?;
        let maintenance =
            Authority::connect_maintenance(maintenance_runtime.clone(), kdf, config, deadline())
                .await?;
        maintenance
            .initialize(key, LoginKey::parse("operator")?, password(), deadline())
            .await?;
        Ok(Self {
            authority,
            maintenance,
            runtime,
            maintenance_runtime,
            key,
        })
    }
    pub async fn login(&self) -> anyhow::Result<IssuedSession> {
        Ok(self
            .authority
            .login_local(
                self.key.tenant,
                LoginKey::parse("operator")?,
                password(),
                AttemptSource::parse("consumer")?,
                None,
                deadline(),
            )
            .await?)
    }
    pub async fn actor(&self, s: &IssuedSession) -> anyhow::Result<AuthenticatedSession> {
        Ok(self
            .authority
            .authenticate_session(self.key.tenant, secret(s), deadline())
            .await?)
    }
    pub async fn close(self) {
        self.runtime.close().await;
        self.maintenance_runtime.close().await;
    }
}
