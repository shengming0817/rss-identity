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
pub fn deployment_identity() -> DeploymentIdentity {
    DeploymentIdentity::new(
        "fixture".into(),
        1,
        "https://identity.example.test".into(),
        "https://product.example.test".into(),
    )
    .unwrap()
}
pub const SYSTEM: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
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
    pub deployment: DeploymentIdentity,
    pub key: AccountKey,
    pub system_key: AccountKey,
    platform_cookie: tokio::sync::Mutex<Option<String>>,
    management_cookie: tokio::sync::Mutex<Option<String>>,
}
impl Fixture {
    pub async fn new() -> anyhow::Result<Self> {
        Self::with_identity(deployment_identity()).await
    }
    pub async fn with_identity(deployment: DeploymentIdentity) -> anyhow::Result<Self> {
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
        sqlx::query("UPDATE identity_authority.deployment SET environment_id=$1,identity_config_version=$2,identity_public_origin=$3,product_public_origin=$4").bind(deployment.environment()).bind(deployment.version()).bind(deployment.identity_origin()).bind(deployment.product_origin()).execute(&owner).await?;
        sqlx::raw_sql("GRANT identity_account_runtime TO identity_runtime; GRANT identity_account_maintenance TO identity_maintenance;").execute(&owner).await?;
        sqlx::raw_sql("GRANT USAGE ON SCHEMA rss_transactional_messaging TO identity_runtime; GRANT SELECT ON rss_transactional_messaging.policy TO identity_runtime;  GRANT SELECT,INSERT ON rss_transactional_messaging.outbox TO identity_runtime; GRANT USAGE ON ALL SEQUENCES IN SCHEMA rss_transactional_messaging TO identity_runtime; GRANT EXECUTE ON FUNCTION rss_transactional_messaging.check_execution() TO identity_runtime;").execute(&owner).await?;
        sqlx::raw_sql("GRANT USAGE ON SCHEMA rss_transactional_messaging TO identity_maintenance; GRANT SELECT ON rss_transactional_messaging.policy TO identity_maintenance;  GRANT SELECT,INSERT ON rss_transactional_messaging.outbox TO identity_maintenance; GRANT USAGE ON ALL SEQUENCES IN SCHEMA rss_transactional_messaging TO identity_maintenance; GRANT EXECUTE ON FUNCTION rss_transactional_messaging.check_execution() TO identity_maintenance;").execute(&owner).await?;
        sqlx::query("INSERT INTO rss_transactional_messaging.storage_lineage VALUES(true,$1,$2)")
            .bind([1_u8; 16].as_slice())
            .bind([2_u8; 16].as_slice())
            .execute(&owner)
            .await?;
        for tenant in [SYSTEM, B] {
            sqlx::query("INSERT INTO rss_transactional_messaging.tenant_epoch VALUES($1::uuid,1)")
                .bind(tenant)
                .execute(&owner)
                .await?;
        }
        let binding = ExecutionBinding::new(
            StorageIdentity::new([1; 16], [2; 16])?,
            vec![
                (TenantId::parse(SYSTEM)?, Epoch::new(1)?),
                (TenantId::parse(A)?, Epoch::new(1)?),
                (TenantId::parse(B)?, Epoch::new(1)?),
            ],
        )?;
        let runtime = Arc::new(
            PgRuntime::connect_producer(
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
            PgRuntime::connect_producer(
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
        sqlx::raw_sql(include_str!("../../../../app/identity/src/grants.sql"))
            .execute(&owner)
            .await?;
        let store = Authority::connect(
            runtime.clone(),
            std::sync::Arc::new(rss_identity_core::account::PasswordKdf::new()),
            deployment.clone(),
            budget,
            TenantId::parse(SYSTEM)?,
            AuthorityProfile::Runtime,
            deadline(),
        )
        .await?;
        let maintenance = Authority::connect(
            maintenance_runtime.clone(),
            std::sync::Arc::new(rss_identity_core::account::PasswordKdf::new()),
            deployment.clone(),
            budget,
            TenantId::parse(SYSTEM)?,
            AuthorityProfile::Maintenance,
            deadline(),
        )
        .await?;
        sqlx::raw_sql(include_str!("../../../../app/identity/src/grants.sql"))
            .execute(&owner)
            .await?;
        let keys = std::sync::Arc::new(CredentialKeys::new(
            "fixture".into(),
            vec![("fixture".into(), [8; 32])],
        )?);
        store.configure_credentials(keys.clone())?;
        maintenance.configure_credentials(keys)?;
        store.configure_runtime(RuntimeSource::new(
            PgConfig::new_for_test_plaintext(
                "127.0.0.1",
                port,
                &db,
                "identity_runtime",
                PgPassword::new("fixture-only"),
            ),
            StorageIdentity::new([1; 16], [2; 16])?,
            Epoch::new(1)?,
        ))?;
        Ok(Self {
            deployment,
            system_key: AccountKey {
                tenant: TenantId::parse(SYSTEM)?,
                principal: PrincipalId::generate(),
            },
            platform_cookie: tokio::sync::Mutex::new(None),
            management_cookie: tokio::sync::Mutex::new(None),
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
                (TenantId::parse(SYSTEM)?, Epoch::new(1)?),
                (TenantId::parse(A)?, Epoch::new(1)?),
                (TenantId::parse(B)?, Epoch::new(1)?),
            ],
        )?;
        Ok(Arc::new(
            PgRuntime::connect_producer(
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
            std::sync::Arc::new(rss_identity_core::account::PasswordKdf::new()),
            self.deployment.clone(),
            budget,
            TenantId::parse(SYSTEM).unwrap(),
            profile,
            deadline(),
        )
        .await
    }
    pub async fn bootstrap(&self) -> anyhow::Result<()> {
        self.maintenance
            .initialize(self.system_key, login("platform"), password(), deadline())
            .await?;
        self.provision_a().await?;
        Ok(())
    }
    pub async fn platform_actor(&self) -> anyhow::Result<AuthenticatedSession> {
        use rss_identity_core::session::SessionSecret;
        let mut cookie = self.platform_cookie.lock().await;
        if let Some(value) = cookie.as_ref()
            && let Ok(actor) = self
                .store
                .inspect_session(
                    TenantId::parse(SYSTEM)?,
                    SessionSecret::parse(value.clone())?,
                    deadline(),
                )
                .await
        {
            return Ok(actor);
        }
        let candidate = self
            .store
            .verify_password(
                TenantId::parse(SYSTEM)?,
                login("platform"),
                password(),
                source(),
                deadline(),
            )
            .await?;
        let session = self
            .store
            .create_session(candidate, None, deadline())
            .await?;
        *cookie = Some(session.secret().expose().into());
        Ok(self
            .store
            .inspect_session(
                TenantId::parse(SYSTEM)?,
                SessionSecret::parse(session.secret().expose().into())?,
                deadline(),
            )
            .await?)
    }
    pub async fn provision_a(&self) -> anyhow::Result<()> {
        self.store
            .provision_business_tenant(
                self.platform_actor().await?,
                "Tenant A".into(),
                NewTenantAdministrator {
                    operation_id: uuid::Uuid::new_v4(),
                    tenant: self.key.tenant,
                    principal: self.key.principal,
                    login: login("admin"),
                    password: password(),
                },
                deadline(),
            )
            .await?;
        Ok(())
    }
    pub async fn actor(&self) -> anyhow::Result<AuthenticatedSession> {
        use rss_identity_core::session::SessionSecret;
        let mut cookie = self.management_cookie.lock().await;
        if let Some(value) = cookie.as_ref() {
            match self
                .store
                .inspect_session(
                    self.key.tenant,
                    SessionSecret::parse(value.clone())?,
                    deadline(),
                )
                .await
            {
                Ok(proof) => return Ok(proof),
                Err(AuthorityError::Rejected) => {}
                Err(error) => return Err(error.into()),
            }
        }
        let issued = self
            .store
            .create_session(self.candidate().await?, None, deadline())
            .await?;
        *cookie = Some(issued.secret().expose().into());
        Ok(self
            .store
            .inspect_session(
                self.key.tenant,
                SessionSecret::parse(issued.secret().expose().into())?,
                deadline(),
            )
            .await?)
    }
    pub async fn account_events(&self) -> anyhow::Result<i64> {
        Ok(sqlx::query_scalar("SELECT count(*) FROM rss_transactional_messaging.outbox WHERE envelope->>'contract'='identity.account.security'").fetch_one(&self.owner).await?)
    }
    pub async fn candidate(&self) -> anyhow::Result<AuthenticationCandidate> {
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
        self.store.close().await;
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
            "DROP ROLE identity_account_runtime; DROP ROLE identity_account_maintenance; DROP ROLE identity_tenant_registrar;",
        )
        .execute(&self.admin)
        .await
        .unwrap();
        self.admin.close().await;
    }
}

// Exercise the concrete session APIs while sharing the existing account transition matrix.
pub async fn apply_change(
    store: &Authority,
    actor: AuthenticatedSession,
    target: rss_identity_core::account::AccountKey,
    change: rss_identity_core::account::AccountChange,
    deadline: rss_transactional_messaging::policy::OperationDeadline,
) -> Result<rss_identity_core::account::AccountState, AuthorityError> {
    use rss_identity_core::account::AccountChange;
    match change {
        AccountChange::Enabled(v) => store.set_account_enabled(actor, target, v, deadline).await,
        AccountChange::Administrator(v) => {
            store
                .set_account_administrator(actor, target, v, deadline)
                .await
        }
        AccountChange::Membership(v) => {
            store
                .set_account_membership(actor, target, v, deadline)
                .await
        }
        AccountChange::Password(v) if actor.account() == target => {
            store
                .change_own_password(actor, password(), v, source(), deadline)
                .await
        }
        AccountChange::Password(v) => store.reset_local_password(actor, target, v, deadline).await,
    }
}

pub async fn session_actor(
    store: &Authority,
    candidate: AuthenticationCandidate,
) -> anyhow::Result<AuthenticatedSession> {
    let tenant = candidate.account().tenant;
    let issued = store.create_session(candidate, None, deadline()).await?;
    Ok(store
        .inspect_session(
            tenant,
            rss_identity_core::session::SessionSecret::parse(issued.secret().expose().into())?,
            deadline(),
        )
        .await?)
}
