//! Public-API-only host on an isolated disposable PG, consuming a fixed Identity revision.
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
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

const TENANT: &str = "11111111-1111-4111-8111-111111111111";
fn deadline() -> OperationDeadline {
    OperationDeadline::from_remaining(Duration::from_secs(30))
}
struct Timer;
impl Clock for Timer {
    fn now(&self) -> Instant {
        Instant::now()
    }
}
impl ExecutionTimer for Timer {
    async fn sleep_until(&self, deadline: Deadline) {
        tokio::time::sleep(deadline.remaining(self.now()).unwrap_or_default()).await;
    }
}
struct DenyManagement;
impl ManagementPolicy for DenyManagement {
    fn authorize<'a>(
        &'a self,
        _: &'a ManagementContext<'a>,
        _: &'a mut sqlx::PgConnection,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<ReauthenticationRequirement, ManagementDenied>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async { Err(ManagementDenied) })
    }
}
async fn runtime(port: u16, role: &str, tenant: TenantId) -> anyhow::Result<Arc<PgRuntime>> {
    Ok(Arc::new(
        PgRuntime::connect_producer(
            PgConfig::new_for_test_plaintext(
                "127.0.0.1",
                port,
                "identity_consumer",
                role,
                PgPassword::new("fixture-only"),
            ),
            Timer,
            ExecutionBinding::new(
                StorageIdentity::new([1; 16], [2; 16])?,
                vec![(tenant, Epoch::new(1)?)],
            )?,
        )
        .await?,
    ))
}

pub async fn run() -> anyhow::Result<()> {
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
    sqlx::query("CREATE DATABASE identity_consumer")
        .execute(&admin)
        .await?;
    let owner = PgPoolOptions::new()
        .max_connections(2)
        .connect_with(options.database("identity_consumer"))
        .await?;
    sqlx::raw_sql("CREATE ROLE rss_tmsg_relay NOLOGIN NOBYPASSRLS; CREATE ROLE identity_runtime LOGIN PASSWORD 'fixture-only' NOBYPASSRLS; CREATE ROLE identity_maintenance LOGIN PASSWORD 'fixture-only' NOBYPASSRLS").execute(&owner).await?;
    sqlx::raw_sql(rss_transactional_messaging_postgres::MIGRATION_SQL)
        .execute(&owner)
        .await?;
    let tenant = TenantId::parse(TENANT)?;
    let instance = InstanceId::generate();
    let mut c = owner.acquire().await?;
    install(&mut c, instance).await?;
    grant_profile(&mut c, "identity_runtime", AuthorityProfile::Runtime).await?;
    grant_profile(
        &mut c,
        "identity_maintenance",
        AuthorityProfile::Maintenance,
    )
    .await?;
    drop(c);
    // Host-owned deployment/fencing setup belongs to RSS, not Identity private storage.
    sqlx::query("INSERT INTO rss_transactional_messaging.storage_lineage VALUES(true,$1,$2)")
        .bind([1u8; 16].as_slice())
        .bind([2u8; 16].as_slice())
        .execute(&owner)
        .await?;
    sqlx::query("INSERT INTO rss_transactional_messaging.tenant_epoch VALUES($1::uuid,1)")
        .bind(TENANT)
        .execute(&owner)
        .await?;
    sqlx::raw_sql("CREATE TABLE public.host_binding(id integer PRIMARY KEY); GRANT INSERT,SELECT ON public.host_binding TO identity_runtime").execute(&owner).await?;
    let runtime = runtime(port, "identity_runtime", tenant).await?;
    let maintenance_runtime = self::runtime(port, "identity_maintenance", tenant).await?;
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
    let maintenance = Authority::connect_maintenance(
        maintenance_runtime.clone(),
        Arc::new(PasswordKdf::new()),
        config.clone(),
        deadline(),
    )
    .await?;
    let authority = Authority::connect_runtime(
        runtime.clone(),
        Arc::new(PasswordKdf::new()),
        config,
        Arc::new(DenyManagement),
        deadline(),
    )
    .await?;
    let key = AccountKey {
        tenant,
        principal: PrincipalId::generate(),
    };
    maintenance
        .initialize(
            key,
            LoginKey::parse("host-user")?,
            Password::new("correct horse battery staple".into())?,
            deadline(),
        )
        .await?;
    let issued = authority
        .login_local(
            tenant,
            LoginKey::parse("host-user")?,
            Password::new("correct horse battery staple".into())?,
            AttemptSource::parse("consumer")?,
            None,
            deadline(),
        )
        .await?;
    let actor = Arc::new(
        authority
            .inspect_session(
                tenant,
                SessionSecret::parse(issued.secret().expose().into())?,
                deadline(),
            )
            .await?,
    );
    for commit in [true, false] {
        let actor = actor.clone();
        let result = runtime
            .local_tx(tenant, deadline(), move |tx| {
                Box::pin(async move {
                    tx.with_connection(move |c| {
                        Box::pin(
                            async move { Ok(recheck_authenticated_session_on(c, &actor).await) },
                        )
                    })
                    .await??;
                    tx.with_connection(move |c| {
                        Box::pin(async move {
                            sqlx::query("INSERT INTO public.host_binding VALUES($1)")
                                .bind(i32::from(commit))
                                .execute(c)
                                .await?;
                            Ok(())
                        })
                    })
                    .await?;
                    if !commit {
                        return Err(sqlx::Error::Protocol("host rolled back".into()).into());
                    }
                    Ok(())
                })
            })
            .await;
        let state = result.fold(
            |_| "committed",
            |_| "not-started",
            |_| "rolled-back",
            |_| "rollback-failed",
            |_| "commit-unknown",
            |_| "fenced",
        );
        anyhow::ensure!(state == if commit { "committed" } else { "rolled-back" });
    }
    let revoker = authority
        .inspect_session(
            tenant,
            SessionSecret::parse(issued.secret().expose().into())?,
            deadline(),
        )
        .await?;
    authority
        .revoke_current_session(revoker, deadline())
        .await?;
    let result = runtime
        .local_tx(tenant, deadline(), move |tx| {
            Box::pin(async move {
                tx.with_connection(move |c| {
                    Box::pin(async move { Ok(recheck_authenticated_session_on(c, &actor).await) })
                })
                .await??;
                tx.with_connection(move |c| {
                    Box::pin(async move {
                        sqlx::query("INSERT INTO public.host_binding VALUES(2)")
                            .execute(c)
                            .await?;
                        Ok(())
                    })
                })
                .await
            })
        })
        .await;
    anyhow::ensure!(result.fold(
        |_| false,
        |_| false,
        |_| true,
        |_| false,
        |_| false,
        |_| false
    ));
    let rows: Vec<i32> = sqlx::query_scalar("SELECT id FROM public.host_binding ORDER BY id")
        .fetch_all(&owner)
        .await?;
    anyhow::ensure!(rows == vec![1]);
    runtime.close().await;
    maintenance_runtime.close().await;
    owner.close().await;
    sqlx::query("DROP DATABASE identity_consumer")
        .execute(&admin)
        .await?;
    admin.close().await;
    println!(
        "fixed-revision live session: host commit, rollback and revoked-session rejection passed"
    );
    Ok(())
}
