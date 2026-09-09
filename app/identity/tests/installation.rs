//! Real TLS PostgreSQL / production config seam, without a product listener or browser.
use rss_identity_app::{
    assembly,
    config::{MigrationConfig, RuntimeConfig},
    migration,
};
use rss_identity_core::account::PasswordKdf;
use rss_identity_postgres::{Authority, AuthorityProfile, DeploymentIdentity};
use rss_transactional_messaging_postgres::PgRuntime;
use sqlx::Connection;
use std::{path::PathBuf, sync::Arc};
#[tokio::test]
#[ignore = "requires make test-assembly"]
async fn installation_configuration_and_rollback_are_verified() -> anyhow::Result<()> {
    let root = PathBuf::from(std::env::var("IDENTITY_TEST_INSTALL_DIR")?);
    let port: u16 = std::env::var("IDENTITY_TEST_PG_PORT")?.parse()?;
    let origin = serde_json::json!({"environment_id":"installation-test","config_version":1,"identity_public_origin":"https://identity.test","product_public_origin":"https://product.test"});
    let value = serde_json::json!({"format_version":1,"identity_origin":origin,"database":{"host":"127.0.0.1","port":port,"database":"postgres","user":"postgres","password_file":root.join("owner"),"ca_file":root.join("server.crt")},"storage":{"target":vec![1;16],"lineage":vec![2;16],"tenants":[{"tenant_id":"11111111-1111-4111-8111-111111111111","epoch":1}]},"runtime_password_file":root.join("runtime"),"maintenance_password_file":root.join("maintenance")});
    let config = || serde_json::from_value::<MigrationConfig>(value.clone()).unwrap();
    let mut owner = sqlx::PgConnection::connect_with(&config().database.sqlx()?).await?;
    sqlx::raw_sql("CREATE ROLE identity_account_runtime NOLOGIN")
        .execute(&mut owner)
        .await?;
    assert!(migration::install(config()).await.is_err());
    let absent:bool=sqlx::query_scalar("SELECT to_regnamespace('rss_transactional_messaging') IS NULL AND to_regnamespace('identity_authority') IS NULL").fetch_one(&mut owner).await?;
    assert!(
        absent,
        "failure must roll back the entire local installation"
    );
    sqlx::raw_sql("DROP ROLE identity_account_runtime")
        .execute(&mut owner)
        .await?;
    // A pre-existing member of the SECURITY DEFINER owner must not inherit future relay powers.
    sqlx::raw_sql("CREATE ROLE rss_tmsg_relay NOLOGIN; CREATE ROLE untrusted_member NOLOGIN; GRANT rss_tmsg_relay TO untrusted_member").execute(&mut owner).await?;
    assert!(migration::install(config()).await.is_err());
    let absent: bool =
        sqlx::query_scalar("SELECT to_regnamespace('rss_transactional_messaging') IS NULL")
            .fetch_one(&mut owner)
            .await?;
    assert!(absent);
    sqlx::raw_sql("REVOKE rss_tmsg_relay FROM untrusted_member")
        .execute(&mut owner)
        .await?;
    let (first, second) = tokio::join!(migration::install(config()), migration::install(config()));
    first?;
    second?;
    sqlx::raw_sql("GRANT rss_tmsg_relay TO untrusted_member")
        .execute(&mut owner)
        .await?;
    assert!(migration::install(config()).await.is_err());
    sqlx::raw_sql("REVOKE rss_tmsg_relay FROM untrusted_member; DROP ROLE untrusted_member")
        .execute(&mut owner)
        .await?;
    let mut wrong = config();
    wrong.identity_origin = DeploymentIdentity::new(
        "other-env".into(),
        1,
        "https://identity.test".into(),
        "https://product.test".into(),
    )?;
    assert!(migration::install(wrong).await.is_err());
    let c = config();
    let mut db = c.database.clone();
    db.user = "identity_runtime".into();
    db.password_file = c.runtime_password_file.clone();
    // Exercise the real application startup failure after PG acquisition, without running a product stack.
    let mut runtime_value: serde_json::Value =
        serde_json::from_str(include_str!("../../../deployment/example.json"))?;
    runtime_value = runtime_value["runtime"].clone();
    runtime_value["identity_origin"] = serde_json::to_value(&c.identity_origin)?;
    runtime_value["database"] = serde_json::json!({"host":"127.0.0.1","port":port,"database":"postgres","user":"identity_runtime","password_file":root.join("runtime"),"ca_file":root.join("server.crt")});
    let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    runtime_value["listen"] = serde_json::json!(occupied.local_addr()?.to_string());
    runtime_value["budgets"] =
        serde_json::json!({"request_seconds":1,"resource_seconds":2,"drain_seconds":4});
    runtime_value["oidc"]["state_key_file"] = serde_json::json!(root.join("state-key"));
    runtime_value["oidc"]["ca_file"] = serde_json::json!(root.join("server.crt"));
    runtime_value["oidc"]["providers"][0]["secret_file"] = serde_json::json!(root.join("runtime"));
    runtime_value["hydra"]["ca_file"] = serde_json::json!(root.join("server.crt"));
    runtime_value["hydra"]["service_secret_file"] = serde_json::json!(root.join("runtime"));
    runtime_value["hydra"]["clients"][0]["oidc_secret_file"] =
        serde_json::json!(root.join("runtime"));
    runtime_value["hydra"]["clients"][0]["validation_secret_file"] =
        serde_json::json!(root.join("maintenance"));
    let runtime_config = serde_json::from_value(runtime_value)?;
    let failed = tokio::time::timeout(
        std::time::Duration::from_secs(6),
        rss_identity_app::lifecycle::serve(runtime_config, std::future::pending()),
    )
    .await?;
    assert!(matches!(
        failed,
        Err(rss_identity_app::AppError::Connection)
    ));
    let leaked: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_stat_activity WHERE usename='identity_runtime'",
    )
    .fetch_one(&mut owner)
    .await?;
    assert_eq!(
        leaked, 0,
        "failed startup must close the acquired runtime pool"
    );
    let pool = Arc::new(
        PgRuntime::connect_producer(db.pg()?, assembly::Timer, c.storage.binding()?).await?,
    );
    let kdf = Arc::new(PasswordKdf::new());
    let tenant = c.storage.tenants()?[0];
    let authority = Authority::connect(
        pool.clone(),
        kdf.clone(),
        c.identity_origin.clone(),
        assembly::delivery_budget()?,
        tenant,
        AuthorityProfile::Runtime,
        assembly::deadline(),
    )
    .await?;
    drop(authority);
    let wrong = DeploymentIdentity::new(
        "installation-test".into(),
        2,
        "https://identity.test".into(),
        "https://product.test".into(),
    )?;
    assert!(
        Authority::connect(
            pool.clone(),
            kdf.clone(),
            wrong,
            assembly::delivery_budget()?,
            tenant,
            AuthorityProfile::Runtime,
            assembly::deadline()
        )
        .await
        .is_err()
    );
    // The app is a producer: neither runtime nor maintenance may acquire relay authority.
    for statement in [
        "GRANT EXECUTE ON FUNCTION rss_transactional_messaging.claim_outbox(uuid,text,integer,bigint) TO identity_runtime",
        "GRANT EXECUTE ON FUNCTION rss_transactional_messaging.outbox_lease(uuid,bigint,uuid,bigint,bigint,uuid) TO identity_maintenance",
        "GRANT EXECUTE ON FUNCTION rss_transactional_messaging.settle_outbox(uuid,bigint,uuid,bigint,text,uuid) TO identity_runtime",
        "GRANT SELECT ON rss_transactional_messaging.inbox TO identity_runtime",
    ] {
        sqlx::raw_sql(statement).execute(&mut owner).await?;
        assert!(migration::install(config()).await.is_err());
        sqlx::raw_sql("REVOKE ALL ON FUNCTION rss_transactional_messaging.claim_outbox(uuid,text,integer,bigint),rss_transactional_messaging.outbox_lease(uuid,bigint,uuid,bigint,bigint,uuid),rss_transactional_messaging.settle_outbox(uuid,bigint,uuid,bigint,text,uuid) FROM identity_runtime,identity_maintenance; REVOKE ALL ON rss_transactional_messaging.inbox FROM identity_runtime,identity_maintenance").execute(&mut owner).await?;
    }
    migration::install(config()).await?;
    // Normal runtime settings/artifact versions are not deployment identity.
    let again = Authority::connect(
        pool.clone(),
        kdf.clone(),
        c.identity_origin.clone(),
        assembly::delivery_budget()?,
        tenant,
        AuthorityProfile::Runtime,
        assembly::deadline(),
    )
    .await?;
    drop(again);
    assert!(
        sqlx::query("UPDATE identity_authority.deployment SET environment_id='takeover'")
            .execute(&mut owner)
            .await
            .is_err()
    );
    pool.close().await;
    kdf.close();
    kdf.wait_closed().await;
    sqlx::raw_sql(
        "GRANT UPDATE(environment_id) ON identity_authority.deployment TO identity_runtime",
    )
    .execute(&mut owner)
    .await?;
    assert!(migration::install(config()).await.is_err());
    sqlx::raw_sql(
        "REVOKE UPDATE(environment_id) ON identity_authority.deployment FROM identity_runtime",
    )
    .execute(&mut owner)
    .await?;
    migration::install(config()).await?;
    // The runtime format has no maintenance credential slot.
    let mut runtime = value.clone();
    runtime["maintenance_password_file"] = serde_json::json!("private");
    assert!(serde_json::from_value::<RuntimeConfig>(runtime).is_err());
    owner.close().await?;
    Ok(())
}
