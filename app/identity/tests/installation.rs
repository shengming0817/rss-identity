//! Real TLS PostgreSQL / production config seam, without a product listener or browser.
use rss_identity_app::{
    assembly,
    config::{MigrationConfig, RuntimeConfig},
    migration,
};
use rss_identity_core::account::PasswordKdf;
use rss_identity_postgres::{Authority, DeploymentIdentity};
use rss_transactional_messaging_postgres::PgRuntime;
use sqlx::Connection;
use std::{path::PathBuf, sync::Arc};
#[tokio::test]
#[ignore = "requires make test-assembly"]
async fn installation_configuration_and_rollback_are_verified() -> anyhow::Result<()> {
    let root = PathBuf::from(std::env::var("IDENTITY_TEST_INSTALL_DIR")?);
    let port: u16 = std::env::var("IDENTITY_TEST_PG_PORT")?.parse()?;
    std::fs::write(root.join("credential-key"), "08".repeat(32))?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            root.join("credential-key"),
            std::fs::Permissions::from_mode(0o600),
        )?;
    }
    let origin = serde_json::json!({"environment_id":"installation-test","config_version":1,"identity_public_origin":"https://identity.test","product_public_origin":"https://product.test"});
    let value = serde_json::json!({"format_version":2,"identity_origin":origin,"database":{"host":"127.0.0.1","port":port,"database":"postgres","user":"postgres","password_file":root.join("owner"),"ca_file":root.join("server.crt")},"storage":{"target":vec![1;16],"lineage":vec![2;16],"system_domain_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","generation":1},"runtime_password_file":root.join("runtime"),"maintenance_password_file":root.join("maintenance"),"credential_keyring":{"active_key_id":"initial","keys":[{"key_id":"initial","path":root.join("credential-key")}] }});
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
    runtime_value["oidc"]["credential_keyring"] = value["credential_keyring"].clone();
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
    let tenant = c.storage.system()?;
    let authority = Authority::connect_runtime(
        pool.clone(),
        kdf.clone(),
        c.identity_origin.clone(),
        assembly::delivery_budget()?,
        tenant,
        rss_identity_postgres::RuntimeConfiguration::new(
            rss_identity_postgres::RuntimeSource::new(
                db.pg()?,
                c.storage.identity()?,
                c.storage.epoch()?,
            ),
            c.credential_keyring.load()?,
        ),
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
        Authority::connect_runtime(
            pool.clone(),
            kdf.clone(),
            wrong,
            assembly::delivery_budget()?,
            tenant,
            rss_identity_postgres::RuntimeConfiguration::new(
                rss_identity_postgres::RuntimeSource::new(
                    db.pg()?,
                    c.storage.identity()?,
                    c.storage.epoch()?
                ),
                c.credential_keyring.load()?
            ),
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
    let again = Authority::connect_runtime(
        pool.clone(),
        kdf.clone(),
        c.identity_origin.clone(),
        assembly::delivery_budget()?,
        tenant,
        rss_identity_postgres::RuntimeConfiguration::new(
            rss_identity_postgres::RuntimeSource::new(
                db.pg()?,
                c.storage.identity()?,
                c.storage.epoch()?,
            ),
            c.credential_keyring.load()?,
        ),
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
    credential_rekey_is_bounded_and_fenced(config(), &root).await?;
    owner.close().await?;
    Ok(())
}

async fn credential_rekey_is_bounded_and_fenced(
    mut config: MigrationConfig,
    root: &std::path::Path,
) -> anyhow::Result<()> {
    use rss_identity_core::{
        PrincipalId,
        account::{AccountKey, LoginKey, Password},
        federation::{ProviderCredentials, ProviderSettings, StateSigner},
        session::SessionSecret,
    };
    use rss_identity_postgres::{
        AttemptSource, CredentialKeys, Federation, NewTenantAdministrator,
    };
    use std::{collections::BTreeMap, os::unix::fs::PermissionsExt};
    let system = config.storage.system()?;
    let mut database = config.database.clone();
    database.user = "identity_maintenance".into();
    database.password_file = config.maintenance_password_file.clone();
    let maintenance_pool = Arc::new(
        PgRuntime::connect_producer(database.pg()?, assembly::Timer, config.storage.binding()?)
            .await?,
    );
    let kdf = Arc::new(PasswordKdf::new());
    let maintenance = Authority::connect_maintenance(
        maintenance_pool.clone(),
        kdf.clone(),
        config.identity_origin.clone(),
        assembly::delivery_budget()?,
        system,
        assembly::deadline(),
    )
    .await?;
    let password =
        || Password::new("synthetic-installation-administrator-password".into()).unwrap();
    maintenance
        .initialize(
            AccountKey {
                tenant: system,
                principal: PrincipalId::generate(),
            },
            LoginKey::parse("platform")?,
            password(),
            assembly::deadline(),
        )
        .await?;
    database.user = "identity_runtime".into();
    database.password_file = config.runtime_password_file.clone();
    let pool = Arc::new(
        PgRuntime::connect_producer(database.pg()?, assembly::Timer, config.storage.binding()?)
            .await?,
    );
    let authority = Authority::connect_runtime(
        pool,
        kdf.clone(),
        config.identity_origin.clone(),
        assembly::delivery_budget()?,
        system,
        rss_identity_postgres::RuntimeConfiguration::new(
            rss_identity_postgres::RuntimeSource::new(
                database.pg()?,
                config.storage.identity()?,
                config.storage.epoch()?,
            ),
            config.credential_keyring.load()?,
        ),
        assembly::deadline(),
    )
    .await?;
    let source = || AttemptSource::parse("127.0.0.1").unwrap();
    let candidate = authority
        .verify_password(
            system,
            LoginKey::parse("platform")?,
            password(),
            source(),
            assembly::deadline(),
        )
        .await?;
    let session = authority
        .create_session(candidate, None, assembly::deadline())
        .await?;
    let actor = authority
        .inspect_session(
            system,
            SessionSecret::parse(session.secret().expose().to_string())?,
            assembly::deadline(),
        )
        .await?;
    let business = rss_request_context::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    authority
        .provision_business_tenant(
            actor,
            "Rekey tenant".into(),
            NewTenantAdministrator {
                operation_id: uuid::Uuid::new_v4(),
                tenant: business,
                principal: PrincipalId::generate(),
                login: LoginKey::parse("admin")?,
                password: password(),
            },
            assembly::deadline(),
        )
        .await?;
    authority
        .activate_registered_tenants(assembly::deadline())
        .await?;
    let federation = Federation::new(
        rss_identity_core::groups::GroupFactsMaxAge::new(300).unwrap(),
        authority.clone(),
        Arc::new(rss_identity_oidc::HttpOidc::new(vec![])?),
        StateSigner::new([7; 32], "https://identity.test")?,
        BTreeMap::new(),
    )?;
    let settings = || -> anyhow::Result<ProviderSettings> {
        Ok(serde_json::from_value::<rss_identity_core::federation::ProviderSettingsInput>(serde_json::json!({"issuer":"https://idp.test","client_id":"installation","redirect_uri":"https://identity.test/api/v1/oidc/callback","scopes":["openid"],"claims":{"email":null,"groups":null},"jit":false}))?.try_into()?)
    };
    for _ in 0..100 {
        let actor = authority
            .inspect_session(
                system,
                SessionSecret::parse(session.secret().expose().to_string())?,
                assembly::deadline(),
            )
            .await?;
        federation
            .create_provider(
                actor,
                settings()?,
                ProviderCredentials::new("encrypted-installation-secret".into(), None)?,
                assembly::deadline(),
            )
            .await?;
    }
    let candidate = authority
        .verify_password(
            business,
            LoginKey::parse("admin")?,
            password(),
            source(),
            assembly::deadline(),
        )
        .await?;
    let session = authority
        .create_session(candidate, None, assembly::deadline())
        .await?;
    let actor = authority
        .inspect_session(
            business,
            SessionSecret::parse(session.secret().expose().to_string())?,
            assembly::deadline(),
        )
        .await?;
    federation
        .create_provider(
            actor,
            settings()?,
            ProviderCredentials::new("different-tenant-secret".into(), None)?,
            assembly::deadline(),
        )
        .await?;
    let mut owner = sqlx::PgConnection::connect_with(&config.database.sqlx()?).await?;
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM rss_transactional_messaging.outbox")
        .fetch_one(&mut owner)
        .await?;
    let new_key = root.join("credential-key-next");
    std::fs::write(&new_key, "09".repeat(32))?;
    std::fs::set_permissions(&new_key, std::fs::Permissions::from_mode(0o600))?;
    config.credential_keyring.active_key_id = "next".into();
    config
        .credential_keyring
        .keys
        .push(rss_identity_app::config::CredentialKeyFile {
            key_id: "next".into(),
            path: new_key.to_string_lossy().into_owned(),
        });
    let value = serde_json::json!({"format_version":2,"identity_origin":config.identity_origin,"database":{"host":config.database.host,"port":config.database.port,"database":config.database.database,"user":config.database.user,"password_file":config.database.password_file,"ca_file":config.database.ca_file},"storage":{"target":config.storage.target,"lineage":config.storage.lineage,"system_domain_id":system.to_string(),"generation":1},"runtime_password_file":config.runtime_password_file,"maintenance_password_file":config.maintenance_password_file,"credential_keyring":{"active_key_id":"next","keys":[{"key_id":"initial","path":root.join("credential-key")},{"key_id":"next","path":new_key}]}});
    let mut missing = value.clone();
    missing["credential_keyring"]["keys"]
        .as_array_mut()
        .unwrap()
        .remove(0);
    assert!(
        rss_identity_app::rekey::run(serde_json::from_value(missing.clone())?)
            .await
            .is_err()
    );
    let mut fenced = value.clone();
    fenced["storage"]["generation"] = serde_json::json!(2);
    assert!(
        rss_identity_app::rekey::run(serde_json::from_value(fenced)?)
            .await
            .is_err()
    );
    let damaged:uuid::Uuid=sqlx::query_scalar("SELECT provider_id FROM identity_authority.provider_credentials WHERE tenant_id=$1::uuid ORDER BY provider_id OFFSET 49 LIMIT 1").bind(system.to_string()).fetch_one(&mut owner).await?;
    let original:serde_json::Value=sqlx::query_scalar("SELECT sealed FROM identity_authority.provider_credentials WHERE tenant_id=$1::uuid AND provider_id=$2").bind(system.to_string()).bind(damaged).fetch_one(&mut owner).await?;
    let mut invalid = original.clone();
    invalid["ciphertext"][0] = serde_json::json!(invalid["ciphertext"][0].as_u64().unwrap() ^ 1);
    sqlx::query("UPDATE identity_authority.provider_credentials SET sealed=$3 WHERE tenant_id=$1::uuid AND provider_id=$2").bind(system.to_string()).bind(damaged).bind(invalid).execute(&mut owner).await?;
    assert!(
        rss_identity_app::rekey::run(serde_json::from_value(value.clone())?)
            .await
            .is_err()
    );
    let untouched:i64=sqlx::query_scalar("SELECT count(*) FROM identity_authority.provider_credentials WHERE sealed->>'key_id'='initial'").fetch_one(&mut owner).await?;
    assert_eq!(
        untouched, 101,
        "failure after earlier UPDATEs must roll back the complete batch"
    );
    sqlx::query("UPDATE identity_authority.provider_credentials SET sealed=$3 WHERE tenant_id=$1::uuid AND provider_id=$2").bind(system.to_string()).bind(damaged).bind(original).execute(&mut owner).await?;
    assert_eq!(
        rss_identity_app::rekey::run(serde_json::from_value(value.clone())?).await?,
        100
    );
    let mut blocker = owner.begin().await?;
    sqlx::query("SELECT provider_id FROM identity_authority.provider_credentials WHERE sealed->>'key_id'='next' ORDER BY tenant_id,provider_id LIMIT 1 FOR UPDATE").execute(&mut *blocker).await?;
    let remaining = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        rss_identity_app::rekey::run(serde_json::from_value(value.clone())?),
    )
    .await;
    blocker.rollback().await?;
    assert_eq!(
        remaining.expect("rekey must not wait on an already-active credential")?,
        1
    );
    assert_eq!(
        rss_identity_app::rekey::run(serde_json::from_value(missing)?).await?,
        0
    );
    let keys = CredentialKeys::new("next".into(), vec![("next".into(), [9; 32])])?;
    let authority_id: uuid::Uuid =
        sqlx::query_scalar("SELECT authority_id FROM identity_authority.deployment")
            .fetch_one(&mut owner)
            .await?;
    let rows:Vec<(uuid::Uuid,uuid::Uuid,i64,serde_json::Value)>=sqlx::query_as("SELECT tenant_id,provider_id,credential_version,sealed FROM identity_authority.provider_credentials").fetch_all(&mut owner).await?;
    assert_eq!(rows.len(), 101);
    for (tenant, provider, version, sealed) in rows {
        assert_eq!(sealed["key_id"], "next");
        assert_eq!(
            version, 1,
            "encryption rotation must preserve provider credential identity"
        );
        keys.reencrypt_value(
            authority_id,
            rss_request_context::TenantId::parse(&tenant.to_string())?,
            rss_identity_core::federation::ProviderId::parse(&provider.to_string())?,
            version,
            sealed,
        )?;
    }
    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM rss_transactional_messaging.outbox")
        .fetch_one(&mut owner)
        .await?;
    assert_eq!(before, after);
    owner.close().await?;
    authority.close().await;
    maintenance.close().await;
    kdf.close();
    kdf.wait_closed().await;
    Ok(())
}
