#[path = "../../../crates/identity-postgres/tests/federation_support/mod.rs"]
mod federation_support;
#[path = "../../../crates/identity-postgres/tests/support/mod.rs"]
mod support;
// Real TLS PostgreSQL installation, host policy and startup seams; no deployed artifact/T3 claim.
use rss_identity_app::{
    AppError, assembly,
    config::{MigrationConfig, RuntimeConfig},
    lifecycle, migration,
};
use rss_identity_core::account::{LoginKey, Password, PasswordKdf};
use rss_identity_postgres::*;
use rss_transactional_messaging_postgres::PgRuntime;
use serde_json::json;
use sqlx::Connection;
use std::{path::PathBuf, sync::Arc, time::Duration};

const PASSWORD: &str = "fixture private account password";
fn password() -> Password {
    Password::new(PASSWORD.into()).unwrap()
}

#[tokio::test]
#[ignore = "requires make test-assembly"]
async fn installation_and_reference_host_seams_are_verified() -> anyhow::Result<()> {
    let root = PathBuf::from(std::env::var("IDENTITY_TEST_INSTALL_DIR")?);
    let port: u16 = std::env::var("IDENTITY_TEST_PG_PORT")?.parse()?;
    let mut value: serde_json::Value =
        serde_json::from_str(include_str!("../../../deployment/example.json"))?;
    value["database"] = json!({"host":"127.0.0.1","port":port,"database":"postgres","user":"postgres","passwordFile":root.join("owner"),"caFile":root.join("server.crt")});
    let owner_db: rss_identity_app::config::DatabaseConfig =
        serde_json::from_value(value["database"].clone())?;
    let mut owner = sqlx::PgConnection::connect_with(&owner_db.sqlx()?).await?;
    sqlx::raw_sql("CREATE ROLE rss_tmsg_relay NOLOGIN NOBYPASSRLS; CREATE ROLE host_runtime LOGIN PASSWORD 'fixture-runtime'; CREATE ROLE host_maintenance LOGIN PASSWORD 'fixture-maintenance'; CREATE ROLE unsafe_parent NOLOGIN BYPASSRLS").execute(&mut owner).await?;
    value["storage"]["tenants"]
        .as_array_mut()
        .unwrap()
        .push(json!("33333333-3333-4333-8333-333333333333"));
    value["bootstrapAccounts"].as_array_mut().unwrap().push(json!({"tenantId":"33333333-3333-4333-8333-333333333333","principalId":"44444444-4444-4444-8444-444444444444"}));
    let install_value = json!({"formatVersion":3,"instanceId":value["instanceId"],"database":value["database"],"storage":value["storage"],"runtimeRole":"host_runtime","maintenanceRole":"host_maintenance"});
    let install_config =
        || serde_json::from_value::<MigrationConfig>(install_value.clone()).unwrap();
    for (corrupt, restore) in [
        (
            "ALTER ROLE host_runtime BYPASSRLS",
            "ALTER ROLE host_runtime NOBYPASSRLS",
        ),
        (
            "ALTER ROLE host_maintenance CREATEROLE",
            "ALTER ROLE host_maintenance NOCREATEROLE",
        ),
        (
            "GRANT unsafe_parent TO host_runtime",
            "REVOKE unsafe_parent FROM host_runtime",
        ),
        (
            "ALTER DEFAULT PRIVILEGES GRANT DELETE ON TABLES TO host_maintenance",
            "ALTER DEFAULT PRIVILEGES REVOKE DELETE ON TABLES FROM host_maintenance",
        ),
        (
            "ALTER DEFAULT PRIVILEGES GRANT SELECT ON TABLES TO host_runtime WITH GRANT OPTION",
            "ALTER DEFAULT PRIVILEGES REVOKE SELECT ON TABLES FROM host_runtime",
        ),
        (
            "ALTER DEFAULT PRIVILEGES GRANT SELECT ON TABLES TO PUBLIC",
            "ALTER DEFAULT PRIVILEGES REVOKE SELECT ON TABLES FROM PUBLIC",
        ),
    ] {
        sqlx::raw_sql(corrupt).execute(&mut owner).await?;
        assert!(
            migration::install(install_config()).await.is_err(),
            "unsafe role must fail before installation commits: {corrupt}"
        );
        let absent: bool = sqlx::query_scalar("SELECT to_regnamespace('identity_authority') IS NULL AND to_regnamespace('rss_transactional_messaging') IS NULL").fetch_one(&mut owner).await?;
        assert!(
            absent,
            "failed installation must roll back both schema owners"
        );
        sqlx::raw_sql(restore).execute(&mut owner).await?;
    }
    migration::install(install_config()).await?;
    migration::verify(install_config()).await?;
    for (corrupt, restore) in [
        (
            "DELETE FROM identity_authority.schema_version",
            "INSERT INTO identity_authority.schema_version VALUES(9)",
        ),
        (
            "UPDATE rss_transactional_messaging.tenant_epoch SET epoch=2",
            "UPDATE rss_transactional_messaging.tenant_epoch SET epoch=1",
        ),
        (
            "ALTER ROLE host_runtime BYPASSRLS",
            "ALTER ROLE host_runtime NOBYPASSRLS",
        ),
    ] {
        sqlx::raw_sql(corrupt).execute(&mut owner).await?;
        assert!(migration::verify(install_config()).await.is_err());
        sqlx::raw_sql(restore).execute(&mut owner).await?;
    }
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM identity_authority.guard")
            .fetch_one(&mut owner)
            .await?,
        0,
        "verification must not initialize tenants"
    );
    assert!(
        migration::install(install_config()).await.is_err(),
        "fresh-only installer must reject existing storage"
    );
    let config: RuntimeConfig = serde_json::from_value(value.clone())?;
    let maintenance_db = rss_identity_app::config::DatabaseConfig {
        user: "host_maintenance".into(),
        password_file: root.join("maintenance").to_string_lossy().into_owned(),
        ..owner_db.clone()
    };
    let maintenance_runtime = Arc::new(
        PgRuntime::connect_producer(
            maintenance_db.pg()?,
            assembly::Timer,
            config.storage.binding()?,
        )
        .await?,
    );
    let kdf = Arc::new(PasswordKdf::new());
    let maintenance = Authority::connect_maintenance(
        maintenance_runtime.clone(),
        kdf.clone(),
        assembly::authority_config(&config)?,
        assembly::deadline(),
    )
    .await?;
    let keys = config.bootstrap_keys()?;
    for key in &keys {
        maintenance
            .initialize(
                *key,
                LoginKey::parse("operator")?,
                password(),
                assembly::deadline(),
            )
            .await?;
    }
    value["database"]["user"] = json!("host_runtime");
    value["database"]["passwordFile"] = json!(root.join("runtime"));
    value["budgets"] = json!({"requestSeconds":1,"drainSeconds":4,"resourceSeconds":2});
    value["publicGateway"] = json!("127.0.0.1");
    let runtime_config = || serde_json::from_value::<RuntimeConfig>(value.clone()).unwrap();
    let config = runtime_config();
    config.validate()?;
    let runtime = Arc::new(
        PgRuntime::connect_producer(
            config.database.pg()?,
            assembly::Timer,
            config.storage.binding()?,
        )
        .await?,
    );
    let authority = assembly::authority(&config, runtime.clone(), kdf.clone()).await?;
    let federation = Federation::new(
        rss_identity_core::groups::GroupFactsMaxAge::new(300)?,
        authority.clone(),
        federation_support::ScriptedOidc::new(),
        rss_identity_core::federation::StateSigner::new([7; 32], &config.public_origin)?,
        FederationConfig {
            callback: format!("{}/api/v2/oidc/callback", config.public_origin),
            credential_keys: support::credential_keys(),
            targets: std::collections::BTreeMap::from([(
                "resume".into(),
                format!("{}/auth/resume", config.public_origin),
            )]),
        },
    )?;
    for key in &keys {
        let issued = authority
            .login_local(
                key.tenant,
                LoginKey::parse("operator")?,
                password(),
                AttemptSource::parse("fixture")?,
                None,
                assembly::deadline(),
            )
            .await?;
        let http = rss_identity_http_axum::HttpConfig::new(
            &config.public_origin,
            config.budgets.request(),
        )?;
        let context = rss_identity_app::context::router(authority.clone(), &config, http)?;
        for (suffix, expected) in [
            ("", axum::http::StatusCode::OK),
            ("; broken", axum::http::StatusCode::BAD_REQUEST),
        ] {
            use tower::ServiceExt;
            let response = context
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .uri(format!(
                            "/api/identity-host/v1/tenants/{}/context",
                            key.tenant
                        ))
                        .header(
                            "cookie",
                            format!(
                                "__Host-identity-session={}{suffix}",
                                issued.secret().expose()
                            ),
                        )
                        .body(axum::body::Body::empty())?,
                )
                .await?;
            assert_eq!(response.status(), expected);
            assert_eq!(response.headers()["cache-control"], "no-store");
            assert!(!response.headers().contains_key("set-cookie"));
            if expected == axum::http::StatusCode::OK {
                let body: serde_json::Value = serde_json::from_slice(
                    &axum::body::to_bytes(response.into_body(), 4096).await?,
                )?;
                assert_eq!(body["tenantId"], key.tenant.to_string());
                assert_eq!(body["principalId"], key.principal.as_uuid().to_string());
                assert_eq!(body["navigation"]["manageAccounts"], true);
            }
        }
        let actor = || {
            rss_identity_core::session::SessionSecret::parse(issued.secret().expose().into())
                .unwrap()
        };
        let manager = authority
            .inspect_session(key.tenant, actor(), assembly::deadline())
            .await?;
        federation
            .create_provider(
                manager,
                federation_support::settings(),
                rss_identity_core::federation::ProviderCredentials::new(
                    "private-rotation-test".into(),
                    None,
                )?,
                assembly::deadline(),
            )
            .await?;
        let manager = authority
            .inspect_session(key.tenant, actor(), assembly::deadline())
            .await?;
        let member = authority
            .create_local_account(
                manager,
                LoginKey::parse("member")?,
                password(),
                assembly::deadline(),
            )
            .await?;
        assert_eq!(member.key().tenant, key.tenant);
        let manager = authority
            .inspect_session(key.tenant, actor(), assembly::deadline())
            .await?;
        assert!(matches!(
            authority
                .set_account_enabled(manager, *key, false, assembly::deadline())
                .await,
            Err(AuthorityError::RuleRejected(_))
        ));
        let member_session = authority
            .login_local(
                key.tenant,
                LoginKey::parse("member")?,
                password(),
                AttemptSource::parse("fixture")?,
                None,
                assembly::deadline(),
            )
            .await?;
        let member_actor = authority
            .inspect_session(
                key.tenant,
                rss_identity_core::session::SessionSecret::parse(
                    member_session.secret().expose().into(),
                )?,
                assembly::deadline(),
            )
            .await?;
        assert!(
            authority
                .list_accounts(member_actor, None, 10, assembly::deadline())
                .await
                .is_err()
        );
        let member_actor = authority
            .inspect_session(
                key.tenant,
                rss_identity_core::session::SessionSecret::parse(
                    member_session.secret().expose().into(),
                )?,
                assembly::deadline(),
            )
            .await?;
        authority
            .change_own_password(
                member_actor,
                password(),
                password(),
                AttemptSource::parse("fixture")?,
                assembly::deadline(),
            )
            .await?;
    }
    // Real host transaction: first tenant changes, second tenant fails AAD authentication.
    use std::os::unix::fs::PermissionsExt;
    for (name, raw) in [("old-key", [8_u8; 32]), ("new-key", [2_u8; 32])] {
        let p = root.join(name);
        std::fs::write(&p, hex::encode(raw))?;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600))?;
    }
    let ring = |only_new: bool| -> rss_identity_app::config::CredentialKeyringConfig {
        let mut entries = vec![json!({"keyId":"next","path":root.join("new-key")})];
        if !only_new {
            entries.push(json!({"keyId":"fixture","path":root.join("old-key")}));
        }
        serde_json::from_value(json!({"activeKeyId":"next","keys":entries})).unwrap()
    };
    let before: Vec<serde_json::Value> = sqlx::query_scalar(
        "SELECT sealed FROM identity_authority.provider_credentials ORDER BY tenant_id",
    )
    .fetch_all(&mut owner)
    .await?;
    assert_eq!(before.len(), 2);
    sqlx::query("UPDATE identity_authority.provider_credentials SET credential_version=credential_version+1 WHERE tenant_id=$1::uuid").bind(keys[1].tenant.to_string()).execute(&mut owner).await?;
    assert!(
        rss_identity_app::rekey::run(install_config(), ring(false), false)
            .await
            .is_err()
    );
    let after: Vec<serde_json::Value> = sqlx::query_scalar(
        "SELECT sealed FROM identity_authority.provider_credentials ORDER BY tenant_id",
    )
    .fetch_all(&mut owner)
    .await?;
    assert_eq!(before, after, "partial tenant updates must roll back");
    sqlx::query("UPDATE identity_authority.provider_credentials SET credential_version=credential_version-1 WHERE tenant_id=$1::uuid").bind(keys[1].tenant.to_string()).execute(&mut owner).await?;
    assert!(
        rss_identity_app::rekey::run(install_config(), ring(true), true)
            .await
            .is_err()
    );
    rss_identity_app::rekey::run(install_config(), ring(false), false).await?;
    rss_identity_app::rekey::run(install_config(), ring(true), true).await?;
    runtime.close().await;
    maintenance_runtime.close().await;
    kdf.close();
    kdf.wait_closed().await;
    assert!(kdf.hash(password()).await.is_err());

    let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    value["listen"] = json!(occupied.local_addr()?.to_string());
    let failed = tokio::time::timeout(
        Duration::from_secs(10),
        lifecycle::serve(
            serde_json::from_value(value.clone())?,
            std::future::pending(),
        ),
    )
    .await?;
    assert!(
        matches!(failed, Err(AppError::Connection)),
        "bind failure must return original error only after a clean PG/KDF drain"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM pg_stat_activity WHERE usename='host_runtime'"
        )
        .fetch_one(&mut owner)
        .await?,
        0
    );
    let listen = occupied.local_addr()?;
    drop(occupied);
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(lifecycle::serve(
        serde_json::from_value(value.clone())?,
        async move { stopped.await.map_err(std::io::Error::other) },
    ));
    let client = reqwest::Client::new();
    let url = format!("http://{listen}");
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if client
                .get(format!("{url}/readyz"))
                .send()
                .await
                .is_ok_and(|r| r.status().is_success())
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await?;
    let response = client
        .post(format!("{url}/api/v2/tenants/{}/login", keys[1].tenant))
        .header("origin", value["publicOrigin"].as_str().unwrap())
        .header("x-identity-request", "1")
        .header("x-forwarded-for", "203.0.113.7")
        .json(&json!({"login":"operator","password":PASSWORD}))
        .send()
        .await?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert!(response.headers().contains_key("set-cookie"));
    let cookie = response.headers()["set-cookie"]
        .to_str()?
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    assert_eq!(
        response.json::<serde_json::Value>().await?["identity"]["principalId"],
        keys[1].principal.as_uuid().to_string()
    );
    let resource = format!(
        "{url}/api/identity-host/v1/tenants/{}/context",
        keys[1].tenant
    );
    let reply = client
        .get(&resource)
        .header("cookie", &cookie)
        .header("x-forwarded-for", "203.0.113.7")
        .send()
        .await?;
    assert_eq!(reply.status(), reqwest::StatusCode::OK);
    assert_eq!(reply.headers()["cache-control"], "no-store");
    let context = reply.json::<serde_json::Value>().await?;
    assert_eq!(
        context["principalId"],
        keys[1].principal.as_uuid().to_string()
    );
    assert_eq!(context["navigation"]["manageAccounts"], true);
    assert_eq!(context["navigation"]["manageProviders"], true);
    let member = client
        .post(format!("{url}/api/v2/tenants/{}/login", keys[1].tenant))
        .header("origin", value["publicOrigin"].as_str().unwrap())
        .header("x-identity-request", "1")
        .header("x-forwarded-for", "203.0.113.8")
        .json(&json!({"login":"member","password":PASSWORD}))
        .send()
        .await?;
    assert_eq!(member.status(), reqwest::StatusCode::OK);
    let member_cookie = member.headers()["set-cookie"]
        .to_str()?
        .split(';')
        .next()
        .unwrap();
    let member_context = client
        .get(&resource)
        .header("cookie", member_cookie)
        .header("x-forwarded-for", "203.0.113.8")
        .send()
        .await?;
    assert_eq!(member_context.status(), reqwest::StatusCode::OK);
    let member_context = member_context.json::<serde_json::Value>().await?;
    assert_eq!(member_context["navigation"]["manageAccounts"], false);
    assert_eq!(member_context["navigation"]["manageProviders"], false);
    sqlx::query(
        "UPDATE identity_authority.accounts SET auth_epoch=auth_epoch+1 WHERE tenant_id=$1::uuid",
    )
    .bind(keys[1].tenant.to_string())
    .execute(&mut owner)
    .await?;
    assert_eq!(
        client
            .get(&resource)
            .header("cookie", &cookie)
            .header("x-forwarded-for", "203.0.113.7")
            .send()
            .await?
            .status(),
        reqwest::StatusCode::UNAUTHORIZED
    );
    stop.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(10), server).await???;
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM pg_stat_activity WHERE usename='host_runtime'"
        )
        .fetch_one(&mut owner)
        .await?,
        0
    );
    // Native logical backup must preserve the exact structural attestation after PG re-parses DDL.
    let container = std::env::var("IDENTITY_TEST_PG_CONTAINER")?;
    let dump = std::process::Command::new("docker")
        .args([
            "exec", &container, "pg_dump", "-U", "postgres", "-d", "postgres", "-Fc",
        ])
        .output()?;
    anyhow::ensure!(dump.status.success(), "fixture dump failed");
    sqlx::query("CREATE DATABASE restored")
        .execute(&mut owner)
        .await?;
    let mut restore = std::process::Command::new("docker")
        .args([
            "exec",
            "-i",
            &container,
            "pg_restore",
            "-U",
            "postgres",
            "-d",
            "restored",
            "--exit-on-error",
            "--single-transaction",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    use std::io::Write;
    restore.stdin.take().unwrap().write_all(&dump.stdout)?;
    anyhow::ensure!(
        restore.wait_with_output()?.status.success(),
        "fixture restore failed"
    );
    let mut restored = install_config();
    restored.database.database = "restored".into();
    migration::verify(restored).await?;
    owner.close().await?;
    Ok(())
}
