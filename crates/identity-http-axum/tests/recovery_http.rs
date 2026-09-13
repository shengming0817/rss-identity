//! Actual PG physical restore and persistent Hydra/Keycloak. Disposable in-process consumer, T2.
mod downstream_support;
#[allow(dead_code)]
#[path = "../../identity-postgres/tests/support/mod.rs"]
mod support;
use downstream_support::*;
use rss_identity_client::{ClientConfig, IdentityClient};
use rss_identity_core::{account::Password, downstream::*, session::SessionSecret};
use rss_identity_postgres::*;
use rss_request_context::{Clock, Deadline, ExecutionTimer};
use rss_transactional_messaging::{
    fence::{Epoch, ExecutionBinding, StorageIdentity},
    policy::DeliveryBudget,
};
use rss_transactional_messaging_postgres::{PgConfig, PgPassword, PgRuntime};
use serde_json::json;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use support::*;
use zeroize::Zeroizing;

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
async fn restored(
    database: &str,
    port: u16,
    password: &str,
) -> anyhow::Result<(Authority, Arc<PgRuntime>)> {
    let binding = ExecutionBinding::new(
        StorageIdentity::new([1; 16], [2; 16])?,
        vec![
            (
                rss_request_context::TenantId::parse(SYSTEM)?,
                Epoch::new(1)?,
            ),
            (rss_request_context::TenantId::parse(A)?, Epoch::new(1)?),
            (rss_request_context::TenantId::parse(B)?, Epoch::new(1)?),
        ],
    )?;
    let runtime = Arc::new(
        PgRuntime::connect_producer(
            PgConfig::new_for_test_plaintext(
                "127.0.0.1",
                port,
                database,
                "identity_runtime",
                PgPassword::new(password),
            ),
            Timer,
            binding,
        )
        .await?,
    );
    let authority = Authority::connect(
        runtime.clone(),
        Arc::new(rss_identity_core::account::PasswordKdf::new()),
        deployment_identity(),
        DeliveryBudget::new(
            Duration::from_secs(60),
            Duration::from_secs(5),
            Duration::from_secs(5),
            Duration::from_secs(5),
        )?,
        rss_request_context::TenantId::parse(SYSTEM)?,
        AuthorityProfile::Runtime,
        deadline(),
    )
    .await?;
    Ok((authority, runtime))
}
async fn control(c: &reqwest::Client, origin: &str, action: &str) -> anyhow::Result<()> {
    c.post(format!("{origin}/fixture/recovery/{action}"))
        .bearer_auth(SERVICE)
        .timeout(Duration::from_secs(180))
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

// Fresh admin authentication on every read avoids carrying an admin session across cuts.
async fn keycloak_marker(create: bool) -> anyhow::Result<bool> {
    let issuer = std::env::var("IDENTITY_TEST_FEDERATED_ISSUER")?;
    let base = issuer.trim_end_matches("/realms/identity");
    let pem = std::fs::read(std::env::var("IDENTITY_TEST_FEDERATED_CA")?)?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .add_root_certificate(reqwest::Certificate::from_pem(&pem)?)
        .timeout(Duration::from_secs(10))
        .build()?;
    let token: serde_json::Value = client
        .post(format!(
            "{base}/realms/master/protocol/openid-connect/token"
        ))
        .form(&[
            ("grant_type", "password"),
            ("client_id", "admin-cli"),
            ("username", "fixture-operator"),
            ("password", "fixture-operator-password"),
        ])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let bearer = Zeroizing::new(
        token["access_token"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("fixture admin token absent"))?
            .to_owned(),
    );
    let url = format!("{base}/admin/realms/identity/users");
    if create {
        let result = client
            .post(&url)
            .bearer_auth(bearer.as_str())
            .json(&json!({"username":"backup-cut-marker-2339", "enabled":false}))
            .send()
            .await?
            .error_for_status()?;
        assert_eq!(result.status(), reqwest::StatusCode::CREATED);
    }
    let users: Vec<serde_json::Value> = client
        .get(url)
        .bearer_auth(bearer.as_str())
        .query(&[("username", "backup-cut-marker-2339"), ("exact", "true")])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    anyhow::ensure!(users.len() <= 1, "duplicate fixture marker");
    Ok(!users.is_empty())
}

#[tokio::test]
#[ignore = "make test-recovery: owns disposable backup/restore fixtures"]
async fn physical_restore_preserves_the_selected_security_cut() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let issuer = std::env::var("IDENTITY_TEST_DOWNSTREAM_ISSUER")?;
    let origin = issuer.trim_end_matches('/');
    let ca = std::fs::read(std::env::var("IDENTITY_TEST_DOWNSTREAM_CA")?)?;
    let hydra = Arc::new(rss_identity_hydra::Hydra::new(
        &issuer,
        &issuer,
        vec!["127.0.0.1/32".parse()?, "::1/128".parse()?],
        Secret::new(SERVICE.into())?,
        Some(&ca),
    )?);
    let c = reqwest::Client::builder()
        .no_proxy()
        .cookie_store(true)
        .redirect(reqwest::redirect::Policy::none())
        .add_root_certificate(reqwest::Certificate::from_pem(&ca)?)
        .timeout(Duration::from_secs(10))
        .build()?;
    let emergency = f
        .store
        .create_local_account(
            session_actor(&f.store, f.candidate().await?).await?,
            login("emergency"),
            password(),
            LocalAccountRole::Emergency,
            deadline(),
        )
        .await?;
    let disabled = f
        .store
        .create_local_account(
            session_actor(&f.store, f.candidate().await?).await?,
            login("disabled"),
            password(),
            LocalAccountRole::Member,
            deadline(),
        )
        .await?;
    let inactive = f
        .store
        .create_local_account(
            session_actor(&f.store, f.candidate().await?).await?,
            login("inactive-member"),
            password(),
            LocalAccountRole::Member,
            deadline(),
        )
        .await?;
    let local = f
        .store
        .create_session(
            f.store
                .verify_password(
                    f.key.tenant,
                    login("emergency"),
                    password(),
                    source(),
                    deadline(),
                )
                .await?,
            None,
            deadline(),
        )
        .await?;
    let cookie = local.secret().expose().to_owned();
    let server = serve(
        f.store.clone(),
        downstream(f.store.clone(), hydra.clone(), &issuer)?,
        origin,
    )
    .await?;
    let session = post(
        &c,
        origin,
        &format!("/api/v1/tenants/{A}/login"),
        json!({"login":"emergency","password":PASSWORD}),
        None,
    )
    .await?;
    let (token, _, _) = flow(
        &c,
        origin,
        &issuer,
        session["csrf_token"].as_str().unwrap(),
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
        false,
    )
    .await?;
    let sdk = IdentityClient::new(
        ClientConfig {
            identity_origin: origin.into(),
            issuer: issuer.clone(),
            client_id: "mdm".into(),
            validation_secret: Zeroizing::new(VALIDATION.into()),
            tenant_id: A.into(),
            audience: "mdm-api".into(),
            timeout: Duration::from_secs(10),
            ca_pem: Some(ca),
        },
        Arc::new(rss_identity_client::SystemClock),
    )?;
    sdk.validate(&token).await?;
    assert!(!keycloak_marker(false).await?);
    control(&c, origin, "backup-old").await?;
    assert!(keycloak_marker(true).await?);
    f.store
        .set_account_enabled(
            session_actor(&f.store, f.candidate().await?).await?,
            disabled.key(),
            false,
            deadline(),
        )
        .await?;
    f.store
        .set_account_membership(
            session_actor(&f.store, f.candidate().await?).await?,
            inactive.key(),
            false,
            deadline(),
        )
        .await?;
    let new_password = "fixture emergency replacement 2339";
    let recovered = f
        .maintenance
        .recover_administrator(
            emergency.key(),
            Password::new(new_password.into())?,
            deadline(),
        )
        .await?;
    assert!(recovered.emergency() && recovered.enabled());
    assert!(recovered.epoch() > emergency.epoch());
    assert!(sdk.validate(&token).await.is_err());
    let expected_events = f.events().await?;
    control(&c, origin, "backup-current").await?;
    control(&c, origin, "corrupt-backup").await?;
    server.abort();
    let _ = server.await;
    f.runtime.close().await;
    f.maintenance_runtime.close().await;
    f.owner.close().await;
    f.admin.close().await;
    control(&c, origin, "restore-current").await?;
    assert!(
        keycloak_marker(false).await?,
        "Keycloak current cut missing"
    );
    let (store, runtime) = restored(&f.database, f.port, "fixture-only").await?;
    for name in ["disabled", "inactive-member", "emergency"] {
        assert!(
            store
                .verify_password(f.key.tenant, login(name), password(), source(), deadline())
                .await
                .is_err(),
            "restored old credential accepted"
        );
    }
    store
        .verify_password(
            f.key.tenant,
            login("emergency"),
            Password::new(new_password.into())?,
            source(),
            deadline(),
        )
        .await?;
    assert!(
        store
            .inspect_session(
                f.key.tenant,
                SessionSecret::parse(cookie.clone())?,
                deadline()
            )
            .await
            .is_err()
    );
    assert!(
        hydra.introspect(&Secret::new(token.clone())?).await?.active,
        "test must exercise a still-active old Hydra credential"
    );
    let server = serve(
        store.clone(),
        downstream(store, hydra.clone(), &issuer)?,
        origin,
    )
    .await?;
    assert!(sdk.validate(&token).await.is_err());
    let owner = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(
            sqlx::postgres::PgConnectOptions::new()
                .host("127.0.0.1")
                .port(f.port)
                .username("postgres")
                .password("fixture-only")
                .database(&f.database),
        )
        .await?;
    let events: i64 = sqlx::query_scalar("SELECT count(*) FROM rss_transactional_messaging.outbox")
        .fetch_one(&owner)
        .await?;
    assert_eq!(events, expected_events);
    // Maintenance-window DB credential rotation needs a new connection, not a cached pool success.
    server.abort();
    let _ = server.await;
    runtime.close().await;
    sqlx::query("ALTER ROLE identity_runtime PASSWORD 'fixture-runtime-rotated-2339'")
        .execute(&owner)
        .await?;
    assert!(restored(&f.database, f.port, "fixture-only").await.is_err());
    let (_, new_runtime) = restored(&f.database, f.port, "fixture-runtime-rotated-2339").await?;
    new_runtime.close().await;
    owner.close().await;
    // An earlier intact snapshot restores earlier account facts. No fictitious anti-rollback claim.
    // Only the fixture is inspected; no Identity listener is opened on this historical restore.
    control(&c, origin, "restore-old").await?;
    assert!(
        !keycloak_marker(false).await?,
        "Keycloak historical cut not restored"
    );
    let (old, old_runtime) = restored(&f.database, f.port, "fixture-only").await?;
    old.verify_password(
        f.key.tenant,
        login("disabled"),
        password(),
        source(),
        deadline(),
    )
    .await?;
    old.verify_password(
        f.key.tenant,
        login("emergency"),
        password(),
        source(),
        deadline(),
    )
    .await?;
    old_runtime.close().await;
    Ok(())
}
