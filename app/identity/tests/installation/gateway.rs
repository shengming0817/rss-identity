//! End-to-end transport and RP-generation checks against the production host.
use reqwest::{Client, StatusCode};
use rss_identity_app::{config::RuntimeConfig, lifecycle};
use rss_request_context::TenantId;
use serde_json::{Value, json};
use sqlx::Connection;
use std::time::Duration;
use webauthn_authenticator_rs::{WebauthnAuthenticator, softpasskey::SoftPasskey};

pub(super) async fn verify(
    mut settings: Value,
    tenant: TenantId,
    owner: &mut sqlx::PgConnection,
) -> anyhow::Result<()> {
    let gateway = std::env::var("IDENTITY_TEST_GATEWAY_URL")?;
    let ca = std::fs::read(std::env::var("IDENTITY_TEST_GATEWAY_CA")?)?;
    settings["listen"] = json!(std::env::var("IDENTITY_TEST_GATEWAY_BACKEND")?);
    settings["publicGateway"] = json!(std::env::var("IDENTITY_TEST_GATEWAY_PEER")?);
    settings["webauthnGeneration"] = json!(7);
    let config: RuntimeConfig = serde_json::from_value(settings)?;
    let origin = url::Url::parse(&config.public_origin)?;
    let instance = config.instance()?;
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(lifecycle::serve(config, async {
        stopped.await.map_err(std::io::Error::other)
    }));
    let client = Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(&ca)?)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .build()?;
    let root = format!("{gateway}/api/v1/identity/tenants/{tenant}");
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if client
                .get(format!("{root}/session"))
                .send()
                .await
                .is_ok_and(|r| r.status() == StatusCode::UNAUTHORIZED)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await?;
    let rejected = client
        .get(format!(
            "{gateway}/api/v1/identity/oidc/callback?state=bad&error=private"
        ))
        .send()
        .await
        .map_err(reqwest::Error::without_url)?;
    assert_eq!(rejected.status(), StatusCode::SEE_OTHER);
    assert_eq!(rejected.headers()["location"], "/auth/error?reason=failed");
    assert_eq!(rejected.headers()["cache-control"], "no-store");
    assert_eq!(rejected.headers()["referrer-policy"], "no-referrer");
    assert!(!rejected.headers().contains_key("set-cookie"));
    let login = client
        .post(format!("{root}/login"))
        .header("origin", origin.origin().ascii_serialization())
        .json(&json!({"login":"operator","password":super::PASSWORD}));
    assert_eq!(
        login.try_clone().unwrap().send().await?.status(),
        StatusCode::FORBIDDEN
    );
    let login = login
        .header("x-identity-request", "1")
        .send()
        .await?
        .error_for_status()?;
    let cookie = login.headers()["set-cookie"]
        .to_str()?
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let login: Value = login.json().await?;
    let write = |path: &str, value: Value| {
        client
            .post(format!("{root}/webauthn/{path}"))
            .header("origin", origin.origin().ascii_serialization())
            .header("cookie", &cookie)
            .header("x-identity-request", "1")
            .header("x-csrf-token", login["csrfToken"].as_str().unwrap())
            .json(&value)
    };
    let mut device = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let register: Value = write("register/begin", json!({"label":"gateway","recover":false}))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let response = device.do_registration(
        origin.clone(),
        serde_json::from_value(register["options"].clone())?,
    )?;
    let registered: Value = write(
        "register/finish",
        json!({"id":register["id"],"response":response}),
    )
    .send()
    .await?
    .error_for_status()?
    .json()
    .await?;
    let operation = json!({"operation":{"kind":"remove","credential":registered["id"]}});
    let begin = || write("authenticate/begin", operation.clone());
    let challenge: Value = begin().send().await?.error_for_status()?.json().await?;
    let response = device.do_authentication(
        origin.clone(),
        serde_json::from_value(challenge["options"].clone())?,
    )?;
    let verified = write(
        "authenticate/finish",
        json!({"id":challenge["id"],"response":response}),
    )
    .send()
    .await?
    .error_for_status()?;
    assert!(
        verified.headers()["set-cookie"]
            .to_str()?
            .starts_with("__Host-identity-operation=")
    );
    let pending: Value = begin().send().await?.error_for_status()?.json().await?;
    let response = device.do_authentication(
        origin.clone(),
        serde_json::from_value(pending["options"].clone())?,
    )?;
    let mut tx = owner.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await?;
    let next = rss_identity_postgres::activate_webauthn_rp_on(
        &mut tx,
        instance,
        tenant,
        origin.host_str().unwrap(),
        &origin,
        7,
    )
    .await?;
    assert_eq!(next, 8);
    tx.commit().await?;
    let rejected = write(
        "authenticate/finish",
        json!({"id":pending["id"],"response":response}),
    )
    .send()
    .await?;
    assert!(rejected.status().is_client_error());
    assert!(!rejected.headers().contains_key("set-cookie"));
    stop.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(10), server).await???;
    Ok(())
}
