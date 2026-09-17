//! Test-only real HTTP host for a separately built Identity UI; not a production binary.
#[path = "../../identity-postgres/tests/federation_support/mod.rs"]
mod federation_support;
#[allow(dead_code)]
#[path = "../../identity-postgres/tests/support/mod.rs"]
mod support;
use rss_identity_core::federation::{
    ClaimMapping, ProviderCredentials, ProviderSettingsInput, StateSigner,
};
use rss_identity_http_axum::{HttpConfig, federated_router, management_router, platform_router};
use rss_identity_oidc::{HttpOidc, TrustedAssuranceProfile};
use rss_identity_postgres::{DeploymentIdentity, Federation};
use std::{collections::BTreeMap, net::SocketAddr, sync::Arc, time::Duration};
use support::*;
#[tokio::test]
#[ignore = "requires make test-ui with fixed frontend artifacts"]
async fn real_identity_ui_management_seam() -> anyhow::Result<()> {
    let origin = std::env::var("IDENTITY_TEST_UI_ORIGIN")?;
    let f = Fixture::with_identity(DeploymentIdentity::new(
        "fixture".into(),
        1,
        origin.clone(),
        "https://product.example.test".into(),
    )?)
    .await?;
    f.bootstrap().await?;
    let issuer = std::env::var("IDENTITY_TEST_FEDERATED_ISSUER")?;
    let upstream = HttpOidc::new(vec![TrustedAssuranceProfile {
        tenant: f.key.tenant,
        issuer: issuer.clone(),
        client_id: "identity-test".into(),
        keycloak_totp: true,
    }])?;
    let service = Federation::new(
        rss_identity_core::groups::GroupFactsMaxAge::new(300).unwrap(),
        f.store.clone(),
        Arc::new(upstream),
        StateSigner::new([7; 32], &origin)?,
        BTreeMap::from([(
            ("identity-ui".into(), "resume".into()),
            format!("{origin}/auth/resume"),
        )]),
    )?;
    let provider = service
        .create_provider(
            f.actor().await?,
            ProviderSettingsInput {
                issuer,
                client_id: "identity-test".into(),
                redirect_uri: format!("{origin}/api/v1/oidc/callback"),
                scopes: vec!["openid".into()],
                claims: ClaimMapping {
                    email: None,
                    groups: None,
                },
                jit: true,
            }
            .try_into()?,
            ProviderCredentials::new(
                "fixture-secret".into(),
                Some(std::fs::read_to_string(std::env::var(
                    "IDENTITY_TEST_FEDERATED_CA",
                )?)?),
            )?,
            deadline(),
        )
        .await?;
    service
        .enable_provider(
            f.actor().await?,
            provider.id,
            provider.version,
            true,
            deadline(),
        )
        .await?;
    let config = HttpConfig::new(&origin, Duration::from_secs(30))?;
    let app = federated_router(service.clone(), config.clone())?
        .merge(management_router(service, config.clone())?)
        .merge(platform_router(f.store.clone(), config)?);
    let port: u16 = std::env::var("IDENTITY_TEST_UI_PORT")?.parse()?;
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            app.layer(axum::middleware::map_request(
                |mut r: axum::extract::Request| async move {
                    if let Some(peer) = r
                        .extensions()
                        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
                    {
                        let source = rss_identity_http_axum::ClientAddress(peer.0.ip());
                        r.extensions_mut().insert(source);
                    }
                    r
                },
            ))
            .into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
    });
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let result = tokio::task::spawn_blocking(move || {
        std::process::Command::new("python3")
            .arg(root.join("hack/ui_browser.py"))
            .current_dir(root)
            .output()
    })
    .await??;
    server.abort();
    let _ = server.await;
    let account_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM identity_authority.local_credentials WHERE login_key='ui-member'",
    )
    .fetch_one(&f.owner)
    .await?;
    let events:i64=sqlx::query_scalar("SELECT count(*) FROM rss_transactional_messaging.outbox WHERE envelope->>'contract'='identity.account.security'").fetch_one(&f.owner).await?;
    let provider_count: i64 = sqlx::query_scalar("SELECT count(*) FROM identity_authority.providers WHERE settings->>'client_id'='identity-test' AND config_version=4 AND NOT enabled AND revocation_epoch=4 AND credential_version=2").fetch_one(&f.owner).await?;
    let tenants: i64 = sqlx::query_scalar("SELECT count(*) FROM identity_authority.local_credentials WHERE login_key='ui-first-admin'").fetch_one(&f.owner).await?;
    f.close().await;
    anyhow::ensure!(
        result.status.success(),
        "UI browser seam failed: {}",
        String::from_utf8_lossy(&result.stdout)
    );
    assert_eq!(account_count, 1);
    assert_eq!(provider_count, 1);
    assert_eq!(tenants, 1);
    // Create, disable, reset and enable. Bootstrap now emits a platform event.
    assert_eq!(events, 4);
    Ok(())
}
