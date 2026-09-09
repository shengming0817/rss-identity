//! Test-only real HTTP host for a separately built Identity UI; not a production binary.
#[path = "../../identity-postgres/tests/federation_support/mod.rs"]
mod federation_support;
#[allow(dead_code)]
#[path = "../../identity-postgres/tests/support/mod.rs"]
mod support;
use rss_identity_http_axum::{HttpConfig, federated_router, management_router};
use std::{net::SocketAddr, time::Duration};
use support::*;
#[tokio::test]
#[ignore = "requires make test-ui with fixed frontend artifacts"]
async fn real_identity_ui_management_seam() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let service = federation_support::service(&f, federation_support::ScriptedOidc::new());
    let origin = std::env::var("IDENTITY_TEST_UI_ORIGIN")?;
    let config = HttpConfig::new(&origin, Duration::from_secs(30))?;
    let app = federated_router(service.clone(), config.clone())?
        .merge(management_router(service, config)?);
    let port: u16 = std::env::var("IDENTITY_TEST_UI_PORT")?.parse()?;
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
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
    f.close().await;
    anyhow::ensure!(
        result.status.success(),
        "UI browser seam failed (raw browser output withheld)"
    );
    assert_eq!(account_count, 1);
    assert!(events >= 5);
    Ok(())
}
