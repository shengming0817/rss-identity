//! Consumer-owned production transport against public components and the reference host policy.
#[path = "../../../crates/identity-postgres/tests/federation_support/mod.rs"]
mod federation_support;
#[path = "../../../crates/identity-postgres/tests/support/mod.rs"]
mod support;
use rss_identity_app::{assembly, config::RuntimeConfig};
use rss_identity_postgres::{Federation, FederationConfig};
use std::{sync::Arc, time::Duration};
use support::*;

#[tokio::test]
#[ignore = "requires make test-ui and the fixed Web runner"]
async fn ui_host_public_components() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let origin = std::env::var("IDENTITY_TEST_UI_ORIGIN")?;
    let mut config: RuntimeConfig =
        serde_json::from_str(include_str!("../../../deployment/example.json"))?;
    config.instance_id = f.instance.to_string();
    config.public_origin = origin.clone();
    config.public_gateway = "127.0.0.1".parse()?;
    config.bootstrap_accounts[0].principal_id = f.key.principal.as_uuid().to_string();
    let kdf = Arc::new(rss_identity_core::account::PasswordKdf::new());
    let authority = assembly::authority(&config, f.runtime.clone(), kdf.clone()).await?;
    let federation = Federation::new(
        rss_identity_core::groups::GroupFactsMaxAge::new(300)?,
        authority.clone(),
        federation_support::ScriptedOidc::new(),
        rss_identity_core::federation::StateSigner::new([7; 32], &origin)?,
        FederationConfig {
            callback: format!("{origin}/api/v2/oidc/callback"),
            credential_keys: credential_keys(),
            targets: std::collections::BTreeMap::from([(
                "resume".into(),
                format!("{origin}/auth/resume"),
            )]),
        },
    )?;
    let http = rss_identity_http_axum::HttpConfig::new(&origin, Duration::from_secs(30))?;
    let app = rss_identity_http_axum::router(authority.clone(), http.clone())?
        .merge(rss_identity_http_axum::federated_router(federation, http)?)
        .merge(rss_identity_app::context::router(authority, &config)?)
        .layer(axum::middleware::from_fn_with_state(
            rss_identity_app::transport::Ingress {
                public: config.public_gateway,
            },
            rss_identity_app::transport::trusted,
        ));
    let port: u16 = std::env::var("IDENTITY_TEST_UI_PORT")?.parse()?;
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(async {
            let _ = stopped.await;
        })
        .await
    });
    let runner = std::env::var("IDENTITY_UI_RUNNER")?;
    let result = tokio::task::spawn_blocking(move || {
        std::process::Command::new("node").arg(runner).status()
    })
    .await?;
    let _ = stop.send(());
    tokio::time::timeout(Duration::from_secs(10), server).await???;
    kdf.close();
    kdf.wait_closed().await;
    f.close().await;
    anyhow::ensure!(result?.success(), "consumer transport verification failed");
    Ok(())
}
