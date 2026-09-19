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
        let mut scope = rss_runtime::LifecycleScope::<(), anyhow::Error, ()>::try_new(
            rss_runtime::TotalDrainBudget::new(Duration::from_secs(10))?,
            Arc::new(assembly::Timer),
        )?;
        let outcome = scope
            .drive(
                |startup| {
                    Box::pin(async move {
                        let mut launch = startup.commit();
                        launch.stage_task_with_token(
                            rss_axum::serve_http1_registration(
                                listener,
                                app,
                                rss_axum::PlainTransport,
                                "ui-host",
                                rss_axum::Http1ServePolicy::new(
                                    rss_axum::ServePolicy::new(
                                        256,
                                        Duration::from_secs(5),
                                        Duration::from_secs(5),
                                        Duration::from_secs(5),
                                    )?,
                                    Duration::from_secs(5),
                                    64,
                                    32768,
                                )?,
                            )
                            .critical(),
                        );
                        let (control, _gate) =
                            launch.finish_with_admission("ui-requests", Duration::from_secs(5));
                        control.open()?;
                        let _control = control;
                        std::future::pending().await
                    })
                },
                async {
                    let _ = stopped.await;
                    Ok(())
                },
            )
            .await?;
        anyhow::ensure!(
            outcome.shutdown().as_ref().is_ok_and(|r| r.is_clean()),
            "UI host shutdown failed"
        );
        Ok::<(), anyhow::Error>(())
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
