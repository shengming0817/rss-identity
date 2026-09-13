#[allow(dead_code)]
#[path = "../../identity-postgres/tests/support/mod.rs"]
mod support;
use rss_identity_core::account::AccountKey;
use serde_json::{Value, json};
use std::{
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::Duration,
};
use support::*;
fn private(path: &Path, bytes: impl AsRef<[u8]>) -> anyhow::Result<()> {
    std::fs::write(path, bytes)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}
async fn cli(root: &Path, args: Vec<String>, expected: i32) -> anyhow::Result<Value> {
    let binary = std::env::var("IDENTITY_PLATFORM_BINARY")?;
    let config = root.join("client.json");
    let output = tokio::task::spawn_blocking(move || {
        std::process::Command::new(binary)
            .arg("--config")
            .arg(config)
            .args(args)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .output()
    })
    .await??;
    assert_eq!(
        output.status.code(),
        Some(expected),
        "CLI returned an unexpected closed exit class: {}; HTTP: {}",
        String::from_utf8_lossy(&output.stderr),
        std::fs::read_to_string(root.join("http-events.jsonl")).unwrap_or_default()
    );
    for bytes in [&output.stdout, &output.stderr] {
        assert!(!String::from_utf8_lossy(bytes).contains(PASSWORD));
    }
    let state = root.join("session/session.json");
    if state.exists() {
        let s: Value = serde_json::from_slice(&std::fs::read(state)?)?;
        if let Some(secret) = s["cookie"].as_str() {
            for bytes in [&output.stdout, &output.stderr] {
                assert!(!String::from_utf8_lossy(bytes).contains(secret));
            }
        }
    }
    if output.stdout.is_empty() {
        Ok(Value::Null)
    } else {
        Ok(serde_json::from_slice(&output.stdout)?)
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires make test-platform"]
async fn real_cli_tls_login_provision_add_unknown_and_logout() -> anyhow::Result<()> {
    let root = PathBuf::from(std::env::var("IDENTITY_PLATFORM_DIR")?);
    let origin = std::env::var("IDENTITY_PLATFORM_ORIGIN")?;
    let port: u16 = std::env::var("IDENTITY_PLATFORM_BACKEND")?.parse()?;
    let f = Fixture::new().await?;
    f.bootstrap().await?;
    let config = rss_identity_http_axum::HttpConfig::new(&origin, Duration::from_secs(30))?;
    let app = rss_identity_http_axum::router(f.store.clone(), config.clone())?
        .merge(rss_identity_http_axum::platform_router(
            f.store.clone(),
            config,
        )?)
        .layer(axum::middleware::from_fn(
            |mut r: axum::extract::Request, next: axum::middleware::Next| async move {
                let peer = r
                    .extensions()
                    .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
                    .unwrap()
                    .0;
                r.extensions_mut()
                    .insert(rss_identity_http_axum::ClientAddress(peer.ip()));
                next.run(r).await
            },
        ));
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).await?;
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(async {
            let _ = rx.await;
        })
        .await
    });
    private(&root.join("password"), PASSWORD)?;
    private(
        &root.join("client.json"),
        serde_json::to_vec(
            &json!({"format_version":1,"origin":origin,"system_domain_id":SYSTEM,"session_dir":root.join("session"),"ca_file":root.join("ca.pem"),"request_seconds":30}),
        )?,
    )?;
    cli(
        &root,
        vec![
            "login".into(),
            "--login".into(),
            "platform".into(),
            "--password-file".into(),
            root.join("password").display().to_string(),
        ],
        0,
    )
    .await?;
    let tenant = uuid::Uuid::new_v4();
    let operation = uuid::Uuid::new_v4();
    let principal = uuid::Uuid::new_v4();
    let args = vec![
        "tenant".into(),
        "create".into(),
        "--tenant".into(),
        tenant.to_string(),
        "--name".into(),
        "CLI tenant".into(),
        "--principal".into(),
        principal.to_string(),
        "--login".into(),
        "new-admin".into(),
        "--password-file".into(),
        root.join("password").display().to_string(),
        "--operation".into(),
        operation.to_string(),
    ];
    let created = cli(&root, args.clone(), 0).await?;
    assert_eq!(created["operation"]["operation_id"], operation.to_string());
    cli(&root, args, 11).await?;
    let extra = uuid::Uuid::new_v4();
    cli(
        &root,
        vec![
            "tenant".into(),
            "admin".into(),
            "add".into(),
            "--tenant".into(),
            tenant.to_string(),
            "--principal".into(),
            extra.to_string(),
            "--login".into(),
            "extra-admin".into(),
            "--password-file".into(),
            root.join("password").display().to_string(),
            "--operation".into(),
            uuid::Uuid::new_v4().to_string(),
        ],
        0,
    )
    .await?;
    let candidate = f
        .store
        .verify_password(
            rss_request_context::TenantId::parse(&tenant.to_string())?,
            login("extra-admin"),
            password(),
            source(),
            deadline(),
        )
        .await?;
    assert_eq!(
        candidate.account(),
        AccountKey {
            tenant: rss_request_context::TenantId::parse(&tenant.to_string())?,
            principal: rss_identity_core::PrincipalId::parse(&extra.to_string())?
        }
    );
    let unknown = uuid::Uuid::new_v4();
    let new_tenant = uuid::Uuid::new_v4();
    std::fs::write(root.join("drop-next"), "/api/v1/platform/tenants")?;
    cli(
        &root,
        vec![
            "tenant".into(),
            "create".into(),
            "--tenant".into(),
            new_tenant.to_string(),
            "--name".into(),
            "Unknown response".into(),
            "--principal".into(),
            uuid::Uuid::new_v4().to_string(),
            "--login".into(),
            "new-admin".into(),
            "--password-file".into(),
            root.join("password").display().to_string(),
            "--operation".into(),
            unknown.to_string(),
        ],
        20,
    )
    .await?;
    let status = cli(
        &root,
        vec![
            "operation".into(),
            "status".into(),
            "--operation".into(),
            unknown.to_string(),
        ],
        0,
    )
    .await?;
    assert_eq!(status["operation"]["tenant_id"], new_tenant.to_string());
    cli(&root, vec!["logout".into()], 0).await?;
    assert!(!root.join("session/session.json").exists());
    let _ = tx.send(());
    tokio::time::timeout(Duration::from_secs(5), server).await???;
    f.close().await;
    Ok(())
}
