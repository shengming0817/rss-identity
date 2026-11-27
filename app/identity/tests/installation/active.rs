//! Test-only embedded resource. Exercise active authentication over TCP with the real host authority.
use axum::{Extension, Json, Router, http::HeaderMap, routing::post};
use reqwest::StatusCode;
use rss_identity_app::config::RuntimeConfig;
use rss_identity_app::{AppError, assembly, lifecycle};
use rss_identity_postgres::{Authority, IssuedSession};
use rss_identity_service_http::HttpError;
use rss_identity_web_credentials::{
    HttpConfig, SessionActivity, authenticate_request, issued_cookie,
};
use rss_request_context::Deadline;
use rss_request_context::TenantId;
use rss_runtime::{LifecycleScope, TotalDrainBudget};
use rss_transactional_messaging::fence::ExecutionBinding;
use std::sync::{Arc, OnceLock};

pub(super) async fn verify(
    authority: &Authority,
    config: Arc<RuntimeConfig>,
    issued: &IssuedSession,
    tenant: TenantId,
    owner: &mut sqlx::PgConnection,
) -> anyhow::Result<()> {
    let authority = authority.clone();
    let budget = config.budgets.request();
    let http = HttpConfig::new(&config.public_origin, budget)?;
    let app = Router::new().route(
        "/tenants/{tenant}/activity",
        post(
            move |Extension(binding): Extension<ExecutionBinding>,
                  Extension(deadline): Extension<Deadline>,
                  headers: HeaderMap| {
                let authority = authority.clone();
                let http = http.clone();
                async move {
                    let (session, _) = authenticate_request(
                        &authority,
                        &http,
                        binding,
                        &headers,
                        SessionActivity::Active,
                        deadline,
                    )
                    .await
                    .map_err(HttpError::from)?;
                    Ok::<_, HttpError>(Json((
                        session.view().idle_expires_at,
                        session.view().absolute_expires_at,
                    )))
                }
            },
        ),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let url = format!(
        "http://{}/tenants/{tenant}/activity",
        listener.local_addr()?
    );
    let gate = Arc::new(OnceLock::new());
    let app = lifecycle::protected_routes(app, config.clone(), gate.clone());
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let (started, ready) = tokio::sync::oneshot::channel();
    let policy = config.http.policy(config.budgets)?;
    let drain = TotalDrainBudget::new(config.budgets.drain())?;
    let per = config.budgets.resource();
    let server = tokio::spawn(async move {
        let mut scope = LifecycleScope::<(), AppError, std::io::Error>::try_new(
            drain,
            Arc::new(assembly::Timer),
        )
        .unwrap();
        scope
            .drive(
                |startup| {
                    Box::pin(async move {
                        let mut launch = startup.commit();
                        launch.stage_task_with_token(
                            rss_axum::serve_http1_registration(
                                listener,
                                app,
                                rss_axum::PlainTransport,
                                "activity",
                                policy,
                            )
                            .critical(),
                        );
                        let (control, admission) = launch.finish_with_admission("requests", per);
                        gate.set(admission).map_err(|_| AppError::Shutdown)?;
                        control.open().map_err(|_| AppError::Shutdown)?;
                        let _ = started.send(());
                        std::future::pending().await
                    })
                },
                async move { stopped.await.map_err(std::io::Error::other) },
            )
            .await
            .unwrap()
            .shutdown()
            .as_ref()
            .is_ok_and(|receipt| receipt.is_clean())
    });
    ready.await?;
    let client = reqwest::Client::new();
    let credentials = issued_cookie(issued)?;
    let mut headers = HeaderMap::new();
    headers.insert(
        "cookie",
        credentials
            .header
            .to_str()?
            .split(';')
            .next()
            .unwrap()
            .parse()?,
    );
    headers.insert("origin", config.public_origin.parse()?);
    headers.insert("x-identity-request", "1".parse()?);
    headers.insert("x-csrf-token", credentials.csrf_token.parse()?);
    assert_eq!(
        client
            .post(&url)
            .headers(headers.clone())
            .send()
            .await?
            .status(),
        StatusCode::FORBIDDEN
    );
    headers.insert("x-forwarded-for", "203.0.113.7".parse()?);
    let id = issued.view().id.to_string();
    let idle: i64=sqlx::query_scalar("UPDATE identity_authority.sessions SET idle_expires_at=idle_expires_at-5 WHERE session_id=$1::uuid RETURNING idle_expires_at")
        .bind(&id).fetch_one(&mut *owner).await?;
    for missing in ["origin", "x-identity-request", "x-csrf-token"] {
        let mut incomplete = headers.clone();
        incomplete.remove(missing);
        assert_eq!(
            client.post(&url).headers(incomplete).send().await?.status(),
            StatusCode::FORBIDDEN
        );
        let observed: i64 = sqlx::query_scalar(
            "SELECT idle_expires_at FROM identity_authority.sessions WHERE session_id=$1::uuid",
        )
        .bind(&id)
        .fetch_one(&mut *owner)
        .await?;
        assert_eq!(observed, idle);
    }
    let (renewed, absolute): (i64, i64) = client
        .post(&url)
        .headers(headers)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert!(renewed > idle);
    assert_eq!(absolute, issued.view().absolute_expires_at);
    stop.send(()).unwrap();
    assert!(server.await?);
    Ok(())
}
