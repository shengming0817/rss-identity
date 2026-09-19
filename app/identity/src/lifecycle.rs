//! One local scope owns process resources; no resource count is a termination claim.
use crate::{AppError, assembly, config::RuntimeConfig, transport};
use axum::{
    Router,
    body::{Body, Bytes},
    extract::{Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use rss_identity_core::account::PasswordKdf;
use rss_identity_http_axum::{HttpConfig, HttpFailure, federated_router, router};
use rss_runtime::{
    AdmissionGate, AdmissionPermit, DynManagedResource, LifecycleScope, ManagedResource, ScopeExit,
    ShutdownError, TotalDrainBudget,
};
use rss_transactional_messaging_postgres::PgRuntime;
use std::{
    pin::Pin,
    sync::{Arc, OnceLock},
    task::{Context, Poll},
    time::Duration,
};

pub struct PoolResource {
    pub pool: Arc<PgRuntime>,
    pub timeout: Duration,
}
impl ManagedResource for PoolResource {
    fn name(&self) -> &str {
        "postgres"
    }
    async fn shutdown(&self) -> Result<(), ShutdownError> {
        self.pool.close().await;
        Ok(())
    }
    fn shutdown_timeout(&self) -> Duration {
        self.timeout
    }
}
pub struct KdfResource {
    pub kdf: Arc<PasswordKdf>,
    pub timeout: Duration,
}
impl ManagedResource for KdfResource {
    fn name(&self) -> &str {
        "password-kdf"
    }
    async fn shutdown(&self) -> Result<(), ShutdownError> {
        self.kdf.close();
        self.kdf.wait_closed().await;
        Ok(())
    }
    fn shutdown_timeout(&self) -> Duration {
        self.timeout
    }
}
struct LeasedBody {
    inner: Body,
    _permit: AdmissionPermit,
}
impl http_body::Body for LeasedBody {
    type Data = Bytes;
    type Error = axum::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
        Pin::new(&mut self.inner).poll_frame(cx)
    }
    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}
async fn admit(
    State(gate): State<Arc<OnceLock<AdmissionGate>>>,
    request: Request,
    next: Next,
) -> Response {
    let Some(permit) = gate.get().and_then(|g| g.try_admit().ok()) else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let response = next.run(request).await;
    response.map(|inner| {
        Body::new(LeasedBody {
            inner,
            _permit: permit,
        })
    })
}
// HttpFailure contains only closed, non-secret classifications. Never log the request or body.
fn record_failure(response: &Response, mut output: impl std::io::Write) {
    if let Some(failure) = response.extensions().get::<HttpFailure>() {
        let _ = writeln!(output, "component=identity-http failure={failure:?}");
    }
}
async fn diagnose(request: Request, next: Next) -> Response {
    let response = next.run(request).await;
    record_failure(&response, std::io::stderr().lock());
    response
}
struct Health {
    config: Arc<RuntimeConfig>,
    pool: Arc<PgRuntime>,
    kdf: Arc<PasswordKdf>,
    gate: Arc<OnceLock<AdmissionGate>>,
    probe: tokio::sync::Semaphore,
}
async fn ready(State(h): State<Arc<Health>>) -> StatusCode {
    let Some(_permit) = h.gate.get().and_then(|g| g.try_admit().ok()) else {
        return StatusCode::SERVICE_UNAVAILABLE;
    };
    let Ok(_probe) = h.probe.try_acquire() else {
        return StatusCode::SERVICE_UNAVAILABLE;
    };
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        if let Err(error) = assembly::authority(&h.config, h.pool.clone(), h.kdf.clone()).await {
            eprintln!("component=postgres readiness=failed reason={error}");
            return Err(error);
        }
        Ok(())
    })
    .await;
    if result.is_err() {
        eprintln!("component=readiness reason=timeout");
    }
    if matches!(result, Ok(Ok(()))) {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}
pub async fn serve(
    config: RuntimeConfig,
    stop: impl std::future::Future<Output = Result<(), std::io::Error>>,
) -> Result<(), AppError> {
    config.validate()?;
    let config = Arc::new(config);
    let total = config.budgets.drain();
    let per = config.budgets.resource();
    let mut scope = LifecycleScope::<(), AppError, std::io::Error>::try_new(
        TotalDrainBudget::new(total).map_err(|_| AppError::Budget)?,
        Arc::new(assembly::Timer),
    )
    .map_err(|_| AppError::Shutdown)?;
    let outcome = scope
        .drive(
            |mut startup| {
                Box::pin(async move {
                    // Register each owned resource before any subsequent cancellable await.
                    let pool = Arc::new(
                        PgRuntime::connect_producer(
                            config.database.pg()?,
                            assembly::Timer,
                            config.storage.binding()?,
                        )
                        .await
                        .map_err(|_| AppError::Connection)?,
                    );
                    startup.stage_resource(DynManagedResource::new_box(PoolResource {
                        pool: pool.clone(),
                        timeout: per,
                    }));
                    let kdf = Arc::new(PasswordKdf::new());
                    startup.stage_resource(DynManagedResource::new_box(KdfResource {
                        kdf: kdf.clone(),
                        timeout: per,
                    }));
                    let authority = assembly::authority(&config, pool.clone(), kdf.clone()).await?;
                    let federation = assembly::federation(&config, authority.clone())?;
                    if let Some(federation) = &federation {
                        federation
                            .check_credential_keys(assembly::deadline())
                            .await?;
                        for tenant in authority.active_tenants()? {
                            federation
                                .reconcile_assurance_profiles(tenant, assembly::deadline())
                                .await?;
                        }
                    }
                    let http = HttpConfig::new(&config.public_origin, config.budgets.request())
                        .map_err(|_| AppError::Configuration)?;
                    let gate = Arc::new(OnceLock::new());
                    let context = crate::context::router(authority.clone(), &config, http.clone())?;
                    let mut app = router(authority, http.clone())?.merge(context);
                    if let Some(federation) = federation {
                        app = app.merge(federated_router(federation, http)?);
                    }
                    let app = app
                        .layer(middleware::from_fn(diagnose))
                        .layer(middleware::from_fn_with_state(gate.clone(), admit))
                        .layer(middleware::from_fn_with_state(
                            transport::Ingress {
                                public: config.public_gateway,
                            },
                            transport::trusted,
                        ));
                    let health = Arc::new(Health {
                        config: config.clone(),
                        pool,
                        kdf,
                        gate: gate.clone(),
                        probe: tokio::sync::Semaphore::new(1),
                    });
                    let app = app.merge(
                        Router::new()
                            .route("/livez", get(|| async { StatusCode::OK }))
                            .route("/readyz", get(ready))
                            .with_state(health),
                    );
                    let listener = tokio::net::TcpListener::bind(config.listen)
                        .await
                        .map_err(|_| AppError::Connection)?;
                    let mut launch = startup.commit();
                    launch.stage_task_with_token(
                        rss_axum::serve_http1_registration(
                            listener,
                            app,
                            rss_axum::PlainTransport,
                            "identity-http",
                            rss_axum::Http1ServePolicy::new(
                                rss_axum::ServePolicy::new(
                                    256,
                                    config.budgets.request(),
                                    config.budgets.request(),
                                    per,
                                )
                                .map_err(|_| AppError::Budget)?,
                                config.budgets.request(),
                                64,
                                32768,
                            )
                            .map_err(|_| AppError::Budget)?,
                        )
                        .critical(),
                    );
                    let (control, admission) = launch.finish_with_admission("requests", per);
                    gate.set(admission).map_err(|_| AppError::Shutdown)?;
                    control.open().map_err(|_| AppError::Shutdown)?;
                    let _control = control;
                    std::future::pending().await
                })
            },
            stop,
        )
        .await
        .map_err(|_| AppError::Shutdown)?;
    let clean = outcome.shutdown().as_ref().is_ok_and(|r| r.is_clean());
    match outcome.exit() {
        ScopeExit::StopRequested(Ok(())) if clean => Ok(()),
        ScopeExit::Completed(Err(error)) if clean => Err(*error),
        _ => Err(AppError::Shutdown),
    }
}
pub async fn signal() -> Result<(), std::io::Error> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {r=tokio::signal::ctrl_c()=>r,_=terminate.recv()=>Ok(())}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn diagnostics_keep_settlement_classification_out_of_the_http_body() {
        use rss_identity_postgres::{AuthorityError, StorageFailure};
        for failure in [
            HttpFailure::Authority(AuthorityError::CommitUnknown(StorageFailure::Transient)),
            HttpFailure::Authority(AuthorityError::RollbackFailed(StorageFailure::Transient)),
            HttpFailure::Authority(AuthorityError::Fenced),
            HttpFailure::RequestTimeout,
        ] {
            let payload = r#"{"code":"identity_unavailable"}"#;
            let mut response = (StatusCode::SERVICE_UNAVAILABLE, payload).into_response();
            response.extensions_mut().insert(failure);
            response
                .headers_mut()
                .insert("set-cookie", "private-cookie".parse().unwrap());
            let mut output = Vec::new();
            record_failure(&response, &mut output);
            let log = String::from_utf8(output).unwrap();
            assert_eq!(
                log,
                format!("component=identity-http failure={failure:?}\n")
            );
            assert!(!log.contains("private-cookie"));
            assert_eq!(
                axum::body::to_bytes(response.into_body(), 1024)
                    .await
                    .unwrap(),
                payload
            );
        }
        let mut output = Vec::new();
        record_failure(&StatusCode::OK.into_response(), &mut output);
        assert!(output.is_empty());
    }
    #[tokio::test]
    async fn response_body_retains_admission_until_consumed_or_dropped() {
        let mut stack = rss_runtime::ShutdownStack::try_new(
            TotalDrainBudget::new(Duration::from_secs(1)).unwrap(),
            Arc::new(assembly::Timer),
        )
        .unwrap();
        let launch = stack.startup().unwrap().commit();
        let (control, gate) = launch.finish_with_admission("requests", Duration::from_secs(1));
        control.open().unwrap();
        let permit = gate.try_admit().unwrap();
        let body = LeasedBody {
            inner: Body::from("held"),
            _permit: permit,
        };
        let mut drain = stack.shutdown();
        assert!(gate.try_admit().is_err());
        assert!(
            tokio::time::timeout(Duration::from_millis(20), drain.wait())
                .await
                .is_err()
        );
        drop(body);
        assert!(drain.wait().await.as_ref().unwrap().is_clean());
    }
}
