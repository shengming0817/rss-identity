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
use rss_identity_http_axum::{HttpConfig, downstream_router, federated_router, management_router};
use rss_runtime::{
    AdmissionGate, AdmissionPermit, DynManagedResource, LifecycleScope, ManagedResource,
    ManagedTask, ScopeExit, ShutdownError, TotalDrainBudget,
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
struct Health {
    config: Arc<RuntimeConfig>,
    pool: Arc<PgRuntime>,
    kdf: Arc<PasswordKdf>,
    hydra: Arc<rss_identity_hydra::Hydra>,
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
        if h.hydra.ready().await.is_err() {
            eprintln!("component=hydra readiness=unavailable");
            return Err(AppError::Provider);
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
    )
    .map_err(|_| AppError::Shutdown)?;
    let outcome=scope.drive(|mut startup|Box::pin(async move {
        // Register each owned resource before any subsequent cancellable await.
        let pool=Arc::new(PgRuntime::connect_producer(config.database.pg()?,assembly::Timer,config.storage.binding()?).await.map_err(|_|AppError::Connection)?);
        startup.stage_resource(DynManagedResource::new_box(PoolResource{pool:pool.clone(),timeout:per}));
        let kdf=Arc::new(PasswordKdf::new());
        startup.stage_resource(DynManagedResource::new_box(KdfResource{kdf:kdf.clone(),timeout:per}));
        let authority=assembly::authority(&config,pool.clone(),kdf.clone()).await?;
        let providers=assembly::providers(&config,authority)?;
        let http=HttpConfig::new(config.identity_origin.identity_origin(),config.budgets.request()).map_err(|_|AppError::Configuration)?;
        let gate=Arc::new(OnceLock::new());
        let app=federated_router(providers.federation.clone(),http.clone())?
            .merge(management_router(providers.federation,http.clone())?)
            .merge(downstream_router(providers.downstream.clone(),http,providers.validation_secrets)?)
            .layer(middleware::from_fn_with_state(gate.clone(),admit))
            .layer(middleware::from_fn_with_state(transport::Ingress{public:config.public_gateway,private:config.private_gateway},transport::trusted));
        let health=Arc::new(Health{config:config.clone(),pool,kdf,hydra:providers.hydra,gate:gate.clone(),probe:tokio::sync::Semaphore::new(1)});
        let app=app.merge(Router::new().route("/livez",get(||async{StatusCode::OK})).route("/readyz",get(ready)).with_state(health));
        let tenants=config.storage.tenants()?;let cleanup=providers.downstream;
        let(worker,_)=ManagedTask::prepare("downstream-cleanup",per);
        startup.stage_deferred_task_with_token(worker.into_registration(move |token|async move {
            loop {
                // The in-flight pass owns its bounded settlement. Cancellation only stops new passes.
                for tenant in &tenants {
                    if token.is_cancelled(){return Ok(());}
                    if cleanup.cleanup_once(*tenant,128,assembly::deadline()).await.is_err(){eprintln!("component=downstream_cleanup result=unavailable");}
                }
                tokio::select!{_ = token.cancelled()=>return Ok(()), _=tokio::time::sleep(Duration::from_secs(30))=>{}}
            }
        }).critical());
        let listener=tokio::net::TcpListener::bind(config.listen).await.map_err(|_|AppError::Connection)?;
        let mut launch=startup.commit();
        launch.stage_task_with_token(rss_axum::serve_http1_registration(listener,app,"identity-http",per).critical());
        let(control,admission)=launch.finish_with_admission("requests",per);
        gate.set(admission).map_err(|_|AppError::Shutdown)?;
        control.open().map_err(|_|AppError::Shutdown)?;
        let _control=control;
        std::future::pending().await
    }),stop).await.map_err(|_|AppError::Shutdown)?;
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
    async fn response_body_retains_admission_until_consumed_or_dropped() {
        let mut stack = rss_runtime::ShutdownStack::try_new(
            TotalDrainBudget::new(Duration::from_secs(1)).unwrap(),
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
