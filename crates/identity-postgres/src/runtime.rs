//! One replaceable runtime/outbox pair; each transaction borrows one immutable pair.
use crate::{Authority, AuthorityError, transaction::corrupt};
use rss_request_context::{Clock, Deadline, ExecutionTimer, TenantId};
use rss_transactional_messaging::{
    fence::{Epoch, ExecutionBinding, StorageIdentity},
    message::MessagingDomain,
    policy::{DeliveryBudget, OperationDeadline},
};
use rss_transactional_messaging_postgres::{PgConfig, PgOutboxStore, PgRuntime};
use std::{
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

/// Host-established generation and connection identity, outside the database restore boundary.
pub struct RuntimeSource {
    config: PgConfig,
    storage: StorageIdentity,
    generation: Epoch,
}
impl RuntimeSource {
    pub fn new(config: PgConfig, storage: StorageIdentity, generation: Epoch) -> Self {
        Self {
            config,
            storage,
            generation,
        }
    }
}
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
pub(crate) struct RuntimeBundle {
    pub runtime: Arc<PgRuntime>,
    pub outbox: Arc<PgOutboxStore<()>>,
    pub tenants: Vec<TenantId>,
}
pub(crate) struct RuntimeState {
    current: RwLock<Arc<RuntimeBundle>>,
    retired: Mutex<Vec<Arc<RuntimeBundle>>>,
    activation: tokio::sync::Mutex<()>,
    closed: AtomicBool,
    budget: DeliveryBudget,
}
impl RuntimeState {
    pub fn new(
        runtime: Arc<PgRuntime>,
        budget: DeliveryBudget,
        system: TenantId,
    ) -> Result<Self, AuthorityError> {
        Ok(Self {
            current: RwLock::new(Self::bundle(runtime, budget, vec![system])?),
            retired: Mutex::new(Vec::new()),
            activation: tokio::sync::Mutex::new(()),
            closed: AtomicBool::new(false),
            budget,
        })
    }
    fn bundle(
        runtime: Arc<PgRuntime>,
        budget: DeliveryBudget,
        tenants: Vec<TenantId>,
    ) -> Result<Arc<RuntimeBundle>, AuthorityError> {
        let outbox = PgOutboxStore::new(
            runtime.clone(),
            MessagingDomain::parse("identity.security").map_err(|_| AuthorityError::Invalid)?,
            budget,
        )
        .map_err(|_| AuthorityError::Invalid)?;
        Ok(Arc::new(RuntimeBundle {
            runtime,
            outbox: Arc::new(outbox),
            tenants,
        }))
    }
    pub fn snapshot(&self) -> Result<Arc<RuntimeBundle>, AuthorityError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(AuthorityError::Unavailable);
        }
        self.current
            .read()
            .map(|v| v.clone())
            .map_err(|_| AuthorityError::Unavailable)
    }
}
impl Authority {
    /// Current PG owner for application readiness and diagnostics; not an authentication API.
    pub fn runtime(&self) -> Result<Arc<PgRuntime>, AuthorityError> {
        Ok(self.runtimes.snapshot()?.runtime.clone())
    }
    pub fn active_tenants(&self) -> Result<Vec<TenantId>, AuthorityError> {
        Ok(self.runtimes.snapshot()?.tenants.clone())
    }
    pub fn tenant_active(&self, tenant: TenantId) -> bool {
        self.runtimes
            .snapshot()
            .is_ok_and(|v| v.tenants.contains(&tenant))
    }
    /// Discover product admission only after system fencing, using an externally supplied epoch.
    pub async fn activate_registered_tenants(
        &self,
        deadline: OperationDeadline,
    ) -> Result<(), AuthorityError> {
        self.require_runtime()?;
        let cutoff = tokio::time::Instant::now() + deadline.timeout();
        let _lock = tokio::time::timeout_at(cutoff, self.runtimes.activation.lock())
            .await
            .map_err(|_| AuthorityError::Busy)?;
        if self.runtimes.closed.load(Ordering::Acquire) {
            return Err(AuthorityError::Unavailable);
        }
        let system = self.system_domain;
        let mut tenants: Vec<TenantId>=self.read_sql(system,OperationDeadline::from_remaining(cutoff.saturating_duration_since(tokio::time::Instant::now())),move|c|Box::pin(async move {
            let ids:Vec<String>=sqlx::query_scalar("SELECT business_tenant::text FROM identity_authority.tenant_registry WHERE tenant_id=$1::uuid ORDER BY business_tenant LIMIT 128").bind(system.to_string()).fetch_all(c).await?;
            if ids.len()>127{return Err(corrupt().into());}
            ids.into_iter().map(|v|TenantId::parse(&v).map_err(|_|corrupt().into())).collect()
        })).await?;
        tenants.push(system);
        tenants.sort_by_key(|v| v.to_string());
        let ready = {
            let mut retired = self
                .runtimes
                .retired
                .lock()
                .map_err(|_| AuthorityError::Unavailable)?;
            let mut ready = Vec::new();
            let mut i = 0;
            while i < retired.len() {
                if Arc::strong_count(&retired[i]) == 1 {
                    ready.push(retired.remove(i));
                } else {
                    i += 1;
                }
            }
            ready
        };
        for old in ready {
            if tokio::time::timeout_at(cutoff, old.runtime.close())
                .await
                .is_err()
            {
                self.runtimes
                    .retired
                    .lock()
                    .map_err(|_| AuthorityError::Unavailable)?
                    .push(old);
                return Err(AuthorityError::Busy);
            }
        }
        if self.runtimes.snapshot()?.tenants == tenants {
            return Ok(());
        }
        if !self
            .runtimes
            .retired
            .lock()
            .map_err(|_| AuthorityError::Unavailable)?
            .is_empty()
        {
            return Err(AuthorityError::Busy);
        }
        let source = &self.runtime_configuration()?.source;
        let binding = ExecutionBinding::new(
            source.storage,
            tenants.iter().map(|t| (*t, source.generation)).collect(),
        )
        .map_err(|_| AuthorityError::Invalid)?;
        let runtime = Arc::new(
            tokio::time::timeout_at(
                cutoff,
                PgRuntime::connect_producer(source.config.clone(), Timer, binding),
            )
            .await
            .map_err(|_| AuthorityError::Unavailable)?
            .map_err(|_| AuthorityError::Unavailable)?,
        );
        let verified = async {
            for tenant in &tenants {
                let result = runtime
                    .local_tx(
                        *tenant,
                        OperationDeadline::from_remaining(
                            cutoff.saturating_duration_since(tokio::time::Instant::now()),
                        ),
                        |_| Box::pin(async { Ok(()) }),
                    )
                    .await;
                result.fold(
                    |_| Ok(()),
                    |_| Err(AuthorityError::Unavailable),
                    |_| Err(AuthorityError::Unavailable),
                    |_| Err(AuthorityError::Unavailable),
                    |_| Err(AuthorityError::Unavailable),
                    |_| Err(AuthorityError::Fenced),
                )?;
            }
            Ok::<_, AuthorityError>(())
        }
        .await;
        if let Err(e) = verified {
            runtime.close().await;
            return Err(e);
        }
        let next = RuntimeState::bundle(runtime, self.runtimes.budget, tenants)?;
        let old = std::mem::replace(
            &mut *self
                .runtimes
                .current
                .write()
                .map_err(|_| AuthorityError::Unavailable)?,
            next,
        );
        self.runtimes
            .retired
            .lock()
            .map_err(|_| AuthorityError::Unavailable)?
            .push(old);
        Ok(())
    }
    /// Shutdown owns active and retired pools; caller provides its lifecycle drain budget.
    pub async fn close(&self) {
        let _lock = self.runtimes.activation.lock().await;
        self.runtimes.closed.store(true, Ordering::Release);
        let active = self
            .runtimes
            .current
            .read()
            .unwrap_or_else(|v| v.into_inner())
            .clone();
        active.runtime.close().await;
        let retired = std::mem::take(
            &mut *self
                .runtimes
                .retired
                .lock()
                .unwrap_or_else(|v| v.into_inner()),
        );
        for old in retired {
            old.runtime.close().await;
        }
    }
}
