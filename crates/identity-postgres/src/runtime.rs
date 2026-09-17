//! Borrow the host runtime; dropping this service never closes the host pool.
use crate::AuthorityError;
use rss_request_context::TenantId;
use rss_transactional_messaging::{message::MessagingDomain, policy::DeliveryBudget};
use rss_transactional_messaging_postgres::{PgOutboxStore, PgRuntime};
use std::sync::Arc;
pub(crate) struct RuntimeBundle {
    pub runtime: Arc<PgRuntime>,
    pub outbox: Arc<PgOutboxStore<()>>,
    pub tenants: Vec<TenantId>,
    pub instance: rss_identity_core::InstanceId,
}
pub(crate) struct RuntimeState(Arc<RuntimeBundle>);
impl RuntimeState {
    pub fn new(
        runtime: Arc<PgRuntime>,
        budget: DeliveryBudget,
        tenants: Vec<TenantId>,
        instance: rss_identity_core::InstanceId,
    ) -> Result<Self, AuthorityError> {
        let outbox = PgOutboxStore::new(
            runtime.clone(),
            MessagingDomain::parse("identity.security").map_err(|_| AuthorityError::Invalid)?,
            budget,
        )
        .map_err(|_| AuthorityError::Invalid)?;
        Ok(Self(Arc::new(RuntimeBundle {
            runtime,
            outbox: Arc::new(outbox),
            tenants,
            instance,
        })))
    }
    pub fn snapshot(&self) -> Result<Arc<RuntimeBundle>, AuthorityError> {
        Ok(self.0.clone())
    }
}
