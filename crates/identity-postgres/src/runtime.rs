//! Immutable host resources; this service never closes the host runtime.
use rss_request_context::TenantId;
use rss_transactional_messaging::fence::ExecutionBinding;
use rss_transactional_messaging_postgres::PgRuntime;
use std::sync::Arc;
pub(crate) struct RuntimeBundle {
    pub runtime: Arc<PgRuntime>,
    pub audit: rss_audit_postgres::Integrity,
    pub bindings: Vec<ExecutionBinding>,
    pub instance: rss_identity_core::InstanceId,
}

impl RuntimeBundle {
    pub fn binding(&self, tenant: TenantId) -> Option<ExecutionBinding> {
        self.bindings
            .iter()
            .find(|binding| binding.tenant() == tenant)
            .copied()
    }
}
