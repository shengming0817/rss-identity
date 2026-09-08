//! Access-owned composition of a business mutation and its mandatory security event.
use futures::future::BoxFuture;
use rss_request_context::TenantId;
use rss_transactional_messaging::{
    error::{MessagingError, MessagingErrorKind},
    message::{MessageEnvelope, MessagingDomain},
    outbox::{AppendOutcome, OutboxStore, PendingMessage},
    policy::{DeliveryBudget, OperationDeadline},
};
use rss_transactional_messaging_postgres::{PgError, PgOutboxStore, PgRuntime, PgTransaction};
use std::sync::Arc;

/// Inject one RSS runtime: it remains the only connection/transaction owner.
pub struct AccessPostgres {
    runtime: Arc<PgRuntime>,
    outbox: Arc<PgOutboxStore<()>>,
}
impl AccessPostgres {
    pub fn new(runtime: Arc<PgRuntime>, budget: DeliveryBudget) -> Result<Self, PgError> {
        let domain = MessagingDomain::parse("access.security").map_err(|_| invariant())?;
        let outbox = Arc::new(PgOutboxStore::new(runtime.clone(), domain, budget)?);
        Ok(Self { runtime, outbox })
    }
    /// Commit a trusted application's write and new security event atomically.
    /// Duplicate event IDs roll back the write; this is not a business idempotency API.
    /// Caller owns event semantics/redaction and must not pass browser-controlled payloads.
    pub async fn write_with_event<T: Send, F>(
        &self,
        tenant: TenantId,
        deadline: OperationDeadline,
        event: MessageEnvelope<Vec<u8>>,
        operation: F,
    ) -> Result<T, WriteError>
    where
        F: for<'a> FnOnce(&'a mut PgTransaction<'_>) -> BoxFuture<'a, Result<T, PgError>>
            + Send
            + 'static,
    {
        if event.metadata().tenant_id() != tenant
            || event.metadata().domain().as_str() != "access.security"
        {
            return Err(WriteError::Binding);
        }
        let outbox = self.outbox.clone();
        self.runtime
            .local_tx(tenant, deadline, move |tx| {
                Box::pin(async move {
                    let result = operation(tx).await?;
                    if outbox.append(tx, PendingMessage::new(event)).await?
                        != AppendOutcome::Inserted
                    {
                        return Err(invariant());
                    }
                    Ok(result)
                })
            })
            .await
            .fold(
                Ok,
                |e| Err(WriteError::NotStarted(e)),
                |e| Err(WriteError::RolledBack(e)),
                |e| Err(WriteError::RollbackFailed(e)),
                |e| Err(WriteError::CommitUnknown(e)),
                |e| Err(WriteError::Fenced(e)),
            )
    }
}
fn invariant() -> PgError {
    MessagingError::new(
        MessagingErrorKind::Invariant,
        std::io::Error::other("access event binding or duplicate identity"),
    )
    .into()
}
/// No unsuccessful or uncertain transaction can produce the operation's success value.
#[derive(Debug, thiserror::Error)]
pub enum WriteError {
    #[error("event destination mismatch")]
    Binding,
    #[error("transaction not started")]
    NotStarted(#[source] PgError),
    #[error("transaction rolled back")]
    RolledBack(#[source] PgError),
    #[error("rollback not confirmed")]
    RollbackFailed(#[source] PgError),
    #[error("commit not confirmed")]
    CommitUnknown(#[source] PgError),
    #[error("execution fenced")]
    Fenced(#[source] PgError),
}
