//! One private settlement path. ref: RSS transaction.rs @ bf5dd1350997d01aa834094a3347fce30247814e.
use crate::{AccountKey, Authority, AuthorityError};
use futures::future::BoxFuture;
use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
use rss_request_context::TenantId;
use rss_transactional_messaging::{
    error::{MessagingError, MessagingErrorKind},
    message::*,
    outbox::{AppendOutcome, OutboxStore, PendingMessage},
    policy::OperationDeadline,
};
use rss_transactional_messaging_postgres::{PgError, PgTransaction};
use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use rss_identity_core::account::{AccountRuleError, AccountState, SecurityAction};
#[derive(Serialize)]
pub(crate) struct AccountEvent {
    pub action: &'static str,
    pub tenant: String,
    pub principal: Uuid,
    pub actor: Option<Uuid>,
    pub epoch: i64,
    pub state: EventState,
}
#[derive(Serialize)]
pub(crate) struct EventState {
    enabled: bool,
    administrator: bool,
    emergency: bool,
    member_active: bool,
    membership_epoch: i64,
}
impl AccountEvent {
    pub fn account(action: SecurityAction, state: AccountState, actor: Option<AccountKey>) -> Self {
        Self {
            action: action.as_str(),
            tenant: state.key().tenant.to_string(),
            principal: state.key().principal.as_uuid(),
            actor: actor.map(|a| a.principal.as_uuid()),
            epoch: state.epoch(),
            state: EventState {
                enabled: state.enabled(),
                administrator: state.administrator(),
                emergency: state.emergency(),
                member_active: state.member_active(),
                membership_epoch: state.membership_epoch(),
            },
        }
    }
}
/// Closed set of event contracts using the same settlement path.
#[derive(Serialize)]
#[serde(untagged)]
pub(crate) enum SecurityEvent {
    Account(AccountEvent),
    Session(crate::sessions::SessionEvent),
    Federation(crate::federation::FederationEvent),
    Downstream(crate::downstream::DownstreamEvent),
}
impl SecurityEvent {
    pub fn account(action: SecurityAction, state: AccountState, actor: Option<AccountKey>) -> Self {
        Self::Account(AccountEvent::account(action, state, actor))
    }
    fn tenant(&self) -> &str {
        match self {
            Self::Downstream(v) => &v.tenant,
            Self::Account(v) => &v.tenant,
            Self::Session(v) => &v.tenant,
            Self::Federation(v) => &v.tenant,
        }
    }
    fn contract(&self) -> (&'static str, &'static str, u32, &'static str) {
        match self {
            Self::Downstream(_) => (
                "downstream.changed",
                "identity.downstream.security",
                1,
                include_str!("downstream-security-event-v1.json"),
            ),
            Self::Account(_) => (
                "account.changed",
                "identity.account.security",
                2,
                EVENT_SCHEMA,
            ),
            Self::Federation(_) => (
                "federation.changed",
                "identity.federation.security",
                1,
                include_str!("federation-security-event-v1.json"),
            ),
            Self::Session(_) => (
                "session.changed",
                "identity.session.security",
                1,
                include_str!("session-security-event-v1.json"),
            ),
        }
    }
}
#[derive(Debug, thiserror::Error)]
pub(crate) enum MutationError {
    #[error(transparent)]
    Storage(#[from] PgError),
    #[error(transparent)]
    Rule(#[from] AccountRuleError),
    #[error(transparent)]
    Federation(#[from] rss_identity_core::federation::FederationError),
    #[error(transparent)]
    Downstream(#[from] rss_identity_core::downstream::DownstreamError),
}
impl From<sqlx::Error> for MutationError {
    fn from(error: sqlx::Error) -> Self {
        Self::Storage(error.into())
    }
}
const EVENT_SCHEMA: &str = include_str!("security-event-v2.json");
pub(crate) fn reject() -> PgError {
    MessagingError::new(
        MessagingErrorKind::Conflict,
        std::io::Error::other("account operation rejected"),
    )
    .into()
}
pub(crate) fn corrupt() -> PgError {
    MessagingError::new(
        MessagingErrorKind::Invariant,
        std::io::Error::other("invalid authority state"),
    )
    .into()
}

impl Authority {
    pub(crate) async fn read<T: Send, F>(
        &self,
        tenant: TenantId,
        deadline: OperationDeadline,
        operation: F,
    ) -> Result<T, AuthorityError>
    where
        F: for<'a> FnOnce(&'a mut PgTransaction<'_>) -> BoxFuture<'a, Result<T, PgError>> + Send,
    {
        if deadline.timeout().is_zero() {
            return Err(AuthorityError::NotStarted(
                crate::StorageFailure::DeadlineElapsed,
            ));
        }
        self.runtime
            .local_tx(tenant, deadline, operation)
            .await
            .fold(
                Ok,
                |e| Err(AuthorityError::NotStarted(e.kind().into())),
                |e| {
                    Err(if e.kind() == MessagingErrorKind::Conflict {
                        AuthorityError::Rejected
                    } else {
                        AuthorityError::RolledBack(e.kind().into())
                    })
                },
                |e| Err(AuthorityError::RollbackFailed(e.kind().into())),
                |e| Err(AuthorityError::CommitUnknown(e.kind().into())),
                |_| Err(AuthorityError::Fenced),
            )
    }
    pub(crate) async fn read_sql<T: Send + 'static, F>(
        &self,
        tenant: TenantId,
        deadline: OperationDeadline,
        work: F,
    ) -> Result<T, AuthorityError>
    where
        F: for<'a> FnOnce(&'a mut sqlx::PgConnection) -> BoxFuture<'a, Result<T, MutationError>>
            + Send
            + 'static,
    {
        let reason = std::sync::Arc::new(std::sync::OnceLock::new());
        let slot = reason.clone();
        let result = self
            .read(tenant, deadline, move |tx| {
                Box::pin(async move {
                    connection(tx, work)
                        .await
                        .map_err(|e| sql_failure(e, &slot))
                })
            })
            .await;
        domain_result(result, reason.get().copied())
    }
    pub(crate) async fn write_sql<T: Send + 'static, F>(
        &self,
        tenant: TenantId,
        deadline: OperationDeadline,
        work: F,
    ) -> Result<T, AuthorityError>
    where
        F: for<'a> FnOnce(
                &'a mut sqlx::PgConnection,
            )
                -> BoxFuture<'a, Result<(T, Vec<SecurityEvent>), MutationError>>
            + Send
            + 'static,
    {
        self.mutate_events(tenant, deadline, move |tx| {
            Box::pin(async move { connection(tx, work).await })
        })
        .await
    }
    pub(crate) async fn mutate<T: Send, F>(
        &self,
        tenant: TenantId,
        deadline: OperationDeadline,
        operation: F,
    ) -> Result<T, AuthorityError>
    where
        F: for<'a> FnOnce(
                &'a mut PgTransaction<'_>,
            ) -> BoxFuture<'a, Result<(T, SecurityEvent), MutationError>>
            + Send
            + 'static,
    {
        self.mutate_events(tenant, deadline, move |tx| {
            Box::pin(async move {
                let (value, event) = operation(tx).await?;
                Ok((value, vec![event]))
            })
        })
        .await
    }
    pub(crate) async fn mutate_events<T: Send, F>(
        &self,
        tenant: TenantId,
        deadline: OperationDeadline,
        operation: F,
    ) -> Result<T, AuthorityError>
    where
        F: for<'a> FnOnce(
                &'a mut PgTransaction<'_>,
            )
                -> BoxFuture<'a, Result<(T, Vec<SecurityEvent>), MutationError>>
            + Send
            + 'static,
    {
        self.settle_events(tenant, deadline, operation, true).await
    }
    /// Conditional domain transition: empty events are permitted only for unchanged business state.
    pub(crate) async fn conditional_write_sql<T: Send + 'static, F>(
        &self,
        tenant: TenantId,
        deadline: OperationDeadline,
        work: F,
    ) -> Result<T, AuthorityError>
    where
        F: for<'a> FnOnce(
                &'a mut sqlx::PgConnection,
            )
                -> BoxFuture<'a, Result<(T, Vec<SecurityEvent>), MutationError>>
            + Send
            + 'static,
    {
        self.settle_events(
            tenant,
            deadline,
            move |tx| Box::pin(async move { connection(tx, work).await }),
            false,
        )
        .await
    }
    async fn settle_events<T: Send, F>(
        &self,
        tenant: TenantId,
        deadline: OperationDeadline,
        operation: F,
        require_event: bool,
    ) -> Result<T, AuthorityError>
    where
        F: for<'a> FnOnce(
                &'a mut PgTransaction<'_>,
            )
                -> BoxFuture<'a, Result<(T, Vec<SecurityEvent>), MutationError>>
            + Send
            + 'static,
    {
        let outbox = self.outbox.clone();
        let reason = std::sync::Arc::new(std::sync::OnceLock::new());
        let reason_slot = reason.clone();
        let result = self
            .read(tenant, deadline, move |tx| {
                Box::pin(async move {
                    let (result, events) = operation(tx)
                        .await
                        .map_err(|e| sql_failure(e, &reason_slot))?;
                    if (require_event && events.is_empty()) || events.len() > 8 {
                        return Err(corrupt());
                    }
                    for event in events {
                        if event.tenant() != tenant.to_string() {
                            return Err(corrupt());
                        }
                        let now: i64 = tx
                            .with_connection(|c| {
                                Box::pin(async {
                                    sqlx::query_scalar(
                                    "SELECT floor(extract(epoch FROM clock_timestamp()))::bigint",
                                )
                                .fetch_one(c)
                                .await
                                })
                            })
                            .await?;
                        let (route, contract, version, schema) = event.contract();
                        let envelope = MessageEnvelope::new(
                            MessageId::parse(&Uuid::new_v4().to_string()).map_err(|_| corrupt())?,
                            MessageMetadata::new(
                                AuthoredMessageMetadata::new(
                                    tenant,
                                    Timepoint::try_from(now).map_err(|_| corrupt())?,
                                    MessagingDomain::parse("identity.security")
                                        .map_err(|_| corrupt())?,
                                    MessageRoute::parse(route).map_err(|_| corrupt())?,
                                    ContractIdentity::new(
                                        ContractId::parse(contract).map_err(|_| corrupt())?,
                                        ContractVersion::from_major(version)
                                            .map_err(|_| corrupt())?,
                                        SchemaDigest::parse(&format!(
                                            "sha256:{:x}",
                                            Sha256::digest(schema)
                                        ))
                                        .map_err(|_| corrupt())?,
                                    ),
                                ),
                                MessageMetadataExtensions::default(),
                            ),
                            serde_json::to_vec(&event).map_err(|_| corrupt())?,
                        );
                        if outbox.append(tx, PendingMessage::new(envelope)).await?
                            != AppendOutcome::Inserted
                        {
                            return Err(corrupt());
                        }
                    }
                    Ok(result)
                })
            })
            .await;
        domain_result(result, reason.get().copied())
    }
}

// Carry domain rejection through SQLx's connection callback, then abort the outer transaction.
pub(crate) async fn connection<T: Send + 'static, E: Send + From<PgError> + 'static, F>(
    tx: &mut PgTransaction<'_>,
    work: F,
) -> Result<T, E>
where
    F: for<'a> FnOnce(&'a mut sqlx::PgConnection) -> BoxFuture<'a, Result<T, E>> + Send,
{
    tx.with_connection(move |c| {
        let future = work(c);
        Box::pin(async move { Ok(future.await) })
    })
    .await
    .map_err(E::from)?
}

fn sql_failure(error: MutationError, reason: &std::sync::OnceLock<AuthorityError>) -> PgError {
    match error {
        MutationError::Storage(e) => e,
        MutationError::Rule(e) => {
            let _ = reason.set(AuthorityError::RuleRejected(e));
            reject()
        }
        MutationError::Downstream(e) => {
            let _ = reason.set(AuthorityError::Downstream(e));
            reject()
        }
        MutationError::Federation(e) => {
            let _ = reason.set(AuthorityError::Federation(e));
            reject()
        }
    }
}
fn domain_result<T>(
    result: Result<T, AuthorityError>,
    reason: Option<AuthorityError>,
) -> Result<T, AuthorityError> {
    match (result, reason) {
        (
            Err(AuthorityError::Rejected),
            Some(AuthorityError::RuleRejected(AccountRuleError::Rejected)),
        ) => Err(AuthorityError::Rejected),
        (Err(AuthorityError::Rejected), Some(reason)) => Err(reason),
        (result, _) => result,
    }
}
