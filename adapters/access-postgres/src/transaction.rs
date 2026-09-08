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

use access_core::account::{AccountRuleError, AccountState, SecurityAction};
#[derive(Serialize)]
pub(crate) struct SecurityEvent {
    pub action: &'static str,
    pub tenant: String,
    pub principal: Uuid,
    pub actor: Option<Uuid>,
    pub epoch: i64,
    pub state: Option<EventState>,
}
impl SecurityEvent {
    pub fn new(
        action: SecurityAction,
        key: AccountKey,
        actor: Option<AccountKey>,
        epoch: i64,
    ) -> Self {
        Self {
            action: action.as_str(),
            tenant: key.tenant.to_string(),
            principal: key.principal.as_uuid(),
            actor: actor.map(|a| a.principal.as_uuid()),
            epoch,
            state: None,
        }
    }
}
#[derive(Serialize)]
pub(crate) struct EventState {
    enabled: bool,
    administrator: bool,
    emergency: bool,
    member_active: bool,
    credential_version: i64,
    membership_epoch: i64,
}
impl SecurityEvent {
    pub fn account(action: SecurityAction, state: AccountState, actor: Option<AccountKey>) -> Self {
        let mut event = Self::new(action, state.key(), actor, state.epoch());
        event.state = Some(EventState {
            enabled: state.enabled(),
            administrator: state.administrator(),
            emergency: state.emergency(),
            member_active: state.member_active(),
            credential_version: state.credential_version(),
            membership_epoch: state.membership_epoch(),
        });
        event
    }
}
#[derive(Debug, thiserror::Error)]
pub(crate) enum MutationError {
    #[error(transparent)]
    Storage(#[from] PgError),
    #[error(transparent)]
    Rule(#[from] AccountRuleError),
}
impl From<sqlx::Error> for MutationError {
    fn from(error: sqlx::Error) -> Self {
        Self::Storage(error.into())
    }
}
const EVENT_SCHEMA: &str = include_str!("security-event-v1.json");
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
        let outbox = self.outbox.clone();
        let reason = std::sync::Arc::new(std::sync::OnceLock::new());
        let reason_slot = reason.clone();
        let result = self
            .read(tenant, deadline, move |tx| {
                Box::pin(async move {
                    let (result, event) = operation(tx).await.map_err(|error| match error {
                        MutationError::Storage(error) => error,
                        MutationError::Rule(rule) => {
                            let _ = reason_slot.set(rule);
                            reject()
                        }
                    })?;
                    if event.tenant != tenant.to_string() {
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
                    let envelope = MessageEnvelope::new(
                        MessageId::parse(&Uuid::new_v4().to_string()).map_err(|_| corrupt())?,
                        MessageMetadata::new(
                            AuthoredMessageMetadata::new(
                                tenant,
                                Timepoint::try_from(now).map_err(|_| corrupt())?,
                                MessagingDomain::parse("access.security").map_err(|_| corrupt())?,
                                MessageRoute::parse("account.changed").map_err(|_| corrupt())?,
                                ContractIdentity::new(
                                    ContractId::parse("access.account.security")
                                        .map_err(|_| corrupt())?,
                                    ContractVersion::from_major(1).map_err(|_| corrupt())?,
                                    SchemaDigest::parse(&format!(
                                        "sha256:{:x}",
                                        Sha256::digest(EVENT_SCHEMA)
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
                    Ok(result)
                })
            })
            .await;
        match (result, reason.get().copied()) {
            (Err(AuthorityError::Rejected), Some(AccountRuleError::Rejected)) => {
                Err(AuthorityError::Rejected)
            }
            (Err(AuthorityError::Rejected), Some(reason)) => {
                Err(AuthorityError::RuleRejected(reason))
            }
            (result, _) => result, // Uncertain settlement always wins over domain diagnostics.
        }
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
