//! Identity-owned audit projection. Hosts supply same-database worker resources and own their lifetime.
//! ref: sqlx sqlx-core/src/transaction.rs@v0.9.0 (only the message owner settles).
mod error;
mod profile;
pub use error::AuditDeliveryError;
pub use profile::{grant_worker, verify_worker};
mod mapping;
mod observations;
use mapping::{accepted_contract, map_event};
use rss_audit_postgres::PgAudit;
use rss_contract::Timepoint;
use rss_identity_core::InstanceId;
use rss_request_context::{Clock, Deadline, ExecutionTimer, TenantId};
use rss_transactional_messaging::{
    error::{MessagingError, MessagingErrorKind},
    inbox::ConsumerGroup,
    message::{MessageEnvelope, MessagingDomain, SubscriptionIdentity},
    observability::{TransactionalMessagingEmitter, TransactionalMessagingObservation},
    policy::{
        ConsumerExecutionPolicy, DeliveryBudget, ExecutionBudget, LeaseRenewalPolicy,
        OperationDeadline, RetryPolicy,
    },
    transaction::{
        EnvelopeValidationFailure, IngressChallenge, IngressValidator, RejectKind,
        SettlementDecision, SettlementKind, TerminalDisposition, VerifiedIngress,
    },
    transport::{
        Delivery, DeliverySettlement, PublishFailure, PublishFailureKind, PublishFailureReason,
        PublishFailureStage, PublishOutcome, Publisher,
    },
};
use rss_transactional_messaging_postgres::{
    PgConsumerEffect, PgConsumerEffectFailure, PgConsumerTx, PgInboxStore, PgOutboxStore,
    PgRuntime, PgTransaction,
};
use rss_transactional_messaging_runtime::{
    consumer::{ConsumerExecution, consume_once},
    relay::{RelayBatchLimit, RelayReport, relay_once},
};
use std::{
    num::NonZeroU32,
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};

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
struct Observations;
impl TransactionalMessagingEmitter for Observations {
    fn emit(&self, event: TransactionalMessagingObservation) {
        observations::record(event, std::io::stderr().lock());
    }
}
struct Effect {
    instance: InstanceId,
    audit: Arc<PgAudit>,
    fatal: Arc<OnceLock<AuditDeliveryError>>,
}
impl PgConsumerEffect<Vec<u8>> for Effect {
    async fn apply(
        &self,
        tx: &mut PgTransaction<'_>,
        message: &MessageEnvelope<Vec<u8>>,
        _: OperationDeadline,
    ) -> Result<TerminalDisposition, PgConsumerEffectFailure> {
        let seconds: i64 = tx
            .with_connection(|c| {
                Box::pin(async {
                    sqlx::query_scalar(
                        "SELECT floor(extract(epoch FROM clock_timestamp()))::bigint",
                    )
                    .fetch_one(c)
                    .await
                })
            })
            .await
            .map_err(PgConsumerEffectFailure::infrastructure)?;
        let recorded =
            Timepoint::try_from(seconds).map_err(PgConsumerEffectFailure::infrastructure)?;
        let Ok(event) = map_event(self.instance, message, recorded) else {
            return Ok(TerminalDisposition::Rejected(RejectKind::Permanent));
        };
        let request = rss_audit_core::prepare(event, recorded)
            .map_err(PgConsumerEffectFailure::infrastructure)?;
        match self.audit.append_in(tx, &request).await {
            Ok(_) => Ok(TerminalDisposition::Succeeded),
            Err(
                rss_audit_postgres::Error::Conflict
                | rss_audit_postgres::Error::ScopeMismatch
                | rss_audit_postgres::Error::Protocol(_),
            ) => Ok(TerminalDisposition::Rejected(RejectKind::Invariant)),
            Err(e) => {
                if matches!(
                    e,
                    rss_audit_postgres::Error::Admission(_)
                        | rss_audit_postgres::Error::StorageContract
                        | rss_audit_postgres::Error::Storage {
                            kind: rss_audit_postgres::StorageFailure::Permanent,
                            ..
                        }
                ) {
                    let _ = self.fatal.set(AuditDeliveryError::Permanent);
                }
                Err(PgConsumerEffectFailure::infrastructure(e))
            }
        }
    }
}
struct Validator {
    tenants: Vec<TenantId>,
}
impl IngressValidator<Vec<u8>> for Validator {
    fn validate(
        &self,
        c: IngressChallenge<'_, Vec<u8>>,
    ) -> Result<VerifiedIngress, EnvelopeValidationFailure> {
        let m = c.message().metadata();
        if !self.tenants.contains(&m.tenant_id()) {
            return Err(EnvelopeValidationFailure::MalformedIdentity);
        }
        let route = accepted_contract(
            m.contract().id().as_str(),
            &m.contract().version().to_string(),
            m.contract().schema_digest().as_str(),
        );
        if m.domain().as_str() != "identity.security" || route != Some(m.route().as_str()) {
            return Err(EnvelopeValidationFailure::UnsupportedContract);
        }
        Ok(c.verified()) // Private publisher receives only the bound PG outbox's envelopes.
    }
}
struct LocalSettlement(Arc<OnceLock<SettlementKind>>);
impl DeliverySettlement for LocalSettlement {
    async fn settle(
        self,
        decision: SettlementDecision,
        _: OperationDeadline,
    ) -> Result<(), MessagingError> {
        self.0.set(decision.kind()).map_err(|_| invalid())
    }
    async fn abandon(self, _: OperationDeadline) -> Result<(), MessagingError> {
        Ok(())
    }
}
fn invalid() -> MessagingError {
    MessagingError::new(
        MessagingErrorKind::Invariant,
        std::io::Error::other("audit delivery contract"),
    )
}
fn outcome(decision: Option<SettlementKind>) -> PublishOutcome<()> {
    let failure = PublishFailure::new(
        PublishFailureKind::Permanent,
        PublishFailureStage::Confirm,
        PublishFailureReason::InvalidMessage,
    );
    match decision {
        Some(SettlementKind::Acknowledge) => PublishOutcome::Confirmed(()),
        Some(SettlementKind::Reject) => PublishOutcome::DefinitelyNotPublished(failure),
        _ => PublishOutcome::Ambiguous(PublishFailure::new(
            PublishFailureKind::Transient,
            PublishFailureStage::Confirm,
            PublishFailureReason::TransportUnavailable,
        )),
    }
}
struct LocalPublisher {
    fatal: Arc<OnceLock<AuditDeliveryError>>,
    inbox: PgInboxStore,
    tx: PgConsumerTx<Effect>,
    validator: Validator,
    group: ConsumerGroup,
}
impl Publisher<Vec<u8>> for LocalPublisher {
    type Receipt = ();
    async fn publish(
        &self,
        message: &MessageEnvelope<Vec<u8>>,
        deadline: OperationDeadline,
    ) -> PublishOutcome<()> {
        let total = deadline.timeout();
        let Ok(budget) = ExecutionBudget::new(total, total / 4) else {
            return outcome(None);
        };
        let retry = RetryPolicy::new(
            NonZeroU32::MIN,
            Duration::from_millis(10),
            Duration::from_millis(10),
        )
        .expect("constant retry policy");
        let meta = message.metadata();
        let subscription = SubscriptionIdentity::new(
            meta.domain().clone(),
            meta.route().clone(),
            meta.contract().clone(),
        );
        let execution = ConsumerExecution::new(
            self.group.clone(),
            &self.validator,
            &subscription,
            &Timer,
            ConsumerExecutionPolicy::new(retry, budget),
            &Observations,
        );
        let decision = Arc::new(OnceLock::new());
        let copy = MessageEnvelope::new(
            message.id().clone(),
            meta.clone(),
            message.payload().clone(),
        );
        // consume_once owns the absolute execution/settlement budget; do not drop its transaction future.
        let result = consume_once(
            &self.inbox,
            &self.tx,
            &execution,
            Delivery::new(copy, LocalSettlement(decision.clone())),
        )
        .await;
        match result {
            Ok(_) => outcome(decision.get().copied()),
            Err(e) if e.kind() == MessagingErrorKind::Conflict => {
                outcome(Some(SettlementKind::Reject))
            }
            Err(e) => {
                if matches!(
                    e.kind(),
                    MessagingErrorKind::Invariant
                        | MessagingErrorKind::OwnershipLost
                        | MessagingErrorKind::Permanent
                ) {
                    let _ = self.fatal.set(AuditDeliveryError::messaging(e.kind()));
                }
                outcome(None)
            }
        }
    }
}
/// Caller-driven bounded relay. Construction does not spawn tasks or take ownership of pools.
/// `runtime` must be the consumer-only worker profile for the Identity database; `audit` must target that
/// same database. The host binds the actual Identity instance and admitted tenants at startup.
pub struct AuditDelivery {
    outbox: PgOutboxStore<()>,
    publisher: LocalPublisher,
    fatal: Arc<OnceLock<AuditDeliveryError>>,
}
impl AuditDelivery {
    /// Bind the existing message mechanisms to Identity's sole audit consumer group.
    pub async fn new(
        runtime: Arc<PgRuntime>,
        audit: Arc<PgAudit>,
        instance: InstanceId,
        tenants: Vec<TenantId>,
        budget: DeliveryBudget,
    ) -> Result<Self, AuditDeliveryError> {
        if tenants.is_empty() || tenants.len() > 128 {
            return Err(AuditDeliveryError::Configuration);
        }
        let lease = LeaseRenewalPolicy::from_ttl(budget.lease_ttl())
            .map_err(|_| AuditDeliveryError::Configuration)?;
        let fatal = Arc::new(OnceLock::new());
        let delivery = Self {
            fatal: fatal.clone(),
            outbox: PgOutboxStore::new(
                runtime.clone(),
                MessagingDomain::parse("identity.security")
                    .map_err(|_| AuditDeliveryError::Configuration)?,
                budget,
            )
            .map_err(AuditDeliveryError::pg)?,
            publisher: LocalPublisher {
                fatal: fatal.clone(),
                inbox: PgInboxStore::new(runtime.clone(), lease).map_err(AuditDeliveryError::pg)?,
                tx: PgConsumerTx::receipt_only(
                    runtime,
                    Effect {
                        instance,
                        audit,
                        fatal,
                    },
                ),
                validator: Validator { tenants },
                group: ConsumerGroup::parse("identity.audit.v1")
                    .map_err(|_| AuditDeliveryError::Configuration)?,
            },
        };
        if delivery
            .outbox
            .has_dead_letters(OperationDeadline::from_remaining(budget.settle_timeout()))
            .await
            .map_err(AuditDeliveryError::pg)?
        {
            return Err(AuditDeliveryError::RejectedEvent);
        }
        Ok(delivery)
    }
    /// Process at most `limit` claimed events. A returned report distinguishes published,
    /// retried and fenced deliveries. Isolated events terminate with `RejectedEvent`; none is an authentication result.
    pub async fn run_once(
        &self,
        limit: RelayBatchLimit,
    ) -> Result<RelayReport, AuditDeliveryError> {
        if let Some(error) = self.fatal.get() {
            return Err(*error);
        }
        let result = relay_once(&self.outbox, &self.publisher, &Timer, &Observations, limit).await;
        if let Some(error) = self.fatal.get() {
            return Err(*error);
        }
        let report = result.map_err(|e| AuditDeliveryError::messaging(e.kind()))?;
        if report.dead_lettered() > 0 {
            let _ = self.fatal.set(AuditDeliveryError::RejectedEvent);
            return Err(AuditDeliveryError::RejectedEvent);
        }
        Ok(report)
    }
}
#[cfg(test)]
mod tests;

#[cfg(test)]
mod pg_tests;
