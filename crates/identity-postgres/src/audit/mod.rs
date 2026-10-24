//! Identity-owned audit projection. Hosts supply same-database worker resources and own their lifetime.
//! ref: sqlx sqlx-core/src/transaction.rs@v0.9.0 (only the message owner settles).
mod diagnostics;
mod error;
mod profile;
pub use error::AuditDeliveryError;
pub use profile::{grant_worker, verify_worker};
mod mapping;
use mapping::{accepted_contract, map_event, record_identity};
use rss_audit_postgres::PgAudit;
use rss_data_protection::Aead;
use rss_identity_core::InstanceId;
use rss_request_context::{Clock, Deadline, TenantId};
use rss_transactional_messaging::{
    inbox::ConsumerGroup,
    message::{MessageEnvelope, MessagingDomain},
    policy::{DeliveryBudget, LeaseRenewalPolicy, OperationDeadline},
    transaction::{
        EnvelopeValidationFailure, IngressChallenge, IngressValidator, RejectKind,
        TerminalDisposition, VerifiedIngress,
    },
};
use rss_transactional_messaging_postgres::{
    OutboxWakeup, PgConsumerEffect, PgConsumerEffectFailure, PgLocalProjection,
    PgProjectionAttempt, PgProjectionOutcome, PgProjectionRecovery, PgRecoveryCapture, PgRuntime,
    PgTransaction,
};
use std::{
    num::NonZeroUsize,
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};

/// Database-local, opaque wakeup channel for one authoritative Identity instance and tenant.
/// The channel is `id_audit_` followed by the first 48 lowercase hex characters of SHA-256
/// over the instance UUID bytes followed by the tenant UUID bytes (57 ASCII bytes total).
/// Identity transactions send an empty payload. Notifications may be lost or forged;
/// hosts must retain durable scans and obtain delivery authority from the worker runtime.
#[must_use]
pub fn notification_channel(instance: InstanceId, tenant: TenantId) -> String {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(instance.as_uuid().as_bytes());
    hash.update(tenant.octets());
    let digest = format!("{:x}", hash.finalize());
    format!("id_audit_{}", &digest[..48])
}

struct Timer;
impl Clock for Timer {
    fn now(&self) -> Instant {
        Instant::now()
    }
}
#[cfg(test)]
impl rss_request_context::ExecutionTimer for Timer {
    async fn sleep_until(&self, d: Deadline) {
        tokio::time::sleep(d.remaining(self.now()).unwrap_or_default()).await;
    }
}
enum ProjectionError {
    Invalid,
    Audit(rss_audit_postgres::Error),
}
impl From<rss_audit_postgres::Error> for ProjectionError {
    fn from(error: rss_audit_postgres::Error) -> Self {
        Self::Audit(error)
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
        let identity = match record_identity(self.instance, message) {
            Ok(identity) => identity,
            Err(_) => return Ok(TerminalDisposition::Rejected(RejectKind::Permanent)),
        };
        let result = self
            .audit
            .append_with_in(tx, &identity, |previous, now| {
                let recorded = match previous {
                    Some(record) => {
                        rss_audit_core::decode_untrusted(record.prepared().canonical_bytes())
                            .map_err(|e| ProjectionError::Audit(e.into()))?
                            .recorded_at()
                    }
                    None => now,
                };
                let event = map_event(self.instance, message, recorded)
                    .map_err(|_| ProjectionError::Invalid)?;
                rss_audit_core::prepare(event, recorded)
                    .map_err(|e| ProjectionError::Audit(e.into()))
            })
            .await;
        match result {
            Err(ProjectionError::Invalid) => {
                Ok(TerminalDisposition::Rejected(RejectKind::Permanent))
            }
            Ok(_) => Ok(TerminalDisposition::Succeeded),
            Err(ProjectionError::Audit(
                rss_audit_postgres::Error::Conflict
                | rss_audit_postgres::Error::ScopeMismatch
                | rss_audit_postgres::Error::Protocol(_),
            )) => Ok(TerminalDisposition::Rejected(RejectKind::Invariant)),
            Err(ProjectionError::Audit(e)) => Err(infrastructure_failure(&self.fatal, e)),
        }
    }
}
fn infrastructure_failure(
    fatal: &OnceLock<AuditDeliveryError>,
    error: rss_audit_postgres::Error,
) -> PgConsumerEffectFailure {
    let error = rss_transactional_messaging_postgres::PgError::from(error);
    let class = AuditDeliveryError::messaging(error.kind());
    if !class.is_retryable() {
        let _ = fatal.set(class);
    }
    PgConsumerEffectFailure::infrastructure(error)
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
        Ok(c.verified()) // Projection receives only the domain-bound PG source envelopes.
    }
}
/// Bounded projection progress. Counts only acknowledged or durably resolved commits.
#[derive(Default, Debug)]
pub struct AuditProjectionReport {
    projected: usize,
    deferred: usize,
    last_deferral: Option<&'static str>,
}
impl AuditProjectionReport {
    fn deferral(class: rss_transactional_messaging::transaction::FailureClass) -> Self {
        use rss_transactional_messaging::transaction::FailureClass;
        Self {
            projected: 0,
            deferred: 1,
            last_deferral: Some(match class {
                FailureClass::Permanent => "permanent",
                FailureClass::Transient => "transient",
                FailureClass::Infrastructure => "infrastructure",
            }),
        }
    }
    pub const fn projected(&self) -> usize {
        self.projected
    }
    pub const fn last_deferral(&self) -> Option<&'static str> {
        self.last_deferral
    }
    pub const fn deferred(&self) -> usize {
        self.deferred
    }
}
/// Caller-driven same-database projection. The host owns pools, protection keys and lifetime.
pub struct AuditDelivery<K> {
    projection: PgLocalProjection<Effect, K>,
    validator: Validator,
    fatal: Arc<OnceLock<AuditDeliveryError>>,
    pending: Mutex<Vec<Arc<PgProjectionRecovery>>>,
    timeout: Duration,
}
impl<K: Aead + Send + Sync> AuditDelivery<K> {
    pub async fn next_wakeup(
        &self,
        deadline: OperationDeadline,
    ) -> Result<OutboxWakeup, AuditDeliveryError> {
        self.check_fatal()?;
        self.projection
            .next_wakeup(deadline)
            .await
            .map_err(AuditDeliveryError::pg)
    }
    /// Bind a dedicated consumer runtime and host-supplied recovery protector to the existing group.
    /// The protector must remain available across restarts and joint database restoration.
    pub async fn new(
        runtime: Arc<PgRuntime>,
        audit: Arc<PgAudit>,
        instance: InstanceId,
        tenants: Vec<TenantId>,
        budget: DeliveryBudget,
        protector: Arc<K>,
    ) -> Result<Self, AuditDeliveryError> {
        if tenants.is_empty() || tenants.len() > 128 {
            return Err(AuditDeliveryError::Configuration);
        }
        let startup = Deadline::from_timeout(&Timer, budget.settle_timeout())
            .map_err(|_| AuditDeliveryError::Configuration)?;
        let validator = audit.clone();
        runtime
            .local_tx(
                tenants[0],
                OperationDeadline::from_cutoff(startup, &Timer),
                move |tx| {
                    Box::pin(async move { validator.validate_in(tx).await.map_err(Into::into) })
                },
            )
            .await
            .fold(Ok, Err, Err, Err, Err, Err)
            .map_err(AuditDeliveryError::pg)?;
        let renewal = LeaseRenewalPolicy::from_ttl(budget.lease_ttl())
            .map_err(|_| AuditDeliveryError::Configuration)?;
        let capture = PgRecoveryCapture::new(
            runtime,
            protector,
            OperationDeadline::from_cutoff(startup, &Timer),
        )
        .await
        .map_err(AuditDeliveryError::recovery)?;
        let fatal = Arc::new(OnceLock::new());
        let projection = PgLocalProjection::new(
            capture,
            ConsumerGroup::parse("identity.audit.v1")
                .map_err(|_| AuditDeliveryError::Configuration)?,
            MessagingDomain::parse("identity.security")
                .map_err(|_| AuditDeliveryError::Configuration)?,
            Effect {
                instance,
                audit,
                fatal: fatal.clone(),
            },
            budget,
            renewal,
            OperationDeadline::from_cutoff(startup, &Timer),
        )
        .await
        .map_err(AuditDeliveryError::pg)?;
        if projection
            .has_dead_letters(OperationDeadline::from_cutoff(startup, &Timer))
            .await
            .map_err(AuditDeliveryError::pg)?
        {
            return Err(AuditDeliveryError::RejectedEvent);
        }
        Ok(Self {
            projection,
            validator: Validator { tenants },
            fatal,
            pending: Mutex::new(Vec::new()),
            timeout: budget.publish_timeout(),
        })
    }
    fn check_fatal(&self) -> Result<(), AuditDeliveryError> {
        self.fatal.get().copied().map_or(Ok(()), Err)
    }
    fn committed(&self, disposition: TerminalDisposition) -> Result<(), AuditDeliveryError> {
        if disposition != TerminalDisposition::Succeeded {
            let _ = self.fatal.set(AuditDeliveryError::RejectedEvent);
        }
        self.check_fatal()
    }
    fn consume_attempt(
        &self,
        attempt: PgProjectionAttempt,
        report: &mut AuditProjectionReport,
    ) -> Result<(), AuditDeliveryError> {
        use rss_transactional_messaging::observability::TransactionalMessagingTransactionStatus as Status;
        let (outcome, identity) = attempt.into_parts();
        diagnostics::record(
            diagnostics::Event::Transaction(outcome.status()),
            std::io::stderr().lock(),
        );
        if matches!(
            outcome.status(),
            Status::RollbackFailed | Status::CommitUnknown
        ) {
            self.pending
                .lock()
                .map_err(|_| AuditDeliveryError::Invariant)?
                .push(Arc::new(identity));
        }
        let progress = outcome.fold(
            |committed| {
                self.committed(committed.into_parts().1.disposition())?;
                Ok(AuditProjectionReport {
                    projected: 1,
                    ..Default::default()
                })
            },
            |class| Ok(AuditProjectionReport::deferral(class)),
            |class| Ok(AuditProjectionReport::deferral(class)),
            || Err(AuditDeliveryError::Transient),
            || Err(AuditDeliveryError::Transient),
            || Err(AuditDeliveryError::OwnershipLost),
        )?;
        report.projected += progress.projected;
        report.deferred += progress.deferred;
        if progress.last_deferral.is_some() {
            report.last_deferral = progress.last_deferral;
        }
        Ok(())
    }
    async fn resolve_pending(
        &self,
        report: &mut AuditProjectionReport,
    ) -> Result<(), AuditDeliveryError> {
        let snapshot = self
            .pending
            .lock()
            .map_err(|_| AuditDeliveryError::Invariant)?
            .clone();
        let mut failure = None;
        for identity in snapshot {
            let result = self
                .projection
                .resolve(&identity, OperationDeadline::from_remaining(self.timeout))
                .await;
            let event = match &result {
                Ok(Some(_)) => diagnostics::Event::ResolutionConfirmed,
                Ok(None) => diagnostics::Event::ResolutionUnresolved,
                Err(_) => diagnostics::Event::ResolutionFailed,
            };
            diagnostics::record(event, std::io::stderr().lock());
            let result = match result {
                Err(error) => Err(AuditDeliveryError::pg(error)),
                Ok(receipt) => {
                    let removed = {
                        let mut pending = self
                            .pending
                            .lock()
                            .map_err(|_| AuditDeliveryError::Invariant)?;
                        pending
                            .iter()
                            .position(|entry| Arc::ptr_eq(entry, &identity))
                            .map(|index| pending.swap_remove(index))
                            .is_some()
                    };
                    // None is not rollback proof. Only a new durable claim authorizes another effect.
                    if let Some(receipt) = receipt.filter(|_| removed) {
                        self.committed(receipt.disposition())
                            .map(|()| report.projected += 1)
                    } else {
                        Ok(())
                    }
                }
            };
            if let Err(error) = result
                && failure.is_none_or(|previous: AuditDeliveryError| previous.is_retryable())
            {
                failure = Some(error);
            }
        }
        failure.map_or(Ok(()), Err)
    }
    /// Resolve prior uncertain outcomes, then claim one batch with independent event budgets.
    /// The host may call concurrently; only the short pending-identity updates are locked.
    pub async fn run_once(
        &self,
        limit: NonZeroUsize,
    ) -> Result<AuditProjectionReport, AuditDeliveryError> {
        self.check_fatal()?;
        let mut report = AuditProjectionReport::default();
        self.resolve_pending(&mut report).await?;
        let batch = self
            .projection
            .project_batch(
                &self.validator,
                limit,
                OperationDeadline::from_remaining(self.timeout),
                self.timeout,
            )
            .await
            .map_err(|error| {
                self.fatal
                    .get()
                    .copied()
                    .unwrap_or_else(|| AuditDeliveryError::pg(error))
            })?;
        let mut failure = None;
        for item in batch {
            let result = match item.into_outcome() {
                Ok(PgProjectionOutcome::Attempt(attempt)) => {
                    self.consume_attempt(*attempt, &mut report)
                }
                Ok(PgProjectionOutcome::Rejected(_) | PgProjectionOutcome::DeliveryExpired) => {
                    let _ = self.fatal.set(AuditDeliveryError::RejectedEvent);
                    Err(AuditDeliveryError::RejectedEvent)
                }
                Ok(PgProjectionOutcome::InProgress) => {
                    report.deferred += 1;
                    report.last_deferral = Some("in_progress");
                    Ok(())
                }
                Err(error) => Err(AuditDeliveryError::pg(error)),
            };
            if let Err(error) = result
                && failure.is_none_or(|previous: AuditDeliveryError| previous.is_retryable())
            {
                failure = Some(error);
            }
        }
        self.check_fatal()?;
        failure.map_or(Ok(report), Err)
    }
}
#[cfg(test)]
mod pg_tests;
#[cfg(test)]
mod tests;
