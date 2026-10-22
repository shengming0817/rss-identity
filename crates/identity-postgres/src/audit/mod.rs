//! Identity-owned audit projection. Hosts supply same-database worker resources and own their lifetime.
//! ref: sqlx sqlx-core/src/transaction.rs@v0.9.0 (only the message owner settles).
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
    PgProjectionFailure, PgProjectionOutcome, PgProjectionRecovery, PgRecoveryCapture, PgRuntime,
    PgTransaction,
};
use rss_transactional_messaging_runtime::relay::RelayBatchLimit;
use std::{
    sync::{Arc, OnceLock},
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
            Err(ProjectionError::Audit(e)) => {
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
        Ok(c.verified()) // Projection receives only the domain-bound PG source envelopes.
    }
}
/// Bounded projection progress. Counts only acknowledged or durably resolved commits.
#[derive(Default, Debug)]
pub struct AuditProjectionReport {
    projected: usize,
    deferred: usize,
}
impl AuditProjectionReport {
    pub const fn projected(&self) -> usize {
        self.projected
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
    pending: tokio::sync::Mutex<Option<PgProjectionRecovery>>,
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
            pending: tokio::sync::Mutex::new(None),
            timeout: budget.publish_timeout(),
        })
    }
    fn check_fatal(&self) -> Result<(), AuditDeliveryError> {
        self.fatal.get().copied().map_or(Ok(()), Err)
    }
    fn deadline(&self) -> Result<OperationDeadline, AuditDeliveryError> {
        Ok(OperationDeadline::from_cutoff(
            Deadline::from_timeout(&Timer, self.timeout)
                .map_err(|_| AuditDeliveryError::Configuration)?,
            &Timer,
        ))
    }
    fn committed(&self, disposition: TerminalDisposition) -> Result<(), AuditDeliveryError> {
        if disposition != TerminalDisposition::Succeeded {
            let _ = self.fatal.set(AuditDeliveryError::RejectedEvent);
        }
        self.check_fatal()
    }
    /// Resolve any prior uncertainty first. Only provider leases authorize a fresh effect attempt.
    pub async fn run_once(
        &self,
        limit: RelayBatchLimit,
    ) -> Result<AuditProjectionReport, AuditDeliveryError> {
        self.check_fatal()?;
        let mut pending = self.pending.lock().await;
        let mut report = AuditProjectionReport::default();
        if let Some(identity) = pending.as_ref() {
            if let Some(receipt) = self
                .projection
                .resolve(identity, self.deadline()?)
                .await
                .map_err(AuditDeliveryError::pg)?
            {
                self.committed(receipt.disposition())?;
                report.projected += 1;
            }
            // None is not rollback proof: subsequent processing still requires a new durable claim.
            *pending = None;
        }
        for _ in 0..limit.get().get() {
            let result = self
                .projection
                .project_one(&self.validator, self.deadline()?)
                .await;
            self.check_fatal()?;
            match result.map_err(AuditDeliveryError::pg)? {
                PgProjectionOutcome::Empty => break,
                PgProjectionOutcome::Committed(receipt) => {
                    self.committed(receipt.disposition())?;
                    report.projected += 1;
                }
                PgProjectionOutcome::Uncertain(identity) => {
                    *pending = Some(identity);
                    return Err(AuditDeliveryError::Transient);
                }
                PgProjectionOutcome::Rejected(_)
                | PgProjectionOutcome::Deferred(PgProjectionFailure::DeliveryExpired) => {
                    let _ = self.fatal.set(AuditDeliveryError::RejectedEvent);
                    return Err(AuditDeliveryError::RejectedEvent);
                }
                PgProjectionOutcome::Deferred(PgProjectionFailure::Fenced) => {
                    return Err(AuditDeliveryError::OwnershipLost);
                }
                PgProjectionOutcome::Deferred(_) | PgProjectionOutcome::InProgress => {
                    report.deferred += 1;
                }
            }
        }
        Ok(report)
    }
}
#[cfg(test)]
mod pg_tests;
#[cfg(test)]
mod tests;
