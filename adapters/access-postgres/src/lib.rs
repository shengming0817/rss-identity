//! Tenant-local account authority. SQL and event envelopes are private implementation details.
mod attempts;
mod authorizations;
mod operations;
mod storage;
mod transaction;
mod types;
pub use types::*;
pub const MIGRATION_SQL: &str = include_str!("../migrations/0001_authority.sql");
use access_core::account::{AccountChange, AccountKey, AccountState};
use rss_transactional_messaging::message::MessagingDomain;
use rss_transactional_messaging::policy::DeliveryBudget;
use rss_transactional_messaging_postgres::{PgOutboxStore, PgRuntime};
use std::sync::Arc;

#[derive(Clone)]
pub struct Authority {
    runtime: Arc<PgRuntime>,
    profile: AuthorityProfile,
    outbox: Arc<PgOutboxStore<()>>,
}
impl Authority {
    /// Validate the Access schema and effective role before exposing an authority.
    pub async fn connect(
        runtime: Arc<PgRuntime>,
        budget: DeliveryBudget,
        tenant: rss_request_context::TenantId,
        profile: AuthorityProfile,
        deadline: rss_transactional_messaging::policy::OperationDeadline,
    ) -> Result<Self, AuthorityError> {
        let domain =
            MessagingDomain::parse("access.security").map_err(|_| AuthorityError::Unavailable)?;
        let outbox = PgOutboxStore::new(runtime.clone(), domain, budget)
            .map_err(|_| AuthorityError::Unavailable)?;
        let authority = Self {
            runtime,
            profile,
            outbox: Arc::new(outbox),
        };
        let label = match profile {
            AuthorityProfile::Runtime => "runtime",
            AuthorityProfile::Issuer => "issuer",
        };
        let valid = authority
            .read(tenant, deadline, move |tx| {
                Box::pin(async move {
                    tx.with_connection(move |c| {
                        Box::pin(async move {
                            sqlx::query_scalar::<_, Option<bool>>(include_str!("probe.sql"))
                                .bind(label)
                                .fetch_one(c)
                                .await
                        })
                    })
                    .await
                })
            })
            .await;
        check_probe(valid)?;
        Ok(authority)
    }

    fn require_runtime(&self) -> Result<(), AuthorityError> {
        if self.profile != AuthorityProfile::Runtime {
            return Err(AuthorityError::Rejected);
        }
        Ok(())
    }
}

fn check_probe(result: Result<Option<bool>, AuthorityError>) -> Result<(), AuthorityError> {
    match result {
        Ok(Some(true)) => Ok(()),
        Ok(_) => Err(AuthorityError::StorageIncompatible),
        Err(error) => Err(error),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn probe_preserves_settlement_and_retry_class() {
        for reason in [
            StorageFailure::Transient,
            StorageFailure::DeadlineElapsed,
            StorageFailure::Permanent,
            StorageFailure::Invariant,
        ] {
            for error in [
                AuthorityError::NotStarted(reason),
                AuthorityError::RolledBack(reason),
                AuthorityError::RollbackFailed(reason),
                AuthorityError::CommitUnknown(reason),
            ] {
                assert_eq!(check_probe(Err(error)), Err(error));
            }
        }
        assert_eq!(
            check_probe(Err(AuthorityError::Fenced)),
            Err(AuthorityError::Fenced)
        );
        assert_eq!(
            check_probe(Ok(Some(false))),
            Err(AuthorityError::StorageIncompatible)
        );
        assert_eq!(
            check_probe(Ok(None)),
            Err(AuthorityError::StorageIncompatible)
        );
        assert_eq!(check_probe(Ok(Some(true))), Ok(()));
    }
}
