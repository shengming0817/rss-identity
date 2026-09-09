//! Tenant-local account authority. SQL and event envelopes are private implementation details.
mod attempts;
mod downstream;
mod downstream_cleanup;
mod downstream_storage;
pub use downstream::{Downstream, FlowHandle, PrepareAdmission, ValidatedIdentity};
mod federation;
mod federation_link;
mod federation_login;
mod federation_storage;
pub use federation::{
    FederatedOutcome, FederatedRedirect, Federation, LinkRequest, LinkResult, LoginRequest,
};
mod maintenance;
mod operations;
pub use operations::{AccountPage, AccountView, LocalAccountRole};
mod session_storage;
mod sessions;
mod storage;
mod transaction;
mod types;
pub use sessions::{
    AuthenticatedSession, IssuedSession, SessionIdentity, SessionPage, SessionView,
};
pub use types::*;
pub const MIGRATION_SQL: &str = include_str!("../migrations/0001_authority.sql");
use rss_identity_core::account::{AccountChange, AccountKey, AccountState};
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
    /// Validate the Identity schema and effective role before exposing an authority.
    pub async fn connect(
        runtime: Arc<PgRuntime>,
        budget: DeliveryBudget,
        tenant: rss_request_context::TenantId,
        profile: AuthorityProfile,
        deadline: rss_transactional_messaging::policy::OperationDeadline,
    ) -> Result<Self, AuthorityError> {
        let domain =
            MessagingDomain::parse("identity.security").map_err(|_| AuthorityError::Unavailable)?;
        let outbox = PgOutboxStore::new(runtime.clone(), domain, budget)
            .map_err(|_| AuthorityError::Unavailable)?;
        let authority = Self {
            runtime,
            profile,
            outbox: Arc::new(outbox),
        };
        let label = match profile {
            AuthorityProfile::Runtime => "runtime",
            AuthorityProfile::Maintenance => "maintenance",
        };
        let valid = authority
            .read(tenant, deadline, move |tx| {
                Box::pin(async move {
                    tx.with_connection(move |c| {
                        Box::pin(async move {
                            // The version table must be resolvable before PostgreSQL can plan
                            // the contract query. Missing objects elsewhere use nullable OIDs.
                            let inventory: String = sqlx::query_scalar(
                                "SELECT CASE WHEN a.attnum IS NULL THEN 'schema-contract'
                                 WHEN has_schema_privilege(current_user,n.oid,'USAGE') IS NOT TRUE
                                   OR has_table_privilege(current_user,t.oid,'SELECT') IS NOT TRUE THEN 'privileges'
                                 ELSE 'ok' END
                                 FROM (VALUES (1)) AS required(dummy)
                                 LEFT JOIN pg_namespace n ON n.nspname='identity_authority'
                                 LEFT JOIN pg_class t ON t.relnamespace=n.oid AND t.relname='schema_version' AND t.relkind='r'
                                 LEFT JOIN pg_attribute a ON a.attrelid=t.oid AND a.attname='version' AND a.atttypid='int4'::regtype AND a.attnum>0 AND NOT a.attisdropped",
                            ).fetch_one(&mut *c).await?;
                            if inventory != "ok" {
                                return Ok(Some(inventory));
                            }
                            let versions:Vec<i32>=sqlx::query_scalar("SELECT version FROM identity_authority.schema_version").fetch_all(&mut *c).await?;
                            if versions != [5] {return Ok(Some("schema-version".into()));}
                            let signature:String=sqlx::query_scalar(include_str!("schema-signature.sql")).fetch_one(&mut *c).await?;
                            if signature != include_str!("schema-signature.sha256").trim() { return Ok(Some("schema-contract".into())); }
                            sqlx::query_scalar::<_, Option<String>>(include_str!("probe.sql"))
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

    fn require_maintenance(&self) -> Result<(), AuthorityError> {
        if self.profile != AuthorityProfile::Maintenance {
            return Err(AuthorityError::Rejected);
        }
        Ok(())
    }

    /// Reject maintenance-only authority when composing a runtime adapter.
    pub fn require_runtime(&self) -> Result<(), AuthorityError> {
        if self.profile != AuthorityProfile::Runtime {
            return Err(AuthorityError::Rejected);
        }
        Ok(())
    }
}

fn check_probe(result: Result<Option<String>, AuthorityError>) -> Result<(), AuthorityError> {
    let reason = match result?.as_deref() {
        Some("ok") => return Ok(()),
        Some("schema-version") => StorageMismatch::SchemaVersion,
        Some("role") => StorageMismatch::Role,
        Some("privileges") => StorageMismatch::Privileges,
        _ => StorageMismatch::SchemaContract,
    };
    Err(AuthorityError::StorageIncompatible(reason))
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
        for (code, reason) in [
            ("schema-version", StorageMismatch::SchemaVersion),
            ("role", StorageMismatch::Role),
            ("privileges", StorageMismatch::Privileges),
            ("schema-contract", StorageMismatch::SchemaContract),
            (
                "private unexpected provider value",
                StorageMismatch::SchemaContract,
            ),
        ] {
            let error = check_probe(Ok(Some(code.into()))).unwrap_err();
            assert_eq!(error, AuthorityError::StorageIncompatible(reason));
            assert!(!error.to_string().contains("private unexpected"));
        }
        assert_eq!(
            check_probe(Ok(None)),
            Err(AuthorityError::StorageIncompatible(
                StorageMismatch::SchemaContract
            ))
        );
        assert_eq!(check_probe(Ok(Some("ok".into()))), Ok(()));
    }
}
