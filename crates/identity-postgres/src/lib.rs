//! Tenant-local account authority. SQL and event envelopes are private implementation details.
mod deployment;
pub use deployment::DeploymentIdentity;
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
mod cli_login;
mod credentials;
mod maintenance;
mod platform;
pub use credentials::CredentialKeys;
pub use platform::{
    NewTenantAdministrator, PlatformOperation, PlatformOperationKind, TenantPage, TenantView,
};
mod operations;
pub use operations::{AccountListEntry, AccountPage, AccountView, LocalAccountRole};
mod runtime;
mod session_storage;
mod sessions;
mod storage;
mod transaction;
pub use runtime::RuntimeSource;
mod types;
pub use sessions::{
    AuthenticatedSession, IssuedSession, SessionIdentity, SessionPage, SessionView,
};
pub use types::*;
pub const SCHEMA_VERSION: i32 = 8;
pub const SCHEMA_SIGNATURE_SQL: &str = include_str!("schema-signature.sql");
pub const SCHEMA_SIGNATURE: &str = include_str!("schema-signature.sha256");
pub const MIGRATION_SQL: &str = include_str!("../migrations/0001_authority.sql");
use rss_identity_core::account::{AccountChange, AccountKey, AccountState};
use rss_transactional_messaging::policy::DeliveryBudget;
use rss_transactional_messaging_postgres::PgRuntime;
use std::sync::Arc;

/// All runtime dependencies are established before a usable authority can exist.
pub struct RuntimeConfiguration {
    source: RuntimeSource,
    credential_keys: Arc<CredentialKeys>,
}
impl RuntimeConfiguration {
    pub fn new(source: RuntimeSource, credential_keys: Arc<CredentialKeys>) -> Self {
        Self {
            source,
            credential_keys,
        }
    }
}
#[derive(Clone)]
enum AuthorityMode {
    Runtime(Arc<RuntimeConfiguration>),
    Maintenance,
}
#[derive(Clone)]
pub struct Authority {
    kdf: Arc<rss_identity_core::account::PasswordKdf>,
    runtimes: Arc<runtime::RuntimeState>,
    mode: AuthorityMode,
    system_domain: rss_request_context::TenantId,
    identity_origin: String,
}
impl Authority {
    /// Construct a runtime authority with its immutable external source and keyring.
    pub async fn connect_runtime(
        runtime: Arc<PgRuntime>,
        kdf: Arc<rss_identity_core::account::PasswordKdf>,
        deployment: DeploymentIdentity,
        budget: DeliveryBudget,
        system: rss_request_context::TenantId,
        configuration: RuntimeConfiguration,
        deadline: rss_transactional_messaging::policy::OperationDeadline,
    ) -> Result<Self, AuthorityError> {
        Self::connect(
            runtime,
            kdf,
            deployment,
            budget,
            system,
            AuthorityMode::Runtime(Arc::new(configuration)),
            deadline,
        )
        .await
    }
    /// Maintenance has no tenant-admission or IdP credential configuration.
    pub async fn connect_maintenance(
        runtime: Arc<PgRuntime>,
        kdf: Arc<rss_identity_core::account::PasswordKdf>,
        deployment: DeploymentIdentity,
        budget: DeliveryBudget,
        system: rss_request_context::TenantId,
        deadline: rss_transactional_messaging::policy::OperationDeadline,
    ) -> Result<Self, AuthorityError> {
        Self::connect(
            runtime,
            kdf,
            deployment,
            budget,
            system,
            AuthorityMode::Maintenance,
            deadline,
        )
        .await
    }
    fn runtime_configuration(&self) -> Result<&RuntimeConfiguration, AuthorityError> {
        match &self.mode {
            AuthorityMode::Runtime(c) => Ok(c),
            AuthorityMode::Maintenance => Err(AuthorityError::Rejected),
        }
    }
    /// Validate the Identity schema and effective role before exposing an authority.
    async fn connect(
        runtime: Arc<PgRuntime>,
        kdf: Arc<rss_identity_core::account::PasswordKdf>,
        deployment: DeploymentIdentity,
        budget: DeliveryBudget,
        tenant: rss_request_context::TenantId,
        mode: AuthorityMode,
        deadline: rss_transactional_messaging::policy::OperationDeadline,
    ) -> Result<Self, AuthorityError> {
        let authority = Self {
            kdf,
            runtimes: Arc::new(runtime::RuntimeState::new(runtime, budget, tenant)?),
            mode,
            system_domain: tenant,
            identity_origin: deployment.identity_origin().to_owned(),
        };
        let label = match &authority.mode {
            AuthorityMode::Runtime(_) => "runtime",
            AuthorityMode::Maintenance => "maintenance",
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
                            if versions != [SCHEMA_VERSION] {return Ok(Some("schema-version".into()));}
                            let signature:String=sqlx::query_scalar(include_str!("schema-signature.sql")).fetch_one(&mut *c).await?;
                            if signature != include_str!("schema-signature.sha256").trim() { return Ok(Some("schema-contract".into())); }
                            let identity_matches: bool = sqlx::query_scalar("SELECT count(*)=1 AND coalesce(bool_and(environment_id=$1 AND identity_config_version=$2 AND identity_public_origin=$3 AND product_public_origin=$4 AND (system_domain IS NULL OR system_domain=$5::uuid)),false) FROM identity_authority.deployment")
                                .bind(deployment.environment_id).bind(deployment.config_version).bind(deployment.identity_public_origin).bind(deployment.product_public_origin).bind(tenant.to_string()).fetch_one(&mut *c).await?;
                            if !identity_matches { return Ok(Some("deployment-identity".into())); }
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
        if !matches!(self.mode, AuthorityMode::Maintenance) {
            return Err(AuthorityError::Rejected);
        }
        Ok(())
    }

    /// Reject maintenance-only authority when composing a runtime adapter.
    pub fn require_runtime(&self) -> Result<(), AuthorityError> {
        if !matches!(self.mode, AuthorityMode::Runtime(_)) {
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
        Some("deployment-identity") => StorageMismatch::DeploymentIdentity,
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
