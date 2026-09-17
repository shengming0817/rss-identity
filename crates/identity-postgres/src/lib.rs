//! Embeddable account/session services over a host-owned PostgreSQL runtime.
mod attempts;
mod auth_facts;
mod credentials;
mod federation;
mod federation_link;
mod federation_login;
mod federation_storage;
mod maintenance;
mod management;
mod operations;
mod runtime;
mod schema;
mod session_storage;
mod sessions;
mod storage;
mod transaction;
mod types;
pub use credentials::CredentialKeys;
pub use federation::{
    FederatedOutcome, FederatedRedirect, Federation, FederationConfig, LinkRequest, LinkResult,
    LoginOption, LoginRequest, SessionSecurity,
};
pub use management::{
    ManagementContext, ManagementDenied, ManagementOperation, ManagementPolicy,
    ReauthenticationRequirement,
};
pub use operations::{AccountPage, AccountView};
use rss_identity_core::{
    InstanceId,
    account::{AccountChange, AccountKey, AccountState},
    session::SessionPolicy,
};
use rss_request_context::TenantId;
use rss_transactional_messaging::policy::{DeliveryBudget, OperationDeadline};
use rss_transactional_messaging_postgres::PgRuntime;
pub use schema::{
    MIGRATION_SQL, SCHEMA_SIGNATURE, SCHEMA_SIGNATURE_SQL, SCHEMA_VERSION, grant_profile, install,
};
pub use sessions::{
    AuthenticatedSession, IssuedSession, SessionIdentity, SessionPage, SessionView, TrustedGroups,
    VerifiedGroups,
};
use std::sync::Arc;
pub use types::*;

/// Instance and admission are explicit; URLs and upstream credentials belong to adapters.
#[derive(Clone)]
pub struct AuthorityConfig {
    instance: InstanceId,
    tenants: Vec<TenantId>,
    sessions: SessionPolicy,
    events: DeliveryBudget,
}
impl AuthorityConfig {
    pub fn new(
        instance: InstanceId,
        mut tenants: Vec<TenantId>,
        sessions: SessionPolicy,
        events: DeliveryBudget,
    ) -> Result<Self, AuthorityError> {
        tenants.sort_by_key(|tenant| tenant.to_string());
        if tenants.is_empty()
            || tenants.len() > 128
            || tenants.windows(2).any(|pair| pair[0] == pair[1])
        {
            return Err(AuthorityError::Invalid);
        }
        Ok(Self {
            instance,
            tenants,
            sessions,
            events,
        })
    }
}
#[derive(Clone)]
pub struct Authority {
    kdf: Arc<rss_identity_core::account::PasswordKdf>,
    runtimes: Arc<runtime::RuntimeState>,
    profile: AuthorityProfile,
    instance: InstanceId,
    session_policy: SessionPolicy,
    policy: Arc<dyn ManagementPolicy>,
}
impl Authority {
    pub async fn connect_runtime(
        runtime: Arc<PgRuntime>,
        kdf: Arc<rss_identity_core::account::PasswordKdf>,
        config: AuthorityConfig,
        policy: Arc<dyn ManagementPolicy>,
        deadline: OperationDeadline,
    ) -> Result<Self, AuthorityError> {
        Self::connect(
            runtime,
            kdf,
            config,
            AuthorityProfile::Runtime,
            policy,
            deadline,
        )
        .await
    }
    pub async fn connect_maintenance(
        runtime: Arc<PgRuntime>,
        kdf: Arc<rss_identity_core::account::PasswordKdf>,
        config: AuthorityConfig,
        deadline: OperationDeadline,
    ) -> Result<Self, AuthorityError> {
        Self::connect(
            runtime,
            kdf,
            config,
            AuthorityProfile::Maintenance,
            Arc::new(management::DenyManagement),
            deadline,
        )
        .await
    }
    async fn connect(
        runtime: Arc<PgRuntime>,
        kdf: Arc<rss_identity_core::account::PasswordKdf>,
        config: AuthorityConfig,
        profile: AuthorityProfile,
        policy: Arc<dyn ManagementPolicy>,
        deadline: OperationDeadline,
    ) -> Result<Self, AuthorityError> {
        let budget = Budget::new(deadline)?;
        let tenant = config.tenants[0];
        let instance = config.instance;
        let authority = Self {
            kdf,
            runtimes: Arc::new(runtime::RuntimeState::new(
                runtime,
                config.events,
                config.tenants,
                instance,
            )?),
            profile,
            instance,
            session_policy: config.sessions,
            policy,
        };
        let valid = Self::read_bundle(
            authority.runtimes.snapshot()?,
            tenant,
            budget.remaining(),
            false,
            move |tx| {
                Box::pin(async move {
                    transaction::connection(tx, move |c| {
                        Box::pin(schema::probe(c, profile, instance))
                    })
                    .await
                })
            },
        )
        .await;
        check_probe(valid)?;
        let bundle = authority.runtimes.snapshot()?;
        // Schema/profile are global, but every declared tenant has its own runtime fence.
        for tenant in bundle.tenants.iter().skip(1) {
            Self::read_bundle(bundle.clone(), *tenant, budget.remaining(), true, |_| {
                Box::pin(async { Ok(()) })
            })
            .await?;
        }
        Ok(authority)
    }
    pub fn instance(&self) -> InstanceId {
        self.instance
    }
    pub fn active_tenants(&self) -> Result<Vec<TenantId>, AuthorityError> {
        Ok(self.runtimes.snapshot()?.tenants.clone())
    }
    pub fn tenant_active(&self, tenant: TenantId) -> bool {
        self.runtimes
            .snapshot()
            .is_ok_and(|r| r.tenants.contains(&tenant))
    }
    fn require_maintenance(&self) -> Result<(), AuthorityError> {
        if self.profile != AuthorityProfile::Maintenance {
            return Err(AuthorityError::Rejected);
        }
        Ok(())
    }
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

#[cfg(test)]
extern crate self as rss_identity_postgres;
#[cfg(test)]
#[path = "tests/atomic.rs"]
mod account_atomic;
#[cfg(test)]
#[path = "tests/federated_atomic.rs"]
mod federated_atomic;
#[cfg(test)]
#[path = "../tests/federation_support/mod.rs"]
mod federation_support;
#[cfg(test)]
#[path = "tests/session_atomic.rs"]
mod session_atomic;
#[cfg(test)]
#[path = "../tests/support/mod.rs"]
mod support;
#[cfg(test)]
impl support::Fixture {
    async fn candidate(&self) -> anyhow::Result<AuthenticationCandidate> {
        Ok(self
            .store
            .verify_password(
                self.key.tenant,
                support::login("admin"),
                support::password(),
                support::source(),
                support::deadline(),
            )
            .await?)
    }
}

#[cfg(test)]
async fn session_actor(
    store: &Authority,
    candidate: AuthenticationCandidate,
) -> anyhow::Result<AuthenticatedSession> {
    let tenant = candidate.account().tenant;
    let issued = store
        .create_session(candidate, None, support::deadline())
        .await?;
    Ok(store
        .inspect_session(
            tenant,
            rss_identity_core::session::SessionSecret::parse(issued.secret().expose().into())?,
            support::deadline(),
        )
        .await?)
}
