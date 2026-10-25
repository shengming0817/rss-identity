//! Embeddable account/session services over a host-owned PostgreSQL runtime.
mod attempts;
mod password_attempts;
pub use password_attempts::{PASSWORD_FAILURE_LIMIT, PASSWORD_FAILURE_SECONDS};
mod audit;
mod auth_facts;
mod credentials;
mod department;
mod entra;
pub use entra::{EntraAuthority, RevalidatedAccount, VerifiedExternalSubject};
mod session_checks;
#[cfg(feature = "test-support")]
pub use session_checks::ControlledFactTime;
mod federation;
mod federation_link;
mod federation_login;
mod federation_storage;
mod groups;
mod maintenance;
mod management;
mod operations;
mod personnel;
pub mod platform;
mod profiles;
pub use personnel::{PersonnelProfileScope, PersonnelRead, PersonnelRevision};
pub use profiles::{
    LocalProfileView, ProfileChange, ProfileReceipt, ProfileSource, ProfileSourcePage,
    ProfileSourceView, ProfileStatus, ProfileView, TrustedProfile,
};
mod runtime;
mod schema;
mod session_reference;
mod session_storage;
mod sessions;
mod storage;
mod transaction;
mod types;
pub use attempts::{
    ATTEMPT_SCOPE_LIMIT, ATTEMPT_SCOPE_SECONDS, ATTEMPT_SOURCE_LIMIT, ATTEMPT_SOURCE_SECONDS,
};
pub use credentials::CredentialKeys;
pub use department::{
    DepartmentAccessError, TrustedDepartmentSnapshot, VerifiedDepartmentSnapshot,
};
pub use federation::{
    FederatedOutcome, FederatedRedirect, Federation, FederationConfig, LinkRequest, LinkResult,
    LoginOption, LoginRequest, SessionSecurity,
};
pub use groups::{GroupAccessError, TrustedGroups, VerifiedGroups};
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
use rss_transactional_messaging::policy::OperationDeadline;
use rss_transactional_messaging_postgres::PgRuntime;
pub use schema::{
    MIGRATION_SQL, SCHEMA_SIGNATURE, SCHEMA_SIGNATURE_SQL, SCHEMA_VERSION,
    grant_platform_subject_admission, grant_profile, grant_profile_source_admission, install,
    verify_platform_subject_admission, verify_profile, verify_profile_source_admission,
};
pub use session_reference::{RevalidatedSession, SessionReference};
pub use sessions::{
    AuthenticatedSession, IssuedSession, SessionIdentity, SessionPage, SessionView,
    recheck_authenticated_session_on,
};
use std::sync::Arc;
pub use types::*;

/// Instance and admission are explicit; URLs and upstream credentials belong to adapters.
#[derive(Clone)]
pub struct AuthorityConfig {
    instance: InstanceId,
    tenants: Vec<TenantId>,
    sessions: SessionPolicy,
    audit: rss_audit_postgres::Integrity,
    platform: Option<Arc<dyn platform::PlatformVerifier>>,
    enterprise: Option<platform::EnterpriseConfig>,
    profile_limits: rss_identity_core::profile::ProfileLimits,
}
impl AuthorityConfig {
    pub fn with_enterprise(mut self, config: platform::EnterpriseConfig) -> Self {
        self.enterprise = Some(config);
        self
    }
    pub fn with_profile_limits(
        mut self,
        limits: rss_identity_core::profile::ProfileLimits,
    ) -> Self {
        self.profile_limits = limits;
        self
    }
    /// Install only a deployment-trusted verifier; replacing it is a host trust decision.
    pub fn with_platform(mut self, verifier: Arc<dyn platform::PlatformVerifier>) -> Self {
        self.platform = Some(verifier);
        self
    }
    pub fn new(
        instance: InstanceId,
        mut tenants: Vec<TenantId>,
        sessions: SessionPolicy,
        audit: rss_audit_postgres::Integrity,
    ) -> Result<Self, AuthorityError> {
        tenants.sort_by_key(|tenant| tenant.to_string());
        if tenants.is_empty()
            || tenants.len() > 128
            || tenants.windows(2).any(|pair| pair[0] == pair[1])
        {
            return Err(AuthorityError::Configuration);
        }
        Ok(Self {
            instance,
            tenants,
            sessions,
            audit,
            platform: None,
            enterprise: None,
            profile_limits: Default::default(),
        })
    }
}
#[derive(Clone)]
pub struct Authority {
    enterprise: Option<platform::EnterpriseConfig>,
    session_checks: session_checks::SessionChecks,
    kdf: Arc<rss_identity_core::account::PasswordKdf>,
    runtime: Arc<runtime::RuntimeBundle>,
    profile: AuthorityProfile,
    instance: InstanceId,
    session_policy: SessionPolicy,
    policy: Arc<dyn ManagementPolicy>,
    profile_limits: rss_identity_core::profile::ProfileLimits,
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
            enterprise: config.enterprise,
            session_checks: session_checks::SessionChecks {
                platform: config.platform,
                ..Default::default()
            },
            kdf,
            runtime: Arc::new(runtime::RuntimeBundle {
                runtime,
                audit: config.audit,
                tenants: config.tenants,
                instance,
            }),
            profile,
            instance,
            session_policy: config.sessions,
            policy,
            profile_limits: config.profile_limits,
        };
        let integrity = authority.runtime.audit.clone();
        let valid = Self::read_bundle(
            authority.runtime.clone(),
            tenant,
            budget.remaining(),
            false,
            move |tx| {
                Box::pin(async move {
                    rss_audit_postgres::validate_in(tx, &integrity)
                        .await
                        .map_err(PgError::from)?;
                    transaction::connection(tx, move |c| {
                        Box::pin(schema::probe(c, profile, instance))
                    })
                    .await
                })
            },
        )
        .await;
        check_probe(valid)?;
        let bundle = authority.runtime.clone();
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
        Ok(self.runtime.clone().tenants.clone())
    }
    pub fn tenant_active(&self, tenant: TenantId) -> bool {
        self.runtime.tenants.contains(&tenant)
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

mod provisioning;
pub use provisioning::{AccountProvisioner, PreparedLocalAccount, ProvisioningError};

mod bearer;
pub use bearer::IssuedBearer;

mod profile_admission;
pub use profile_admission::{ProfileSourceAdmissionError, admit_profile_source_on};

mod step_up;
pub use step_up::{ConsumedStepUp, StepUpGrant, consume_step_up_on};
mod webauthn;
pub use webauthn::{
    RegistrationAuthorization, WebauthnAuthority, WebauthnChallenge, WebauthnCredentialView,
    activate_webauthn_rp_on, webauthn_management_context,
};
