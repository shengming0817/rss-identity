//! Minimal reference host: owns policy, runtime fencing, URLs and optional upstream configuration.
use crate::{AppError, config::RuntimeConfig, read_secret};
use rss_identity_core::{account::AccountKey, federation::StateSigner, session::SessionPolicy};
use rss_identity_oidc::{HttpOidc, TrustedAssuranceProfile};
use rss_identity_postgres::{
    Authority, AuthorityConfig, Federation, FederationConfig, ManagementContext, ManagementDenied,
    ManagementOperation, ManagementPolicy, ReauthenticationRequirement,
};
use rss_request_context::{Clock, Deadline, ExecutionTimer, TenantId};
use rss_transactional_messaging::policy::{DeliveryBudget, OperationDeadline};
use rss_transactional_messaging_postgres::PgRuntime;
use std::{
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};
pub struct Timer;
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
pub fn delivery_budget() -> Result<DeliveryBudget, AppError> {
    DeliveryBudget::new(
        Duration::from_secs(60),
        Duration::from_secs(5),
        Duration::from_secs(5),
        Duration::from_secs(5),
    )
    .map_err(|_| AppError::Budget)
}
pub fn deadline() -> OperationDeadline {
    OperationDeadline::from_remaining(Duration::from_secs(10))
}

/// Product policy, deliberately outside the authentication component.
pub struct BootstrapPolicy(pub Vec<AccountKey>);
impl BootstrapPolicy {
    pub fn is_manager(&self, account: AccountKey) -> bool {
        self.0.contains(&account)
    }
}
impl ManagementPolicy for BootstrapPolicy {
    fn authorize(
        &self,
        context: &ManagementContext<'_>,
    ) -> Result<ReauthenticationRequirement, ManagementDenied> {
        if context.operation() == ManagementOperation::ChangeOwnPassword
            && context.target() == Some(context.actor())
        {
            return Ok(ReauthenticationRequirement::Recent(Duration::from_secs(
                300,
            )));
        }
        if !self.is_manager(context.actor())
            || (context
                .target()
                .is_some_and(|target| self.0.contains(&target))
                && matches!(
                    context.operation(),
                    ManagementOperation::SetAccountEnabled(false)
                        | ManagementOperation::SetMembership(false)
                ))
        {
            return Err(ManagementDenied);
        }
        Ok(ReauthenticationRequirement::Recent(Duration::from_secs(
            300,
        )))
    }
}
/// Session policy used by the reference host and its offline acceptance profile.
pub fn session_policy() -> Result<SessionPolicy, AppError> {
    SessionPolicy::new(900, 14400).map_err(|_| AppError::Configuration)
}
pub fn authority_config(config: &RuntimeConfig) -> Result<AuthorityConfig, AppError> {
    Ok(AuthorityConfig::new(
        config.instance()?,
        config.storage.tenants()?,
        session_policy()?,
        delivery_budget()?,
    )?)
}
pub async fn authority(
    config: &RuntimeConfig,
    runtime: Arc<PgRuntime>,
    kdf: Arc<rss_identity_core::account::PasswordKdf>,
) -> Result<Authority, AppError> {
    Ok(Authority::connect_runtime(
        runtime,
        kdf,
        authority_config(config)?,
        Arc::new(BootstrapPolicy(config.bootstrap_keys()?)),
        deadline(),
    )
    .await?)
}
struct FederationInputs {
    oidc: HttpOidc,
    signer: StateSigner,
    options: FederationConfig,
    group_policy: rss_identity_core::groups::GroupFactsMaxAge,
}
/// Offline validation through the same constructors used by runtime assembly.
pub fn preflight(config: &RuntimeConfig) -> Result<(), AppError> {
    config.validate()?;
    config.database.pg()?;
    authority_config(config)?;
    federation_inputs(config)?;
    Ok(())
}
pub fn federation(
    config: &RuntimeConfig,
    authority: Authority,
) -> Result<Option<Federation>, AppError> {
    federation_inputs(config)?
        .map(|inputs| {
            Ok(Federation::new(
                inputs.group_policy,
                authority,
                Arc::new(inputs.oidc),
                inputs.signer,
                inputs.options,
            )?)
        })
        .transpose()
}
fn federation_inputs(config: &RuntimeConfig) -> Result<Option<FederationInputs>, AppError> {
    let Some(c) = &config.oidc else {
        return Ok(None);
    };
    let profiles = c
        .assurance_profiles
        .iter()
        .map(|v| {
            Ok(TrustedAssuranceProfile {
                tenant: TenantId::parse(&v.tenant_id).map_err(|_| AppError::Tenant)?,
                issuer: v.issuer.clone(),
                client_id: v.client_id.clone(),
                keycloak_totp: v.keycloak_totp,
            })
        })
        .collect::<Result<Vec<_>, AppError>>()?;
    let oidc = HttpOidc::new(profiles, c.private_access(&config.storage.tenants()?)?)
        .map_err(|_| AppError::Provider)?;
    let raw = read_secret(Path::new(&c.state_key_file))?;
    let mut key = zeroize::Zeroizing::new([0; 32]);
    hex::decode_to_slice(raw.as_str(), key.as_mut()).map_err(|_| AppError::Configuration)?;
    let signer = StateSigner::new(*key, &config.instance()?.to_string())
        .map_err(|_| AppError::Configuration)?;
    let options = FederationConfig {
        callback: format!("{}/api/v2/oidc/callback", config.public_origin),
        credential_keys: c.credential_keyring.load()?,
        targets: c.return_targets.clone(),
    };
    options.validate()?;
    Ok(Some(FederationInputs {
        oidc,
        signer,
        options,
        group_policy: c.group_policy()?,
    }))
}
