//! Minimal reference host: owns policy, runtime fencing, URLs and optional upstream configuration.
use crate::{AppError, config::RuntimeConfig, read_secret};
use rss_identity_core::{account::AccountKey, session::SessionPolicy};
use rss_identity_oidc::{HttpOidc, TrustedAssuranceProfile};
use rss_identity_postgres::StateSigner;
use rss_identity_postgres::{
    Authority, AuthorityConfig, Federation, FederationConfig, ManagementContext, ManagementDenied,
    ManagementOperation, ManagementPolicy, ReauthenticationRequirement,
};
use rss_request_context::{Clock, Deadline, ExecutionTimer, TenantId};
use rss_request_context::SharedExecutionTimer;
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
/// Product policy, deliberately outside the authentication component.
pub struct BootstrapPolicy(pub Vec<AccountKey>, pub Duration);
impl BootstrapPolicy {
    pub fn is_manager(&self, account: AccountKey) -> bool {
        self.0.contains(&account)
    }
}
impl ManagementPolicy for BootstrapPolicy {
    fn authorize<'a>(
        &'a self,
        context: &'a ManagementContext<'a>,
        _connection: &'a mut sqlx::PgConnection,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<ReauthenticationRequirement, ManagementDenied>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            if matches!(
                context.operation(),
                ManagementOperation::RegisterWebauthn
                    | ManagementOperation::RemoveWebauthn
                    | ManagementOperation::RecoverWebauthn
            ) && context.target() == Some(context.actor())
            {
                // The component checks first-enrollment freshness or consumes the exact MFA proof.
                return Ok(ReauthenticationRequirement::None);
            }
            if context.operation() == ManagementOperation::AuthorizeWebauthnRecovery {
                return Err(ManagementDenied);
            }
            if context.operation() == ManagementOperation::ChangeOwnPassword
                && context.target() == Some(context.actor())
            {
                return Ok(ReauthenticationRequirement::Recent(self.1));
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
            Ok(ReauthenticationRequirement::Recent(self.1))
        })
    }
}
/// Session policy used by the reference host and its offline acceptance profile.
pub fn session_policy() -> Result<SessionPolicy, AppError> {
    SessionPolicy::new(900, 14400).map_err(|_| AppError::Configuration)
}
pub fn authority_config(config: &RuntimeConfig) -> Result<AuthorityConfig, AppError> {
    config.authority.apply(
        AuthorityConfig::new(
            config.instance()?,
            session_policy()?,
            rss_audit_postgres::Integrity::Plain,
            config.database.audit_budget()?,
        )?,
        config.budgets.request(),
    )
}
pub async fn authority(
    config: &RuntimeConfig,
    authority_config: AuthorityConfig,
    runtime: Arc<PgRuntime>,
    kdf: Arc<rss_identity_core::account::PasswordKdf>,
    cutoff: Deadline,
) -> Result<Authority, AppError> {
    Ok(Authority::connect_runtime(
        runtime,
        kdf,
        authority_config,
        config.storage.binding(config.bootstrap_keys()?[0].tenant)?,
        Arc::new(BootstrapPolicy(
            config.bootstrap_keys()?,
            std::time::Duration::from_secs(u64::from(
                config.authority.operation_proof_seconds.get(),
            )),
        )),
        cutoff,
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
    federation_inputs(config, SharedExecutionTimer::new(Timer))?;
    Ok(())
}
pub fn federation(
    config: &RuntimeConfig,
    authority: Authority,
) -> Result<Option<Federation>, AppError> {
    federation_inputs(config, authority.execution_timer().clone())?
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
fn federation_inputs(config: &RuntimeConfig, timer: SharedExecutionTimer) -> Result<Option<FederationInputs>, AppError> {
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
    let oidc = HttpOidc::new(
        rss_identity_oidc::ProviderClock::new(timer, std::time::SystemTime::now),
        profiles,
        c.private_access()?,
        c.transport()?,
        c.reuse.policy()?,
    )
    .map_err(|_| AppError::Provider)?
    .with_future_skew(config.authority.future_skew_seconds);
    let raw = read_secret(Path::new(&c.state_key_file))?;
    let mut key = zeroize::Zeroizing::new([0; 32]);
    hex::decode_to_slice(raw.as_str(), key.as_mut()).map_err(|_| AppError::Configuration)?;
    let signer = StateSigner::new(*key, &config.instance()?.to_string())
        .map_err(|_| AppError::Configuration)?;
    let options = FederationConfig {
        callback: format!("{}/api/v1/identity/oidc/callback", config.public_origin),
        credential_keys: c.credential_keyring.load()?,
        targets: {
            let mut targets = c.return_targets.clone();
            targets.insert(
                "security".into(),
                format!("{}/identity-security", config.public_origin),
            );
            targets
        },
    };
    options.validate()?;
    Ok(Some(FederationInputs {
        oidc,
        signer,
        options,
        group_policy: c.group_policy()?,
    }))
}
