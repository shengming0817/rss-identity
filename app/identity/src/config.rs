//! Application-owned configuration. Secrets are file references, never configuration values.
use crate::{AppError, read_public_file, read_secret};
use rss_identity_core::{InstanceId, PrincipalId, account::AccountKey};
use rss_request_context::TenantId;
use rss_transactional_messaging::fence::{Epoch, ExecutionBinding, StorageIdentity};
use rss_transactional_messaging_postgres::{PgConfig, PgPassword, PgPrivateCa};
use serde::Deserialize;
use std::{
    net::{IpAddr, SocketAddr},
    path::Path,
    time::Duration,
};

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DatabaseConfig {
    pub host: String,
    pub port: u16,
    pub database: String,
    pub user: String,
    pub password_file: String,
    pub ca_file: String,
    pub min_connections: u32,
    pub max_connections: u32,
    pub acquire_seconds: u64,
}
impl DatabaseConfig {
    pub fn pg(&self) -> Result<PgConfig, AppError> {
        if self.host.is_empty()
            || self.database.is_empty()
            || self.user.is_empty()
            || self.port == 0
            || self.max_connections == 0
            || self.min_connections > self.max_connections
            || finite_seconds(self.acquire_seconds).is_err()
        {
            return Err(AppError::Configuration);
        }
        Ok(PgConfig::new(
            self.host.clone(),
            self.port,
            self.database.clone(),
            self.user.clone(),
            PgPassword::new(read_secret(Path::new(&self.password_file))?.to_string()),
            PgPrivateCa::from_pem(read_public_file(Path::new(&self.ca_file), 1024 * 1024)?)
                .map_err(|_| AppError::Ca)?,
        )
        .with_pool_limits(self.min_connections, self.max_connections)
        .with_acquire_timeout(finite_seconds(self.acquire_seconds)?))
    }
    pub fn sqlx(&self) -> Result<sqlx::postgres::PgConnectOptions, AppError> {
        // Validate the same file/CA boundary as the RSS pool before configuring the owner connection.
        let _ = self.pg()?;
        Ok(sqlx::postgres::PgConnectOptions::new()
            .host(&self.host)
            .port(self.port)
            .database(&self.database)
            .username(&self.user)
            .password(&read_secret(Path::new(&self.password_file))?)
            .ssl_mode(sqlx::postgres::PgSslMode::VerifyFull)
            .ssl_root_cert_from_pem(read_public_file(Path::new(&self.ca_file), 1024 * 1024)?))
    }
}
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StorageConfig {
    pub target: [u8; 16],
    pub lineage: [u8; 16],
    pub generation: i64,
}
impl StorageConfig {
    pub fn identity(&self) -> Result<StorageIdentity, AppError> {
        StorageIdentity::new(self.target, self.lineage).map_err(|_| AppError::StorageIdentity)
    }
    pub fn epoch(&self) -> Result<Epoch, AppError> {
        Epoch::new(self.generation).map_err(|_| AppError::StorageEpoch)
    }
    pub fn binding(&self, tenant: TenantId) -> Result<ExecutionBinding, AppError> {
        Ok(ExecutionBinding::new(
            self.identity()?,
            tenant,
            self.epoch()?,
        ))
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssuranceProfileConfig {
    pub tenant_id: String,
    pub issuer: String,
    pub client_id: String,
    pub keycloak_totp: bool,
}
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialKeyFile {
    pub key_id: String,
    pub path: String,
}
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialKeyringConfig {
    pub active_key_id: String,
    pub keys: Vec<CredentialKeyFile>,
}
impl CredentialKeyringConfig {
    pub fn load(&self) -> Result<std::sync::Arc<rss_identity_postgres::CredentialKeys>, AppError> {
        let mut keys = Vec::new();
        for key in &self.keys {
            let raw = read_secret(Path::new(&key.path))?;
            let mut bytes = zeroize::Zeroizing::new([0; 32]);
            hex::decode_to_slice(raw.as_str(), bytes.as_mut())
                .map_err(|_| AppError::Configuration)?;
            keys.push((key.key_id.clone(), *bytes));
        }
        Ok(std::sync::Arc::new(
            rss_identity_postgres::CredentialKeys::new(self.active_key_id.clone(), keys)?,
        ))
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrivateProviderConfig {
    pub tenant_id: String,
    pub issuer: String,
    pub client_id: String,
    pub cidrs: Vec<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OidcReuseConfig {
    pub max_providers: usize,
    pub max_resident_bytes: usize,
    pub max_refreshes: usize,
    pub max_idle_per_host: usize,
    pub idle_seconds: u64,
    pub discovery_seconds: u64,
    pub jwks_seconds: u64,
    pub refresh_cooldown_seconds: u64,
}
impl OidcReuseConfig {
    pub fn policy(&self) -> Result<rss_identity_oidc::ReusePolicy, AppError> {
        rss_identity_oidc::ReusePolicy {
            max_providers: self.max_providers,
            max_resident_bytes: self.max_resident_bytes,
            max_refreshes: self.max_refreshes,
            max_idle_per_host: self.max_idle_per_host,
            idle_timeout: finite_seconds(self.idle_seconds)?,
            discovery_ttl: finite_seconds(self.discovery_seconds)?,
            jwks_ttl: finite_seconds(self.jwks_seconds)?,
            refresh_cooldown: finite_seconds(self.refresh_cooldown_seconds)?,
        }
        .validate()
        .map_err(|_| AppError::Configuration)
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OidcConfig {
    pub reuse: OidcReuseConfig,
    pub request_seconds: u64,
    pub connect_seconds: u64,
    pub max_response_bytes: usize,
    pub max_jwks_keys: usize,
    pub group_facts_max_age_seconds: i64,
    pub assurance_profiles: Vec<AssuranceProfileConfig>,
    pub private_providers: Vec<PrivateProviderConfig>,
    pub state_key_file: String,
    pub credential_keyring: CredentialKeyringConfig,
    pub return_targets: std::collections::BTreeMap<String, String>,
}
impl OidcConfig {
    pub fn transport(&self) -> Result<rss_identity_oidc::TransportPolicy, AppError> {
        rss_identity_oidc::TransportPolicy::new(
            finite_seconds(self.request_seconds)?,
            finite_seconds(self.connect_seconds)?,
            self.max_response_bytes,
            self.max_jwks_keys,
        )
        .map_err(|_| AppError::Configuration)
    }

    pub fn private_access(
        &self,
    ) -> Result<Vec<rss_identity_oidc::PrivateProviderAccess>, AppError> {
        self.private_providers
            .iter()
            .map(|value| {
                let tenant = TenantId::parse(&value.tenant_id).map_err(|_| AppError::Tenant)?;
                Ok(rss_identity_oidc::PrivateProviderAccess {
                    tenant,
                    issuer: value.issuer.clone(),
                    client_id: value.client_id.clone(),
                    cidrs: value
                        .cidrs
                        .iter()
                        .map(|v| v.parse().map_err(|_| AppError::Configuration))
                        .collect::<Result<_, _>>()?,
                })
            })
            .collect()
    }
    pub fn group_policy(&self) -> Result<rss_identity_core::groups::GroupFactsMaxAge, AppError> {
        rss_identity_core::groups::GroupFactsMaxAge::new(self.group_facts_max_age_seconds)
            .map_err(|_| AppError::Configuration)
    }
}
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Budgets {
    pub request_seconds: u64,
    pub drain_seconds: u64,
    pub resource_seconds: u64,
    pub startup_seconds: u64,
    pub maintenance_seconds: u64,
    pub migration_seconds: u64,
}
impl Budgets {
    pub fn validate(self) -> Result<Self, AppError> {
        if self.request_seconds == 0
            || self.drain_seconds == 0
            || std::time::Instant::now()
                .checked_add(self.drain())
                .is_none()
            || self.resource_seconds == 0
            || self.resource_seconds > self.drain_seconds
            || self.request_seconds > self.drain_seconds
        {
            return Err(AppError::Budget);
        }
        finite_seconds(self.startup_seconds)?;
        finite_seconds(self.maintenance_seconds)?;
        // PostgreSQL statement_timeout and lock_timeout are signed millisecond integers.
        i32::try_from(finite_seconds(self.migration_seconds)?.as_millis())
            .map_err(|_| AppError::Budget)?;
        Ok(self)
    }
    pub fn request(self) -> Duration {
        Duration::from_secs(self.request_seconds)
    }
    pub fn drain(self) -> Duration {
        Duration::from_secs(self.drain_seconds)
    }
    pub fn resource(self) -> Duration {
        Duration::from_secs(self.resource_seconds)
    }
}
/// All non-secret configuration input shares this host-owned file budget.
pub const CONFIG_MAX_BYTES: usize = 16 * 1024 * 1024;
pub fn finite_seconds(seconds: u64) -> Result<Duration, AppError> {
    let duration = Duration::from_secs(seconds);
    if seconds == 0 || std::time::Instant::now().checked_add(duration).is_none() {
        return Err(AppError::Budget);
    }
    Ok(duration)
}
pub fn cutoff(seconds: u64) -> Result<rss_request_context::Deadline, AppError> {
    let duration = finite_seconds(seconds)?;
    Ok(rss_request_context::Deadline::at(
        std::time::Instant::now()
            .checked_add(duration)
            .ok_or(AppError::Budget)?,
    ))
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PasswordWorkConfig {
    pub concurrency: std::num::NonZeroUsize,
    pub reserved_memory_bytes: std::num::NonZeroU64,
}
impl PasswordWorkConfig {
    pub fn build(&self) -> Result<rss_identity_core::account::PasswordKdf, AppError> {
        rss_identity_core::account::PasswordKdf::new(self.concurrency, self.reserved_memory_bytes)
            .map_err(|_| AppError::Budget)
    }
}
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthoritySettings {
    pub source_limit: u32,
    pub source_seconds: u32,
    pub scope_limit: u32,
    pub scope_seconds: u32,
    pub password_failure_limit: u32,
    pub password_failure_seconds: u32,
    pub attempt_records: u32,
    pub cleanup_batch: u16,
    pub provider_capacity: std::num::NonZeroU16,
    pub profile_receipts: std::num::NonZeroU32,
    pub profile_bytes: usize,
    pub profile_members: usize,
    pub profile_depth: usize,
    pub profile_array: usize,
    pub profile_max_age_seconds: u32,
    pub max_auth_facts_bytes: std::num::NonZeroU32,
    pub future_skew_seconds: u32,
    pub operation_proof_seconds: std::num::NonZeroU32,
}
impl AuthoritySettings {
    pub fn apply(
        &self,
        config: rss_identity_postgres::AuthorityConfig,
        claim_ttl: Duration,
    ) -> Result<rss_identity_postgres::AuthorityConfig, AppError> {
        use rss_identity_postgres::{AttemptWindow, AuthenticationPolicy};
        Ok(config
            .with_authentication_policy(AuthenticationPolicy::new(
                AttemptWindow::new(self.source_limit, self.source_seconds)?,
                AttemptWindow::new(self.scope_limit, self.scope_seconds)?,
                AttemptWindow::new(self.password_failure_limit, self.password_failure_seconds)?,
                self.attempt_records,
                self.cleanup_batch,
                claim_ttl,
            )?)
            .with_provider_capacity(self.provider_capacity)?
            .with_profile_receipt_capacity(self.profile_receipts)
            .with_profile_limits(
                rss_identity_core::profile::ProfileLimits::new(
                    self.profile_bytes,
                    self.profile_members,
                    self.profile_depth,
                    self.profile_array,
                    self.profile_max_age_seconds,
                )
                .map_err(|_| AppError::Configuration)?,
            )
            .with_auth_facts_budget(self.max_auth_facts_bytes)
            .with_future_skew(self.future_skew_seconds)
            .with_operation_proof_lifetime(self.operation_proof_seconds))
    }
}
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HttpServerConfig {
    pub connections: usize,
    pub headers: usize,
    pub buffer_bytes: usize,
}
impl HttpServerConfig {
    pub fn policy(self, budgets: Budgets) -> Result<rss_axum::Http1ServePolicy, AppError> {
        self.connections
            .checked_mul(self.buffer_bytes)
            .ok_or(AppError::Budget)?;
        rss_axum::Http1ServePolicy::new(
            rss_axum::ServePolicy::new(
                self.connections,
                budgets.request(),
                budgets.request(),
                budgets.resource(),
            )
            .map_err(|_| AppError::Budget)?,
            budgets.request(),
            self.headers,
            self.buffer_bytes,
        )
        .map_err(|_| AppError::Budget)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeConfig {
    pub webauthn_generation: i64,
    pub authority: AuthoritySettings,
    pub password_work: PasswordWorkConfig,
    pub http: HttpServerConfig,
    pub format_version: u32,
    pub instance_id: String,
    pub public_origin: String,
    pub bootstrap_accounts: Vec<Bootstrap>,
    pub database: DatabaseConfig,
    pub storage: StorageConfig,
    pub listen: SocketAddr,
    pub public_gateway: IpAddr,
    pub budgets: Budgets,
    pub oidc: Option<OidcConfig>,
}
impl RuntimeConfig {
    pub fn load(path: &Path) -> Result<Self, AppError> {
        let v: Self = load(path)?;
        v.validate()?;
        Ok(v)
    }
    pub fn validate(&self) -> Result<(), AppError> {
        if self.format_version != 5
            || self.public_gateway.is_unspecified()
            || self.public_gateway.is_multicast()
            || self.listen.port() == 0
        {
            return Err(AppError::Configuration);
        }
        self.budgets.validate()?;
        self.storage.identity()?;
        self.storage.epoch()?;
        self.instance()?;
        rss_identity_postgres::RpGeneration::new(self.webauthn_generation)?;
        self.bootstrap_keys()?;
        self.password_work.build()?;
        crate::assembly::authority_config(self)?;
        self.http.policy(self.budgets)?;
        rss_identity_http_axum::HttpConfig::new(&self.public_origin, self.budgets.request())
            .map_err(|_| AppError::Configuration)?;
        if let Some(oidc) = &self.oidc {
            oidc.group_policy()?;
            oidc.transport()?;
            oidc.reuse.policy()?;
            if oidc.assurance_profiles.len() > 1024 {
                return Err(AppError::Configuration);
            }
        }
        Ok(())
    }
    pub fn instance(&self) -> Result<InstanceId, AppError> {
        InstanceId::parse(&self.instance_id).map_err(|_| AppError::Configuration)
    }
    pub fn bootstrap_keys(&self) -> Result<Vec<AccountKey>, AppError> {
        bootstrap_keys(&self.bootstrap_accounts)
    }
}
/// Explicit targets of one installation or maintenance page, never runtime admission.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TenantTarget {
    pub tenant_id: String,
    pub generation: i64,
}
pub fn target_bindings(
    storage: &StorageConfig,
    targets: &[TenantTarget],
) -> Result<Vec<ExecutionBinding>, AppError> {
    let storage = storage.identity()?;
    let mut seen = std::collections::BTreeSet::new();
    if targets.is_empty() {
        return Err(AppError::Tenant);
    }
    targets
        .iter()
        .map(|target| {
            let tenant = TenantId::parse(&target.tenant_id).map_err(|_| AppError::Tenant)?;
            if !seen.insert(tenant.to_string()) {
                return Err(AppError::Tenant);
            }
            Ok(ExecutionBinding::new(
                storage,
                tenant,
                Epoch::new(target.generation).map_err(|_| AppError::StorageEpoch)?,
            ))
        })
        .collect()
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Bootstrap {
    pub tenant_id: String,
    pub principal_id: String,
}
impl Bootstrap {
    pub fn key(&self) -> Result<AccountKey, AppError> {
        Ok(AccountKey {
            tenant: TenantId::parse(&self.tenant_id).map_err(|_| AppError::Tenant)?,
            principal: PrincipalId::parse(&self.principal_id).map_err(|_| AppError::Principal)?,
        })
    }
}
/// Generated from the same deployment input as RuntimeConfig; no independent bootstrap identity.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MaintenanceConfig {
    pub authority: AuthoritySettings,
    pub password_work: PasswordWorkConfig,
    pub budgets: Budgets,
    pub format_version: u32,
    pub instance_id: String,
    pub bootstrap_accounts: Vec<Bootstrap>,
    pub database: DatabaseConfig,
    pub storage: StorageConfig,
}
impl MaintenanceConfig {
    pub fn validate(&self) -> Result<(), AppError> {
        if self.format_version != 5 {
            return Err(AppError::Configuration);
        }
        InstanceId::parse(&self.instance_id).map_err(|_| AppError::Configuration)?;
        self.storage.identity()?;
        self.storage.epoch()?;
        bootstrap_keys(&self.bootstrap_accounts)?;
        self.budgets.validate()?;
        self.password_work.build()?;
        self.authority.apply(
            rss_identity_postgres::AuthorityConfig::new(
                InstanceId::parse(&self.instance_id).map_err(|_| AppError::Configuration)?,
                crate::assembly::session_policy()?,
                rss_audit_postgres::Integrity::Plain,
            )?,
            finite_seconds(self.budgets.maintenance_seconds)?,
        )?;
        Ok(())
    }
    pub fn bootstrap_key(&self, tenant: TenantId) -> Result<AccountKey, AppError> {
        self.validate()?;
        bootstrap_keys(&self.bootstrap_accounts)?
            .into_iter()
            .find(|k| k.tenant == tenant)
            .ok_or(AppError::Tenant)
    }
}
fn bootstrap_keys(accounts: &[Bootstrap]) -> Result<Vec<AccountKey>, AppError> {
    let keys = accounts
        .iter()
        .map(Bootstrap::key)
        .collect::<Result<Vec<_>, _>>()?;
    let mut tenants = std::collections::BTreeSet::new();
    if keys.is_empty()
        || keys
            .iter()
            .any(|key| !tenants.insert(key.tenant.to_string()))
    {
        return Err(AppError::Tenant);
    }
    Ok(keys)
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MigrationConfig {
    pub targets: Vec<TenantTarget>,
    pub budgets: Budgets,
    pub audit: AuditInstallation,
    pub format_version: u32,
    pub instance_id: String,
    pub database: DatabaseConfig,
    pub storage: StorageConfig,
    pub runtime_role: String,
    pub maintenance_role: String,
}
pub fn load<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, AppError> {
    serde_json::from_slice(&read_public_file(path, CONFIG_MAX_BYTES)?).map_err(|_| AppError::Json)
}

/// Required owner for fresh Audit installation; business roles append directly.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditInstallation {
    pub owner_role: String,
}
