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
#[serde(deny_unknown_fields)]
pub struct DatabaseConfig {
    pub host: String,
    pub port: u16,
    pub database: String,
    pub user: String,
    pub password_file: String,
    pub ca_file: String,
}
impl DatabaseConfig {
    pub fn pg(&self) -> Result<PgConfig, AppError> {
        if self.host.is_empty()
            || self.database.is_empty()
            || self.user.is_empty()
            || self.port == 0
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
        ))
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
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    pub target: [u8; 16],
    pub lineage: [u8; 16],
    pub tenants: Vec<String>,
    pub generation: i64,
}
impl StorageConfig {
    pub fn tenants(&self) -> Result<Vec<TenantId>, AppError> {
        if self.tenants.is_empty() || self.tenants.len() > 128 {
            return Err(AppError::Tenant);
        }
        let tenants = self
            .tenants
            .iter()
            .map(|t| TenantId::parse(t).map_err(|_| AppError::Tenant))
            .collect::<Result<Vec<_>, _>>()?;
        let mut seen = std::collections::BTreeSet::new();
        if tenants.iter().any(|t| !seen.insert(t.to_string())) {
            return Err(AppError::Tenant);
        }
        Ok(tenants)
    }
    pub fn identity(&self) -> Result<StorageIdentity, AppError> {
        StorageIdentity::new(self.target, self.lineage).map_err(|_| AppError::StorageIdentity)
    }
    pub fn epoch(&self) -> Result<Epoch, AppError> {
        Epoch::new(self.generation).map_err(|_| AppError::StorageEpoch)
    }
    pub fn binding(&self) -> Result<ExecutionBinding, AppError> {
        ExecutionBinding::new(
            self.identity()?,
            self.tenants()?
                .into_iter()
                .map(|t| Ok((t, self.epoch()?)))
                .collect::<Result<Vec<_>, AppError>>()?,
        )
        .map_err(|_| AppError::StorageIdentity)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssuranceProfileConfig {
    pub tenant_id: String,
    pub issuer: String,
    pub client_id: String,
    pub keycloak_totp: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialKeyFile {
    pub key_id: String,
    pub path: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct OidcConfig {
    pub group_facts_max_age_seconds: i64,
    pub assurance_profiles: Vec<AssuranceProfileConfig>,
    pub state_key_file: String,
    pub credential_keyring: CredentialKeyringConfig,
    pub return_targets: std::collections::BTreeMap<String, String>,
}
impl OidcConfig {
    pub fn group_policy(&self) -> Result<rss_identity_core::groups::GroupFactsMaxAge, AppError> {
        rss_identity_core::groups::GroupFactsMaxAge::new(self.group_facts_max_age_seconds)
            .map_err(|_| AppError::Configuration)
    }
}
#[derive(Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Budgets {
    pub request_seconds: u64,
    pub drain_seconds: u64,
    pub resource_seconds: u64,
}
impl Budgets {
    pub fn validate(self) -> Result<Self, AppError> {
        if !(1..=60).contains(&self.request_seconds)
            || !(1..=300).contains(&self.drain_seconds)
            || self.resource_seconds == 0
            || self.resource_seconds > self.drain_seconds
            || self.request_seconds > self.drain_seconds
        {
            return Err(AppError::Budget);
        }
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
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfig {
    pub format_version: u32,
    pub instance_id: String,
    pub public_origin: String,
    pub bootstrap: Bootstrap,
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
        if self.format_version != 3
            || self.public_gateway.is_unspecified()
            || self.public_gateway.is_multicast()
            || self.listen.port() == 0
        {
            return Err(AppError::Configuration);
        }
        self.budgets.validate()?;
        self.storage.binding()?;
        self.instance()?;
        let bootstrap = self.bootstrap.key()?;
        if !self.storage.tenants()?.contains(&bootstrap.tenant) {
            return Err(AppError::Tenant);
        }
        rss_identity_http_axum::HttpConfig::new(&self.public_origin, self.budgets.request())
            .map_err(|_| AppError::Configuration)?;
        if let Some(oidc) = &self.oidc {
            oidc.group_policy()?;
            if oidc.assurance_profiles.len() > 128 {
                return Err(AppError::Configuration);
            }
        }
        Ok(())
    }
    pub fn instance(&self) -> Result<InstanceId, AppError> {
        InstanceId::parse(&self.instance_id).map_err(|_| AppError::Configuration)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
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
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationConfig {
    pub format_version: u32,
    pub instance_id: String,
    pub database: DatabaseConfig,
    pub storage: StorageConfig,
    pub runtime_role: String,
    pub maintenance_role: String,
}
pub fn load<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, AppError> {
    serde_json::from_slice(&read_public_file(path, 256 * 1024)?).map_err(|_| AppError::Json)
}
