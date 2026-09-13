//! Application-owned configuration. Secrets are file references, never configuration values.
use crate::{AppError, read_public_file, read_secret};
use rss_identity_postgres::DeploymentIdentity;
use rss_request_context::TenantId;
use rss_transactional_messaging::fence::{Epoch, ExecutionBinding, StorageIdentity};
use rss_transactional_messaging_postgres::{PgConfig, PgPassword, PgPrivateCa};
use serde::Deserialize;
use std::{
    collections::BTreeSet,
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
    pub system_domain_id: String,
    pub generation: i64,
}
impl StorageConfig {
    pub fn system(&self) -> Result<TenantId, AppError> {
        TenantId::parse(&self.system_domain_id).map_err(|_| AppError::Tenant)
    }
    pub fn identity(&self) -> Result<StorageIdentity, AppError> {
        StorageIdentity::new(self.target, self.lineage).map_err(|_| AppError::StorageIdentity)
    }
    pub fn epoch(&self) -> Result<Epoch, AppError> {
        Epoch::new(self.generation).map_err(|_| AppError::StorageEpoch)
    }
    pub fn binding(&self) -> Result<ExecutionBinding, AppError> {
        ExecutionBinding::new(self.identity()?, vec![(self.system()?, self.epoch()?)])
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
    pub assurance_profiles: Vec<AssuranceProfileConfig>,
    pub state_key_file: String,
    pub credential_keyring: CredentialKeyringConfig,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    pub tenant_id: String,
    pub client_id: String,
    pub audience: String,
    pub config_version: i64,
    pub validation_secret_file: String,
    pub oidc_secret_file: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HydraConfig {
    pub admin_url: String,
    pub addresses: Vec<String>,
    pub ca_file: String,
    pub service_secret_file: String,
    pub request_seconds: i64,
    pub code_seconds: i64,
    pub access_token_seconds: i64,
    pub clock_skew_seconds: i64,
    pub clients: Vec<ClientConfig>,
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
    pub identity_origin: DeploymentIdentity,
    pub database: DatabaseConfig,
    pub storage: StorageConfig,
    pub listen: SocketAddr,
    pub public_gateway: IpAddr,
    pub private_gateway: IpAddr,
    pub budgets: Budgets,
    pub oidc: OidcConfig,
    pub hydra: HydraConfig,
}
impl RuntimeConfig {
    pub fn load(path: &Path) -> Result<Self, AppError> {
        let v: Self = load(path)?;
        v.validate()?;
        Ok(v)
    }
    pub fn validate(&self) -> Result<(), AppError> {
        if self.format_version != 2
            || self.public_gateway == self.private_gateway
            || self.public_gateway.is_unspecified()
            || self.private_gateway.is_unspecified()
            || self.public_gateway.is_multicast()
            || self.private_gateway.is_multicast()
            || self.listen.port() == 0
        {
            return Err(AppError::Configuration);
        }
        self.budgets.validate()?;
        self.storage.binding()?;
        if self.oidc.assurance_profiles.len() > 128 || self.hydra.clients.len() > 128 {
            return Err(AppError::Configuration);
        }
        let mut clients = BTreeSet::new();
        for client in &self.hydra.clients {
            let tenant = TenantId::parse(&client.tenant_id).map_err(|_| AppError::Tenant)?;
            if tenant == self.storage.system()? || !clients.insert(&client.client_id) {
                return Err(AppError::Configuration);
            }
        }
        Ok(())
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationConfig {
    pub format_version: u32,
    pub identity_origin: DeploymentIdentity,
    pub database: DatabaseConfig,
    pub storage: StorageConfig,
    pub runtime_password_file: String,
    pub maintenance_password_file: String,
    pub credential_keyring: CredentialKeyringConfig,
}
pub fn load<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, AppError> {
    serde_json::from_slice(&read_public_file(path, 256 * 1024)?).map_err(|_| AppError::Json)
}
