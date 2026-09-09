//! Construct concrete providers once; the lifecycle owns every acquired resource.
use crate::{AppError, config::RuntimeConfig, read_public_file, read_secret};
use rss_identity_core::{downstream::*, federation::StateSigner};
use rss_identity_hydra::Hydra;
use rss_identity_oidc::{ApprovedProvider, HttpOidc};
use rss_identity_postgres::{
    Authority, AuthorityProfile, Downstream, Federation, PrepareAdmission,
};
use rss_request_context::{Clock, Deadline, ExecutionTimer, TenantId};
use rss_transactional_messaging::policy::{DeliveryBudget, OperationDeadline};
use rss_transactional_messaging_postgres::PgRuntime;
use std::{
    collections::BTreeMap,
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
pub async fn authority(
    config: &RuntimeConfig,
    runtime: Arc<PgRuntime>,
    kdf: Arc<rss_identity_core::account::PasswordKdf>,
) -> Result<Authority, AppError> {
    let mut connected = None;
    for tenant in config.storage.tenants()? {
        connected = Some(
            Authority::connect(
                runtime.clone(),
                kdf.clone(),
                config.identity_origin.clone(),
                delivery_budget()?,
                tenant,
                AuthorityProfile::Runtime,
                deadline(),
            )
            .await?,
        );
    }
    connected.ok_or(AppError::Tenant)
}
pub struct Providers {
    pub federation: Federation,
    pub downstream: Downstream,
    pub hydra: Arc<Hydra>,
    pub validation_secrets: BTreeMap<String, zeroize::Zeroizing<String>>,
}
pub fn providers(c: &RuntimeConfig, a: Authority) -> Result<Providers, AppError> {
    let mut bindings = Vec::new();
    let mut secrets = BTreeMap::new();
    for v in &c.oidc.providers {
        let value = read_secret(Path::new(&v.secret_file))?;
        if value.is_empty() || secrets.insert(v.secret_ref.clone(), value).is_some() {
            return Err(AppError::Configuration);
        }
        bindings.push(ApprovedProvider {
            tenant: TenantId::parse(&v.tenant_id).map_err(|_| AppError::Tenant)?,
            issuer: v.issuer.clone(),
            client_id: v.client_id.clone(),
            secret_ref: v.secret_ref.clone(),
            redirect_uri: c.identity_origin.identity_callback(),
            addresses: v
                .addresses
                .iter()
                .map(|a| a.parse().map_err(|_| AppError::Configuration))
                .collect::<Result<_, _>>()?,
        });
    }
    let oidc = HttpOidc::new(
        bindings,
        secrets,
        Some(&read_public_file(Path::new(&c.oidc.ca_file), 1024 * 1024)?),
    )
    .map_err(|_| AppError::Provider)?;
    let raw = read_secret(Path::new(&c.oidc.state_key_file))?;
    let mut key = zeroize::Zeroizing::new([0; 32]);
    hex::decode_to_slice(raw.as_str(), key.as_mut()).map_err(|_| AppError::Configuration)?;
    let signer = StateSigner::new(*key, c.identity_origin.identity_origin())
        .map_err(|_| AppError::Configuration)?;
    let hydra = Arc::new(
        Hydra::new(
            &c.hydra.admin_url,
            &c.identity_origin.issuer(),
            c.hydra
                .addresses
                .iter()
                .map(|a| a.parse().map_err(|_| AppError::Configuration))
                .collect::<Result<_, _>>()?,
            Secret::new(read_secret(Path::new(&c.hydra.service_secret_file))?.to_string())
                .map_err(|_| AppError::Configuration)?,
            Some(&read_public_file(Path::new(&c.hydra.ca_file), 1024 * 1024)?),
        )
        .map_err(|_| AppError::Provider)?,
    );
    let limits = Lifetimes::new(LifetimeLimits {
        request: c.hydra.request_seconds,
        code: c.hydra.code_seconds,
        access_token: c.hydra.access_token_seconds,
        clock_skew: c.hydra.clock_skew_seconds,
    })
    .map_err(|_| AppError::Configuration)?;
    let mut registrations = Vec::new();
    let mut validation_secrets = BTreeMap::new();
    let mut targets = BTreeMap::new();
    targets.insert(
        ("identity-ui".into(), "resume".into()),
        format!("{}/auth/resume", c.identity_origin.identity_origin()),
    );
    for client in &c.hydra.clients {
        let oidc_secret = read_secret(Path::new(&client.oidc_secret_file))?;
        let validation = read_secret(Path::new(&client.validation_secret_file))?;
        if oidc_secret.len() < 32
            || *oidc_secret == *validation
            || validation_secrets
                .insert(client.client_id.clone(), validation)
                .is_some()
        {
            return Err(AppError::Configuration);
        }
        registrations.push(
            Registration::new(RegistrationInput {
                tenant: TenantId::parse(&client.tenant_id).map_err(|_| AppError::Tenant)?,
                client: client.client_id.clone(),
                audience: client.audience.clone(),
                issuer: c.identity_origin.issuer(),
                redirect: c.identity_origin.product_callback(),
                version: client.config_version,
            })
            .map_err(|_| AppError::Configuration)?,
        );
    }
    let federation = Federation::new(a.clone(), Arc::new(oidc), signer, targets)?;
    let admission = Arc::new(PrepareAdmission::new(16, 120, Duration::from_secs(60))?);
    let downstream = Downstream::new(a, hydra.clone(), registrations, limits, admission)?;
    Ok(Providers {
        federation,
        downstream,
        hydra,
        validation_secrets,
    })
}
