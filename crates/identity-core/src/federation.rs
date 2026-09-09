//! Federation values and narrow upstream port. Values are not authentication proofs.
//! ref: RustCrypto/MACs hmac/src/lib.rs @ hmac-v0.12.1.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};

use hmac::{Hmac, Mac};

use rand_core::{OsRng, RngCore};

use rss_request_context::TenantId;

use serde::{Deserialize, Serialize};

use sha2::{Digest, Sha256};

use std::{future::Future, pin::Pin};

use uuid::Uuid;

use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct ProviderId(Uuid);

impl ProviderId {
    pub fn generate() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn parse(value: &str) -> Result<Self, FederationError> {
        let id = Uuid::parse_str(value).map_err(|_| FederationError::Configuration)?;

        if id.is_nil() {
            return Err(FederationError::Configuration);
        }

        Ok(Self(id))
    }
}

impl std::fmt::Display for ProviderId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl<'de> Deserialize<'de> for ProviderId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Self::parse(&String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ClaimMapping {
    pub email: Option<String>,
    pub groups: Option<String>,
}

/// Untrusted configuration input. Convert before entering the domain or restoring storage.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderSettingsInput {
    pub issuer: String,
    pub client_id: String,
    pub secret_ref: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub claims: ClaimMapping,
    pub jit: bool,
}

impl ProviderSettingsInput {
    fn validate(&self) -> Result<(), FederationError> {
        for (s, max) in [
            (&self.issuer, 2048),
            (&self.client_id, 256),
            (&self.secret_ref, 256),
            (&self.redirect_uri, 2048),
        ] {
            if s.is_empty() || s.len() > max || s.trim() != s || s.chars().any(char::is_control) {
                return Err(FederationError::Configuration);
            }
        }

        for value in [&self.issuer, &self.redirect_uri] {
            let url = url::Url::parse(value).map_err(|_| FederationError::Configuration)?;
            if !matches!(url.scheme(), "http" | "https")
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
            {
                return Err(FederationError::Configuration);
            }
        }
        // A reference is a versioned opaque binding owned by deployment, never a mutable alias.
        if !self.secret_ref.contains('@')
            || self.secret_ref.starts_with('@')
            || self.secret_ref.ends_with('@')
        {
            return Err(FederationError::Configuration);
        }

        if self.scopes.is_empty()
            || self.scopes.len() > 16
            || !self.scopes.iter().any(|s| s == "openid")
        {
            return Err(FederationError::Configuration);
        }

        let mut seen = std::collections::BTreeSet::new();

        for s in &self.scopes {
            if s.len() > 128
                || s.is_empty()
                || !s
                    .bytes()
                    .all(|b| (0x21..=0x7e).contains(&b) && b != b'"' && b != b'\\')
                || s == "offline_access"
                || !seen.insert(s)
            {
                return Err(FederationError::Configuration);
            }
        }

        for s in [&self.claims.email, &self.claims.groups]
            .into_iter()
            .flatten()
        {
            if s.is_empty()
                || s.len() > 64
                || !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                || ["sub", "iss", "aud", "nonce", "azp"].contains(&s.as_str())
            {
                return Err(FederationError::Configuration);
            }
        }

        Ok(())
    }
}

/// Validated immutable domain configuration; serde restoration uses the same constructor.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ProviderSettings {
    issuer: crate::IssuerId,
    client_id: crate::ClientId,
    secret_ref: String,
    redirect_uri: String,
    scopes: Vec<String>,
    claims: ClaimMapping,
    jit: bool,
}
impl TryFrom<ProviderSettingsInput> for ProviderSettings {
    type Error = FederationError;
    fn try_from(input: ProviderSettingsInput) -> Result<Self, Self::Error> {
        input.validate()?;
        Ok(Self {
            issuer: crate::IssuerId::parse(&input.issuer)
                .map_err(|_| FederationError::Configuration)?,
            client_id: crate::ClientId::parse(&input.client_id)
                .map_err(|_| FederationError::Configuration)?,
            secret_ref: input.secret_ref,
            redirect_uri: input.redirect_uri,
            scopes: input.scopes,
            claims: input.claims,
            jit: input.jit,
        })
    }
}
impl<'de> Deserialize<'de> for ProviderSettings {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Self::try_from(ProviderSettingsInput::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}
impl ProviderSettings {
    pub fn issuer(&self) -> &crate::IssuerId {
        &self.issuer
    }
    pub fn client_id(&self) -> &crate::ClientId {
        &self.client_id
    }
    pub fn secret_ref(&self) -> &str {
        &self.secret_ref
    }
    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }
    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }
    pub fn claims(&self) -> &ClaimMapping {
        &self.claims
    }
    pub fn jit(&self) -> bool {
        self.jit
    }
    pub fn input(&self) -> ProviderSettingsInput {
        ProviderSettingsInput {
            issuer: self.issuer.as_str().into(),
            client_id: self.client_id.as_str().into(),
            secret_ref: self.secret_ref.clone(),
            redirect_uri: self.redirect_uri.clone(),
            scopes: self.scopes.clone(),
            claims: self.claims.clone(),
            jit: self.jit,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ProviderView {
    pub id: ProviderId,
    pub version: i64,
    pub enabled: bool,
    pub revocation_epoch: i64,
    pub settings: ProviderSettings,
    #[serde(skip)]
    pub deployment_approval: Option<[u8; 32]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Purpose {
    Login,
    Reauthenticate,
    Link,
}

impl Purpose {
    pub fn code(self) -> u8 {
        match self {
            Self::Login => 0,
            Self::Reauthenticate => 1,
            Self::Link => 2,
        }
    }

    pub fn from_code(code: u8) -> Result<Self, FederationError> {
        match code {
            0 => Ok(Self::Login),
            1 => Ok(Self::Reauthenticate),
            2 => Ok(Self::Link),
            _ => Err(FederationError::Rejected),
        }
    }
}

/// Separate from all client and session secrets. One current key; rotation cancels pending flows.
pub struct StateSigner {
    key: Zeroizing<[u8; 32]>,
    origin: String,
}

pub struct StateLocator {
    tenant: TenantId,
    id: [u8; 32],
    purpose: Purpose,
}

impl StateLocator {
    pub fn tenant(&self) -> TenantId {
        self.tenant
    }

    pub fn id(&self) -> &[u8; 32] {
        &self.id
    }

    pub fn purpose(&self) -> Purpose {
        self.purpose
    }
}

impl StateSigner {
    pub fn new(key: [u8; 32], origin: &str) -> Result<Self, FederationError> {
        if key == [0; 32] || origin.is_empty() || origin.len() > 2048 {
            return Err(FederationError::Configuration);
        }

        Ok(Self {
            key: Zeroizing::new(key),
            origin: origin.into(),
        })
    }

    fn mac(&self, payload: &[u8]) -> Hmac<Sha256> {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(self.key.as_ref()).expect("HMAC accepts 32-byte keys");

        mac.update(b"rss-identity.oidc.state.v1\0");

        mac.update(&(self.origin.len() as u32).to_be_bytes());

        mac.update(self.origin.as_bytes());

        mac.update(payload);

        mac
    }

    pub fn issue(&self, tenant: TenantId, purpose: Purpose) -> Result<String, FederationError> {
        let mut payload = vec![1, purpose.code()];

        let tenant = Uuid::parse_str(&tenant.to_string()).map_err(|_| FederationError::Rejected)?;

        payload.extend_from_slice(tenant.as_bytes());

        let mut id = [0; 32];

        OsRng
            .try_fill_bytes(&mut id)
            .map_err(|_| FederationError::Unavailable)?;

        payload.extend_from_slice(&id);

        let tag = self.mac(&payload).finalize().into_bytes();

        payload.extend_from_slice(&tag);

        Ok(B64.encode(payload))
    }

    pub fn verify(&self, state: &str) -> Result<StateLocator, FederationError> {
        if state.len() != 110 {
            return Err(FederationError::Rejected);
        }

        let bytes = B64.decode(state).map_err(|_| FederationError::Rejected)?;

        if bytes.len() != 82 || B64.encode(&bytes) != state || bytes[0] != 1 {
            return Err(FederationError::Rejected);
        }

        self.mac(&bytes[..50])
            .verify_slice(&bytes[50..])
            .map_err(|_| FederationError::Rejected)?;

        let purpose = Purpose::from_code(bytes[1])?;

        let tenant = TenantId::parse(
            &Uuid::from_slice(&bytes[2..18])
                .map_err(|_| FederationError::Rejected)?
                .to_string(),
        )
        .map_err(|_| FederationError::Rejected)?;

        Ok(StateLocator {
            tenant,
            id: bytes[18..50]
                .try_into()
                .map_err(|_| FederationError::Rejected)?,
            purpose,
        })
    }
}

pub fn digest(value: &str) -> [u8; 32] {
    Sha256::digest(value.as_bytes()).into()
}

pub fn random_secret() -> Result<Zeroizing<String>, FederationError> {
    let mut bytes = [0; 32];

    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| FederationError::Unavailable)?;

    Ok(Zeroizing::new(B64.encode(bytes)))
}

/// Secret protocol material deliberately has no Debug/Serialize implementation.
pub struct ProtocolMaterial {
    pub state: Zeroizing<String>,
    pub nonce: Zeroizing<String>,
    pub verifier: Zeroizing<String>,
}

impl ProtocolMaterial {
    pub fn new(state: String) -> Result<Self, FederationError> {
        Ok(Self {
            state: Zeroizing::new(state),
            nonce: random_secret()?,
            verifier: random_secret()?,
        })
    }
}

/// Output of the trusted upstream adapter. Not a principal, session, or deserializable proof.
#[derive(Clone)]
pub struct UpstreamClaims {
    pub issuer: String,
    pub subject: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub groups: Vec<String>,
    pub assurance: crate::assurance::Assurance,
}

impl UpstreamClaims {
    pub fn validate(&self) -> Result<(), FederationError> {
        if self.subject.is_empty()
            || self.subject.len() > 255
            || self.subject.chars().any(char::is_control)
            || self.groups.len() > 100
            || self
                .groups
                .iter()
                .any(|s| s.is_empty() || s.len() > 256 || s.chars().any(char::is_control))
            || self
                .email
                .as_ref()
                .is_some_and(|s| s.len() > 320 || s.chars().any(char::is_control))
        {
            return Err(FederationError::Claims);
        }

        Ok(())
    }
}

pub type UpstreamFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, FederationError>> + Send + 'a>>;

/// Installed by trusted composition once. Tenant identity comes from the persisted flow.
pub trait UpstreamOidc: Send + Sync {
    /// Check only deployment-approved tenant, issuer, client, callback, secret reference
    /// and egress bindings. Synchronous and without network I/O or secret resolution.
    /// Called before saving configuration; an approved but unavailable secret is allowed.
    /// Return a stable profile identity; changing it fences attempts and revokes sessions.
    /// Reject unapproved bindings with a closed configuration/provider error.
    fn approve_configuration(
        &self,
        tenant: TenantId,
        config: &ProviderSettings,
    ) -> Result<[u8; 32], FederationError>;
    /// Check runtime usability, including deployment approval and availability of
    /// secrets/trust material. Synchronous: network checks belong to prepare/test/exchange.
    /// Called for protocol operations, never required for listing or disabling providers.
    fn validate(&self, tenant: TenantId, config: &ProviderSettings) -> Result<(), FederationError>;
    fn prepare<'a>(
        &'a self,
        tenant: TenantId,
        config: &'a ProviderSettings,
        material: &'a ProtocolMaterial,
        mode: crate::assurance::AuthenticationMode,
    ) -> UpstreamFuture<'a, String>;
    fn exchange<'a>(
        &'a self,
        tenant: TenantId,
        config: &'a ProviderSettings,
        material: ProtocolMaterial,
        code: Zeroizing<String>,
    ) -> UpstreamFuture<'a, UpstreamClaims>;
    fn test<'a>(
        &'a self,
        tenant: TenantId,
        config: &'a ProviderSettings,
    ) -> UpstreamFuture<'a, ConnectionReport>;
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderStage {
    Binding,
    Discovery,
    Jwks,
    Exchange,
    Claims,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderReason {
    UnapprovedBinding,
    MissingSecret,
    InvalidTrustAnchor,
    EgressDenied,
    TlsRejected,
    Unavailable,
    Timeout,
    InvalidResponse,
    IssuerMismatch,
    IssuerResponseUnsupported,
    CodeRejected,
    InvalidToken,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[error("provider {stage:?}: {reason:?}")]
pub struct ProviderFailure {
    pub stage: ProviderStage,
    pub reason: ProviderReason,
}
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ConnectionReport {
    pub checks: Vec<ProviderStage>,
    pub tls_verified: bool,
    pub authorization_response_issuer: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FederationError {
    #[error("invalid federation input")]
    Configuration,
    #[error("federation transaction rejected")]
    Rejected,
    #[error("identity linking conflict")]
    Conflict,
    #[error("federation configuration changed")]
    StaleConfiguration,
    #[error("federation provider limit reached")]
    ProviderLimitReached,
    #[error("federation provider unavailable")]
    Unavailable,
    #[error("federation claims rejected")]
    Claims,
    #[error(transparent)]
    Provider(#[from] ProviderFailure),
}
impl FederationError {
    pub fn provider(stage: ProviderStage, reason: ProviderReason) -> Self {
        Self::Provider(ProviderFailure { stage, reason })
    }
    pub fn diagnostic(self) -> ProviderFailure {
        match self {
            Self::Provider(f) => f,
            Self::Claims => ProviderFailure {
                stage: ProviderStage::Claims,
                reason: ProviderReason::InvalidToken,
            },
            Self::Unavailable => ProviderFailure {
                stage: ProviderStage::Discovery,
                reason: ProviderReason::Timeout,
            },
            _ => ProviderFailure {
                stage: ProviderStage::Binding,
                reason: ProviderReason::InvalidResponse,
            },
        }
    }
}
