//! Downstream protocol policy. ref: ory/hydra flow/consent_types.go @ 0b84568fffccf151dc5e6c7955fdfb738555bf4b.
use rss_request_context::TenantId;
use serde::{Deserialize, Serialize};
use std::{future::Future, pin::Pin};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DownstreamError {
    #[error("invalid downstream configuration or request")]
    Invalid,
    #[error("invalid protocol credential or binding")]
    Rejected,
    #[error("identity is not active")]
    Inactive,
    #[error("protocol unavailable")]
    Unavailable,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(i16)]
pub enum FlowState {
    AwaitingLogin = 0,
    LoginAccepting = 1,
    AwaitingConsent = 2,
    ConsentAccepting = 3,
    Active = 4,
    Revoking = 5,
}
impl FlowState {
    pub fn advance(self, next: Self) -> Result<Self, DownstreamError> {
        use FlowState::*;
        if matches!(
            (self, next),
            (AwaitingLogin, LoginAccepting)
                | (LoginAccepting, AwaitingConsent)
                | (AwaitingConsent, ConsentAccepting)
                | (ConsentAccepting, Active)
        ) || (self != Revoking && next == Revoking)
        {
            Ok(next)
        } else {
            Err(DownstreamError::Rejected)
        }
    }
    pub fn from_storage(value: i16) -> Result<Self, DownstreamError> {
        match value {
            0 => Ok(Self::AwaitingLogin),
            1 => Ok(Self::LoginAccepting),
            2 => Ok(Self::AwaitingConsent),
            3 => Ok(Self::ConsentAccepting),
            4 => Ok(Self::Active),
            5 => Ok(Self::Revoking),
            _ => Err(DownstreamError::Invalid),
        }
    }
}
/// Explicit deployment duration bounds, in seconds, matching Hydra's configuration.
#[derive(Debug, Clone, Copy)]
pub struct LifetimeLimits {
    pub request: i64,
    pub code: i64,
    pub access_token: i64,
    pub clock_skew: i64,
}
/// Named deployment input; converted once into an immutable validated registration.
#[derive(Debug, Clone)]
pub struct RegistrationInput {
    pub tenant: TenantId,
    pub client: String,
    pub audience: String,
    pub issuer: String,
    pub redirect: String,
    pub version: i64,
}
/// Required deployment bounds, matching Hydra's effective configuration. No unbounded fallback.
#[derive(Debug, Clone, Copy)]
pub struct Lifetimes {
    clock_skew: i64,
    request: i64,
    horizon: i64,
}
impl Lifetimes {
    pub fn new(limits: LifetimeLimits) -> Result<Self, DownstreamError> {
        let LifetimeLimits {
            request,
            code,
            access_token,
            clock_skew: skew,
        } = limits;
        if !(1..=300).contains(&request)
            || !(1..=600).contains(&code)
            || !(1..=86400).contains(&access_token)
            || !(0..=60).contains(&skew)
        {
            return Err(DownstreamError::Invalid);
        }
        Ok(Self {
            clock_skew: skew,
            request,
            horizon: request + code + access_token + skew + 60,
        })
    }
    pub fn clock_skew(self) -> i64 {
        self.clock_skew
    }
    pub fn request(self) -> i64 {
        self.request
    }
    pub fn horizon(self) -> i64 {
        self.horizon
    }
}
#[derive(Debug, Clone)]
pub struct Registration {
    tenant: TenantId,
    client: String,
    audience: String,
    issuer: String,
    redirect: String,
    version: i64,
}
impl Registration {
    pub fn new(input: RegistrationInput) -> Result<Self, DownstreamError> {
        let RegistrationInput {
            tenant,
            client,
            audience,
            issuer,
            redirect,
            version,
        } = input;
        let (client, audience, issuer, redirect) = (
            client.as_str(),
            audience.as_str(),
            issuer.as_str(),
            redirect.as_str(),
        );
        for value in [client, audience] {
            bounded(value, 256)?;
        }
        for value in [issuer, redirect] {
            let u = url::Url::parse(value).map_err(|_| DownstreamError::Invalid)?;
            if u.scheme() != "https"
                || u.host_str().is_none()
                || !u.username().is_empty()
                || u.password().is_some()
                || u.query().is_some()
                || u.fragment().is_some()
            {
                return Err(DownstreamError::Invalid);
            }
            bounded(value, 2048)?;
        }
        if version < 1 {
            return Err(DownstreamError::Invalid);
        }
        Ok(Self {
            tenant,
            client: client.into(),
            audience: audience.into(),
            issuer: issuer.into(),
            redirect: redirect.into(),
            version,
        })
    }
    pub fn fingerprint(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"identity.downstream.registration.v1");
        for value in [
            self.tenant.to_string(),
            self.client.clone(),
            self.audience.clone(),
            self.issuer.clone(),
            self.redirect.clone(),
            self.version.to_string(),
        ] {
            h.update((value.len() as u64).to_be_bytes());
            h.update(value.as_bytes());
        }
        h.finalize().into()
    }
    pub fn tenant(&self) -> TenantId {
        self.tenant
    }
    pub fn client(&self) -> &str {
        &self.client
    }
    pub fn audience(&self) -> &str {
        &self.audience
    }
    pub fn issuer(&self) -> &str {
        &self.issuer
    }
    pub fn redirect(&self) -> &str {
        &self.redirect
    }
    pub fn version(&self) -> i64 {
        self.version
    }
    pub fn check(&self, r: &Challenge) -> Result<(), DownstreamError> {
        if r.client != self.client
            || r.redirect != self.redirect
            || r.audiences != [self.audience.clone()]
            || r.scopes != ["openid"]
            || !r.pkce_s256
        {
            return Err(DownstreamError::Rejected);
        }
        bounded(&r.login_session_id, 512)?;
        Ok(())
    }
}
pub fn bounded(s: &str, max: usize) -> Result<(), DownstreamError> {
    if s.is_empty() || s.len() > max || s.trim() != s || s.chars().any(char::is_control) {
        Err(DownstreamError::Invalid)
    } else {
        Ok(())
    }
}
/// Secret protocol material, never serialized by the domain or printed in diagnostics.
pub struct Secret(Zeroizing<String>);
impl Secret {
    pub fn new(s: String) -> Result<Self, DownstreamError> {
        bounded(&s, 16384)?;
        Ok(Self(Zeroizing::new(s)))
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
}
impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}
/// Observation from the one injected trusted Hydra adapter, not an authentication proof.
pub struct Challenge {
    pub client: String,
    pub redirect: String,
    pub audiences: Vec<String>,
    pub scopes: Vec<String>,
    pub pkce_s256: bool,
    pub login_session_id: String,
    pub subject: Option<String>,
    pub consent_request_id: Option<String>,
    pub login_binding: Option<String>,
}
pub struct LoginDecision {
    pub grant_id: String,
    pub subject: String,
}
pub struct ConsentDecision {
    pub grant_id: String,
    pub audience: String,
}
#[derive(Debug)]
pub struct TokenObservation {
    pub active: bool,
    pub issuer: String,
    pub client: String,
    pub audiences: Vec<String>,
    pub subject: String,
    pub expires_at: i64,
    pub issued_at: i64,
    pub not_before: i64,
    pub grant_id: String,
    pub version: u64,
    pub token_use: String,
    pub token_type: String,
    pub scope: String,
}
pub type ProtocolFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, DownstreamError>> + Send + 'a>>;
/// Installed once by trusted composition. It does not own identity state or transactions.
pub trait DownstreamProtocol: Send + Sync {
    /// Exact configured issuer identity, checked against every registration at composition.
    fn issuer(&self) -> &str;
    fn login<'a>(&'a self, challenge: &'a Secret) -> ProtocolFuture<'a, Challenge>;
    fn consent<'a>(&'a self, challenge: &'a Secret) -> ProtocolFuture<'a, Challenge>;
    fn accept_login<'a>(
        &'a self,
        challenge: &'a Secret,
        decision: LoginDecision,
    ) -> ProtocolFuture<'a, Secret>;
    fn accept_consent<'a>(
        &'a self,
        challenge: &'a Secret,
        decision: ConsentDecision,
    ) -> ProtocolFuture<'a, Secret>;
    fn introspect<'a>(&'a self, credential: &'a Secret) -> ProtocolFuture<'a, TokenObservation>;
    fn revoke<'a>(&'a self, consent: Option<&'a str>, sid: &'a str) -> ProtocolFuture<'a, ()>;
}

/// Browser-only flow credential; distinct from the central session credential.
/// ```compile_fail
/// fn copy(s: rss_identity_core::downstream::BrowserBindingSecret) { let _ = s.clone(); }
/// ```
pub struct BrowserBindingSecret(Zeroizing<String>);
impl std::fmt::Debug for BrowserBindingSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BrowserBindingSecret(<redacted>)")
    }
}
impl BrowserBindingSecret {
    pub fn generate() -> Result<Self, DownstreamError> {
        use rand_core::RngCore;
        let mut bytes = Zeroizing::new([0u8; 32]);
        rand_core::OsRng
            .try_fill_bytes(bytes.as_mut())
            .map_err(|_| DownstreamError::Unavailable)?;
        let mut value = String::with_capacity(64);
        for byte in bytes.iter() {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            value.push(HEX[(byte >> 4) as usize] as char);
            value.push(HEX[(byte & 15) as usize] as char);
        }
        Ok(Self(Zeroizing::new(value)))
    }
    pub fn parse(value: String) -> Result<Self, DownstreamError> {
        let value = Zeroizing::new(value);
        if value.len() != 64
            || !value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(DownstreamError::Invalid);
        }
        Ok(Self(value))
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
    pub fn digest(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hash = Sha256::new();
        hash.update(b"rss-identity.downstream.browser.v1\0");
        hash.update(self.0.as_bytes());
        hash.finalize().into()
    }
}
