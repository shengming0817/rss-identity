//! Tenant-bound OIDC adapter with versioned credentials and independent trusted MFA profiles.
//! ref: openidconnect-rs src/verification/mod.rs @ b639b5d39eac6903238867aeb2b29326502e6b26.
#![deny(missing_docs)]
mod assurance;
mod egress;
pub use ipnet::IpNet;
use openidconnect::{
    AsyncHttpClient, AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    HttpRequest, HttpResponse, IssuerUrl, Nonce, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl,
    Scope, TokenResponse, core::*,
};
use reqwest::Url;
use rss_identity_core::{assurance::AuthenticationMode, federation::*};
use rss_request_context::TenantId;
use serde::{Deserialize, Serialize};
use std::{
    sync::atomic::{AtomicU8, Ordering},
    time::Duration,
};
use zeroize::Zeroizing;
/// Host-approved interpretation of verified authentication facts. Not IdP admission.
#[derive(Clone)]
pub struct TrustedAssuranceProfile {
    /// Exact tenant owning this authentication policy.
    pub tenant: TenantId,
    /// Exact issuer owning the verified token.
    pub issuer: String,
    /// Registered RP client.
    pub client_id: String,
    /// The operator verified this client uses the Keycloak password/TOTP LoA 2 flow.
    pub keycloak_totp: bool,
}
fn failure(stage: ProviderStage, reason: ProviderReason) -> FederationError {
    FederationError::provider(stage, reason)
}
#[derive(Debug, thiserror::Error)]
#[error("invalid protocol destination")]
struct EgressDenied;
/// Protocol transport with tenant credentials supplied for each exact provider version.
pub struct HttpOidc {
    profiles: Vec<TrustedAssuranceProfile>,
    loopback: bool,
}
impl HttpOidc {
    /// Production uses HTTPS, certificate verification and only vetted public unicast addresses.
    /// Every DNS answer must be public; special/private IP literals are rejected at binding.
    /// Empty assurance profile sets are valid and do not relax the destination policy.
    pub fn new(profiles: Vec<TrustedAssuranceProfile>) -> Result<Self, FederationError> {
        Self::build(profiles, false)
    }
    /// Explicit loopback fixture (HTTP or HTTPS). Never enabled by production configuration.
    #[cfg(any(test, feature = "test-support"))]
    pub fn for_loopback_test(
        profiles: Vec<TrustedAssuranceProfile>,
    ) -> Result<Self, FederationError> {
        Self::build(profiles, true)
    }
    fn build(
        profiles: Vec<TrustedAssuranceProfile>,
        loopback: bool,
    ) -> Result<Self, FederationError> {
        if profiles.len() > 128 {
            return Err(FederationError::Configuration);
        }
        let mut seen = std::collections::BTreeSet::new();
        for p in &profiles {
            parse_url(&p.issuer, loopback)?;
            if p.client_id.is_empty()
                || p.client_id.len() > 256
                || !seen.insert((p.tenant.to_string(), p.issuer.clone(), p.client_id.clone()))
            {
                return Err(FederationError::Configuration);
            }
        }
        Ok(Self { profiles, loopback })
    }
    fn trusted(&self, tenant: TenantId, c: &ProviderSettings) -> bool {
        self.profiles.iter().any(|p| {
            p.tenant == tenant
                && p.issuer == c.issuer().as_str()
                && p.client_id == c.client_id().as_str()
                && p.keycloak_totp
        })
    }
    fn transport(
        &self,
        tenant: TenantId,
        c: &ProviderSettings,
        credentials: &ProviderCredentials,
    ) -> Result<Transport, FederationError> {
        self.validate(tenant, c, credentials)?;
        let origin = parse_url(c.issuer().as_str(), self.loopback)?
            .origin()
            .ascii_serialization();
        let mut builder = reqwest::Client::builder()
            .no_proxy()
            .dns_resolver(std::sync::Arc::new(egress::VettedResolver::new(
                self.loopback,
            )))
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(5))
            .connect_timeout(Duration::from_secs(3));
        for root in certificates(credentials)? {
            builder = builder.add_root_certificate(root);
        }
        Ok(Transport {
            origin,
            http: builder
                .build()
                .map_err(|_| failure(ProviderStage::Binding, ProviderReason::InvalidResponse))?,
            requests: AtomicU8::new(0),
            phase: AtomicU8::new(0),
        })
    }
    async fn discover(
        &self,
        tenant: TenantId,
        c: &ProviderSettings,
        credentials: &ProviderCredentials,
    ) -> Result<(Metadata, Transport), FederationError> {
        let transport = self.transport(tenant, c, credentials)?;
        let metadata = Metadata::discover_async(
            IssuerUrl::new(c.issuer().as_str().into())
                .map_err(|_| FederationError::Configuration)?,
            &transport,
        )
        .await
        .map_err(|error| match error {
            openidconnect::DiscoveryError::Request(error) => error,
            openidconnect::DiscoveryError::Validation(_) => {
                failure(ProviderStage::Discovery, ProviderReason::IssuerMismatch)
            }
            _ => failure(transport.stage(), ProviderReason::InvalidResponse),
        })?;
        if metadata
            .authorization_endpoint()
            .url()
            .origin()
            .ascii_serialization()
            != transport.origin
            || metadata
                .token_endpoint()
                .is_none_or(|u| u.url().origin().ascii_serialization() != transport.origin)
        {
            return Err(failure(
                ProviderStage::Discovery,
                ProviderReason::EgressDenied,
            ));
        }
        Ok((metadata, transport))
    }
}
fn certificates(
    credentials: &ProviderCredentials,
) -> Result<Vec<reqwest::Certificate>, FederationError> {
    match credentials.ca_pem() {
        None => Ok(Vec::new()),
        Some(pem) => {
            let roots = reqwest::Certificate::from_pem_bundle(pem.as_bytes())
                .map_err(|_| failure(ProviderStage::Binding, ProviderReason::InvalidTrustAnchor))?;
            if roots.is_empty() || roots.len() > 16 {
                return Err(failure(
                    ProviderStage::Binding,
                    ProviderReason::InvalidTrustAnchor,
                ));
            }
            Ok(roots)
        }
    }
}
fn parse_url(value: &str, loopback: bool) -> Result<Url, FederationError> {
    let u = Url::parse(value).map_err(|_| FederationError::Configuration)?;
    let local = loopback
        && u.scheme() == "http"
        && matches!(u.host_str(), Some("127.0.0.1") | Some("localhost"));
    if (!local && u.scheme() != "https")
        || u.host_str().is_none()
        || !u.username().is_empty()
        || u.password().is_some()
        || u.fragment().is_some()
        || u.query().is_some()
    {
        return Err(FederationError::Configuration);
    }
    let host = u.host_str().unwrap();
    if host
        .trim_matches(['[', ']'])
        .parse::<std::net::IpAddr>()
        .is_ok_and(|ip| !egress::allowed(ip, loopback))
    {
        return Err(failure(
            ProviderStage::Binding,
            ProviderReason::EgressDenied,
        ));
    }
    Ok(u)
}
struct Transport {
    http: reqwest::Client,
    origin: String,
    requests: AtomicU8,
    phase: AtomicU8,
}
impl Transport {
    fn stage(&self) -> ProviderStage {
        match self.phase.load(Ordering::Relaxed) {
            0 => ProviderStage::Discovery,
            1 => ProviderStage::Jwks,
            _ => ProviderStage::Exchange,
        }
    }
    fn request_error(&self, error: reqwest::Error) -> FederationError {
        let mut cause: Option<&(dyn std::error::Error + 'static)> = Some(&error);
        while let Some(value) = cause {
            if value.is::<EgressDenied>() {
                return failure(self.stage(), ProviderReason::EgressDenied);
            }
            if value.is::<rustls::Error>() {
                return failure(self.stage(), ProviderReason::TlsRejected);
            }
            cause = if let Some(io) = value.downcast_ref::<std::io::Error>() {
                io.get_ref()
                    .map(|v| v as &(dyn std::error::Error + 'static))
                    .or_else(|| value.source())
            } else {
                value.source()
            };
        }
        failure(
            self.stage(),
            if error.is_timeout() {
                ProviderReason::Timeout
            } else {
                ProviderReason::Unavailable
            },
        )
    }
}
impl<'a> AsyncHttpClient<'a> for Transport {
    type Error = FederationError;
    type Future = UpstreamFuture<'a, HttpResponse>;
    fn call(&'a self, request: HttpRequest) -> Self::Future {
        Box::pin(async move {
            let previous = self.requests.fetch_add(1, Ordering::Relaxed);
            self.phase.store(
                if request.method() == openidconnect::http::Method::POST {
                    2
                } else if previous == 0 {
                    0
                } else {
                    1
                },
                Ordering::Relaxed,
            );
            let u = Url::parse(&request.uri().to_string())
                .map_err(|_| failure(self.stage(), ProviderReason::InvalidResponse))?;
            if u.origin().ascii_serialization() != self.origin
                || !u.username().is_empty()
                || u.password().is_some()
            {
                return Err(failure(self.stage(), ProviderReason::EgressDenied));
            }
            let mut response = self
                .http
                .execute(
                    request
                        .try_into()
                        .map_err(|_| failure(self.stage(), ProviderReason::InvalidResponse))?,
                )
                .await
                .map_err(|e| self.request_error(e))?;
            let status = response.status();
            if status.is_server_error() || status.as_u16() == 429 {
                return Err(failure(self.stage(), ProviderReason::Unavailable));
            }
            let headers = response.headers().clone();
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(|e| self.request_error(e))? {
                if bytes.len().saturating_add(chunk.len()) > 1024 * 1024 {
                    return Err(failure(self.stage(), ProviderReason::InvalidResponse));
                }
                bytes.extend_from_slice(&chunk);
            }
            let mut result = HttpResponse::new(bytes);
            *result.status_mut() = status;
            *result.headers_mut() = headers;
            Ok(result)
        })
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct DiscoveryExtra {
    #[serde(default)]
    authorization_response_iss_parameter_supported: bool,
}
impl openidconnect::AdditionalProviderMetadata for DiscoveryExtra {}
type Metadata = openidconnect::ProviderMetadata<
    DiscoveryExtra,
    CoreAuthDisplay,
    CoreClientAuthMethod,
    CoreClaimName,
    CoreClaimType,
    CoreGrantType,
    CoreJweContentEncryptionAlgorithm,
    CoreJweKeyManagementAlgorithm,
    CoreJsonWebKey,
    CoreResponseMode,
    CoreResponseType,
    CoreSubjectIdentifierType,
>;
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Extra {
    #[serde(flatten)]
    values: serde_json::Map<String, serde_json::Value>,
}

impl openidconnect::AdditionalClaims for Extra {}

type MappedToken = openidconnect::IdToken<
    Extra,
    openidconnect::core::CoreGenderClaim,
    openidconnect::core::CoreJweContentEncryptionAlgorithm,
    openidconnect::core::CoreJwsSigningAlgorithm,
>;

fn verify<'a>(
    token: &'a MappedToken,
    verifier: &openidconnect::core::CoreIdTokenVerifier<'_>,
    nonce: &Nonce,
    client: &ClientId,
) -> Result<
    &'a openidconnect::IdTokenClaims<Extra, openidconnect::core::CoreGenderClaim>,
    FederationError,
> {
    let claims = token
        .claims(verifier, nonce)
        .map_err(|_| FederationError::Claims)?;

    if claims.subject().as_str().is_empty()
        || claims.authorized_party().is_some_and(|v| v != client)
    {
        return Err(FederationError::Claims);
    }

    Ok(claims)
}

impl UpstreamOidc for HttpOidc {
    fn assurance_profile(&self, tenant: TenantId, c: &ProviderSettings) -> AssuranceProfile {
        let approved = self.trusted(tenant, c);
        AssuranceProfile {
            fingerprint: assurance::profile_identity(approved),
            supports_step_up: approved,
        }
    }
    fn validate(
        &self,
        _tenant: TenantId,
        c: &ProviderSettings,
        credentials: &ProviderCredentials,
    ) -> Result<(), FederationError> {
        parse_url(c.issuer().as_str(), self.loopback)?;
        parse_url(c.redirect_uri(), self.loopback)?;
        let roots = certificates(credentials)?;
        if !roots.is_empty() {
            let mut builder = reqwest::Client::builder().no_proxy();
            for root in roots {
                builder = builder.add_root_certificate(root);
            }
            builder
                .build()
                .map_err(|_| failure(ProviderStage::Binding, ProviderReason::InvalidTrustAnchor))?;
        }
        Ok(())
    }
    fn prepare<'a>(
        &'a self,
        tenant: TenantId,
        c: &'a ProviderSettings,
        credentials: &'a ProviderCredentials,
        m: &'a ProtocolMaterial,
        mode: AuthenticationMode,
    ) -> UpstreamFuture<'a, String> {
        Box::pin(async move {
            if mode == AuthenticationMode::StepUp
                && !self.assurance_profile(tenant, c).supports_step_up
            {
                return Err(FederationError::Configuration);
            }
            let (metadata, _) = self.discover(tenant, c, credentials).await?;

            let client = CoreClient::from_provider_metadata(
                metadata,
                ClientId::new(c.client_id().as_str().to_owned()),
                Some(ClientSecret::new(credentials.client_secret().to_string())),
            )
            .set_redirect_uri(
                RedirectUrl::new(c.redirect_uri().to_owned())
                    .map_err(|_| FederationError::Configuration)?,
            );

            let state = m.state.to_string();

            let nonce = m.nonce.to_string();

            let mut request = client
                .authorize_url(
                    AuthenticationFlow::<openidconnect::core::CoreResponseType>::AuthorizationCode,
                    move || CsrfToken::new(state),
                    move || Nonce::new(nonce),
                )
                .set_pkce_challenge(PkceCodeChallenge::from_code_verifier_sha256(
                    &PkceCodeVerifier::new(m.verifier.to_string()),
                ));

            for scope in c.scopes() {
                if scope != "openid" {
                    request = request.add_scope(Scope::new(scope.clone()));
                }
            }

            if mode != AuthenticationMode::Login {
                request = request
                    .add_prompt(CoreAuthPrompt::Login)
                    .set_max_age(Duration::ZERO);
            }
            if mode == AuthenticationMode::StepUp {
                request =
                    request.add_auth_context_value(openidconnect::AuthenticationContextClass::new(
                        assurance::KEYCLOAK_TOTP_ACR.into(),
                    ));
            }

            Ok(request.url().0.to_string())
        })
    }

    fn exchange<'a>(
        &'a self,
        tenant: TenantId,
        c: &'a ProviderSettings,
        credentials: &'a ProviderCredentials,
        m: ProtocolMaterial,
        code: Zeroizing<String>,
    ) -> UpstreamFuture<'a, UpstreamClaims> {
        Box::pin(async move {
            if code.is_empty() || code.len() > 4096 {
                return Err(FederationError::Rejected);
            }

            let (metadata, transport) = self.discover(tenant, c, credentials).await?;

            let client_id = ClientId::new(c.client_id().as_str().to_owned());

            let client = CoreClient::from_provider_metadata(
                metadata,
                client_id.clone(),
                Some(ClientSecret::new(credentials.client_secret().to_string())),
            )
            .set_redirect_uri(
                RedirectUrl::new(c.redirect_uri().to_owned())
                    .map_err(|_| FederationError::Configuration)?,
            );

            let token = client
                .exchange_code(AuthorizationCode::new(code.to_string()))
                .map_err(|_| FederationError::Configuration)?
                .set_pkce_verifier(PkceCodeVerifier::new(m.verifier.to_string()))
                .request_async(&transport)
                .await
                .map_err(|e| match e {
                    openidconnect::RequestTokenError::Request(error) => error,
                    openidconnect::RequestTokenError::ServerResponse(_) => {
                        failure(ProviderStage::Exchange, ProviderReason::CodeRejected)
                    }
                    _ => failure(ProviderStage::Exchange, ProviderReason::InvalidResponse),
                })?;

            let raw = token.id_token().ok_or(FederationError::Claims)?;

            let token: MappedToken =
                serde_json::from_value(serde_json::Value::String(raw.to_string()))
                    .map_err(|_| FederationError::Claims)?;

            let claims = verify(
                &token,
                &client.id_token_verifier(),
                &Nonce::new(m.nonce.to_string()),
                &client_id,
            )?;

            let all = serde_json::to_value(claims).map_err(|_| FederationError::Claims)?;

            let email = match c.claims().email.as_ref().and_then(|k| all.get(k)) {
                None | Some(serde_json::Value::Null) => None,
                Some(serde_json::Value::String(s)) => Some(s.clone()),
                _ => return Err(FederationError::Claims),
            };

            let groups = mapped_groups(c.claims().groups.as_deref(), &all)?;

            let value = UpstreamClaims {
                issuer: c.issuer().as_str().to_owned(),
                subject: claims.subject().as_str().to_owned(),
                email,
                email_verified: c.claims().email.as_deref() == Some("email")
                    && claims.email_verified() == Some(true),
                groups,
                department: mapped_department(
                    c.claims().department.as_ref().map(|d| d.claim()),
                    &all,
                )?,
                issued_at: claims.issue_time().timestamp(),
                expires_at: claims.expiration().timestamp(),
                assurance: assurance::normalize(
                    claims.auth_time().map(|v| v.timestamp()),
                    claims.auth_context_ref().map(|v| v.as_str()),
                    claims
                        .auth_method_refs()
                        .map(|v| v.iter().map(|v| v.as_str().to_owned()).collect())
                        .unwrap_or_default(),
                    self.trusted(tenant, c),
                )?,
            };

            value.validate()?;

            Ok(value)
        })
    }

    fn test<'a>(
        &'a self,
        tenant: TenantId,
        c: &'a ProviderSettings,
        credentials: &'a ProviderCredentials,
    ) -> UpstreamFuture<'a, ConnectionReport> {
        Box::pin(async move {
            let (metadata, _) = self.discover(tenant, c, credentials).await?;
            if !metadata
                .additional_metadata()
                .authorization_response_iss_parameter_supported
            {
                return Err(failure(
                    ProviderStage::Discovery,
                    ProviderReason::IssuerResponseUnsupported,
                ));
            }
            Ok(ConnectionReport {
                checks: vec![
                    ProviderStage::Binding,
                    ProviderStage::Discovery,
                    ProviderStage::Jwks,
                ],
                tls_verified: c.issuer().as_str().starts_with("https://"),
                authorization_response_issuer: true,
            })
        })
    }
}

fn mapped_groups(
    claim: Option<&str>,
    claims: &serde_json::Value,
) -> Result<rss_identity_core::groups::UpstreamGroups, FederationError> {
    use rss_identity_core::groups::UpstreamGroups;
    match claim {
        None => Ok(UpstreamGroups::NotConfigured),
        Some(key) => match claims.get(key) {
            None | Some(serde_json::Value::Null) => Ok(UpstreamGroups::Missing),
            Some(serde_json::Value::Array(values)) => UpstreamGroups::present(
                values
                    .iter()
                    .map(|v| v.as_str().map(str::to_owned).ok_or(FederationError::Claims))
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            _ => Err(FederationError::Claims),
        },
    }
}

fn mapped_department(
    claim: Option<&str>,
    claims: &serde_json::Value,
) -> Result<rss_identity_core::department::UpstreamDepartment, FederationError> {
    use rss_identity_core::department::{DepartmentId, UpstreamDepartment};
    match claim {
        None => Ok(UpstreamDepartment::NotConfigured),
        Some(key) => match claims.get(key) {
            None => Ok(UpstreamDepartment::Missing),
            Some(serde_json::Value::Null) => Ok(UpstreamDepartment::NoDepartment),
            Some(serde_json::Value::String(value)) => Ok(UpstreamDepartment::Present(
                DepartmentId::new(value.clone())?,
            )),
            _ => Err(FederationError::Claims),
        },
    }
}

#[cfg(test)]
mod tests;
