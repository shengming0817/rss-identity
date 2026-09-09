//! Tenant-bound OIDC adapter. One deployment approval binds credentials to their exact AS/client.
//! ref: openidconnect-rs src/verification/mod.rs @ b639b5d39eac6903238867aeb2b29326502e6b26.
#![deny(missing_docs)]
mod assurance;
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
    collections::BTreeMap,
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    time::Duration,
};
use zeroize::Zeroizing;
/// One indivisible deployment permission. No cross-product of separate allowlists is authorized.
#[derive(Clone)]
pub struct ApprovedProvider {
    /// Tenant allowed to use these credentials.
    pub tenant: TenantId,
    /// Exact issuer, including its realm/path.
    pub issuer: String,
    /// RP client registered at this issuer.
    pub client_id: String,
    /// Exact registered Identity callback.
    pub redirect_uri: String,
    /// Immutable versioned secret binding.
    pub secret_ref: String,
    /// Allowed addresses for this issuer, checked after resolution.
    pub addresses: Vec<IpNet>,
    /// This exact Keycloak client uses the approved password + TOTP LoA 2 flow.
    pub keycloak_totp: bool,
}
fn failure(stage: ProviderStage, reason: ProviderReason) -> FederationError {
    FederationError::provider(stage, reason)
}
fn approved<'a>(
    bindings: &'a [ApprovedProvider],
    tenant: TenantId,
    c: &ProviderSettings,
    loopback: bool,
) -> Result<&'a ApprovedProvider, FederationError> {
    let binding = bindings
        .iter()
        .find(|b| {
            b.tenant == tenant
                && b.issuer == c.issuer().as_str()
                && b.client_id == c.client_id().as_str()
                && b.redirect_uri == c.redirect_uri()
                && b.secret_ref == c.secret_ref()
        })
        .ok_or_else(|| failure(ProviderStage::Binding, ProviderReason::UnapprovedBinding))?;
    parse_url(&binding.issuer, loopback)?;
    parse_url(&binding.redirect_uri, loopback)?;
    if binding.addresses.is_empty() || binding.addresses.len() > 32 {
        return Err(failure(
            ProviderStage::Binding,
            ProviderReason::EgressDenied,
        ));
    }
    Ok(binding)
}
#[derive(Debug, thiserror::Error)]
#[error("destination outside approved network")]
struct EgressDenied;
struct Resolver {
    host: String,
    addresses: Vec<IpNet>,
}
impl reqwest::dns::Resolve for Resolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = self.host.clone();
        let allowed = self.addresses.clone();
        Box::pin(async move {
            if name.as_str() != host {
                return Err(EgressDenied.into());
            }
            let addresses: Vec<_> = tokio::net::lookup_host((host.as_str(), 0)).await?.collect();
            if addresses.is_empty()
                || addresses
                    .iter()
                    .any(|a| !allowed.iter().any(|n| n.contains(&a.ip())))
            {
                return Err(EgressDenied.into());
            }
            Ok(Box::new(addresses.into_iter()) as reqwest::dns::Addrs)
        })
    }
}
/// Immutable deployment bindings and secret values, independent of browser input.
pub struct HttpOidc {
    bindings: Vec<ApprovedProvider>,
    secrets: BTreeMap<String, Zeroizing<String>>,
    roots: Vec<reqwest::Certificate>,
    loopback: bool,
}
impl HttpOidc {
    /// Construct a production adapter. Every outbound request checks the full tenant/client tuple.
    pub fn new(
        bindings: Vec<ApprovedProvider>,
        secrets: BTreeMap<String, Zeroizing<String>>,
        ca_pem: Option<&[u8]>,
    ) -> Result<Self, FederationError> {
        Self::build(bindings, secrets, ca_pem, false)
    }
    /// Validate static deployment approval without loading client or login state secrets.
    pub fn approve(
        bindings: &[ApprovedProvider],
        tenant: TenantId,
        config: &ProviderSettings,
    ) -> Result<(), FederationError> {
        approved(bindings, tenant, config, false).map(|_| ())
    }
    /// Explicit fixture transport; the application callback still requires response issuer validation.
    #[cfg(any(test, feature = "test-support"))]
    pub fn for_loopback_test(
        bindings: Vec<ApprovedProvider>,
        secrets: BTreeMap<String, Zeroizing<String>>,
    ) -> Result<Self, FederationError> {
        Self::build(bindings, secrets, None, true)
    }
    fn build(
        bindings: Vec<ApprovedProvider>,
        secrets: BTreeMap<String, Zeroizing<String>>,
        ca: Option<&[u8]>,
        loopback: bool,
    ) -> Result<Self, FederationError> {
        if bindings.is_empty() || bindings.len() > 128 {
            return Err(failure(
                ProviderStage::Binding,
                ProviderReason::UnapprovedBinding,
            ));
        }
        for b in &bindings {
            let c = ProviderSettings::try_from(ProviderSettingsInput {
                issuer: b.issuer.clone(),
                client_id: b.client_id.clone(),
                secret_ref: b.secret_ref.clone(),
                redirect_uri: b.redirect_uri.clone(),
                scopes: vec!["openid".into()],
                claims: ClaimMapping {
                    email: None,
                    groups: None,
                },
                jit: false,
            })?;
            approved(&bindings, b.tenant, &c, loopback)?;
        }
        if secrets
            .iter()
            .any(|(k, v)| !k.contains('@') || v.is_empty() || v.len() > 4096)
        {
            return Err(failure(
                ProviderStage::Binding,
                ProviderReason::MissingSecret,
            ));
        }
        let roots = ca
            .map(|p| {
                reqwest::Certificate::from_pem(p)
                    .map(|c| vec![c])
                    .map_err(|_| {
                        failure(ProviderStage::Binding, ProviderReason::InvalidTrustAnchor)
                    })
            })
            .transpose()?
            .unwrap_or_default();
        Ok(Self {
            bindings,
            secrets,
            roots,
            loopback,
        })
    }
    fn transport(
        &self,
        tenant: TenantId,
        c: &ProviderSettings,
    ) -> Result<Transport, FederationError> {
        self.validate(tenant, c)?;
        let rule = approved(&self.bindings, tenant, c, self.loopback)?;
        let u = parse_url(c.issuer().as_str(), self.loopback)?;
        let origin = u.origin().ascii_serialization();
        let host = u
            .host_str()
            .ok_or(FederationError::Configuration)?
            .trim_matches(['[', ']'])
            .to_owned();
        if let Ok(ip) = host.parse::<IpAddr>()
            && !rule.addresses.iter().any(|n| n.contains(&ip))
        {
            return Err(failure(
                ProviderStage::Binding,
                ProviderReason::EgressDenied,
            ));
        }
        let mut builder = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(5))
            .connect_timeout(Duration::from_secs(3))
            .dns_resolver(Arc::new(Resolver {
                host,
                addresses: rule.addresses.clone(),
            }));
        for root in &self.roots {
            builder = builder.add_root_certificate(root.clone());
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
    ) -> Result<(Metadata, Transport), FederationError> {
        let transport = self.transport(tenant, c)?;
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
    fn approve_configuration(
        &self,
        tenant: TenantId,
        c: &ProviderSettings,
    ) -> Result<(), FederationError> {
        approved(&self.bindings, tenant, c, self.loopback).map(|_| ())
    }
    fn validate(&self, tenant: TenantId, c: &ProviderSettings) -> Result<(), FederationError> {
        approved(&self.bindings, tenant, c, self.loopback)?;
        if !self.secrets.contains_key(c.secret_ref()) {
            return Err(failure(
                ProviderStage::Binding,
                ProviderReason::MissingSecret,
            ));
        }
        Ok(())
    }
    fn prepare<'a>(
        &'a self,
        tenant: TenantId,
        c: &'a ProviderSettings,
        m: &'a ProtocolMaterial,
        mode: AuthenticationMode,
    ) -> UpstreamFuture<'a, String> {
        Box::pin(async move {
            let binding = approved(&self.bindings, tenant, c, self.loopback)?;
            if mode == AuthenticationMode::StepUp && !binding.keycloak_totp {
                return Err(FederationError::Configuration);
            }
            let (metadata, _) = self.discover(tenant, c).await?;

            let client = CoreClient::from_provider_metadata(
                metadata,
                ClientId::new(c.client_id().as_str().to_owned()),
                Some(ClientSecret::new(self.secrets[c.secret_ref()].to_string())),
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
        m: ProtocolMaterial,
        code: Zeroizing<String>,
    ) -> UpstreamFuture<'a, UpstreamClaims> {
        Box::pin(async move {
            if code.is_empty() || code.len() > 4096 {
                return Err(FederationError::Rejected);
            }

            let (metadata, transport) = self.discover(tenant, c).await?;

            let client_id = ClientId::new(c.client_id().as_str().to_owned());

            let client = CoreClient::from_provider_metadata(
                metadata,
                client_id.clone(),
                Some(ClientSecret::new(self.secrets[c.secret_ref()].to_string())),
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

            let mut groups = match c.claims().groups.as_ref().and_then(|k| all.get(k)) {
                None | Some(serde_json::Value::Null) => vec![],
                Some(serde_json::Value::Array(v)) => v
                    .iter()
                    .map(|v| v.as_str().map(str::to_owned).ok_or(FederationError::Claims))
                    .collect::<Result<Vec<_>, _>>()?,
                _ => return Err(FederationError::Claims),
            };

            groups.sort();

            groups.dedup();

            let value = UpstreamClaims {
                issuer: c.issuer().as_str().to_owned(),
                subject: claims.subject().as_str().to_owned(),
                email,
                email_verified: c.claims().email.as_deref() == Some("email")
                    && claims.email_verified() == Some(true),
                groups,
                assurance: assurance::normalize(
                    claims.auth_time().map(|v| v.timestamp()),
                    claims.auth_context_ref().map(|v| v.as_str()),
                    claims
                        .auth_method_refs()
                        .map(|v| v.iter().map(|v| v.as_str().to_owned()).collect())
                        .unwrap_or_default(),
                    approved(&self.bindings, tenant, c, self.loopback)?.keycloak_totp,
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
    ) -> UpstreamFuture<'a, ConnectionReport> {
        Box::pin(async move {
            let (metadata, _) = self.discover(tenant, c).await?;
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

#[cfg(test)]
mod tests;
