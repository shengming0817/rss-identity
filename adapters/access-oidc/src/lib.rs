//! OIDC client seam. I05 owns persistent, tenant-bound login transactions and JIT.
#![deny(missing_docs)]
use openidconnect::{
    AsyncHttpClient, AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    HttpRequest, HttpResponse, IssuerUrl, Nonce, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl,
    Scope, TokenResponse,
    core::{CoreClient, CoreProviderMetadata},
};
use reqwest::Url;
use std::{future::Future, pin::Pin, time::Duration};

/// Explicit trusted operator configuration; no Debug representation exposes the secret.
pub struct ProviderConfig {
    issuer: IssuerUrl,
    client: ClientId,
    secret: ClientSecret,
    redirect: RedirectUrl,
}
impl ProviderConfig {
    /// Validate trusted operator configuration: HTTPS issuer and exact HTTPS callback,
    /// nonempty client/secret, no userinfo or fragments. Returns Configuration on rejection.
    /// This does not perform discovery or authenticate any browser input.
    pub fn new(
        issuer: &str,
        client: &str,
        secret: &str,
        redirect: &str,
    ) -> Result<Self, OidcError> {
        Self::parse(issuer, client, secret, redirect, false)
    }
    #[cfg(feature = "test-support")]
    /// Isolated loopback fixture only. Does not relax the production constructor.
    pub fn for_loopback_test(
        issuer: &str,
        client: &str,
        secret: &str,
        redirect: &str,
    ) -> Result<Self, OidcError> {
        Self::parse(issuer, client, secret, redirect, true)
    }
    fn parse(
        issuer: &str,
        client: &str,
        secret: &str,
        redirect: &str,
        loopback: bool,
    ) -> Result<Self, OidcError> {
        for s in [issuer, redirect] {
            let u = Url::parse(s).map_err(|_| OidcError::Configuration)?;
            let local = loopback
                && u.scheme() == "http"
                && matches!(u.host_str(), Some("127.0.0.1") | Some("localhost"));
            if (!local && u.scheme() != "https")
                || u.host_str().is_none()
                || !u.username().is_empty()
                || u.password().is_some()
                || u.fragment().is_some()
            {
                return Err(OidcError::Configuration);
            }
        }
        if client.trim().is_empty()
            || client.trim() != client
            || client.chars().any(char::is_control)
            || secret.is_empty()
            || Url::parse(issuer)
                .map_err(|_| OidcError::Configuration)?
                .query()
                .is_some()
        {
            return Err(OidcError::Configuration);
        }
        Ok(Self {
            issuer: IssuerUrl::new(issuer.into()).map_err(|_| OidcError::Configuration)?,
            client: ClientId::new(client.into()),
            secret: ClientSecret::new(secret.into()),
            redirect: RedirectUrl::new(redirect.into()).map_err(|_| OidcError::Configuration)?,
        })
    }
}

/// All back-channel destinations must remain on the configured issuer origin.
/// Cross-origin providers require an explicit future policy, not discovery-driven trust expansion.
struct Transport {
    http: reqwest::Client,
    origin: String,
}
impl Transport {
    fn new(origin: String) -> Result<Self, OidcError> {
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(5))
            .connect_timeout(Duration::from_secs(3))
            .build()
            .map_err(|_| OidcError::Configuration)?;
        Ok(Self { http, origin })
    }
}
impl<'c> AsyncHttpClient<'c> for Transport {
    type Error = OidcError;
    type Future = Pin<Box<dyn Future<Output = Result<HttpResponse, OidcError>> + Send + 'c>>;
    fn call(&'c self, request: HttpRequest) -> Self::Future {
        Box::pin(async move {
            let url =
                Url::parse(&request.uri().to_string()).map_err(|_| OidcError::Configuration)?;
            if url.origin().ascii_serialization() != self.origin {
                return Err(OidcError::Configuration);
            }
            let request: reqwest::Request =
                request.try_into().map_err(|_| OidcError::Configuration)?;
            let mut received = self
                .http
                .execute(request)
                .await
                .map_err(|_| OidcError::Unavailable)?;
            let status = received.status();
            if status.is_server_error() || status.as_u16() == 429 {
                return Err(OidcError::Unavailable);
            }
            let headers = received.headers().clone();
            let mut bytes = Vec::new();
            while let Some(chunk) = received.chunk().await.map_err(|_| OidcError::Unavailable)? {
                if bytes.len().saturating_add(chunk.len()) > 1024 * 1024 {
                    return Err(OidcError::Unavailable);
                }
                bytes.extend_from_slice(&chunk);
            }
            let mut response = HttpResponse::new(bytes);
            *response.status_mut() = status;
            *response.headers_mut() = headers;
            Ok(response)
        })
    }
}

/// Discovered, origin-constrained OIDC client for one trusted configuration.
pub struct Provider {
    config: ProviderConfig,
    metadata: CoreProviderMetadata,
    transport: Transport,
}
/// Single-use in-memory attempt; I05 must add durable/browser/tenant/config-version binding.
/// Dropping or consuming an attempt never allows a second exchange through this value.
pub struct LoginAttempt {
    nonce: Nonce,
    state: CsrfToken,
    verifier: PkceCodeVerifier,
    binding: (String, String, String),
}
/// A validated upstream subject, not an Access principal or a trusted product context.
pub struct UpstreamSubject {
    issuer: String,
    subject: String,
}
impl UpstreamSubject {
    /// Exact verified upstream issuer; combine with subject and tenant/provider identity.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }
    /// Verified upstream subject, never an Access principal or an email-based association.
    pub fn subject(&self) -> &str {
        &self.subject
    }
}
impl Provider {
    /// Discover from trusted configuration; back-channel requests stay on issuer origin,
    /// disallow redirects and enforce time/size bounds. External authorization endpoints fail.
    /// Transport failures and HTTP 429/5xx return Unavailable; invalid discovery returns
    /// Discovery. Configuration reports invalid local policy. Errors omit provider payloads.
    pub async fn discover(config: ProviderConfig) -> Result<Self, OidcError> {
        let origin = config.issuer.url().origin().ascii_serialization();
        let transport = Transport::new(origin)?;
        let metadata = CoreProviderMetadata::discover_async(config.issuer.clone(), &transport)
            .await
            .map_err(|error| match error {
                openidconnect::DiscoveryError::Request(OidcError::Unavailable) => {
                    OidcError::Unavailable
                }
                _ => OidcError::Discovery,
            })?;
        if metadata
            .authorization_endpoint()
            .url()
            .origin()
            .ascii_serialization()
            != transport.origin
        {
            return Err(OidcError::Configuration);
        }
        Ok(Self {
            config,
            metadata,
            transport,
        })
    }
    fn binding(&self) -> (String, String, String) {
        (
            self.config.issuer.as_str().into(),
            self.config.client.as_str().into(),
            self.config.redirect.as_str().into(),
        )
    }
    /// Generate a new authorization URL and single-use state/nonce/S256 attempt.
    /// The caller must bind this attempt to its browser, tenant and configuration version;
    /// this in-memory seam supplies no durable login transaction or Access authentication.
    pub fn begin(&self) -> (Url, LoginAttempt) {
        let client = CoreClient::from_provider_metadata(
            self.metadata.clone(),
            self.config.client.clone(),
            Some(self.config.secret.clone()),
        )
        .set_redirect_uri(self.config.redirect.clone());
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let (url, state, nonce) = client
            .authorize_url(
                AuthenticationFlow::<openidconnect::core::CoreResponseType>::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .add_scope(Scope::new("profile".into()))
            .set_pkce_challenge(challenge)
            .url();
        (
            url,
            LoginAttempt {
                nonce,
                state,
                verifier,
                binding: self.binding(),
            },
        )
    }
    /// Consume the attempt, compare state and provider binding, exchange code using PKCE,
    /// then verify ID-token issuer/audience/nonce/expiry/authorized party before returning subject.
    /// State mismatch returns State; network/429/5xx returns Unavailable; protocol rejection
    /// returns Exchange; missing/invalid ID token returns Claims. No provider text is exposed.
    /// Even an Unavailable result consumes the attempt: start a fresh login, never replay code.
    pub async fn finish(
        &self,
        attempt: LoginAttempt,
        returned_state: &str,
        code: String,
    ) -> Result<UpstreamSubject, OidcError> {
        if attempt.binding != self.binding()
            || !constant_time_eq::constant_time_eq(
                attempt.state.secret().as_bytes(),
                returned_state.as_bytes(),
            )
        {
            return Err(OidcError::State);
        }
        let client = CoreClient::from_provider_metadata(
            self.metadata.clone(),
            self.config.client.clone(),
            Some(self.config.secret.clone()),
        )
        .set_redirect_uri(self.config.redirect.clone());
        let token = client
            .exchange_code(AuthorizationCode::new(code))
            .map_err(|_| OidcError::Configuration)?
            .set_pkce_verifier(attempt.verifier)
            .request_async(&self.transport)
            .await
            .map_err(|error| match error {
                openidconnect::RequestTokenError::Request(OidcError::Unavailable) => {
                    OidcError::Unavailable
                }
                _ => OidcError::Exchange,
            })?;
        let id_token = token.id_token().ok_or(OidcError::Claims)?;
        let subject = verify_subject(
            id_token,
            &client.id_token_verifier(),
            &attempt.nonce,
            &self.config.client,
        )?;
        Ok(UpstreamSubject {
            issuer: self.config.issuer.as_str().into(),
            subject,
        })
    }
}

/// Closed errors never include URLs, tokens, provider response text or secret material.
#[derive(Debug, thiserror::Error)]
pub enum OidcError {
    #[error("invalid provider configuration")]
    /// Invalid trusted configuration or outbound origin policy.
    Configuration,
    #[error("provider discovery failed")]
    /// Discovery document, key set or protocol response rejected.
    Discovery,
    #[error("provider unavailable")]
    /// Transport/body failure or HTTP 429/5xx; begin a fresh login after recovery.
    Unavailable,
    #[error("login transaction mismatch")]
    /// Attempt state or provider binding mismatch.
    State,
    #[error("authorization exchange failed")]
    /// Authorization-code protocol rejection or malformed token response.
    Exchange,
    #[error("identity claims rejected")]
    /// Missing or invalid identity claims.
    Claims,
}

fn verify_subject(
    token: &openidconnect::core::CoreIdToken,
    verifier: &openidconnect::core::CoreIdTokenVerifier<'_>,
    nonce: &Nonce,
    client: &ClientId,
) -> Result<String, OidcError> {
    let claims = token
        .claims(verifier, nonce)
        .map_err(|_| OidcError::Claims)?;
    if claims.subject().as_str().is_empty()
        || claims
            .authorized_party()
            .is_some_and(|party| party != client)
    {
        return Err(OidcError::Claims);
    }
    Ok(claims.subject().as_str().into())
}

#[cfg(test)]
mod tests;
