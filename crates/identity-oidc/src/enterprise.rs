//! Fixed ES256 assertion signing for Keycloak's supported JWT authorization grant.
//! ref: keycloak 26.7.3 JWTAuthorizationGrantType.java and AbstractBaseJWTValidator.java.
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use rss_identity_core::enterprise::{EnterpriseClaims, EnterpriseSigner};
use zeroize::Zeroizing;

/// Deployment supplies a dedicated P-256 PKCS#8 private key; never reuse cookie/state keys.
pub struct Es256EnterpriseSigner {
    key: EncodingKey,
    kid: String,
}
impl Es256EnterpriseSigner {
    /// Load a dedicated ES256 signing key and public key identifier.
    pub fn new(kid: String, pem: &[u8]) -> Result<Self, &'static str> {
        if kid.is_empty()
            || kid.len() > 128
            || !kid
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
        {
            return Err("invalid signing key identifier");
        }
        let key = EncodingKey::from_ec_pem(pem).map_err(|_| "invalid enterprise signing key")?;
        Ok(Self { key, kid })
    }
}
impl EnterpriseSigner for Es256EnterpriseSigner {
    fn sign(&self, claims: &EnterpriseClaims) -> Result<Zeroizing<String>, &'static str> {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.kid.clone());
        jsonwebtoken::encode(&header, claims, &self.key)
            .map(Zeroizing::new)
            .map_err(|_| "enterprise signing failed")
    }
}

/// Verified provider token, retained only by the authorized RP backend.
pub struct EnterpriseAccess {
    token: Zeroizing<String>,
    subject: String,
    expires_at: i64,
}
impl EnterpriseAccess {
    /// Expose only to the RP's server-side protocol adapter.
    pub fn expose(&self) -> &str {
        &self.token
    }
    /// Stable Keycloak subject verified against the host's explicit account mapping.
    pub fn subject(&self) -> &str {
        &self.subject
    }
    /// Signed token deadline; it does not imply an active browser session.
    pub fn expires_at(&self) -> i64 {
        self.expires_at
    }
}
#[derive(serde::Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    refresh_token: Option<String>,
}
#[derive(serde::Deserialize)]
struct AccessClaims {
    sub: String,
    azp: String,
    exp: i64,
}
impl crate::HttpOidc {
    /// Exchange a one-use backend assertion through the existing bounded, vetted transport.
    /// `expected_subject` comes from the host's provisioned stable IdP mapping, never browser JSON.
    /// No retries: a network failure may follow successful upstream assertion consumption.
    pub async fn exchange_enterprise(
        &self,
        tenant: rss_request_context::TenantId,
        provider: &rss_identity_core::federation::ProviderSettings,
        credentials: &rss_identity_core::federation::ProviderCredentials,
        target: &rss_identity_core::enterprise::EnterpriseTarget,
        assertion: &str,
        assertion_expires_at: i64,
        expected_subject: &str,
    ) -> Result<EnterpriseAccess, rss_identity_core::federation::FederationError> {
        use openidconnect::AsyncHttpClient;
        use rss_identity_core::federation::FederationError;
        target
            .validate()
            .map_err(|_| FederationError::Configuration)?;
        if target.client_id != provider.client_id().as_str()
            || assertion.is_empty()
            || assertion.len() > 16384
            || expected_subject.is_empty()
            || expected_subject.len() > 512
        {
            return Err(FederationError::Configuration);
        }
        let (metadata, transport) = self.discover(tenant, provider, credentials).await?;
        if metadata
            .token_endpoint()
            .is_none_or(|u| u.as_str() != target.token_endpoint)
        {
            return Err(FederationError::Configuration);
        }
        let form = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
            .append_pair("client_id", &target.client_id)
            .append_pair("client_secret", credentials.client_secret())
            .append_pair(
                "scope",
                &target.scopes.iter().cloned().collect::<Vec<_>>().join(" "),
            )
            .append_pair("assertion", assertion)
            .finish();
        let request = openidconnect::http::Request::builder()
            .method("POST")
            .uri(&target.token_endpoint)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(form.into_bytes())
            .map_err(|_| FederationError::Configuration)?;
        let response = transport.call(request).await?;
        if !response.status().is_success() {
            return Err(FederationError::Rejected);
        }
        let token: TokenResponse =
            serde_json::from_slice(response.body()).map_err(|_| FederationError::Claims)?;
        if !token.token_type.eq_ignore_ascii_case("bearer")
            || token.refresh_token.is_some()
            || token.access_token.len() > 16384
        {
            return Err(FederationError::Claims);
        }
        let header = jsonwebtoken::decode_header(&token.access_token)
            .map_err(|_| FederationError::Claims)?;
        if header.alg != Algorithm::RS256 {
            return Err(FederationError::Claims);
        }
        let kid = header.kid.ok_or(FederationError::Claims)?;
        let jwks: jsonwebtoken::jwk::JwkSet = serde_json::from_value(
            serde_json::to_value(metadata.jwks()).map_err(|_| FederationError::Claims)?,
        )
        .map_err(|_| FederationError::Claims)?;
        let key =
            jsonwebtoken::DecodingKey::from_jwk(jwks.find(&kid).ok_or(FederationError::Claims)?)
                .map_err(|_| FederationError::Claims)?;
        let mut validation = jsonwebtoken::Validation::new(Algorithm::RS256);
        validation.set_audience(&[&target.client_id]);
        validation.set_issuer(&[provider.issuer().as_str()]);
        validation.leeway = 0;
        let claims = jsonwebtoken::decode::<AccessClaims>(&token.access_token, &key, &validation)
            .map_err(|_| FederationError::Claims)?
            .claims;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| FederationError::Unavailable)?
            .as_secs() as i64;
        if claims.sub != expected_subject
            || claims.azp != target.client_id
            || claims.exp <= now
            || claims.exp > now + 30
            || claims.exp > assertion_expires_at
        {
            return Err(FederationError::Claims);
        }
        Ok(EnterpriseAccess {
            token: Zeroizing::new(token.access_token),
            subject: claims.sub,
            expires_at: claims.exp,
        })
    }
}
