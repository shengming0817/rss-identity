//! Tenant-specific Entra v2 access-token verification; never uses ID-token nonce.
//! ref: jsonwebtoken src/validation.rs@11f83ab50d796f7e3a51d8fbd203ab3d050fed1b.
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::Jwk};
use rss_identity_core::{
    entra::*,
    federation::{FederationError, UpstreamFuture},
};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;
use zeroize::Zeroizing;

type TenantKeys = Arc<tokio::sync::Mutex<Option<Cached>>>;
struct Cached {
    until: Instant,
    keys: Vec<serde_json::Value>,
}
/// Vetted Microsoft transport and a bounded, short-lived public-key cache.
pub struct HttpEntra {
    http: reqwest::Client,
    keys: tokio::sync::Mutex<BTreeMap<Uuid, TenantKeys>>,
    #[cfg(any(test, feature = "test-support"))]
    fixture: Option<String>,
}
impl HttpEntra {
    /// Construct the production Microsoft-only verifier; no private-network bypass.
    pub fn new() -> Result<Self, FederationError> {
        Self::build(false)
    }
    fn build(loopback: bool) -> Result<Self, FederationError> {
        Ok(Self {
            http: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .dns_resolver(Arc::new(crate::egress::VettedResolver::new(
                    loopback,
                    vec![],
                )))
                .timeout(Duration::from_secs(5))
                .connect_timeout(Duration::from_secs(3))
                .build()
                .map_err(|_| FederationError::Unavailable)?,
            keys: tokio::sync::Mutex::new(BTreeMap::new()),
            #[cfg(any(test, feature = "test-support"))]
            fixture: None,
        })
    }
    /// Explicit loopback JWKS fixture. Production configuration cannot select this transport.
    #[cfg(any(test, feature = "test-support"))]
    pub fn for_loopback_test(jwks: String) -> Result<Self, FederationError> {
        let url = reqwest::Url::parse(&jwks).map_err(|_| FederationError::Configuration)?;
        if url.scheme() != "http"
            || !url.host_str().is_some_and(|h| {
                h.parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
            })
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(FederationError::Configuration);
        }
        let mut verifier = Self::build(true)?;
        verifier.fixture = Some(jwks);
        Ok(verifier)
    }
    async fn key(&self, p: &EntraTokenProfile, kid: &str) -> Result<DecodingKey, FederationError> {
        let entry = {
            let mut entries = self.keys.lock().await;
            entries.retain(|_, entry| {
                Arc::strong_count(entry) > 1
                    || entry.try_lock().map_or(true, |cached| {
                        cached.as_ref().is_some_and(|v| v.until > Instant::now())
                    })
            });
            if !entries.contains_key(&p.tenant) && entries.len() >= 128 {
                return Err(FederationError::Unavailable);
            }
            entries
                .entry(p.tenant)
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(None)))
                .clone()
        };
        // Coalesce only this tenant's misses; no network awaits under the shared map lock.
        let mut cached = entry.lock().await;
        if cached.as_ref().is_none_or(|v| v.until <= Instant::now()) {
            let endpoint = format!(
                "https://login.microsoftonline.com/{}/discovery/v2.0/keys",
                p.tenant
            );
            #[cfg(any(test, feature = "test-support"))]
            let endpoint = self.fixture.clone().unwrap_or(endpoint);
            let mut response = self
                .http
                .get(endpoint)
                .send()
                .await
                .map_err(|_| FederationError::Unavailable)?;
            if !response.status().is_success() {
                return Err(FederationError::Unavailable);
            }
            let mut bytes = Vec::new();
            while let Some(part) = response
                .chunk()
                .await
                .map_err(|_| FederationError::Unavailable)?
            {
                if bytes.len().saturating_add(part.len()) > 1024 * 1024 {
                    return Err(FederationError::Claims);
                }
                bytes.extend_from_slice(&part);
            }
            let document: serde_json::Value =
                serde_json::from_slice(&bytes).map_err(|_| FederationError::Claims)?;
            let keys = document
                .get("keys")
                .and_then(serde_json::Value::as_array)
                .ok_or(FederationError::Claims)?;
            if keys.is_empty() || keys.len() > 128 {
                return Err(FederationError::Claims);
            }
            *cached = Some(Cached {
                until: Instant::now() + Duration::from_secs(60),
                keys: keys.clone(),
            });
        }
        let matches: Vec<_> = cached
            .as_ref()
            .ok_or(FederationError::Unavailable)?
            .keys
            .iter()
            .filter(|key| key.get("kid").and_then(serde_json::Value::as_str) == Some(kid))
            .collect();
        if matches.len() != 1 {
            return Err(FederationError::Claims);
        }
        let value = matches[0];
        if value.get("kty").and_then(serde_json::Value::as_str) != Some("RSA")
            || value.get("use").is_some_and(|v| v.as_str() != Some("sig"))
            || value
                .get("alg")
                .is_some_and(|v| v.as_str() != Some("RS256"))
            || value.get("issuer").is_some_and(|v| {
                !v.as_str().is_some_and(|i| {
                    i == p.issuer() || i == "https://login.microsoftonline.com/{tenantid}/v2.0"
                })
            })
        {
            return Err(FederationError::Claims);
        }
        let jwk: Jwk =
            serde_json::from_value(value.clone()).map_err(|_| FederationError::Claims)?;
        DecodingKey::from_jwk(&jwk).map_err(|_| FederationError::Claims)
    }
}

#[derive(Deserialize)]
struct Claims {
    ver: String,
    idtyp: String,
    tid: Uuid,
    oid: Uuid,
    azp: Uuid,
    aud: Uuid,
    iat: i64,
    exp: i64,
    nbf: i64,
    scp: Option<String>,
    #[serde(flatten)]
    extra: BTreeMap<String, serde_json::Value>,
}
impl EntraTokenVerifier for HttpEntra {
    fn verify<'a>(
        &'a self,
        p: &'a EntraTokenProfile,
        token: Zeroizing<String>,
    ) -> UpstreamFuture<'a, EntraTokenClaims> {
        Box::pin(async move {
            p.validate()?;
            if token.is_empty() || token.len() > 32768 {
                return Err(FederationError::Claims);
            }
            let header = decode_header(&token).map_err(|_| FederationError::Claims)?;
            if header.alg != Algorithm::RS256 {
                return Err(FederationError::Claims);
            }
            let kid = header
                .kid
                .filter(|s| !s.is_empty() && s.len() <= 256)
                .ok_or(FederationError::Claims)?;
            let key = self.key(p, &kid).await?;
            let mut validation = Validation::new(Algorithm::RS256);
            validation.set_required_spec_claims(&["exp", "nbf", "iss", "aud"]);
            validation.set_audience(&[p.app_id.to_string()]);
            validation.set_issuer(&[p.issuer()]);
            validation.validate_nbf = true;
            validation.leeway = 0;
            let c = decode::<Claims>(&token, &key, &validation)
                .map_err(|_| FederationError::Claims)?
                .claims;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| FederationError::Unavailable)?
                .as_secs() as i64;
            if c.ver != "2.0"
                || c.idtyp != "user"
                || c.tid != p.tenant
                || c.aud != p.app_id
                || c.oid.is_nil()
                || !p.authorized_clients.contains(&c.azp)
                || c.iat > now
                || c.nbf > now
                || c.exp <= now
            {
                return Err(FederationError::Claims);
            }
            let scopes: Vec<_> = c
                .scp
                .as_deref()
                .unwrap_or("")
                .split_ascii_whitespace()
                .collect();
            if p.required_scopes
                .iter()
                .any(|s| !scopes.contains(&s.as_str()))
            {
                return Err(FederationError::Claims);
            }
            let device = match c.extra.get(&p.device_claim) {
                None => None,
                Some(serde_json::Value::String(v)) => {
                    Some(Uuid::parse_str(v).map_err(|_| FederationError::Claims)?)
                }
                _ => return Err(FederationError::Claims),
            };
            let result = EntraTokenClaims {
                tenant: c.tid,
                user: c.oid,
                device,
                issued_at: c.iat,
                expires_at: c.exp,
            };
            result.validate(p)?;
            Ok(result)
        })
    }
}
