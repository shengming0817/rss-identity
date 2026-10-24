//! Bounded discovery using the existing vetted transport; JWT verification has one owner.
//! ref: openidconnect-rs src/discovery/mod.rs @ b639b5d39eac6903238867aeb2b29326502e6b26.
use super::{Transport, failure};
use oauth2::{AsyncHttpClient, AuthUrl, TokenUrl, http};
use rss_identity_core::federation::{FederationError, ProviderReason, ProviderStage};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

#[derive(Default, Deserialize, Serialize)]
pub(super) struct Jwks {
    pub keys: Vec<serde_json::Value>,
}
#[derive(Deserialize)]
pub(super) struct Metadata {
    pub issuer: String,
    pub authorization_endpoint: AuthUrl,
    pub token_endpoint: Option<TokenUrl>,
    jwks_uri: url::Url,
    #[serde(rename = "response_types_supported")]
    _response_types_supported: Vec<String>,
    #[serde(rename = "subject_types_supported")]
    _subject_types_supported: Vec<String>,
    pub id_token_signing_alg_values_supported: Vec<String>,
    #[serde(default)]
    pub authorization_response_iss_parameter_supported: bool,
    #[serde(skip)]
    pub jwks: Jwks,
}

async fn get<T: DeserializeOwned>(
    transport: &Transport,
    url: &str,
    jwks: bool,
) -> Result<T, FederationError> {
    let request = http::Request::builder()
        .uri(url)
        .header("accept", "application/json")
        .body(Vec::new())
        .map_err(|_| failure(transport.stage(), ProviderReason::InvalidResponse))?;
    let response = transport.call(request).await?;
    let media_valid = response
        .headers()
        .get(http::header::CONTENT_TYPE)
        .is_none_or(|value| {
            value.to_str().is_ok_and(|value| {
                let essence = value.split(';').next().unwrap_or("").trim();
                essence.eq_ignore_ascii_case("application/json")
                    || (jwks && essence.eq_ignore_ascii_case("application/jwk-set+json"))
            })
        });
    if response.status() != http::StatusCode::OK || !media_valid {
        return Err(failure(transport.stage(), ProviderReason::InvalidResponse));
    }
    serde_json::from_slice(response.body())
        .map_err(|_| failure(transport.stage(), ProviderReason::InvalidResponse))
}

pub(super) async fn discover(
    transport: &Transport,
    issuer: &str,
) -> Result<Metadata, FederationError> {
    // OIDC discovery appends to the issuer path; URL::join would replace a realm segment.
    let url = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    let mut metadata: Metadata = get(transport, &url, false).await?;
    if metadata.issuer != issuer {
        return Err(failure(
            ProviderStage::Discovery,
            ProviderReason::IssuerMismatch,
        ));
    }
    metadata.jwks = get(transport, metadata.jwks_uri.as_str(), true).await?;
    Ok(metadata)
}
