//! Exchange the OIDC authorization code through the provider's vetted transport.
//! ref: oauth2-rs v5.0.0 src/endpoint.rs (RFC 6749 client authentication and exchange).
use super::{Transport, failure};
use base64::{Engine, engine::general_purpose::STANDARD};
use http::{HeaderValue, StatusCode, header};
use rss_identity_core::federation::{
    FederationError, ProtocolMaterial, ProviderCredentials, ProviderReason, ProviderSettings,
    ProviderStage,
};
use serde::Deserialize;
use url::{Url, form_urlencoded};
use zeroize::Zeroizing;

#[derive(Deserialize)]
struct TokenResponse {
    id_token: String,
    #[serde(rename = "access_token")]
    _access_token: String,
    #[serde(rename = "token_type")]
    _token_type: String,
    #[serde(rename = "expires_in")]
    _expires_in: Option<u64>,
    #[serde(rename = "refresh_token")]
    _refresh_token: Option<String>,
    #[serde(rename = "scope")]
    _scope: Option<String>,
}

#[derive(Deserialize)]
struct TokenError {
    #[serde(rename = "error")]
    _error: String,
    #[serde(rename = "error_description")]
    _description: Option<String>,
    #[serde(rename = "error_uri")]
    _uri: Option<String>,
}

pub(super) async fn exchange(
    transport: &Transport,
    endpoint: &Url,
    settings: &ProviderSettings,
    credentials: &ProviderCredentials,
    material: &ProtocolMaterial,
    code: &str,
) -> Result<Zeroizing<String>, FederationError> {
    let invalid = || failure(ProviderStage::Exchange, ProviderReason::InvalidResponse);
    let client_id: String =
        form_urlencoded::byte_serialize(settings.client_id().as_str().as_bytes()).collect();
    let secret = Zeroizing::new(
        form_urlencoded::byte_serialize(credentials.client_secret().as_bytes()).collect::<String>(),
    );
    let basic = Zeroizing::new(format!("{client_id}:{}", secret.as_str()));
    let mut authorization =
        HeaderValue::from_str(&format!("Basic {}", STANDARD.encode(basic.as_bytes())))
            .map_err(|_| invalid())?;
    authorization.set_sensitive(true);
    let body = form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", settings.redirect_uri()),
            ("code_verifier", material.verifier.as_str()),
        ])
        .finish();
    let request = http::Request::post(endpoint.as_str())
        .header(header::ACCEPT, "application/json")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::AUTHORIZATION, authorization)
        .body(body.into_bytes())
        .map_err(|_| invalid())?;
    let response = transport.call(request).await?;
    if response.status() != StatusCode::OK {
        return Err(
            match serde_json::from_slice::<TokenError>(response.body()) {
                Ok(_) => failure(ProviderStage::Exchange, ProviderReason::CodeRejected),
                Err(_) => invalid(),
            },
        );
    }
    if response
        .headers()
        .get(header::CONTENT_TYPE)
        .is_some_and(|v| {
            !v.to_str().is_ok_and(|v| {
                v.split(';')
                    .next()
                    .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/json"))
            })
        })
    {
        return Err(invalid());
    }
    let token: TokenResponse = serde_json::from_slice(response.body()).map_err(|_| invalid())?;
    Ok(Zeroizing::new(token.id_token))
}
