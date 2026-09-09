//! Identity v1 wire data. Deserializing these values does not authenticate anyone.
use serde::{Deserialize, Serialize};
/// Server-to-server request; never log or cache its credential.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationRequest {
    pub credential: String,
    pub tenant_id: String,
    pub audience: String,
}
/// Wire projection only. The validation client owns the request-scoped proof.
#[derive(Debug, Serialize, Deserialize)]
pub struct IdentityFacts {
    pub subject: String,
    pub tenant_id: String,
    pub session_id: String,
    pub client_id: String,
    pub audience: String,
    pub issuer: String,
    pub auth_time: i64,
    pub amr: Vec<String>,
    pub acr: String,
    pub expires_at: i64,
}
/// Sanitized diagnostic, never a provider or database error message.
#[derive(Debug, Serialize, Deserialize)]
pub struct ValidationFailure {
    pub code: ValidationFailureCode,
    pub correlation_id: String,
}

/// Closed v1 failure identity and its HTTP status. Unknown wire values fail deserialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationFailureCode {
    MalformedRequest,
    InvalidClient,
    InvalidCredential,
    IdentityNotActive,
    IdentityUnavailable,
    RateLimited,
    CsrfRejected,
}
impl ValidationFailureCode {
    pub const fn http_status(self) -> u16 {
        match self {
            Self::MalformedRequest => 400,
            Self::InvalidClient | Self::InvalidCredential => 401,
            Self::IdentityNotActive | Self::CsrfRejected => 403,
            Self::RateLimited => 429,
            Self::IdentityUnavailable => 503,
        }
    }
}
