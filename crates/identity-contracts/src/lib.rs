//! Identity v1 wire data. Deserializing these values does not authenticate anyone.
use serde::{Deserialize, Serialize};
/// Closed normalized authentication strength. ref: serde enum representations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Acr {
    Unspecified,
    Mfa,
}
impl Acr {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unspecified => "unspecified",
            Self::Mfa => "mfa",
        }
    }
}
impl std::str::FromStr for Acr {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "unspecified" => Ok(Self::Unspecified),
            "mfa" => Ok(Self::Mfa),
            _ => Err("unknown acr"),
        }
    }
}
/// Verified authentication methods, ordered by canonical wire spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Amr {
    Mfa,
    Otp,
    Pwd,
}
impl Amr {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mfa => "mfa",
            Self::Otp => "otp",
            Self::Pwd => "pwd",
        }
    }
}
impl std::str::FromStr for Amr {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "mfa" => Ok(Self::Mfa),
            "otp" => Ok(Self::Otp),
            "pwd" => Ok(Self::Pwd),
            _ => Err("unknown amr"),
        }
    }
}
/// The closed enum bounds cardinality; ordering also rejects duplicate methods.
pub fn canonical_methods(methods: &[Amr]) -> bool {
    methods.windows(2).all(|w| w[0] < w[1])
}

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
    pub amr: Vec<Amr>,
    pub acr: Acr,
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

#[cfg(test)]
mod assurance_tests {
    use super::*;
    #[test]
    fn authentication_vocabulary_is_closed_and_methods_are_canonical() {
        assert_eq!("mfa".parse::<Acr>().unwrap(), Acr::Mfa);
        assert!("other".parse::<Acr>().is_err());
        assert!("invented".parse::<Amr>().is_err());
        assert!(canonical_methods(&[Amr::Otp, Amr::Pwd]));
        assert!(!canonical_methods(&[Amr::Pwd, Amr::Pwd]));
        assert!(!canonical_methods(&[Amr::Pwd, Amr::Otp]));
    }
}
