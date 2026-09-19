//! Optional, source-scoped department codes. Parsed values alone are not trusted facts.
use crate::{federation::FederationError, groups::valid_max_age};
use serde::{Deserialize, Serialize};

/// An exact controlled code, not a display name or globally unique identifier.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct DepartmentId(String);
impl DepartmentId {
    pub fn new(value: String) -> Result<Self, FederationError> {
        if value.is_empty()
            || value.len() > 256
            || value.trim() != value
            || value.chars().any(char::is_control)
        {
            return Err(FederationError::Claims);
        }
        Ok(Self(value))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl std::fmt::Debug for DepartmentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DepartmentId(<redacted>)")
    }
}
impl TryFrom<String> for DepartmentId {
    type Error = FederationError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}
impl From<DepartmentId> for String {
    fn from(value: DepartmentId) -> Self {
        value.0
    }
}

/// Enabling a department mapping always includes its explicit bounded lifetime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "DepartmentClaimInput")]
pub struct DepartmentClaim {
    claim: String,
    max_age_seconds: i64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DepartmentClaimInput {
    claim: String,
    max_age_seconds: i64,
}
impl TryFrom<DepartmentClaimInput> for DepartmentClaim {
    type Error = FederationError;
    fn try_from(value: DepartmentClaimInput) -> Result<Self, Self::Error> {
        Self::new(value.claim, value.max_age_seconds)
    }
}
impl DepartmentClaim {
    pub fn new(claim: String, max_age_seconds: i64) -> Result<Self, FederationError> {
        // Standard ID token/user-info claims are never a department identity.
        const RESERVED: &[&str] = &[
            "iss",
            "sub",
            "sid",
            "aud",
            "exp",
            "nbf",
            "iat",
            "jti",
            "auth_time",
            "nonce",
            "acr",
            "amr",
            "azp",
            "at_hash",
            "c_hash",
            "s_hash",
            "name",
            "given_name",
            "family_name",
            "middle_name",
            "nickname",
            "preferred_username",
            "profile",
            "picture",
            "website",
            "email",
            "email_verified",
            "gender",
            "birthdate",
            "zoneinfo",
            "locale",
            "phone_number",
            "phone_number_verified",
            "address",
            "updated_at",
        ];
        if claim.is_empty()
            || claim.len() > 64
            || !claim
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
            || RESERVED.contains(&claim.as_str())
            || !valid_max_age(max_age_seconds)
        {
            return Err(FederationError::Configuration);
        }
        Ok(Self {
            claim,
            max_age_seconds,
        })
    }
    pub fn claim(&self) -> &str {
        &self.claim
    }
    pub fn max_age_seconds(&self) -> i64 {
        self.max_age_seconds
    }
    /// The signed observation fixes the deadline; an already stale fact is not renewed.
    pub fn expires_at(
        &self,
        issued_at: i64,
        expires_at: i64,
        now: i64,
    ) -> Result<i64, FederationError> {
        crate::fact_time::expires_at(self.max_age_seconds, issued_at, expires_at, now)
    }
}

/// Exact verified claim presence. Absence never proves that the user has no department.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamDepartment {
    NotConfigured,
    Missing,
    NoDepartment,
    Present(DepartmentId),
}
