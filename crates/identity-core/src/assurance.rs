//! Normalized authentication facts, not authorization or a transferable proof.
//! ref: openidconnect-rs src/verification/mod.rs@b639b5d39eac6903238867aeb2b29326502e6b26.
use crate::federation::FederationError;
use serde::{Deserialize, Serialize};

/// Exact request intent; reauthentication alone never asks for or proves MFA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i16)]
pub enum AuthenticationMode {
    Login = 0,
    Reauthenticate = 1,
    StepUp = 2,
}
impl AuthenticationMode {
    pub fn from_storage(value: i16) -> Result<Self, FederationError> {
        match value {
            0 => Ok(Self::Login),
            1 => Ok(Self::Reauthenticate),
            2 => Ok(Self::StepUp),
            _ => Err(FederationError::Claims),
        }
    }
}

/// A validated snapshot. Only the upstream adapter interprets signed provider claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Input")]
pub struct Assurance {
    auth_time: Option<i64>,
    acr: String,
    amr: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    auth_time: Option<i64>,
    acr: String,
    amr: Vec<String>,
}
impl TryFrom<Input> for Assurance {
    type Error = FederationError;
    fn try_from(v: Input) -> Result<Self, Self::Error> {
        if v.auth_time.is_some_and(|t| t <= 0)
            || !matches!(v.acr.as_str(), "unspecified" | "mfa")
            || (v.acr == "mfa" && v.auth_time.is_none())
            || v.amr.len() > 3
            || v.amr
                .iter()
                .any(|m| !matches!(m.as_str(), "pwd" | "otp" | "mfa"))
            || v.amr.windows(2).any(|w| w[0] >= w[1])
        {
            return Err(FederationError::Claims);
        }
        Ok(Self {
            auth_time: v.auth_time,
            acr: v.acr,
            amr: v.amr,
        })
    }
}
impl Assurance {
    /// Interpret already signature/issuer/audience/nonce-verified OIDC claims.
    /// `keycloak_totp` is an immutable deployment approval, never tenant/browser input.
    pub fn from_verified_oidc(
        auth_time: Option<i64>,
        acr: Option<&str>,
        mut amr: Vec<String>,
        keycloak_totp: bool,
    ) -> Result<Self, FederationError> {
        if acr.is_some_and(|s| s.is_empty() || s.len() > 256 || s.chars().any(char::is_control))
            || amr.len() > 16
            || amr
                .iter()
                .any(|s| s.is_empty() || s.len() > 64 || s.chars().any(char::is_control))
        {
            return Err(FederationError::Claims);
        }
        amr.retain(|m| keycloak_totp && matches!(m.as_str(), "pwd" | "otp" | "mfa"));
        amr.sort();
        amr.dedup();
        Input {
            auth_time,
            acr: if keycloak_totp && acr == Some("2") && auth_time.is_some() {
                "mfa"
            } else {
                "unspecified"
            }
            .into(),
            amr,
        }
        .try_into()
    }
    pub fn password(auth_time: i64) -> Result<Self, FederationError> {
        Input {
            auth_time: Some(auth_time),
            acr: "unspecified".into(),
            amr: vec!["pwd".into()],
        }
        .try_into()
    }
    /// PG supplies the attempt creation time and a fresh post-lock clock.
    pub fn check(
        &self,
        mode: AuthenticationMode,
        started: i64,
        now: i64,
    ) -> Result<(), FederationError> {
        if started <= 0
            || now < started
            || self.auth_time.is_some_and(|t| t > now.saturating_add(30))
            || (mode != AuthenticationMode::Login
                && self
                    .auth_time
                    .is_none_or(|t| t < started.saturating_sub(30)))
            || (mode == AuthenticationMode::StepUp && self.acr != "mfa")
        {
            return Err(FederationError::Claims);
        }
        Ok(())
    }
    pub fn auth_time(&self) -> Option<i64> {
        self.auth_time
    }
    pub fn acr(&self) -> &str {
        &self.acr
    }
    pub fn amr(&self) -> &[String] {
        &self.amr
    }
}
