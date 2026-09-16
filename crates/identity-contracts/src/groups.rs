//! Required online groups contract, version 1. DTOs alone confer no trust.
use serde::{Deserialize, Serialize};
pub const VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnavailableReason {
    LocalIdentity,
    NotConfigured,
    ClaimMissing,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupSource {
    pub provider_id: uuid::Uuid,
    pub issuer: String,
}
/// Only available contains values. Unknown states/fields fail deserialization;
/// consumers must also validate the explicit version and metadata.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum Groups {
    Available {
        version: u32,
        source: GroupSource,
        snapshot_id: uuid::Uuid,
        provider_config_version: i64,
        observed_at: i64,
        expires_at: i64,
        values: Vec<String>,
    },
    Unavailable {
        version: u32,
        reason: UnavailableReason,
    },
    Expired {
        version: u32,
    },
}
impl std::fmt::Debug for Groups {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Groups(<redacted>)")
    }
}
impl Groups {
    pub fn unavailable(reason: UnavailableReason) -> Self {
        Self::Unavailable {
            version: VERSION,
            reason,
        }
    }
    /// Structural and temporal validation, including an already expired available
    /// response that crossed its deadline in transport. Expiry preserves identity.
    pub fn structurally_valid_at(&self, now: i64) -> bool {
        match self {
            Self::Unavailable { version, .. } | Self::Expired { version } => *version == VERSION,
            Self::Available {
                version,
                source,
                snapshot_id,
                provider_config_version,
                observed_at,
                expires_at,
                values,
            } => {
                *version == VERSION
                    && !source.provider_id.is_nil()
                    && !snapshot_id.is_nil()
                    && *provider_config_version > 0
                    && *observed_at > 0
                    && *observed_at <= now
                    && *expires_at > *observed_at
                    && expires_at
                        .checked_sub(*observed_at)
                        .is_some_and(|v| v <= 300)
                    && canonical_values(values)
                    && valid_issuer(&source.issuer)
            }
        }
    }
}
fn valid_issuer(value: &str) -> bool {
    value.len() <= 2048
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && url::Url::parse(value).is_ok_and(|u| {
            matches!(u.scheme(), "https" | "http")
                && u.host_str().is_some()
                && u.username().is_empty()
                && u.password().is_none()
                && u.query().is_none()
                && u.fragment().is_none()
        })
}
pub fn bounded_values(values: &[String]) -> bool {
    values.len() <= 100
        && values
            .iter()
            .all(|v| !v.is_empty() && v.len() <= 256 && !v.chars().any(char::is_control))
}
pub fn canonical_values(values: &[String]) -> bool {
    bounded_values(values) && values.windows(2).all(|v| v[0] < v[1])
}
