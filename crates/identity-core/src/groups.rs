//! Bounded observations from signed upstream tokens; not product authorization.
use crate::federation::FederationError;

/// Deployment policy. There is deliberately no implicit default constructor.
#[derive(Clone, Copy)]
pub struct GroupFactsMaxAge(i64);
impl GroupFactsMaxAge {
    pub fn new(seconds: i64) -> Result<Self, FederationError> {
        if !(1..=300).contains(&seconds) {
            return Err(FederationError::Configuration);
        }
        Ok(Self(seconds))
    }
    /// Only signed iat/exp determine the fixed deadline. An already stale observation
    /// is valid authentication input, but cannot yield available groups.
    pub fn expires_at(
        self,
        issued_at: i64,
        expires_at: i64,
        now: i64,
    ) -> Result<i64, FederationError> {
        if issued_at <= 0 || issued_at > now || expires_at <= issued_at || expires_at <= now {
            return Err(FederationError::Claims);
        }
        Ok(issued_at
            .checked_add(self.0)
            .ok_or(FederationError::Claims)?
            .min(expires_at))
    }
}

/// Exact claim presence; an absent claim never proves an empty membership set.
#[derive(Clone, PartialEq, Eq)]
pub enum UpstreamGroups {
    NotConfigured,
    Missing,
    Present(Vec<String>),
}
impl UpstreamGroups {
    pub fn present(mut values: Vec<String>) -> Result<Self, FederationError> {
        if !rss_identity_contracts::groups::bounded_values(&values) {
            return Err(FederationError::Claims);
        }
        values.sort();
        values.dedup();
        Ok(Self::Present(values))
    }
    pub fn values(&self) -> Option<&[String]> {
        match self {
            Self::Present(values) => Some(values),
            Self::NotConfigured | Self::Missing => None,
        }
    }
    pub fn validate(&self) -> Result<(), FederationError> {
        if self
            .values()
            .is_some_and(|v| !rss_identity_contracts::groups::canonical_values(v))
        {
            return Err(FederationError::Claims);
        }
        Ok(())
    }
}
