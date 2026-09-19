//! Shared signed-observation arithmetic; no wall clock or refresh policy.
use crate::{federation::FederationError, groups::acceptable_observation};

pub(crate) fn expires_at(
    max_age: i64,
    issued_at: i64,
    expires_at: i64,
    now: i64,
) -> Result<i64, FederationError> {
    if !acceptable_observation(issued_at, now) || expires_at <= issued_at || expires_at <= now {
        return Err(FederationError::Claims);
    }
    Ok(issued_at
        .checked_add(max_age)
        .ok_or(FederationError::Claims)?
        .min(expires_at))
}
