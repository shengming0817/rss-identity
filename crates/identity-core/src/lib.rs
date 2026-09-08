//! Identity binding rules, not an authentication service.
//!
//! Passing these checks does not authenticate a caller. The future I06 authority must first
//! authenticate the protocol credential and load the authoritative session from storage.
pub mod account;
use rss_request_context::TenantId;
use uuid::Uuid;

/// Non-nil Identity PrincipalId; never inferred from browser claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrincipalId(Uuid);
impl PrincipalId {
    pub fn generate() -> Self {
        Self(Uuid::new_v4())
    }
    pub fn as_uuid(self) -> Uuid {
        self.0
    }
    /// Parse a non-nil UUID from the authoritative source.
    pub fn parse(value: &str) -> Result<Self, ValidationError> {
        let id = Uuid::parse_str(value).map_err(|_| ValidationError::InvalidValue)?;
        if id.is_nil() {
            return Err(ValidationError::InvalidValue);
        }
        Ok(Self(id))
    }
}

/// Non-nil Identity SessionId; never inferred from browser claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionId(Uuid);
impl SessionId {
    /// Parse a non-nil UUID from the authoritative source.
    pub fn parse(value: &str) -> Result<Self, ValidationError> {
        let id = Uuid::parse_str(value).map_err(|_| ValidationError::InvalidValue)?;
        if id.is_nil() {
            return Err(ValidationError::InvalidValue);
        }
        Ok(Self(id))
    }
}

/// Exact registered IssuerId; URL policy remains with the protocol adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerId(String);
impl IssuerId {
    /// Reject empty, surrounding whitespace and control characters.
    pub fn parse(value: &str) -> Result<Self, ValidationError> {
        if value.is_empty() || value.trim() != value || value.chars().any(char::is_control) {
            return Err(ValidationError::InvalidValue);
        }
        Ok(Self(value.into()))
    }
}

/// Exact registered ClientId; URL policy remains with the protocol adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientId(String);
impl ClientId {
    /// Reject empty, surrounding whitespace and control characters.
    pub fn parse(value: &str) -> Result<Self, ValidationError> {
        if value.is_empty() || value.trim() != value || value.chars().any(char::is_control) {
            return Err(ValidationError::InvalidValue);
        }
        Ok(Self(value.into()))
    }
}

/// Exact registered Audience; URL policy remains with the protocol adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Audience(String);
impl Audience {
    /// Reject empty, surrounding whitespace and control characters.
    pub fn parse(value: &str) -> Result<Self, ValidationError> {
        if value.is_empty() || value.trim() != value || value.chars().any(char::is_control) {
            return Err(ValidationError::InvalidValue);
        }
        Ok(Self(value.into()))
    }
}

/// Positive identity generation from the authoritative source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Epoch(u64);
impl Epoch {
    /// Construct a positive value; zero is invalid.
    pub fn new(value: u64) -> Result<Self, ValidationError> {
        if value == 0 {
            return Err(ValidationError::InvalidValue);
        }
        Ok(Self(value))
    }
}

/// Positive Unix timestamp in seconds from the authoritative source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct UnixTime(u64);
impl UnixTime {
    /// Construct a positive value; zero is invalid.
    pub fn new(value: u64) -> Result<Self, ValidationError> {
        if value == 0 {
            return Err(ValidationError::InvalidValue);
        }
        Ok(Self(value))
    }
}

/// Exact credential destination, constructed from registered server-side configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    issuer: IssuerId,
    tenant: TenantId,
    client: ClientId,
    audience: Audience,
}
impl Binding {
    /// Construct a binding. OIDC URL validation is owned by the protocol adapter.
    /// ```compile_fail
    /// use rss_identity_core::*;
    /// fn swapped(i: IssuerId, t: rss_request_context::TenantId, c: ClientId, a: Audience) {
    ///     Binding::new(i, t, a, c);
    /// }
    /// ```
    pub fn new(issuer: IssuerId, tenant: TenantId, client: ClientId, audience: Audience) -> Self {
        Self {
            issuer,
            tenant,
            client,
            audience,
        }
    }
}

/// Storage snapshot only; deliberately not named or serializable as VerifiedIdentityContext.
#[derive(Debug, Clone)]
pub struct SessionSnapshot {
    binding: Binding,
    principal: PrincipalId,
    session: SessionId,
    epoch: Epoch,
    expires_at: UnixTime,
}
impl SessionSnapshot {
    /// Construct a snapshot. The caller must load it from the authoritative store.
    ///
    /// Principal and session identities cannot be interchanged.
    /// ```compile_fail
    /// use rss_identity_core::*;
    /// fn swapped(b: Binding, p: PrincipalId, s: SessionId, e: Epoch, t: UnixTime) {
    ///     SessionSnapshot::new(b, s, p, e, t);
    /// }
    /// ```
    /// Epochs and timestamps cannot be interchanged.
    /// ```compile_fail
    /// use rss_identity_core::*;
    /// fn swapped(s: SessionSnapshot, b: Binding, e: Epoch, t: UnixTime) {
    ///     s.check(&b, e, t, true);
    /// }
    /// ```
    pub fn new(
        binding: Binding,
        principal: PrincipalId,
        session: SessionId,
        epoch: Epoch,
        expires_at: UnixTime,
    ) -> Self {
        Self {
            binding,
            principal,
            session,
            epoch,
            expires_at,
        }
    }
    /// Check the destination and current authoritative state for this request only.
    /// `enabled` is the conjunction of account, membership and session validity.
    pub fn check(
        &self,
        expected: &Binding,
        now: UnixTime,
        current_epoch: Epoch,
        enabled: bool,
    ) -> Result<(), ValidationError> {
        if &self.binding != expected {
            return Err(ValidationError::BindingMismatch);
        }
        if !enabled || now >= self.expires_at || self.epoch != current_epoch {
            return Err(ValidationError::Inactive);
        }
        Ok(())
    }
    /// Internal Identity principal; not a public cross-product subject.
    pub fn principal(&self) -> PrincipalId {
        self.principal
    }
    /// Identity authentication session identity.
    pub fn session(&self) -> SessionId {
        self.session
    }
}

/// Closed rule failures; HTTP error projection belongs to I06.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ValidationError {
    #[error("invalid identity value")]
    InvalidValue,
    #[error("credential binding mismatch")]
    BindingMismatch,
    #[error("identity is not active")]
    Inactive,
}
