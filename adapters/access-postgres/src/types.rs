use access_core::account::{AccountKey, AccountState, PasswordError};
use rand_core::{OsRng, RngCore};
use rss_transactional_messaging::policy::OperationDeadline;
use std::time::Instant;
use uuid::Uuid;
use zeroize::Zeroizing;

/// This owned, short-lived candidate is neither a session nor a bearer credential.
/// ```compile_fail
/// fn copy(c: access_postgres::AuthenticationCandidate) { let _ = c.clone(); }
/// ```
pub struct AuthenticationCandidate {
    pub(crate) state: AccountState,
    pub(crate) authority: Uuid,
    pub(crate) expires: Instant,
}
impl AuthenticationCandidate {
    pub fn account(&self) -> AccountKey {
        self.state.key()
    }
}
impl std::fmt::Debug for AuthenticationCandidate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthenticationCandidate(<private>)")
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationPurpose {
    Initialize,
    Recover,
}
impl AuthorizationPurpose {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Initialize => "initialize",
            Self::Recover => "recover",
        }
    }
}

pub struct AuthorizationSecret(Zeroizing<String>);
impl AuthorizationSecret {
    pub fn parse(value: String) -> Result<Self, AuthorityError> {
        let value = Zeroizing::new(value);
        if value.len() != 64
            || !value
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(AuthorityError::Invalid);
        }
        Ok(Self(value))
    }
    pub(crate) fn generate() -> Self {
        let mut bytes = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(bytes.as_mut());
        Self(Zeroizing::new(
            bytes.iter().map(|b| format!("{b:02x}")).collect(),
        ))
    }
    /// Explicit secret access for the local secret-file boundary only. Never log this value.
    pub fn expose(&self) -> &str {
        &self.0
    }
}
impl std::fmt::Debug for AuthorizationSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthorizationSecret(<redacted>)")
    }
}
/// Only the confirmed transaction path can construct this receipt.
/// ```compile_fail
/// fn forge(secret:access_postgres::AuthorizationSecret) {
///     let _=access_postgres::IssuedAuthorization {secret};
/// }
/// ```
#[derive(Debug)]
pub struct IssuedAuthorization {
    pub(crate) secret: AuthorizationSecret,
}

impl IssuedAuthorization {
    pub fn secret(&self) -> &AuthorizationSecret {
        &self.secret
    }
    pub fn into_secret(self) -> AuthorizationSecret {
        self.secret
    }
}

/// Trusted adapter attribution. Network adapters must derive this from the transport, not headers.
#[derive(Clone)]
pub struct AttemptSource(String);
impl AttemptSource {
    pub fn parse(value: &str) -> Result<Self, AuthorityError> {
        if value.is_empty()
            || value.len() > 128
            || !value.is_ascii()
            || value.chars().any(char::is_control)
        {
            return Err(AuthorityError::Invalid);
        }
        Ok(Self(value.into()))
    }
    pub(crate) fn value(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthorityError {
    #[error("invalid account input")]
    Invalid,
    #[error("authentication or operation rejected")]
    Rejected,
    #[error("transaction rolled back: {0}")]
    RuleRejected(access_core::account::AccountRuleError),
    #[error("attempt budget exhausted")]
    RateLimited,
    #[error("password computation capacity exhausted")]
    Busy,
    #[error("authority unavailable")]
    Unavailable,
    #[error("incompatible Access storage or authority role")]
    StorageIncompatible,
    #[error("transaction not started ({0})")]
    NotStarted(StorageFailure),
    #[error("transaction rolled back ({0})")]
    RolledBack(StorageFailure),
    #[error("rollback not confirmed ({0})")]
    RollbackFailed(StorageFailure),
    #[error("commit not confirmed ({0})")]
    CommitUnknown(StorageFailure),
    #[error("execution fenced")]
    Fenced,
}
impl From<PasswordError> for AuthorityError {
    fn from(e: PasswordError) -> Self {
        match e {
            PasswordError::Invalid => Self::Invalid,
            PasswordError::Busy => Self::Busy,
            PasswordError::Unavailable => Self::Unavailable,
        }
    }
}

pub(crate) struct Budget(pub Instant);
impl Budget {
    pub fn new(deadline: OperationDeadline) -> Result<Self, AuthorityError> {
        Instant::now()
            .checked_add(deadline.timeout())
            .map(Self)
            .ok_or(AuthorityError::Invalid)
    }
    pub fn remaining(&self) -> OperationDeadline {
        OperationDeadline::from_remaining(self.0.saturating_duration_since(Instant::now()))
    }
    pub async fn password<T>(
        &self,
        future: impl std::future::Future<Output = Result<T, PasswordError>>,
    ) -> Result<T, AuthorityError> {
        tokio::time::timeout_at(self.0.into(), future)
            .await
            .map_err(|_| AuthorityError::Unavailable)?
            .map_err(Into::into)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StorageFailure {
    #[error("temporarily unavailable")]
    Transient,
    #[error("invalid operation")]
    Permanent,
    #[error("conflicting state")]
    Conflict,
    #[error("ownership lost")]
    OwnershipLost,
    #[error("invalid stored state")]
    Invariant,
    #[error("deadline elapsed")]
    DeadlineElapsed,
}
impl From<rss_transactional_messaging::error::MessagingErrorKind> for StorageFailure {
    fn from(k: rss_transactional_messaging::error::MessagingErrorKind) -> Self {
        use rss_transactional_messaging::error::MessagingErrorKind as K;
        match k {
            K::Transient => Self::Transient,
            K::Permanent => Self::Permanent,
            K::Conflict => Self::Conflict,
            K::OwnershipLost => Self::OwnershipLost,
            K::Invariant => Self::Invariant,
            K::DeadlineElapsed => Self::DeadlineElapsed,
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityProfile {
    Runtime,
    Issuer,
}
