use rss_identity_core::account::{AccountKey, AccountState, PasswordError};
use rss_transactional_messaging::policy::OperationDeadline;
use std::time::Instant;
use uuid::Uuid;

/// This owned, short-lived candidate is neither a session nor a bearer credential.
/// ```compile_fail
/// fn copy(c: rss_identity_postgres::AuthenticationCandidate) { let _ = c.clone(); }
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
    #[error(transparent)]
    Downstream(#[from] rss_identity_core::downstream::DownstreamError),
    #[error(transparent)]
    Federation(#[from] rss_identity_core::federation::FederationError),
    #[error("authentication or operation rejected")]
    Rejected,
    #[error("current password rejected")]
    ReauthenticationFailed,
    #[error("transaction rolled back: {0}")]
    RuleRejected(rss_identity_core::account::AccountRuleError),
    #[error("attempt budget exhausted")]
    RateLimited,
    #[error("password computation capacity exhausted")]
    Busy,
    #[error("authority unavailable")]
    Unavailable,
    #[error("incompatible Identity storage: {0}")]
    StorageIncompatible(StorageMismatch),
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
/// Non-secret deployment diagnostics, independent of provider/SQL error text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StorageMismatch {
    #[error("unsupported schema version; check the development database rebuild guide")]
    SchemaVersion,
    #[error(
        "database role does not match the operation; use the matching runtime or maintenance configuration"
    )]
    Role,
    #[error(
        "database privileges differ from the required profile; ask the deployment owner to check grants"
    )]
    Privileges,
    #[error(
        "schema constraints or tenant policies differ from the required contract; ask the deployment owner to check the schema"
    )]
    SchemaContract,
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
    Maintenance,
}
