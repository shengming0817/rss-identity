//! Explicit system-domain policy. Values are snapshots, never authentication proofs.
use crate::account::{AccountState, LocalChange};
use rss_request_context::TenantId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PlatformError {
    #[error("platform administrator required")]
    Forbidden,
    #[error("invalid platform input or state")]
    Invalid,
    #[error("last local platform administrator must remain available")]
    LastAdministrator,
    #[error("platform operation already exists")]
    Conflict,
    #[error("platform object not observed")]
    NotObserved,
    #[error("platform capacity reached")]
    Capacity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlatformAccount {
    state: AccountState,
    role: bool,
}
impl PlatformAccount {
    pub fn new(system: TenantId, state: AccountState, role: bool) -> Result<Self, PlatformError> {
        if state.key().tenant != system || state.administrator() || state.emergency() {
            return Err(PlatformError::Invalid);
        }
        Ok(Self { state, role })
    }
    pub fn account(self) -> AccountState {
        self.state
    }
    pub fn has_role(self) -> bool {
        self.role
    }
    pub fn available_local_administrator(self) -> bool {
        self.role && self.state.active() && self.state.has_local_password()
    }
    pub fn authorize(self) -> Result<(), PlatformError> {
        if self.role && self.state.active() {
            Ok(())
        } else {
            Err(PlatformError::Forbidden)
        }
    }
    fn protect(self, next: Self, available: i64) -> Result<Self, PlatformError> {
        if available < 0 {
            return Err(PlatformError::Invalid);
        }
        if self.available_local_administrator()
            && !next.available_local_administrator()
            && available < 2
        {
            return Err(PlatformError::LastAdministrator);
        }
        Ok(next)
    }
    pub fn set_role(self, granted: bool, available: i64) -> Result<Self, PlatformError> {
        let next = Self {
            state: self
                .state
                .advance_epoch()
                .map_err(|_| PlatformError::Invalid)?,
            role: granted,
        };
        self.protect(next, available)
    }
    /// The adapter must authorize the actor and hold the system guard through commit.
    pub fn change(self, change: LocalChange, available: i64) -> Result<Self, PlatformError> {
        if matches!(change, LocalChange::Administrator(_)) {
            return Err(PlatformError::Invalid);
        }
        let (state, _) = self
            .state
            .transition(change)
            .map_err(|_| PlatformError::Invalid)?;
        self.protect(
            Self {
                state,
                role: self.role,
            },
            available,
        )
    }
    /// Maintenance does not restore role, account or membership state.
    pub fn recover(self) -> Result<Self, PlatformError> {
        if !self.role || !self.state.has_local_password() {
            return Err(PlatformError::Forbidden);
        }
        Ok(Self {
            state: self
                .state
                .advance_epoch()
                .map_err(|_| PlatformError::Invalid)?,
            role: self.role,
        })
    }
}
