//! Pure account policy; persistence and transaction locking belong to the adapter.
use super::Password;
use crate::PrincipalId;
use rss_request_context::TenantId;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountKey {
    pub tenant: TenantId,
    pub principal: PrincipalId,
}
/// Validated domain snapshot, never an authentication proof or PostgreSQL fencing token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountState {
    key: AccountKey,
    enabled: bool,
    administrator: bool,
    emergency: bool,
    member_active: bool,
    epoch: i64,
    has_local_password: bool,
    membership_epoch: i64,
}
#[derive(Debug)]
pub enum AccountChange {
    Enabled(bool),
    Administrator(bool),
    Membership(bool),
    Password(Password),
}
#[derive(Debug, Clone, Copy)]
pub enum LocalChange {
    Enabled(bool),
    Administrator(bool),
    Membership(bool),
    Password,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AccountRuleError {
    #[error("invalid account state")]
    InvalidState,
    #[error("account operation rejected")]
    Rejected,
    #[error("last local administrator must remain available")]
    LastAdministrator,
    #[error("account generation exhausted")]
    EpochExhausted,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityAction {
    Initialized,
    AccountCreated,
    AccountEnabled,
    AccountDisabled,
    AdministratorGranted,
    AdministratorRevoked,
    MembershipEnabled,
    MembershipDisabled,
    PasswordChanged,
    AdministratorRecovered,
}
impl SecurityAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Initialized => "initialized",
            Self::AccountCreated => "account_created",
            Self::AccountEnabled => "account_enabled",
            Self::AccountDisabled => "account_disabled",
            Self::AdministratorGranted => "administrator_granted",
            Self::AdministratorRevoked => "administrator_revoked",
            Self::MembershipEnabled => "membership_enabled",
            Self::MembershipDisabled => "membership_disabled",
            Self::PasswordChanged => "password_changed",
            Self::AdministratorRecovered => "administrator_recovered",
        }
    }
}
impl AccountState {
    #[allow(clippy::too_many_arguments)] // The single persistence hydration boundary validates every generation.
    pub fn restore(
        key: AccountKey,
        enabled: bool,
        administrator: bool,
        emergency: bool,
        member_active: bool,
        epoch: i64,
        has_local_password: bool,
        membership_epoch: i64,
    ) -> Result<Self, AccountRuleError> {
        if epoch < 1 || membership_epoch < 1 || (emergency && !administrator) {
            return Err(AccountRuleError::InvalidState);
        }
        Ok(Self {
            key,
            enabled,
            administrator,
            emergency,
            member_active,
            epoch,
            has_local_password,
            membership_epoch,
        })
    }
    pub fn new_local(
        key: AccountKey,
        administrator: bool,
        emergency: bool,
    ) -> Result<Self, AccountRuleError> {
        Self::restore(key, true, administrator, emergency, true, 1, true, 1)
    }
    pub fn key(self) -> AccountKey {
        self.key
    }
    pub fn enabled(self) -> bool {
        self.enabled
    }
    pub fn administrator(self) -> bool {
        self.administrator
    }
    pub fn emergency(self) -> bool {
        self.emergency
    }
    pub fn member_active(self) -> bool {
        self.member_active
    }
    pub fn epoch(self) -> i64 {
        self.epoch
    }
    pub fn has_local_password(self) -> bool {
        self.has_local_password
    }
    pub fn new_federated(key: AccountKey) -> Result<Self, AccountRuleError> {
        Self::restore(key, true, false, false, true, 1, false, 1)
    }
    pub fn available_local_administrator(self) -> bool {
        self.available_administrator() && self.has_local_password
    }
    pub fn membership_epoch(self) -> i64 {
        self.membership_epoch
    }
    /// Invalidate all authentication, including outstanding password candidates.
    pub fn revoke_sessions(self) -> Result<Self, AccountRuleError> {
        if !self.active() {
            return Err(AccountRuleError::Rejected);
        }
        let mut next = self;
        next.epoch = next
            .epoch
            .checked_add(1)
            .ok_or(AccountRuleError::EpochExhausted)?;
        Ok(next)
    }
    pub fn active(self) -> bool {
        self.enabled && self.member_active
    }
    pub fn available_administrator(self) -> bool {
        self.active() && self.administrator
    }
    pub fn authorize_administration(self, tenant: TenantId) -> Result<(), AccountRuleError> {
        if self.key.tenant != tenant || !self.available_administrator() {
            return Err(AccountRuleError::Rejected);
        }
        Ok(())
    }
    pub fn matches_verification(self, expected: Self) -> bool {
        self.active()
            && self.key == expected.key
            && self.epoch == expected.epoch
            && self.has_local_password == expected.has_local_password
            && self.membership_epoch == expected.membership_epoch
    }
    pub fn change(
        self,
        actor: &Self,
        change: LocalChange,
        available_admins: i64,
    ) -> Result<(Self, SecurityAction), AccountRuleError> {
        if matches!(change, LocalChange::Password) && !self.has_local_password {
            return Err(AccountRuleError::Rejected);
        }
        if available_admins < 0 {
            return Err(AccountRuleError::InvalidState);
        }
        if !(matches!(change, LocalChange::Password) && actor.key == self.key && actor.active()) {
            actor.authorize_administration(self.key.tenant)?;
        }
        let mut next = self;
        next.epoch = next
            .epoch
            .checked_add(1)
            .ok_or(AccountRuleError::EpochExhausted)?;
        let action = match change {
            LocalChange::Enabled(v) => {
                next.enabled = v;
                if v {
                    SecurityAction::AccountEnabled
                } else {
                    SecurityAction::AccountDisabled
                }
            }
            LocalChange::Administrator(v) => {
                next.administrator = v;
                next.emergency &= v;
                if v {
                    SecurityAction::AdministratorGranted
                } else {
                    SecurityAction::AdministratorRevoked
                }
            }
            LocalChange::Membership(v) => {
                if v != next.member_active {
                    next.membership_epoch = next
                        .membership_epoch
                        .checked_add(1)
                        .ok_or(AccountRuleError::EpochExhausted)?;
                }
                next.member_active = v;
                if v {
                    SecurityAction::MembershipEnabled
                } else {
                    SecurityAction::MembershipDisabled
                }
            }
            LocalChange::Password => SecurityAction::PasswordChanged,
        };
        if !next.available_local_administrator()
            && available_admins - i64::from(self.available_local_administrator()) < 1
        {
            return Err(AccountRuleError::LastAdministrator);
        }
        Ok((next, action))
    }
    /// The adapter must verify maintenance authority before persisting this result.
    pub fn recover(self) -> Result<(Self, SecurityAction), AccountRuleError> {
        if !self.administrator || !self.has_local_password {
            return Err(AccountRuleError::Rejected);
        }
        let mut next = self;
        next.epoch = next
            .epoch
            .checked_add(1)
            .ok_or(AccountRuleError::EpochExhausted)?;
        Ok((next, SecurityAction::AdministratorRecovered))
    }
}
