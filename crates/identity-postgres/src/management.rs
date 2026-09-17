//! Host authorization is the only management authority. No product roles are stored here.
use crate::session_storage::Loaded;
use rss_identity_core::{
    InstanceId,
    account::{AccountKey, AccountRuleError},
    assurance::{Acr, Assurance},
    federation::ProviderId,
    groups::Groups,
};
use std::time::Duration;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagementOperation {
    ListAccounts,
    CreateAccount,
    SetAccountEnabled(bool),
    SetMembership(bool),
    ResetPassword,
    ListProviders,
    CreateProvider,
    UpdateProvider(ProviderId),
    SetProviderEnabled(ProviderId, bool),
    TestProvider(ProviderId),
}
#[derive(Debug, Clone, Copy)]
pub enum ReauthenticationRequirement {
    None,
    Recent(Duration),
    RecentMfa(Duration),
}
#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("management denied by host")]
pub struct ManagementDenied;
/// Created only after the component has loaded authoritative state in this transaction.
pub struct ManagementContext<'a> {
    instance: InstanceId,
    actor: AccountKey,
    target: Option<AccountKey>,
    operation: ManagementOperation,
    assurance: &'a Assurance,
    groups: &'a Groups,
}
impl ManagementContext<'_> {
    pub fn instance(&self) -> InstanceId {
        self.instance
    }
    pub fn actor(&self) -> AccountKey {
        self.actor
    }
    pub fn target(&self) -> Option<AccountKey> {
        self.target
    }
    pub fn operation(&self) -> ManagementOperation {
        self.operation
    }
    pub fn assurance(&self) -> &Assurance {
        self.assurance
    }
    pub fn groups(&self) -> &Groups {
        self.groups
    }
}
/// Bounded in-process policy, invoked for every management operation. Do not perform blocking I/O.
pub trait ManagementPolicy: Send + Sync {
    fn authorize(
        &self,
        context: &ManagementContext<'_>,
    ) -> Result<ReauthenticationRequirement, ManagementDenied>;
}
pub(crate) struct DenyManagement;
impl ManagementPolicy for DenyManagement {
    fn authorize(
        &self,
        _: &ManagementContext<'_>,
    ) -> Result<ReauthenticationRequirement, ManagementDenied> {
        Err(ManagementDenied)
    }
}
pub(crate) fn authorize(
    policy: &dyn ManagementPolicy,
    instance: InstanceId,
    loaded: &Loaded,
    operation: ManagementOperation,
    target: Option<AccountKey>,
) -> Result<(), AccountRuleError> {
    if target.is_some_and(|t| t.tenant != loaded.state.key().tenant) {
        return Err(AccountRuleError::InsufficientPrivilege);
    }
    let requirement = policy
        .authorize(&ManagementContext {
            instance,
            actor: loaded.state.key(),
            target,
            operation,
            assurance: &loaded.assurance,
            groups: &loaded.groups,
        })
        .map_err(|_| AccountRuleError::InsufficientPrivilege)?;
    let (max_age, mfa) = match requirement {
        ReauthenticationRequirement::None => return Ok(()),
        ReauthenticationRequirement::Recent(age) => (age, false),
        ReauthenticationRequirement::RecentMfa(age) => (age, true),
    };
    let age = loaded
        .assurance
        .auth_time()
        .and_then(|time| loaded.now.checked_sub(time));
    if max_age.is_zero()
        || age.is_none_or(|age| {
            age < 0 || u64::try_from(age).is_ok_and(|age| age >= max_age.as_secs())
        })
        || (mfa && loaded.assurance.acr() != Acr::Mfa)
    {
        return Err(AccountRuleError::ReauthenticationRequired);
    }
    Ok(())
}
