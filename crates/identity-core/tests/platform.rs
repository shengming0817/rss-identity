use rss_identity_core::{
    PrincipalId,
    account::{AccountKey, AccountState, LocalChange},
    platform::{PlatformAccount, PlatformError},
};
use rss_request_context::TenantId;

fn account() -> AccountState {
    AccountState::new_local(
        AccountKey {
            tenant: TenantId::parse("11111111-1111-4111-8111-111111111111").unwrap(),
            principal: PrincipalId::generate(),
        },
        false,
        false,
    )
    .unwrap()
}

#[test]
fn platform_authority_is_explicit_and_system_scoped() {
    let state = account();
    assert_eq!(
        PlatformAccount::new(state.key().tenant, state, false)
            .unwrap()
            .authorize(),
        Err(PlatformError::Forbidden)
    );
    let platform = PlatformAccount::new(state.key().tenant, state, true).unwrap();
    assert!(platform.authorize().is_ok());
    assert!(!platform.account().administrator());
    let other = TenantId::parse("22222222-2222-4222-8222-222222222222").unwrap();
    assert!(PlatformAccount::new(other, state, true).is_err());
    let tenant_admin = AccountState::new_local(state.key(), true, false).unwrap();
    assert!(PlatformAccount::new(state.key().tenant, tenant_admin, true).is_err());
}

#[test]
fn final_local_platform_administrator_cannot_be_removed() {
    let state = account();
    let admin = PlatformAccount::new(state.key().tenant, state, true).unwrap();
    assert_eq!(
        admin.set_role(false, 1),
        Err(PlatformError::LastAdministrator)
    );
    for change in [LocalChange::Enabled(false), LocalChange::Membership(false)] {
        assert_eq!(
            admin.change(change, 1),
            Err(PlatformError::LastAdministrator)
        );
    }
    let next = admin.set_role(false, 2).unwrap();
    assert!(!next.has_role());
    assert_eq!(next.account().epoch(), state.epoch() + 1);
    assert_eq!(next.authorize(), Err(PlatformError::Forbidden));
}

#[test]
fn platform_recovery_never_restores_access() {
    let state = account();
    let admin = PlatformAccount::new(state.key().tenant, state, true).unwrap();
    let disabled = admin.change(LocalChange::Enabled(false), 2).unwrap();
    let recovered = disabled.recover().unwrap();
    assert!(!recovered.account().enabled());
    assert!(recovered.has_role());
    assert_eq!(recovered.account().epoch(), disabled.account().epoch() + 1);
    assert!(admin.set_role(false, 2).unwrap().recover().is_err());
    assert!(admin.change(LocalChange::Administrator(true), 2).is_err());
}
