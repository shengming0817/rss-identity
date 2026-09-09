use rss_identity_core::{
    PrincipalId,
    account::{AccountKey, AccountRuleError, AccountState, LocalChange},
};
fn key() -> AccountKey {
    AccountKey {
        tenant: rss_request_context::TenantId::parse("11111111-1111-4111-8111-111111111111")
            .unwrap(),
        principal: PrincipalId::generate(),
    }
}
#[test]
fn core_owns_transitions_and_last_administrator() {
    let admin = AccountState::new_local(key(), true, false).unwrap();
    assert_eq!(
        admin
            .change(&admin, LocalChange::Enabled(false), 1)
            .unwrap_err(),
        AccountRuleError::LastAdministrator
    );
    let (disabled, _) = admin
        .change(&admin, LocalChange::Enabled(false), 2)
        .unwrap();
    assert!(!disabled.enabled());
    assert_eq!(disabled.epoch(), 2);
    let (recovered, _) = disabled.recover().unwrap();
    assert!(!recovered.enabled());
    assert!(recovered.administrator());
    assert_eq!(recovered.epoch(), 3);
    let member = AccountState::new_local(key(), false, false).unwrap();
    assert!(
        admin
            .change(&member, LocalChange::Administrator(false), 2)
            .is_err()
    );
    assert!(AccountState::restore(key(), true, true, false, true, 0, true, 1).is_err());
    let max = AccountState::restore(key(), true, true, false, true, i64::MAX, true, 1).unwrap();
    assert_eq!(max.recover().unwrap_err(), AccountRuleError::EpochExhausted);
}

#[test]
fn actions_preserve_transition_direction() {
    let admin = AccountState::new_local(key(), true, true).unwrap();
    for (change, action) in [
        (LocalChange::Administrator(true), "administrator_granted"),
        (LocalChange::Administrator(false), "administrator_revoked"),
        (LocalChange::Membership(true), "membership_enabled"),
        (LocalChange::Membership(false), "membership_disabled"),
    ] {
        let (next, actual) = admin.change(&admin, change, 2).unwrap();
        assert_eq!(actual.as_str(), action);
        assert_eq!(next.epoch(), admin.epoch() + 1);
        assert!(!next.matches_verification(admin));
    }
}

#[test]
fn transition_state_and_last_administrator_matrix() {
    let admin = AccountState::new_local(key(), true, true).unwrap();
    let member = AccountState::new_local(key(), false, false).unwrap();
    let (granted, _) = member
        .change(&admin, LocalChange::Administrator(true), 1)
        .unwrap();
    assert!(granted.administrator());
    let (revoked, _) = admin
        .change(&admin, LocalChange::Administrator(false), 2)
        .unwrap();
    assert!(!revoked.administrator() && !revoked.emergency());
    let (disabled, _) = granted
        .change(&admin, LocalChange::Membership(false), 2)
        .unwrap();
    assert!(!disabled.active());
    assert_eq!(disabled.membership_epoch(), 2);
    let (enabled, _) = disabled
        .change(&admin, LocalChange::Membership(true), 1)
        .unwrap();
    assert!(enabled.active());
    assert_eq!(enabled.membership_epoch(), 3);
    for change in [
        LocalChange::Administrator(false),
        LocalChange::Membership(false),
        LocalChange::Enabled(false),
    ] {
        assert_eq!(
            admin.change(&admin, change, 1).unwrap_err(),
            AccountRuleError::LastAdministrator
        );
        assert_eq!(
            admin.change(&member, change, 2).unwrap_err(),
            AccountRuleError::Rejected
        );
    }
}
