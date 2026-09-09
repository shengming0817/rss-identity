use rss_identity_core::{
    PrincipalId,
    account::{AccountKey, AccountState, LocalChange},
};

#[test]
fn federated_accounts_are_members_without_local_credentials() {
    let key = AccountKey {
        tenant: rss_request_context::TenantId::parse("11111111-1111-4111-8111-111111111111")
            .unwrap(),
        principal: PrincipalId::generate(),
    };
    let member = AccountState::new_federated(key).unwrap();
    assert!(member.active());
    assert!(!member.has_local_password());
    assert!(!member.administrator());
    assert!(!member.emergency());
    let admin = AccountState::new_local(
        AccountKey {
            principal: PrincipalId::generate(),
            ..key
        },
        true,
        false,
    )
    .unwrap();
    let (federated_admin, _) = member
        .change(&admin, LocalChange::Administrator(true), 1)
        .unwrap();
    assert!(!federated_admin.available_local_administrator());
    assert!(
        admin
            .change(&admin, LocalChange::Enabled(false), 1)
            .is_err()
    );
    assert!(member.change(&admin, LocalChange::Password, 1).is_err());
    assert!(federated_admin.recover().is_err());
}

#[test]
fn state_authentication_precedes_tenant_use_and_separates_purpose() {
    use rss_identity_core::federation::{Purpose, StateSigner};
    let tenant =
        rss_request_context::TenantId::parse("11111111-1111-4111-8111-111111111111").unwrap();
    let signer = StateSigner::new([7; 32], "https://identity.example.test").unwrap();
    let state = signer.issue(tenant, Purpose::Login).unwrap();
    let decoded = signer.verify(&state).unwrap();
    assert_eq!(decoded.tenant(), tenant);
    assert_eq!(decoded.purpose(), Purpose::Login);
    assert!(
        StateSigner::new([8; 32], "https://identity.example.test")
            .unwrap()
            .verify(&state)
            .is_err()
    );
    assert!(
        StateSigner::new([7; 32], "https://other.example.test")
            .unwrap()
            .verify(&state)
            .is_err()
    );
    for i in 0..state.len() {
        let mut tampered = state.clone().into_bytes();
        tampered[i] = if tampered[i] == b'A' { b'B' } else { b'A' };
        assert!(
            signer
                .verify(std::str::from_utf8(&tampered).unwrap())
                .is_err()
        );
    }
}

#[test]
fn provider_settings_are_validated_at_every_deserialization_boundary() {
    use rss_identity_core::federation::*;
    let valid = serde_json::json!({"issuer":"https://idp.example.test","client_id":"client","secret_ref":"secret@1","redirect_uri":"https://identity.example.test/callback","scopes":["openid"],"claims":{"email":null,"groups":null},"jit":false});
    let checked: ProviderSettings = serde_json::from_value(valid.clone()).unwrap();
    assert!(!checked.jit());
    assert_eq!(checked.issuer().as_str(), "https://idp.example.test");
    for (key, value) in [
        (
            "issuer",
            serde_json::json!("https://user:password@idp.test"),
        ),
        ("client_id", serde_json::json!("")),
        ("secret_ref", serde_json::json!("mutable")),
        ("scopes", serde_json::json!(["openid", "offline_access"])),
        ("claims", serde_json::json!({"email":"sub","groups":null})),
    ] {
        let mut invalid = valid.clone();
        invalid[key] = value;
        assert!(serde_json::from_value::<ProviderSettings>(invalid).is_err());
    }
    let mut edited = checked.input();
    edited.issuer = "not-url".into();
    assert!(ProviderSettings::try_from(edited).is_err());
}
