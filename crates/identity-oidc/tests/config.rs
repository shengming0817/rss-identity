use rss_identity_core::federation::*;
use rss_identity_oidc::{ApprovedProvider, HttpOidc};
use rss_request_context::TenantId;
use std::collections::BTreeMap;
use zeroize::Zeroizing;
fn tenant() -> TenantId {
    TenantId::parse("11111111-1111-4111-8111-111111111111").unwrap()
}
fn input() -> ProviderSettingsInput {
    ProviderSettingsInput {
        issuer: "https://idp.example.test".into(),
        client_id: "client".into(),
        secret_ref: "fixture@1".into(),
        redirect_uri: "https://identity.example.test/callback".into(),
        scopes: vec!["openid".into()],
        claims: ClaimMapping {
            email: None,
            groups: None,
        },
        jit: false,
    }
}
fn binding(c: &ProviderSettingsInput) -> ApprovedProvider {
    ApprovedProvider {
        keycloak_totp: false,
        tenant: tenant(),
        issuer: c.issuer.clone(),
        client_id: c.client_id.clone(),
        secret_ref: c.secret_ref.clone(),
        redirect_uri: c.redirect_uri.clone(),
        addresses: vec!["192.0.2.0/24".parse().unwrap()],
    }
}
#[test]
fn rejects_insecure_ambiguous_and_unapproved_configuration() {
    let adapter = HttpOidc::new(
        vec![binding(&input())],
        BTreeMap::from([("fixture@1".into(), Zeroizing::new("secret".into()))]),
        None,
    )
    .unwrap();
    let config: ProviderSettings = input().try_into().unwrap();
    assert!(adapter.validate(tenant(), &config).is_ok());
    for issuer in [
        "http://idp.example.test",
        "not a url",
        "https://user:secret@idp.example.test",
        "https://idp.example.test/#fragment",
        "https://127.0.0.1",
        "https://169.254.169.254",
    ] {
        let mut c = config.input();
        c.issuer = issuer.into();
        assert!(
            ProviderSettings::try_from(c)
                .and_then(|c| adapter.validate(tenant(), &c))
                .is_err()
        );
    }
    for callback in [
        "http://identity.example.test/callback",
        "https://other.example.test/callback",
    ] {
        let mut c = config.input();
        c.redirect_uri = callback.into();
        assert!(adapter.validate(tenant(), &c.try_into().unwrap()).is_err());
    }
    let mut c = config.input();
    c.secret_ref = "fixture@2".into();
    assert!(adapter.validate(tenant(), &c.try_into().unwrap()).is_err());
    let mut c = config.input();
    c.scopes.push("offline_access".into());
    assert!(ProviderSettings::try_from(c).is_err());
}
#[test]
fn credentials_cannot_be_recombined_with_another_approved_issuer() {
    let victim = input();
    let mut attacker = input();
    attacker.issuer = "https://attacker.example.test".into();
    attacker.client_id = "attacker-client".into();
    attacker.secret_ref = "attacker@1".into();
    let adapter = HttpOidc::new(
        vec![binding(&victim), binding(&attacker)],
        BTreeMap::from([("fixture@1".into(), Zeroizing::new("secret".into()))]),
        None,
    )
    .unwrap();
    let mut forged = victim.clone();
    forged.issuer = attacker.issuer;
    assert_eq!(
        adapter.validate(tenant(), &forged.try_into().unwrap()),
        Err(FederationError::provider(
            ProviderStage::Binding,
            ProviderReason::UnapprovedBinding
        ))
    );
    let other = TenantId::parse("22222222-2222-4222-8222-222222222222").unwrap();
    assert!(
        adapter
            .validate(other, &victim.try_into().unwrap())
            .is_err()
    );
}
#[test]
fn static_approval_does_not_load_secrets() {
    let c = input();
    assert!(HttpOidc::approve(&[binding(&c)], tenant(), &c.try_into().unwrap()).is_ok());
}
