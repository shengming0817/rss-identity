use rss_identity_core::federation::*;
use rss_identity_oidc::{HttpOidc, TrustedAssuranceProfile};
use rss_request_context::TenantId;
fn tenant() -> TenantId {
    TenantId::parse("11111111-1111-4111-8111-111111111111").unwrap()
}
fn input() -> ProviderSettingsInput {
    ProviderSettingsInput {
        issuer: "https://idp.example.test".into(),
        client_id: "client".into(),
        redirect_uri: "https://identity.example.test/api/v1/oidc/callback".into(),
        scopes: vec!["openid".into()],
        claims: ClaimMapping {
            email: None,
            groups: None,
        },
        jit: false,
    }
}
fn credentials() -> ProviderCredentials {
    ProviderCredentials::new("fixture-secret".into(), None).unwrap()
}
#[test]
fn self_service_accepts_network_locations_without_deployment_approval() {
    let adapter = HttpOidc::new(vec![]).unwrap();
    for issuer in [
        "https://idp.example.test",
        "https://127.0.0.1",
        "https://169.254.169.254",
        "https://10.0.0.1",
    ] {
        let mut c = input();
        c.issuer = issuer.into();
        assert!(
            adapter
                .validate(tenant(), &c.try_into().unwrap(), &credentials())
                .is_ok()
        );
    }
    for issuer in [
        "http://idp.example.test",
        "not a url",
        "https://user:secret@idp.example.test",
        "https://idp.example.test/#fragment",
    ] {
        let mut c = input();
        c.issuer = issuer.into();
        assert!(
            ProviderSettings::try_from(c)
                .and_then(|c| adapter.validate(tenant(), &c, &credentials()))
                .is_err()
        );
    }
    let c: ProviderSettings = input().try_into().unwrap();
    assert!(
        adapter
            .validate(
                tenant(),
                &c,
                &ProviderCredentials::new(
                    "fixture-secret".into(),
                    Some("invalid certificate".into())
                )
                .unwrap()
            )
            .is_err()
    );
}
#[test]
fn trusted_assurance_is_independent_and_exactly_scoped() {
    let c: ProviderSettings = input().try_into().unwrap();
    let weak = HttpOidc::new(vec![]).unwrap();
    let trusted = HttpOidc::new(vec![TrustedAssuranceProfile {
        tenant: tenant(),
        issuer: c.issuer().as_str().into(),
        client_id: c.client_id().as_str().into(),
        keycloak_totp: true,
    }])
    .unwrap();
    assert_ne!(
        weak.assurance_profile(tenant(), &c),
        trusted.assurance_profile(tenant(), &c)
    );
    let other = TenantId::parse("22222222-2222-4222-8222-222222222222").unwrap();
    assert_eq!(
        weak.assurance_profile(other, &c),
        trusted.assurance_profile(other, &c)
    );
    assert!(trusted.validate(other, &c, &credentials()).is_ok());
}
