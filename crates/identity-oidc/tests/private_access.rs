use rss_identity_core::federation::*;
use rss_identity_oidc::{HttpOidc, PrivateProviderAccess};
use rss_request_context::TenantId;

fn tenant() -> TenantId {
    TenantId::parse("11111111-1111-4111-8111-111111111111").unwrap()
}
fn grant(issuer: &str, cidrs: &[&str]) -> PrivateProviderAccess {
    PrivateProviderAccess {
        tenant: tenant(),
        issuer: issuer.into(),
        client_id: "client".into(),
        cidrs: cidrs.iter().map(|value| value.parse().unwrap()).collect(),
    }
}
fn settings(issuer: &str, client: &str) -> ProviderSettings {
    ProviderSettingsInput {
        issuer: issuer.into(),
        client_id: client.into(),
        redirect_uri: "https://reference.example.test/api/v2/oidc/callback".into(),
        scopes: vec!["openid".into()],
        claims: ClaimMapping {
            email: None,
            groups: None,
            department_snapshot: None,
        },
        jit: false,
    }
    .try_into()
    .unwrap()
}
#[test]
fn private_grants_are_exact_and_do_not_grant_mfa() {
    let issuer = "https://10.42.0.9:8443/realms/reference";
    let adapter = HttpOidc::new(vec![], vec![grant(issuer, &["10.42.0.9/32"])]).unwrap();
    let credentials = ProviderCredentials::new("private-test-secret".into(), None).unwrap();
    let provider = settings(issuer, "client");
    assert!(adapter.validate(tenant(), &provider, &credentials).is_ok());
    assert!(
        !adapter
            .assurance_profile(tenant(), &provider)
            .supports_step_up
    );
    for (owner, config) in [
        (tenant(), settings(issuer, "other")),
        (
            tenant(),
            settings("https://10.42.0.9:8443/realms/other", "client"),
        ),
        (
            tenant(),
            settings("https://10.42.0.10:8443/realms/reference", "client"),
        ),
        (
            TenantId::parse("22222222-2222-4222-8222-222222222222").unwrap(),
            provider,
        ),
    ] {
        assert!(adapter.validate(owner, &config, &credentials).is_err());
    }
}
#[test]
fn only_bounded_canonical_private_networks_are_authorizable() {
    for cidrs in [
        vec![],
        vec!["0.0.0.0/0"],
        vec!["127.0.0.1/32"],
        vec!["169.254.169.254/32"],
        vec!["100.64.0.0/10"],
        vec!["::/0"],
        vec!["::1/128"],
        vec!["fe80::/10"],
        vec!["::ffff:10.42.0.9/128"],
        vec!["10.42.0.9/24"],
        vec!["10.42.0.0/24", "10.42.0.0/24"],
    ] {
        assert!(
            HttpOidc::new(
                vec![],
                vec![grant("https://idp.example.test/realm", &cidrs)]
            )
            .is_err(),
            "{cidrs:?}"
        );
    }
    for cidr in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fd00::/8"] {
        assert!(
            HttpOidc::new(
                vec![],
                vec![grant("https://idp.example.test/realm", &[cidr])]
            )
            .is_ok()
        );
    }
    let duplicate = || grant("https://idp.example.test/realm", &["10.0.0.0/8"]);
    assert!(HttpOidc::new(vec![], vec![duplicate(), duplicate()]).is_err());
    assert!(
        HttpOidc::new(
            vec![],
            (0..129)
                .map(|i| grant(&format!("https://idp{i}.example.test"), &["10.0.0.0/8"]))
                .collect()
        )
        .is_err()
    );
    assert!(
        HttpOidc::new(
            vec![],
            vec![grant("http://idp.example.test", &["10.0.0.0/8"])]
        )
        .is_err()
    );
}
