use rss_identity_core::department::{DepartmentId, DepartmentSnapshotClaim};
use rss_identity_core::federation::{ClaimMapping, ProviderSettings, ProviderSettingsInput};
use serde_json::json;

#[test]
fn department_ids_are_exact_bounded_and_never_display_name_normalized() {
    for value in ["engineering", "Engineering", "工程", "dept/a"] {
        assert_eq!(DepartmentId::new(value.into()).unwrap().as_str(), value);
    }
    for value in [
        "".into(),
        " a".into(),
        "a ".into(),
        "a\nb".into(),
        "\u{2003}".into(),
        "x".repeat(257),
        "界".repeat(86),
    ] {
        assert!(DepartmentId::new(value).is_err());
    }
    assert!(DepartmentId::new("x".repeat(256)).is_ok());
    assert!(DepartmentId::new("界".repeat(85)).is_ok());
    assert!(serde_json::from_value::<DepartmentId>(json!(" bad")).is_err());
}

#[test]
fn department_mapping_is_complete_validated_and_has_no_default_age() {
    for seconds in [1, 300] {
        let mapping =
            DepartmentSnapshotClaim::new("organization_snapshot".into(), seconds).unwrap();
        assert_eq!(mapping.claim(), "organization_snapshot");
        assert_eq!(mapping.max_age_seconds(), seconds);
        assert_eq!(
            mapping.expires_at(1000, 2000, 1000).unwrap(),
            1000 + seconds
        );
    }
    for seconds in [0, 301, i64::MAX] {
        assert!(DepartmentSnapshotClaim::new("organization_snapshot".into(), seconds).is_err());
    }
    for claim in [
        "",
        "department.name",
        "email",
        "sub",
        "sid",
        "iat",
        "name",
        "preferred_username",
        "phone_number",
    ] {
        assert!(DepartmentSnapshotClaim::new(claim.into(), 60).is_err());
    }
    for value in [
        json!({"claim":"organization_snapshot"}),
        json!({"max_age_seconds":60}),
        json!({"claim":"organization_snapshot","max_age_seconds":0}),
        json!({"claim":"email","max_age_seconds":60}),
        json!({"claim":"sid","max_age_seconds":60}),
        json!({"claim":"organization_snapshot","max_age_seconds":60,"other":true}),
    ] {
        assert!(serde_json::from_value::<DepartmentSnapshotClaim>(value).is_err());
    }
    let mapping = DepartmentSnapshotClaim::new("organization_snapshot".into(), 60).unwrap();
    assert_eq!(mapping.expires_at(1000, 1020, 1000).unwrap(), 1020);
    assert_eq!(mapping.expires_at(1000, 2000, 1500).unwrap(), 1060);
    assert_eq!(mapping.expires_at(1030, 2000, 1000).unwrap(), 1090);
    assert!(mapping.expires_at(1031, 2000, 1000).is_err());
    assert!(
        mapping
            .expires_at(i64::MAX - 1, i64::MAX, i64::MAX - 1)
            .is_err()
    );
}

#[test]
fn department_mapping_cannot_reuse_email_or_group_claims() {
    for (email, groups) in [(Some("custom".into()), None), (None, Some("custom".into()))] {
        assert!(
            ProviderSettings::try_from(ProviderSettingsInput {
                issuer: "https://idp.test".into(),
                client_id: "client".into(),
                redirect_uri: "https://host.test/api/v2/oidc/callback".into(),
                scopes: vec!["openid".into()],
                jit: false,
                claims: ClaimMapping {
                    email,
                    groups,
                    department_snapshot: Some(
                        DepartmentSnapshotClaim::new("custom".into(), 60).unwrap()
                    )
                },
            })
            .is_err()
        );
    }
}
