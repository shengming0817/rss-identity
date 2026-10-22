use rss_identity_core::profile::*;
use serde_json::json;
#[test]
fn values_remain_typed_and_cannot_become_security_facts() {
    let settings = ProfileSettings {
        extensions_claim: Some("attributes".into()),
        max_age_seconds: 14400,
    };
    let profile=Profile::from_claims(json!({"name":"","email":42,"email_verified":"true","attributes":{"mfa":true,"roles":["admin"],"remote":false,"count":0,"empty":[],"unset":null}}).as_object().unwrap(),&settings);
    assert_eq!(profile.display_name.value().map(String::as_str), Some(""));
    assert!(matches!(profile.email, Attribute::Invalid));
    assert!(matches!(profile.email_verified, Attribute::Invalid));
    let values = profile.extensions.value().unwrap().object();
    assert_eq!(values["remote"], false);
    assert_eq!(values["count"], 0);
    assert_eq!(values["empty"], json!([]));
    assert!(
        Profile::from_claims(json!({}).as_object().unwrap(), &settings)
            .extensions
            .value()
            .is_none()
    );
    let wire = serde_json::to_value(profile).unwrap();
    assert!(wire.get("principalId").is_none());
}
#[test]
fn extension_budgets_and_sensitive_material_fail_closed() {
    assert!(Extensions::try_from(json!({"a":vec![0;128]})).is_ok());
    assert!(Extensions::try_from(json!({"a":vec![0;129]})).is_err());
    assert!(Extensions::try_from(json!({"n":9007199254740992_u64})).is_err());
    assert!(Extensions::try_from(json!({"n":9007199254740991_u64})).is_ok());
    assert!(Extensions::try_from(json!({"n":1.25})).is_ok());
    let mut object = serde_json::Map::new();
    for i in 0..256 {
        object.insert(i.to_string(), json!(null));
    }
    assert!(Extensions::try_from(json!(object)).is_ok());
    object.insert("extra".into(), json!(null));
    assert!(Extensions::try_from(json!(object)).is_err());
    let mut value = json!({});
    for _ in 1..8 {
        value = json!({"nested":value});
    }
    assert!(Extensions::try_from(value.clone()).is_ok());
    assert!(Extensions::try_from(json!({"nested":value})).is_err());
    assert!(Extensions::try_from(json!({"s":"x".repeat(MAX_BYTES)})).is_err());
    for name in [
        "password",
        "client_secret",
        "private-key",
        "refresh_token",
        "totp_seed",
    ] {
        assert!(Extensions::try_from(json!({"nested":{name:"secret"}})).is_err());
    }
    for age in [0, 59, 86401, u32::MAX] {
        assert!(
            ProfileSettings {
                extensions_claim: None,
                max_age_seconds: age
            }
            .validate()
            .is_err()
        );
    }
    for age in [60, 14400, 86400] {
        assert!(
            ProfileSettings {
                extensions_claim: None,
                max_age_seconds: age
            }
            .validate()
            .is_ok()
        );
    }
}
#[test]
fn local_profile_has_no_verified_email_or_authority_override() {
    let local = LocalProfile {
        display_name: None,
        username: Some("display-only".into()),
        email: Some("a@example.test".into()),
        extensions: Extensions::try_from(json!({"principalId":"untrusted"})).unwrap(),
        max_age_seconds: 60,
    };
    assert!(matches!(
        local.observation().unwrap().email_verified,
        Attribute::Missing
    ));
    let mut input = serde_json::to_value(local).unwrap();
    input["emailVerified"] = json!(true);
    assert!(serde_json::from_value::<LocalProfile>(input).is_err());
}
