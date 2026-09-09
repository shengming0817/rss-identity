use rss_identity_core::assurance::{Assurance, AuthenticationMode};

#[test]
fn only_the_deployment_approved_acr_and_time_establish_mfa() {
    let facts = Assurance::from_verified_oidc(Some(100), Some("2"), vec![], true).unwrap();
    assert_eq!(facts.acr(), "mfa");
    assert!(facts.amr().is_empty(), "ACR must not manufacture AMR");
    assert_eq!(facts.auth_time(), Some(100));
    assert!(facts.check(AuthenticationMode::StepUp, 100, 101).is_ok());
    for (time, acr, trusted) in [
        (Some(100), Some("2"), false),
        (Some(100), Some("1"), true),
        (Some(100), None, true),
        (None, Some("2"), true),
    ] {
        let facts = Assurance::from_verified_oidc(time, acr, vec![], trusted).unwrap();
        assert_eq!(facts.acr(), "unspecified");
        assert!(facts.check(AuthenticationMode::StepUp, 100, 101).is_err());
    }
}

#[test]
fn refresh_or_callback_time_does_not_refresh_authentication() {
    for time in [None, Some(69), Some(132)] {
        let facts = Assurance::from_verified_oidc(time, Some("2"), vec![], true).unwrap();
        assert!(facts.check(AuthenticationMode::StepUp, 100, 101).is_err());
    }
    let facts =
        Assurance::from_verified_oidc(Some(70), Some("2"), vec!["otp".into()], true).unwrap();
    assert!(facts.check(AuthenticationMode::StepUp, 100, 101).is_ok());
    assert_eq!(facts.auth_time(), Some(70));
    assert!(facts.check(AuthenticationMode::StepUp, 100, 99).is_err());
    assert!(Assurance::from_verified_oidc(Some(0), None, vec![], false).is_err());
}

#[test]
fn persisted_facts_are_closed_and_methods_are_bounded() {
    for input in [
        r#"{"auth_time":100,"acr":"unknown","amr":[]}"#,
        r#"{"auth_time":null,"acr":"mfa","amr":[]}"#,
        r#"{"auth_time":100,"acr":"mfa","amr":["invented"]}"#,
        r#"{"auth_time":100,"acr":"mfa","amr":[],"trusted":true}"#,
    ] {
        assert!(serde_json::from_str::<Assurance>(input).is_err());
    }
    let facts = Assurance::from_verified_oidc(
        Some(100),
        Some("2"),
        vec!["otp".into(), "pwd".into(), "otp".into(), "unknown".into()],
        true,
    )
    .unwrap();
    assert_eq!(facts.amr(), ["otp", "pwd"]);
    let encoded = serde_json::to_string(&facts).unwrap();
    assert_eq!(serde_json::from_str::<Assurance>(&encoded).unwrap(), facts);
    assert!(
        Assurance::from_verified_oidc(Some(100), Some("2"), vec!["pwd".into(); 17], true).is_err()
    );
}
