use rss_identity_core::assurance::{Assurance, AuthenticationMode};
#[test]
fn normalized_facts_enforce_time_strength_and_method_invariants() {
    let facts = Assurance::new(Some(100), "mfa", vec!["otp".into()]).unwrap();
    assert!(facts.check(AuthenticationMode::StepUp, 100, 101).is_ok());
    for time in [69, 132] {
        assert!(
            Assurance::new(Some(time), "mfa", vec![])
                .unwrap()
                .check(AuthenticationMode::StepUp, 100, 101)
                .is_err()
        );
    }
    for (time, acr, methods) in [
        (None, "mfa", vec![]),
        (Some(0), "unspecified", vec![]),
        (Some(100), "unknown", vec![]),
        (Some(100), "mfa", vec!["invented".into()]),
        (Some(100), "mfa", vec!["otp".into(), "otp".into()]),
    ] {
        assert!(Assurance::new(time, acr, methods).is_err());
    }
    assert_eq!(
        serde_json::from_str::<Assurance>(&serde_json::to_string(&facts).unwrap()).unwrap(),
        facts
    );
    assert!(
        serde_json::from_str::<Assurance>(
            r#"{"auth_time":100,"acr":"mfa","amr":[],"trusted":true}"#
        )
        .is_err()
    );
}
