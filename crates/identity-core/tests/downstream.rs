use rss_identity_core::downstream::{
    FlowState, LifetimeLimits, Lifetimes, Registration, RegistrationInput,
};
use rss_request_context::TenantId;
#[test]
fn downstream_transitions_cannot_skip_or_reactivate() {
    use FlowState::*;
    assert!(AwaitingLogin.advance(LoginAccepting).is_ok());
    assert!(LoginAccepting.advance(AwaitingConsent).is_ok());
    assert!(AwaitingConsent.advance(ConsentAccepting).is_ok());
    assert!(ConsentAccepting.advance(Active).is_ok());
    for s in [
        AwaitingLogin,
        LoginAccepting,
        AwaitingConsent,
        ConsentAccepting,
        Active,
    ] {
        assert!(s.advance(Revoking).is_ok());
        assert!(Revoking.advance(s).is_err());
    }
    assert!(AwaitingLogin.advance(Active).is_err());
    assert!(Active.advance(Active).is_err());
}
#[test]
fn downstream_requires_finite_horizon_and_exact_registration() {
    assert!(
        Lifetimes::new(LifetimeLimits {
            request: 300,
            code: 60,
            access_token: 300,
            clock_skew: 30
        })
        .is_ok()
    );
    assert!(
        Lifetimes::new(LifetimeLimits {
            request: 0,
            code: 60,
            access_token: 300,
            clock_skew: 30
        })
        .is_err()
    );
    assert!(
        Lifetimes::new(LifetimeLimits {
            request: i64::MAX,
            code: 60,
            access_token: 300,
            clock_skew: 30
        })
        .is_err()
    );
    let t = TenantId::parse("11111111-1111-4111-8111-111111111111").unwrap();
    for issuer in [
        "http://identity.example.test/oidc",
        "https://user@identity.example.test/oidc",
        "https://identity.example.test/oidc?x=1",
    ] {
        assert!(
            Registration::new(RegistrationInput {
                tenant: t,
                client: ("mdm").to_owned(),
                audience: ("mdm-api").to_owned(),
                issuer: (issuer).to_owned(),
                redirect: ("https://mdm.example.test/auth/callback").to_owned(),
                version: 1
            })
            .is_err()
        );
    }
    assert!(
        Registration::new(RegistrationInput {
            tenant: t,
            client: ("mdm").to_owned(),
            audience: ("mdm-api").to_owned(),
            issuer: ("https://identity.example.test/oidc").to_owned(),
            redirect: ("https://mdm.example.test/auth/callback").to_owned(),
            version: 1
        })
        .is_ok()
    );
}

#[test]
fn browser_binding_is_redacted_and_domain_separated() {
    let secret = rss_identity_core::downstream::BrowserBindingSecret::generate().unwrap();
    assert_eq!(secret.expose().len(), 64);
    assert!(!format!("{secret:?}").contains(secret.expose()));
    let parsed =
        rss_identity_core::downstream::BrowserBindingSecret::parse(secret.expose().into()).unwrap();
    assert_eq!(parsed.digest(), secret.digest());
    let session = rss_identity_core::session::SessionSecret::parse(secret.expose().into()).unwrap();
    assert_ne!(session.digest(), secret.digest());
    for invalid in ["", "z", &"A".repeat(64), &"a".repeat(63)] {
        assert!(
            rss_identity_core::downstream::BrowserBindingSecret::parse(invalid.into()).is_err()
        );
    }
}
