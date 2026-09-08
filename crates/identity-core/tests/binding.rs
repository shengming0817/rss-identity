use rss_identity_core::{
    Audience, Binding, ClientId, Epoch, IssuerId, PrincipalId, SessionId, SessionSnapshot,
    UnixTime, ValidationError,
};

fn principal(n: u128) -> PrincipalId {
    PrincipalId::parse(&uuid::Uuid::from_u128(n).to_string()).unwrap()
}
fn sid(n: u128) -> SessionId {
    SessionId::parse(&uuid::Uuid::from_u128(n).to_string()).unwrap()
}
fn time(n: u64) -> UnixTime {
    UnixTime::new(n).unwrap()
}
fn epoch(n: u64) -> Epoch {
    Epoch::new(n).unwrap()
}
fn tenant(n: u128) -> rss_request_context::TenantId {
    rss_request_context::TenantId::parse(&uuid::Uuid::from_u128(n).to_string()).unwrap()
}
fn binding() -> Binding {
    Binding::new(
        IssuerId::parse("https://identity.example.test").unwrap(),
        tenant(1),
        ClientId::parse("mdm").unwrap(),
        Audience::parse("mdm-api").unwrap(),
    )
}
fn session() -> SessionSnapshot {
    SessionSnapshot::new(binding(), principal(2), sid(3), epoch(1), time(100))
}

#[test]
fn validates_only_matching_current_unexpired_binding() {
    assert!(
        session()
            .check(&binding(), time(99), epoch(1), true)
            .is_ok()
    );
    assert_eq!(
        session().check(&binding(), time(100), epoch(1), true),
        Err(ValidationError::Inactive)
    );
    assert_eq!(
        session().check(&binding(), time(99), epoch(2), true),
        Err(ValidationError::Inactive)
    );
    assert_eq!(
        session().check(&binding(), time(99), epoch(1), false),
        Err(ValidationError::Inactive)
    );
}
#[test]
fn rejects_every_binding_mismatch() {
    for expected in [
        Binding::new(
            IssuerId::parse("https://other.example.test").unwrap(),
            tenant(1),
            ClientId::parse("mdm").unwrap(),
            Audience::parse("mdm-api").unwrap(),
        ),
        Binding::new(
            IssuerId::parse("https://identity.example.test").unwrap(),
            tenant(4),
            ClientId::parse("mdm").unwrap(),
            Audience::parse("mdm-api").unwrap(),
        ),
        Binding::new(
            IssuerId::parse("https://identity.example.test").unwrap(),
            tenant(1),
            ClientId::parse("other").unwrap(),
            Audience::parse("mdm-api").unwrap(),
        ),
        Binding::new(
            IssuerId::parse("https://identity.example.test").unwrap(),
            tenant(1),
            ClientId::parse("mdm").unwrap(),
            Audience::parse("other").unwrap(),
        ),
    ] {
        assert_eq!(
            session().check(&expected, time(99), epoch(1), true),
            Err(ValidationError::BindingMismatch)
        );
    }
}
#[test]
fn invalid_values_never_construct() {
    assert!(PrincipalId::parse("not-a-uuid").is_err());
    assert!(SessionId::parse(&uuid::Uuid::nil().to_string()).is_err());
    assert!(IssuerId::parse("").is_err());
    assert!(ClientId::parse(" ").is_err());
    assert!(Audience::parse("invalid\n").is_err());
    assert!(Epoch::new(0).is_err());
    assert!(UnixTime::new(0).is_err());
}
