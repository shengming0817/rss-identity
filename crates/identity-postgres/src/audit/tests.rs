use super::*;
#[test]
fn rejects_unknown_contract() {
    assert!(accepted_contract("identity.unknown", "1.0.0", "sha256:bad").is_none());
}
use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
use rss_transactional_messaging::message::*;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
const TENANT: &str = "11111111-1111-4111-8111-111111111111";
const PRINCIPAL: &str = "22222222-2222-4222-8222-222222222222";
const SESSION: &str = "33333333-3333-4333-8333-333333333333";
pub(super) fn envelope(kind: &str, body: Value) -> MessageEnvelope<Vec<u8>> {
    let (version, schema) = match kind {
        "account" => (3, include_str!("../security-event-v3.json")),
        "session" => (1, include_str!("../session-security-event-v1.json")),
        _ => (2, include_str!("../federation-security-event-v2.json")),
    };
    MessageEnvelope::new(
        MessageId::parse("event-1").unwrap(),
        MessageMetadata::new(
            AuthoredMessageMetadata::new(
                TenantId::parse(TENANT).unwrap(),
                Timepoint::try_from(100).unwrap(),
                MessagingDomain::parse("identity.security").unwrap(),
                MessageRoute::parse(&format!("{kind}.changed")).unwrap(),
                ContractIdentity::new(
                    ContractId::parse(&format!("identity.{kind}.security")).unwrap(),
                    ContractVersion::from_major(version).unwrap(),
                    SchemaDigest::parse(&format!("sha256:{:x}", Sha256::digest(schema))).unwrap(),
                ),
            ),
            MessageMetadataExtensions::default(),
        ),
        serde_json::to_vec(&body).unwrap(),
    )
}
fn mapped(kind: &str, body: Value) -> rss_audit_core::AuditEventV1 {
    map_event(
        InstanceId::parse(TENANT).unwrap(),
        &envelope(kind, body),
        Timepoint::try_from(101).unwrap(),
    )
    .unwrap()
}
#[test]
fn all_actions_have_explicit_safe_facts() {
    let state = json!({"enabled":true,"member_active":true,"membership_epoch":1});
    for action in [
        "initialized",
        "account_created",
        "account_enabled",
        "account_disabled",
        "membership_enabled",
        "membership_disabled",
        "password_changed",
        "password_recovered",
    ] {
        let event = mapped(
            "account",
            json!({"action":action,"tenant":TENANT,"principal":PRINCIPAL,"actor":PRINCIPAL,"epoch":1,"state":state}),
        );
        assert_eq!(
            event.facts().action().as_str(),
            format!("identity.account.{action}")
        );
        assert_eq!(event.facts().resource().id().as_str(), PRINCIPAL);
        assert_eq!(event.facts().outcome(), rss_audit_core::Outcome::Succeeded);
    }
    for action in ["created", "refreshed", "revoked", "all_revoked"] {
        let event = mapped(
            "session",
            json!({"action":action,"tenant":TENANT,"principal":PRINCIPAL,"session_id":SESSION,"replaced_session_id":null,"epoch":1}),
        );
        assert_eq!(
            event.facts().resource().id().as_str(),
            if action == "all_revoked" {
                PRINCIPAL
            } else {
                SESSION
            }
        );
        assert_eq!(
            event.facts().resource().kind().as_str(),
            if action == "all_revoked" {
                "account_sessions"
            } else {
                "session"
            }
        );
    }
    for action in [
        "provider_created",
        "provider_updated",
        "provider_enabled",
        "provider_disabled",
        "provider_tested",
        "provider_test_failed",
        "jit_created",
        "logged_in",
        "linked",
        "already_linked",
        "reauthenticated",
        "stepped_up",
    ] {
        let mut body = json!({"tenant":TENANT,"action":action,"principal":PRINCIPAL,"provider_id":SESSION,"config_version":1});
        if action == "provider_test_failed" {
            body["diagnostic"] = json!({"stage":"claims","reason":"invalid_token"});
        }
        let event = mapped("federation", body);
        assert_eq!(
            event.facts().outcome(),
            if action == "provider_test_failed" {
                rss_audit_core::Outcome::Failed
            } else {
                rss_audit_core::Outcome::Succeeded
            }
        );
        let payload = String::from_utf8(event.context().payload().as_bytes().to_vec()).unwrap();
        assert!(!payload.contains("credential"));
    }
}
#[test]
fn malformed_and_sensitive_additions_are_rejected() {
    let body = json!({"action":"created","tenant":TENANT,"principal":PRINCIPAL,"session_id":SESSION,"replaced_session_id":null,"epoch":1});
    for (key, value) in [
        ("token", json!("secret")),
        ("tenant", json!(PRINCIPAL)),
        ("action", json!("future")),
        ("epoch", json!(0)),
        ("session_id", json!("bearer-secret")),
    ] {
        let mut changed = body.clone();
        changed[key] = value;
        assert!(
            map_event(
                InstanceId::generate(),
                &envelope("session", changed),
                Timepoint::try_from(101).unwrap()
            )
            .is_err()
        );
    }
    let mut missing = body.clone();
    missing
        .as_object_mut()
        .unwrap()
        .remove("replaced_session_id");
    assert!(
        map_event(
            InstanceId::generate(),
            &envelope("session", missing),
            Timepoint::try_from(101).unwrap()
        )
        .is_err()
    );
    assert!(
        map_event(
            InstanceId::generate(),
            &envelope("session", body),
            Timepoint::try_from(99).unwrap()
        )
        .is_err()
    );
    assert!(matches!(outcome(None), PublishOutcome::Ambiguous(_)));
    assert!(matches!(
        outcome(Some(SettlementKind::Requeue)),
        PublishOutcome::Ambiguous(_)
    ));
    assert!(matches!(
        outcome(Some(SettlementKind::Reject)),
        PublishOutcome::DefinitelyNotPublished(_)
    ));
    assert!(matches!(
        outcome(Some(SettlementKind::Acknowledge)),
        PublishOutcome::Confirmed(())
    ));
}
