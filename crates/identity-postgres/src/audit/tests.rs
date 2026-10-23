use super::*;
#[test]
fn notification_channel_is_stable_opaque_and_scope_bound() {
    let instance = InstanceId::parse("11111111-1111-4111-8111-111111111111").unwrap();
    let tenant = TenantId::parse("22222222-2222-4222-8222-222222222222").unwrap();
    let channel = notification_channel(instance, tenant);
    assert_eq!(
        channel,
        "id_audit_6b98298d7dd945af598b610aa8801c898a349ad3f6f8796a"
    );
    assert_eq!(channel.len(), 57);
    assert_ne!(
        channel,
        notification_channel(InstanceId::generate(), tenant)
    );
    assert_ne!(
        channel,
        notification_channel(instance, TenantId::parse(TENANT).unwrap())
    );
}
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
        "profile" => (1, include_str!("../profile-security-event-v1.json")),
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
            json!({"action":action,"tenant":TENANT,"principal":PRINCIPAL,"source":"local_password","session_id":SESSION,"replaced_session_id":null,"epoch":1}),
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
    let body = json!({"action":"created","tenant":TENANT,"principal":PRINCIPAL,"source":"local_password","session_id":SESSION,"replaced_session_id":null,"epoch":1});
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
}

#[test]
fn known_contracts_require_exact_version_and_schema() {
    for (name, version, schema) in [
        ("account", 3, include_str!("../security-event-v3.json")),
        (
            "session",
            1,
            include_str!("../session-security-event-v1.json"),
        ),
        (
            "federation",
            2,
            include_str!("../federation-security-event-v2.json"),
        ),
    ] {
        let id = format!("identity.{name}.security");
        let digest = format!("sha256:{:x}", Sha256::digest(schema));
        assert_eq!(
            accepted_contract(&id, &format!("v{version}"), &digest),
            Some(format!("{name}.changed").as_str())
        );
        assert!(accepted_contract(&id, &format!("v{}", version + 1), &digest).is_none());
        assert!(
            accepted_contract(
                &id,
                &format!("v{version}"),
                &format!("sha256:{}", "0".repeat(64))
            )
            .is_none()
        );
    }
}

#[test]
fn unadmitted_envelope_tenant_never_receives_ingress_authority() {
    let message = envelope(
        "session",
        json!({"action":"created","tenant":TENANT,"principal":PRINCIPAL,"source":"local_password","session_id":SESSION,"replaced_session_id":null,"epoch":1}),
    );
    let m = message.metadata();
    let subscription =
        SubscriptionIdentity::new(m.domain().clone(), m.route().clone(), m.contract().clone());
    let validator = Validator {
        tenants: vec![TenantId::parse(PRINCIPAL).unwrap()],
    };
    let rejected = rss_transactional_messaging::transaction::verify_ingress(
        &validator,
        ConsumerGroup::parse("identity.audit.v1").unwrap(),
        &subscription,
        &message,
    )
    .err()
    .unwrap();
    assert_eq!(
        rejected.reason(),
        EnvelopeValidationFailure::MalformedIdentity
    );
}

#[test]
fn complete_forensic_facts_cover_special_actor_and_resource_cases() {
    let state = json!({"enabled":true,"member_active":true,"membership_epoch":7});
    let cases = [
        (
            "account",
            json!({"action":"account_created","tenant":TENANT,"principal":PRINCIPAL,"actor":null,"epoch":2,"state":state}),
            "maintenance",
            TENANT,
            "identity.account.account_created",
            "account",
            PRINCIPAL,
            json!({"epoch":2,"state":state}),
        ),
        (
            "account",
            json!({"action":"account_disabled","tenant":TENANT,"principal":PRINCIPAL,"actor":SESSION,"epoch":2,"state":state}),
            "principal",
            SESSION,
            "identity.account.account_disabled",
            "account",
            PRINCIPAL,
            json!({"epoch":2,"state":state}),
        ),
        (
            "session",
            json!({"action":"created","tenant":TENANT,"principal":PRINCIPAL,"source":"local_password","session_id":SESSION,"replaced_session_id":TENANT,"epoch":2}),
            "principal",
            PRINCIPAL,
            "identity.session.created",
            "session",
            SESSION,
            json!({"epoch":2,"source":"local_password","session_id":SESSION,"replaced_session_id":TENANT}),
        ),
        (
            "session",
            json!({"action":"all_revoked","tenant":TENANT,"principal":PRINCIPAL,"source":"local_password","session_id":SESSION,"replaced_session_id":null,"epoch":3}),
            "principal",
            PRINCIPAL,
            "identity.session.all_revoked",
            "account_sessions",
            PRINCIPAL,
            json!({"epoch":3,"source":"local_password","session_id":SESSION,"replaced_session_id":null}),
        ),
        (
            "federation",
            json!({"action":"provider_updated","tenant":TENANT,"principal":null,"provider_id":SESSION,"config_version":4}),
            "system",
            TENANT,
            "identity.federation.provider_updated",
            "provider",
            SESSION,
            json!({"provider_id":SESSION,"config_version":4,"diagnostic":null}),
        ),
        (
            "federation",
            json!({"action":"logged_in","tenant":TENANT,"principal":PRINCIPAL,"provider_id":SESSION,"config_version":4}),
            "principal",
            PRINCIPAL,
            "identity.federation.logged_in",
            "federated_principal",
            PRINCIPAL,
            json!({"provider_id":SESSION,"config_version":4,"diagnostic":null}),
        ),
    ];
    for (kind, body, actor_kind, actor_id, action, resource_kind, resource_id, payload) in cases {
        let event = mapped(kind, body);
        assert_eq!(event.identity().tenant().to_string(), TENANT);
        assert_eq!(
            event.identity().source().source_id().as_str(),
            format!("identity.{TENANT}")
        );
        assert_eq!(event.identity().event_id().as_str(), "event-1");
        assert_eq!(
            event.identity().source().contract().id().as_str(),
            format!("identity.{kind}.security")
        );
        let (version, schema) = match kind {
            "account" => ("v3", include_str!("../security-event-v3.json")),
            "session" => ("v1", include_str!("../session-security-event-v1.json")),
            _ => ("v2", include_str!("../federation-security-event-v2.json")),
        };
        assert_eq!(
            event.identity().source().contract().version().to_string(),
            version
        );
        assert_eq!(
            event
                .identity()
                .source()
                .contract()
                .schema_digest()
                .as_str(),
            format!("sha256:{:x}", Sha256::digest(schema))
        );
        assert!(event.context().coordinates().correlation_id().is_none());
        assert!(event.context().coordinates().request_id().is_none());
        assert!(event.context().coordinates().operation_id().is_none());
        assert_eq!(event.facts().actor().kind().as_str(), actor_kind);
        assert_eq!(event.facts().actor().id().as_str(), actor_id);
        assert_eq!(event.facts().action().as_str(), action);
        assert_eq!(event.facts().resource().kind().as_str(), resource_kind);
        assert_eq!(event.facts().resource().id().as_str(), resource_id);
        assert_eq!(event.facts().outcome(), rss_audit_core::Outcome::Succeeded);
        assert_eq!(event.facts().occurred_at().unix_seconds(), 100);
        assert_eq!(
            serde_json::from_slice::<Value>(event.context().payload().as_bytes()).unwrap(),
            payload
        );
    }
}

#[test]
fn optional_diagnostic_rejects_explicit_null_per_source_schema() {
    let body = json!({"action":"provider_updated","tenant":TENANT,"principal":PRINCIPAL,"provider_id":SESSION,"config_version":1,"diagnostic":null});
    assert!(
        map_event(
            InstanceId::generate(),
            &envelope("federation", body),
            Timepoint::try_from(101).unwrap()
        )
        .is_err()
    );
}

#[test]
fn nested_event_objects_do_not_accept_sequence_encoding() {
    for (kind, body) in [
        (
            "account",
            json!({"action":"account_created","tenant":TENANT,"principal":PRINCIPAL,"actor":null,"epoch":1,"state":[true,true,1]}),
        ),
        (
            "federation",
            json!({"action":"provider_test_failed","tenant":TENANT,"principal":PRINCIPAL,"provider_id":SESSION,"config_version":1,"diagnostic":["binding","unavailable"]}),
        ),
    ] {
        assert!(
            map_event(
                InstanceId::generate(),
                &envelope(kind, body),
                Timepoint::try_from(101).unwrap()
            )
            .is_err()
        );
    }
}

#[test]
fn profile_events_project_only_source_and_changed_field_identifiers() {
    for action in ["observed", "local_updated"] {
        let mut body = json!({"action":action,"tenant":TENANT,"principal":PRINCIPAL,"actor":null,"source":{"kind":"identity_local"},"snapshot_id":null,"revision":1,"changed_fields":["displayName","extensions"]});
        if action == "observed" {
            body["snapshot_id"] = json!(SESSION);
        } else {
            body["actor"] = json!(PRINCIPAL);
        }
        let event = mapped("profile", body.clone());
        let projected: Value =
            serde_json::from_slice(event.context().payload().as_bytes()).unwrap();
        assert_eq!(projected["source"], body["source"]);
        assert_eq!(projected["changed_fields"], body["changed_fields"]);
        assert_eq!(event.facts().actor().id().as_str(), PRINCIPAL);
        body["value"] = json!({"email":"private@example.test"});
        assert!(
            map_event(
                InstanceId::generate(),
                &envelope("profile", body),
                Timepoint::try_from(101).unwrap()
            )
            .is_err()
        );
    }
}

#[test]
fn wrapped_storage_errors_keep_the_owner_classification() {
    use rss_transactional_messaging_postgres::{PgError, PgStorageContractFailure};
    let fatal = OnceLock::new();
    let wrapped = rss_audit_postgres::Error::Ledger(
        PgError::IncompatibleStorageContract(PgStorageContractFailure::RuntimeAcl).into(),
    );
    let _ = infrastructure_failure(&fatal, wrapped);
    assert_eq!(fatal.get(), Some(&AuditDeliveryError::Invariant));
    let fatal = OnceLock::new();
    let wrapped = rss_audit_postgres::Error::Messaging(PgError::from(sqlx::Error::PoolClosed));
    let _ = infrastructure_failure(&fatal, wrapped);
    assert_eq!(fatal.get(), Some(&AuditDeliveryError::Permanent));
    let fatal = OnceLock::new();
    let wrapped = rss_audit_postgres::Error::Ledger(sqlx::Error::PoolTimedOut.into());
    let _ = infrastructure_failure(&fatal, wrapped);
    assert!(
        fatal.get().is_none(),
        "transient dependency failure must remain recoverable"
    );
}
