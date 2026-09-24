use rss_audit_core::*;
use rss_contract::Timepoint;
use rss_identity_core::InstanceId;
use rss_transactional_messaging::message::MessageEnvelope;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("invalid identity audit event")]
pub(super) struct InvalidEvent;

pub(super) fn accepted_contract(id: &str, version: &str, digest: &str) -> Option<&'static str> {
    let (expected, schema, route) = match id {
        "identity.account.security" => (
            "v3",
            include_str!("../security-event-v3.json"),
            "account.changed",
        ),
        "identity.session.security" => (
            "v1",
            include_str!("../session-security-event-v1.json"),
            "session.changed",
        ),
        "identity.federation.security" => (
            "v2",
            include_str!("../federation-security-event-v2.json"),
            "federation.changed",
        ),
        _ => return None,
    };
    (version == expected && digest == format!("sha256:{:x}", Sha256::digest(schema)))
        .then_some(route)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Account {
    action: String,
    tenant: Uuid,
    principal: Uuid,
    actor: Option<Uuid>,
    epoch: i64,
    state: State,
}
#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct State {
    enabled: bool,
    member_active: bool,
    membership_epoch: i64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Session {
    action: String,
    tenant: Uuid,
    principal: Uuid,
    session_id: Uuid,
    replaced_session_id: Option<Uuid>,
    epoch: i64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Federation {
    action: String,
    tenant: Uuid,
    principal: Option<Uuid>,
    provider_id: Uuid,
    config_version: i64,
    diagnostic: Option<Diagnostic>,
}
#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct Diagnostic {
    stage: String,
    reason: String,
}
fn require(ok: bool) -> Result<(), InvalidEvent> {
    if ok { Ok(()) } else { Err(InvalidEvent) }
}
fn parse<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    required: &[&str],
) -> Result<T, InvalidEvent> {
    // Option<T> accepts an absent field; the wire requires explicit null for these coordinates.
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| InvalidEvent)?;
    require(required.iter().all(|key| value.get(*key).is_some()))?;
    serde_json::from_slice(bytes).map_err(|_| InvalidEvent)
}

pub(super) fn map_event(
    instance: InstanceId,
    message: &MessageEnvelope<Vec<u8>>,
    recorded: Timepoint,
) -> Result<AuditEventV1, InvalidEvent> {
    let meta = message.metadata();
    let contract = meta.contract();
    let route = accepted_contract(
        contract.id().as_str(),
        &contract.version().to_string(),
        contract.schema_digest().as_str(),
    )
    .ok_or(InvalidEvent)?;
    require(meta.domain().as_str() == "identity.security" && meta.route().as_str() == route)?;
    require(message.payload().len() <= 4096 && meta.occurred_at() <= recorded)?;
    let tenant = meta.tenant_id().to_string();
    let (action, actor_kind, actor_id, resource_kind, resource_id, outcome, payload) = match route {
        "account.changed" => {
            let e: Account = parse(message.payload(), &["actor"])?;
            require(e.tenant.to_string() == tenant && e.epoch > 0 && e.state.membership_epoch > 0)?;
            require(matches!(
                e.action.as_str(),
                "initialized"
                    | "account_created"
                    | "account_enabled"
                    | "account_disabled"
                    | "membership_enabled"
                    | "membership_disabled"
                    | "password_changed"
                    | "password_recovered"
            ))?;
            require(
                e.actor.is_some()
                    || matches!(
                        e.action.as_str(),
                        "initialized" | "account_created" | "password_recovered"
                    ),
            )?;
            let (kind, actor) = e.actor.map_or(("maintenance", instance.to_string()), |a| {
                ("principal", a.to_string())
            });
            (
                format!("identity.account.{}", e.action),
                kind,
                actor,
                "account",
                e.principal.to_string(),
                Outcome::Succeeded,
                json!({"epoch":e.epoch,"state":e.state}),
            )
        }
        "session.changed" => {
            let e: Session = parse(message.payload(), &["replaced_session_id"])?;
            require(e.tenant.to_string() == tenant && e.epoch > 0)?;
            require(matches!(
                e.action.as_str(),
                "created" | "refreshed" | "revoked" | "all_revoked"
            ))?;
            require(e.action == "created" || e.replaced_session_id.is_none())?;
            let (kind, id) = if e.action == "all_revoked" {
                ("account_sessions", e.principal)
            } else {
                ("session", e.session_id)
            };
            (
                format!("identity.session.{}", e.action),
                "principal",
                e.principal.to_string(),
                kind,
                id.to_string(),
                Outcome::Succeeded,
                json!({"epoch":e.epoch,"session_id":e.session_id,"replaced_session_id":e.replaced_session_id}),
            )
        }
        _ => {
            let e: Federation = parse(message.payload(), &["principal"])?;
            require(e.tenant.to_string() == tenant && e.config_version > 0)?;
            let provider_action = matches!(
                e.action.as_str(),
                "provider_created"
                    | "provider_updated"
                    | "provider_enabled"
                    | "provider_disabled"
                    | "provider_tested"
                    | "provider_test_failed"
            );
            require(
                provider_action
                    || matches!(
                        e.action.as_str(),
                        "jit_created"
                            | "logged_in"
                            | "linked"
                            | "already_linked"
                            | "reauthenticated"
                            | "stepped_up"
                    ),
            )?;
            require(e.principal.is_some() || e.action == "provider_updated")?;
            require(e.diagnostic.is_some() == (e.action == "provider_test_failed"))?;
            if let Some(d) = &e.diagnostic {
                require(matches!(
                    d.stage.as_str(),
                    "binding" | "discovery" | "jwks" | "exchange" | "claims"
                ))?;
                require(matches!(
                    d.reason.as_str(),
                    "unapproved_binding"
                        | "missing_secret"
                        | "invalid_trust_anchor"
                        | "egress_denied"
                        | "tls_rejected"
                        | "unavailable"
                        | "timeout"
                        | "invalid_response"
                        | "issuer_mismatch"
                        | "issuer_response_unsupported"
                        | "code_rejected"
                        | "invalid_token"
                ))?;
            }
            let (kind, actor) = e.principal.map_or(("system", instance.to_string()), |p| {
                ("principal", p.to_string())
            });
            let (resource, id) = if provider_action {
                ("provider", e.provider_id)
            } else {
                ("federated_principal", e.principal.ok_or(InvalidEvent)?)
            };
            (
                format!("identity.federation.{}", e.action),
                kind,
                actor,
                resource,
                id.to_string(),
                if e.action == "provider_test_failed" {
                    Outcome::Failed
                } else {
                    Outcome::Succeeded
                },
                json!({"provider_id":e.provider_id,"config_version":e.config_version,"diagnostic":e.diagnostic}),
            )
        }
    };
    let build = || -> Result<_, rss_audit_core::Error> {
        Ok(AuditEventV1::new(
            RecordIdentity::new(
                meta.tenant_id(),
                SourceIdentity::new(
                    SourceId::parse(&format!("identity.{instance}"))?,
                    SourceContract::new(
                        contract.id().clone(),
                        contract.version(),
                        contract.schema_digest().clone(),
                    ),
                ),
                EventId::parse(message.id().as_str())?,
            ),
            EventFacts::new(
                ActorRef::new(ActorKind::parse(actor_kind)?, ActorId::parse(&actor_id)?),
                Action::parse(&action)?,
                ResourceRef::new(
                    ResourceKind::parse(resource_kind)?,
                    ResourceId::parse(&resource_id)?,
                ),
                outcome,
                meta.occurred_at(),
            ),
            EventContext::new(
                Coordinates::new(None, None, None),
                AuditPayload::new(
                    serde_json::to_vec(&payload)
                        .map_err(|_| rss_audit_core::Error::MalformedEncoding)?,
                )?,
            ),
        ))
    };
    build().map_err(|_| InvalidEvent)
}
