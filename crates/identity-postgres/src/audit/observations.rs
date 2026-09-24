use rss_transactional_messaging::observability::TransactionalMessagingObservation as Event;
use serde_json::json;

pub(super) fn record(event: Event, mut output: impl std::io::Write) {
    let name = event.event().name();
    let mut fields = match event {
        Event::RuntimeFailure { phase, kind } => {
            json!({"phase":phase.as_label(),"kind":kind.as_label()})
        }
        Event::OutboxPublish { status } => json!({"status":status.as_label()}),
        Event::OutboxPublishFailure {
            stage,
            reason,
            ambiguous,
        } => json!({"stage":stage.as_label(),"reason":reason.as_label(),"ambiguous":ambiguous}),
        Event::OutboxBacklog {
            pending_depth,
            oldest_pending_age,
            partition_blocked_depth,
        } => {
            json!({"pending_depth":pending_depth,"oldest_pending_age_seconds":oldest_pending_age.as_secs_f64(),"partition_blocked_depth":partition_blocked_depth})
        }
        Event::RelayTick { phase, duration } => {
            json!({"phase":phase.as_label(),"duration_seconds":duration.as_secs_f64()})
        }
        Event::InboxBacklog {
            stale_claim_depth,
            oldest_stale_claim_age,
        } => {
            json!({"stale_claim_depth":stale_claim_depth,"oldest_stale_claim_age_seconds":oldest_stale_claim_age.as_secs_f64()})
        }
        Event::ConsumerIngressRejected { reason } => json!({"reason":reason.as_label()}),
        Event::ConsumerTransaction { status } => json!({"outcome":status.as_label()}),
        Event::ConsumerSettlement { action, outcome } => {
            json!({"action":action.as_label(),"outcome":outcome.as_label()})
        }
        Event::ConsumerSubscribeRetry { outcome } => json!({"outcome":outcome.as_label()}),
        Event::OutboxBacklogUnavailable
        | Event::InboxBacklogUnavailable
        | Event::ConsumerClaimInProgress
        | Event::ConsumerLeaseLost
        | Event::RelayLeaseLost
        | Event::ConsumerReleaseFailed => json!({}),
    };
    fields["component"] = json!("identity-audit");
    fields["event"] = json!(name);
    let _ = serde_json::to_writer(&mut output, &fields);
    let _ = writeln!(output);
}
#[cfg(test)]
mod tests {
    use super::*;
    use rss_transactional_messaging::{
        error::MessagingErrorKind,
        observability::{
            TransactionalMessagingDisposition as Status,
            TransactionalMessagingRuntimePhase as Phase,
        },
        transaction::EnvelopeValidationFailure,
    };
    #[test]
    fn diagnostics_use_stable_closed_fields() {
        for (event, expected) in [
            (
                Event::OutboxPublish {
                    status: Status::Requeue,
                },
                json!({"status":"requeue","event":"transactional_messaging.outbox.publish","component":"identity-audit"}),
            ),
            (
                Event::ConsumerIngressRejected {
                    reason: EnvelopeValidationFailure::FingerprintConflict,
                },
                json!({"reason":"fingerprint_conflict","event":"transactional_messaging.consumer.ingress_rejected","component":"identity-audit"}),
            ),
            (
                Event::RuntimeFailure {
                    phase: Phase::ConsumerClaim,
                    kind: MessagingErrorKind::Transient,
                },
                json!({"phase":"consumer_claim","kind":"transient","event":"transactional_messaging.runtime.failure","component":"identity-audit"}),
            ),
        ] {
            let mut bytes = Vec::new();
            record(event, &mut bytes);
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
                expected
            );
        }
    }
}
