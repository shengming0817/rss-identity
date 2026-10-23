//! Closed projection diagnostics: never accept identifiers, event bytes or provider messages.
use rss_transactional_messaging::observability::TransactionalMessagingTransactionStatus;

pub(super) enum Event {
    Transaction(TransactionalMessagingTransactionStatus),
    ResolutionConfirmed,
    ResolutionUnresolved,
    ResolutionFailed,
}
pub(super) fn record(event: Event, mut output: impl std::io::Write) {
    let (phase, status) = match event {
        Event::Transaction(status) => ("transaction", status.as_label()),
        Event::ResolutionConfirmed => ("resolve", "confirmed"),
        Event::ResolutionUnresolved => ("resolve", "unresolved"),
        Event::ResolutionFailed => ("resolve", "failed"),
    };
    let fields = serde_json::json!({"component":"identity-audit","event":"audit_projection","phase":phase,"status":status});
    let _ = serde_json::to_writer(&mut output, &fields);
    let _ = writeln!(output);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn uncertain_transactions_and_resolution_remain_distinct() {
        let mut output = Vec::new();
        for event in [
            Event::Transaction(TransactionalMessagingTransactionStatus::CommitUnknown),
            Event::Transaction(TransactionalMessagingTransactionStatus::RollbackFailed),
            Event::ResolutionConfirmed,
            Event::ResolutionUnresolved,
            Event::ResolutionFailed,
        ] {
            record(event, &mut output);
        }
        let records: Vec<serde_json::Value> = std::str::from_utf8(&output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let statuses: Vec<_> = records
            .iter()
            .map(|v| v["status"].as_str().unwrap())
            .collect();
        assert_eq!(
            statuses,
            [
                "commit_unknown",
                "rollback_failed",
                "confirmed",
                "unresolved",
                "failed"
            ]
        );
        assert!(records.iter().all(|v| v.as_object().unwrap().len() == 4));
    }
}
