/// Closed Identity audit delivery outcome. No provider text or transaction proof is exposed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AuditDeliveryError {
    /// Invalid host-selected configuration or role identifier.
    #[error("invalid audit delivery configuration")]
    Configuration,
    /// Delivery may be retried with its unchanged source identity.
    #[error("audit delivery temporarily unavailable")]
    Transient,
    /// Storage configuration or permissions require operator intervention.
    #[error("audit storage permanently unavailable")]
    Permanent,
    /// The host's storage or tenant execution authority was fenced.
    #[error("audit delivery ownership lost")]
    OwnershipLost,
    /// Storage or transaction invariants were violated.
    #[error("audit delivery invariant violated")]
    Invariant,
    /// An event was isolated; successful audit continuity cannot be claimed.
    #[error("audit event isolated")]
    RejectedEvent,
}
impl AuditDeliveryError {
    /// Whether repeating the unchanged operation may recover without reconfiguration.
    pub const fn is_retryable(self) -> bool {
        matches!(self, Self::Transient)
    }
    /// Stable, low-cardinality diagnostic label.
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::Configuration => "configuration",
            Self::Transient => "transient",
            Self::Permanent => "permanent",
            Self::OwnershipLost => "ownership_lost",
            Self::Invariant => "invariant",
            Self::RejectedEvent => "rejected_event",
        }
    }
    pub(super) fn messaging(kind: rss_transactional_messaging::error::MessagingErrorKind) -> Self {
        use rss_transactional_messaging::error::MessagingErrorKind as K;
        match kind {
            K::Transient | K::DeadlineElapsed => Self::Transient,
            K::OwnershipLost => Self::OwnershipLost,
            K::Permanent => Self::Permanent,
            K::Invariant | K::Conflict => Self::Invariant,
        }
    }
    pub(super) fn pg(error: rss_transactional_messaging_postgres::PgError) -> Self {
        Self::messaging(error.kind())
    }
}
