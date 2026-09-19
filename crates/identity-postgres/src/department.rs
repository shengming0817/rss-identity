//! Borrowed department facts; source comes only from the checked session origin.
use crate::{
    auth_facts::{DepartmentAssignment, DepartmentSnapshot},
    session_storage::TimeSample,
    transaction::reject,
};
use rss_identity_core::{
    InstanceId,
    account::AccountKey,
    department::DepartmentId,
    groups::{GroupSource, UnavailableReason, acceptable_observation},
};
use rss_transactional_messaging_postgres::PgError;
use std::time::Instant;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DepartmentAccessError {
    #[error("authentication proof expired")]
    ProofExpired,
    #[error("department snapshot expired")]
    SnapshotExpired,
}

pub(crate) enum DepartmentFacts {
    Unavailable(UnavailableReason),
    Expired,
    Available {
        source: GroupSource,
        provider_config_version: i64,
        snapshot_id: Uuid,
        observed_at: i64,
        expires_at: i64,
        assignment: DepartmentAssignment,
        expires: Instant,
    },
}
impl DepartmentFacts {
    pub(crate) fn new(
        snapshot: DepartmentSnapshot,
        source: GroupSource,
        version: i64,
        sample: &TimeSample,
    ) -> Result<Self, PgError> {
        Ok(match snapshot {
            DepartmentSnapshot::Unavailable { reason } => Self::Unavailable(reason),
            DepartmentSnapshot::Available {
                snapshot_id,
                observed_at,
                expires_at,
                assignment,
            } => {
                if !acceptable_observation(observed_at, sample.seconds()) {
                    return Err(reject());
                }
                if sample.seconds() < observed_at {
                    return Ok(Self::Unavailable(UnavailableReason::NotYetValid));
                }
                if sample.seconds() >= expires_at {
                    return Ok(Self::Expired);
                }
                Self::Available {
                    source,
                    provider_config_version: version,
                    snapshot_id,
                    observed_at,
                    expires_at,
                    assignment,
                    expires: sample.deadline(expires_at)?,
                }
            }
        })
    }
    pub(crate) fn view(
        &self,
        instance: InstanceId,
        account: AccountKey,
        proof: Instant,
    ) -> Result<VerifiedDepartment<'_>, DepartmentAccessError> {
        self.view_at(instance, account, proof, Instant::now())
    }
    fn view_at(
        &self,
        instance: InstanceId,
        account: AccountKey,
        proof: Instant,
        now: Instant,
    ) -> Result<VerifiedDepartment<'_>, DepartmentAccessError> {
        if now >= proof {
            return Err(DepartmentAccessError::ProofExpired);
        }
        Ok(match self {
            Self::Unavailable(reason) => VerifiedDepartment::Unavailable(*reason),
            Self::Expired => VerifiedDepartment::Expired,
            Self::Available { expires, .. } if now >= *expires => VerifiedDepartment::Expired,
            Self::Available {
                source,
                provider_config_version,
                snapshot_id,
                observed_at,
                expires_at,
                assignment,
                expires,
            } => VerifiedDepartment::Available(TrustedDepartment {
                instance,
                account,
                source,
                provider_config_version: *provider_config_version,
                snapshot_id: *snapshot_id,
                observed_at: *observed_at,
                expires_at: *expires_at,
                value: match assignment {
                    DepartmentAssignment::Assigned { id } => Some(id),
                    DepartmentAssignment::NoDepartment {} => None,
                },
                proof,
                expires: *expires,
            }),
        })
    }
}

/// Only Available contains a component-issued snapshot, including explicit no-department.
pub enum VerifiedDepartment<'a> {
    Available(TrustedDepartment<'a>),
    Unavailable(UnavailableReason),
    Expired,
}
/// Metadata identifies an observation; value access checks both fixed deadlines.
/// A copied value or completed authorization remains the host's responsibility.
/// ```compile_fail
/// let fact: rss_identity_postgres::TrustedDepartment<'_> = serde_json::from_str("{}").unwrap();
/// ```
pub struct TrustedDepartment<'a> {
    instance: InstanceId,
    account: AccountKey,
    source: &'a GroupSource,
    provider_config_version: i64,
    snapshot_id: Uuid,
    observed_at: i64,
    expires_at: i64,
    value: Option<&'a DepartmentId>,
    proof: Instant,
    expires: Instant,
}
impl TrustedDepartment<'_> {
    pub fn instance(&self) -> InstanceId {
        self.instance
    }
    pub fn account(&self) -> AccountKey {
        self.account
    }
    pub fn provider_id(&self) -> Uuid {
        self.source.provider_id
    }
    pub fn issuer(&self) -> &str {
        &self.source.issuer
    }
    pub fn provider_config_version(&self) -> i64 {
        self.provider_config_version
    }
    pub fn snapshot_id(&self) -> Uuid {
        self.snapshot_id
    }
    pub fn observed_at(&self) -> i64 {
        self.observed_at
    }
    pub fn expires_at(&self) -> i64 {
        self.expires_at
    }
    /// None is a current signed assertion of no department, never missing input.
    pub fn value(&self) -> Result<Option<&DepartmentId>, DepartmentAccessError> {
        self.value_at(Instant::now())
    }
    fn value_at(&self, now: Instant) -> Result<Option<&DepartmentId>, DepartmentAccessError> {
        if now >= self.proof {
            return Err(DepartmentAccessError::ProofExpired);
        }
        if now >= self.expires {
            return Err(DepartmentAccessError::SnapshotExpired);
        }
        Ok(self.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    fn account() -> AccountKey {
        AccountKey {
            tenant: rss_request_context::TenantId::parse("11111111-1111-4111-8111-111111111111")
                .unwrap(),
            principal: rss_identity_core::PrincipalId::generate(),
        }
    }
    #[test]
    fn assigned_and_absent_retained_views_check_both_deadlines() {
        let start = Instant::now();
        let expiry = start + Duration::from_secs(1);
        let proof = expiry + Duration::from_secs(1);
        let instance = InstanceId::generate();
        let account = account();
        for assignment in [
            DepartmentAssignment::Assigned {
                id: DepartmentId::new("dept".into()).unwrap(),
            },
            DepartmentAssignment::NoDepartment {},
        ] {
            let absent = matches!(assignment, DepartmentAssignment::NoDepartment {});
            let facts = DepartmentFacts::Available {
                source: GroupSource {
                    provider_id: Uuid::new_v4(),
                    issuer: "https://idp.test".into(),
                },
                provider_config_version: 1,
                snapshot_id: Uuid::new_v4(),
                observed_at: 100,
                expires_at: 101,
                assignment,
                expires: expiry,
            };
            let VerifiedDepartment::Available(view) =
                facts.view_at(instance, account, proof, start).unwrap()
            else {
                panic!("available");
            };
            assert_eq!(view.value_at(start).unwrap().is_none(), absent);
            assert_eq!(view.instance(), instance);
            assert_eq!(view.account(), account);
            assert!(view.value_at(expiry - Duration::from_nanos(1)).is_ok());
            assert_eq!(
                view.value_at(expiry),
                Err(DepartmentAccessError::SnapshotExpired)
            );
            assert_eq!(
                view.value_at(proof),
                Err(DepartmentAccessError::ProofExpired)
            );
            assert!(matches!(
                facts.view_at(instance, account, proof, expiry),
                Ok(VerifiedDepartment::Expired)
            ));
            for earlier in [start + Duration::from_millis(500), expiry] {
                let VerifiedDepartment::Available(view) =
                    facts.view_at(instance, account, earlier, start).unwrap()
                else {
                    panic!("available");
                };
                assert_eq!(
                    view.value_at(earlier),
                    Err(DepartmentAccessError::ProofExpired)
                );
            }
        }
        for reason in [
            UnavailableReason::LocalIdentity,
            UnavailableReason::NotConfigured,
            UnavailableReason::ClaimMissing,
            UnavailableReason::NotYetValid,
        ] {
            let facts = DepartmentFacts::Unavailable(reason);
            assert!(
                matches!(facts.view_at(instance, account, proof, start), Ok(VerifiedDepartment::Unavailable(r)) if r == reason)
            );
            assert!(matches!(
                facts.view_at(instance, account, proof, proof),
                Err(DepartmentAccessError::ProofExpired)
            ));
        }
    }
}
