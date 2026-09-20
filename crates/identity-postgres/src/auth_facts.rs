//! The only persisted authentication-facts codec. Provider authority stays in Origin.
use crate::transaction::{corrupt, reject};
use rss_identity_core::{
    assurance::Assurance,
    department::{
        DepartmentSnapshot, DepartmentSnapshotClaim, DepartmentUnavailableReason,
        UpstreamDepartmentSnapshot,
    },
    facts::{FactSource, FactUnavailableReason, acceptable_observation, valid_snapshot_window},
    federation::{FederationError, UpstreamClaims},
    groups::{GroupFactsMaxAge, Groups, UpstreamGroups, VERSION},
};
use rss_transactional_messaging_postgres::PgError;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuthenticationFacts {
    format_version: u32,
    pub provider_config_version: i64,
    email: Option<String>,
    email_verified: bool,
    pub assurance: Assurance,
    groups: Snapshot,
    pub(crate) department_snapshot: Box<DepartmentObservation>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum Snapshot {
    Unavailable {
        reason: FactUnavailableReason,
    },
    Available {
        snapshot_id: Uuid,
        observed_at: i64,
        expires_at: i64,
        values: Vec<String>,
    },
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum DepartmentObservation {
    Unavailable {
        reason: DepartmentUnavailableReason,
    },
    Available {
        snapshot_id: Uuid,
        observed_at: i64,
        expires_at: i64,
        snapshot: DepartmentSnapshot,
    },
}
impl DepartmentObservation {
    fn collect(
        claims: &UpstreamClaims,
        mapping: Option<&DepartmentSnapshotClaim>,
        now: i64,
    ) -> Result<Self, FederationError> {
        let (mapping, snapshot) = match (&claims.department_snapshot, mapping) {
            (UpstreamDepartmentSnapshot::NotConfigured, None) => {
                return Ok(Self::Unavailable {
                    reason: DepartmentUnavailableReason::NotConfigured,
                });
            }
            (UpstreamDepartmentSnapshot::Missing, Some(_)) => {
                return Ok(Self::Unavailable {
                    reason: DepartmentUnavailableReason::ClaimMissing,
                });
            }
            (UpstreamDepartmentSnapshot::Invalid, Some(_)) => {
                return Ok(Self::Unavailable {
                    reason: DepartmentUnavailableReason::InvalidClaim,
                });
            }
            (UpstreamDepartmentSnapshot::Present(snapshot), Some(mapping)) => {
                (mapping, snapshot.clone())
            }
            _ => return Err(FederationError::Claims),
        };
        Ok(Self::Available {
            snapshot_id: Uuid::new_v4(),
            observed_at: claims.issued_at,
            expires_at: mapping.expires_at(claims.issued_at, claims.expires_at, now)?,
            snapshot,
        })
    }
    fn validate(&self) -> Result<(), PgError> {
        match self {
            Self::Unavailable {
                reason:
                    DepartmentUnavailableReason::NotConfigured
                    | DepartmentUnavailableReason::ClaimMissing
                    | DepartmentUnavailableReason::InvalidClaim,
            } => Ok(()),
            Self::Available {
                snapshot_id,
                observed_at,
                expires_at,
                ..
            } if !snapshot_id.is_nil() && valid_snapshot_window(*observed_at, *expires_at) => {
                Ok(())
            }
            _ => Err(corrupt()),
        }
    }
}

impl AuthenticationFacts {
    pub fn collect(
        claims: &UpstreamClaims,
        version: i64,
        policy: GroupFactsMaxAge,
        department_snapshot: Option<&DepartmentSnapshotClaim>,
        now: i64,
    ) -> Result<Self, FederationError> {
        claims.validate()?;
        let expires_at = policy.expires_at(claims.issued_at, claims.expires_at, now)?;
        if version < 1 {
            return Err(FederationError::Claims);
        }
        let groups = match &claims.groups {
            UpstreamGroups::NotConfigured => Snapshot::Unavailable {
                reason: FactUnavailableReason::NotConfigured,
            },
            UpstreamGroups::Missing => Snapshot::Unavailable {
                reason: FactUnavailableReason::ClaimMissing,
            },
            UpstreamGroups::Present(values) => Snapshot::Available {
                snapshot_id: Uuid::new_v4(),
                observed_at: claims.issued_at,
                expires_at,
                values: values.clone(),
            },
        };
        Ok(Self {
            format_version: 3,
            department_snapshot: Box::new(DepartmentObservation::collect(
                claims,
                department_snapshot,
                now,
            )?),
            provider_config_version: version,
            email: claims.email.clone(),
            email_verified: claims.email_verified,
            assurance: claims.assurance.clone(),
            groups,
        })
    }
    pub fn decode(value: serde_json::Value) -> Result<Self, PgError> {
        let facts: Self = serde_json::from_value(value).map_err(|_| corrupt())?;
        if facts.format_version != 3
            || facts.provider_config_version < 1
            || facts
                .email
                .as_ref()
                .is_some_and(|v| v.len() > 320 || v.chars().any(char::is_control))
        {
            return Err(corrupt());
        }
        facts.department_snapshot.validate()?;
        match &facts.groups {
            Snapshot::Unavailable {
                reason: FactUnavailableReason::LocalIdentity | FactUnavailableReason::NotYetValid,
            } => return Err(corrupt()),
            Snapshot::Available {
                snapshot_id,
                observed_at,
                expires_at,
                values,
            } => {
                if snapshot_id.is_nil()
                    || !valid_snapshot_window(*observed_at, *expires_at)
                    || !rss_identity_core::groups::canonical_values(values)
                {
                    return Err(corrupt());
                }
            }
            Snapshot::Unavailable { .. } => {}
        }
        Ok(facts)
    }
    /// PostgreSQL jsonb::text is the storage constraint's exact representation,
    /// including JSON escaping and whitespace. Apply it to sessions, intents and grants.
    pub async fn encode(&self, c: &mut sqlx::PgConnection) -> Result<serde_json::Value, PgError> {
        let mut value = serde_json::to_value(self).map_err(|_| corrupt())?;
        let size: i32 = sqlx::query_scalar("SELECT octet_length($1::jsonb::text)")
            .bind(&value)
            .fetch_one(&mut *c)
            .await?;
        if size > 32768 {
            if !matches!(
                &*self.department_snapshot,
                DepartmentObservation::Available { .. }
            ) {
                return Err(reject());
            }
            // An oversized optional assertion cannot suppress independent identity/groups.
            // Recheck the exact total budget after withholding the entire department fact.
            value["department_snapshot"] =
                serde_json::to_value(DepartmentObservation::Unavailable {
                    reason: DepartmentUnavailableReason::InvalidClaim,
                })
                .map_err(|_| corrupt())?;
            let remaining: i32 = sqlx::query_scalar("SELECT octet_length($1::jsonb::text)")
                .bind(&value)
                .fetch_one(&mut *c)
                .await?;
            if remaining > 32768 {
                return Err(reject());
            }
        }
        Ok(value)
    }
    pub fn project(&self, source: FactSource, now: i64) -> Result<Groups, PgError> {
        match &self.groups {
            Snapshot::Unavailable { reason } => Ok(Groups::unavailable(*reason)),
            Snapshot::Available {
                snapshot_id,
                observed_at,
                expires_at,
                values,
            } => {
                if !acceptable_observation(*observed_at, now) {
                    return Err(reject());
                }
                if now < *observed_at {
                    return Ok(Groups::unavailable(FactUnavailableReason::NotYetValid));
                }
                if now >= *expires_at {
                    return Ok(Groups::Expired { version: VERSION });
                }
                Ok(Groups::Available {
                    version: VERSION,
                    source,
                    snapshot_id: *snapshot_id,
                    provider_config_version: self.provider_config_version,
                    observed_at: *observed_at,
                    expires_at: *expires_at,
                    values: values.clone(),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn claims(groups: UpstreamGroups) -> UpstreamClaims {
        UpstreamClaims {
            department_snapshot:
                rss_identity_core::department::UpstreamDepartmentSnapshot::NotConfigured,
            issuer: "https://idp.test".into(),
            subject: "subject".into(),
            email: None,
            email_verified: false,
            issued_at: 1000,
            expires_at: 1600,
            groups,
            assurance: Assurance::password(1000).unwrap(),
        }
    }
    fn source() -> FactSource {
        FactSource::new(Uuid::new_v4(), "https://idp.test".into()).unwrap()
    }
    #[test]
    fn department_format_is_explicit_and_legacy_is_rejected() {
        let facts = AuthenticationFacts::collect(
            &claims(UpstreamGroups::NotConfigured),
            1,
            GroupFactsMaxAge::new(300).unwrap(),
            None,
            1000,
        )
        .unwrap();
        let value = serde_json::to_value(facts).unwrap();
        assert_eq!(value["format_version"], 3);
        assert_eq!(
            value["department_snapshot"],
            serde_json::json!({"status":"unavailable","reason":"not_configured"})
        );
        let mut missing = value.clone();
        missing
            .as_object_mut()
            .unwrap()
            .remove("department_snapshot");
        assert!(AuthenticationFacts::decode(missing).is_err());
        for version in [1, 2, 4] {
            let mut legacy = value.clone();
            legacy["format_version"] = serde_json::json!(version);
            assert!(AuthenticationFacts::decode(legacy).is_err());
        }
    }

    #[test]
    fn department_snapshot_is_closed_fixed_and_independent_of_groups() {
        let mapping = DepartmentSnapshotClaim::new("organization_snapshot".into(), 60).unwrap();
        let snapshot: DepartmentSnapshot = serde_json::from_value(serde_json::json!({"version":1,"sourceRevision":"r1","nodes":[{"id":"dept","displayName":"Department","parentId":null}],"memberships":["dept"]})).unwrap();
        for department in [
            UpstreamDepartmentSnapshot::Present(snapshot),
            UpstreamDepartmentSnapshot::Missing,
            UpstreamDepartmentSnapshot::Invalid,
        ] {
            let mut claims = claims(UpstreamGroups::present(vec!["staff".into()]).unwrap());
            claims.department_snapshot = department;
            let facts = AuthenticationFacts::collect(
                &claims,
                1,
                GroupFactsMaxAge::new(300).unwrap(),
                Some(&mapping),
                1000,
            )
            .unwrap();
            let value = serde_json::to_value(&facts).unwrap();
            assert_eq!(value["groups"]["expires_at"], 1300);
            if !matches!(
                claims.department_snapshot,
                UpstreamDepartmentSnapshot::Present(_)
            ) {
                assert_eq!(
                    value["department_snapshot"],
                    serde_json::json!({"status":"unavailable","reason":if matches!(claims.department_snapshot, UpstreamDepartmentSnapshot::Missing) {"claim_missing"} else {"invalid_claim"}})
                );
            } else {
                assert_eq!(value["department_snapshot"]["expires_at"], 1060);
                assert_eq!(value["department_snapshot"]["observed_at"], 1000);
                for (key, bad) in [
                    ("snapshot", serde_json::json!(null)),
                    (
                        "snapshot",
                        serde_json::json!({"version":1,"sourceRevision":"r1","nodes":[],"memberships":[]}),
                    ),
                    ("assignment", serde_json::json!({"status":"no_department"})),
                    ("expires_at", serde_json::json!(1301)),
                    ("snapshot_id", serde_json::json!(Uuid::nil())),
                ] {
                    let mut corrupted = value.clone();
                    corrupted["department_snapshot"][key] = bad;
                    assert!(AuthenticationFacts::decode(corrupted).is_err());
                }
            }
            let restored = AuthenticationFacts::decode(value.clone()).unwrap();
            assert_eq!(serde_json::to_value(restored).unwrap(), value);
            assert!(
                AuthenticationFacts::collect(
                    &claims,
                    1,
                    GroupFactsMaxAge::new(300).unwrap(),
                    None,
                    1000
                )
                .is_err()
            );
        }
        let claims = claims(UpstreamGroups::NotConfigured);
        assert!(
            AuthenticationFacts::collect(
                &claims,
                1,
                GroupFactsMaxAge::new(300).unwrap(),
                Some(&mapping),
                1000
            )
            .is_err()
        );
    }

    #[test]
    fn snapshot_is_fixed_and_only_available_contains_values() {
        let facts = AuthenticationFacts::collect(
            &claims(UpstreamGroups::present(vec![]).unwrap()),
            2,
            GroupFactsMaxAge::new(300).unwrap(),
            None,
            1200,
        )
        .unwrap();
        let value = serde_json::to_value(&facts).unwrap();
        let restored = AuthenticationFacts::decode(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(&restored).unwrap(), value);
        assert!(matches!(
            restored.project(source(), 1299).unwrap(),
            Groups::Available {
                expires_at: 1300,
                observed_at: 1000,
                ..
            }
        ));
        for now in [1300, 1500] {
            assert_eq!(
                serde_json::to_value(restored.project(source(), now).unwrap()).unwrap(),
                serde_json::json!({"version":1,"status":"expired"})
            );
        }
        assert!(restored.project(source(), 969).is_err());
        for (groups, reason) in [
            (
                UpstreamGroups::NotConfigured,
                FactUnavailableReason::NotConfigured,
            ),
            (UpstreamGroups::Missing, FactUnavailableReason::ClaimMissing),
        ] {
            let facts = AuthenticationFacts::collect(
                &claims(groups),
                2,
                GroupFactsMaxAge::new(1).unwrap(),
                None,
                1200,
            )
            .unwrap();
            assert_eq!(
                facts.project(source(), 1600).unwrap(),
                Groups::unavailable(reason)
            );
        }
    }
    #[test]
    fn storage_rejects_old_or_malformed_formats() {
        let facts = AuthenticationFacts::collect(
            &claims(UpstreamGroups::present(vec![]).unwrap()),
            2,
            GroupFactsMaxAge::new(300).unwrap(),
            None,
            1000,
        )
        .unwrap();
        let base = serde_json::to_value(facts).unwrap();
        for (key, value) in [
            ("format_version", serde_json::json!(1)),
            ("provider_config_version", serde_json::json!(0)),
            ("mapping_version", serde_json::json!(2)),
        ] {
            let mut input = base.clone();
            input[key] = value;
            assert!(AuthenticationFacts::decode(input).is_err());
        }
        for (key, value) in [
            ("status", serde_json::json!("expired")),
            ("snapshot_id", serde_json::json!(Uuid::nil())),
            ("expires_at", serde_json::json!(1301)),
            ("values", serde_json::json!(["b", "a"])),
        ] {
            let mut input = base.clone();
            input["groups"][key] = value;
            assert!(AuthenticationFacts::decode(input).is_err());
        }
        for reason in ["local_identity", "not_yet_valid"] {
            let mut input = base.clone();
            input["groups"] = serde_json::json!({"status":"unavailable","reason":reason});
            assert!(AuthenticationFacts::decode(input).is_err());
        }
        assert!(
            AuthenticationFacts::decode(serde_json::json!({"groups":[],"mapping_version":2}))
                .is_err()
        );
    }

    #[test]
    fn future_observation_preserves_identity_and_withholds_groups_until_observed() {
        for groups in [
            UpstreamGroups::NotConfigured,
            UpstreamGroups::Missing,
            UpstreamGroups::present(vec![]).unwrap(),
        ] {
            let mut claims = claims(groups);
            claims.issued_at = 1030;
            claims.assurance = Assurance::password(1030).unwrap();
            let facts = AuthenticationFacts::collect(
                &claims,
                1,
                GroupFactsMaxAge::new(1).unwrap(),
                None,
                1000,
            )
            .unwrap();
            let encoded = serde_json::to_value(&facts).unwrap();
            let restored = AuthenticationFacts::decode(encoded.clone()).unwrap();
            let before = serde_json::to_value(restored.project(source(), 1029).unwrap()).unwrap();
            assert_eq!(before["status"], "unavailable");
            assert!(before.get("values").is_none());
            if claims.groups.values().is_some() {
                assert_eq!(before["reason"], "not_yet_valid");
                assert!(matches!(
                    restored.project(source(), 1030).unwrap(),
                    Groups::Available {
                        expires_at: 1031,
                        ..
                    }
                ));
                assert!(matches!(
                    restored.project(source(), 1031).unwrap(),
                    Groups::Expired { .. }
                ));
            }
            assert_eq!(serde_json::to_value(&restored).unwrap(), encoded);
            assert!(
                AuthenticationFacts::collect(
                    &claims,
                    1,
                    GroupFactsMaxAge::new(1).unwrap(),
                    None,
                    999
                )
                .is_err()
            );
        }
    }
}
