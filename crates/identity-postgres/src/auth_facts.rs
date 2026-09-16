//! The only persisted authentication-facts codec. Provider authority stays in Origin.
use crate::transaction::{corrupt, reject};
use rss_identity_contracts::groups::{
    GroupSource, Groups, UnavailableReason, VERSION, acceptable_observation, valid_snapshot_window,
};
use rss_identity_core::{
    assurance::Assurance,
    federation::{FederationError, UpstreamClaims},
    groups::{GroupFactsMaxAge, UpstreamGroups},
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
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum Snapshot {
    Unavailable {
        reason: UnavailableReason,
    },
    Available {
        snapshot_id: Uuid,
        observed_at: i64,
        expires_at: i64,
        values: Vec<String>,
    },
}
impl AuthenticationFacts {
    pub fn collect(
        claims: &UpstreamClaims,
        version: i64,
        policy: GroupFactsMaxAge,
        now: i64,
    ) -> Result<Self, FederationError> {
        claims.validate()?;
        let expires_at = policy.expires_at(claims.issued_at, claims.expires_at, now)?;
        if version < 1 {
            return Err(FederationError::Claims);
        }
        let groups = match &claims.groups {
            UpstreamGroups::NotConfigured => Snapshot::Unavailable {
                reason: UnavailableReason::NotConfigured,
            },
            UpstreamGroups::Missing => Snapshot::Unavailable {
                reason: UnavailableReason::ClaimMissing,
            },
            UpstreamGroups::Present(values) => Snapshot::Available {
                snapshot_id: Uuid::new_v4(),
                observed_at: claims.issued_at,
                expires_at,
                values: values.clone(),
            },
        };
        Ok(Self {
            format_version: 1,
            provider_config_version: version,
            email: claims.email.clone(),
            email_verified: claims.email_verified,
            assurance: claims.assurance.clone(),
            groups,
        })
    }
    pub fn decode(value: serde_json::Value) -> Result<Self, PgError> {
        let facts: Self = serde_json::from_value(value).map_err(|_| corrupt())?;
        if facts.format_version != 1
            || facts.provider_config_version < 1
            || facts
                .email
                .as_ref()
                .is_some_and(|v| v.len() > 320 || v.chars().any(char::is_control))
        {
            return Err(corrupt());
        }
        match &facts.groups {
            Snapshot::Unavailable {
                reason: UnavailableReason::LocalIdentity | UnavailableReason::NotYetValid,
            } => return Err(corrupt()),
            Snapshot::Available {
                snapshot_id,
                observed_at,
                expires_at,
                values,
            } => {
                if snapshot_id.is_nil()
                    || !valid_snapshot_window(*observed_at, *expires_at)
                    || !rss_identity_contracts::groups::canonical_values(values)
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
        let value = serde_json::to_value(self).map_err(|_| corrupt())?;
        let size: i32 = sqlx::query_scalar("SELECT octet_length($1::jsonb::text)")
            .bind(&value)
            .fetch_one(c)
            .await?;
        if size > 32768 {
            return Err(reject());
        }
        Ok(value)
    }
    pub fn project(&self, source: GroupSource, now: i64) -> Result<Groups, PgError> {
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
                    return Ok(Groups::unavailable(UnavailableReason::NotYetValid));
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
    fn source() -> GroupSource {
        GroupSource {
            provider_id: Uuid::new_v4(),
            issuer: "https://idp.test".into(),
        }
    }
    #[test]
    fn snapshot_is_fixed_and_only_available_contains_values() {
        let facts = AuthenticationFacts::collect(
            &claims(UpstreamGroups::present(vec![]).unwrap()),
            2,
            GroupFactsMaxAge::new(300).unwrap(),
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
                UnavailableReason::NotConfigured,
            ),
            (UpstreamGroups::Missing, UnavailableReason::ClaimMissing),
        ] {
            let facts = AuthenticationFacts::collect(
                &claims(groups),
                2,
                GroupFactsMaxAge::new(1).unwrap(),
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
            1000,
        )
        .unwrap();
        let base = serde_json::to_value(facts).unwrap();
        for (key, value) in [
            ("format_version", serde_json::json!(2)),
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
            let facts =
                AuthenticationFacts::collect(&claims, 1, GroupFactsMaxAge::new(1).unwrap(), 1000)
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
                AuthenticationFacts::collect(&claims, 1, GroupFactsMaxAge::new(1).unwrap(), 999)
                    .is_err()
            );
        }
    }
}
