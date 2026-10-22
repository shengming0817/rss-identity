//! Private HTTP profile projections; capability/storage codecs are not wire contracts.
use rss_identity_core::profile as core;
use rss_identity_postgres as pg;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Change {
    operation_id: Uuid,
    expected_revision: i64,
    value: Option<LocalValue>,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LocalValue {
    display_name: Option<String>,
    username: Option<String>,
    email: Option<String>,
    extensions: Value,
    max_age_seconds: u32,
}
impl TryFrom<Change> for pg::ProfileChange {
    type Error = core::ProfileError;
    fn try_from(v: Change) -> Result<Self, Self::Error> {
        Ok(Self {
            operation_id: v.operation_id,
            expected_revision: v.expected_revision,
            value: v
                .value
                .map(|v| {
                    Ok(core::LocalProfile {
                        display_name: v.display_name,
                        username: v.username,
                        email: v.email,
                        extensions: core::Extensions::try_from(v.extensions)?,
                        max_age_seconds: v.max_age_seconds,
                    })
                })
                .transpose()?,
        })
    }
}
impl From<core::LocalProfile> for LocalValue {
    fn from(v: core::LocalProfile) -> Self {
        Self {
            display_name: v.display_name,
            username: v.username,
            email: v.email,
            extensions: v.extensions.into_value(),
            max_age_seconds: v.max_age_seconds,
        }
    }
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Local {
    revision: i64,
    value: Option<LocalValue>,
}
impl From<pg::LocalProfileView> for Local {
    fn from(v: pg::LocalProfileView) -> Self {
        Self {
            revision: v.revision,
            value: v.value.map(Into::into),
        }
    }
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Receipt {
    operation_id: Uuid,
    revision: i64,
}
impl From<pg::ProfileReceipt> for Receipt {
    fn from(v: pg::ProfileReceipt) -> Self {
        Self {
            operation_id: v.operation_id,
            revision: v.revision,
        }
    }
}
#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum Attribute<T> {
    NotConfigured,
    Missing,
    Invalid,
    Available { value: T },
}
fn attribute<T, U>(v: &core::Attribute<T>, convert: impl FnOnce(&T) -> U) -> Attribute<U> {
    match v {
        core::Attribute::NotConfigured => Attribute::NotConfigured,
        core::Attribute::Missing => Attribute::Missing,
        core::Attribute::Invalid => Attribute::Invalid,
        core::Attribute::Available { value } => Attribute::Available {
            value: convert(value),
        },
    }
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Profile {
    display_name: Attribute<String>,
    username: Attribute<String>,
    email: Attribute<String>,
    email_verified: Attribute<bool>,
    extensions: Attribute<Value>,
}
impl From<&core::Profile> for Profile {
    fn from(v: &core::Profile) -> Self {
        Self {
            display_name: attribute(&v.display_name, Clone::clone),
            username: attribute(&v.username, Clone::clone),
            email: attribute(&v.email, Clone::clone),
            email_verified: attribute(&v.email_verified, |v| *v),
            extensions: attribute(&v.extensions, |v| Value::Object(v.object().clone())),
        }
    }
}
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Source {
    IdentityLocal,
    Idp { provider: String },
}
impl From<pg::ProfileSource> for Source {
    fn from(v: pg::ProfileSource) -> Self {
        match v {
            pg::ProfileSource::IdentityLocal => Self::IdentityLocal,
            pg::ProfileSource::Idp { provider } => Self::Idp {
                provider: provider.to_string(),
            },
        }
    }
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Observation {
    instance_id: String,
    tenant_id: String,
    principal_id: String,
    source: Option<Source>,
    status: &'static str,
    snapshot_id: Option<Uuid>,
    provider_config_version: Option<i64>,
    source_revision: Option<i64>,
    observed_at: Option<i64>,
    collected_at_micros: Option<i64>,
    expires_at: Option<i64>,
    profile: Option<Profile>,
}
impl From<&pg::ProfileView> for Observation {
    fn from(v: &pg::ProfileView) -> Self {
        Self {
            instance_id: v.instance_id.clone(),
            tenant_id: v.tenant_id.clone(),
            principal_id: v.principal_id.clone(),
            source: v.source.map(Into::into),
            status: match v.status {
                pg::ProfileStatus::Available => "available",
                pg::ProfileStatus::Missing => "missing",
                pg::ProfileStatus::Expired => "expired",
                pg::ProfileStatus::Unavailable => "unavailable",
            },
            snapshot_id: v.snapshot_id,
            provider_config_version: v.provider_config_version,
            source_revision: v.source_revision,
            observed_at: v.observed_at,
            collected_at_micros: v.collected_at_micros,
            expires_at: v.expires_at,
            profile: v.profile.as_ref().map(Into::into),
        }
    }
}
