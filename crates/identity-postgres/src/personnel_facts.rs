//! Bounded observations for host-owned background predicates in a tenant transaction.
//! ref: PostgreSQL REL_17_STABLE doc/src/sgml/ref/create_function.sgml
use crate::{AuthorityError, ProfileSource, ProfileStatus};
use rss_identity_core::{InstanceId, PrincipalId, federation::ProviderId, profile::ProfileLimits};
use rss_request_context::TenantId;
use sqlx::{Connection, PgConnection, Row};
use uuid::Uuid;

/// A profile path consists of decoded JSON Pointer segments in the normalized profile document.
/// A host authorizes the selected path against its field definition before calling this API.
pub enum PersonnelField<'a> {
    Profile {
        source: ProfileSource,
        path: &'a [String],
    },
    Groups(ProviderId),
    Departments(ProviderId),
}

pub const MAX_PERSONNEL_SUBJECTS: usize = 64;

/// A page and generation come from one PostgreSQL statement snapshot. An empty request
/// returns only the generation. Timestamps are Unix seconds unless named otherwise.
pub struct PersonnelFactPage {
    pub generation: i64,
    pub sampled_at: i64,
    pub items: Vec<PersonnelFact>,
}

pub struct PersonnelFact {
    pub principal: PrincipalId,
    pub status: ProfileStatus,
    pub snapshot_id: Option<Uuid>,
    pub provider_version: Option<i64>,
    pub source_revision: Option<i64>,
    pub collected_at_micros: Option<i64>,
    pub observed_at: Option<i64>,
    pub expires_at: Option<i64>,
    /// Available observations contain one profile scalar, an array of group identifiers,
    /// or the normalized department snapshot. Hosts enforce freshness until publication/use.
    pub value: Option<serde_json::Value>,
}

pub async fn read_personnel_facts_on(
    c: &mut PgConnection,
    instance: InstanceId,
    tenant: TenantId,
    principals: &[PrincipalId],
    field: PersonnelField<'_>,
    limits: ProfileLimits,
) -> Result<PersonnelFactPage, AuthorityError> {
    if !c.is_in_transaction() || principals.len() > MAX_PERSONNEL_SUBJECTS {
        return Err(AuthorityError::Rejected);
    }
    let (family, source, path): (_, _, &[String]) = match field {
        PersonnelField::Profile { source, path } => ("profile", source, path),
        PersonnelField::Groups(provider) => ("groups", ProfileSource::Idp { provider }, &[]),
        PersonnelField::Departments(provider) => {
            ("department_snapshot", ProfileSource::Idp { provider }, &[])
        }
    };
    let ids: Vec<_> = principals
        .iter()
        .map(|principal| principal.as_uuid())
        .collect();
    let rows =
        sqlx::query("SELECT * FROM identity_authority.personnel_facts($1,$2::uuid,$3,$4,$5,$6,$7)")
            .bind(instance.as_uuid())
            .bind(tenant.to_string())
            .bind(ids)
            .bind(source.key())
            .bind(family)
            .bind(path)
            .bind(i64::from(limits.max_age_seconds()))
            .fetch_all(c)
            .await
            .map_err(|_| AuthorityError::Unavailable)?;
    let first = rows.first().ok_or(AuthorityError::Rejected)?;
    let decode = |_: sqlx::Error| AuthorityError::Unavailable;
    let mut page = PersonnelFactPage {
        generation: first.try_get("generation").map_err(decode)?,
        sampled_at: first.try_get("sampled_at").map_err(decode)?,
        items: Vec::with_capacity(principals.len()),
    };
    for row in rows {
        let Some(id) = row
            .try_get::<Option<Uuid>, _>("principal")
            .map_err(decode)?
        else {
            continue;
        };
        let principal =
            PrincipalId::parse(&id.to_string()).map_err(|_| AuthorityError::Unavailable)?;
        let status = match row.try_get::<&str, _>("status").map_err(decode)? {
            "available" => ProfileStatus::Available,
            "expired" => ProfileStatus::Expired,
            "missing" => ProfileStatus::Missing,
            "unavailable" => ProfileStatus::Unavailable,
            _ => return Err(AuthorityError::Unavailable),
        };
        page.items.push(PersonnelFact {
            principal,
            status,
            snapshot_id: row.try_get("snapshot_id").map_err(decode)?,
            provider_version: row.try_get("provider_version").map_err(decode)?,
            source_revision: row.try_get("source_revision").map_err(decode)?,
            collected_at_micros: row.try_get("collected_at_micros").map_err(decode)?,
            observed_at: row.try_get("observed_at").map_err(decode)?,
            expires_at: row.try_get("expires_at").map_err(decode)?,
            value: row.try_get("value").map_err(decode)?,
        });
    }
    Ok(page)
}
