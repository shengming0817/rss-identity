//! Identity owns its schema; host deployment owns database roles, RSS migrations and tenant fences.
use crate::{AuthorityError, AuthorityProfile};
use rss_identity_core::InstanceId;
use rss_transactional_messaging_postgres::PgError;
use sqlx::PgConnection;
pub const SCHEMA_VERSION: i32 = 9;
pub const MIGRATION_SQL: &str = include_str!("../migrations/0001_authority.sql");
pub const SCHEMA_SIGNATURE_SQL: &str = include_str!("schema-signature.sql");
pub const SCHEMA_SIGNATURE: &str = include_str!("schema-signature.sha256");
/// Run inside the host's migration transaction on an empty identity schema.
pub async fn install(
    connection: &mut PgConnection,
    instance: InstanceId,
) -> Result<(), sqlx::Error> {
    sqlx::raw_sql(MIGRATION_SQL)
        .execute(&mut *connection)
        .await?;
    sqlx::query("INSERT INTO identity_authority.deployment(authority_id) VALUES($1)")
        .bind(instance.as_uuid())
        .execute(connection)
        .await?;
    Ok(())
}
/// Grant to a host-chosen role. Does not create users, pools, secrets, epochs or memberships.
pub async fn grant_profile(
    connection: &mut PgConnection,
    role: &str,
    profile: AuthorityProfile,
) -> Result<(), sqlx::Error> {
    if role.is_empty() || role.len() > 63 || role.contains('\0') {
        return Err(sqlx::Error::Protocol("invalid role identifier".into()));
    }
    let role = format!("\"{}\"", role.replace('"', "\"\""));
    let sql = match profile {
        AuthorityProfile::Runtime => include_str!("grants-runtime.sql"),
        AuthorityProfile::Maintenance => include_str!("grants-maintenance.sql"),
    };
    // Only substitution is a quoted identifier; embedded quotes are doubled above.
    sqlx::raw_sql(sqlx::AssertSqlSafe(sql.replace("{role}", &role)))
        .execute(connection)
        .await?;
    Ok(())
}
/// Verify the current SQL role against the same storage contract used by authority startup.
/// The host owns the connection, transaction and role selection; this does not commit anything.
pub async fn verify_profile(
    connection: &mut PgConnection,
    profile: AuthorityProfile,
    instance: InstanceId,
) -> Result<(), AuthorityError> {
    crate::check_probe(
        probe(connection, profile, instance)
            .await
            .map_err(|_| AuthorityError::Unavailable),
    )
}

pub(crate) async fn probe(
    connection: &mut PgConnection,
    profile: AuthorityProfile,
    instance: InstanceId,
) -> Result<Option<String>, PgError> {
    let schema_exists: bool =
        sqlx::query_scalar("SELECT to_regnamespace('identity_authority') IS NOT NULL")
            .fetch_one(&mut *connection)
            .await?;
    if !schema_exists {
        return Ok(Some("schema-contract".into()));
    }
    let usage: bool = sqlx::query_scalar(
        "SELECT has_schema_privilege(current_user,'identity_authority','USAGE')",
    )
    .fetch_one(&mut *connection)
    .await?;
    if !usage {
        return Ok(Some("privileges".into()));
    }
    for table in [
        "identity_authority.schema_version",
        "identity_authority.deployment",
    ] {
        let exists: bool = sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
            .bind(table)
            .fetch_one(&mut *connection)
            .await?;
        if !exists {
            return Ok(Some("schema-contract".into()));
        }
        let readable: bool =
            sqlx::query_scalar("SELECT has_table_privilege(current_user,$1,'SELECT')")
                .bind(table)
                .fetch_one(&mut *connection)
                .await?;
        if !readable {
            return Ok(Some("privileges".into()));
        }
    }
    if crate::storage::authority_id(connection).await? != instance.as_uuid() {
        return Ok(Some("deployment-identity".into()));
    }
    let versions: Vec<i32> =
        sqlx::query_scalar("SELECT version FROM identity_authority.schema_version")
            .fetch_all(&mut *connection)
            .await?;
    if versions != [SCHEMA_VERSION] {
        return Ok(Some("schema-version".into()));
    }
    let signature: Option<String> = sqlx::query_scalar(SCHEMA_SIGNATURE_SQL)
        .fetch_one(&mut *connection)
        .await?;
    if signature.as_deref() != Some(SCHEMA_SIGNATURE.trim()) {
        return Ok(Some("schema-contract".into()));
    }
    let result: String = sqlx::query_scalar(include_str!("probe.sql"))
        .bind(match profile {
            AuthorityProfile::Runtime => "runtime",
            AuthorityProfile::Maintenance => "maintenance",
        })
        .fetch_one(&mut *connection)
        .await?;
    if result != "ok" {
        return Ok(Some(result));
    }
    Ok(Some("ok".into()))
}
