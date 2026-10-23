//! Identity owns its schema; host deployment owns database roles, RSS migrations and tenant fences.
use crate::{AuthorityError, AuthorityProfile};
use rss_identity_core::InstanceId;
use rss_transactional_messaging_postgres::PgError;
use sqlx::PgConnection;
pub const SCHEMA_VERSION: i32 = 16;
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
        AuthorityProfile::Provisioning => include_str!("grants-provisioning.sql"),
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
            AuthorityProfile::Provisioning => "provisioning",
        })
        .fetch_one(&mut *connection)
        .await?;
    if result != "ok" {
        return Ok(Some(result));
    }
    Ok(Some("ok".into()))
}

/// Narrow metadata admission grants for a host business transaction role. In particular this
/// does not grant password, provider credential, session or profile-observation access.
pub async fn grant_profile_source_admission(
    c: &mut PgConnection,
    role: &str,
) -> Result<(), sqlx::Error> {
    if role.is_empty() || role.len() > 63 || role.contains('\0') {
        return Err(sqlx::Error::Protocol("invalid role identifier".into()));
    }
    let role = format!("\"{}\"", role.replace('"', "\"\""));
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!("GRANT USAGE ON SCHEMA identity_authority TO {role}; GRANT SELECT ON identity_authority.schema_version,identity_authority.deployment TO {role}; GRANT SELECT(tenant_id),UPDATE(tenant_id) ON identity_authority.guard TO {role}; GRANT SELECT(tenant_id,provider_id,enabled,config_version,settings) ON identity_authority.providers TO {role};"))).execute(c).await?;
    Ok(())
}
/// Verify only this narrow Identity profile; unrelated host schema privileges are unaffected.
pub async fn verify_profile_source_admission(
    c: &mut PgConnection,
    instance: InstanceId,
) -> Result<(), AuthorityError> {
    let result=async {
        // SET reachability includes NOINHERIT membership; effective privileges alone are insufficient.
        let reachable_safe:bool=sqlx::query_scalar("WITH reachable AS (SELECT oid,rolsuper,rolbypassrls,rolcreaterole FROM pg_roles WHERE pg_has_role(current_user,oid,'SET')) SELECT NOT EXISTS(SELECT FROM reachable r WHERE r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR has_schema_privilege(r.oid,'identity_authority','CREATE')) AND NOT EXISTS(SELECT FROM reachable r CROSS JOIN pg_attribute a JOIN pg_class cl ON cl.oid=a.attrelid JOIN pg_namespace n ON n.oid=cl.relnamespace WHERE n.nspname='identity_authority' AND cl.relkind='r' AND a.attnum>0 AND NOT a.attisdropped AND ((has_column_privilege(r.oid,a.attrelid,a.attnum,'SELECT') AND NOT (cl.relname IN ('schema_version','deployment') OR (cl.relname='guard' AND a.attname='tenant_id') OR (cl.relname='providers' AND a.attname IN ('tenant_id','provider_id','enabled','config_version','settings')))) OR (has_column_privilege(r.oid,a.attrelid,a.attnum,'UPDATE') AND NOT (cl.relname='guard' AND a.attname='tenant_id')) OR has_column_privilege(r.oid,a.attrelid,a.attnum,'INSERT,REFERENCES') OR has_table_privilege(r.oid,a.attrelid,'DELETE,TRUNCATE,TRIGGER')))").fetch_one(&mut *c).await?;
        if !reachable_safe {return Ok::<_,sqlx::Error>(false);}
        let valid:bool=sqlx::query_scalar("SELECT NOT rolsuper AND NOT rolbypassrls AND NOT rolcreaterole AND NOT has_schema_privilege(current_user,'identity_authority','CREATE') AND has_schema_privilege(current_user,'identity_authority','USAGE') FROM pg_roles WHERE rolname=current_user").fetch_one(&mut *c).await?;
        if !valid {return Ok::<_,sqlx::Error>(false);}
        let valid:bool=sqlx::query_scalar("SELECT bool_and(has_column_privilege(current_user,a.attrelid,a.attnum,'SELECT') = (cl.relname IN ('schema_version','deployment') OR (cl.relname='guard' AND a.attname='tenant_id') OR (cl.relname='providers' AND a.attname IN ('tenant_id','provider_id','enabled','config_version','settings'))) AND has_column_privilege(current_user,a.attrelid,a.attnum,'UPDATE') = (cl.relname='guard' AND a.attname='tenant_id') AND NOT has_column_privilege(current_user,a.attrelid,a.attnum,'INSERT') AND NOT has_column_privilege(current_user,a.attrelid,a.attnum,'REFERENCES') AND NOT has_table_privilege(current_user,a.attrelid,'DELETE,TRUNCATE,TRIGGER')) FROM pg_attribute a JOIN pg_class cl ON cl.oid=a.attrelid JOIN pg_namespace n ON n.oid=cl.relnamespace WHERE n.nspname='identity_authority' AND cl.relkind='r' AND a.attnum>0 AND NOT a.attisdropped").fetch_one(&mut *c).await?;
        if !valid {return Ok(false);}
        let actual:uuid::Uuid=sqlx::query_scalar("SELECT authority_id FROM identity_authority.deployment").fetch_one(&mut *c).await?;
        let versions:Vec<i32>=sqlx::query_scalar("SELECT version FROM identity_authority.schema_version").fetch_all(&mut *c).await?;
        let signature:Option<String>=sqlx::query_scalar(SCHEMA_SIGNATURE_SQL).fetch_one(c).await?;
        Ok(actual==instance.as_uuid() && versions==[SCHEMA_VERSION] && signature.as_deref()==Some(SCHEMA_SIGNATURE.trim()))
    }.await.map_err(|_|AuthorityError::Unavailable)?;
    if result {
        Ok(())
    } else {
        Err(AuthorityError::Configuration)
    }
}
