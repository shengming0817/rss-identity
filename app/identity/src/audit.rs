//! Required Audit installation; business runtime credentials append directly.
use crate::{AppError, config::MigrationConfig};
use sqlx::PgConnection;
const OWNER_PROFILE: &str = "SELECT EXISTS(SELECT FROM pg_roles WHERE rolname=$1 AND NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication)";
pub fn validate_installation(c: &MigrationConfig) -> Result<(), AppError> {
    let roles = [
        &c.audit.owner_role,
        &c.runtime_role,
        &c.maintenance_role,
        &c.database.user,
    ];
    if roles
        .iter()
        .any(|r| r.is_empty() || r.len() > 63 || r.contains('\0'))
        || roles
            .iter()
            .enumerate()
            .any(|(i, r)| roles[i + 1..].contains(r))
    {
        return Err(AppError::Configuration);
    }
    Ok(())
}
/// Run only in the caller's fresh installation transaction, before granting business profiles.
pub async fn install(c: &mut PgConnection, config: &MigrationConfig) -> Result<(), sqlx::Error> {
    let owner_role = &config.audit.owner_role;
    let safe: bool = sqlx::query_scalar(OWNER_PROFILE)
        .bind(owner_role)
        .fetch_one(&mut *c)
        .await?;
    if !safe {
        return Err(sqlx::Error::Protocol("audit owner rejected".into()));
    }
    let owner = format!("\"{}\"", owner_role.replace('"', "\"\""));
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!("SET LOCAL ROLE {owner}")))
        .execute(&mut *c)
        .await?;
    sqlx::raw_sql(rss_audit_postgres::MIGRATION_SQL)
        .execute(&mut *c)
        .await?;
    sqlx::raw_sql("SET LOCAL ROLE NONE").execute(c).await?;
    Ok(())
}
/// Read-only installation role check. Full component admission runs on each Authority connection.
pub async fn verify(c: &mut PgConnection, config: &MigrationConfig) -> Result<(), sqlx::Error> {
    let owner = &config.audit.owner_role;
    let present: bool = sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_namespace n JOIN pg_roles r ON r.oid=n.nspowner WHERE n.nspname='rss_audit' AND r.rolname=$1)").bind(owner).fetch_one(&mut *c).await?;
    let safe: bool = sqlx::query_scalar(OWNER_PROFILE)
        .bind(owner)
        .fetch_one(&mut *c)
        .await?;
    if !present || !safe {
        return Err(sqlx::Error::Protocol("audit installation rejected".into()));
    }
    for role in [&config.runtime_role, &config.maintenance_role] {
        let safe: bool = sqlx::query_scalar("SELECT NOT pg_has_role($1,$2,'SET') AND has_schema_privilege($1,'rss_audit','USAGE') AND has_table_privilege($1,'rss_audit.records','SELECT') AND NOT has_table_privilege($1,'rss_audit.records','INSERT,UPDATE,DELETE,TRUNCATE') AND NOT has_sequence_privilege($1,'rss_audit.positions','USAGE,SELECT,UPDATE') AND has_function_privilege($1,'rss_audit.append_batch(uuid,text[],text[],bigint[],bytea[],bigint[])','EXECUTE')")
            .bind(role).bind(owner).fetch_one(&mut *c).await?;
        if !safe {
            return Err(sqlx::Error::Protocol("audit writer grants rejected".into()));
        }
    }
    Ok(())
}
