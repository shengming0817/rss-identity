use super::AuditDeliveryError;
use sqlx::PgConnection;

/// Grant the Identity audit worker's version-matched public provider permissions.
/// The host creates roles and installs messaging/Audit schemas before calling this in its transaction.
/// It never grants producer functions or Identity business-table access.
pub async fn grant_worker(
    connection: &mut PgConnection,
    role: &str,
) -> Result<(), AuditDeliveryError> {
    if role.is_empty() || role.len() > 63 || role.contains('\0') {
        return Err(AuditDeliveryError::Configuration);
    }
    rss_transactional_messaging_postgres::grant_consumer(connection, role)
        .await
        .map_err(AuditDeliveryError::pg)?;
    let role = format!("\"{}\"", role.replace('"', "\"\""));
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!("GRANT USAGE ON SCHEMA rss_audit TO {role}; GRANT SELECT ON rss_audit.heads,rss_audit.records TO {role}; GRANT EXECUTE ON FUNCTION rss_audit.reserve(uuid),rss_audit.append(uuid,text,text,bigint,bytea,bigint) TO {role}"))).execute(connection).await.map_err(|e|AuditDeliveryError::pg(e.into()))?;
    Ok(())
}
/// Verify the host-selected worker's complete SET-role authority closure, without changing grants.
/// Provider schema admission remains owned by `PgRuntime::connect_consumer` and `PgAudit::new`.
pub async fn verify_worker(
    connection: &mut PgConnection,
    role: &str,
) -> Result<(), AuditDeliveryError> {
    let safe: bool = sqlx::query_scalar(include_str!("worker-probe.sql"))
        .bind(role)
        .fetch_one(connection)
        .await
        .map_err(|e| AuditDeliveryError::pg(e.into()))?;
    if safe {
        Ok(())
    } else {
        Err(AuditDeliveryError::Permanent)
    }
}
