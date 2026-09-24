//! Reference host ownership of audit worker connections, permissions and lifecycle.
use crate::{
    AppError,
    assembly::Timer,
    config::{AuditConfig, AuditInstallation, MigrationConfig, RuntimeConfig},
};
use rss_audit_postgres::{Control, Integrity, PgAudit};
use rss_identity_postgres::audit::AuditDelivery;
use rss_request_context::Deadline;
use rss_runtime::{ManagedTask, ManagedTaskRegistration, ShutdownError};
use rss_transactional_messaging::error::MessagingErrorKind;
use rss_transactional_messaging_postgres::PgRuntime;
use rss_transactional_messaging_runtime::relay::RelayBatchLimit;
use sqlx::{PgConnection, PgPool};
use std::{num::NonZeroUsize, sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;

pub fn validate_installation(c: &MigrationConfig) -> Result<(), AppError> {
    if let AuditInstallation::Enabled {
        owner_role,
        worker_role,
    } = &c.audit
    {
        let roles = [
            owner_role,
            worker_role,
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
    }
    Ok(())
}
fn quoted(role: &str) -> String {
    format!("\"{}\"", role.replace('"', "\"\""))
}
/// Runs in the caller's fresh installation transaction, never in server startup.
pub async fn install(c: &mut PgConnection, config: &MigrationConfig) -> Result<(), sqlx::Error> {
    let AuditInstallation::Enabled {
        owner_role,
        worker_role,
    } = &config.audit
    else {
        return Ok(());
    };
    let owner = quoted(owner_role);
    let worker = quoted(worker_role);
    let safe: bool = sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_roles WHERE rolname=$1 AND NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication)").bind(owner_role).fetch_one(&mut *c).await?;
    if !safe {
        return Err(sqlx::Error::Protocol("audit owner rejected".into()));
    }
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!("SET LOCAL ROLE {owner}")))
        .execute(&mut *c)
        .await?;
    sqlx::raw_sql(rss_audit_postgres::MIGRATION_SQL)
        .execute(&mut *c)
        .await?;
    sqlx::raw_sql("SET LOCAL ROLE NONE")
        .execute(&mut *c)
        .await?;
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!("GRANT USAGE ON SCHEMA rss_audit TO {worker}; GRANT SELECT ON ALL TABLES IN SCHEMA rss_audit TO {worker}; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA rss_audit TO {worker}; {grants}", grants=include_str!("audit-grants.sql").replace("{role}",&worker)))).execute(c).await?;
    Ok(())
}
/// Host-owned handles must be registered for cleanup before constructing the adapter.
pub async fn delivery(
    config: &RuntimeConfig,
    runtime: Arc<PgRuntime>,
    pool: PgPool,
) -> Result<AuditDelivery, AppError> {
    // The worker must not acquire credential access through inherited or PUBLIC grants.
    let role: String = sqlx::query_scalar("SELECT current_user::text")
        .fetch_one(&pool)
        .await
        .map_err(|_| AppError::Provider)?;
    let safe: bool = sqlx::query_scalar(include_str!("audit-worker-probe.sql"))
        .bind(role)
        .fetch_one(&pool)
        .await
        .map_err(|_| AppError::Provider)?;
    if !safe {
        return Err(AppError::Configuration);
    }
    let cancel = CancellationToken::new();
    let control = Control::new(
        &Timer,
        Deadline::from_timeout(&Timer, Duration::from_secs(10)).map_err(|_| AppError::Budget)?,
        &cancel,
    );
    let audit = PgAudit::new(pool, Integrity::Plain, &control)
        .await
        .map_err(|_| AppError::Provider)?;
    AuditDelivery::new(
        runtime,
        Arc::new(audit),
        config.instance()?,
        config.storage.tenants()?,
        crate::assembly::delivery_budget()?,
    )
    .map_err(|_| AppError::Provider)
}
pub fn registration(
    config: &AuditConfig,
    delivery: AuditDelivery,
    drain: Duration,
) -> Result<ManagedTaskRegistration, AppError> {
    let AuditConfig::Enabled {
        poll_millis, batch, ..
    } = config
    else {
        return Err(AppError::Configuration);
    };
    let limit = RelayBatchLimit::new(NonZeroUsize::new(*batch).ok_or(AppError::Budget)?)
        .map_err(|_| AppError::Budget)?;
    let poll = Duration::from_millis(*poll_millis);
    let (start, _) = ManagedTask::prepare("identity-audit", drain);
    Ok(start.into_registration(move |stop| async move {
        loop {
            if stop.is_cancelled() { return Ok(()); }
            if let Err(e) = delivery.run_once(limit).await {
                if matches!(e.kind(),MessagingErrorKind::Invariant|MessagingErrorKind::OwnershipLost|MessagingErrorKind::Permanent|MessagingErrorKind::Conflict) { return Err(ShutdownError::new(e)); }
                eprintln!("component=identity-audit retry={:?}",e.kind());
            }
            tokio::select! { () = stop.cancelled() => return Ok(()), () = tokio::time::sleep(poll) => {} }
        }
    }).critical())
}
/// Verify the selected installation without repairing it. Runtime probes validate exact provider schemas.
pub async fn verify(c: &mut PgConnection, config: &MigrationConfig) -> Result<(), sqlx::Error> {
    let AuditInstallation::Enabled {
        owner_role,
        worker_role,
    } = &config.audit
    else {
        return Ok(());
    };
    let present: bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_namespace n JOIN pg_roles r ON r.oid=n.nspowner WHERE n.nspname='rss_audit' AND r.rolname=$1 AND NOT r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolbypassrls AND NOT r.rolcreaterole)").bind(owner_role).fetch_one(&mut *c).await?;
    if !present {
        return Err(sqlx::Error::Protocol("audit installation mismatch".into()));
    }
    let isolated: bool = sqlx::query_scalar(include_str!("audit-worker-probe.sql"))
        .bind(worker_role)
        .fetch_one(&mut *c)
        .await?;
    if !isolated {
        return Err(sqlx::Error::Protocol(
            "audit worker authority rejected".into(),
        ));
    }
    let safe: bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_roles WHERE rolname=$1 AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcreaterole AND NOT rolcreatedb) AND NOT pg_has_role($1,$2,'SET') AND has_schema_privilege($1,'rss_audit','USAGE') AND has_table_privilege($1,'rss_audit.records','SELECT') AND NOT has_table_privilege($1,'rss_audit.records','INSERT,UPDATE,DELETE,TRUNCATE') AND has_function_privilege($1,'rss_audit.reserve(uuid)','EXECUTE') AND has_function_privilege($1,'rss_audit.append(uuid,text,text,bigint,bytea,bigint)','EXECUTE')").bind(worker_role).bind(owner_role).fetch_one(c).await?;
    if !safe {
        return Err(sqlx::Error::Protocol("audit worker rejected".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn enabled_worker_requires_enough_time_to_drain_active_batch() {
        let mut value: serde_json::Value =
            serde_json::from_str(include_str!("../../../deployment/example.json")).unwrap();
        value["audit"] = serde_json::json!({"mode":"enabled","user":"audit","passwordFile":"p","pollMillis":1000,"batch":16});
        for (resource, drain, valid) in [(29, 60, false), (30, 59, false), (30, 60, true)] {
            value["budgets"]["resourceSeconds"] = serde_json::json!(resource);
            value["budgets"]["drainSeconds"] = serde_json::json!(drain);
            assert_eq!(
                serde_json::from_value::<RuntimeConfig>(value.clone())
                    .unwrap()
                    .validate()
                    .is_ok(),
                valid
            );
        }
    }
    #[test]
    fn host_requires_explicit_mode_and_current_format() {
        let baseline: serde_json::Value =
            serde_json::from_str(include_str!("../../../deployment/example.json")).unwrap();
        let mut missing = baseline.clone();
        missing.as_object_mut().unwrap().remove("audit");
        assert!(serde_json::from_value::<RuntimeConfig>(missing).is_err());
        let mut old = baseline.clone();
        old["formatVersion"] = serde_json::json!(4);
        assert!(
            serde_json::from_value::<RuntimeConfig>(old)
                .unwrap()
                .validate()
                .is_err()
        );
        for a in [
            serde_json::json!({"mode":"enabled","user":"identity_runtime","passwordFile":"p","pollMillis":100,"batch":1}),
            serde_json::json!({"mode":"enabled","user":"audit","passwordFile":"p","pollMillis":1,"batch":1}),
            serde_json::json!({"mode":"enabled","user":"audit","passwordFile":"p","pollMillis":100,"batch":65}),
        ] {
            let mut bad = baseline.clone();
            bad["audit"] = a;
            assert!(
                serde_json::from_value::<RuntimeConfig>(bad)
                    .unwrap()
                    .validate()
                    .is_err()
            );
        }
    }
}
