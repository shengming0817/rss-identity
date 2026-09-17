//! Fresh reference-host installation; existing schemas are rejected without mutation.
use crate::{AppError, config::MigrationConfig};
use rss_identity_core::InstanceId;
use rss_identity_postgres::{AuthorityProfile, grant_profile};
use sqlx::{Connection, PgConnection};
pub(crate) fn validate(config: &MigrationConfig) -> Result<InstanceId, AppError> {
    if config.format_version != 3
        || config.runtime_role == config.maintenance_role
        || config.runtime_role == config.database.user
        || config.maintenance_role == config.database.user
        || [&config.runtime_role, &config.maintenance_role]
            .iter()
            .any(|r| r.is_empty() || r.len() > 63 || r.contains('\0'))
    {
        return Err(AppError::Configuration);
    }
    config.storage.binding()?;
    InstanceId::parse(&config.instance_id).map_err(|_| AppError::Configuration)
}

/// Read-only snapshot verification; never installs, initializes, repairs or increments a fence.
pub async fn verify(config: MigrationConfig) -> Result<(), AppError> {
    let instance = validate(&config)?;
    let mut c = PgConnection::connect_with(&config.database.sqlx()?)
        .await
        .map_err(|_| AppError::Connection)?;
    let result = tokio::time::timeout(std::time::Duration::from_secs(60), async {
        let mut tx = c.begin().await?;
        sqlx::raw_sql("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY; SET LOCAL statement_timeout='30s'; SET LOCAL lock_timeout='10s'").execute(&mut *tx).await?;
        verify_storage(&mut tx, &config.storage).await?;
        for (role, profile) in [(&config.runtime_role, AuthorityProfile::Runtime), (&config.maintenance_role, AuthorityProfile::Maintenance)] {
            let switch = format!("SET LOCAL ROLE \"{}\"", role.replace('"', "\"\""));
            sqlx::raw_sql(sqlx::AssertSqlSafe(switch)).execute(&mut *tx).await?;
            rss_identity_postgres::verify_profile(&mut tx, profile, instance).await.map_err(|_| sqlx::Error::Protocol("installation verification failed".into()))?;
            sqlx::raw_sql("SET LOCAL ROLE NONE").execute(&mut *tx).await?;
        }
        tx.rollback().await
    }).await;
    let outcome = result
        .map_err(|_| AppError::Migration)
        .and_then(|r| r.map_err(|_| AppError::Migration));
    finish_installation(outcome, c.close()).await
}
pub(crate) async fn verify_storage(
    c: &mut PgConnection,
    storage: &crate::config::StorageConfig,
) -> Result<(), sqlx::Error> {
    let identity: Vec<(Vec<u8>, Vec<u8>)> =
        sqlx::query_as("SELECT target,lineage FROM rss_transactional_messaging.storage_lineage")
            .fetch_all(&mut *c)
            .await?;
    let tenants: Vec<(uuid::Uuid, i64)> = sqlx::query_as(
        "SELECT tenant_id,epoch FROM rss_transactional_messaging.tenant_epoch ORDER BY tenant_id",
    )
    .fetch_all(c)
    .await?;
    let mut expected = storage
        .tenants()
        .map_err(|_| sqlx::Error::Protocol("invalid tenant binding".into()))?
        .into_iter()
        .map(|t| (t.to_string(), storage.generation))
        .collect::<Vec<_>>();
    expected.sort();
    if identity != [(storage.target.to_vec(), storage.lineage.to_vec())]
        || tenants
            .into_iter()
            .map(|(t, e)| (t.to_string(), e))
            .collect::<Vec<_>>()
            != expected
    {
        return Err(sqlx::Error::Protocol("storage binding mismatch".into()));
    }
    Ok(())
}
pub async fn install(config: MigrationConfig) -> Result<(), AppError> {
    if config.format_version != 3
        || config.runtime_role == config.maintenance_role
        || config.runtime_role == config.database.user
        || config.maintenance_role == config.database.user
    {
        return Err(AppError::Configuration);
    }
    let instance = InstanceId::parse(&config.instance_id).map_err(|_| AppError::Configuration)?;
    let tenants = config.storage.tenants()?;
    config.storage.binding()?;
    let mut c = PgConnection::connect_with(&config.database.sqlx()?)
        .await
        .map_err(|_| AppError::Connection)?;
    let result = tokio::time::timeout(std::time::Duration::from_secs(60), async {
        let mut tx = c.begin().await?;
        sqlx::raw_sql("SET LOCAL lock_timeout='10s'; SET LOCAL statement_timeout='30s'")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT pg_advisory_xact_lock(2435,9)")
            .execute(&mut *tx)
            .await?;
        // RSS's migration owns its relay role contract. Roles/logins are provisioned by the host operator.
        sqlx::raw_sql(rss_transactional_messaging_postgres::MIGRATION_SQL)
            .execute(&mut *tx)
            .await?;
        // RSS leaves host default table/sequence ACLs to its migrator. Reject ambient PUBLIC
        // grants before committing a producer installation; Identity revokes its own PUBLIC ACLs.
        let public_grants: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL aclexplode(c.relacl) a WHERE n.nspname='rss_transactional_messaging' AND a.grantee=0)",
        ).fetch_one(&mut *tx).await?;
        if public_grants {
            return Err(sqlx::Error::Protocol("unexpected public storage privileges".into()));
        }
        rss_identity_postgres::install(&mut tx, instance).await?;
        grant_profile(&mut tx, &config.runtime_role, AuthorityProfile::Runtime).await?;
        grant_profile(
            &mut tx,
            &config.maintenance_role,
            AuthorityProfile::Maintenance,
        )
        .await?;
        sqlx::query("INSERT INTO rss_transactional_messaging.storage_lineage VALUES(true,$1,$2)")
            .bind(config.storage.target.as_slice())
            .bind(config.storage.lineage.as_slice())
            .execute(&mut *tx)
            .await?;
        for tenant in tenants {
            sqlx::query("INSERT INTO rss_transactional_messaging.tenant_epoch VALUES($1::uuid,$2)")
                .bind(tenant.to_string())
                .bind(config.storage.generation)
                .execute(&mut *tx)
                .await?;
        }
        for (role, profile) in [
            (&config.runtime_role, AuthorityProfile::Runtime),
            (&config.maintenance_role, AuthorityProfile::Maintenance),
        ] {
            // grant_profile already validated the name; quote it as an SQL identifier again.
            let switch = format!("SET LOCAL ROLE \"{}\"", role.replace('"', "\"\""));
            sqlx::raw_sql(sqlx::AssertSqlSafe(switch)).execute(&mut *tx).await?;
            rss_identity_postgres::verify_profile(&mut tx, profile, instance)
                .await
                .map_err(|_| sqlx::Error::Protocol("installation profile verification failed".into()))?;
            sqlx::raw_sql("SET LOCAL ROLE NONE").execute(&mut *tx).await?;
        }
        tx.commit().await
    })
    .await;
    let outcome = result
        .map_err(|_| AppError::Migration)
        .and_then(|r| r.map_err(|_| AppError::Migration));
    finish_installation(outcome, c.close()).await
}

async fn finish_installation(
    outcome: Result<(), AppError>,
    close: impl std::future::Future<Output = Result<(), sqlx::Error>>,
) -> Result<(), AppError> {
    // Connection shutdown is independent of commit acknowledgement. Never rewrite settlement.
    if !matches!(
        tokio::time::timeout(std::time::Duration::from_secs(5), close).await,
        Ok(Ok(()))
    ) {
        eprintln!("component=migration cleanup=unconfirmed");
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn cleanup_failure_preserves_confirmed_and_unknown_installation_outcomes() {
        assert!(
            finish_installation(Ok(()), async { Err(sqlx::Error::PoolClosed) })
                .await
                .is_ok()
        );
        assert!(matches!(
            finish_installation(Err(AppError::Migration), async { Ok(()) }).await,
            Err(AppError::Migration)
        ));
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_secs(10),
                finish_installation(Ok(()), std::future::pending())
            )
            .await
            .unwrap()
            .is_ok()
        );
    }
}
